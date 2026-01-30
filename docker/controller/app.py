#!/usr/bin/env python3
"""
Controller Flask App - Docker version of the Lambda controller
Runs on EC2 to manage instances and provide the controller UI
"""

import os
import json
import ipaddress
from datetime import datetime, timezone, timedelta
from functools import wraps

import boto3
from botocore.exceptions import ClientError
from dateutil.relativedelta import relativedelta
from flask import Flask, request, jsonify, make_response, send_file
import jwt

app = Flask(__name__)

# Configuration from environment variables
PROJECT_ID = os.environ.get('PROJECT_ID', 'myowuty')
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')

# Initialize AWS clients
ec2_client = boto3.client('ec2', region_name=AWS_REGION)
s3_client = boto3.client('s3', region_name=AWS_REGION)
ssm_client = boto3.client('ssm', region_name=AWS_REGION)
scheduler = boto3.client('scheduler', region_name=AWS_REGION)

# Cache for project info
_project_info_cache = None
_cache_time = None
CACHE_TTL = 300  # 5 minutes


def get_project_info(parameter_name):
    """Retrieve project info from SSM Parameter Store"""
    try:
        response = ssm_client.get_parameter(Name=parameter_name, WithDecryption=True)
        parameter_value = response['Parameter']['Value']
        return json.loads(parameter_value)
    except ssm_client.exceptions.ParameterNotFound:
        print(f"Parameter {parameter_name} not found")
    except json.JSONDecodeError:
        print("Failed to parse JSON from parameter value")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
    return None


def get_cached_project_info():
    """Get project info with caching"""
    global _project_info_cache, _cache_time
    
    now = datetime.now()
    if _project_info_cache is None or _cache_time is None or (now - _cache_time).seconds > CACHE_TTL:
        parameter_name = f'/{PROJECT_ID}/info'
        _project_info_cache = get_project_info(parameter_name)
        
        # Get apps
        apps = get_project_info(f'/{PROJECT_ID}/apps')
        appsg = get_project_info(f'/{PROJECT_ID}/appsg')
        _project_info_cache['apps'] = apps if apps else []
        _project_info_cache['appsg'] = appsg if appsg else []
        
        _cache_time = now
    
    return _project_info_cache


def get_safe_project_info():
    """Get project info with sensitive keys removed"""
    project_info = get_cached_project_info()
    keys_to_remove = [
        'controller_jwt_secret_key', 'controller_auth_key', 
        'bedrockGatewayApiKey', 'codeServerPassword', 
        'jupyterLabToken', 'liteLLMApiKey', 
        'serverToolPassword', 'serverToolJwtSecret'
    ]
    return {k: v for k, v in project_info.items() if k not in keys_to_remove}


def generate_token(auth_key, jwt_secret_key):
    """Generate JWT token"""
    payload = {
        'auth_key': auth_key,
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, jwt_secret_key, algorithm='HS256')


def verify_token(token, jwt_secret_key):
    """Verify JWT token"""
    try:
        jwt.decode(token, jwt_secret_key, algorithms=['HS256'])
        return True
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return False
    except Exception as e:
        print(f"Token verification error: {str(e)}")
        return False


def token_required(f):
    """Decorator to require valid token for routes"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        project_info = get_cached_project_info()
        jwt_secret_key = project_info['controller_jwt_secret_key']
        
        if not verify_token(token, jwt_secret_key):
            return jsonify({'message': 'Invalid or expired token'}), 401
        
        return f(*args, **kwargs)
    return decorated


# Routes

@app.route('/')
def login_page():
    """Serve login page"""
    return send_file('login.html')


@app.route('/login', methods=['POST'])
def login():
    """Handle login"""
    project_info = get_cached_project_info()
    auth_key = project_info['controller_auth_key']
    jwt_secret_key = project_info['controller_jwt_secret_key']
    
    data = request.get_json()
    if data.get('key') == auth_key:
        token = generate_token(auth_key, jwt_secret_key)
        response = make_response(jsonify({'token': token}))
        return response
    else:
        return jsonify({'error': 'Invalid key'}), 401


@app.route('/index')
@token_required
def index_page():
    """Serve main controller page"""
    return send_file('index.html')


@app.route('/hello')
def hello():
    """Health check endpoint"""
    return "Hello there!"


@app.route('/logout')
def logout():
    """Handle logout"""
    response = make_response(jsonify({'message': 'Logged out successfully'}))
    response.set_cookie('token', '', expires=0)
    return response


@app.route('/project-info')
@token_required
def project_info_route():
    """Get project info"""
    return jsonify(get_safe_project_info())


@app.route('/ec2s')
@token_required
def ec2s():
    """Get EC2 instances"""
    try:
        response = ec2_client.describe_instances()
        instances = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instances.append({
                    'InstanceId': instance['InstanceId'],
                    'PublicIP': instance.get('PublicIpAddress', 'N/A'),
                    'PublicDNS': instance.get('PublicDnsName', 'N/A')
                })
        return jsonify(instances)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/ec2_status')
@token_required
def ec2_status():
    """Get EC2 instance status"""
    try:
        project_info = get_cached_project_info()
        index = int(request.args.get('index', 0))
        instance_id = project_info['instanceId'] if index == 0 else project_info.get('instanceIdG')
        
        if not instance_id:
            return jsonify({'error': 'Instance not found'}), 404
        
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        if response['Reservations'] and response['Reservations'][0]['Instances']:
            status = response['Reservations'][0]['Instances'][0]['State']['Name']
            return jsonify(status)
        return jsonify(None)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/start-ec2')
@token_required
def start_ec2():
    """Start EC2 instance"""
    try:
        project_info = get_cached_project_info()
        index = int(request.args.get('index', 0))
        instance_id = project_info['instanceId'] if index == 0 else project_info.get('instanceIdG')
        
        if not instance_id:
            return jsonify({'error': 'Instance not found'}), 404
        
        response = ec2_client.start_instances(InstanceIds=[instance_id])
        status = response['StartingInstances'][0]['CurrentState']['Name']
        return jsonify({'status': status})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/stop-ec2')
@token_required
def stop_ec2():
    """Stop EC2 instance"""
    try:
        project_info = get_cached_project_info()
        index = int(request.args.get('index', 0))
        instance_id = project_info['instanceId'] if index == 0 else project_info.get('instanceIdG')
        
        if not instance_id:
            return jsonify({'error': 'Instance not found'}), 404
        
        response = ec2_client.stop_instances(InstanceIds=[instance_id])
        status = response['StoppingInstances'][0]['CurrentState']['Name']
        return jsonify({'status': status})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/sg')
@token_required
def security_group():
    """Get security group info"""
    try:
        project_info = get_cached_project_info()
        sg_id = project_info.get('ec2SecurityGroupId')
        if sg_id:
            response = ec2_client.describe_security_groups(GroupIds=[sg_id])
            if response['SecurityGroups']:
                return jsonify(response['SecurityGroups'][0])
        return jsonify({'error': 'Security group not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/apps')
@token_required
def apps():
    """Get apps list"""
    project_info = get_cached_project_info()
    return jsonify(project_info.get('apps', []))


def check_ip_type(ip_address):
    """Check if IP is IPv4 or IPv6"""
    try:
        ipaddress.IPv4Address(ip_address)
        return "IPv4"
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv6Address(ip_address)
            return "IPv6"
        except ipaddress.AddressValueError:
            return "Invalid IP address"


@app.route('/allow')
@token_required
def allow_ip():
    """Add IP to security group"""
    try:
        project_info = get_cached_project_info()
        ec2_security_group_id = project_info['ec2SecurityGroupId']
        allow_ip = request.args.get('ip')
        
        if not allow_ip:
            return jsonify({'error': 'IP address required'}), 400
        
        ip_type = check_ip_type(allow_ip)
        if ip_type == "IPv4":
            ip_range = f'{allow_ip}/32'
        elif ip_type == "IPv6":
            ip_range = f'{allow_ip}/128'
        else:
            return jsonify({'error': 'Invalid IP address'}), 400
        
        # Get security group and find main-range rule
        response = ec2_client.describe_security_groups(GroupIds=[ec2_security_group_id])
        security_group = response['SecurityGroups'][0]
        
        main_range_rule = None
        for rule in security_group['IpPermissions']:
            if 'IpRanges' in rule and rule['IpRanges']:
                if 'Description' in rule['IpRanges'][0] and rule['IpRanges'][0]['Description'] == 'main-range':
                    main_range_rule = rule
                    break
        
        if not main_range_rule:
            return jsonify({'message': 'Not able to find main range', 'error': True}), 500
        
        # Add new rule
        current_time = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        new_description = f"added-on-{current_time}"
        
        permission = {
            'IpProtocol': main_range_rule['IpProtocol'],
            'FromPort': main_range_rule['FromPort'],
            'ToPort': main_range_rule['ToPort']
        }
        
        if ip_type == "IPv4":
            permission['IpRanges'] = [{'CidrIp': ip_range, 'Description': new_description}]
        else:
            permission['Ipv6Ranges'] = [{'CidrIpv6': ip_range, 'Description': new_description}]
        
        ec2_client.authorize_security_group_ingress(
            GroupId=ec2_security_group_id,
            IpPermissions=[permission]
        )
        
        return jsonify({'message': 'Done', 'error': False})
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidPermission.Duplicate':
            return jsonify({'message': 'Already allowed', 'error': False})
        return jsonify({'message': 'Failed to allow', 'error': str(e)}), 500
    except Exception as e:
        return jsonify({'message': 'Failed to allow', 'error': str(e)}), 500


def get_scheduler_info(scheduler_name):
    """Get EventBridge scheduler info"""
    try:
        response = scheduler.get_schedule(Name=scheduler_name)
        schedule_expression = response.get('ScheduleExpression', 'N/A')
        state = response.get('State', 'N/A')
        is_disabled = state.lower() == 'disabled'
        return {"isDisabled": is_disabled, "time": schedule_expression}
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return {"isDisabled": True, "time": "N/A"}
        raise


@app.route('/ec2-schedular-info')
@token_required
def ec2_scheduler_info():
    """Get EC2 scheduler info"""
    try:
        start_info = get_scheduler_info(f'{PROJECT_ID}-start-ec2-schedule')
        stop_info = get_scheduler_info(f'{PROJECT_ID}-stop-ec2-schedule')
        return jsonify({"start": start_info, "stop": stop_info})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/ensble-disable-start-stop-ec2-schedular')
@token_required
def toggle_ec2_scheduler():
    """Enable/disable EC2 scheduler"""
    try:
        action = request.args.get('action')
        if action not in ['ENABLED', 'DISABLED']:
            return jsonify({'error': 'Invalid action'}), 400
        
        for schedule_type in ['start', 'stop']:
            schedule_name = f'{PROJECT_ID}-{schedule_type}-ec2-schedule'
            try:
                scheduler.update_schedule(Name=schedule_name, State=action)
            except Exception as e:
                print(f"Error updating {schedule_name}: {e}")
        
        return jsonify({'result': f'EC2 start and stop scheduler are {action}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def get_s3_file_age(bucket_name, file_name):
    """Get age of S3 file"""
    try:
        response = s3_client.head_object(Bucket=bucket_name, Key=file_name)
        last_modified = response['LastModified']
        current_time = datetime.now(last_modified.tzinfo)
        time_difference = relativedelta(current_time, last_modified)
        
        age_parts = []
        if time_difference.years > 0:
            age_parts.append(f"{time_difference.years} year{'s' if time_difference.years > 1 else ''}")
        if time_difference.months > 0:
            age_parts.append(f"{time_difference.months} month{'s' if time_difference.months > 1 else ''}")
        if time_difference.days > 0:
            age_parts.append(f"{time_difference.days} day{'s' if time_difference.days > 1 else ''}")
        if time_difference.hours > 0:
            age_parts.append(f"{time_difference.hours} hour{'s' if time_difference.hours > 1 else ''}")
        if time_difference.minutes > 0:
            age_parts.append(f"{time_difference.minutes} minute{'s' if time_difference.minutes > 1 else ''}")
        
        if not age_parts:
            return "Just now", time_difference
        
        return ", ".join(age_parts) + " ago", time_difference
    except Exception as e:
        print(f"Error getting S3 file age: {str(e)}")
        return None, None


@app.route('/ec2-setup-status')
@token_required
def ec2_setup_status():
    """Get EC2 setup status"""
    try:
        project_info = get_cached_project_info()
        bucket_name = project_info['dataBucketName']
        
        ended = None
        ended_minutes = 0
        ended_hours = 0
        status = ""
        
        started, _ = get_s3_file_age(bucket_name, f'{PROJECT_ID}-ec2-setup-started')
        if not started:
            status = "EC2 setup is not yet started."
        else:
            status = f'Setup started since: {started}.'
            ended, time_difference = get_s3_file_age(bucket_name, f'{PROJECT_ID}-ec2-setup-ended')
            if ended:
                ended_minutes = getattr(time_difference, 'minutes', 0)
                ended_hours = getattr(time_difference, 'hours', 0)
                status = f'Setup ended since: {ended}.'
        
        return jsonify({
            'started': started,
            'ended': ended,
            'status': status,
            'endedMinutes': ended_minutes,
            'endedHours': ended_hours
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
