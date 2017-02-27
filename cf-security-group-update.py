import os
import boto3
from botocore.vendored import requests

def get_cloudflare_ip_list():
    'Call the CloudFlare API and return a list of IPs'
    response = requests.get('https://api.cloudflare.com/client/v4/ips')
    temp = response.json()
    if 'result' in temp and 'ipv4_cidrs' in temp['result']:
        return temp['result']['ipv4_cidrs']

    raise Exception("Cloudflare response error")

def get_aws_security_group(group_id):
    'Return the defined Security Group'
    ec2 = boto3.resource('ec2')
    group = ec2.SecurityGroup(group_id)
    if group.group_id == group_id:
        return group
    raise Exception('Failed to retrieve Security Group')

def check_rule_exists(rules, address, port):
    'Check if the rule currently exists'
    for rule in rules:
        for ip_range in rule['IpRanges']:
            if ip_range['CidrIp'] == address and rule['FromPort'] == port:
                return True
    return False

def add_rule(group, address, port):
    'Add the ip address/port to the security group'
    group.authorize_ingress(IpProtocol="tcp", CidrIp=address, FromPort=port, ToPort=port)
    print "Added %s : %i  " % (address, port)

def lambda_handler(event, context):
    'aws lambda main func'
    ports = map(int, os.environ['PORTS_LIST'].split(","))
    if not ports:
        ports = [80]

    security_group = get_aws_security_group(os.environ['SECURITY_GROUP_ID'])
    current_rules = security_group.ip_permissions
    ip_addresses = get_cloudflare_ip_list()

    for ip_address in ip_addresses:
        for port in ports:
            if not check_rule_exists(current_rules, ip_address, port):
                add_rule(security_group, ip_address, port)
