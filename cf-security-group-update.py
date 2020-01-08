import os
import boto3
import json
from botocore.vendored import requests


def get_cloudflare_ip_list():
    """ Call the CloudFlare API and return a list of IPs """
    response = requests.get('https://api.cloudflare.com/client/v4/ips')
    temp = response.json()
    if 'result' in temp:
        return temp['result']
    raise Exception("Cloudflare response error")

def get_aws_s3_bucket_policy(s3_id):
    """ Return the Policy of an S3 """
    s3 = boto3.client('s3')
    result = s3.get_bucket_policy(Bucket=s3_id)
    if not 'Policy' in result:
        raise Exception("Failed to retrieve Policy from S3 %s" % (s3_id))
    policy = json.loads(result['Policy'])
    return { 'id' : s3_id, s3_id : policy }


def get_aws_security_group(group_id):
    """ Return the defined Security Group """
    ec2 = boto3.resource('ec2')
    group = ec2.SecurityGroup(group_id)
    if group.group_id == group_id:
        return group
    raise Exception('Failed to retrieve Security Group')


def check_ipv4_rule_exists(rules, address, port):
    """ Check if the rule currently exists """
    for rule in rules:
        for ip_range in rule['IpRanges']:
            if ip_range['CidrIp'] == address and rule['FromPort'] == port:
                return True
    return False


def add_ipv4_rule(group, address, port):
    """ Add the IP address/port to the security group """
    group.authorize_ingress(IpProtocol="tcp",
                            CidrIp=address,
                            FromPort=port,
                            ToPort=port)
    print("Added %s : %i to %s  " % (address, port, group.group_id))


def delete_ipv4_rule(group, address, port):
    """ Remove the IP address/port from the security group """
    group.revoke_ingress(IpProtocol="tcp",
                         CidrIp=address,
                         FromPort=port,
                         ToPort=port)
    print("Removed %s : %i from %s  " % (address, port, group.group_id))


def check_ipv6_rule_exists(rules, address, port):
    """ Check if the rule currently exists """
    for rule in rules:
        for ip_range in rule['Ipv6Ranges']:
            if ip_range['CidrIpv6'] == address and rule['FromPort'] == port:
                return True
    return False


def add_ipv6_rule(group, address, port):
    """ Add the IP address/port to the security group """
    group.authorize_ingress(IpPermissions=[{
        'IpProtocol': "tcp",
        'FromPort': port,
        'ToPort': port,
        'Ipv6Ranges': [
            {
                'CidrIpv6': address
            },
        ]
    }])
    print("Added %s : %i to %s  " % (address, port, group.group_id))


def delete_ipv6_rule(group, address, port):
    """ Remove the IP address/port from the security group """
    group.revoke_ingress(IpPermissions=[{
        'IpProtocol': "tcp",
        'FromPort': port,
        'ToPort': port,
        'Ipv6Ranges': [
            {
                'CidrIpv6': address
            },
        ]
    }])
    print("Removed %s : %i from %s  " % (address, port, group.group_id))

def update_s3_policies_policies(ip_addresses):
    """ Update S3 policies """
    print("Checking policies of S3")

    s3 = boto3.client('s3')

    ipv4 = ip_addresses['ipv4_cidrs']
    ipv6 = ip_addresses['ipv6_cidrs']

    cloudflare_ips = ipv4 + ipv6

    if not "S3_CLOUDFLARE_SID" in os.environ:
        print("Not configured 'S3_CLOUDFLARE_SID' variable, so will not check S3")
        return

    if not "S3_BUCKET_IDS_LIST" in os.environ and not "S3_BUCKET_ID" in os.environ:
        raise Exception("Missing S3 basic configuration 'S3_BUCKET_IDS_LIST' or 'S3_BUCKET_ID'.") 

    sid = os.environ['S3_CLOUDFLARE_SID']
    s3_policy_tuple = map(get_aws_s3_bucket_policy, os.environ['S3_BUCKET_IDS_LIST'].split(","))
    if not s3_policy_tuple:
        s3_policy_tuple = [get_aws_s3_bucket_policy(os.environ['S3_BUCKET_ID'])]

    for s3_tuple in s3_policy_tuple:
        updated = False
        s3_id = s3_tuple['id']
        print("Checking Policy of S3 Bucket '%s'" % (s3_id) )
        policy = s3_tuple[s3_id]
        if not 'Statement' in policy:
            raise Exception("Problem reading policy of S3 Bucket '%s'" % (s3_id) )
        for statement in policy['Statement']:
            if not "Sid" in statement:
                raise Exception("Problem reading Sid inside Statement of S3 Bucket '%s'" % (s3_id) )
            if ((not sid == statement['Sid']) or
              (not "Condition" in statement) or
              (not "IpAddress" in statement["Condition"]) or
              (not "aws:SourceIp" in statement["Condition"]["IpAddress"])):
                continue

            statement["Condition"]["IpAddress"]["aws:SourceIp"] = cloudflare_ips
            updated = True

        if updated:
            policy = json.dumps(policy)
            print("Going to update policy %s " % (s3_id) )
            s3.put_bucket_policy(Bucket=s3_id, Policy=policy)

def update_security_group_policies(ip_addresses):
    """ Update Information of Security Groups """
    print("Checking policies of Security Groups")

    if not "SECURITY_GROUP_IDS_LIST" in os.environ and not "SECURITY_GROUP_ID" in os.environ:
        print("Missing S3 basic configuration 'SECURITY_GROUP_IDS_LIST' or 'SECURITY_GROUP_ID'. Will not check Security Policy.") 
        return
   
    ports = map(int, os.environ['PORTS_LIST'].split(","))
    if not ports:
        ports = [80]

    security_groups = map(get_aws_security_group, os.environ['SECURITY_GROUP_IDS_LIST'].split(","))
    if not security_groups:
        security_groups = [get_aws_security_group(os.environ['SECURITY_GROUP_ID'])]
    
    ## Security Groups
    for security_group in security_groups: 
        current_rules = security_group.ip_permissions
        ## IPv4
        # add new addresses
        for ipv4_cidr in ip_addresses['ipv4_cidrs']:
            for port in ports:
                if not check_ipv4_rule_exists(current_rules, ipv4_cidr, port):
                    add_ipv4_rule(security_group, ipv4_cidr, port)
    
        # remove old addresses
        for port in ports:
            for rule in current_rules:
                # is it necessary/correct to check both From and To?
                if rule['FromPort'] == port and rule['ToPort'] == port:
                    for ip_range in rule['IpRanges']:
                        if ip_range['CidrIp'] not in ip_addresses['ipv4_cidrs']:
                            delete_ipv4_rule(security_group, ip_range['CidrIp'], port)
    
        ## IPv6 -- because of boto3 syntax, this has to be separate
        # add new addresses
        for ipv6_cidr in ip_addresses['ipv6_cidrs']:
            for port in ports:
                if not check_ipv6_rule_exists(current_rules, ipv6_cidr, port):
                    add_ipv6_rule(security_group, ipv6_cidr, port)
    
        # remove old addresses
        for port in ports:
            for rule in current_rules:
                for ip_range in rule['Ipv6Ranges']:
                    if ip_range['CidrIpv6'] not in ip_addresses['ipv6_cidrs']: 
                        delete_ipv6_rule(security_group, ip_range['CidrIpv6'], port)


def lambda_handler(event, context):
    """ AWS Lambda main function """
    
    ip_addresses = get_cloudflare_ip_list()

    update_security_group_policies(ip_addresses)

    update_s3_policies_policies(ip_addresses)
