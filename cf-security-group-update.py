import os
import boto3
import json
import urllib3


def get_cloudflare_ip_list():
    """ Call the CloudFlare API and return a list of IPs """
    http = urllib3.PoolManager()
    response = http.request('GET', 'https://api.cloudflare.com/client/v4/ips')
    temp = json.loads(response.data.decode('utf-8'))
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
    group.authorize_ingress(
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': port,
                'ToPort': port,
                'IpRanges': [
                    {
                        'CidrIp': address,
                        'Description': 'from https://api.cloudflare.com/client/v4/ips'
                    },
                ]
            },
        ]
    )
    print("Added %s : %i to %s (%s) " % (address, port, group.group_id, group.group_name))


def delete_ipv4_rule(group, address, port):
    """ Remove the IP address/port from the security group """
    group.revoke_ingress(IpProtocol="tcp",
                         CidrIp=address,
                         FromPort=port,
                         ToPort=port)
    print("Removed %s : %i from %s (%s) " % (address, port, group.group_id, group.group_name))


def check_ipv6_rule_exists(rules, address, port):
    """ Check if the rule currently exists """
    for rule in rules:
        for ip_range in rule['Ipv6Ranges']:
            if ip_range['CidrIpv6'] == address and rule['FromPort'] == port:
                return True
    return False


def add_ipv6_rule(group, address, port):
    """ Add the IP address/port to the security group """
    group.authorize_ingress(
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': port,
                'ToPort': port,
                'Ipv6Ranges': [
                    {
                        'CidrIpv6': address,
                        'Description': 'from https://api.cloudflare.com/client/v4/ips'
                    },
                ]
            },
        ]
    )
    print("Added %s : %i to %s (%s) " % (address, port, group.group_id, group.group_name))


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
    print("Removed %s : %i from %s (%s) " % (address, port, group.group_id, group.group_name))

def get_update_ipv6():
    try:
        return bool(int(os.environ['UPDATE_IPV6']))
    except (KeyError, ValueError):
        return True

def update_s3_policies_policies(ip_addresses):
    """ Update S3 policies """
    print("Checking policies of S3")

    s3 = boto3.client('s3')

    if not "S3_CLOUDFLARE_SID" in os.environ:
        print("Not configured 'S3_CLOUDFLARE_SID' variable, so will not check S3")
        return

    if not "S3_BUCKET_IDS_LIST" in os.environ and not "S3_BUCKET_ID" in os.environ:
        raise Exception("Missing S3 basic configuration 'S3_BUCKET_IDS_LIST' or 'S3_BUCKET_ID'.")

    ipv4 = ip_addresses['ipv4_cidrs']
    ipv6 = ip_addresses['ipv6_cidrs']

    if get_update_ipv6():
        cloudflare_ips = ipv4 + ipv6
    else:
        print('Not updating IPv6 ranges in S3 policies.')
        cloudflare_ips = ipv4

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

    try:
        security_groups = os.environ['SECURITY_GROUP_IDS_LIST']
    except KeyError:
        try:
            security_groups = os.environ['SECURITY_GROUP_ID']
        except KeyError:
            print('Missing environment variables SECURITY_GROUP_IDS_LIST and SECURITY_GROUP_ID. Will not update security groups.')
            return

    security_groups = map(get_aws_security_group, security_groups.split(','))

    try:
        ports = os.environ['PORTS_LIST']
    except KeyError:
        ports = '80,443'

    ports = map(int, ports.split(','))

    if (not ports) or (not security_groups):
        raise Exception('At least one TCP port and one security group ID are required.')

    ## Security Groups
    for security_group in security_groups:
        current_rules = security_group.ip_permissions
        for port in ports:
            ## IPv4
            # add new addresses
            for ipv4_cidr in ip_addresses['ipv4_cidrs']:
                if not check_ipv4_rule_exists(current_rules, ipv4_cidr, port):
                    add_ipv4_rule(security_group, ipv4_cidr, port)

            # remove old addresses
            for rule in current_rules:
                # is it necessary/correct to check both From and To?
                if rule['IpProtocol'] == 'tcp' and rule['FromPort'] == port and rule['ToPort'] == port:
                    for ip_range in rule['IpRanges']:
                        if ip_range['CidrIp'] not in ip_addresses['ipv4_cidrs']:
                            delete_ipv4_rule(security_group, ip_range['CidrIp'], port)

            ## IPv6 -- because of boto3 syntax, this has to be separate
            if get_update_ipv6():
                # add new addresses
                for ipv6_cidr in ip_addresses['ipv6_cidrs']:
                    if not check_ipv6_rule_exists(current_rules, ipv6_cidr, port):
                        add_ipv6_rule(security_group, ipv6_cidr, port)

                # remove old addresses
                for rule in current_rules:
                    if rule['IpProtocol'] == 'tcp' and rule['FromPort'] == port and rule['ToPort'] == port:
                        for ip_range in rule['Ipv6Ranges']:
                            if ip_range['CidrIpv6'] not in ip_addresses['ipv6_cidrs']:
                                delete_ipv6_rule(security_group, ip_range['CidrIpv6'], port)
            else:
                print('Not updating IPv6 ranges in security groups.')

def lambda_handler(event, context):
    """ AWS Lambda main function """

    ip_addresses = get_cloudflare_ip_list()

    update_security_group_policies(ip_addresses)

    update_s3_policies_policies(ip_addresses)
