cloudflare-ip-security-group-update
===================================

This Lambda function to retrieve Cloudflare's IP address list and
update an AWS Security Group and S3 Policies.

It was originally written by John McCracken (johnmccuk@gmail.com), 
updated by Ryan Gibbons (rtgibbons) and Endrigo Antonini (antonini).

Instructions
------------

Use the content of the file `cf-security-group-update.py` in your lambda ou upload it.

It is also required that you upload or create the `package` file as is available on this repository.

The Lambda uses the Python 2.7 runtime and requires the following
enviroment variables:

* `SECURITY_GROUP_IDS_LIST` - a list of security group IDs to update
* `SECURITY_GROUP_ID` - If list is undefined, a group ID for the specified security group
* `PORTS_LIST` - comma-separated list of ports e.g. `80,443`.
* `S3_CLOUDFLARE_SID` - Sid that stores all the CloudFlare configurataion. That Sid is stored on the Stament policy.
* `S3_BUCKET_IDS_LIST` - a list of S3 buckets IDs to update
* `S3_BUCKET_ID` - if list is undefined, a ID for the specified S3 bucket.
* `UPDATE_IPV6` - if set to 0, will not update IPv6 ranges in security groups nor S3 bucket policies.

You need to allow the Lambda to execute those actions (example on the file `allow-lambda-ingress-role`:

* ec2:AuthorizeSecurityGroupIngress
* ec2:RevokeSecurityGroupIngress
* ec2:DescribeSecurityGroup
* s3:GetBucketPolicyStatus
* s3:PutBucketPolicy
* s3:GetBucketPolicy



To update Security Groups
------------

You need to define at least `SECURITY_GROUP_ID` or `SECURITY_GROUP_IDS_LIST`.
The parameter `PORTS_LIST` is also used to update an AWS Security Group.

To update S3 Policy
------------

You need to define the parameter `S3_CLOUDFLARE_SID` and at least one of the
following parameters `S3_BUCKET_IDS_LIST` or `S3_BUCKET_ID`.

Contributors
-----------

* John McCracken ([@johnmccuk](https://www.github.com/johnmccuk))
* Ryan Gibbons ([@rtgibbons](https://www.github.com/rtgibbons)) 
* Ben Steinberg ([@bensteinberg](https://www.github.com/bensteinberg))
* Endrigo Antonini ([@antonini](https://www.github.com/antonini))
