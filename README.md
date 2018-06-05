cloudflare-ip-security-group-update
===================================

This Lambda function to retrieve Cloudflare's IP address list and
update an AWS security group was originally written by John McCracken
(johnmccuk@gmail.com).

Instructions
------------

The Lambda uses the Python 2.7 runtime and requires the following
enviroment variables:

* `SECURITY_GROUP_ID` - the group ID for the specified security group
* `PORTS_LIST` - comma-separated list of ports e.g. `80,443`. If none
  is specified, the default is port 80.
