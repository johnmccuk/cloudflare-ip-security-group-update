# cloudflare-ip-security-group-update
Lambda function to retrieve Cloudflare's IP address list and update the specified security group

John McCracken (johnmccuk@gmail.com)

26/02/17

https://github.com/johnmccuk/cloudflare-ip-security-group-update


###Instructions
Python 2.7 code which should be placed in an AWS Lambda function and performs the following:
* Calls Cloudlfare API and returns the latest list of IP addresses
* Retrieves the specified AWS Security Goup
* Adds any IP addreses to the Security Group rules for ports 80 and 443

The Lambda requires the following Lambda enviromental varibles:
* SECURITY_GROUP_ID - the group ID for the specified security group
* PORTS_LIST - comma seperated list of ports i.e. "80,443". If none is specified, port 80 is used
