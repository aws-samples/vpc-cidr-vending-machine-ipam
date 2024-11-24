This is optional, and can be run on a _member_ account to test the VPC allocation without actually creating a VPC

It outputs the VPC CIDR, and you can verify that the Cidr DynamoDB table has that range as USED

If you delete the template, that CIDR range should be back to AVAILABLE
