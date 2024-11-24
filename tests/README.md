# Testing IP allocation

### Create local DynamoDB instance

In a terminal, run:

```
docker run --rm -p 8000:8000 amazon/dynamodb-local
```

Then copy and paste the YAML DynamoDB table definition from CloudFormation (everything under `Properties`) into a file called ipam-table.yaml in this folder. In this YAML file, rename the TableName (which has a !Sub) to 'Cidrs-local'. 

Run:

```
export AWS_DEFAULT_REGION=ap-southeast-2
export AWS_ACCESS_KEY_ID=X
export AWS_SECRET_ACCESS_KEY=X

aws dynamodb create-table --cli-input-yaml file://ipam-table.yaml --endpoint-url http://localhost:8000
```

Insert the supernet into the DB:

```
aws dynamodb put-item \
  --endpoint-url http://localhost:8000 \
  --table-name Cidrs-local \
  --item '
      {
        "cidr": {
          "S": "10.113.0.0/16"
        },
        "allocation_status": {
          "S": "ap-southeast-2:AVAILABLE"
        },
        "subnet_mask": {
          "N": "16"
        }
      }
  '
```

If you want to view the DynamoDB table in a web interface, try this third party solution: [https://github.com/aaronshaf/dynamodb-admin](https://github.com/aaronshaf/dynamodb-admin):

```
export AWS_DEFAULT_REGION=ap-southeast-2
export AWS_ACCESS_KEY_ID=X
export AWS_SECRET_ACCESS_KEY=X
DYNAMO_ENDPOINT=http://localhost:8000 dynamodb-admin
# Load the URL in the output in a web browser.
```


Then pretend to be a VPC requesting for a resource:

```
cd ../src/
export AWS_DEFAULT_REGION=ap-southeast-2
export AWS_ACCESS_KEY_ID=X
export AWS_SECRET_ACCESS_KEY=X
export AWS_REGION=$AWS_DEFAULT_REGION
export CIDR_TABLE=Cidrs-local
./cidr-vending-machine.py --action Create --stack-arn arn:aws:cloudformation:ap-southeast-2:012345678901:stack/Test/aaaabbbb --mask 24 --vpc-name MyVPC
```

To delete, get the X.X.X.X/X output of the previous stack, and run:

```
cidr=1.2.3.4/24 #<--- Replace
./cidr-vending-machine.py --action Delete --stack-arn arn:aws:cloudformation:ap-southeast-2:012345678901:stack/Test/aaaabbbb --mask 24 --vpc-name MyVPC --physical-id $cidr

```



