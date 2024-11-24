# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

#!/bin/bash
# Installs the VPC CIDR Vending Machine IPAM solution
# Core stack needs to be created in one master region
# Topic stack can be created in every region that will need to use the VPC CIDR vending machine

set -e

environment="${1:?First argument is the name of the pool (eg. prod)}"
# Optional:
LowIPSpaceAlertEmail01="$2"
LowIPSpaceAlertEmail02="$3"
LowIPSpaceAlertEmail03="$4"

sam_build_argument=""
# Uncomment this to use Docker to build:
#sam_build_argument="--use-container"


echo "Make sure your AWS_PROFILE ($AWS_PROFILE) points to the network account. Press enter to create/update stack for the pool environment $environment"
read x

# Error on unbound variables:
set -u

CORE_STACK=VPC-CIDR-Vender-Core
TOPIC_STACK=VPC-CIDR-Vender-Topic
BACKUP_STACK=VPC-CIDR-Vender-Backups
CLOUDWATCH_STACK=VPC-CIDR-Vender-CloudWatch
organization_id=$(aws --output text organizations describe-organization --query Organization.Id)

# Get stack output
function get_stack_output() {
  local stack="$1"
  local output="$2"

  value=$(aws --output text cloudformation describe-stacks --stack-name $stack --query "Stacks[].Outputs[?OutputKey=='"$output"'].OutputValue[]")

  if [ -z "$value" ]; then
    >&2 echo "Could not get the Output $output from stack $stack"
    return 1
  fi
  echo $value
}

# Get CFN bucket name, or create CFN bucket if it doesn't exist
function get_cfn_bucket() {

  # Check if the install.sh script was used to create the bucket before (i.e. bucket starts with vpc-cidr-vender):
  local bucket_name=$(aws --output text s3api list-buckets --query "Buckets[?starts_with(Name,'vpc-cidr-vender-')].Name")
  if [ -n "$bucket_name" ]; then
    echo $bucket_name
    return
  fi

  # Bucket doesn't exist, so create a bucket:
  local account_id=$(aws --output text sts get-caller-identity --query Account)
  local bucket_name="vpc-cidr-vender-$account_id"
  aws s3 mb s3://$bucket_name
  # Default encryption:
  aws s3api put-bucket-encryption \
    --bucket $bucket_name \
    --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}'
  # Enable versioning:
  aws s3api put-bucket-versioning \
    --bucket $bucket_name \
    --versioning-configuration Status=Enabled
  # Enable public access block:
  aws s3api put-public-access-block \
    --bucket $bucket_name \
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

  echo "$bucket_name"
}

core_stack_name="$CORE_STACK-$environment"
topic_stack_name="$TOPIC_STACK-$environment"
backup_stack_name="$BACKUP_STACK-$environment"
cloudwatch_stack_name="$CLOUDWATCH_STACK-$environment"


# Deploy the Core stack:
sam build --template-file templates/$CORE_STACK.yml $sam_build_argument
sam deploy \
  --s3-bucket $(get_cfn_bucket) \
  --stack-name $core_stack_name \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset \
  --confirm-changeset \
  --parameter-overrides Environment=$environment

# Get VendingMachineARN from previous stack:
vending_machine_arn=$(get_stack_output $core_stack_name CidrVendingMachineArn)
dynamodb_table_arn=$(get_stack_output $core_stack_name CidrTableArn)
backup_table_arn="$dynamodb_table_arn"

# Deploy the Topic stack:
sam build --template-file templates/$TOPIC_STACK.yml $sam_build_argument
sam deploy \
  --s3-bucket $(get_cfn_bucket) \
  --stack-name $topic_stack_name \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
      Environment=$environment \
      CidrVendingMachineArn=$vending_machine_arn \
      OrgID=$organization_id 


# Deploy/update CloudWatch Dashboard:
aws cloudformation deploy \
  --template-file templates/VPC-CIDR-Vender-CloudWatch.yml \
  --stack-name $cloudwatch_stack_name \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
      Environment=$environment \
      LowIPSpaceAlertEmail01=$LowIPSpaceAlertEmail01 \
      LowIPSpaceAlertEmail02=$LowIPSpaceAlertEmail02 \
      LowIPSpaceAlertEmail03=$LowIPSpaceAlertEmail03


# Deploy/update backup stack with table ARN:
aws cloudformation deploy \
  --template-file templates/VPC-CIDR-Backups.yml \
  --stack-name $backup_stack_name \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
      DynamoDBARNs=$backup_table_arn \
      Environment=$environment


