# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

#!/usr/bin/env python3
# Upgrade script, to delete all old AVAILABLE entries

import argparse
import boto3
from botocore.config import Config
boto3_config = Config(retries={'max_attempts': 10, 'mode': 'standard'})
dynamodb = boto3.resource('dynamodb', config=boto3_config)
region = 'ap-southeast-2'

def scan_table(table):
    return_list = []
    scan_kwargs = {}
    done = False
    start_key = None
    while not done:
        if start_key:
            scan_kwargs['ExclusiveStartKey'] = start_key
        response = table.scan(**scan_kwargs)
        items = response.get('Items', [])
        return_list.extend(items)
        start_key = response.get('LastEvaluatedKey', None)
        done = start_key is None
    return return_list

parser = argparse.ArgumentParser(description='Delete old AVAILABLE entries')
parser.add_argument(
    '--table', help='DynamoDB table name (eg. Cidrs-sandbox)', required=True)
args = parser.parse_args()
table = dynamodb.Table(args.table)
ddb_table = scan_table(table)
for item in ddb_table:
  cidr = item['cidr']
  if item['allocation_status'] == f'{region}:AVAILABLE':
    # Check if it has the old "parent_cidr" attribute:
    if item.get('parent_cidr'):
      print(f'Deleting AVAILABLE cidr {cidr}...')
      table.delete_item(
          Key={'cidr': cidr}
      )
print('Done')