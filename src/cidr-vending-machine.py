#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import os
import json
import logging
import re
import boto3
from botocore.config import Config
from boto3.dynamodb.conditions import Key, Attr
from pprint import pprint
from datetime import datetime
import uuid
import re
from netaddr import IPNetwork, IPSet

# Only used for Cloud Watch metrics:
cloudwatch_metrics_namespace = 'VPC-Cidr-Vending-IPAM'
# The following is used to insert metrics on the number of networks that can be 
# crearted for each of the following /XX prefixes.
cloudwatch_metrics_sample_prefixes = (24, 23, 22, 21, 20)

# Logging configuration:
logging.basicConfig(level=logging.DEBUG)
logging.getLogger('boto3').setLevel(logging.INFO)
logging.getLogger('botocore').setLevel(logging.INFO)
logging.getLogger('urllib3').setLevel(logging.INFO)

# Boto3 configuration:
boto3_config = Config(retries={'max_attempts': 10, 'mode': 'standard'})
boto3_args = { 'config': boto3_config }

# Use local DynamoDB endpoint if running interactively:
if __name__ == '__main__':
    boto3_args['endpoint_url'] = 'http://127.0.0.1:8000'
    # Mock cfnresponse locally:
    class Cfnresponse(object):
        SUCCESS='SUCCESS'
        FAILED='FAILED'
        def send(*k):
            print('')
            print(k)
    cfnresponse = Cfnresponse()
else:
  import cfnresponse
  
dynamodb = boto3.resource('dynamodb', **boto3_args)
cloudwatch_logs = boto3.client('logs', config=boto3_config)
cloudwatch = boto3.client('cloudwatch', config=boto3_config)

# CloudWatch Logs variables.
# If the Lambda function is warm, the following can stick around,
# so that we can re-use the existing log stream.
uuid_str = str(uuid.uuid4())
timestamp_str = datetime.utcnow().strftime('%Y/%m/%d/%H/%M/%S')
log_stream = f'{timestamp_str}-{uuid_str}'
log_request_token = None


def lambda_handler(event, context):
    '''
    Main entry point for the CloudFormation custom resource Lambda
    '''
    logging.info('Event Received:\n%s', json.dumps(event))

    if 'RequestType' in event:
        # Request comes from CloudFormation
        msg = event
        region = os.environ['AWS_REGION']
    elif 'Records' in event:
        # Request comes from SNS, unpack the message body from SNS.
        msg = json.loads(event['Records'][0]['Sns']['Message'])
        region = msg['ServiceToken'].split(':')[3]
    else:
        raise ValueError('Unsupported event. This function only supports CustomResource requests coming from CloudFormation directly or via SNS.')

    responseStatus = cfnresponse.SUCCESS
    responseReason = None
    responseData = {}
    physicalResourceId = msg['PhysicalResourceId'] if 'PhysicalResourceId' in msg else None

    try:
        print(f'Event is: {msg}')
        table = dynamodb.Table(os.environ['CIDR_TABLE'])
        requestType = msg['RequestType']
        stackId = msg['StackId']
        vpcName = msg['ResourceProperties'].get('VpcName', '')
        # RequestCidr was the old name, now renamed to RequestNetwork
        requestNetwork = msg['ResourceProperties'].get('RequestCidr') or msg['ResourceProperties'].get('RequestNetwork')

        if 'SubnetMask' in msg['ResourceProperties']:
            subnetMask = int(str(msg['ResourceProperties']['SubnetMask']))
        else:
            raise ValueError('Missing required property "SubnetMask".')

        if subnetMask < 16 or subnetMask > 28:
            raise ValueError('SubnetMask must be between 16 and 28, inclusive.')

        if requestNetwork and not re.match(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$', requestNetwork):
            raise ValueError('requestNetwork in incorrect format. Expected X.X.X.X (no prefix)')

        if requestNetwork:
            requestCidr = f'{requestNetwork}/{subnetMask}'
        else:
            requestCidr = None

        if requestType == 'Create':
            responseData['Cidr'] = allocate_cidr(table, stackId, subnetMask, region, vpcName, requestCidr)
            physicalResourceId = responseData['Cidr']


        elif requestType == 'Update':
            # This does not support most updates, as a change in the CIDR would recreate a VPC, which is risky.
            # The only update that is supported is the VPC name change.
            existing_cidr = physicalResourceId
            existing_mask = int(existing_cidr.split('/')[1])

            if subnetMask != existing_mask:
                raise ValueError(f'Cannot update subnet mask, this can only be set on creation')
            if requestCidr and requestCidr != existing_cidr:
                raise ValueError(f'Cannot update requested network, this can only be set on creation')

            old_properties = msg['OldResourceProperties']
            old_vpc_name = old_properties.get('VpcName', '')
            # Update the VPC name:
            if old_vpc_name != vpcName:
                cidr = physicalResourceId
                update_vpc_name(table, cidr, vpcName)
                try:
                    log_cloudwatch(
                        {
                            'action': 'RENAME',
                            'cidr': physicalResourceId,
                            'account_id': get_account_id(stackId),
                            'vpc_name': vpcName,
                            'stack_name': get_stack_name(stackId),
                            'region': region,
                            'message': f'Updated VPC name from {old_vpc_name} to {vpcName}.'
                        }
                    )
                except:
                    pass

        elif requestType == 'Delete':
            # physicalResourceId is the previously vended CIDR:
            if physicalResourceId == None:
                raise ValueError('Unable to get PhysicalResourceId, which is required for deletion.')
            # Check if the physicalResourceId is a valid CIDR:
            if re.match(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/\d{1,2}$', physicalResourceId):
                cidr = physicalResourceId
                deallocate_cidr(table, cidr)
                try:
                    log_cloudwatch(
                        {
                            'action': 'REMOVE',
                            'cidr': cidr,
                            'account_id': get_account_id(stackId),
                            'vpc_name': vpcName,
                            'stack_name': get_stack_name(stackId),
                            'region': region,
                            'message': f'The VPC {vpcName} was deleted, successfully released {cidr} from pool.'
                        }
                    )
                except:
                    pass
        else:
            raise ValueError('Unsupported request type "{0}".'.format(requestType))
    except Exception as ex:
        responseStatus = cfnresponse.FAILED
        responseReason = ex
        logging.error(ex)

    cfnresponse.send(msg, context, responseStatus, responseReason, responseData, physicalResourceId)


def metric_update(event=None, context=None):
    '''
    Updates the CloudWatch metrics.
    Also entry point for the scheduled lambda that updates the metrics every 24 hours.
    This is done to have some metrics in the CloudWatch Dashboard if there was
    no VPC Cidr requests in the past several days/weeks.
    '''

    table_name = os.environ['CIDR_TABLE']
    table = dynamodb.Table(table_name)
    ddb_table = scan_table(table)
    region = os.environ['AWS_REGION']

    generate_cloudwatch_metrics_from_table_data(table_name, ddb_table, region)


def generate_cloudwatch_metrics_from_table_data(table_name:str, ddb_table:list, region:str):
    '''
    Write CloudWatch metric data using the given entire scanned DDB table.

    Parameters:
        table_name: DynamoDB table name, eg. Cidrs-sandbox
        ddb_table: Output of scan_table(), which is a Python list of dicts representing DDB
        region: Region string

    Returns: None
    '''
    # Number of DDB entries that are marked as USED
    number_of_used_entries = 0

    # List of Metric data to insert to CloudWatch:
    metric_data = []

    # Keep track of all available & used IP space
    available_space = IPSet()
    used_space = IPSet()

    # Populate the available and allocated space:
    for item in ddb_table:
        try:
            cidr = item['cidr']
            if item['allocation_status'] == f'{region}:AVAILABLE':
                available_space.add(cidr)
            elif item['allocation_status'] == f'{region}:USED':
                number_of_used_entries += 1
                used_space.add(cidr)
        except Exception as e:
            # Corrupt item.
            logging.warning(str(e))

    # Minus used space from available space
    available_space = available_space - used_space

    def make_metric_data(name, value):
        return {
            'MetricName': name,
            'Dimensions': [
                {
                    'Name': 'Table',
                    'Value': table_name
                }
            ],
            'Unit': 'Count',
            'Value': value
        }


    logging.info(f'Metrics - Number of {region}:USED entries: {number_of_used_entries}')
    metric_data.append(make_metric_data('NumberOfUsedEntries', number_of_used_entries))

    # Calculate the potential space for common prefixes:
    for prefix in cloudwatch_metrics_sample_prefixes:
        number_of_networks = 0
        for available_network in available_space.iter_cidrs():
            number_of_networks += len(list(available_network.subnet(prefix)))
        logging.info(f'Metrics - Number of potential /{prefix} networks: {number_of_networks}')    
        metric_data.append(make_metric_data(f'NumberOfPotential{prefix}Networks', number_of_networks))


    # Write to CloudWatch metrics:
    # Skip this if it running locally:
    if __name__ == '__main__':
        return
    try:
        cloudwatch.put_metric_data(MetricData=metric_data, Namespace=cloudwatch_metrics_namespace)
    except Exception as e:
        logging.error('Could not write to CloudWatch metrics')
        logging.error(str(e))


def log_cloudwatch(message_dict):
    '''
    Log given message dict to CloudWatch log as a JSON message.
    '''
    # If LOG_GROUP is not set (eg. running locally), just pretty print it:
    log_group = os.environ.get('LOG_GROUP')
    if not log_group:
        pprint(message_dict)
        return

    try:
        global log_request_token
        message = json.dumps(message_dict)

        if not log_request_token:
            cloudwatch_logs.create_log_stream(
                logGroupName=log_group,
                logStreamName=log_stream,
            )
        put_log_args = {
            'logGroupName': log_group,
            'logStreamName': log_stream,
            'logEvents': [
                {
                    'timestamp': int(datetime.now().timestamp() * 1000),
                    'message': message
                }
            ]
        }
        if log_request_token:
            put_log_args['sequenceToken'] = log_request_token

        response = cloudwatch_logs.put_log_events(**put_log_args)
        log_request_token = response['nextSequenceToken']

    except Exception as e:
        logging.warn(e)
        print(message_dict)



def scan_table(table):
    # Returns a full scan of the entire DDB table
    # As the IPAM database is only likely to contain less than 5000 VPCs
    # (most likely < 500 VPCs), and because the IPAM is only called in the 
    # event of a VPC creation, the RCU cost (on-demand) is acceptable.
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


def mark_cidr_as_used(cidr, table, stackId, region, vpcName):
    '''
    Marks given CIDR as used in the DynamoDB Table.
    
    Parameters:
        cidr: CIDR string in X.X.X.X/X format
        table: DynamoDB table boto3 resource
        stackId: The CloudFormation stack ARN, used to get the account ID & stack name.
        region: AWS region string
        vpcName: Name of the VPC, for informational purposes in DDB.

    Returns: None.
    '''
    accountId = get_account_id(stackId)
    stackName = get_stack_name(stackId)
    subnetMask = int(cidr.split('/')[1])

    table.put_item(
        Item = {
            'cidr': cidr,
            'allocation_status': f'{region}:USED',
            'subnet_mask': subnetMask,
            'account_id': accountId,
            'vpc_name': vpcName,
            'stack_name': stackName,   
        }
    )
    logging.info(f'Marked {cidr} as USED')
    log_cloudwatch(
        {
            'action': 'ADD',
            'cidr': cidr,
            'account_id': accountId,
            'vpc_name': vpcName,
            'stack_name': stackName,
            'region': region,
            'message': f'Allocated {cidr} for the VPC {vpcName}, and marking it as USED.'
        }
    )



def allocate_cidr(table, stackId, subnetMask, region, vpcName, requestCidr=None):
    '''
    Finds an available CIDR with the given subnetMask from the DynamoDB table.
    If the requestCidr is given, check if the cidr is available or allocated.
    If successful, inserts it into the DDB table as USED, and returns it.
    
    Parameters:
        table: DynamoDB table boto3 resource
        stackId: The CloudFormation stack ARN, used to get the account ID & stack name.
        subnetMask: The CIDR prefix requested, eg. 24
        region: AWS region string
        vpcName: Name of the VPC, for informational purposes in DDB.
        requestCidr: Either None, or a specific CIDR to check+return (X.X.X.X/X).

    Returns: A CIDR string (eg. 10.113.0.1/24).
    '''
    ddb_table = scan_table(table)

    # Keep track of all available IP space (list of supernets)
    available_space = IPSet()
    # Keep track of all allocate space, which is not vended automatically until requested specifically:
    allocated_space = IPSet()
    # Keep track of used IP space
    used_space = IPSet()

    # Populate the available and allocated space:
    for item in ddb_table:
        try:
            cidr = item['cidr']
            if item['allocation_status'] == f'{region}:AVAILABLE':
                available_space.add(cidr)
            elif item['allocation_status'] == f'{region}:ALLOCATED':
                allocated_space.add(cidr)
            elif item['allocation_status'] == f'{region}:USED':
                used_space.add(cidr)
        except Exception as e:
            # Corrupt item.
            logging.warning(str(e))

    # Minus used space from available space
    available_space = available_space - used_space
    allocated_space = allocated_space - used_space
    # Available space for vended IPs should not include allocated space:
    available_space = available_space - allocated_space

    logging.debug(f'Available space is {available_space}')
    logging.debug(f'Allocated space is {allocated_space}')


    # If there is a specific CIDR requested, make sure it's available:
    if requestCidr:
        # Make sure it matches the pattern:
        requestCidrMask = int(requestCidr.split('/')[1])
        if requestCidrMask != int(subnetMask):
            raise ValueError(f'Requested CIDR ({requestCidr}) and mask ({subnetMask}) does not match')
        requestCidr = IPNetwork(requestCidr)
        if requestCidr in allocated_space or requestCidr in available_space:
            mark_cidr_as_used(str(requestCidr), table, stackId, region, vpcName)
            # Update the local in memory of the table to add the USED CIDR.
            # This is for the metrics generation later:
            ddb_table.append(
                {'cidr': str(requestCidr), 'allocation_status': f'{region}:USED'}
            )
            table_name = table.table_name
            generate_cloudwatch_metrics_from_table_data(table_name,ddb_table, region)
            return str(requestCidr)
        else:
            error_message = f'Requested CIDR ({str(requestCidr)}) by the VPC {vpcName} is not available in the pool.'
            try:
                log_cloudwatch(
                    {
                        'action': 'FAILED',
                        'account_id': get_account_id(stackId),
                        'vpc_name': vpcName,
                        'stack_name': get_stack_name(stackId),
                        'region': region,
                        'message': error_message
                    }
                )
            except:
                pass
            raise ValueError(error_message)

    # Otherwise, pick the first subnet available (not allocated) for the given mask.
    # Do this by trying to split the available network ranges into the given mask:
    for available_network in available_space.iter_cidrs():
        try:
            free_cidr = list(available_network.subnet(int(subnetMask)))[0]
            # If we didn't throw an exception, this is it:
            mark_cidr_as_used(str(free_cidr), table, stackId, region, vpcName)
            
            # Update the local in memory of the table to add the USED CIDR.
            # This is for the metrics generation later:
            ddb_table.append(
                {'cidr': free_cidr, 'allocation_status': f'{region}:USED'}
            )

            # Update metrics
            table_name = table.table_name
            generate_cloudwatch_metrics_from_table_data(table_name,ddb_table, region)

            # Return the chosen CIDR:
            return str(free_cidr)
        except:
            pass

    # If we didn't return in the above loop, it means we are out of space:
    error_message = f'There is no more space available in the pool for the given mask ({subnetMask})'
    try:
        log_cloudwatch(
            {
                'action': 'FAILED',
                'account_id': get_account_id(stackId),
                'vpc_name': vpcName,
                'stack_name': get_stack_name(stackId),
                'region': region,
                'message': error_message
            }
        )
    except:
        pass
    raise ValueError(error_message)


def deallocate_cidr(table, cidr:str):
    table.delete_item(
        Key = { 'cidr': cidr }
    )
    logging.info(f'Successfully deallocated CIDR {cidr}')

    # Try to update the CloudWatch metrics:
    metric_update()


def update_vpc_name(table, cidr:str, vpc_name:str):
    # Updates the vpc_name for the given cidr
    table.update_item(
        Key={'cidr': cidr},
        UpdateExpression='SET vpc_name = :new_vpc_name',
        ExpressionAttributeValues={
            ':new_vpc_name': vpc_name
        }
    )
    logging.info(f'Updated VPC name of CIDR {cidr} to {vpc_name}')

def get_account_id(stackId):
    return stackId.split(':')[4]

def get_stack_name(stackId):
    return stackId.split(':')[5].split('/')[1]


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Simulate IPAM locally')
    parser.add_argument('--action', help='Either Create, Update or Delete', required=True)
    parser.add_argument('--stack-arn', help='Fake/mock CloudFormation stack ARN', required=True)
    parser.add_argument('--mask', help='VPC mask, eg. 24', required=True)
    parser.add_argument('--vpc-name', help='Fake VPC name, eg. Test', required=True)
    parser.add_argument('--physical-id', help='Required for deletion. Physical ID should be set to the CIDR allocated.')
    parser.add_argument('--request-cidr', help='Request specific CIDR and insert it into the database')
    args = parser.parse_args()

    # Call Lambda handler with fake JSON:
    event = {
        "RequestType": args.action,
        "StackId": args.stack_arn,
        "LogicalResourceId": "AutomaticVPCCidr",
        "ResourceProperties": {
            "SubnetMask": args.mask,
            "VpcName": args.vpc_name
        }
    }
    if args.physical_id:
        event['PhysicalResourceId'] = args.physical_id
    if args.request_cidr:
        event['ResourceProperties']['RequestCidr'] = args.request_cidr


    lambda_handler(event, None)
