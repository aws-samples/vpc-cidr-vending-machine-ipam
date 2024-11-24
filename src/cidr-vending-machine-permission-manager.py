# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import boto3
import cfnresponse
import json, logging, uuid

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


def lambda_handler(event, context):
    LOGGER.info('Event Received:\n%s', json.dumps(event))

    responseStatus = cfnresponse.SUCCESS
    responseReason = None
    responseData = {}
    physicalResourceId = event['PhysicalResourceId'] if 'PhysicalResourceId' in event else None

    try:
        requestType = event['RequestType']
        properties = event['ResourceProperties']
        sourceArn = properties['SourceArn']
        functionName = properties['FunctionName']
        functionRegion = properties.get('FunctionRegion', None)

        client = boto3.client('lambda', region_name = functionRegion)

        if requestType == 'Create' or requestType == 'Update':
            stmtId = str(uuid.uuid4())
            client.add_permission(
                Principal = 'sns.amazonaws.com',
                Action = 'lambda:InvokeFunction',
                SourceArn = sourceArn,
                FunctionName = functionName,
                StatementId = stmtId,
            )
            physicalResourceId = stmtId

        elif requestType == 'Delete':
            if physicalResourceId:
                client.remove_permission(
                    FunctionName = functionName,
                    StatementId = physicalResourceId
                )
        else:
            raise ValueError('Unsupported request type "{0}".'.format(requestType))

    except Exception as ex:
        responseStatus = cfnresponse.FAILED
        responseReason = ex
        LOGGER.error(ex)

    cfnresponse.send(event, context, responseStatus, responseReason, responseData, physicalResourceId)
