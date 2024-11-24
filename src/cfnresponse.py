import requests
import json

SUCCESS = 'SUCCESS'
FAILED = 'FAILED'

def send(event, context, responseStatus, responseReason, responseData, physicalResourceId = None, noEcho = False):
    responseUrl = event['ResponseURL']

    print(responseUrl)

    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['Reason'] = '{}See CloudWatch Log Stream "{}" for more details.'.format(str(responseReason) + ' ' if responseReason else '', context.log_stream_name)
    responseBody['PhysicalResourceId'] = physicalResourceId or context.log_stream_name
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['NoEcho'] = noEcho
    responseBody['Data'] = responseData

    json_responseBody = json.dumps(responseBody)

    print('Response body:\n' + json_responseBody)

    headers = {
        'content-type': '',
        'content-length': str(len(json_responseBody))
    }

    try:
        response = requests.put(responseUrl, data = json_responseBody, headers = headers)
        print('Status code: ' + response.reason)
    except Exception as e:
        print('Failed executing requests.put: {}'.format(e))
