import boto3
import json
import os
from datetime import datetime, timezone

def handler(event, context):

    print(event['detail']['eventName'])

    account = os.environ['AWS_ACCOUNT']
    region = os.environ['REGION']

    now = datetime.now(timezone.utc).isoformat().replace('+00:00','Z')

    securityhub_client = boto3.client('securityhub')

    securityhub_response = securityhub_client.batch_import_findings(
        Findings = [
            {
                "SchemaVersion": "2018-10-08",
                "Id": region+"/"+account+"/alert",
                "ProductArn": "arn:aws:securityhub:"+region+":"+account+":product/"+account+"/default", 
                "GeneratorId": "ct-alert",
                "AwsAccountId": account,
                "CreatedAt": now,
                "UpdatedAt": now,
                "Title": "Alert",
                "Description": str(event['detail']['eventName'])+" event in "+str(region)+" for account "+str(account),
                "Resources": [
                    {
                        "Type": "AwsLambda",
                        "Id": "arn:aws:lambda:"+region+":"+account+":function:alert"
                    }
                ],
                "FindingProviderFields": {
                    "Confidence": 100,
                    "Severity": {
                        "Label": "CRITICAL"
                    },
                    "Types": [
                        "security/ct/alert"
                    ]
                }
            }
        ]
    )

    print(securityhub_response)

    return {
        'statusCode': 200,
        'body': json.dumps('Expediate Alert')
    }