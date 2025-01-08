import boto3
import json
from datetime import datetime

def lambda_handler(event, context):
    # Retrieve the roleName from the GuardDuty Finding.
    role_name = event['detail']['resource']['accessKeyDetails']['userName']

    # Extract the GuardDuty event time and format it.
    event_time = event['detail']['updatedAt']
    formatted_event_time = datetime.strptime(event_time, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%dT%H:%M:%S")

    # Attach the IAM Policy to revoke all active sessions for the role
    iam_client = boto3.client('iam')
    policy_name = 'RevokeCredentialsPolicy'
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "RevokeCredentials",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "DateLessThan": {
                        "aws:TokenIssueTime": formatted_event_time
                    }
                }
            }
        ]
    }
    response = iam_client.create_policy(
        PolicyName=policy_name,
        PolicyDocument=json.dumps(policy_document)
    )

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        # Get the policy ARN
        policy_arn = response['Policy']['Arn']

        # Attach the policy to the role
        attach_response = iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn
        )
        if attach_response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return {
                'statusCode': 200,
                'body': f"Successfully attached policy to revoke permissions for temporary credentials for role: {role_name}"
            }
        return {
            'statusCode': response['ResponseMetadata']['HTTPStatusCode'],
            'body': f"Error attaching policy to revoke permissions for temporary credentials for role: {role_name}"
        }