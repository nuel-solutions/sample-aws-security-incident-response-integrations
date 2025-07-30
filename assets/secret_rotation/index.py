import json
import boto3
import secrets
import string

def lambda_handler(event, context):
    """
    Lambda function to rotate API Gateway authorization token
    """
    client = boto3.client('secretsmanager')
    secret_arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']
    
    if step == "createSecret":
        # Generate new token
        alphabet = string.ascii_letters + string.digits
        new_token = ''.join(secrets.choice(alphabet) for _ in range(32))
        
        secret_dict = {"token": new_token}
        client.put_secret_value(
            SecretId=secret_arn,
            ClientRequestToken=token,
            SecretString=json.dumps(secret_dict),
            VersionStage="AWSPENDING"
        )
        
    elif step == "setSecret":
        # No external service to update for this token
        pass
        
    elif step == "testSecret":
        # Test would be done by API Gateway validation
        pass
        
    elif step == "finishSecret":
        # Move AWSPENDING to AWSCURRENT
        client.update_secret_version_stage(
            SecretId=secret_arn,
            VersionStage="AWSCURRENT",
            ClientRequestToken=token,
            RemoveFromVersionId=client.describe_secret(SecretId=secret_arn)['VersionIdsToStages']
        )
    
    return {"statusCode": 200}