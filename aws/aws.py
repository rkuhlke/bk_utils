import boto3
import base64
import json
import logging
import os
from botocore.exceptions import ClientError


class AWS:
    """
    Makes life easy when using AWS API Resources
    """
    def __init__(self, logLevel:str="", region:str="us-east-1"):
        self.logger = logging.getLogger(__name__)
        ch = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

        if logLevel.lower() == "debug":
            self.logger.setLevel(logging.DEBUG)
        elif logLevel.lower() == "error":
            self.logger.setLevel(logging.ERROR)
        else:
            self.logger.setLevel(logging.INFO)
        
        self.region = region
    
    ########################### S3 ###################################
        
    def s3GetObject(self, bucket:str, key:str):
        s3 = boto3.client("s3")
        try:
            file = s3.get_object(Bucket=bucket, Key=key)
        except ClientError as error:
            self.logger.error(f"S3 Get Object Error: {error}")
            return
        self.logger.info(f"Get Object Successful: s3://{bucket}/{key}")
        return file.get("Body").read().decode("utf-8")
    
    def s3DownloadObject(self, bucket:str, key:str, path:str):
        s3 = boto3.client("s3")
        try:
            s3.download_file(bucket, key, os.path.join(path, key))
        except ClientError as error:
            self.logger.error(f"S3 Download Object Error: {error}")
            return
        self.logger.info(f"Download Object Successful: s3://{bucket}/{key} -> {os.path.join(path, key)}")
    
    def s3PutObject(self, bucket:str, key:str, data:any):
        s3 = boto3.client("s3")
        try:
            s3.put_object(Body=data, Bucket=bucket, Key=key)
        except ClientError as error:
            self.logger.error(f"S3 Put Object Error: {error}")
            return
        self.logger.info(f"Put Object Successful: s3://{bucket}/{key}")
    
    def s3DeleteObject(self, bucket:str, key:str):
        s3 = boto3.client("s3")
        try:
            s3.delete_object(Bucket=bucket, Key=key)
        except ClientError as error:
            self.logger.error(f"S3 Delete Object Error: {error}")
            return
        self.logger.info(f"Delete Object Successful: s3://{bucket}/{key}")

    ########################### S3 ###################################

    
    ########################## Secrets Manager #######################

    def secretsManagerGetSecret(self, secretName:str):        
        session = boto3.session.Session()
        client = session.client(
            service_name="secretsmanager",
            region_name=self.region
        )
        try:
            get_secret_value_response = client.get_secret_value(
                SecretId=secretName
            )
        except ClientError as error:
            self.logger.error(f"Secrets Manager Get Secret Error: {error}")
            return
        else:
            if "SecretString" in get_secret_value_response:
                self.logger.info(f"Get Secret Successful: {secretName}")
                return json.loads(get_secret_value_response["SecretString"])
            else:
                self.logger.info(f"Get Secret Successful: {secretName}")
                return json.loads(base64.b64decode(get_secret_value_response["StringBinary"]))

    #####################Secrets Manager #############################
    
    ########################## DynamoDB ##############################
    
    def ddbPutItem(self, tableName:str, item:dict):
        dynamodb = boto3.resource("dynamodb", region_name=self.region)
        table = dynamodb.Table(tableName)
        
        try:
            table.put_item(
                Item=item
            )
        except ClientError as error:
            self.logger.error(f"DynamoDB PutItem Error: {error}")
            return
        self.logger.info("DynamoDb Put Item Successful")
        return

    def ddbGettem(self, tableName:str, primary_key_name:str, primary_key_value:any):
        dynamodb = boto3.resource("dynamodb", region_name=self.region)
        table = dynamodb.Table(tableName)
        try:
            response = table.get_item(
                key={
                    primary_key_name: primary_key_value
                }
            )
        except ClientError as error:
            self.logger.error(f"DynamoDB Get Item Error: {error}")
            return
        self.logger.info("DynamoDB Get Item Successful")
        return response.get("Item")

    def ddbUpdateItem(self, tableName:str, primary_key_name:str, primary_key_value:any, key_name:str, key_value:any):
        dynamodb = boto3.resource("dynamodb", region_name=self.region)
        table = dynamodb.Table(tableName)
        try:
            table.update_item(
                Key={
                    primary_key_name: primary_key_value
                },
                AttributeUpdates={
                    key_name: key_value
                },
            )
        except ClientError as error:
            self.logger.error(f"DynamoDb Update Item Error: {error}")
            return
        self.logger.info("DynamoDB Update Item Successful")
        return

    def ddbDeleteItem(self, tableName:str, primary_key_name:str, primary_key_value:any):
        dynamodb = boto3.resource("dynamodb", region_name=self.region)
        table = dynamodb.Table(tableName)
        try:
            table.delete_item(
                Key={
                    primary_key_name: primary_key_value
                }
            )
        except ClientError as error:
            self.logger.error(f"DynamoDB Delete Item Error: {error}")
            return
        self.logger.info("DynamoDB Delete Item Successful")
        return
    
    def ddbScanTable(self, tableName:str):
        dynamodb = boto3.client("dynamodb", region_name=self.region)
        results = []
        last_evaluated_key = None
        while True:
            if last_evaluated_key:
                try:
                    response = dynamodb.scan(
                        TableName=tableName,
                        ExclusiveStartKey=last_evaluated_key
                    )
                except ClientError as error:
                    self.logger.error(f"DynamoDB Scan Table Error: {error}")
                    return
            else:
                try:
                    response = dynamodb.scan(TableName=tableName)
                except ClientError as error:
                    self.logger.error(f"DynamoDB Scan Table Error: {error}")
                    return
            last_evaluated_key = response.get("LastEvaluatedKey")
            results.extend(response.get("Items"))
            
            if not last_evaluated_key:
                break
        self.logger.info("DynamoDB Scan Table Successful")
        return results

    ########################## DynamoDB ##############################
