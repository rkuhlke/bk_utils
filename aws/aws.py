import boto3
import base64
import json
import os
from botocore.exceptions import ClientError
from .logger import setLogLevel


class AWS:
    """
    Makes life easy when using AWS API Resources
    """
    def __init__(self, logLevel=""):
        self.logger = setLogLevel(logLevel, "utilities-aws")
        
    def s3GetObject(self, bucket, key):
        s3 = boto3.client("s3")
        try:
            file = s3.get_object(Bucket=bucket, Key=key)
        except ClientError as error:
            self.logger.error("Error:", error)
            return
        self.logger.info("Get Object Successful:", f"s3://{bucket}/{key}")
        return file
    
    def s3DownloadObject(self, bucket, key, path):
        s3 = boto3.client("s3")
        try:
            s3.download_file(bucket, key, os.path.join(path, key))
        except ClientError as error:
            self.logger.error("Error:", error)
            return
        self.logger.info("Download Object Successful:", f"s3://{bucket}/{key} -> {os.path.join(path, key)}")
    
    def s3PutObject(self, bucket, key, data):
        s3 = boto3.client("s3")
        try:
            s3.put_object(Body=data, Bucket=bucket, Key=key)
        except ClientError as error:
            self.logger.error("Error:", error)
            return
        self.logger.info("Put Object Successful:", f"s3://{bucket}/{key}")
    
    def s3DeleteObject(self, bucket, key):
        s3 = boto3.client("s3")
        try:
            s3.delete_object(Bucket=bucket, Key=key)
        except ClientError as error:
            self.logger.error("Error:", error)
            return
        self.logger.info("Delete Object Successful:", f"s3://{bucket}/{key}")
    
    def secretsManagerGetSecret(self, secretName):
        region = "us-east-1"
        
        session = boto3.session.Session()
        client = session.client(
            service_name="secretsmanager",
            region_name=region
        )
        try:
            get_secret_value_response = client.get_secret_value(
                SecretId=secretName
            )
        except ClientError as e:
            raise e
        else:
            if "SecretString" in get_secret_value_response:
                self.logger.info("Get Secret Successful:", f"{secretName}")
                return json.loads(get_secret_value_response["SecretString"])
            else:
                self.logger.info("Get Secret Successful:", f"{secretName}")
                return json.loads(base64.b64decode(get_secret_value_response["StringBinary"]))
        
