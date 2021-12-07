import boto3
import base64
import json
import logging
import os
from botocore.exceptions import ClientError

logging.basicConfig(format="%(asctime)s - %(message)s", level=logging.INFO)

class AWS:
    def s3GetObject(bucket, key):
        s3 = boto3.client("s3")
        try:
            file = s3.get_object(Bucket=bucket, Key=key)
        except ClientError as error:
            logging.error("Error:", error)
            return
        logging.info("Get Object Successful:", f"s3://{bucket}/{key}")
        return file
    
    def s3DownloadObject(bucket, key, path):
        s3 = boto3.client("s3")
        try:
            s3.download_file(bucket, key, os.path.join(path, key))
        except ClientError as error:
            logging.error("Error:", error)
            return
        logging.info("Download Object Successful:", f"s3://{bucket}/{key} -> {os.path.join(path, key)}")
    
    def s3PutObject(bucket, key, data):
        s3 = boto3.client("s3")
        try:
            s3.put_object(Body=data, Bucket=bucket, Key=key)
        except ClientError as error:
            logging.error("Error:", error)
            return
        logging.info("Put Object Successful:", f"s3://{bucket}/{key}")
    
    def s3DeleteObject(bucket, key):
        s3 = boto3.client("s3")
        try:
            s3.delete_object(Bucket=bucket, Key=key)
        except ClientError as error:
            logging.error("Error:", error)
            return
        logging.info("Delete Object Successful:", f"s3://{bucket}/{key}")
    
    def getSecret(secretName):
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
                return json.loads(get_secret_value_response["SecretString"])
            else:
                return json.loads(base64.b64decode(get_secret_value_response["StringBinary"]))
        
