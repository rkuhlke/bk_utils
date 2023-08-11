from pydoc import resolve
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
    def __init__(self, region:str="us-east-1", logLevel:str=""):
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
            return self.logger.error(f"S3 Get Object Error: {error}")
        self.logger.info(f"S3 Get Object Successful: s3://{bucket}/{key}")
        return file.get("Body").read().decode("utf-8")
    
    def s3DownloadObject(self, bucket:str, key:str, path:str):
        s3 = boto3.client("s3")
        try:
            s3.download_file(bucket, key, os.path.join(path, key))
        except ClientError as error:
            return self.logger.error(f"S3 Download Object Error: {error}")
        return self.logger.info(f"S3 Download Object Successful: s3://{bucket}/{key} -> {os.path.join(path, key)}")
    
    def s3PutObject(self, bucket:str, key:str, data:any):
        s3 = boto3.client("s3")
        try:
            s3.put_object(Body=data, Bucket=bucket, Key=key)
        except ClientError as error:
            return self.logger.error(f"S3 Put Object Error: {error}")
        return self.logger.info(f"S3 Put Object Successful: s3://{bucket}/{key}")
    
    def s3DeleteObject(self, bucket:str, key:str):
        s3 = boto3.client("s3")
        try:
            s3.delete_object(Bucket=bucket, Key=key)
        except ClientError as error:
            return self.logger.error(f"S3 Delete Object Error: {error}")
        return self.logger.info(f"S3 Delete Object Successful: s3://{bucket}/{key}")
    ########################### S3 ###################################

    
    ########################## Secrets Manager #######################
    def secretsManagerGetSecret(self, secretName:str):        
        client = boto3.client("secretsmanager")
        try:
            get_secret_value_response = client.get_secret_value(
                SecretId=secretName
            )
        except ClientError as error:
            return self.logger.error(f"Secrets Manager Get Secret Error: {error}")
        else:
            self.logger.info(f"Secrets Manager Get Secret Successful: {secretName}")
            if "SecretString" in get_secret_value_response:
                return json.loads(get_secret_value_response["SecretString"])
            else:
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
                Key={
                    primary_key_name: primary_key_value
                }
            )
        except ClientError as error:
            return self.logger.error(f"DynamoDB Get Item Error: {error}")
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
            return self.logger.error(f"DynamoDB Update Item Error: {error}")
        return self.logger.info("DynamoDB Update Item Successful")

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
            return self.logger.error(f"DynamoDB Delete Item Error: {error}")
        return self.logger.info("DynamoDB Delete Item Successful")
    
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
                    return self.logger.error(f"DynamoDB Scan Table Error: {error}")
            else:
                try:
                    response = dynamodb.scan(TableName=tableName)
                except ClientError as error:
                    return self.logger.error(f"DynamoDB Scan Table Error: {error}")
            last_evaluated_key = response.get("LastEvaluatedKey")
            results.extend(response.get("Items"))
            
            if not last_evaluated_key:
                break
        self.logger.info("DynamoDB Scan Table Successful")
        return results

    ########################## DynamoDB ##############################

    ############################# EC2 ################################
    def ec2DescribeInstances(self):
        ec2 = boto3.client("ec2")
        ec2_list = []
        try:
            ec2s = ec2.describe_instances()
        except ClientError as error:
            return self.logger.error(f"Ec2 Describe Instance Error: {error}")
        while "NextToken" in ec2s:
            ec2_list.append(ec2s)
            try:
                ec2.decsribe_instances(NextToken=ec2s.get("NextToken"))
            except ClientError as error:
                return self.logger.error(f"Ec2 Describe Instance Error: {error}")
        ec2_list.append(ec2s)
        self.logger.info("Successfully Described All Instances")
        return ec2_list
    
    def ec2StartInstances(self, instanceIds:list):
        ec2 = boto3.client("ec2")
        try:
            response = ec2.start_instances(
                InstanceIds=instanceIds
            )
        except ClientError as error:
            return self.logger.error(f"EC2 Start Instances Error: {error}")
        self.logger.info(f"EC2 Start Instances Successful: {instanceIds}")
        return response

    def ec2StopInstances(self, instanceIds:list):
        ec2 = boto3.client("ec2")
        try:
            response = ec2.stop_instances(
                InstanceIds=instanceIds
            )
        except ClientError as error:
            return self.logger.error(f"EC2 Stop Instances Error: {error}")
        self.logger.info(f"EC2 Stop Instances Successful: {instanceIds}")
        return response
    ############################# EC2 ################################

    ############################# ECS ################################
    def ecsListClusters(self):
        ecs = boto3.client("ecs")
        ecs_cluster_list = []
        try:
            response = ecs.list_clusters()
        except ClientError as error:
            return self.logger.error(f"ECS List Clusters Error: {error}")
        for cluster in response.get("clusterArns"):
            ecs_cluster_list.append(cluster)
        while "nextToken" in response:
            try:
                response = ecs.list_clusters(
                    nextToken=response.get("nextToken")
                )
            except ClientError as error:
                return self.logger.error(f"ECS List Clusters Error: {error}")
            for cluster in response.get("clusterArns"):
                ecs_cluster_list.append(cluster)
        self.logger.info("ECS List Clusers Successful")
        return cluster
        
    def ecsListTasks(self, clusterArn:str):
        ecs = boto3.client("ecs")
        ecs_task_list = []
        try:
            response = ecs.list_tasks(
                cluster=clusterArn
            )
        except ClientError as error:
            return self.logger.error(f"ECS List Tasks Error: {error}")
        for task in response.get("taskArns"):
            ecs_task_list.append(task)
        while "nextToken" in response:
            for task in response.get("taskArns"):
                ecs_task_list.append(task)
        self.logger.info("ECS List Tasks Successful")
        return ecs_task_list

    def ecsDescribeTask(self, task:str):
        ecs = boto3.client("ecs")
        try:
            response = ecs.describe_tasks(
                tasks=[task]
            )
        except ClientError as error:
            return self.logger.error(f"ECS Describe Task Error: {error}")
        self.logger.info("ECS Describe Task Successful")
        return response.get("tasks")[0]         
    ############################# ECS ################################

    ############################# ECR ################################
    def ecrDescribeRepositories(self, registryId:str, repositoryNames:list):
        ecr = boto3.client("ecr")
        ecr_repo_list = []
        try:
            response = ecr.describe_repositories(
                registryId=registryId,
                repositoryNames=repositoryNames,
            )
        except ClientError as error:
            return self.logger.error(f"ECR Describe Repositories Error: {error}")
        while "nextToken" in response:
            ecr_repo_list.append(response.get("repositories"))
            try:
                response = ecr.describe_repositories(
                    registryId=registryId,
                    repositoryNames=repositoryNames,
                    nextToken=response.get("nextToken")
                )
            except ClientError as error:
                return self.logger.error(f"ECR Describe Repositories Error: {error}")
        ecr_repo_list.append(response.get("repositories"))
        self.logger.info(f"ECR Describe Repositories Successful: {repositoryNames}")
        return ecr_repo_list

    def ecrDescribeImages(self, registryId:str, repositoryName:str, imageIds:list, tagStatus:str="ANY"):
        ecr = boto3.client("ecr")
        ecr_image_list = []
        try:
            response = ecr.describe_images(
                registryId=registryId,
                repositoryName=repositoryName,
                imageIds=imageIds,
                filter={
                    "tagStatus":tagStatus
                }
            )
        except ClientError as error:
            return self.logger.error(f"ECR Describe Images Error: {error}")
        ecr_image_list.append(response.get("imageDetails"))
        while "nextToken" in response:
            pass
            
            
    def ecrPerformImageScan(self):
        pass
    ############################# ECR ################################

