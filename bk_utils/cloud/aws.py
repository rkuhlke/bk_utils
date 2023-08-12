import boto3
import base64
import json
import os
from botocore.exceptions import ClientError
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from ..base import Base
from .utils import utils


class AWS(Base):
    """
    Makes life easy when using AWS API Resources
    """
    def __init__(self, *, region:str='us-east-1', session:boto3.Session or None=None, access_key_id:str or None=None, secret_key_id:str or None=None, name: str = 'aws', logLevel: str = None) -> None:
        super().__init__(name=name, logLevel=logLevel)
        
        self.region = region
        self.session = session
        self.access_key_id = access_key_id
        self.secret_key_id = secret_key_id
    
    ########################### S3 ###################################
    def s3GetObject(self, bucket:str, key:str):
        if self.session:
            s3 = self.session.client('s3', region_name=self.region)
        else:
            s3 = boto3.client("s3", region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        try:
            file = s3.get_object(Bucket=bucket, Key=key)
            self.logger.info(f"S3 Get Object Successful: s3://{bucket}/{key}")
            return file.get("Body").read().decode("utf-8")
        except ClientError as error:
            raise f"S3 Get Object Error: {error}"
    
    def s3DownloadObject(self, bucket:str, key:str, path:str):
        if self.session:
            s3 = self.session.client('s3', region_name=self.region)
        else:
            s3 = boto3.client("s3", region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        try:
            s3.download_file(bucket, key, os.path.join(path, key))
            self.logger.info(f"S3 Download Object Successful: s3://{bucket}/{key} -> {os.path.join(path, key)}")
            return
        except ClientError as error:
            raise f"S3 Download Object Error: {error}"
    
    def s3PutObject(self, bucket:str, key:str, data:any):
        if self.session:
            s3 = self.session.client('s3', region_name=self.region)
        else:
            s3 = boto3.client("s3", region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        try:
            s3.put_object(Body=data, Bucket=bucket, Key=key)
            self.logger.info(f"S3 Put Object Successful: s3://{bucket}/{key}")
            return
        except ClientError as error:
            raise f"S3 Put Object Error: {error}"
    
    def s3DeleteObject(self, bucket:str, key:str):
        if self.session:
            s3 = self.session.client('s3', region_name=self.region)
        else:
            s3 = boto3.client("s3", region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        try:
            s3.delete_object(Bucket=bucket, Key=key)
        except ClientError as error:
            raise f"S3 Delete Object Error: {error}"
        return self.logger.info(f"S3 Delete Object Successful: s3://{bucket}/{key}")
    
    def s3ListObjects(self, bucket:str, *, prefix:str=''):
        if self.session:
            s3 = self.session.client('s3', region_name=self.region)
        else:
            s3 = boto3.client("s3", region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        objectList = []
        paginator = s3.get_paginator('list_objects_v2')
        try:
            pages = paginator.paginate(
                Bucket=bucket,
                Prefix=prefix
            )
        except ClientError as error:
            raise f'S3 List Objects Error: {error}'
        self.logger.info('Successfully retrieved all S3 Objects Parsing...')
        for page in pages:
            for content in page.get('Contents'):
                objectList.append(content.get('Key'))
        return objectList
            
    ########################### S3 ###################################

    
    ########################## Secrets Manager #######################
    def secretsManagerGetSecret(self, secretName:str):   
        if self.session:
            client = self.session.client('secretsmanager', region_name=self.region)
        else:
            client = boto3.client("secretsmanager", region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        try:
            get_secret_value_response = client.get_secret_value(
                SecretId=secretName
            )
        except ClientError as error:
            raise f"Secrets Manager Get Secret Error: {error}"
        else:
            self.logger.info(f"Secrets Manager Get Secret Successful: {secretName}")
            if "SecretString" in get_secret_value_response:
                return json.loads(get_secret_value_response["SecretString"])
            else:
                return json.loads(base64.b64decode(get_secret_value_response["StringBinary"]))
    #####################Secrets Manager #############################
    
    ########################## DynamoDB ##############################
    def ddbPutItem(self, tableName:str, item:dict):
        if self.session:
            dynamodb = self.session.resource('dynamodb', region_name=self.region)
        else:
            dynamodb = boto3.resource("dynamodb", region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        table = dynamodb.Table(tableName)
        try:
            table.put_item(
                Item=item
            )
            self.logger.info("DynamoDb Put Item Successful")
            return
        except ClientError as error:
            raise f"DynamoDB PutItem Error: {error}"

    def ddbGettem(self, tableName:str, primary_key_name:str, primary_key_value:any):
        if self.session:
            dynamodb = self.session.resource('dynamodb', region_name=self.region)
        else:
            dynamodb = boto3.resource("dynamodb", region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        table = dynamodb.Table(tableName)
        try:
            response = table.get_item(
                Key={
                    primary_key_name: primary_key_value
                }
            )
        except ClientError as error:
            raise f"DynamoDB Get Item Error: {error}"
        self.logger.info("DynamoDB Get Item Successful")
        return response.get("Item")

    def ddbUpdateItem(self, tableName:str, primary_key_name:str, primary_key_value:any, item:dict):
        if self.session:
            dynamodb = self.session.resource('dynamodb', region_name=self.region)
        else:
            dynamodb = boto3.resource("dynamodb", region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        table = dynamodb.Table(tableName)
        item_list = utils.convert_dict_to_list(item)
        for i in item_list:
            key_name = i[0]
            key_value = i[1]
            try:
                table.update_item(
                    Key={
                        primary_key_name: primary_key_value
                    },
                    AttributeUpdates={
                        key_name: {
                            "Value": key_value
                        }
                    },
                )
            except ClientError as error:
                raise f"DynamoDB Update Item Error: {error}"
        self.logger.info("DynamoDB Update Item Successful")
        return

    def ddbDeleteItem(self, tableName:str, primary_key_name:str, primary_key_value:any):
        if self.session:
            dynamodb = self.session.resource('dynamodb', region_name=self.region)
        else:
            dynamodb = boto3.resource("dynamodb", region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        table = dynamodb.Table(tableName)
        try:
            table.delete_item(
                Key={
                    primary_key_name: primary_key_value
                }
            )
        except ClientError as error:
            raise f"DynamoDB Delete Item Error: {error}"
        self.logger.info("DynamoDB Delete Item Successful")
        return
    
    def ddbScanTable(
        self,
        tableName:str,
        expressionAttributeNames:str or None=None,
        expressionAttributeValues:str or None=None,
        filterExpression:str='#n0 = :v0',
        returnConsumedCapacity:str='TOTAL'
        ):
        if self.session:
            dynamodb = self.session.client('dynamodb', region_name=self.region)
        else:
            dynamodb = boto3.client("dynamodb", region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        results = []
        last_evaluated_key = None
        while True:
            if last_evaluated_key:
                if expressionAttributeNames and expressionAttributeValues:
                    try:
                        response = dynamodb.scan(
                            TableName=tableName,
                            ReturnConsumedCapacity=returnConsumedCapacity,
                            ExpressionAttributeNames={
                                '#n0': expressionAttributeNames
                            },
                            ExpressionAttributeValues={
                                ':v0': {
                                    'S': expressionAttributeValues
                                }
                            },
                            FilterExpression=filterExpression,
                            ExclusiveStartKey=last_evaluated_key
                        )
                    except ClientError as error:
                        raise f"DynamoDB Scan Table Error: {error}"
                else:
                    try:
                        response = dynamodb.scan(
                            TableName=tableName,
                            ReturnConsumedCapacity=returnConsumedCapacity,
                            ExclusiveStartKey=last_evaluated_key
                        )
                    except ClientError as error:
                        raise f"DynamoDB Scan Table Error: {error}"
            else:
                if expressionAttributeNames and expressionAttributeValues:
                    try:
                        response = dynamodb.scan(
                            TableName=tableName,
                            ReturnConsumedCapacity=returnConsumedCapacity,
                            ExpressionAttributeNames={
                                '#n0': expressionAttributeNames
                            },
                            ExpressionAttributeValues={
                                ':v0': {
                                    'S': expressionAttributeValues
                                }
                            },
                            FilterExpression=filterExpression
                        )
                    except ClientError as error:
                        raise f"DynamoDB Scan Table Error: {error}"
                else:
                    try:
                        response = dynamodb.scan(
                            TableName=tableName,
                            ReturnConsumedCapacity=returnConsumedCapacity
                        )
                    except ClientError as error:
                        raise f"DynamoDB Scan Table Error: {error}"
            last_evaluated_key = response.get("LastEvaluatedKey")
            results.extend(response.get("Items"))
            
            if not last_evaluated_key:
                break
        self.logger.info("DynamoDB Scan Table Successful")
        return results
    
    def ddbQueryTable(
        self,
        tableName:str,
        expressionAttributeNames:str,
        expressionAttributeValues:any,
        filterExpression:str='#n0 = :v0',
        returnConsumedCapacity:str='TOTAL'
        ) -> dict:
        
        if self.session:
            dynamodb = self.session.client('dynamodb', region_name=self.region)
        else:
            dynamodb = boto3.client("dynamodb", region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        try:
            return dynamodb.query(
                TableName=tableName,
                ReturnConsumedCapacity=returnConsumedCapacity,
                ExpressionAttributeNames={
                    '#n0': expressionAttributeNames
                },
                ExpressionAttributeValues={
                    ':v0': {
                        'S': expressionAttributeValues
                    }
                },
                FilterExpression=filterExpression,
                Limit=500
            )
        except ClientError as error:
            raise f'DynamoDB Query Error: {error}'
        
    ########################## DynamoDB ##############################
    
    ########################### Lambda ###############################
    def lambdaInvokeFunction(self, functionARN:str, payload:dict):
        if self.session:
            client = self.session.client('lambda', region_name=self.region)
        else:
            client = boto3.client('lambda', region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        try:
            client.invoke(
                FunctionName=functionARN,
                InvocationType='RequestResponse',
                Payload=json.dumps(payload)
            )
            self.logger.info(f'Successfully Execution Error: {functionARN}')
            return
        except ClientError as error:
            raise f'Lambda Invoke Error: {error}'
        
    ########################### Lambda ###############################
    
    ######################## StepFunction ############################
    def sfnStartExecution(self, stateMachineARN:str, payload:dict):
        if self.session:
            sfn = self.session.client('stepfunctions', region_name=self.region)
        else:
            sfn = boto3.client('stepfunctions', region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        try:
            sfn.start_execution(
                stateMachineArn=stateMachineARN,
                input=json.dumps(payload)
            )
        except ClientError as error:
            raise f'StateMachine Execution Error: {error}'
    ######################## StepFunction ############################
    
    ############################# SES ################################
    def sesSendEmail(
        self,
        sender:str,
        recipients:list,
        subject:str,
        emailBody:str or None=None,
        htmlEmailBody:str or None=None
        ):
        if self.session:
            ses = self.session.client('ses', region_name=self.region)
        else:
            ses = boto3.client('ses', region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        
        charset = 'utf-8'
        try:
            ses.send_email(
                Destination={
                    'ToAddresses': recipients
                },
                Message={
                    'Body': {
                        'HTML': {
                            'Charset': charset,
                            'Data': htmlEmailBody
                        },
                        'Text': {
                            'Charset': charset,
                            'Data': emailBody
                        }
                    },
                    'Subject': {
                        'Charset': charset,
                        'Data': subject
                    }
                },
                Source=sender
            )
        except ClientError as error:
            raise f'SES Send Email Error: {error}'
        self.logger.info(f'Successfully Sent Email to: {recipients} from {sender}')
        return
    
    def sesSendEmailWithAttachment(
        self,
        sender:str,
        recipients:list,
        subject:str,
        emailBody:str or None=None,
        htmlEmailBody:str or None=None,
        pathToAttachment:str or None=None,
        bucket:str or None=None,
        key:str or None=None
        ):
        if self.session:
            ses = self.session.client('ses', region_name=self.region)
        else:
            ses = boto3.client('ses', region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        
        charset = 'utf-8'
        msg = MIMEMultipart('mixed')
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = ','.join(recipients)
        
        msg_body = MIMEMultipart('alternative')
        if emailBody:
            textPart = MIMEText(emailBody.encode(charset), 'plain', charset)
            msg_body.attach(textPart)
        if htmlEmailBody:
            htmlPart = MIMEText(htmlEmailBody.encode(charset), 'html')
            msg_body.attach(htmlPart)
        
        if pathToAttachment:
            att = MIMEApplication(open(pathToAttachment, 'rb').read())
            att.add_header('Content-Disposition', 'attachment', filename=os.path.basename(pathToAttachment))
        
        if bucket and key:
            att = MIMEApplication(self.s3GetObject(bucket, key).read(), key)
            att.add_header('Content-Disposition', 'attachment', filename=key)
        
        elif not pathToAttachment or (bucket and key):
            raise 'Please Supply A FilePath or Bucket and Key'
        
        msg.attach(att)
        try:
            ses.send_raw_email(
                Source=sender,
                Destinations=recipients,
                RawMessage={
                    'Data': msg.as_string()
                }
            )
        except ClientError as error:
            raise f'SES Send Email With Attachment Error: {error}'
        self.logger.info(f'Successfully Sent Email To: {recipients} From: {sender}')
        return
    ############################# SES ################################
    
    ############################# STS ################################
    def stsAssumeRole(self, roleArn:str, sessionName:str):
        if self.session:
            sts = self.session.client('sts', region_name=self.region)
        else:
            sts = boto3.client('sts', region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        try:
            response = sts.assume_role(
                RoleArn=roleArn,
                RoleSessionName=sessionName
            )
            self.logger.info(f'STS Assume Role Successful: {roleArn}')
            return response
        except ClientError as error:
            raise f'STS Assume Role Error: {error}'
    
    def stsGetCallerIdentity(self):
        if self.session:
            sts = self.session.client('sts', region_name=self.region)
        else:
            sts = boto3.client('sts', region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        try:
            return sts.get_caller_identity()
        except ClientError as error:
            raise f'STS Get Caller Identity Error: {error}'
    ############################# STS ################################
    
    ############################# IAM ################################
    def iamUpdateAccessKey(self, username:str, accessKeyId:str, status:str):
        if self.session:
            iam = self.session.client('iam', region_name=self.region)
        else:
            iam = boto3.client('iam', region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        if status not in ['Active', 'Inactive']:
            raise f'Status must be one of ["Active", "Inactive"]\nGot: {status}'
        try:
            return iam.update_access_key(
                AccessKeyId=accessKeyId,
                Status=status,
                UserName=username
            )
        except ClientError as error:
            raise f'IAM Update Access Key Error: {error}'
    
    def iamGetAccessKeyLastUsed(self, accessKeyId:str):
        if self.session:
            iam = self.session.client('iam', region_name=self.region)
        else:
            iam = boto3.client('iam', region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        try:
            return iam.get_access_key_last_used(AccessKeyId=accessKeyId)
        except ClientError as error:
            raise f'IAM Access Key Last Used Error: {error}'
    ############################# IAM ################################
    
    ############################ WAFv2 ###############################
    def wafv2AssociateWebACL(self, wafACL:str, resourceARN:str):
        if self.session:
            wafv2 = self.session.client('wafv2', region_name=self.region)
        else:
            wafv2 = boto3.client('wafv2', region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        try:
            return wafv2.associate_web_acl(WebACLArn=wafACL, ResourceArn=resourceARN)
        except ClientError as error:
            raise f'WAFv2 Associate Web ACL Error: {error}'
    ############################ WAFv2 ###############################

    ############################# EC2 ################################
    def ec2DescribeRegions(self):
        if self.session:
            ec2 = self.session.client('ec2', region_name=self.region)
        else:
            ec2 = boto3.client("ec2", region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        try:
            return ec2.describe_regions(
                AllRegions=True
            )
        except ClientError as error:
            raise f'EC2 Describe Region Error: {error}'
    
    def ec2DescribeNetworkACLs(self):
        if self.session:
            ec2 = self.session.client('ec2', region_name=self.region)
        else:
            ec2 = boto3.client("ec2", region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        try:
            response = ec2.describe_network_acls(MaxResults=5)
        except ClientError as error:
            raise f'EC2 Describe Network ACL Error: {error}'
        return response
        
    def ec2DescribeInstances(self):
        if self.session:
            ec2 = self.session.client('ec2', region_name=self.region)
        else:
            ec2 = boto3.client("ec2", region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        ec2_list = []
        try:
            ec2s = ec2.describe_instances()
        except ClientError as error:
            raise f"Ec2 Describe Instance Error: {error}"
        for ec2 in ec2s['Reservations']:
            for instances in ec2['Instances']:
                ec2_list.append(instances)
        while "NextToken" in ec2s:
            for ec2 in ec2s['Reservations']:
                for instances in ec2['Instances']:
                    ec2_list.append(instances)
            try:
                ec2.describe_instances(NextToken=ec2s.get("NextToken"))
            except ClientError as error:
                raise f"Ec2 Describe Instance Error: {error}"
        ec2_list.append(ec2s)
        self.logger.info("Successfully Described All Instances")
        return ec2_list
    
    def ec2StartInstances(self, instanceIds:list):
        if self.session:
            ec2 = self.session.client('ec2', region_name=self.region)
        else:
            ec2 = boto3.client("ec2", region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        try:
            response = ec2.start_instances(
                InstanceIds=instanceIds
            )
        except ClientError as error:
            raise f"EC2 Start Instances Error: {error}"
        self.logger.info(f"EC2 Start Instances Successful: {instanceIds}")
        return response

    def ec2StopInstances(self, instanceIds:list):
        if self.session:
            ec2 = self.session.client('ec2', region_name=self.region)
        else:
            ec2 = boto3.client("ec2", region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        try:
            response = ec2.stop_instances(
                InstanceIds=instanceIds
            )
        except ClientError as error:
            raise f"EC2 Stop Instances Error: {error}"
        self.logger.info(f"EC2 Stop Instances Successful: {instanceIds}")
        return response
    ############################# EC2 ################################

    ############################# ECS ################################
    def ecsListClusters(self):
        if self.session:
            ecs = self.session.client('ecs', region_name=self.region)
        else:
            ecs = boto3.client('ecs', region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        ecs_cluster_list = []
        try:
            response = ecs.list_clusters()
        except ClientError as error:
            raise f"ECS List Clusters Error: {error}"
        for cluster in response.get("clusterArns"):
            ecs_cluster_list.append(cluster)
        while "nextToken" in response:
            try:
                response = ecs.list_clusters(
                    nextToken=response.get("nextToken")
                )
            except ClientError as error:
                raise f"ECS List Clusters Error: {error}"
            for cluster in response.get("clusterArns"):
                ecs_cluster_list.append(cluster)
        self.logger.info("ECS List Clusers Successful")
        return ecs_cluster_list
        
    def ecsListTasks(self, clusterArn:str):
        if self.session:
            ecs = self.session.client('ecs', region_name=self.region)
        else:
            ecs = boto3.client('ecs', region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        ecs_task_list = []
        try:
            response = ecs.list_tasks(
                cluster=clusterArn
            )
        except ClientError as error:
            raise f"ECS List Tasks Error: {error}"
        for task in response.get("taskArns"):
            ecs_task_list.append(task)
        while "nextToken" in response:
            for task in response.get("taskArns"):
                ecs_task_list.append(task)
        self.logger.info("ECS List Tasks Successful")
        return ecs_task_list

    def ecsDescribeTask(self, tasks:list):
        if self.session:
            ecs = self.session.client('ecs', region_name=self.region)
        else:
            ecs = boto3.client('ecs', region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        try:
            return ecs.describe_tasks(
                tasks=tasks
            )
        except ClientError as error:
            raise f"ECS Describe Task Error: {error}"         
    ############################# ECS ################################

    ############################# ECR ################################
    def ecrDescribeRepositories(self, registryId:str, repositoryNames:list or None=None):
        if self.session:
            ecr = self.session.client('ecr', region_name=self.region)
        else:
            ecr = boto3.client('ecr', region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        ecr_repo_list = []
        try:
            response = ecr.describe_repositories(
                registryId=registryId,
                repositoryNames=repositoryNames,
            )
        except ClientError as error:
            raise f"ECR Describe Repositories Error: {error}"
        while "nextToken" in response:
            ecr_repo_list.append(response.get("repositories"))
            try:
                response = ecr.describe_repositories(
                    registryId=registryId,
                    repositoryNames=repositoryNames,
                    nextToken=response.get("nextToken")
                )
            except ClientError as error:
                raise f"ECR Describe Repositories Error: {error}"
        ecr_repo_list.append(response.get("repositories"))
        self.logger.info(f"ECR Describe Repositories Successful: {repositoryNames}")
        return ecr_repo_list

    def ecrDescribeImages(self, registryId:str, repositoryName:str, imageIds:list or None=None, tagStatus:str="ANY"):
        if self.session:
            ecr = self.session.client('ecr', region_name=self.region)
        else:
            ecr = boto3.client('ecr', region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
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
            raise f"ECR Describe Images Error: {error}"
        ecr_image_list.extend(response.get("imageDetails"))
        while "nextToken" in response:
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
                raise f"ECR Describe Images Error: {error}"
            ecr_image_list.extend(response.get("imageDetails"))
        return ecr_image_list 
            
    def ecrStartImageScan(self, registryId:str, repositoryName:str, imageId:dict):
        if self.session:
            ecr = self.session.client('ecr', region_name=self.region)
        else:
            ecr = boto3.client('ecr', region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        try:
            return ecr.start_image_scan(
                repositoryName=repositoryName,
                imageId=imageId,
                registryId=registryId
            )
        except ClientError as error:
            raise f'ECR Start Image Scan Error: {error}'
    
    def ecrDescribeImageScanFindings(self, registryId:str, repositoryName:str, imageId:dict):
        if self.session:
            ecr = self.session.client('ecr', region_name=self.region)
        else:
            ecr = boto3.client('ecr', region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        findingsList = []
        enhancedFindingsList = []
        try:
            response = ecr.describe_image_scan_findings(
                registryId=registryId,
                repositoryName=repositoryName,
                imageId=imageId
            )
        except ClientError as error:
            raise f'ECR Describe Image Scan Findings Error: {error}'
        findingsList.extend(response['imageScanFindings'].get('findings'))
        if response['imageScanFindings'].get('enhancedFindings'):
            enhancedFindingsList.extend(response['imageScanFindings'].get('enhancedFindings'))
        while 'nextToken' in response:
            findingsList.extend(response['imageScanFindings'].get('findings'))
            if response['imageScanFindings'].get('enhancedFindings'):
                enhancedFindingsList.extend(response['imageScanFindings'].get('enhancedFindings'))
            try:
                response = ecr.describe_image_scan_findings(
                    registryId=registryId,
                    repositoryName=repositoryName,
                    imageId=imageId,
                    nextToken=response['nextToken']
                )
            except ClientError as error:
                raise f'ECR Describe Image Scan Findings Error: {error}'
        response['imageScanFindings'].update({'findings': findingsList, 'enhancedFindings': enhancedFindingsList})
        return response
    ############################# ECR ################################
    
    ######################### API Gateway ############################
    def apiGWCreateAPIKey(self, name:str, description:str='', enabled:bool=True):
        if self.session:
            apigw = self.session.client('apigateway', region_name=self.region)
        else:
            apigw = boto3.client('apigateway', region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        try:
            return apigw.create_api_key(
                name=name,
                description=description,
                enabled=enabled,
                generateDistinctId=True
            )
        except ClientError as error:
            raise f'API Gateway Create API Key Error: {error}'
        
    def apiGWCreateUsagePlanKey(self, usagePlanId:str, keyId:str, keyType:str):
        if self.session:
            apigw = self.session.client('apigateway', region_name=self.region)
        else:
            apigw = boto3.client('apigateway', region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        try:
            return apigw.create_usage_plan_key(
                usagePlanId=usagePlanId,
                keyId=keyId,
                keyType=keyType
            )
        except ClientError as error:
            raise f'API Gateway Create Usage Plan Key Error: {error}'
    
    def apiGWDeleteAPIKey(self, apiKey:str):
        if self.session:
            apigw = self.session.client('apigateway', region_name=self.region)
        else:
            apigw = boto3.client('apigateway', region_name=self.region, aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_key_id)
        
        try:
            return apigw.delete_api_key(
                apiKey=apiKey
            )
        except ClientError as error:
            raise f'API Gateway Delete API Key Error: {error}'
    ######################### API Gateway ############################