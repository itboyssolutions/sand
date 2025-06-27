import boto3
import json
import logging
import time
from datetime import datetime, timezone
from botocore.config import Config
import botocore

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configure AWS clients with 3 retries
cfg = Config(retries={'max_attempts': 3, 'mode': 'standard'})
s3 = boto3.client('s3', config=cfg)
ec2 = boto3.client('ec2', config=cfg)
iam = boto3.client('iam', config=cfg)
rds = boto3.client('rds', config=cfg)
eks = boto3.client('eks', config=cfg)
ecr = boto3.client('ecr', config=cfg)
elbv2 = boto3.client('elbv2', config=cfg)
dynamodb = boto3.client('dynamodb', config=cfg)
ecs = boto3.client('ecs', config=cfg)
cf = boto3.client('cloudformation', config=cfg)

BUCKET = "aws-sandbox-tracker-659840170574-eu-west-1"
PREFIX = "sessions/"

def retry(func, *args, **kwargs):
    for attempt in range(3):
        try:
            return func(*args, **kwargs)
        except botocore.exceptions.ClientError as e:
            code = e.response['Error']['Code']
            if code in ("Throttling", "TooManyRequestsException", "DependencyViolation"):
                backoff = 2 ** attempt
                logger.warning("Retryable error %s on %s, attempt %d/3, sleeping %ds", code, func.__name__, attempt+1, backoff)
                time.sleep(backoff)
                continue
            raise
    raise RuntimeError(f"{func.__name__} failed after 3 retries")

def teardown_vpc(username, tag_filters):
    vpcs = retry(ec2.describe_vpcs, Filters=tag_filters)['Vpcs']
    for vpc in vpcs:
        vid = vpc['VpcId']
        logger.info("Tearing down VPC %s", vid)
        # IGWs
        for igw in retry(ec2.describe_internet_gateways, Filters=[{'Name':'attachment.vpc-id','Values':[vid]}])['InternetGateways']:
            igwid = igw['InternetGatewayId']
            retry(ec2.detach_internet_gateway, InternetGatewayId=igwid, VpcId=vid)
            retry(ec2.delete_internet_gateway, InternetGatewayId=igwid)
        # NATs
        for nat in retry(ec2.describe_nat_gateways, Filters=tag_filters)['NatGateways']:
            retry(ec2.delete_nat_gateway, NatGatewayId=nat['NatGatewayId'])
        # Subnets
        for sub in retry(ec2.describe_subnets, Filters=tag_filters)['Subnets']:
            retry(ec2.delete_subnet, SubnetId=sub['SubnetId'])
        # Route tables
        for rt in retry(ec2.describe_route_tables, Filters=[{'Name':'vpc-id','Values':[vid]}])['RouteTables']:
            for assoc in rt.get('Associations', []):
                if not assoc.get('Main'):
                    retry(ec2.disassociate_route_table, AssociationId=assoc['RouteTableAssociationId'])
            retry(ec2.delete_route_table, RouteTableId=rt['RouteTableId'])
        retry(ec2.delete_vpc, VpcId=vid)
        logger.info("Deleted VPC %s", vid)

def lambda_handler(event, context):
    resp = s3.list_objects_v2(Bucket=BUCKET, Prefix=PREFIX)
    if 'Contents' not in resp:
        logger.info("No sessions to process.")
        return

    now = datetime.now(timezone.utc)
    for obj in resp['Contents']:
        key = obj['Key']
        if not key.endswith('.json'): continue

        data = json.loads(s3.get_object(Bucket=BUCKET, Key=key)['Body'].read())
        username = data.get('username')
        expires = datetime.fromisoformat(data['expires_at'].replace("Z","+00:00"))
        if now < expires:
            logger.info("Skipping unexpired session for %s", username)
            continue
        logger.info("Cleaning up resources for user %s", username)
        tag = {'Name':'tag:Username', 'Values':[username]}
        tag_filters = [tag]

        try:
            teardown_vpc(username, tag_filters)
        except Exception as e:
            logger.error("VPC teardown error for %s: %s", username, e)

        # EC2 instances
        try:
            res = retry(ec2.describe_instances, Filters=tag_filters)
            for r in res['Reservations']:
                for inst in r['Instances']:
                    retry(ec2.terminate_instances, InstanceIds=[inst['InstanceId']])
                    logger.info("Terminated EC2 %s", inst['InstanceId'])
        except Exception as e:
            logger.error("EC2 termination failed for %s: %s", username, e)

        # Volumes
        try:
            vols = retry(ec2.describe_volumes, Filters=tag_filters)['Volumes']
            for v in vols:
                retry(ec2.delete_volume, VolumeId=v['VolumeId'])
                logger.info("Deleted Volume %s", v['VolumeId'])
        except Exception as e:
            logger.error("Volume deletion failed: %s", e)

        # ELBv2
        try:
            lbs = retry(elbv2.describe_load_balancers)['LoadBalancers']
            for lb in lbs:
                arn = lb['LoadBalancerArn']
                tags = retry(elbv2.describe_tags, ResourceArns=[arn])['TagDescriptions'][0]['Tags']
                if any(t['Key']=='Username' and t['Value']==username for t in tags):
                    retry(elbv2.delete_load_balancer, LoadBalancerArn=arn)
                    logger.info("Deleted LB %s", arn)
        except Exception as e:
            logger.error("Load balancer deletion failed: %s", e)

        # CloudFormation
        try:
            stacks = retry(cf.describe_stacks)['Stacks']
            for stk in stacks:
                if any(t['Key']=='Username' and t['Value']==username for t in stk.get('Tags', [])):
                    retry(cf.delete_stack, StackName=stk['StackName'])
                    logger.info("Deleted CFN stack %s", stk['StackName'])
        except Exception as e:
            logger.error("CFN deletion failed: %s", e)

        # S3 buckets
        try:
            for b in retry(s3.list_buckets)['Buckets']:
                nm = b['Name']
                try:
                    tags = retry(s3.get_bucket_tagging, Bucket=nm)['TagSet']
                    if any(t['Key']=='Username' and t['Value']==username for t in tags):
                        objs = retry(s3.list_objects_v2, Bucket=nm).get('Contents', [])
                        for o in objs:
                            retry(s3.delete_object, Bucket=nm, Key=o['Key'])
                        retry(s3.delete_bucket, Bucket=nm)
                        logger.info("Deleted bucket %s", nm)
                except botocore.exceptions.ClientError:
                    pass
        except Exception as e:
            logger.error("Bucket deletion failed: %s", e)

        # RDS
        try:
            for db in retry(rds.describe_db_instances)['DBInstances']:
                arn = db['DBInstanceArn']
                tags = retry(rds.list_tags_for_resource, ResourceName=arn)['TagList']
                if any(t['Key']=='Username' and t['Value']==username for t in tags):
                    retry(rds.delete_db_instance, DBInstanceIdentifier=db['DBInstanceIdentifier'], SkipFinalSnapshot=True)
                    logger.info("Deleted RDS %s", db['DBInstanceIdentifier'])
        except Exception as e:
            logger.error("RDS deletion failed: %s", e)

        # EKS
        try:
            for cname in retry(eks.list_clusters)['clusters']:
                tags = retry(eks.describe_cluster, name=cname)['cluster'].get('tags',{})
                if tags.get('Username') == username:
                    retry(eks.delete_cluster, name=cname)
                    logger.info("Deleted EKS %s", cname)
        except Exception as e:
            logger.error("EKS deletion failed: %s", e)

        # ECR
        try:
            for repo in retry(ecr.describe_repositories)['repositories']:
                arn = repo['repositoryArn']
                tags = retry(ecr.list_tags_for_resource, resourceArn=arn)['tags']
                if any(t['Key']=='Username' and t['Value']==username for t in tags):
                    retry(ecr.delete_repository, repositoryName=repo['repositoryName'], force=True)
                    logger.info("Deleted ECR %s", repo['repositoryName'])
        except Exception as e:
            logger.error("ECR deletion failed: %s", e)

        # EIPs
        try:
            for addr in retry(ec2.describe_addresses)['Addresses']:
                tags = retry(ec2.describe_tags, Filters=[{'Name':'resource-id','Values':[addr['AllocationId']]}])['Tags']
                if any(t['Key']=='Username' and t['Value']==username for t in tags):
                    retry(ec2.release_address, AllocationId=addr['AllocationId'])
                    logger.info("Released EIP %s", addr['AllocationId'])
        except Exception as e:
            logger.error("EIP release failed: %s", e)

        # NAT Gateways (extra cleanup)
        try:
            for nat in retry(ec2.describe_nat_gateways)['NatGateways']:
                if any(t['Key']=='Username' and t['Value']==username for t in nat.get('Tags',[])):
                    retry(ec2.delete_nat_gateway, NatGatewayId=nat['NatGatewayId'])
                    logger.info("Deleted NAT GW %s", nat['NatGatewayId'])
        except Exception as e:
            logger.error("NAT deletion failed: %s", e)

        # DynamoDB tables
        try:
            for tab in retry(dynamodb.list_tables)['TableNames']:
                arn = retry(dynamodb.describe_table, TableName=tab)['Table']['TableArn']
                tags = retry(dynamodb.list_tags_of_resource, ResourceArn=arn)['Tags']
                if any(t['Key']=='Username' and t['Value']==username for t in tags):
                    retry(dynamodb.delete_table, TableName=tab)
                    logger.info("Deleted DynamoDB %s", tab)
        except Exception as e:
            logger.error("DynamoDB deletion failed: %s", e)

        # Key pairs
        try:
            for kp in retry(ec2.describe_key_pairs)['KeyPairs']:
                nm = kp['KeyName']
                tags = retry(ec2.describe_tags, Filters=[{'Name':'resource-id','Values':[nm]}])['Tags']
                if any(t['Key']=='Username' and t['Value']==username for t in tags):
                    retry(ec2.delete_key_pair, KeyName=nm)
                    logger.info("Deleted KeyPair %s", nm)
        except Exception as e:
            logger.error("KeyPair deletion failed: %s", e)

        # ECS clusters
        try:
            for arn in retry(ecs.list_clusters)['clusterArns']:
                tags = retry(ecs.list_tags_for_resource, resourceArn=arn)['tags']
                if any(t['Key']=='Username' and t['Value']==username for t in tags):
                    retry(ecs.delete_cluster, cluster=arn.split('/')[-1])
                    logger.info("Deleted ECS %s", arn)
        except Exception as e:
            logger.error("ECS deletion failed: %s", e)

        # IAM cleanup
        try:
            for key_obj in retry(iam.list_access_keys, UserName=username)['AccessKeyMetadata']:
                retry(iam.delete_access_key, UserName=username, AccessKeyId=key_obj['AccessKeyId'])
            retry(iam.delete_login_profile, UserName=username)
        except Exception as e:
            logger.error("IAM access disable failed: %s", e)

        try:
            for grp in retry(iam.list_groups_for_user, UserName=username)['Groups']:
                retry(iam.remove_user_from_group, GroupName=grp['GroupName'], UserName=username)
                logger.info("Removed %s from %s", username, grp['GroupName'])
        except Exception as e:
            logger.error("IAM group removal failed: %s", e)

        try:
            retry(iam.delete_user, UserName=username)
            logger.info("Deleted IAM user %s", username)
        except Exception as e:
            logger.error("IAM user deletion failed: %s", e)

        # Delete session record
        try:
            retry(s3.delete_object, Bucket=BUCKET, Key=key)
            logger.info("Deleted session file %s", key)
        except Exception as e:
            logger.error("Session record deletion failed: %s", e)
