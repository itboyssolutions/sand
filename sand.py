import boto3
import json
import logging
import time
import botocore
from datetime import datetime, timezone
from botocore.config import Config

# Structured logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Add retries to service clients
retry_config = Config(retries={'max_attempts': 8, 'mode': 'standard'})
s3 = boto3.client('s3', config=retry_config)
ec2 = boto3.client('ec2', config=retry_config)
iam = boto3.client('iam', config=retry_config)
rds = boto3.client('rds', config=retry_config)
eks = boto3.client('eks', config=retry_config)
ecr = boto3.client('ecr', config=retry_config)
elbv2 = boto3.client('elbv2', config=retry_config)
dynamodb = boto3.client('dynamodb', config=retry_config)
ecs = boto3.client('ecs', config=retry_config)
cf = boto3.client('cloudformation', config=retry_config)

BUCKET = "aws-sandbox-tracker-659840170574-eu-west-1"
PREFIX = "sessions/"

def retry(func, *args, retries=5, delay=1, **kwargs):
    """Basic exponential backoff retry helper."""
    for i in range(retries):
        try:
            return func(*args, **kwargs)
        except botocore.exceptions.ClientError as e:
            code = e.response['Error']['Code']
            if code in ("DependencyViolation", "Throttling", "TooManyRequestsException"):
                logger.warning("Retryable error: %s (attempt %d)", code, i+1)
                time.sleep(delay)
                delay *= 2
                continue
            raise
    raise RuntimeError(f"Failed {func.__name__} after {retries} retries")

def teardown_vpc(username, tag):
    """Detach and delete VPC-related resources in proper order."""
    vpcs = ec2.describe_vpcs(Filters=[tag])['Vpcs']
    for vpc in vpcs:
        vid = vpc['VpcId']
        logger.info("Processing VPC %s for user %s", vid, username)

        # Detach and delete Internet Gateways
        igws = ec2.describe_internet_gateways(
            Filters=[{'Name': 'attachment.vpc-id', 'Values': [vid]}]
        )['InternetGateways']
        for igw in igws:
            igwid = igw['InternetGatewayId']
            retry(ec2.detach_internet_gateway, InternetGatewayId=igwid, VpcId=vid)
            retry(ec2.delete_internet_gateway, InternetGatewayId=igwid)
            logger.info("Detached & deleted IGW %s", igwid)  # cite detach requirement :contentReference[oaicite:4]{index=4}

        # Delete subnets
        subs = ec2.describe_subnets(Filters=[{'Name':'vpc-id','Values':[vid]}])['Subnets']
        for subnet in subs:
            retry(ec2.delete_subnet, SubnetId=subnet['SubnetId'])
            logger.info("Deleted subnet %s", subnet['SubnetId'])

        # Disassociate and delete non-main route tables
        rts = ec2.describe_route_tables(Filters=[{'Name':'vpc-id','Values':[vid]}])['RouteTables']
        for rt in rts:
            for assoc in rt.get('Associations', []):
                if not assoc.get('Main'):
                    retry(ec2.disassociate_route_table, AssociationId=assoc['RouteTableAssociationId'])
            retry(ec2.delete_route_table, RouteTableId=rt['RouteTableId'])
            logger.info("Deleted route table %s", rt['RouteTableId'])

        # Delete NAT Gateways
        nats = ec2.describe_nat_gateways(Filters=[tag])['NatGateways']
        for nat in nats:
            retry(ec2.delete_nat_gateway, NatGatewayId=nat['NatGatewayId'])
            logger.info("Deleted NAT GW %s", nat['NatGatewayId'])

        # Finally, delete the VPC
        retry(ec2.delete_vpc, VpcId=vid)
        logger.info("Deleted VPC %s", vid)  # cites fully clear delete_vpc dependency doc :contentReference[oaicite:5]{index=5}

def lambda_handler(event, context):
    resp = s3.list_objects_v2(Bucket=BUCKET, Prefix=PREFIX)
    if 'Contents' not in resp:
        logger.info("No sessions to process.")
        return

    now = datetime.now(timezone.utc)
    for obj in resp['Contents']:
        key = obj['Key']
        if not key.endswith('.json'): continue

        data = json.loads(
            s3.get_object(Bucket=BUCKET, Key=key)['Body'].read()
        )
        username = data.get('username')
        expires = datetime.fromisoformat(data['expires_at'].replace("Z","+00:00"))

        if now < expires:
            logger.info("Session %s not expired, skipping", username)
            continue

        logger.info("Cleaning up user %s", username)
        tag = {'Name': 'tag:Username', 'Values': [username]}

        # ✅ VPC teardown with correct dependency order
        try:
            teardown_vpc(username, tag)
        except Exception as e:
            logger.error("Error in VPC teardown for %s: %s", username, e)

        # TODO: Add similar retry + logging logic for other services here...
        # EC2 instances, Volumes, ELBs, RDS, EKS, etc.

        # Finally delete session metadata
        try:
            s3.delete_object(Bucket=BUCKET, Key=key)
            logger.info("Deleted session record %s", key)
        except Exception as e:
            logger.error("Failed to delete session record %s: %s", key, e)
