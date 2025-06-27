import boto3
import json
import os
from datetime import datetime, timezone

# AWS clients
s3 = boto3.client('s3')
iam = boto3.client('iam')
ec2 = boto3.client('ec2')
lambda_client = boto3.client('lambda')
eks = boto3.client('eks')
ecs = boto3.client('ecs')
cf = boto3.client('cloudformation')
dynamodb = boto3.client('dynamodb')
rds = boto3.client('rds')
ecr = boto3.client('ecr')
elbv2 = boto3.client('elbv2')

# S3 metadata location
BUCKET_NAME = "aws-sandbox-tracker-659840170574-eu-west-1"
SESSION_FOLDER = 'sessions/'

def lambda_handler(event, context):
    response = s3.list_objects_v2(Bucket=BUCKET_NAME, Prefix=SESSION_FOLDER)
    if 'Contents' not in response:
        print("No session files found.")
        return

    for obj in response['Contents']:
        key = obj['Key']
        if not key.endswith('.json'):
            continue

        session_data = json.loads(s3.get_object(Bucket=BUCKET_NAME, Key=key)['Body'].read())
        username = session_data['username']
        expires_at = datetime.fromisoformat(session_data['expires_at'].replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)

        if now < expires_at:
            print(f"User {username} not expired yet.")
            continue

        print(f"Cleaning up resources tagged with username: {username}")

        tag_filters = [{'Name': 'tag:Username', 'Values': [username]}]

        # EC2 Instances
        try:
            instances = ec2.describe_instances(Filters=tag_filters)
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    ec2.terminate_instances(InstanceIds=[instance['InstanceId']])
                    print(f"Terminated EC2 instance: {instance['InstanceId']}")
        except Exception as e:
            print(f"Failed to terminate EC2 instances: {e}")

        # Volumes
        try:
            volumes = ec2.describe_volumes(Filters=tag_filters)['Volumes']
            for vol in volumes:
                ec2.delete_volume(VolumeId=vol['VolumeId'])
                print(f"Deleted volume: {vol['VolumeId']}")
        except Exception as e:
            print(f"Failed to delete volumes: {e}")

        # VPCs
        try:
            vpcs = ec2.describe_vpcs(Filters=tag_filters)['Vpcs']
            for vpc in vpcs:
                ec2.delete_vpc(VpcId=vpc['VpcId'])
                print(f"Deleted VPC: {vpc['VpcId']}")
        except Exception as e:
            print(f"Failed to delete VPCs: {e}")

        # Load Balancers
        try:
            lbs = elbv2.describe_load_balancers()['LoadBalancers']
            for lb in lbs:
                arn = lb['LoadBalancerArn']
                tags = elbv2.describe_tags(ResourceArns=[arn])['TagDescriptions'][0]['Tags']
                if any(tag['Key'] == 'Username' and tag['Value'] == username for tag in tags):
                    elbv2.delete_load_balancer(LoadBalancerArn=arn)
                    print(f"Deleted load balancer: {arn}")
        except Exception as e:
            print(f"Failed to delete load balancers: {e}")

        # CloudFormation Stacks
        try:
            stacks = cf.describe_stacks()['Stacks']
            for stack in stacks:
                tags = stack.get('Tags', [])
                if any(tag['Key'] == 'Username' and tag['Value'] == username for tag in tags):
                    cf.delete_stack(StackName=stack['StackName'])
                    print(f"Deleted CloudFormation stack: {stack['StackName']}")
        except Exception as e:
            print(f"Failed to delete CloudFormation stacks: {e}")

        # S3 Buckets
        try:
            buckets = s3.list_buckets()['Buckets']
            for bucket in buckets:
                name = bucket['Name']
                try:
                    tagging = s3.get_bucket_tagging(Bucket=name)['TagSet']
                    if any(tag['Key'] == 'Username' and tag['Value'] == username for tag in tagging):
                        objs = s3.list_objects_v2(Bucket=name).get('Contents', [])
                        for obj in objs:
                            s3.delete_object(Bucket=name, Key=obj['Key'])
                        s3.delete_bucket(Bucket=name)
                        print(f"Deleted bucket: {name}")
                except Exception:
                    continue
        except Exception as e:
            print(f"Failed to delete S3 buckets: {e}")

        # RDS
        try:
            rds_instances = rds.describe_db_instances()['DBInstances']
            for db in rds_instances:
                arn = db['DBInstanceArn']
                tags = rds.list_tags_for_resource(ResourceName=arn)['TagList']
                if any(tag['Key'] == 'Username' and tag['Value'] == username for tag in tags):
                    rds.delete_db_instance(DBInstanceIdentifier=db['DBInstanceIdentifier'], SkipFinalSnapshot=True)
                    print(f"Deleted RDS instance: {db['DBInstanceIdentifier']}")
        except Exception as e:
            print(f"Failed to delete RDS instances: {e}")

        # EKS
        try:
            clusters = eks.list_clusters()['clusters']
            for cluster_name in clusters:
                desc = eks.describe_cluster(name=cluster_name)['cluster']
                tags = desc.get('tags', {})
                if tags.get('Username') == username:
                    eks.delete_cluster(name=cluster_name)
                    print(f"Deleted EKS cluster: {cluster_name}")
        except Exception as e:
            print(f"Failed to delete EKS clusters: {e}")

        # ECR
        try:
            repos = ecr.describe_repositories()['repositories']
            for repo in repos:
                arn = repo['repositoryArn']
                tags = ecr.list_tags_for_resource(resourceArn=arn)['tags']
                if any(tag['Key'] == 'Username' and tag['Value'] == username for tag in tags):
                    ecr.delete_repository(repositoryName=repo['repositoryName'], force=True)
                    print(f"Deleted ECR repo: {repo['repositoryName']}")
        except Exception as e:
            print(f"Failed to delete ECR repositories: {e}")

        # Elastic IPs
        try:
            eips = ec2.describe_addresses()['Addresses']
            for eip in eips:
                tags = ec2.describe_tags(Filters=[{'Name': 'resource-id', 'Values': [eip['AllocationId']]}])['Tags']
                if any(tag['Key'] == 'Username' and tag['Value'] == username for tag in tags):
                    ec2.release_address(AllocationId=eip['AllocationId'])
                    print(f"Released EIP: {eip['AllocationId']}")
        except Exception as e:
            print(f"Failed to release EIPs: {e}")

        # NAT Gateways
        try:
            nats = ec2.describe_nat_gateways()['NatGateways']
            for nat in nats:
                tags = nat.get('Tags', [])
                if any(tag['Key'] == 'Username' and tag['Value'] == username for tag in tags):
                    ec2.delete_nat_gateway(NatGatewayId=nat['NatGatewayId'])
                    print(f"Deleted NAT Gateway: {nat['NatGatewayId']}")
        except Exception as e:
            print(f"Failed to delete NAT Gateways: {e}")

        # Internet Gateways
        try:
            igws = ec2.describe_internet_gateways()['InternetGateways']
            for igw in igws:
                tags = igw.get('Tags', [])
                if any(tag['Key'] == 'Username' and tag['Value'] == username for tag in tags):
                    ec2.delete_internet_gateway(InternetGatewayId=igw['InternetGatewayId'])
                    print(f"Deleted Internet Gateway: {igw['InternetGatewayId']}")
        except Exception as e:
            print(f"Failed to delete Internet Gateways: {e}")

        # DynamoDB Tables
        try:
            tables = dynamodb.list_tables()['TableNames']
            for table in tables:
                tags = dynamodb.list_tags_of_resource(ResourceArn=dynamodb.describe_table(TableName=table)['Table']['TableArn'])['Tags']
                if any(tag['Key'] == 'Username' and tag['Value'] == username for tag in tags):
                    dynamodb.delete_table(TableName=table)
                    print(f"Deleted DynamoDB Table: {table}")
        except Exception as e:
            print(f"Failed to delete DynamoDB tables: {e}")

        # Key Pairs
        try:
            key_pairs = ec2.describe_key_pairs()['KeyPairs']
            for kp in key_pairs:
                name = kp['KeyName']
                try:
                    tags = ec2.describe_tags(Filters=[{'Name': 'resource-id', 'Values': [name]}])['Tags']
                    if any(tag['Key'] == 'Username' and tag['Value'] == username for tag in tags):
                        ec2.delete_key_pair(KeyName=name)
                        print(f"Deleted Key Pair: {name}")
                except: continue
        except Exception as e:
            print(f"Failed to delete Key Pairs: {e}")

        # ECS Clusters
        try:
            clusters = ecs.list_clusters()['clusterArns']
            for arn in clusters:
                tags = ecs.list_tags_for_resource(resourceArn=arn)['tags']
                if any(tag['Key'] == 'Username' and tag['Value'] == username for tag in tags):
                    ecs.delete_cluster(cluster=arn.split('/')[-1])
                    print(f"Deleted ECS Cluster: {arn}")
        except Exception as e:
            print(f"Failed to delete ECS Clusters: {e}")

        # IAM Cleanup
        try:
            for key_obj in iam.list_access_keys(UserName=username)['AccessKeyMetadata']:
                iam.delete_access_key(UserName=username, AccessKeyId=key_obj['AccessKeyId'])
            iam.delete_login_profile(UserName=username)
        except Exception as e:
            print(f"Access disable failed for {username}: {e}")

        try:
            groups = iam.list_groups_for_user(UserName=username)['Groups']
            for group in groups:
                iam.remove_user_from_group(GroupName=group['GroupName'], UserName=username)
                print(f"Removed {username} from group: {group['GroupName']}")
        except Exception as e:
            print(f"Group removal failed for {username}: {e}")

        try:
            iam.delete_user(UserName=username)
            print(f"Deleted IAM user: {username}")
        except Exception as e:
            print(f"User delete failed for {username}: {e}")

        try:
            s3.delete_object(Bucket=BUCKET_NAME, Key=key)
            print(f"Deleted session file: {key}")
        except Exception as e:
            print(f"Failed to delete session file: {key}, Error: {e}")
