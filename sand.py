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

        # Disable User
        try:
            for key_obj in iam.list_access_keys(UserName=username)['AccessKeyMetadata']:
                iam.delete_access_key(UserName=username, AccessKeyId=key_obj['AccessKeyId'])
            iam.delete_login_profile(UserName=username)
        except Exception as e:
            print(f"Access disable failed for {username}: {e}")

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

        # EKS Cleanup
        try:
            clusters = eks.list_clusters()['clusters']
            for cluster_name in clusters:
                desc = eks.describe_cluster(name=cluster_name)['cluster']
                tags = desc.get('tags', {})
                if tags.get('Username') == username:
                    print(f"Cleaning up EKS cluster: {cluster_name}")

                    # 1. Delete Node Groups first
                    node_groups = eks.list_nodegroups(clusterName=cluster_name)['nodegroups']
                    for node_group in node_groups:
                        eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=node_group)
                        print(f"Deleted Node Group: {node_group} from cluster: {cluster_name}")

                    # 2. Delete ECR repositories associated with this EKS cluster
                    ecr_repos = ecr.describe_repositories()['repositories']
                    for repo in ecr_repos:
                        tags = ecr.list_tags_for_resource(resourceArn=repo['repositoryArn'])['tags']
                        if any(tag['Key'] == 'Username' and tag['Value'] == username for tag in tags):
                            ecr.delete_repository(repositoryName=repo['repositoryName'], force=True)
                            print(f"Deleted ECR repository: {repo['repositoryName']}")

                    # 3. Delete Load Balancers (ALB/NLB) used by the EKS services
                    lb_arns = elbv2.describe_load_balancers()['LoadBalancers']
                    for lb in lb_arns:
                        arn = lb['LoadBalancerArn']
                        lb_tags = elbv2.describe_tags(ResourceArns=[arn])['TagDescriptions'][0]['Tags']
                        if any(tag['Key'] == 'Username' and tag['Value'] == username for tag in lb_tags):
                            elbv2.delete_load_balancer(LoadBalancerArn=arn)
                            print(f"Deleted Load Balancer: {arn}")

                    # 4. Delete the EKS cluster itself
                    eks.delete_cluster(name=cluster_name)
                    print(f"Deleted EKS cluster: {cluster_name}")

        except Exception as e:
            print(f"Failed to delete EKS cluster or associated resources: {e}")

        # VPCs and Dependencies
        try:
            vpcs = ec2.describe_vpcs(Filters=tag_filters)['Vpcs']
            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                print(f"Cleaning up resources for VPC: {vpc_id}")

                # 1. Detach and Delete Internet Gateways
                igws = ec2.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])['InternetGateways']
                for igw in igws:
                    igw_id = igw['InternetGatewayId']
                    ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
                    ec2.delete_internet_gateway(InternetGatewayId=igw_id)
                    print(f"Detached and deleted Internet Gateway: {igw_id}")

                # 2. Delete Route Tables (Ensure they are not the main route table before deleting)
                route_tables = ec2.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['RouteTables']
                for route_table in route_tables:
                    if not route_table['Associations'][0]['Main']:  # Don't delete the main route table
                        ec2.delete_route_table(RouteTableId=route_table['RouteTableId'])
                        print(f"Deleted Route Table: {route_table['RouteTableId']}")

                # 4. Delete NAT Gateways
                nat_gateways = ec2.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['NatGateways']
                for nat in nat_gateways:
                    ec2.delete_nat_gateway(NatGatewayId=nat['NatGatewayId'])
                    print(f"Deleted NAT Gateway: {nat['NatGatewayId']}")

                #  Delete Subnets
                subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['Subnets']
                for subnet in subnets:
                    subnet_id = subnet['SubnetId']
                    print(f"Deleting subnet: {subnet_id}")
                    ec2.delete_subnet(SubnetId=subnet_id)
                    print(f"Deleted subnet: {subnet_id}")

                #  Finally, Delete the VPC
                ec2.delete_vpc(VpcId=vpc_id)
                print(f"Deleted VPC: {vpc_id}")

        except Exception as e:
            print(f"Failed to delete VPC or associated resources: {e}")

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
