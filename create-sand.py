import boto3
import json
import datetime
import os

# === Configuration ===
REGION = "eu-west-1"
SANDBOX_NAME = "Kubernetes"
VALIDITY_MINUTES = 10
ACCESS_GROUPS = ["EKS_Group1", "EKS_Group2"]
STATIC_PASSWORD = "Lo6+sd26G6yY@"
CONSOLE_URL = "https://agile-techpractices.signin.aws.amazon.com/console"

# AWS Clients
sts = boto3.client('sts')
iam = boto3.client('iam')
s3 = boto3.client('s3', region_name=REGION)

def lambda_handler(event, context):
    print("🚀 Lambda triggered")

    # Generate session username
    session_id = f"{SANDBOX_NAME}_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    username = session_id
    print(f"🧑 Generating IAM user: {username}")

    # Get AWS Account ID
    try:
        account_id = sts.get_caller_identity()['Account']
        print(f"✅ Account ID: {account_id}")
    except Exception as e:
        print(f"❌ Error getting account ID: {e}")
        return {"statusCode": 500, "body": "Error getting account ID"}

    bucket_name = f"aws-sandbox-tracker-{account_id}-{REGION}"
    print(f"📦 Using bucket: {bucket_name}")

    # Ensure bucket exists
    try:
        s3.head_bucket(Bucket=bucket_name)
        print("✅ S3 bucket exists")
    except s3.exceptions.ClientError:
        try:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': REGION}
            )
            print("✅ S3 bucket created")
        except Exception as e:
            print(f"❌ Failed to create bucket: {e}")
            return {"statusCode": 500, "body": "Failed to create S3 bucket"}

    # Create IAM user
    try:
        iam.create_user(UserName=username)
        print("👤 IAM user created")
    except Exception as e:
        print(f"❌ Error creating user: {e}")
        return {"statusCode": 500, "body": "Error creating IAM user"}

    # Add user to groups
    for group in ACCESS_GROUPS:
        try:
            iam.add_user_to_group(UserName=username, GroupName=group)
            print(f"✅ Added to group: {group}")
        except Exception as e:
            print(f"❌ Failed to add to group {group}: {e}")

    # Create login profile
    try:
        iam.create_login_profile(
            UserName=username,
            Password=STATIC_PASSWORD,
            PasswordResetRequired=False
        )
        print("🔐 Login profile created")
    except Exception as e:
        print(f"❌ Error creating login profile: {e}")
        return {"statusCode": 500, "body": "Failed to create login profile"}

    # Create access keys
    try:
        keys = iam.create_access_key(UserName=username)
        access_key_id = keys['AccessKey']['AccessKeyId']
        secret_access_key = keys['AccessKey']['SecretAccessKey']
        print("🔑 Access keys created")
    except Exception as e:
        print(f"❌ Error creating access keys: {e}")
        return {"statusCode": 500, "body": "Failed to create access keys"}

    # Tag user
    try:
        iam.tag_user(
            UserName=username,
            Tags=[
                {'Key': 'Creator', 'Value': 'Sandbox'},
                {'Key': 'ExpiryMinutes', 'Value': str(VALIDITY_MINUTES)},
                {'Key': 'Type', 'Value': 'AppID'}
            ]
        )
        print("🏷️ IAM user tagged")
    except Exception as e:
        print(f"❌ Failed to tag user: {e}")

    # Create metadata and upload to S3
    try:
        created_at = datetime.datetime.utcnow().isoformat() + 'Z'
        expires_at = (datetime.datetime.utcnow() + datetime.timedelta(minutes=VALIDITY_MINUTES)).isoformat() + 'Z'

        metadata = {
            "username": username,
            "created_at": created_at,
            "expires_at": expires_at,
            "validity_minutes": VALIDITY_MINUTES
        }

        tmp_file = f"/tmp/{username}.json"
        with open(tmp_file, 'w') as f:
            json.dump(metadata, f)

        s3.upload_file(tmp_file, bucket_name, f"sessions/{username}.json")
        os.remove(tmp_file)
        print("📝 Metadata uploaded to S3")
    except Exception as e:
        print(f"❌ Failed to store metadata: {e}")
        return {"statusCode": 500, "body": "Metadata upload failed"}

    # Success response
    print("✅ All steps completed successfully")
    return {
        "statusCode": 200,
        "body": json.dumps({
            "username": username,
            "console_password": STATIC_PASSWORD,
            "console_login": CONSOLE_URL,
            "access_key_id": access_key_id,
            "secret_access_key": secret_access_key,
            "validity_minutes": VALIDITY_MINUTES,
            "tag_instruction": f"Key=Username,Value={username}"
        })
    }
