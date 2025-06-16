#!/bin/bash

# === Step 1: Configuration ===
SANDBOX_NAME="terraform"
VALIDITY_MINUTES="${1:-20}"
SESSION_ID="${SANDBOX_NAME}_$(date +%Y%m%d_%H%M%S)"
USERNAME="$SESSION_ID"
GROUPS=("Terraformgrp1" "Terraformgrp2")
STATIC_PASSWORD="Lo6+kl*G6yY@"
CONSOLE_URL="https://signin.aws.amazon.com/console"

# Get AWS account ID and region
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region)
BUCKET_NAME="aws-sandbox-tracker-${ACCOUNT_ID}-${REGION}"

# === Step 2: Create S3 bucket if it doesn't exist ===
if ! aws s3api head-bucket --bucket "$BUCKET_NAME" 2>/dev/null; then
  aws s3api create-bucket \
    --bucket "$BUCKET_NAME" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION"
  echo "✅ S3 bucket created: $BUCKET_NAME"
else
  echo "✅ S3 bucket already exists: $BUCKET_NAME"
fi

echo "🔧 Creating sandbox user: $USERNAME (valid for $VALIDITY_MINUTES minutes)"

# === Step 3: Create IAM user ===
aws iam create-user --user-name "$USERNAME" >/dev/null

# === Step 4: Add user to groups ===
for group in "${GROUPS[@]}"; do
  aws iam add-user-to-group --user-name "$USERNAME" --group-name "$group"
done

# === Step 5: Create login profile ===
aws iam create-login-profile \
  --user-name "$USERNAME" \
  --password "$STATIC_PASSWORD" \
  --password-reset-required

# === Step 6: Create CLI access keys ===
ACCESS_KEYS=$(aws iam create-access-key --user-name "$USERNAME")
AWS_ACCESS_KEY_ID=$(echo "$ACCESS_KEYS" | jq -r .AccessKey.AccessKeyId)
AWS_SECRET_ACCESS_KEY=$(echo "$ACCESS_KEYS" | jq -r .AccessKey.SecretAccessKey)

# === Step 7: Tag the user for cleanup tracking ===
aws iam tag-user --user-name "$USERNAME" --tags \
  Key=Creator,Value=Sandbox \
  Key=ExpiryMinutes,Value="$VALIDITY_MINUTES"

# === Step 8: Push metadata to S3 ===
CREATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EXPIRES_AT=$(date -u -d "+$VALIDITY_MINUTES minutes" +"%Y-%m-%dT%H:%M:%SZ")

# Create JSON file
cat <<EOF > "${USERNAME}.json"
{
  "username": "$USERNAME",
  "created_at": "$CREATED_AT",
  "expires_at": "$EXPIRES_AT",
  "validity_minutes": $VALIDITY_MINUTES
}
EOF

# Upload to S3
aws s3 cp "${USERNAME}.json" "s3://${BUCKET_NAME}/sessions/${USERNAME}.json"
rm "${USERNAME}.json"
echo "📝 Metadata stored in S3: s3://${BUCKET_NAME}/sessions/${USERNAME}.json"

# === Step 9: Display login credentials ===
echo ""
echo "✅ Sandbox user created!"
echo "---------------------------------------"
echo "👤 Username:          $USERNAME"
echo "🔐 Console Password:  $STATIC_PASSWORD"
echo "🌐 Console Login:     $CONSOLE_URL"
echo "🧩 Access Key ID:     $AWS_ACCESS_KEY_ID"
echo "🔑 Secret Access Key: $AWS_SECRET_ACCESS_KEY"
echo "🕒 Expires in:        $VALIDITY_MINUTES minutes"

