#!/bin/bash
# One-time: add stripe_customer_id GSI to taxstat360-users (run on EC2 or with AWS CLI creds).
# Enables O(1) webhook plan updates instead of full-table scans.
set -euo pipefail

TABLE="${USERS_TABLE:-taxstat360-users}"
INDEX="${USERS_STRIPE_CUSTOMER_GSI:-stripe_customer_id-index}"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"

echo "Creating GSI ${INDEX} on ${TABLE} (region ${REGION})..."

aws dynamodb update-table \
  --region "$REGION" \
  --table-name "$TABLE" \
  --attribute-definitions AttributeName=stripe_customer_id,AttributeType=S \
  --global-secondary-index-updates \
  "[{\"Create\":{\"IndexName\":\"${INDEX}\",\"KeySchema\":[{\"AttributeName\":\"stripe_customer_id\",\"KeyType\":\"HASH\"}],\"Projection\":{\"ProjectionType\":\"ALL\"}}}]"

echo "Waiting for index to become ACTIVE..."
aws dynamodb wait table-exists --region "$REGION" --table-name "$TABLE"
while true; do
  STATUS=$(aws dynamodb describe-table --region "$REGION" --table-name "$TABLE" \
    --query "Table.GlobalSecondaryIndexes[?IndexName=='${INDEX}'].IndexStatus | [0]" \
    --output text)
  echo "  ${INDEX} status: ${STATUS}"
  [ "$STATUS" = "ACTIVE" ] && break
  sleep 5
done
echo "Done. Set USERS_STRIPE_CUSTOMER_GSI=${INDEX} in .env if you use a custom name."
