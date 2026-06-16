#!/bin/bash
# One-time creation of the account-deletion audit-log table.
# The app also tries to auto-create this on first use, but if the runtime IAM role
# lacks CreateTable permission, run this once with admin credentials.
set -e

REGION="${AWS_DEFAULT_REGION:-us-east-1}"
TABLE="${AUDIT_TABLE:-taxstat360-audit}"

echo "Creating DynamoDB table '${TABLE}' in ${REGION} ..."
aws dynamodb create-table \
  --table-name "${TABLE}" \
  --attribute-definitions AttributeName=auditId,AttributeType=S \
  --key-schema AttributeName=auditId,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region "${REGION}"

echo "Waiting for table to become active ..."
aws dynamodb wait table-exists --table-name "${TABLE}" --region "${REGION}"
echo "Done. '${TABLE}' is ready."
