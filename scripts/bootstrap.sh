#!/bin/bash
set -e

REGION="us-east-1"
OWNER="natashaverela-speckm"
REPO="taxstat360-api"

FUNCTIONS=(
  taxstat360-login
  taxstat360-register
  taxstat360-mfa
  taxstat360-password-reset
  taxstat360-email-verify
  taxstat360-aria
  taxstat360-contact
  taxstat360-stripe-checkout
  taxstat360-paystub-proxy
  taxstat360-fb-oauth
  taxstat360-freshbooks-oauth
  taxstat360-xero-oauth
  taxstat360-wave-oauth
  taxstat360-qb-oauth
)

echo ""
echo "=== TaxStat360 Lambda Bootstrap ==="
echo "Paste your GitHub token, then press Enter:"
read -r GITHUB_TOKEN
echo ""

cd /tmp
rm -rf ${REPO}
git clone "https://${OWNER}:${GITHUB_TOKEN}@github.com/${OWNER}/${REPO}.git" "${REPO}"
cd "${REPO}"
git config user.email "natasha.verela@gmail.com"
git config user.name "natashaverela-speckm"
mkdir -p functions

for FN in "${FUNCTIONS[@]}"; do
  echo "Extracting ${FN}..."
  mkdir -p "functions/${FN}"
  URL=$(aws lambda get-function \
    --function-name "${FN}" \
    --region "${REGION}" \
    --query 'Code.Location' \
    --output text)
  curl -s "${URL}" -o "/tmp/${FN}.zip"
  unzip -oq "/tmp/${FN}.zip" -d "functions/${FN}"
  rm "/tmp/${FN}.zip"
  echo "  OK"
done

git add functions/
git commit -m "feat: initial extraction of all 14 Lambda functions from AWS"
git remote set-url origin "https://${OWNER}:${GITHUB_TOKEN}@github.com/${OWNER}/${REPO}.git"
git push origin main

echo ""
echo "Done. All 14 functions are in source control."
echo "https://github.com/${OWNER}/${REPO}"
