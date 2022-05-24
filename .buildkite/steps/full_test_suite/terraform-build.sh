#!/bin/bash
set -euo pipefail

source .buildkite/steps/revision.sh

cd .buildkite/steps/full_test_suite

# Terraform part
export TF_VAR_branch=${BUILDKITE_BRANCH}
export TFSTATE_BUCKET="nl-ci-stands"
export TFSTATE_KEY="tests/test-${BUILDKITE_COMMIT}"
export TFSTATE_REGION="us-east-2"
export TF_BACKEND_CONFIG="-backend-config="bucket=${TFSTATE_BUCKET}" -backend-config="key=${TFSTATE_KEY}" -backend-config="region=${TFSTATE_REGION}""
export TF_VAR_proxy_model_commit=${REVISION}
export TF_VAR_neon_evm_commit=${NEON_EVM_COMMIT}
export TF_VAR_faucet_model_commit=${FAUCET_COMMIT}

terraform init ${TF_BACKEND_CONFIG}
terraform apply --auto-approve=true


# Get IPs
terraform output --json | jq -r '.proxy_ip.value' | buildkite-agent meta-data set "PROXY_IP"
terraform output --json | jq -r '.solana_ip.value' | buildkite-agent meta-data set "SOLANA_IP"


# Show IPs
buildkite-agent meta-data get 'PROXY_IP'
buildkite-agent meta-data get 'SOLANA_IP'
