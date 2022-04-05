#!/bin/bash

source .buildkite/steps/full_test_suite/utils.sh


cd .buildkite/steps/full_test_suite

export NEON_EVM_COMMIT=${NEON_EVM_COMMIT:-latest}
export PROXY_MODEL_COMMIT=${BUILDKITE_COMMIT}

### Clean infrastructure by terraform
export TF_VAR_branch=${BUILDKITE_BRANCH}
export TF_VAR_neon_evm_commit=${NEON_EVM_COMMIT}
export TF_VAR_proxy_model_commit=${PROXY_MODEL_COMMIT}
export TFSTATE_BUCKET="nl-ci-stands"
export TFSTATE_KEY="tests/test-$BUILDKITE_COMMIT"
export TFSTATE_REGION="us-east-2"
export TF_BACKEND_CONFIG="-backend-config="bucket=${TFSTATE_BUCKET}" -backend-config="key=${TFSTATE_KEY}" -backend-config="region=${TFSTATE_REGION}""
terraform init $TF_BACKEND_CONFIG
handle_error "Failed to proceed the terraform init step. TF_BACKEND_CONFIG: ${TF_BACKEND_CONFIG}"
terraform destroy --auto-approve=true
handle_error "Failed to proceed terraform destroy step"


# info
buildkite-agent meta-data get "PROXY_IP"
buildkite-agent meta-data get "SOLANA_IP"
