#!/bin/bash


# Install docker
sudo apt-get remove docker docker-engine docker.io containerd runc
sudo apt-get update
sudo apt-get -y install ca-certificates curl gnupg lsb-release
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get -y install docker-ce docker-ce-cli containerd.io

sudo apt-get -y install pbzip2

# Install docker-compose
sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose


# Get docker-compose file
cd /opt
curl -O https://raw.githubusercontent.com/neonlabsorg/proxy-model.py/${branch}/proxy/docker-compose-test.yml


# Set required environment variables
export REVISION=${proxy_model_commit}
export SOLANA_URL=http:\/\/${solana_ip}:8899
export NEON_EVM_COMMIT=${neon_evm_commit}
export FAUCET_COMMIT=${faucet_model_commit}


# Generate docker-compose override file
cat > docker-compose-test.override.yml <<EOF
version: "3"

services:
  solana:
    healthcheck:
      test: [ CMD-SHELL, "/echo done" ]
    entrypoint: "/usr/bin/sleep 10000"

services:
  proxy:
    environment:
      - SOLANA_URL=$SOLANA_URL
  faucet:
    environment:
      - SOLANA_URL=$SOLANA_URL
  indexer:
    environment:
      - SOLANA_URL=$SOLANA_URL
  deploy_contracts:
    command: bash -c "echo done"
  proxy_program_loader:
    command: bash -c "echo done"
EOF


# Get list of services
SERVICES=$(docker-compose -f docker-compose-test.yml config --services | grep -vP "solana|airdropper|prometheus|deploy_contracts|proxy_program_loader")


# Pull latest versions
docker-compose -f docker-compose-test.yml -f docker-compose-test.override.yml pull $SERVICES


# Check if Solana is available, max attepts is 100(each for 2 seconds)
CHECK_COMMAND=`curl $SOLANA_URL -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1, "method":"getHealth"}'`
MAX_COUNT=100
CURRENT_ATTEMPT=1
while [[ "$CHECK_COMMAND" != "{\"jsonrpc\":\"2.0\",\"result\":\"ok\",\"id\":1}" && $CURRENT_ATTEMPT -lt $MAX_COUNT ]]
do
  CHECK_COMMAND=`curl $SOLANA_URL -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1, "method":"getHealth"}'`
  echo $CHECK_COMMAND >> /tmp/output.txt
  echo "attempt: $CURRENT_ATTEMPT" 1>&2
  ((CURRENT_ATTEMPT=CURRENT_ATTEMPT+1))
  sleep 2
done;


# Up all services
docker-compose -f docker-compose-test.yml -f docker-compose-test.override.yml up -d $SERVICES


# Remove unused
docker rm -f solana
docker rm -f deploy_contracts
