#!/bin/bash
set -x


NOT_RUNNING="true" fab local
# Build Only narwhal-node
# cargo build --bin narwhal-node
# Copy narwhal-node to local for docker build
rm ./narwhal-node
cp --dereference ../../target/debug/narwhal-node .

# Build docker image
docker build -t mec-narwhal .

numNodes=4


# Copy keys and config files to validators for container running
for i in $(seq 0 $((numNodes - 1)))
do
   cp .primary-"${i}"-key.json ./validators/validator-"${i}"/primary-key.json
   cp .primary-"${i}"-network-key.json ./validators/validator-"${i}"/network-key.json
   cp .worker-"${i}"-key.json ./validators/validator-"${i}"/worker-key.json
done

# It's fucking important part... 
# convert default local address (i.e., 127.0.0.1 to docker address)
./convert-local-to-docker.py --committee.json ".committee.json" --workers.json ".workers.json" --parameters.json ".parameters.json"


cp .committee.json ./validators/committee.json
cp .workers.json ./validators/workers.json
cp .parameters.json ./validators/parameters.json

# copy to deploy directory 
DeployDir="/home/jyr/go/src/github.com/hyperledger/fabric/speculator/production/deploy/swarm/production/production-narwhal"

sudo cp ./validators ./production-narwhal/ -r
sudo rm ${DeployDir}/validators -rf
sudo cp ./validators ${DeployDir} -r
set +x
