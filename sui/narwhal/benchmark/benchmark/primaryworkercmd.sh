# Primary
./narwhal-node -vvv run 
                --primary-keys .primary-0-key.json
                --primary-network-keys .primary-0-network-key.json 
                --worker-keys .worker-0-key.json 
                --committee .committee.json 
                --workers .workers.json 
                --store .db-0 
                --parameters .parameters.json
                primary
                
./narwhal-node -vvv run --primary-keys .primary-1-key.json --primary-network-keys .primary-1-network-key.json --worker-keys .worker-0-key.json --committee .committee.json --workers .workers.json --store .db-1 --parameters .parameters.json primary
./narwhal-node -vvv run --primary-keys .primary-2-key.json --primary-network-keys .primary-2-network-key.json --worker-keys .worker-0-key.json --committee .committee.json --workers .workers.json --store .db-2 --parameters .parameters.json primary
./narwhal-node -vvv run --primary-keys .primary-3-key.json --primary-network-keys .primary-3-network-key.json --worker-keys .worker-0-key.json --committee .committee.json --workers .workers.json --store .db-3 --parameters .parameters.json primary
# Worker
./narwhal-node -vvv run --primary-keys .primary-0-key.json --primary-network-keys .primary-0-network-key.json --worker-keys .worker-0-key.json --committee .committee.json --workers .workers.json --store .db-0-0 --parameters .parameters.json worker --id 0
./narwhal-node -vvv run --primary-keys .primary-1-key.json --primary-network-keys .primary-1-network-key.json --worker-keys .worker-1-key.json --committee .committee.json --workers .workers.json --store .db-1-0 --parameters .parameters.json worker --id 0
./narwhal-node -vvv run --primary-keys .primary-2-key.json --primary-network-keys .primary-2-network-key.json --worker-keys .worker-2-key.json --committee .committee.json --workers .workers.json --store .db-2-0 --parameters .parameters.json worker --id 0
./narwhal-node -vvv run --primary-keys .primary-3-key.json --primary-network-keys .primary-3-network-key.json --worker-keys .worker-3-key.json --committee .committee.json --workers .workers.json --store .db-3-0 --parameters .parameters.json worker --id 0