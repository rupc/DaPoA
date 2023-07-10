#! env sh

# if [ -d ./data ]; then
#     echo "removing the existing blockchain data directory"
#     rm ./data -rf
# fi

if [ ! -f genesis.json ]; then
    echo "genesis.json must be provided"
    exit 1
fi


if [ -d ./signer/geth ]; then
    echo "signer/geth removed"
    rm ./signer/geth -R
fi

if [ -d ./node1/geth ]; then
    echo "node1/geth removed"
    rm ./node1/geth -R
fi

if [ -d ./node2/geth ]; then
    echo "node2/geth removed"
    rm ./node2/geth -R
fi


echo "Initializing signer node directory"
geth init --datadir ./signer genesis.json
echo ""

echo "Initializing Member node(node1,node2) directory"
geth init --datadir ./node1 genesis.json
geth init --datadir ./node2 genesis.json
