#!/bin/bash
# start node1
geth attach --exec admin.nodeInfo.enr signer/geth.ipc | xargs -I{} geth --http --http.api "eth,net,web3,personal" --http.addr 0.0.0.0 --http.port 40000 --ws --ws.addr 0.0.0.0 --ws.port 40001 --ws.origins "*" --ws.api "eth,net,web3,personal" --datadir node1 --port 30307 --bootnodes {} --networkid 42342 --authrpc.port 8552 --allow-insecure-unlock --log.debug --rpc.enabledeprecatedpersonal --vmodule miner/*=4,ethapi/*=4,core/*=4,fetcher/*=4,eth/*=3
