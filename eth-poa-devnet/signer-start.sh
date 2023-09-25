#!/bin/bash
geth --datadir signer --unlock 6f39b305240abcbd803b9962c0457669b508369f --password= --mine --miner.gasprice 0 --miner.etherbase 6f39b305240abcbd803b9962c0457669b508369f --networkid 42342 --bootnodes enode://0a13916723b1ba1950f89e8358e2ee773e8eeff14089820e7db606c66950c007cc087121ff06ffca08e4bdb56214fe2b7215acaac91d96ab4a4d191b21680806@127.0.0.1:0?discport=30305 --nat extip:141.223.121.45 --log.debug --vmodule miner=4 --vmodule miner/*=4,ethapi/*=4,core/*=4,fetcher/*=4
