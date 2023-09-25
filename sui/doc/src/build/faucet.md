---
title: Requesting Gas Tokens from Faucet
---

Sui faucet is a helpful tool where Sui developers can get free test SUI tokens to deploy and interact with their programs on Sui's Devnet and Testnet.

You can request test tokens in the following ways:

## Prerequisites

To request tokens from the faucet, you must own a wallet address that can receive the SUI tokens. You can generate an address via the [Sui CLI tool](../build/cli-client.md#active-address) or the [Sui wallet](../explore/wallet-browser.md).

## 1. Request test tokens through Discord

1. Join [Discord](https://discord.gg/sui).
   If you try to join the Sui Discord channel using a newly created Discord account, you may need to wait a few days for validation.
1. Request test SUI tokens in the Sui [#devnet-faucet](https://discord.com/channels/916379725201563759/971488439931392130) or [#testnet-faucet](https://discord.com/channels/916379725201563759/1037811694564560966) Discord channels. Note that the Testnet faucet is only available while Testnet is live.
   Send the following message to the channel with your client address:
   `!faucet <Your client address>`

## 2. Request test tokens through wallet

You can request test tokens within [Sui Wallet](../explore/wallet-browser.md#add-sui-tokens-to-your-sui-wallet).

**Important:** This option is disabled for Testnet in Testnet Wave 2. Use the Discord channels instead for Testnet Wave 2.

## 3. Request test tokens through cURL

Use the following cURL command to request tokens directly from the faucet server:

```
curl --location --request POST 'https://faucet.devnet.sui.io/gas' \
--header 'Content-Type: application/json' \
--data-raw '{
    "FixedAmountRequest": {
        "recipient": "<YOUR SUI ADDRESS>"
    }
}'
```

Replace `'https://faucet.devnet.sui.io/gas'` with `http://127.0.0.1:5003/gas` when working with a local network.

**Important:** This option is disabled for Testnet in Testnet Wave 2. Use the Discord channels instead for Testnet Wave 2.

## 4. Request test tokens through TypeScript SDK

You can also access the faucet through the TS-SDK.

```
import { JsonRpcProvider, Network } from '@mysten/sui.js';
// connect to Devnet
const provider = new JsonRpcProvider(Network.DEVNET);
// get tokens from the Devnet faucet server
await provider.requestSuiFromFaucet(
  '<YOUR SUI ADDRESS>'
);
```

**Important:** This option is disabled for Testnet in Testnet Wave 2. Use the Discord channels instead for Testnet Wave 2.
Related topics:

- [Connect to Sui Devnet](../build/devnet.md).
