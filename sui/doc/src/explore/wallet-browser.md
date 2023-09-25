---
title: Sui Wallet
---

This topic describes how to install and use the [Sui Wallet browser extension](https://chrome.google.com/webstore/detail/sui-wallet/opcgpfmipidbgpenhmajoajpbobppdil). You can use the Sui Wallet to create an address, complete transactions, mint NFTs, view or manage assets on the Sui network, and connect with blockchain dApps on Web3.

The early versions of Sui Wallet let you experiment with the Sui network for testing. The Sui network is still in development, and the tokens have no real value. Accounts reset with each deployment of a new version of the network, typically weekly. View the [devnet-updates](https://discord.com/channels/916379725201563759/1004638487078772736) channel in Discord for updates about the network.

To test more advanced features not available in Sui Wallet, see [Sui CLI client](../build/cli-client.md).

## Sui Wallet features

You can use Sui Wallet to:

* Mint NFTs
* Stake and earn SUI
* Transfer coins and NFTs to another address
* View your coins, tokens, and NFTs
* View recent transactions
* Auto split/merge coins to the exact transfer amount
* Easily access transaction history in the [Sui Explorer](https://explorer.sui.io/)

Note that in the current release, Sui Wallet includes buttons to **Buy**, **Swap**, and **Stake & Earn SUI**. These are placeholders for functionality included in future versions of Sui Wallet.

## Install the Sui Wallet browser extension

To use Sui Wallet you must install a Chrome browser extension. You can use the extension with any browser that supports Chrome extensions from the Chrome Web Store.

1. Using a chromium-based browser, open the [Sui Wallet](https://chrome.google.com/webstore/detail/sui-wallet/opcgpfmipidbgpenhmajoajpbobppdil) page on the Chrome Web Store.
1. Click **Add to Chrome**.
1. Acknowledge the message about permissions for the extension, and then click **Add Extension**.

## Create a new wallet

If you don't yet have a Sui Wallet, create a new one. To import an existing wallet, see [Import an existing Sui Wallet](#import-an-existing-sui-wallet).

1. Open the Sui Wallet extension in your browser and then click **Get Started**.
1. Click **Create a New Wallet**.
1. Under **Create Password**, enter a password for your wallet.
   This is not a global password for Sui Wallet. It applies only to this installation in this browser.
1. Under **Confirm Password**, enter the same password to confirm it.
1. Click the checkbox to accept the Terms of Service.
1. Click **Create Wallet**.
1. Copy the Recovery Phrase and store it in a safe location, then click the checkbox for **I saved my recovery phrase**.
1. Click **Open Sui Wallet**.

Sui Wallet prompts you to enter your password when you open it after the first use.

If you lose access to your wallet, you can recover it only with the recovery phrase. If you lose the recovery phrase, you lose access to your wallet and any coins or NFTs stored in it.

## Import an existing Sui Wallet

You can use your Sui Wallet on multiple devices and browsers. After you create a Sui Wallet, use the 12-word recovery phrase to import your wallet to a new browser or device.

1. Open the Sui Wallet extension in your browser and then click **Get Started**.
1. Click **Import an Existing Wallet**.
1. Enter your 12-word recovery phrase, and then click **Continue**.
1. Under **Create Password**, enter a password for your wallet.
   This is not a global password for Sui Wallet. It applies only to this installation in this browser.
1. Under **Confirm Password**, enter the same password to confirm it.
1. Click **Import**.
1. Click **Open Sui Wallet**.

Sui Wallet prompts you to enter your password when you open it after the first use.

## Add SUI tokens to your Sui Wallet

When you first open the wallet, you have no coins in it. You can add test SUI coins to your wallet using the faucet in Discord.

**To get SUI test coins through Discord**
1. Click **Coins**.
1. Click the small clipboard icon next to your address to copy it.
   It's near the top of the wallet and starts with 0x.
1. Go to the Discord faucet channel for the network you use:
   * [devnet-faucet](https://discord.com/channels/916379725201563759/971488439931392130) channel in Discord.
   * [testnet-faucet](https://discord.com/channels/916379725201563759/1037811694564560966).
1. Use the `!faucet` command with your wallet address to request tokens:
   `!faucet 0x6c04ed5110554acf59ff1b535129548dd9a0c741`
   Replace the address in the command with your wallet address.

The channel bot displays a message confirming your request.

## View Sui Wallet details

To view details about your Sui Wallet, including the Account ID, current network, and installed version, click the menu (the three bars) at the top-right corner of the Sui Wallet interface.

## Reset your Sui Wallet password

If you forget the password for your Sui Wallet you can reset it using your 12-word recovery phrase.

1. Click **Forgot password?** on the **Welcome Back** page.
1. Enter your 12-word recovery phrase, and then click **Continue**.
1. Enter a password, then confirm the password.
1. Click **Reset**.

## Lock your Sui Wallet

You can lock your wallet to prevent unauthorized access. You must enter your password to unlock it.

1. Click the menu (the three bars) at the top-right corner of the Sui Wallet interface.
1. Click **Lock Wallet**.

You can also set a timer to automatically lock your wallet after a period of idle time, up to 30 minutes.

1. Click the menu (the three bars) at the top-right corner of the Sui Wallet interface.
1. Click **Account**.
1. In the field under **AUTO-LOCK TIMER**, enter the number of minutes to wait, up to 30, before the wallet locks, and then click **Save**.

The wallet remains unlocked for the number of minutes you specify, even if you switch tabs in your browser.

## Change the active network

You can change the active network for Sui Wallet. Currently, Sui Wallet supports **Sui Devnet**, **Local**, and **Custom RPC URL**. Use Devnet unless you have a local network for testing. To learn how to create a local network, see [Create a Local Sui Network](../build/sui-local-network.md).

1. Click the menu (the three bars) at the top-right corner of the Sui Wallet interface.
1. Click **Network**.
1. Click the network to use.
   A checkmark displays next to the active network.

## View your wallet balance

To view your wallet balance, click **Coins**. The wallet shows your SUI balance and lists the other coins in your wallet, if any.

## Send coins

You can send coins from your wallet to another address.

1. Open the Sui Wallet extension in your browser.
1. Click **Coins** and then click **Send**.
1. In the **Amount** field, enter the number of SUI to send, and then click **Continue**.
1. Enter the recipient's address, then click **Send Coins Now**.

## Stake and earn SUI (Testnet only)

While the Testnet network is available, you can try out staking to earn SUI. When you stake SUI, you delegate your SUI tokens to a validator to stake. The validator then pays you rewards for delegating your SUI to stake. Note that SUI tokens have no value. The rewards are for testing purposes and have no real value.

1. Open your wallet and click **Coins**.
1. Click **Stake & Earn SUI**.
1. Select a validator to stake with.
1. Choose an amount of SUI to stake.
   Be sure to enter an amount that leaves enough SUI in your wallet to cover gas fees.
1. Click **Stake Now**.

Your stake starts earning rewards at the start of the next epoch.

## View current stake

To view details about your current stakes, click **Currently Staked** on the **Coins** tab of the Wallet. Details include: the amount you staked, the validator you chose, amount earned, and the validator commission.

## View recent transaction details

The wallet displays the recent transactions to and from your wallet on the **Activity** tab. Click on any transaction to view transaction details.

## View all transactions in Sui Explorer

You can view all transactions for your address in [Sui Explorer](https://explorer.sui.io/).

To view all of the transactions for your address, click **Apps** and then click **View account on Sui Explorer**.

Sui Explorer opens with the details for your wallet address displayed.

## Mint an example NFT

You can mint an example Sui NFT directly from Sui Wallet.

Click **Apps**, then click **Mint an NFT**. In the current version you can mint only example NFTs.

## Create a new NFT

The [Sui Wallet demo](https://sui-wallet-demo.sui.io/) site lets you create a new NFT on the Sui network using your own image file. To access the site directly from Sui Wallet, click the **Apps** tab, and then click **Sui NFT Mint**. You must have an active wallet to mint NFTs.

To mint a new NFT using the demo site
1. Open the [Sui Wallet demo](https://sui-wallet-demo.sui.io/) site.
1. Click **Connect**.
1. In your Sui Wallet, click **Connect** to connect your wallet with the demo site.
   You may need to enter your wallet password.
1. Enter a **Name** and **Description** for your NFT, and then enter Image URL to the image to use.
1. Click **Create**.
1. Click **Approve** in your wallet to allow the site to add the NFT to your wallet and withdraw gas fees from your SUI balance.

After you successfully create a new NFT, you can transfer it to another wallet address. Enter the address to send it to in the **Recipient** field, then click **Transfer**. Click **Approve** in your wallet to allow the transfer.

You can view details for the transactions to create the NFT and then transfer it in [Sui Explorer](https://explorer.sui.io/).

## View your NFTs

Click the **NFTs** tab to view all of the NFTS that you mint, purchase, or receive in your wallet. This includes any NFTs that you obtain from connected apps.  Click on an NFT to view additional details about it, view a larger NFT image, or send the NFT to another address.

## Send an NFT

You can use Sui Wallet to send an NFT to another address.

1. Click **NFTs**.
1. Click on the NFT to send, and then click **Send NFT**.
1. Enter the recipient address then click **Send NFT Now**.
1. Click **Done** to return to the wallet.

## Wallet Playground

You can view and try out some apps that already support Sui Wallet from the Playground on the Apps tab. The apps displayed let you connect your Sui Wallet and use SUI tokens to interact with them, perform transactions, and obtain NFTs that go directly to your connected wallet.

Click on an app to open the site for the app. Follow the guidance on the site to connect your wallet. After you connect your wallet to an app you can view the app on the **Active Connections** view.

## View connected apps

To view the apps with active connections to your wallet, click **Apps**. By default, the **Playground** view displays. Click **Active Connections** to view the connected apps.

To open the site associated with the app, click on the app and then click **View**.

## Disconnect from an app

You can easily disconnect your wallet from a connected app.
1. Click **Apps** and then click **Active Connections**.
1. Click the app to disconnect from your wallet, then click **Disconnect**.

Your wallet immediately disconnects from the app and returns to the **Apps** tab.
