// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import {
  Ed25519Keypair,
  getCertifiedTransaction,
  getTransactionEffects,
  JsonRpcProvider,
  LocalTxnDataSerializer,
  RawSigner,
  Connection,
  devnetConnection, getEvents,
} from "@mysten/sui.js";
import {
  WalletAdapter,
  WalletAdapterEvents,
} from "@mysten/wallet-adapter-base";
import { ReadonlyWalletAccount } from "@mysten/wallet-standard";

export class UnsafeBurnerWalletAdapter implements WalletAdapter {
  name = "Unsafe Burner Wallet";
  icon =
    "data:image/png;base64,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";

  connecting: boolean;
  connected: boolean;

  #provider: JsonRpcProvider;
  #keypair: Ed25519Keypair;
  #signer: RawSigner;
  #account: ReadonlyWalletAccount;

  constructor(network: Connection = devnetConnection) {
    this.#keypair = new Ed25519Keypair();
    this.#provider = new JsonRpcProvider(network);
    this.#account = new ReadonlyWalletAccount({
      address: this.#keypair.getPublicKey().toSuiAddress(),
      chains: ["sui:unknown"],
      features: ["sui:signAndExecuteTransaction", "sui:signTransaction"],
      publicKey: this.#keypair.getPublicKey().toBytes(),
    });
    this.#signer = new RawSigner(
      this.#keypair,
      this.#provider,
      new LocalTxnDataSerializer(this.#provider)
    );
    this.connecting = false;
    this.connected = false;

    console.warn(
      "Your application is currently using the `UnsafeBurnerWalletAdapter`. Make sure that this adapter is not included in production."
    );
  }

  async getAccounts() {
    return [this.#account];
  }

  signMessage: WalletAdapter["signMessage"] = async (messageInput) => {
    return this.#signer.signMessage(messageInput.message);
  };

  signTransaction: WalletAdapter["signTransaction"] = async (
    transactionInput
  ) => {
    return this.#signer.signTransaction(transactionInput.transaction);
  };

  signAndExecuteTransaction: WalletAdapter["signAndExecuteTransaction"] =
    async (transactionInput) => {
      const response = await this.#signer.signAndExecuteTransaction(
        transactionInput.transaction,
        transactionInput.options?.requestType
      );

      return {
        certificate: getCertifiedTransaction(response)!,
        effects: getTransactionEffects(response)!,
        events: getEvents(response)!,
        timestamp_ms: null,
        parsed_data: null,
      };
    };

  async connect() {
    this.connecting = true;
    try {
      this.#signer.requestSuiFromFaucet();
    } catch (e) {
      console.warn(
        "Failed to request Sui from the faucet. This may prevent transactions from being submitted."
      );
      console.warn(e);
    }
    this.connecting = false;
    this.connected = true;
  }

  async disconnect() {
    this.connecting = false;
    this.connected = false;
  }

  on: <E extends keyof WalletAdapterEvents>(
    event: E,
    callback: WalletAdapterEvents[E]
  ) => () => void = () => {
    return () => {};
  };
}
