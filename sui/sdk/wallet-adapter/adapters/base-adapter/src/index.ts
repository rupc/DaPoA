// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import {
  SignedTransaction,
  SuiTransactionResponse,
  SignedMessage,
} from "@mysten/sui.js";
import {
  SuiSignTransactionInput,
  SuiSignAndExecuteTransactionInput,
  WalletAccount,
  SuiSignMessageInput,
} from "@mysten/wallet-standard";

export interface WalletAdapterEvents {
  change(changes: {
    connected?: boolean;
    accounts?: readonly WalletAccount[];
  }): void;
}

export interface WalletAdapter {
  // Metadata
  name: string;
  icon?: string;

  connected: boolean;
  connecting: boolean;
  // Connection Management
  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
  on: <E extends keyof WalletAdapterEvents>(
    event: E,
    callback: WalletAdapterEvents[E]
  ) => () => void;
  signMessage(messageInput: SuiSignMessageInput): Promise<SignedMessage>;
  signTransaction(
    transactionInput: SuiSignTransactionInput
  ): Promise<SignedTransaction>;
  /**
   * Suggest a transaction for the user to sign. Supports all valid transaction types.
   */
  signAndExecuteTransaction(
    transactionInput: SuiSignAndExecuteTransactionInput
  ): Promise<SuiTransactionResponse>;

  getAccounts: () => Promise<readonly WalletAccount[]>;
}

type WalletAdapterProviderUnsubscribe = () => void;

/**
 * An interface that can dynamically provide wallet adapters. This is useful for
 * cases where the list of wallet adapters is dynamic.
 */
export interface WalletAdapterProvider {
  /** Get a list of wallet adapters from this provider. */
  get(): WalletAdapter[];
  /** Detect changes to the list of wallet adapters. */
  on(
    eventName: "changed",
    callback: () => void
  ): WalletAdapterProviderUnsubscribe;
}

export type WalletAdapterOrProvider = WalletAdapterProvider | WalletAdapter;
export type WalletAdapterList = WalletAdapterOrProvider[];

export function isWalletAdapter(
  wallet: WalletAdapterOrProvider
): wallet is WalletAdapter {
  return "connect" in wallet;
}

export function isWalletProvider(
  wallet: WalletAdapterOrProvider
): wallet is WalletAdapterProvider {
  return !isWalletAdapter(wallet);
}

/**
 * Takes an array of wallet adapters and providers, and resolves it to a
 * flat list of wallet adapters.
 */
export function resolveAdapters(adapterAndProviders: WalletAdapterList) {
  return adapterAndProviders.flatMap((adapter) => {
    if (isWalletProvider(adapter)) {
      return adapter.get();
    }

    return adapter;
  });
}
