// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { type SuiSignTransactionOutput } from '@mysten/wallet-standard';

import { isBasePayload } from '_payloads';

import type { SuiTransactionResponse } from '@mysten/sui.js';
import type { BasePayload, Payload } from '_payloads';

export interface ExecuteTransactionResponse extends BasePayload {
    type: 'execute-transaction-response';
    result: SuiTransactionResponse;
}

export function isExecuteTransactionResponse(
    payload: Payload
): payload is ExecuteTransactionResponse {
    return (
        isBasePayload(payload) &&
        payload.type === 'execute-transaction-response'
    );
}

export interface SignTransactionResponse extends BasePayload {
    type: 'sign-transaction-response';
    result: SuiSignTransactionOutput;
}

export function isSignTransactionResponse(
    payload: Payload
): payload is SignTransactionResponse {
    return (
        isBasePayload(payload) && payload.type === 'sign-transaction-response'
    );
}
