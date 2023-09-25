// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import BigNumber from 'bignumber.js';

export function formatAmount(
    amount?: BigNumber | bigint | number | string | null
) {
    if (typeof amount === 'undefined' || amount === null) {
        return '--';
    }

    let postfix = '';
    let bn = new BigNumber(amount.toString());

    if (bn.gte(1_000_000_000)) {
        bn = bn.shiftedBy(-9);
        postfix = ' B';
    } else if (bn.gte(1_000_000)) {
        bn = bn.shiftedBy(-6);
        postfix = ' M';
    } else if (bn.gte(10_000)) {
        bn = bn.shiftedBy(-3);
        postfix = ' K';
    }

    if (bn.gte(1)) {
        bn = bn.decimalPlaces(3, BigNumber.ROUND_DOWN);
    }

    return bn.toFormat() + postfix;
}
