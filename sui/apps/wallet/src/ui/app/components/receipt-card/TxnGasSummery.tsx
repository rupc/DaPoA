// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useFormatCoin } from '_hooks';
import { GAS_TYPE_ARG } from '_redux/slices/sui-objects/Coin';
import { Text } from '_src/ui/app/shared/text';

import type { GasCostSummary } from '@mysten/sui.js';

type TxnGasSummeryProps = {
    gasSummary?: GasCostSummary;
    totalGas: number;
    transferAmount: number | null;
};

//TODO add gas breakdown
export function TxnGasSummery({
    gasSummary,
    totalGas,
    transferAmount,
}: TxnGasSummeryProps) {
    const [totalAmount, totalAmountSymbol] = useFormatCoin(
        totalGas + (transferAmount || 0),
        GAS_TYPE_ARG
    );
    const [gas, symbol] = useFormatCoin(totalGas, GAS_TYPE_ARG);

    return (
        <div className="flex flex-col w-full items-center gap-3.5 border-t border-solid border-steel/20 border-x-0 border-b-0 py-3.5 first:pt-0">
            <div className="flex justify-between items-center w-full">
                <Text variant="body" weight="medium" color="steel-darker">
                    Gas Fees
                </Text>

                <div className="flex gap-1 items-center">
                    <Text variant="body" weight="medium" color="steel-darker">
                        {gas} {symbol}
                    </Text>
                </div>
            </div>
            {transferAmount ? (
                <div className="flex justify-between items-center w-full">
                    <Text variant="body" weight="medium" color="steel-darker">
                        Total Amount
                    </Text>

                    <div className="flex gap-1 items-center">
                        <Text
                            variant="body"
                            weight="medium"
                            color="steel-darker"
                        >
                            {totalAmount} {totalAmountSymbol}
                        </Text>
                    </div>
                </div>
            ) : null}
        </div>
    );
}
