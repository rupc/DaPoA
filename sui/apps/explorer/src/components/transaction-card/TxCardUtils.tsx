// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import {
    getExecutionStatusType,
    getTotalGasUsed,
    getTransactions,
    getTransactionDigest,
    getTransactionKindName,
    getTransferObjectTransaction,
    getTransferSuiTransaction,
    SUI_TYPE_ARG,
    type GetTxnDigestsResponse,
    type ExecutionStatusType,
    type TransactionKindName,
    type JsonRpcProvider,
    getTransactionSender,
    formatDigest,
    formatAddress,
} from '@mysten/sui.js';
import { Fragment } from 'react';

import { ReactComponent as ContentArrowRight } from '../../assets/SVGIcons/16px/ArrowRight.svg';
import { getAmount } from '../../utils/getAmount';
import { TxTimeType } from '../tx-time/TxTimeType';

import styles from './RecentTxCard.module.css';

import { useFormatCoin } from '~/hooks/useFormatCoin';
import { AddressLink, ObjectLink, TransactionLink } from '~/ui/InternalLink';
import { TransactionType } from '~/ui/TransactionType';

export type TxnData = {
    To?: string;
    txId: string;
    status: ExecutionStatusType;
    txGas: number;
    suiAmount: bigint | number;
    coinType?: string | null;
    kind: TransactionKindName | undefined;
    From: string;
    timestamp_ms?: number;
};

type Category = 'object' | 'transaction' | 'address';

export type LinkObj = {
    url: string;
    name?: string;
    category?: Category;
};

export function SuiAmount({
    amount,
}: {
    amount: bigint | number | string | undefined | null;
}) {
    const [formattedAmount, coinType] = useFormatCoin(amount, SUI_TYPE_ARG);

    if (amount) {
        const SuiSuffix = <abbr className={styles.suisuffix}>{coinType}</abbr>;

        return (
            <section>
                <span className={styles.suiamount}>
                    {formattedAmount}
                    {SuiSuffix}
                </span>
            </section>
        );
    }

    return <span className={styles.suiamount}>--</span>;
}

export function TxAddresses({ content }: { content: LinkObj[] }) {
    return (
        <section className={styles.addresses}>
            {content.map((itm, idx) => (
                <Fragment key={idx + itm.url}>
                    {itm.category === 'address' ? (
                        <AddressLink address={itm.url} />
                    ) : itm.category === 'object' ? (
                        <ObjectLink objectId={itm.url} />
                    ) : (
                        <TransactionLink digest={itm.url} />
                    )}
                    {idx !== content.length - 1 && <ContentArrowRight />}
                </Fragment>
            ))}
        </section>
    );
}

// Generate table data from the transaction data
export const genTableDataFromTxData = (
    results: TxnData[],
    truncateLength: number
) => ({
    data: results.map((txn) => ({
        date: <TxTimeType timestamp={txn.timestamp_ms} />,
        transactionId: (
            <TxAddresses
                content={[
                    {
                        url: txn.txId,
                        name: formatDigest(txn.txId),
                        category: 'transaction',
                    },
                ]}
            />
        ),
        addresses: (
            <TxAddresses
                content={[
                    {
                        url: txn.From,
                        name: formatAddress(txn.From),
                        category: 'address',
                    },
                    ...(txn.To
                        ? [
                              {
                                  url: txn.To,
                                  name: formatAddress(txn.To),
                                  category: 'address',
                              } as const,
                          ]
                        : []),
                ]}
            />
        ),
        txTypes: (
            <TransactionType
                isSuccess={txn.status === 'success'}
                type={txn.kind}
            />
        ),
        amounts: <SuiAmount amount={txn.suiAmount} />,
        gas: <SuiAmount amount={txn.txGas} />,
    })),
    columns: [
        {
            header: 'Type',
            accessorKey: 'txTypes',
        },
        {
            header: () => (
                <div className={styles.addresses}>Transaction ID</div>
            ),
            accessorKey: 'transactionId',
        },
        {
            header: () => <div className={styles.addresses}>Addresses</div>,
            accessorKey: 'addresses',
        },
        {
            header: 'Amount',
            accessorKey: 'amounts',
        },
        {
            header: 'Gas',
            accessorKey: 'gas',
        },
        {
            header: 'Time',
            accessorKey: 'date',
        },
    ],
});

const dedupe = (arr: string[]) => Array.from(new Set(arr));

export const getDataOnTxDigests = (
    rpc: JsonRpcProvider,
    transactions: GetTxnDigestsResponse
) =>
    rpc.getTransactionWithEffectsBatch(dedupe(transactions)).then((txEffs) =>
        txEffs
            .map((txEff) => {
                const digest = transactions.filter(
                    (transactionId) =>
                        transactionId === getTransactionDigest(txEff)
                )[0];
                // TODO: handle multiple transactions
                const txns = getTransactions(txEff);
                if (txns.length > 1) {
                    console.error(
                        'Handling multiple transactions is not yet supported',
                        txEff
                    );
                    return null;
                }
                const txn = txns[0];
                const txKind = getTransactionKindName(txn);
                const recipient =
                    getTransferObjectTransaction(txn)?.recipient ||
                    getTransferSuiTransaction(txn)?.recipient;

                const transfer = getAmount({
                    txnData: txEff,
                    suiCoinOnly: true,
                })[0];

                // use only absolute value of sui amount
                const suiAmount = transfer?.amount
                    ? Math.abs(transfer.amount)
                    : null;

                return {
                    txId: digest,
                    status: getExecutionStatusType(txEff)!,
                    txGas: getTotalGasUsed(txEff),
                    suiAmount,
                    coinType: transfer?.coinType || null,
                    kind: txKind,
                    From: getTransactionSender(txEff),
                    timestamp_ms: txEff.timestamp_ms || txEff.timestampMs,
                    ...(recipient
                        ? {
                              To: recipient,
                          }
                        : {}),
                };
            })
            // Remove failed transactions
            .filter((itm) => itm)
    );
