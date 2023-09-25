// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';

import { TxTimeType } from '../tx-time/TxTimeType';

import type {
    SuiEventEnvelope,
    PaginatedEvents,
    SuiEvents,
} from '@mysten/sui.js';

import { useRpc } from '~/hooks/useRpc';
import { Banner } from '~/ui/Banner';
import { AddressLink, ObjectLink, TransactionLink } from '~/ui/InternalLink';
import { PlaceholderTable } from '~/ui/PlaceholderTable';
import { TableCard } from '~/ui/TableCard';

const TRANSACTION_STALE_TIME = 10 * 1000;

const columns = [
    {
        header: 'Time',
        accessorKey: 'time',
    },
    {
        header: 'Package ID',
        accessorKey: 'packageId',
    },
    {
        header: 'Transaction ID',
        accessorKey: 'txnDigest',
    },
    {
        header: 'Sender',
        accessorKey: 'sender',
    },
];

type PackageTableData = {
    time?: string | JSX.Element;
    packageId?: string | JSX.Element;
    txnDigest?: string | JSX.Element;
    sender?: string | JSX.Element;
};

const transformTable = (events: SuiEvents) => ({
    data: events.map(
        ({
            event,
            timestamp,
            txDigest,
        }: SuiEventEnvelope): PackageTableData => {
            if (!('publish' in event)) return {};
            return {
                time: <TxTimeType timestamp={timestamp} />,
                sender: <AddressLink address={event.publish.sender} />,
                packageId: <ObjectLink objectId={event.publish.packageId} />,
                txnDigest: <TransactionLink digest={txDigest} />,
            };
        }
    ),

    columns: [...columns],
});

const RECENT_MODULES_COUNT = 10;

export function RecentModulesCard() {
    const rpc = useRpc();

    const { data, isLoading, isSuccess, isError } = useQuery(
        ['recentPackage'],
        async () => {
            const recentPublishMod: PaginatedEvents = await rpc.getEvents(
                {
                    EventType: 'Publish',
                },
                null,
                RECENT_MODULES_COUNT,
                'descending'
            );

            return recentPublishMod.data;
        },
        {
            staleTime: TRANSACTION_STALE_TIME,
        }
    );

    const tableData = useMemo(
        () => (data ? transformTable(data) : null),
        [data]
    );

    if (isError || (!isLoading && !tableData?.data.length)) {
        return (
            <Banner variant="error" fullWidth>
                No Package Found
            </Banner>
        );
    }

    return (
        <section>
            {isLoading && (
                <PlaceholderTable
                    rowCount={4}
                    rowHeight="13px"
                    colHeadings={[
                        'Time',
                        'Package ID',
                        'Transaction ID',
                        'Sender',
                    ]}
                    colWidths={['25px', '135px', '220px', '220px']}
                />
            )}
            {isSuccess && tableData && (
                <TableCard data={tableData.data} columns={tableData.columns} />
            )}
        </section>
    );
}
