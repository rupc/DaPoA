// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { type Validator } from '@mysten/sui.js';
import { useMemo } from 'react';

import { ReactComponent as ArrowRight } from '../../assets/SVGIcons/12px/ArrowRight.svg';
import { StakeColumn } from './StakeColumn';

import { useGetSystemObject } from '~/hooks/useGetObject';
import { Banner } from '~/ui/Banner';
import { ImageIcon } from '~/ui/ImageIcon';
import { ValidatorLink } from '~/ui/InternalLink';
import { Link } from '~/ui/Link';
import { PlaceholderTable } from '~/ui/PlaceholderTable';
import { TableCard } from '~/ui/TableCard';
import { Text } from '~/ui/Text';

const NUMBER_OF_VALIDATORS = 10;

export function processValidators(set: Validator[]) {
    return set.map((av) => ({
        name: av.metadata.name,
        address: av.metadata.sui_address,
        stake: av.staking_pool.sui_balance,
        logo: av.metadata.image_url,
    }));
}

const validatorsTable = (
    validatorsData: Validator[],
    limit?: number,
    showIcon?: boolean
) => {
    const validators = processValidators(validatorsData).sort((a, b) =>
        Math.random() > 0.5 ? -1 : 1
    );

    const validatorsItems = limit ? validators.splice(0, limit) : validators;

    return {
        data: validatorsItems.map(({ name, stake, address, logo }) => ({
            name: (
                <div className="flex items-center gap-2.5">
                    {showIcon && (
                        <ImageIcon
                            src={logo}
                            size="sm"
                            fallback={name}
                            label={name}
                            circle
                        />
                    )}

                    <Link to={`/validator/${encodeURIComponent(address)}`}>
                        {name}
                    </Link>
                </div>
            ),
            stake: <StakeColumn stake={stake} />,
            delegation: (
                <Text variant="bodySmall/medium" color="steel-darker">
                    {stake.toString()}
                </Text>
            ),
            address: <ValidatorLink address={address} noTruncate={!limit} />,
        })),
        columns: [
            {
                header: 'Name',
                accessorKey: 'name',
            },
            {
                header: 'Address',
                accessorKey: 'address',
            },
            {
                header: 'Stake',
                accessorKey: 'stake',
            },
        ],
    };
};

type TopValidatorsCardProps = {
    limit?: number;
    showIcon?: boolean;
};

export function TopValidatorsCard({ limit, showIcon }: TopValidatorsCardProps) {
    const { data, isLoading, isSuccess, isError } = useGetSystemObject();

    const tableData = useMemo(
        () =>
            data
                ? validatorsTable(
                      data.validators.active_validators,
                      limit,
                      showIcon
                  )
                : null,
        [data, limit, showIcon]
    );

    if (isError || (!isLoading && !tableData?.data.length)) {
        return (
            <Banner variant="error" fullWidth>
                Validator data could not be loaded
            </Banner>
        );
    }

    return (
        <>
            {isLoading && (
                <PlaceholderTable
                    rowCount={limit || NUMBER_OF_VALIDATORS}
                    rowHeight="13px"
                    colHeadings={['Name', 'Address', 'Stake']}
                    colWidths={['220px', '220px', '220px']}
                />
            )}

            {isSuccess && tableData && (
                <>
                    <TableCard
                        data={tableData.data}
                        columns={tableData.columns}
                    />
                    {limit && (
                        <div className="mt-3">
                            <Link to="/validators">
                                <div className="flex items-center gap-2">
                                    More Validators
                                    <ArrowRight fill="currentColor" />
                                </div>
                            </Link>
                        </div>
                    )}
                </>
            )}
        </>
    );
}
