// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { cx } from 'class-variance-authority';

import { Text } from '../shared/text';

import type { ReactNode } from 'react';

export type SummaryCardProps = {
    header?: string;
    body: ReactNode;
    footer?: ReactNode;
    minimalPadding?: boolean;
    showDivider?: boolean;
};

export function SummaryCard({
    body,
    header,
    footer,
    minimalPadding,
    showDivider = false,
}: SummaryCardProps) {
    return (
        <div className="bg-white flex flex-col flex-nowrap border border-solid border-gray-45 rounded-2xl">
            {header ? (
                <div className="flex flex-row flex-nowrap items-center justify-center uppercase bg-gray-40 px-3.75 py-3 rounded-t-2xl">
                    <Text
                        variant="captionSmall"
                        weight="semibold"
                        color="steel-darker"
                        truncate
                    >
                        {header}
                    </Text>
                </div>
            ) : null}
            <div
                className={cx(
                    'flex-1 flex flex-col items-stretch flex-nowrap px-4',
                    minimalPadding ? 'py-2' : 'py-4',
                    showDivider
                        ? 'divide-x-0 divide-y divide-gray-45 divide-solid'
                        : ''
                )}
            >
                {body}
            </div>
            {footer ? (
                <div className="p-4 pt-3 border-x-0 border-b-0 border-t border-solid border-gray-40">
                    {footer}
                </div>
            ) : null}
        </div>
    );
}
