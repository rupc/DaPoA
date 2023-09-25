// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { cva, type VariantProps } from 'class-variance-authority';

import { Heading } from '_app/shared/heading';
import { Text } from '_app/shared/text';
import Icon, { SuiIcons } from '_components/icon';

import type { ReactNode } from 'react';

const cardLayoutStyles = cva(
    [
        'flex flex-col flex-nowrap rounded-20 items-center justify-center bg-alice-blue shadow-wallet-content p-7.5 pt-10 flex-grow w-full',
    ],
    {
        variants: {
            mode: {
                box: 'bg-alice-blue max-h-popup-height max-w-popup-width',
                plain: 'bg-transparent',
            },
        },
        defaultVariants: {
            mode: 'box',
        },
    }
);

export interface CardLayoutProps extends VariantProps<typeof cardLayoutStyles> {
    title?: string;
    subtitle?: string;
    headerCaption?: string;
    icon?: 'success' | 'sui';
    children: ReactNode | ReactNode[];
}

export default function CardLayout({
    children,
    title,
    subtitle,
    headerCaption,
    icon,
    ...styleProps
}: CardLayoutProps) {
    return (
        <div className={cardLayoutStyles(styleProps)}>
            {icon === 'success' ? (
                <div className="rounded-full w-12 h-12 border-dotted border-success border-2 flex items-center justify-center mb-2.5 p-1">
                    <div className="bg-success rounded-full h-8 w-8 flex items-center justify-center">
                        <Icon
                            icon={SuiIcons.ThumbsUp}
                            className="text-white text-2xl"
                        />
                    </div>
                </div>
            ) : null}
            {icon === 'sui' ? (
                <div className="flex flex-col flex-nowrap items-center justify-center rounded-full w-16 h-16 bg-sui mb-7">
                    <Icon
                        icon={SuiIcons.SuiLogoIcon}
                        className="text-white text-4xl"
                    />
                </div>
            ) : null}
            {headerCaption ? (
                <Text variant="caption" color="steel-dark" weight="semibold">
                    {headerCaption}
                </Text>
            ) : null}
            {title ? (
                <div className="text-center mt-1.25">
                    <Heading
                        variant="heading1"
                        color="gray-90"
                        as="h1"
                        weight="bold"
                        leading="none"
                    >
                        {title}
                    </Heading>
                </div>
            ) : null}
            {subtitle ? (
                <div className="text-center mb-3.75">
                    <Text variant="caption" color="steel-darker" weight="bold">
                        {subtitle}
                    </Text>
                </div>
            ) : null}
            {children}
        </div>
    );
}
