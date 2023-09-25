// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { cva, type VariantProps } from 'class-variance-authority';
import { forwardRef, type ReactNode, type Ref } from 'react';

import { ButtonOrLink, type ButtonOrLinkProps } from './utils/ButtonOrLink';

const styles = cva(
    [
        'transition flex flex-nowrap items-center justify-center outline-none gap-1 w-full',
        'no-underline bg-transparent p-0 border-none',
        'text-bodySmall',
        'active:opacity-70',
        'disabled:opacity-40',
        'cursor-pointer group',
    ],
    {
        variants: {
            color: {
                steelDark: [
                    'text-steel-dark hover:text-steel-darker focus:text-steel-darker disabled:text-steel-dark',
                ],
                heroDark: [
                    'text-hero-dark hover:text-hero-darkest focus:text-hero-darkest disabled:text-hero-dark',
                ],
                suiDark: ['text-sui-dark'],
            },
            weight: {
                semibold: 'font-semibold',
                medium: 'font-medium',
            },
        },
    }
);

const iconStyles = cva(['transition flex'], {
    variants: {
        color: {
            steelDark: [
                'text-steel group-hover:text-steel-darker group-focus:text-steel-darker group-disabled:text-steel-dark',
            ],
            heroDark: [
                'text-hero group-hover:text-hero-darkest group-focus:text-hero-darkest group-disabled:text-hero-dark',
            ],
            suiDark: [
                'text-steel group-hover:text-sui-dark group-focus:text-sui-dark group-disabled:text-steel',
            ],
        },
    },
});

interface LinkProps
    extends VariantProps<typeof styles>,
        VariantProps<typeof iconStyles>,
        Omit<ButtonOrLinkProps, 'className' | 'color'> {
    before?: ReactNode;
    after?: ReactNode;
    text?: ReactNode;
}

export const Link = forwardRef(
    (
        { before, after, text, color, weight, ...otherProps }: LinkProps,
        ref: Ref<HTMLAnchorElement | HTMLButtonElement>
    ) => (
        <ButtonOrLink
            className={styles({ color, weight })}
            {...otherProps}
            ref={ref}
        >
            {before ? (
                <div className={iconStyles({ color })}>{before}</div>
            ) : null}
            {text ? (
                <div className={'truncate leading-tight'}>{text}</div>
            ) : null}
            {after ? (
                <div className={iconStyles({ color })}>{after}</div>
            ) : null}
        </ButtonOrLink>
    )
);

Link.displayName = 'Link';
