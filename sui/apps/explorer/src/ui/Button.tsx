// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { cva, type VariantProps } from 'class-variance-authority';

import { LoadingSpinner } from './LoadingSpinner';
import { ButtonOrLink, type ButtonOrLinkProps } from './utils/ButtonOrLink';

const buttonStyles = cva(['inline-flex items-center justify-center relative'], {
    variants: {
        variant: {
            primary: 'bg-sui-dark text-sui-light hover:text-white border-none',
            secondary: 'bg-gray-90 text-gray-50 hover:text-white border-none',
            outline:
                'bg-white border border-steel text-steel-dark hover:text-steel-darker hover:border-steel-dark active:text-steel active:border-steel disabled:border-gray-45 disabled:text-steel-dark',
        },
        size: {
            md: 'px-3 py-2 rounded-md text-bodySmall font-semibold',
            lg: 'px-4 py-3 rounded-lg text-body font-semibold',
        },
    },
    defaultVariants: {
        variant: 'primary',
        size: 'md',
    },
});

export interface ButtonProps
    extends VariantProps<typeof buttonStyles>,
        ButtonOrLinkProps {
    loading?: boolean;
}

export function Button({
    variant,
    size,
    loading,
    children,
    ...props
}: ButtonProps) {
    return (
        <ButtonOrLink
            className={buttonStyles({ variant, size })}
            {...props}
            disabled={props.disabled || loading}
        >
            {loading ? (
                <>
                    <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2">
                        <LoadingSpinner />
                    </div>
                    <div className="text-transparent">{children}</div>
                </>
            ) : (
                children
            )}
        </ButtonOrLink>
    );
}
