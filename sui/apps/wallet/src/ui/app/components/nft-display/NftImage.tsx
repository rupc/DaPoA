// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { Image32 } from '@mysten/icons';
import { cva } from 'class-variance-authority';
import cl from 'classnames';
import { useState } from 'react';

import type { VariantProps } from 'class-variance-authority';

const nftImageStyles = cva('overflow-hidden', {
    variants: {
        animateHover: {
            true: [
                'ease-ease-out-cubic duration-400',
                'group-hover:shadow-blurXl group-hover:shadow-steel/50',
            ],
        },
        borderRadius: {
            md: 'rounded-md',
            xl: 'rounded-xl',
            sm: 'rounded',
        },
        size: {
            xs: 'w-10 h-10',
            sm: 'w-12 h-12',
            md: 'w-36 h-36',
            lg: 'w-44 h-44',
        },
    },
    compoundVariants: [
        {
            animateHover: true,
            borderRadius: 'xl',
            class: 'group-hover:rounded-md',
        },
    ],
    defaultVariants: {
        borderRadius: 'md',
    },
});

export interface NftImageProps extends VariantProps<typeof nftImageStyles> {
    src: string | null;
    name: string | null;
    title?: string;
    showLabel?: boolean;
}

//TODO: create a fallback image for broken images urls
export function NftImage({
    src,
    name,
    title,
    showLabel,
    animateHover,
    borderRadius,
    size,
}: NftImageProps) {
    const [error, setError] = useState(false);
    const imgCls = cl(
        'w-full h-full object-cover',
        animateHover && 'group-hover:scale-110 duration-500 ease-ease-out-cubic'
    );
    const imgSrc = src
        ? src.replace(/^ipfs:\/\//, 'https://ipfs.io/ipfs/')
        : '';
    return (
        <div
            className={nftImageStyles({
                animateHover,
                borderRadius,
                size,
            })}
        >
            {error ? (
                <div
                    className={cl(
                        imgCls,
                        'flex flex-col flex-nowrap items-center justify-center',
                        'select-none uppercase text-steel-dark gap-2 bg-gray-40'
                    )}
                    title={title}
                >
                    <Image32 className="text-steel text-3xl" />
                    {showLabel ? (
                        <span className="text-captionSmall font-medium">
                            No media
                        </span>
                    ) : null}
                </div>
            ) : (
                <img
                    className={imgCls}
                    src={imgSrc}
                    alt={name || 'NFT'}
                    title={title}
                    onError={() => setError(true)}
                />
            )}
        </div>
    );
}
