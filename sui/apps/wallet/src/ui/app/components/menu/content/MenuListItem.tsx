// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { ChevronRight16 } from '@mysten/icons';
import { Link } from 'react-router-dom';

import type { MouseEventHandler, ReactNode } from 'react';

export type ItemProps = {
    icon: ReactNode;
    title: ReactNode;
    subtitle?: ReactNode;
    iconAfter?: ReactNode;
    to?: string;
    onClick?: MouseEventHandler<Element>;
};

function MenuListItem({
    icon,
    title,
    subtitle,
    iconAfter,
    to = '',
    onClick,
}: ItemProps) {
    const Component = to ? Link : 'div';
    return (
        <Component
            className="flex flex-nowrap items-center px-1 py-4.5 first:pt-3 last:pb-3 gap-5 no-underline overflow-hidden group cursor-pointer"
            to={to}
            onClick={onClick}
        >
            <div className="flex flex-nowrap flex-1 gap-2 items-center overflow-hidden basis-3/5">
                <div className="flex text-steel text-2xl flex-none">{icon}</div>
                <div className="flex-1 text-gray-90 text-body font-semibold truncate">
                    {title}
                </div>
            </div>
            <div className="flex flex-nowrap flex-1 justify-end gap-1 items-center overflow-hidden basis-2/5">
                {subtitle ? (
                    <div className="transition truncate text-steel-dark text-bodySmall font-medium group-hover:text-steel-darker">
                        {subtitle}
                    </div>
                ) : null}
                <div className="transition flex text-steel flex-none text-base group-hover:text-steel-darker">
                    {iconAfter || (to && <ChevronRight16 />) || null}
                </div>
            </div>
        </Component>
    );
}

export default MenuListItem;
