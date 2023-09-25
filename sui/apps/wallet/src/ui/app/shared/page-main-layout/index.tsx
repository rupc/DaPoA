// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import cl from 'classnames';
import { type ReactNode } from 'react';

import { useAppSelector } from '../../hooks';
import DappStatus from '../dapp-status';
import { Header } from '../header/Header';
import { Toaster } from '../toaster';
import { ErrorBoundary } from '_components/error-boundary';
import { MenuButton, MenuContent } from '_components/menu';
import Navigation from '_components/navigation';

import st from './PageMainLayout.module.scss';

export type PageMainLayoutProps = {
    children: ReactNode | ReactNode[];
    bottomNavEnabled?: boolean;
    topNavMenuEnabled?: boolean;
    dappStatusEnabled?: boolean;
    className?: string;
};

export default function PageMainLayout({
    children,
    bottomNavEnabled = false,
    topNavMenuEnabled = false,
    dappStatusEnabled = false,
    className,
}: PageMainLayoutProps) {
    const networkName = useAppSelector(({ app: { apiEnv } }) => apiEnv);

    return (
        <div className={st.container}>
            <Header
                networkName={networkName}
                middleContent={dappStatusEnabled ? <DappStatus /> : undefined}
                rightContent={topNavMenuEnabled ? <MenuButton /> : undefined}
            />
            <div className={st.content}>
                <main
                    className={cl(
                        st.main,
                        { [st.withNav]: bottomNavEnabled },
                        className
                    )}
                >
                    <ErrorBoundary>{children}</ErrorBoundary>
                </main>
                {bottomNavEnabled ? <Navigation /> : null}
                {topNavMenuEnabled ? <MenuContent /> : null}
                <Toaster bottomNavEnabled={bottomNavEnabled} />
            </div>
        </div>
    );
}
