// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import {
    type ExplorerLinkConfig,
    useExplorerLink,
} from '../../hooks/useExplorerLink';
import ExternalLink from '_components/external-link';
import Icon, { SuiIcons } from '_components/icon';
import { trackEvent } from '_src/shared/plausible';

import type { ReactNode } from 'react';

import st from './ExplorerLink.module.scss';

export type ExplorerLinkProps = ExplorerLinkConfig & {
    track?: boolean;
    children?: ReactNode;
    className?: string;
    title?: string;
    showIcon?: boolean;
};

function ExplorerLink({
    track,
    children,
    className,
    title,
    showIcon,
    ...linkConfig
}: ExplorerLinkProps) {
    const explorerHref = useExplorerLink(linkConfig);
    if (!explorerHref) {
        return null;
    }

    return (
        <ExternalLink
            href={explorerHref}
            className={className}
            title={title}
            showIcon={false}
            onClick={() => {
                if (track) {
                    trackEvent('ViewExplorerAccount');
                }
            }}
        >
            <>
                {children}{' '}
                {showIcon && (
                    <Icon
                        icon={SuiIcons.ArrowLeft}
                        className={st.explorerIcon}
                    />
                )}
            </>
        </ExternalLink>
    );
}

export default ExplorerLink;
