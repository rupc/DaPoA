// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { lte, coerce } from 'semver';
import Browser from 'webextension-polyfill';

import { LOCK_ALARM_NAME } from './Alarms';
import FeatureGating from './FeatureGating';
import NetworkEnv from './NetworkEnv';
import Permissions from './Permissions';
import { Connections } from './connections';
import Keyring from './keyring';
import { isSessionStorageSupported } from './storage-utils';
import { openInNewTab } from '_shared/utils';
import { MSG_CONNECT } from '_src/content-script/keep-bg-alive';
import { setAttributes } from '_src/shared/experimentation/features';

Browser.runtime.onInstalled.addListener(async ({ reason, previousVersion }) => {
    // Skip automatically opening the onboarding in end-to-end tests.
    if (navigator.userAgent === 'Playwright') {
        return;
    }

    // TODO: Our versions don't use semver, and instead are date-based. Instead of using the semver
    // library, we can use some combination of parsing into a date + inspecting patch.
    const previousVersionSemver = coerce(previousVersion)?.version;

    if (reason === 'install') {
        openInNewTab();
    } else if (
        reason === 'update' &&
        previousVersionSemver &&
        lte(previousVersionSemver, '0.1.1')
    ) {
        // clear everything in the storage
        // mainly done to clear the mnemonic that was stored
        // as plain text
        await Browser.storage.local.clear();
    }
});

const connections = new Connections();

Permissions.permissionReply.subscribe((permission) => {
    if (permission) {
        connections.notifyContentScript({
            event: 'permissionReply',
            permission,
        });
    }
});

Permissions.on('connectedAccountsChanged', ({ origin, accounts }) => {
    connections.notifyContentScript({
        event: 'walletStatusChange',
        origin,
        change: { accounts },
    });
});

const keyringStatusCallback = () => {
    connections.notifyUI({
        event: 'lockStatusUpdate',
        isLocked: Keyring.isLocked,
    });
};
Keyring.on('lockedStatusUpdate', keyringStatusCallback);
Keyring.on('accountsChanged', keyringStatusCallback);
Keyring.on('activeAccountChanged', keyringStatusCallback);

Browser.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === LOCK_ALARM_NAME) {
        Keyring.reviveDone.finally(() => Keyring.lock());
    }
});

if (!isSessionStorageSupported()) {
    Keyring.on('lockedStatusUpdate', async (isLocked) => {
        if (!isLocked) {
            const allTabs = await Browser.tabs.query({});
            for (const aTab of allTabs) {
                if (aTab.id) {
                    try {
                        await Browser.tabs.sendMessage(aTab.id, MSG_CONNECT);
                    } catch (e) {
                        // not all tabs have the cs installed
                    }
                }
            }
        }
    });
}
NetworkEnv.getActiveNetwork().then(async ({ env, customRpcUrl }) => {
    setAttributes(await FeatureGating.getGrowthBook(), {
        apiEnv: env,
        customRPC: customRpcUrl,
    });
});

NetworkEnv.on('changed', async (network) => {
    setAttributes(await FeatureGating.getGrowthBook(), {
        apiEnv: network.env,
        customRPC: network.customRpcUrl,
    });
    connections.notifyUI({ event: 'networkChanged', network });
    connections.notifyContentScript({
        event: 'walletStatusChange',
        change: { network },
    });
});
