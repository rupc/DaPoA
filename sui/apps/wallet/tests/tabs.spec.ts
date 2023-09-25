// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { test, expect } from './fixtures';
import { createWallet } from './utils/auth';

test('NFTs tab', async ({ page, extensionUrl }) => {
    await createWallet(page, extensionUrl);
    await page
        .getByRole('navigation')
        .getByRole('link', { name: 'NFTs' })
        .click();

    await expect(page.getByRole('main').getByRole('heading')).toHaveText(
        /NFTs/
    );
});

test('Apps tab', async ({ page, extensionUrl }) => {
    await createWallet(page, extensionUrl);
    await page
        .getByRole('navigation')
        .getByRole('link', { name: 'Apps' })
        .click();

    await expect(page.getByRole('main')).toHaveText(
        /Builders in sui ecosystem/i
    );
});

test('Activity tab', async ({ page, extensionUrl }) => {
    await createWallet(page, extensionUrl);
    await page
        .getByRole('navigation')
        .getByRole('link', { name: 'Activity' })
        .click();

    await expect(page.getByRole('main').getByRole('heading')).toHaveText(
        /Your Activity/
    );
});
