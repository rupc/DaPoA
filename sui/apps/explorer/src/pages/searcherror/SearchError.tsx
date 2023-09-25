// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useParams } from 'react-router-dom';

import { Banner } from '~/ui/Banner';

const addressErrEnd =
    'must be a hex string encoding 20 bytes, with or without the "0x" prefix.';

function SearchError() {
    const { category } = useParams();

    let msg = 'unknown';
    switch (category) {
        case 'transactions':
            // TODO - generate expected length errors from source of truth in Rust
            msg = 'transaction id must be a base64 string encoding 32 bytes';
            break;
        case 'objects':
            msg = `object id ${addressErrEnd}`;
            break;
        case 'addresses':
            msg = `address ${addressErrEnd}`;
            break;
        case 'all':
            msg =
                'Search terms currently supported are transaction IDs (32 byte base58/base64), object IDs (20 byte hex), and addresses (20 byte hex)';
            break;
        case 'missing':
            msg = 'Data on the following query could not be found';
    }

    return (
        <Banner variant="error" spacing="lg" fullWidth>
            {msg}
        </Banner>
    );
}

export default SearchError;
