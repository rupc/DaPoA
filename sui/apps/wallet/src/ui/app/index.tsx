// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useEffect } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';

import { AppType } from './redux/slices/app/AppType';
import { Staking } from './staking/home';
import ForgotPasswordPage from '_app/wallet/forgot-password-page';
import LockedPage from '_app/wallet/locked-page';
import { useAppDispatch, useAppSelector } from '_hooks';
import { DappTxApprovalPage } from '_pages/dapp-tx-approval';
import HomePage, {
    NftsPage,
    TokensPage,
    TransactionsPage,
    TransferCoinPage,
    NFTDetailsPage,
    ReceiptPage,
    CoinsSelectorPage,
    AppsPage,
    NftTransferPage,
} from '_pages/home';
import InitializePage from '_pages/initialize';
import BackupPage from '_pages/initialize/backup';
import CreatePage from '_pages/initialize/create';
import ImportPage from '_pages/initialize/import';
import SelectPage from '_pages/initialize/select';
import SiteConnectPage from '_pages/site-connect';
import WelcomePage from '_pages/welcome';
import { setNavVisibility } from '_redux/slices/app';

const HIDDEN_MENU_PATHS = [
    '/nft-details',
    '/nft-transfer',
    '/receipt',
    '/send',
    '/send/select',
    '/apps/disconnectapp',
];

const App = () => {
    const dispatch = useAppDispatch();
    const isPopup = useAppSelector(
        (state) => state.app.appType === AppType.popup
    );
    useEffect(() => {
        document.body.classList[isPopup ? 'add' : 'remove']('is-popup');
        document.body.classList.remove('app-initializing');
    }, [isPopup]);
    const location = useLocation();
    useEffect(() => {
        const menuVisible = !HIDDEN_MENU_PATHS.some((aPath) =>
            location.pathname.startsWith(aPath)
        );
        dispatch(setNavVisibility(menuVisible));
    }, [location, dispatch]);

    return (
        <Routes>
            <Route path="/*" element={<HomePage />}>
                <Route path="tokens/*" element={<TokensPage />} />
                <Route path="nfts" element={<NftsPage />} />
                <Route path="apps/*" element={<AppsPage />} />
                <Route path="nft-details" element={<NFTDetailsPage />} />
                <Route
                    path="nft-transfer/:nftId"
                    element={<NftTransferPage />}
                />
                <Route path="transactions" element={<TransactionsPage />} />
                <Route path="send" element={<TransferCoinPage />} />
                <Route path="send/select" element={<CoinsSelectorPage />} />
                <Route path="stake/*" element={<Staking />} />
                <Route path="receipt" element={<ReceiptPage />} />
                <Route
                    path="*"
                    element={<Navigate to="/tokens" replace={true} />}
                />
            </Route>

            <Route
                path="/dapp/*"
                element={
                    <HomePage disableNavigation limitToPopUpSize={false} />
                }
            >
                <Route
                    path="connect/:requestID"
                    element={<SiteConnectPage />}
                />
                <Route
                    path="tx-approval/:txID"
                    element={<DappTxApprovalPage />}
                />
            </Route>

            <Route path="welcome" element={<WelcomePage />} />
            <Route path="/initialize" element={<InitializePage />}>
                <Route path="select" element={<SelectPage />} />
                <Route path="create" element={<CreatePage />} />
                <Route path="import" element={<ImportPage />} />
                <Route path="backup" element={<BackupPage />} />
                <Route
                    path="backup-imported"
                    element={<BackupPage mode="imported" />}
                />
            </Route>
            <Route path="locked" element={<LockedPage />} />
            <Route path="forgot-password" element={<ForgotPasswordPage />} />
        </Routes>
    );
};

export default App;
