// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import StepOne from './steps/StepOne';
import StepTwo from './steps/StepTwo';
import CardLayout from '_app/shared/card-layout';
import { useAppDispatch } from '_hooks';
import { createVault, logout } from '_redux/slices/account';
import { MAIN_UI_URL } from '_shared/utils';
import { entropyToSerialized, mnemonicToEntropy } from '_shared/utils/bip39';

const initialValues = {
    mnemonic: '',
    password: '',
    confirmPassword: '',
};

const allSteps = [StepOne, StepTwo];

export type ImportValuesType = typeof initialValues;
export type ImportPageProps = {
    mode?: 'import' | 'forgot';
};
const ImportPage = ({ mode = 'import' }: ImportPageProps) => {
    const [data, setData] = useState<ImportValuesType>(initialValues);
    const [step, setStep] = useState(0);
    const dispatch = useAppDispatch();
    const navigate = useNavigate();
    const onHandleSubmit = useCallback(
        async ({ mnemonic, password }: ImportValuesType) => {
            try {
                if (mode === 'forgot') {
                    // clear everything in storage
                    await dispatch(logout());
                }
                await dispatch(
                    createVault({
                        importedEntropy: entropyToSerialized(
                            mnemonicToEntropy(mnemonic)
                        ),
                        password,
                    })
                ).unwrap();
                if (mode === 'import') {
                    navigate('../backup-imported');
                } else {
                    // refresh the page to re-initialize the store
                    window.location.href = MAIN_UI_URL;
                }
            } catch (e) {
                // Do nothing
            }
        },
        [dispatch, navigate, mode]
    );
    const totalSteps = allSteps.length;
    const StepForm = step < totalSteps ? allSteps[step] : null;
    return (
        <CardLayout
            headerCaption={mode === 'import' ? 'Wallet Setup' : undefined}
            title={
                mode === 'import'
                    ? 'Import an Existing Wallet'
                    : 'Reset Password for This Wallet'
            }
            mode={mode === 'import' ? 'box' : 'plain'}
        >
            {StepForm ? (
                <div className="mt-7.5 flex flex-col flex-nowrap items-stretch flex-1 flex-grow w-full">
                    <StepForm
                        next={async (data, stepIncrement) => {
                            const nextStep = step + stepIncrement;
                            if (nextStep >= totalSteps) {
                                await onHandleSubmit(data);
                            }
                            setData(data);
                            if (nextStep < 0) {
                                return;
                            }
                            setStep(nextStep);
                        }}
                        data={data}
                        mode={mode}
                    />
                </div>
            ) : null}
        </CardLayout>
    );
};

export default ImportPage;
