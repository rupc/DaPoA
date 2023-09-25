// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import {
    getExecutionStatusType,
    getObjectExistsResponse,
    getObjectId,
    getTimestampFromTransactionResponse,
    getTotalGasUsed,
    getTransactionDigest,
    getObjectVersion,
    SUI_SYSTEM_STATE_OBJECT_ID,
} from '@mysten/sui.js';
import {
    createAsyncThunk,
    createEntityAdapter,
    createSlice,
} from '@reduxjs/toolkit';

import { activeAccountSelector } from '../account';
import { ExampleNFT } from './NFT';

import type { SuiObject, SuiAddress, ObjectId } from '@mysten/sui.js';
import type { RootState } from '_redux/RootReducer';
import type { AppThunkConfig } from '_store/thunk-extras';

const objectsAdapter = createEntityAdapter<SuiObject>({
    selectId: ({ reference }) => reference.objectId,
    sortComparer: (a, b) =>
        a.reference.objectId.localeCompare(b.reference.objectId),
});

export const fetchAllOwnedAndRequiredObjects = createAsyncThunk<
    SuiObject[],
    void,
    AppThunkConfig
>('sui-objects/fetch-all', async (_, { getState, extra: { api } }) => {
    const state = getState();
    const {
        account: { address },
    } = state;
    const allSuiObjects: SuiObject[] = [];
    if (address) {
        const allObjectRefs =
            await api.instance.fullNode.getObjectsOwnedByAddress(`${address}`);
        const objectIDs = allObjectRefs
            .filter((anObj) => {
                const fetchedVersion = getObjectVersion(anObj);
                const storedObj = suiObjectsAdapterSelectors.selectById(
                    state,
                    getObjectId(anObj)
                );
                const storedVersion = storedObj
                    ? getObjectVersion(storedObj.reference)
                    : null;
                const objOutdated = fetchedVersion !== storedVersion;
                if (!objOutdated && storedObj) {
                    allSuiObjects.push(storedObj);
                }
                return objOutdated;
            })
            .map((anObj) => anObj.objectId);
        objectIDs.push(SUI_SYSTEM_STATE_OBJECT_ID);
        const allObjRes = await api.instance.fullNode.getObjectBatch(objectIDs);
        for (const objRes of allObjRes) {
            const suiObj = getObjectExistsResponse(objRes);
            if (suiObj) {
                allSuiObjects.push(suiObj);
            }
        }
    }
    return allSuiObjects;
});

export const batchFetchObject = createAsyncThunk<
    SuiObject[],
    ObjectId[],
    AppThunkConfig
>('sui-objects/batch', async (objectIDs, { extra: { api } }) => {
    const allSuiObjects: SuiObject[] = [];
    const allObjRes = await api.instance.fullNode.getObjectBatch(objectIDs);
    for (const objRes of allObjRes) {
        const suiObj = getObjectExistsResponse(objRes);
        if (suiObj) {
            allSuiObjects.push(suiObj);
        }
    }
    return allSuiObjects;
});

export const mintDemoNFT = createAsyncThunk<void, void, AppThunkConfig>(
    'mintDemoNFT',
    async (_, { extra: { api, background }, dispatch, getState }) => {
        const activeAddress = activeAccountSelector(getState());
        if (!activeAddress) {
            throw new Error('Error, active address is not defined');
        }
        const signer = api.getSignerInstance(activeAddress, background);
        await ExampleNFT.mintExampleNFT(signer);
        await dispatch(fetchAllOwnedAndRequiredObjects());
    }
);

type NFTTxResponse = {
    timestamp_ms?: number;
    status?: string;
    gasFee?: number;
    txId?: string;
};

export const transferNFT = createAsyncThunk<
    NFTTxResponse,
    { objectId: ObjectId; recipient: SuiAddress; gasBudget: number },
    AppThunkConfig
>(
    'transferNFT',
    async (data, { extra: { api, background }, dispatch, getState }) => {
        const activeAddress = activeAccountSelector(getState());
        if (!activeAddress) {
            throw new Error('Error, active address is not defined');
        }
        const signer = api.getSignerInstance(activeAddress, background);
        const txn = await signer.transferObject(data);
        await dispatch(fetchAllOwnedAndRequiredObjects());
        const txnResp = {
            timestamp_ms: getTimestampFromTransactionResponse(txn),
            status: getExecutionStatusType(txn),
            gasFee: txn ? getTotalGasUsed(txn) : 0,
            txId: getTransactionDigest(txn),
        };
        return txnResp as NFTTxResponse;
    }
);
interface SuiObjectsManualState {
    loading: boolean;
    error: false | { code?: string; message?: string; name?: string };
    lastSync: number | null;
}
const initialState = objectsAdapter.getInitialState<SuiObjectsManualState>({
    loading: true,
    error: false,
    lastSync: null,
});

const slice = createSlice({
    name: 'sui-objects',
    initialState: initialState,
    reducers: {
        clearSuiObjects: (state) => {
            state.error = false;
            state.lastSync = null;
            objectsAdapter.removeAll(state);
        },
    },
    extraReducers: (builder) => {
        builder
            .addCase(
                fetchAllOwnedAndRequiredObjects.fulfilled,
                (state, action) => {
                    objectsAdapter.setAll(state, action.payload);
                    state.loading = false;
                    state.error = false;
                    state.lastSync = Date.now();
                }
            )
            .addCase(
                fetchAllOwnedAndRequiredObjects.pending,
                (state, action) => {
                    state.loading = true;
                }
            )
            .addCase(
                fetchAllOwnedAndRequiredObjects.rejected,
                (state, { error: { code, name, message } }) => {
                    state.loading = false;
                    state.error = { code, message, name };
                }
            );
    },
});

export default slice.reducer;

export const { clearSuiObjects } = slice.actions;

export const suiObjectsAdapterSelectors = objectsAdapter.getSelectors(
    (state: RootState) => state.suiObjects
);

export const suiSystemObjectSelector = (state: RootState) =>
    suiObjectsAdapterSelectors.selectById(state, SUI_SYSTEM_STATE_OBJECT_ID);
