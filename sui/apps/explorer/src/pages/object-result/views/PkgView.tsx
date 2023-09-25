// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
import { ErrorBoundary } from '../../../components/error-boundary/ErrorBoundary';
import PkgModulesWrapper from '../../../components/module/PkgModulesWrapper';
import TxForID from '../../../components/transaction-card/TxForID';
import { getOwnerStr } from '../../../utils/objectUtils';
import { trimStdLibPrefix } from '../../../utils/stringUtils';
import { type DataType } from '../ObjectResultType';

import styles from './ObjectView.module.css';

import { Heading } from '~/ui/Heading';
import { AddressLink, ObjectLink } from '~/ui/InternalLink';
import { Tab, TabGroup, TabList, TabPanel, TabPanels } from '~/ui/Tabs';

function PkgView({ data }: { data: DataType }) {
    const viewedData = {
        ...data,
        objType: trimStdLibPrefix(data.objType),
        tx_digest: data.data.tx_digest,
        owner: getOwnerStr(data.owner),
    };

    const checkIsPropertyType = (value: any) =>
        ['number', 'string'].includes(typeof value);

    const properties = Object.entries(viewedData.data?.contents)
        .filter(([key, _]) => key !== 'name')
        .filter(([_, value]) => checkIsPropertyType(value));

    return (
        <div>
            <div>
                <TabGroup size="lg">
                    <TabList>
                        <Tab>Details</Tab>
                    </TabList>
                    <TabPanels>
                        <TabPanel>
                            <table
                                className={styles.description}
                                id="descriptionResults"
                            >
                                <tbody>
                                    <tr>
                                        <td>Object ID</td>
                                        <td
                                            id="objectID"
                                            className={styles.objectid}
                                        >
                                            <ObjectLink
                                                objectId={viewedData.id}
                                                noTruncate
                                            />
                                        </td>
                                    </tr>

                                    <tr>
                                        <td>Version</td>
                                        <td>{viewedData.version}</td>
                                    </tr>

                                    {viewedData?.publisherAddress && (
                                        <tr>
                                            <td>Publisher</td>
                                            <td id="lasttxID">
                                                <AddressLink
                                                    address={
                                                        viewedData.publisherAddress
                                                    }
                                                    noTruncate
                                                />
                                            </td>
                                        </tr>
                                    )}
                                </tbody>
                            </table>
                        </TabPanel>
                    </TabPanels>
                </TabGroup>

                <div className="mb-3">
                    <Heading as="h2" variant="heading4/semibold">
                        Modules
                    </Heading>
                </div>
                <ErrorBoundary>
                    <PkgModulesWrapper id={data.id} modules={properties} />
                </ErrorBoundary>
                <div className={styles.txsection}>
                    <h2 className={styles.header}>Transactions</h2>
                    <ErrorBoundary>
                        <TxForID id={viewedData.id} category="object" />
                    </ErrorBoundary>
                </div>
            </div>
        </div>
    );
}

export default PkgView;
