// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { ArrowUpRight12 } from '@mysten/icons';
import { toB64, type Validator } from '@mysten/sui.js';

import { StakeButton } from './StakeButton';

import { DescriptionList, DescriptionItem } from '~/ui/DescriptionList';
import { Heading } from '~/ui/Heading';
import { ImageIcon } from '~/ui/ImageIcon';
import { AddressLink } from '~/ui/InternalLink';
import { Text } from '~/ui/Text';

type ValidatorMetaProps = {
    validatorData: Validator;
};

export function ValidatorMeta({ validatorData }: ValidatorMetaProps) {
    const validatorPublicKey = toB64(
        new Uint8Array(validatorData.metadata.pubkey_bytes)
    );

    const validatorName = validatorData.metadata.name;
    const logo = validatorData.metadata.image_url;
    const description = validatorData.metadata.description;
    const projectUrl = validatorData.metadata.project_url;

    return (
        <>
            <div className="flex basis-full gap-5 border-r border-transparent border-r-gray-45 md:mr-7.5 md:basis-1/4">
                <ImageIcon
                    src={logo}
                    label={validatorName}
                    fallback={validatorName}
                    size="xl"
                />
                <div className="mt-1.5 flex flex-col">
                    <Heading as="h1" variant="heading2/bold" color="gray-90">
                        {validatorName}
                    </Heading>
                    {projectUrl && (
                        <a
                            href={projectUrl}
                            target="_blank"
                            rel="noreferrer noopener"
                            className="mt-2.5 inline-flex items-center gap-1.5 text-body font-medium text-sui-dark no-underline"
                        >
                            {projectUrl}
                            <ArrowUpRight12 className="text-steel" />
                        </a>
                    )}
                    <div className="mt-3.5">
                        <StakeButton />
                    </div>
                </div>
            </div>
            <div className="min-w-0 basis-full break-words md:basis-2/3">
                <DescriptionList>
                    <DescriptionItem title="Description">
                        <Text variant="p1/medium" color="gray-90">
                            {description || '--'}
                        </Text>
                    </DescriptionItem>
                    <DescriptionItem title="Location">
                        <Text variant="p1/medium" color="gray-90">
                            --
                        </Text>
                    </DescriptionItem>
                    <DescriptionItem title="Address">
                        <AddressLink
                            address={validatorData.metadata.sui_address}
                            noTruncate
                        />
                    </DescriptionItem>
                    <DescriptionItem title="Public Key">
                        <Text variant="p1/medium" color="gray-90">
                            {validatorPublicKey}
                        </Text>
                    </DescriptionItem>
                </DescriptionList>
            </div>
        </>
    );
}
