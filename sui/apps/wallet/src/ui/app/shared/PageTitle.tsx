// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { ArrowLeft16 } from '@mysten/icons';
import { useNavigate } from 'react-router-dom';

import { Button } from './ButtonUI';
import { Heading } from './heading';

export type PageTitleProps = {
    title?: string;
    back?: boolean | string | (() => void);
};

function PageTitle({ title = '', back }: PageTitleProps) {
    const navigate = useNavigate();
    const backOnClick =
        back && typeof back !== 'string'
            ? () => {
                  if (typeof back === 'function') {
                      back();
                      return;
                  }
                  navigate(-1);
              }
            : undefined;
    return (
        <div className="flex items-center relative gap-5">
            {back ? (
                <div className="flex">
                    <Button
                        to={typeof back === 'string' ? back : undefined}
                        onClick={backOnClick}
                        size="tiny"
                        before={
                            <ArrowLeft16 className="text-base leading-none" />
                        }
                        variant="plain"
                    />
                </div>
            ) : null}
            <div className="flex items-center justify-center flex-1 overflow-hidden">
                <Heading as="h6" variant="heading6" color="gray-90" truncate>
                    {title}
                </Heading>
            </div>
            {back ? <div className="basis-8" /> : null}
        </div>
    );
}

export default PageTitle;
