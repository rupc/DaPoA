// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { type Validator } from '@mysten/sui.js';
import { useMemo } from 'react';

import { DelegationAmount } from './DelegationAmount';
import { calculateAPY } from './calculateAPY';

import { Card } from '~/ui/Card';
import { Heading } from '~/ui/Heading';
import { Stats } from '~/ui/Stats';

type StatsCardProps = {
    validatorData: Validator;
    epoch: number | string;
    epochRewards: string;
};

export function ValidatorStats({
    validatorData,
    epoch,
    epochRewards,
}: StatsCardProps) {
    // TODO: add missing fields
    // const numberOfDelegators = 0;
    //  const networkStakingParticipation = 0;
    //  const votedLastRound =  0;
    //  const tallyingScore =  0;
    //  const lastNarwhalRound = 0;

    const apy = useMemo(
        () => calculateAPY(validatorData, +epoch),
        [validatorData, epoch]
    );
    const totalStake = +validatorData.staking_pool.sui_balance;
    const commission = +validatorData.commission_rate / 100;
    const rewardsPoolBalance = +validatorData.staking_pool.rewards_pool;

    return (
        <div className="flex flex-col items-stretch gap-5 md:flex-row">
            <div className="flex-grow">
                <Card spacing="lg">
                    <div className="flex basis-full flex-col gap-8 md:basis-1/3">
                        <Heading
                            as="div"
                            variant="heading4/semibold"
                            color="steel-darker"
                        >
                            SUI Staked on Validator
                        </Heading>
                        <div className="flex flex-col gap-8 lg:flex-row">
                            <Stats
                                label="Staking APY"
                                tooltip="This is the Annualized Percentage Yield of the a specific validator’s past operations. Note there is no guarantee this APY will be true in the future."
                                unavailable={apy <= 0}
                            >
                                {apy}%
                            </Stats>
                            <Stats
                                label="Total SUI Staked"
                                tooltip="The total SUI staked on the network by validators and delegators to validate the network and earn rewards."
                                unavailable={totalStake <= 0}
                            >
                                <DelegationAmount amount={totalStake} isStats />
                            </Stats>
                        </div>
                        <div className="flex flex-col gap-8 lg:flex-row">
                            <Stats
                                label="Commission"
                                tooltip="Coming soon"
                                unavailable={commission <= 0}
                            >
                                <Heading
                                    as="h3"
                                    variant="heading2/semibold"
                                    color="steel-darker"
                                >
                                    {commission}%
                                </Heading>
                            </Stats>
                            <Stats
                                label="Delegators"
                                tooltip="The number of active delegators"
                                unavailable
                            />
                        </div>
                    </div>
                </Card>
            </div>

            <div className="flex-grow">
                <Card spacing="lg">
                    <div className="flex basis-full flex-col items-stretch gap-8 md:basis-80">
                        <Heading
                            as="div"
                            variant="heading4/semibold"
                            color="steel-darker"
                        >
                            Validator Staking Rewards
                        </Heading>
                        <div className="flex flex-col gap-8">
                            <Stats
                                label="Last Epoch SUI Rewards"
                                tooltip="The stake rewards collected during the last epoch."
                                unavailable={+epochRewards <= 0}
                            >
                                <DelegationAmount
                                    amount={epochRewards}
                                    isStats
                                />
                            </Stats>

                            <Stats
                                label="Reward Pool"
                                tooltip="Amount currently in this validator’s reward pool"
                                unavailable={+rewardsPoolBalance <= 0}
                            >
                                <DelegationAmount
                                    amount={rewardsPoolBalance}
                                    isStats
                                />
                            </Stats>
                        </div>
                    </div>
                </Card>
            </div>

            <div className="flex-grow">
                <Card spacing="lg">
                    <div className="flex max-w-full flex-col gap-8">
                        <Heading
                            as="div"
                            variant="heading4/semibold"
                            color="steel-darker"
                        >
                            Network Participation
                        </Heading>
                        <div className="flex flex-col gap-8">
                            <div className="flex flex-col gap-8 lg:flex-row">
                                <Stats
                                    label="Checkpoint Participation"
                                    tooltip="The percentage of checkpoints certified thus far by this validator."
                                    unavailable
                                />

                                <Stats
                                    label="Voted Last Round"
                                    tooltip="Did this validator vote in the latest round."
                                    unavailable
                                />
                            </div>
                            <div className="flex flex-col gap-8 lg:flex-row">
                                <Stats
                                    label="Tallying Score"
                                    tooltip="A score generated by validators to evaluate each other’s performance throughout Sui’s regular operations."
                                    unavailable
                                />
                                <Stats
                                    label="Last Narwhal Round"
                                    tooltip="Latest Narwhal round for this epoch."
                                    unavailable
                                />
                            </div>
                        </div>
                    </div>
                </Card>
            </div>
        </div>
    );
}
