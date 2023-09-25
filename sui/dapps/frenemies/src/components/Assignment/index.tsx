// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useScorecard } from "../../network/queries/scorecard";
import { useValidators } from "../../network/queries/sui-system";
import { Goal } from "../../network/types";
import { formatBalance } from "../../utils/format";
import { Card } from "../Card";
import { Stat } from "../Stat";

const DEC = 9;
const HAPPY_CAPY = "/capy_thumbs_up.svg";
const SAD_CAPY = "/capy_cry.svg";

const GOAL_TO_COPY = {
  [Goal.Friend]: "1-13",
  [Goal.Neutral]: "14-25",
  [Goal.Enemy]: "26-41",
};

function getIsInRank(goal: Goal, index: number) {
  const rank = index + 1;
  switch (goal) {
    case Goal.Friend:
      return 13 >= rank;
    case Goal.Neutral:
      return 25 >= rank && rank >= 14;
    case Goal.Enemy:
      return rank >= 26;
  }
}

export function Assignment() {
  const { data: validators } = useValidators();
  const { data: scorecard } = useScorecard();

  const sortedValidators = validators
    ? [...validators].sort((a, b) =>
        Number(
          BigInt(b.next_epoch_stake) +
            BigInt(b.next_epoch_delegation) -
            (BigInt(a.next_epoch_stake) + BigInt(a.next_epoch_delegation))
        )
      )
    : null;

  const assignment = scorecard?.data.assignment;

  if (!assignment) return null;

  const assignedValidatorIndex = sortedValidators?.findIndex((validator) => {
    return validator.sui_address.replace("0x", "") === assignment.validator;
  });

  const assignedValidator =
    typeof assignedValidatorIndex === "number"
      ? sortedValidators?.[assignedValidatorIndex]
      : null;

  if (!assignedValidator) return null;

  const name = assignedValidator.name;
  const selfStake = BigInt(assignedValidator.next_epoch_stake);
  const delegatedStake = BigInt(assignedValidator.next_epoch_delegation);
  const totalStake = selfStake + delegatedStake;

  const isInRank = getIsInRank(assignment.goal, assignedValidatorIndex!);

  return (
    <Card spacing="xl">
      <div className="flex items-center gap-12">
        <img src={isInRank ? HAPPY_CAPY : SAD_CAPY} alt="Capy" />

        <div>
          <h2 className="text-steel-dark font-semibold text-heading2">
            {name} on Staking Leaderboard
          </h2>
          <div className="mt-5 flex flex-col md:flex-row gap-4 md:gap-20">
            <div className="space-y-4">
              <Stat label="Rank">
                {typeof assignedValidatorIndex === "number"
                  ? assignedValidatorIndex + 1
                  : "--"}
                <span className="text-steel-dark font-extralight">
                  /{sortedValidators?.length}
                </span>
              </Stat>
              <Stat label="SUI Staked">
                <div className="text-steel-dark font-semibold text-xl">
                  {formatBalance(totalStake, DEC)}
                </div>
              </Stat>
            </div>
            <div className="flex-1">
              <Stat label="Your Objective">
                {GOAL_TO_COPY[assignment.goal]}{" "}
                <span className="text-steel-dark font-extralight">
                  {name} Rank
                </span>
              </Stat>

              {/* TODO: Validate copy states: */}
              <div className="mt-1 max-w-xs text-steel-dark text-p1">
                Move your Validator to the assigned rank by allocating SUI Stake
                to them.
              </div>
            </div>
          </div>
        </div>
      </div>
    </Card>
  );
}
