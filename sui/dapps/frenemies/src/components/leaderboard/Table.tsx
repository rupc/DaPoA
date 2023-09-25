// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { ReactNode } from "react";
import { Leaderboard } from "../../network/types";

interface Props {
  data: Leaderboard;
}

const Cell = ({
  as: As = "td",
  children,
}: {
  as?: "th" | "td";
  children: ReactNode;
}) => (
  <As className="text-left text-base font-normal leading-tight py-3">
    {children}
  </As>
);

const ELLIPSIS = '\u{2026}';
function formatName(name: string) {
  if (name.length <= 4) {
    return name;
  }
  return `${name.slice(0, 4)}${ELLIPSIS}`
}

export function Table({ data }: Props) {
  return (
    <div className="overflow-y-scroll max-h-60">
      <table className="table-fixed w-full">
        <thead>
          <tr>
            <Cell as="th">Name</Cell>
            <Cell as="th">Score</Cell>
            <Cell as="th">Active Rounds</Cell>
          </tr>
        </thead>
        <tbody>
          {data.topScores.map((score) => (
            <tr key={score.name} className="border-t border-white/20">
              <Cell>{formatName(score.name)}</Cell>
              <Cell>{score.score}</Cell>
              <Cell>{score.participation}</Cell>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
