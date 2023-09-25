// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import ESLintPlugin from 'eslint-webpack-plugin';
import StyleLintPlugin from 'stylelint-webpack-plugin';
import { merge } from 'webpack-merge';

import configCommon from './webpack.config.common';

import type { Configuration } from 'webpack';

const configDev: Configuration = {
    mode: 'development',
    devtool: 'cheap-source-map',
    plugins: [
        new ESLintPlugin({ extensions: ['ts', 'tsx', 'js', 'jsx'] }),
        new StyleLintPlugin(),
    ],
    watchOptions: {
        aggregateTimeout: 600,
    },
    stats: {
        loggingDebug: ['sass-loader'],
    },
};

async function getConfig() {
    return merge(await configCommon(), configDev);
}

export default getConfig;
