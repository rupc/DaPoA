// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeAll } from 'vitest';
import { LocalTxnDataSerializer, ObjectId, RawSigner } from '../../src';
import { publishPackage, setup, TestToolbox } from './utils/setup';

describe('Test Object Display Standard', () => {
  let toolbox: TestToolbox;
  let signer: RawSigner;
  let packageId: ObjectId;

  beforeAll(async () => {
    toolbox = await setup();
    signer = new RawSigner(
      toolbox.keypair,
      toolbox.provider,
      new LocalTxnDataSerializer(toolbox.provider),
    );
    const packagePath = __dirname + '/./data/display_test';
    packageId = await publishPackage(signer, true, packagePath);
  });

  it('Test getting Display Object', async () => {
    const boarId = (
      await toolbox.provider.getObjectsOwnedByAddress(
        toolbox.address(),
        `${packageId}::boars::Boar`,
      )
    )[0].objectId;
    const display = await toolbox.provider.call('sui_getDisplayDeprecated', [
      boarId,
    ]);
    expect(display).toEqual({
      age: '10',
      buyer: `0x${toolbox.address()}`,
      creator: 'Chris',
      description: `Unique Boar from the Boars collection with First Boar and ${boarId}`,
      img_url: 'https://get-a-boar.com/first.png',
      name: 'First Boar',
      price: '',
      project_url: 'https://get-a-boar.com/',
      full_url: 'https://get-a-boar.fullurl.com/',
      escape_syntax: '{name}',
    });
  });
});
