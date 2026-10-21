const { expect } = require('chai');
const { ethers } = require('hardhat');
const { deployExecutionManager } = require('./helpers/execution-v1');

// An independent policy oracle invalidates descendants explicitly. It does not
// copy the contract's epoch/generation lookup algorithm or inspect its storage.
describe('VaultPermissionManager adversarial authorization sequences', function () {
  const NONE = 0;
  const READ = 1;
  const WRITE = 2;
  const ADMIN = 3;
  const NAMES = ['default', 'Default'];
  const TOKENS = [1, 2];

  function random(seed) {
    let state = seed >>> 0;
    return (bound) => {
      state ^= state << 13;
      state ^= state >>> 17;
      state ^= state << 5;
      return (state >>> 0) % bound;
    };
  }

  for (const nonceMode of [false, true]) {
    it(`matches a separate authority model across mixed operations (${nonceMode ? 'nonce' : 'observed'} profile)`, async function () {
      this.timeout(120000);
      const actors = (await ethers.getSigners()).slice(0, 7);
      const deploy = async (name, ...args) => {
        const contract = await (await ethers.getContractFactory(name)).deploy(...args);
        return contract.deployed();
      };
      const collection = await deploy(
        nonceMode ? 'MockNonceTrackedCollection' : 'MockBAP578ForVPM',
      );
      const logic = await deploy('VPMRawReturnLogic');
      for (const token of TOKENS) await collection.mint(token, actors[0].address, logic.address);
      const source = await deploy('LegacyBAP578StateResolver', collection.address);
      const resolver = nonceMode
        ? await deploy('NonceTrackedStateResolver', source.address)
        : source;
      const manager = await deployExecutionManager(resolver);

      const state = new Map(
        TOKENS.map((token) => [
          token,
          {
            owner: 0,
            nonce: nonceMode ? 1 : 0,
            observedOwner: undefined,
            observedNonce: undefined,
            epoch: 0,
            scopes: new Map(),
          },
        ]),
      );
      let expectedCalls = 0;
      let serial = 0;

      function changed(token) {
        return (
          token.observedOwner !== undefined &&
          (token.owner !== token.observedOwner ||
            (nonceMode && token.nonce !== token.observedNonce))
        );
      }

      function invalidateAll(token) {
        for (const records of token.scopes.values()) {
          for (const record of records.values()) record.stale = true;
        }
      }

      function observe(token) {
        if (changed(token)) {
          token.epoch++;
          invalidateAll(token);
        }
        token.observedOwner = token.owner;
        token.observedNonce = token.nonce;
      }

      function authority(token, scope, actor, time) {
        const records = token.scopes.get(scope);
        if (!records) return NONE;
        if (actor === token.owner) return ADMIN;
        if (changed(token)) return NONE;
        const record = records.get(actor);
        const live = (entry) =>
          entry && !entry.stale && entry.live && (entry.expiry === 0 || time <= entry.expiry);
        if (!live(record)) return NONE;
        if (record.issuer !== undefined) {
          const parent = records.get(record.issuer);
          if (!live(parent) || parent.role !== ADMIN) return NONE;
        }
        return record.role;
      }

      function invalidateChildren(records, actor) {
        for (const entry of records.values()) {
          if (entry.issuer === actor) entry.live = false;
        }
      }

      async function assertAuthority(label) {
        const time = (await ethers.provider.getBlock('latest')).timestamp;
        const checks = [];
        for (const tokenId of TOKENS) {
          const token = state.get(tokenId);
          checks.push(
            (async () => {
              expect(
                await manager.permissionEpoch(tokenId),
                `${label}: committed epoch ${tokenId}`,
              ).to.equal(token.epoch);
            })(),
          );
          for (const scope of NAMES) {
            for (let actor = 0; actor < actors.length; actor++) {
              const expected = authority(token, scope, actor, time);
              for (const tier of [READ, WRITE, ADMIN]) {
                checks.push(
                  (async () => {
                    const result = await manager.checkPermission(
                      tokenId,
                      scope,
                      actors[actor].address,
                      tier,
                    );
                    expect(
                      result[0],
                      `${label}: token ${tokenId}, ${scope}, actor ${actor}, tier ${tier}`,
                    ).to.equal(expected >= tier);
                  })(),
                );
              }
            }
          }
        }
        await Promise.all(checks);
        expect(await logic.callCount(), `${label}: unauthorized logic side effect`).to.equal(
          expectedCalls,
        );
      }

      async function step(operation) {
        const {
          kind,
          tokenId = 1,
          scope = NAMES[0],
          actor = 0,
          target = 5,
          role = WRITE,
        } = operation;
        const token = state.get(tokenId);
        const records = token.scopes.get(scope);
        const current = (await ethers.provider.getBlock('latest')).timestamp;
        const time = current + (operation.advance || 1);
        const expiry = operation.duration === undefined ? 0 : time + operation.duration;
        const label = `${++serial}: ${JSON.stringify(operation)}`;
        await ethers.provider.send('evm_setNextBlockTimestamp', [time]);
        let expected = true;
        let send;
        let commit = () => {};
        const signer = manager.connect(actors[actor]);
        const options = { gasLimit: 8000000 };

        if (kind === 'create') {
          expected = actor === token.owner && !records;
          send = () => signer.createVault(tokenId, scope, '', options);
          commit = () => {
            observe(token);
            token.scopes.set(scope, new Map());
          };
        } else if (kind === 'grant') {
          const owner = actor === token.owner;
          const parent = records && records.get(actor);
          const previous = records && records.get(target);
          expected =
            Boolean(records) &&
            actor !== target &&
            target !== token.owner &&
            role !== NONE &&
            (expiry === 0 || expiry > time) &&
            (owner ||
              (authority(token, scope, actor, time) === ADMIN &&
                role !== ADMIN &&
                (!previous || previous.stale || previous.issuer === actor) &&
                (parent.expiry === 0 || (expiry !== 0 && expiry <= parent.expiry))));
          send = () =>
            signer.grantPermission(
              tokenId,
              scope,
              actors[target].address,
              role,
              expiry,
              '',
              options,
            );
          commit = () => {
            observe(token);
            invalidateChildren(records, target);
            records.set(target, {
              role,
              expiry,
              issuer: owner ? undefined : actor,
              live: true,
              stale: false,
            });
          };
        } else if (kind === 'revoke') {
          const previous = records && records.get(target);
          expected =
            Boolean(previous) &&
            (actor === token.owner ||
              (authority(token, scope, actor, time) === ADMIN &&
                (actor === target || (!previous.stale && previous.issuer === actor))));
          send = () => signer.revokePermission(tokenId, scope, actors[target].address, options);
          commit = () => {
            observe(token);
            invalidateChildren(records, target);
            records.delete(target);
          };
        } else if (kind === 'reset') {
          expected = actor === token.owner;
          send = () => signer.resetPermissions(tokenId, options);
          commit = () => {
            observe(token);
            token.epoch++;
            invalidateAll(token);
          };
        } else if (kind === 'sync') {
          send = () => signer.syncAgentState(tokenId, options);
          commit = () => observe(token);
        } else if (kind === 'forward') {
          expected = authority(token, scope, actor, time) >= WRITE;
          send = () =>
            signer.forwardHandleAction(tokenId, scope, 'security-sequence', '0xabcd', options);
          commit = () => {
            observe(token);
            expectedCalls++;
          };
        } else if (kind === 'transfer') {
          send = () => collection.transfer(tokenId, actors[target].address, options);
          commit = () => {
            token.owner = target;
            if (nonceMode) token.nonce++;
          };
        } else if (kind === 'time') {
          await ethers.provider.send('evm_mine');
          await assertAuthority(label);
          return;
        } else {
          throw new Error(`Unknown operation ${kind}`);
        }

        let succeeded = false;
        try {
          await (await send()).wait();
          succeeded = true;
        } catch (error) {
          // An EVM revert is an expected possible outcome. Local setup, RPC,
          // decoding, and other non-revert failures must still fail the test.
          if (
            !['CALL_EXCEPTION', 'UNPREDICTABLE_GAS_LIMIT'].includes(error.code) &&
            !/revert|VM Exception/.test(error.message)
          )
            throw error;
        }
        expect(succeeded, label).to.equal(expected);
        if (succeeded) commit();
        await assertAuthority(label);
      }

      for (const tokenId of TOKENS) {
        for (const scope of NAMES) {
          await step({ kind: 'create', tokenId, scope });
          await step({ kind: 'grant', tokenId, scope, target: 2, role: ADMIN });
          await step({ kind: 'grant', tokenId, scope, target: 3, role: ADMIN });
          await step({ kind: 'grant', tokenId, scope, target: 1, role: READ });
          await step({ kind: 'grant', tokenId, scope, actor: 2, target: 4, role: READ });
          await step({ kind: 'grant', tokenId, scope, actor: 2, target: 5, role: WRITE });
        }
      }

      const adversarial = [
        { kind: 'grant', actor: 2, target: 3, role: WRITE },
        { kind: 'grant', actor: 2, target: 1, role: WRITE },
        { kind: 'grant', actor: 3, target: 5, role: WRITE },
        { kind: 'grant', target: 2, role: ADMIN, duration: 40 },
        { kind: 'forward', actor: 5 },
        { kind: 'grant', actor: 2, target: 5, role: WRITE, duration: 10 },
        { kind: 'grant', actor: 2, target: 4, role: WRITE },
        { kind: 'grant', actor: 2, target: 2, role: READ },
        { kind: 'grant', actor: 2, target: 6, role: ADMIN },
        { kind: 'grant', target: 2, role: WRITE },
        { kind: 'grant', target: 2, role: ADMIN },
        { kind: 'forward', actor: 5 },
        { kind: 'grant', actor: 2, target: 5, role: WRITE },
        { kind: 'revoke', actor: 2, target: 2 },
        { kind: 'grant', target: 2, role: ADMIN },
        { kind: 'forward', actor: 5 },
        { kind: 'grant', actor: 2, target: 5, role: WRITE },
        { kind: 'transfer', target: 1 },
        { kind: 'forward', actor: 5 },
        { kind: 'transfer', target: 0 },
        { kind: 'forward', actor: 5 },
        { kind: 'sync', actor: 6 },
        { kind: 'reset' },
        { kind: 'grant', actor: 3, target: 6, role: WRITE },
        { kind: 'forward', actor: 5, tokenId: 2 },
        { kind: 'forward', actor: 5, scope: NAMES[1] },
      ];
      for (const operation of adversarial) await step(operation);

      const next = random(nonceMode ? 0x94ac27 : 0x812f03);
      const kinds = [
        'grant',
        'grant',
        'grant',
        'revoke',
        'revoke',
        'transfer',
        'sync',
        'reset',
        'forward',
        'time',
      ];
      for (let i = 0; i < 72; i++) {
        const operation = {
          kind: kinds[next(kinds.length)],
          tokenId: TOKENS[next(TOKENS.length)],
          scope: NAMES[next(NAMES.length)],
          actor: next(actors.length),
          target: next(actors.length),
          role: 1 + next(3),
        };
        if (operation.kind === 'grant' && next(2)) operation.duration = 5 + next(50);
        if (operation.kind === 'time') operation.advance = 20 + next(40);
        await step(operation);
      }
    });
  }
});
