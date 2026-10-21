const { expect } = require('chai');
const { ethers, upgrades } = require('hardhat');
const {
  deployExecutionManager,
  deployLegacyManager,
  executeGovernance,
} = require('./helpers/execution-v1');

describe('VaultPermissionManager conformance', function () {
  const TOKEN = 1;
  const VAULT = 'default';
  const READ = 1;
  const WRITE = 2;
  const ADMIN = 3;
  let owner, operator, admin, peer, other, collection, logic, vpm;

  async function deploy(name, ...args) {
    const contract = await (await ethers.getContractFactory(name)).deploy(...args);
    await contract.deployed();
    return contract;
  }

  async function proxyFor(resolver) {
    return deployExecutionManager(resolver);
  }

  async function timestamp() {
    return (await ethers.provider.getBlock('latest')).timestamp;
  }

  async function moveTo(time) {
    await ethers.provider.send('evm_setNextBlockTimestamp', [time]);
    await ethers.provider.send('evm_mine');
  }

  async function grantAdmin(expiry = 0, recipient = admin) {
    await vpm.grantPermission(TOKEN, VAULT, recipient.address, ADMIN, expiry, 'administrator');
  }

  async function child(expiry = 0, recipient = operator) {
    await vpm
      .connect(admin)
      .grantPermission(TOKEN, VAULT, recipient.address, WRITE, expiry, 'child');
  }

  async function forwardAs(caller = operator, action = 'check', data = '0x') {
    return vpm.connect(caller).forwardHandleAction(TOKEN, VAULT, action, data);
  }

  async function expectContextCleared(manager = vpm) {
    const context = await manager.getForwardingContext();
    expect(context.tokenId).to.equal(0);
    expect(context.vaultIdHash).to.equal(ethers.constants.HashZero);
    expect(context.accessor).to.equal(ethers.constants.AddressZero);
    expect(context.logicAddress).to.equal(ethers.constants.AddressZero);
    expect(context.ownershipNonce).to.equal(0);
    expect(context.executionRevision).to.equal(0);
  }

  beforeEach(async function () {
    [owner, operator, admin, peer, other] = await ethers.getSigners();
    collection = await deploy('MockBAP578ForVPM');
    logic = await deploy('VPMRawReturnLogic');
    await collection.mint(TOKEN, owner.address, logic.address);
    vpm = await deployLegacyManager(collection);
    await vpm.createVault(TOKEN, VAULT, 'conformance');
  });

  describe('owner authority and bounded delegation', function () {
    it('lets the owner forward as implicit ADMIN without granting itself', async function () {
      expect(await vpm.canForward(TOKEN, VAULT, owner.address)).to.equal(true);
      expect((await vpm.checkPermission(TOKEN, VAULT, owner.address, ADMIN))[0]).to.equal(true);
      expect((await vpm.getGrant(TOKEN, VAULT, owner.address)).exists).to.equal(false);
      await forwardAs(owner);
      expect(await logic.callCount()).to.equal(1);
      await expect(vpm.grantPermission(TOKEN, VAULT, owner.address, WRITE, 0, '')).to.be.reverted;
      await grantAdmin();
      await expect(vpm.connect(admin).grantPermission(TOKEN, VAULT, owner.address, WRITE, 0, '')).to
        .be.reverted;
    });

    it('does not infer owner permission on a namespace that does not exist', async function () {
      expect(await vpm.canForward(TOKEN, 'absent', owner.address)).to.equal(false);
      expect((await vpm.checkPermission(TOKEN, 'absent', owner.address, ADMIN))[0]).to.equal(false);
    });

    it('rejects permanent or overlong children of a finite ADMIN', async function () {
      const expiry = (await timestamp()) + 3600;
      await grantAdmin(expiry);
      await expect(child(0)).to.be.reverted;
      await expect(child(expiry + 1)).to.be.reverted;
      await child(expiry);
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(true);
      const record = await vpm.getGrant(TOKEN, VAULT, operator.address);
      expect(record.expiry).to.equal(expiry);
      expect(record.parentAdmin).to.equal(admin.address);
    });

    it('allows a permanent ADMIN to issue a permanent child', async function () {
      await grantAdmin();
      await child();
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(true);
    });

    it('keeps expiry inclusive and expires ADMIN and child one second later', async function () {
      const expiry = (await timestamp()) + 3600;
      await grantAdmin(expiry);
      await child(expiry);
      await moveTo(expiry - 1);
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(true);
      await moveTo(expiry);
      expect(await vpm.canForward(TOKEN, VAULT, admin.address)).to.equal(true);
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(true);
      await moveTo(expiry + 1);
      expect(await vpm.canForward(TOKEN, VAULT, admin.address)).to.equal(false);
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
    });

    it('immediately invalidates children when their ADMIN is revoked', async function () {
      await grantAdmin();
      await child();
      await vpm.revokePermission(TOKEN, VAULT, admin.address);
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
      await expect(forwardAs()).to.be.reverted;
    });

    it('does not resurrect old children when a revoked ADMIN is granted again', async function () {
      await grantAdmin();
      await child();
      const original = await vpm.getGrant(TOKEN, VAULT, operator.address);
      await vpm.revokePermission(TOKEN, VAULT, admin.address);
      await grantAdmin();
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
      await child();
      const renewed = await vpm.getGrant(TOKEN, VAULT, operator.address);
      expect(renewed.parentGeneration).to.be.gt(original.parentGeneration);
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(true);
    });

    it('invalidates prior children even when owner renews ADMIN without a revoke', async function () {
      await grantAdmin();
      await child();
      await grantAdmin();
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
    });

    it('invalidates children after ADMIN downgrade and does not restore them on promotion', async function () {
      await grantAdmin();
      await child();
      await vpm.grantPermission(TOKEN, VAULT, admin.address, WRITE, 0, 'downgraded administrator');
      expect(await vpm.canForward(TOKEN, VAULT, admin.address)).to.equal(true);
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
      await grantAdmin();
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
      await child();
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(true);
    });

    it('does not resurrect an expired ADMIN child after owner renews the parent', async function () {
      const expiry = (await timestamp()) + 100;
      await grantAdmin(expiry);
      await child(expiry);
      await moveTo(expiry + 1);
      await grantAdmin();
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
    });

    it('prevents ADMIN overwriting or revoking an owner-issued WRITE grant', async function () {
      await grantAdmin();
      await vpm.grantPermission(TOKEN, VAULT, operator.address, WRITE, 0, 'owner-issued');
      await expect(vpm.connect(admin).grantPermission(TOKEN, VAULT, operator.address, READ, 0, ''))
        .to.be.reverted;
      await expect(vpm.connect(admin).revokePermission(TOKEN, VAULT, operator.address)).to.be
        .reverted;
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(true);
    });

    it('prevents ADMIN changing another ADMIN or that ADMIN children', async function () {
      await grantAdmin();
      await grantAdmin(0, peer);
      await vpm
        .connect(peer)
        .grantPermission(TOKEN, VAULT, operator.address, WRITE, 0, 'peer-child');
      await expect(vpm.connect(admin).revokePermission(TOKEN, VAULT, peer.address)).to.be.reverted;
      await expect(vpm.connect(admin).grantPermission(TOKEN, VAULT, peer.address, READ, 0, '')).to
        .be.reverted;
      await expect(vpm.connect(admin).revokePermission(TOKEN, VAULT, operator.address)).to.be
        .reverted;
      await expect(child()).to.be.reverted;
    });

    it('allows ADMIN to update and revoke its own child and to revoke itself', async function () {
      await grantAdmin();
      await child();
      await vpm
        .connect(admin)
        .grantPermission(TOKEN, VAULT, operator.address, READ, 0, 'downgrade');
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
      await vpm.connect(admin).revokePermission(TOKEN, VAULT, operator.address);
      await child();
      await vpm.connect(admin).revokePermission(TOKEN, VAULT, admin.address);
      expect(await vpm.canForward(TOKEN, VAULT, admin.address)).to.equal(false);
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
    });

    it('lets owner replace a child with an independent root grant', async function () {
      await grantAdmin();
      await child();
      await vpm.grantPermission(TOKEN, VAULT, operator.address, WRITE, 0, 'root replacement');
      await vpm.revokePermission(TOKEN, VAULT, admin.address);
      expect((await vpm.getGrant(TOKEN, VAULT, operator.address)).parentAdmin).to.equal(
        ethers.constants.AddressZero,
      );
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(true);
    });

    it('lets only owner reset all grants while preserving namespaces', async function () {
      await grantAdmin();
      await child();
      const epoch = await vpm.permissionEpoch(TOKEN);
      await expect(vpm.connect(admin).resetPermissions(TOKEN)).to.be.reverted;
      await vpm.resetPermissions(TOKEN);
      expect(await vpm.permissionEpoch(TOKEN)).to.be.gt(epoch);
      expect(await vpm.vaultExists(TOKEN, VAULT)).to.equal(true);
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
      expect(await vpm.canForward(TOKEN, VAULT, admin.address)).to.equal(false);
      expect(await vpm.canForward(TOKEN, VAULT, owner.address)).to.equal(true);
    });
  });

  describe('owner observations and transfer nonce profile', function () {
    beforeEach(async function () {
      await vpm.grantPermission(TOKEN, VAULT, operator.address, WRITE, 0, '');
    });

    it('denies stale grants immediately but keeps stored owner epoch monotonic', async function () {
      const epoch = await vpm.permissionEpoch(TOKEN);
      await collection.transfer(TOKEN, other.address);
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
      expect(await vpm.permissionEpoch(TOKEN)).to.equal(epoch);
      await vpm.connect(peer).syncAgentState(TOKEN);
      expect(await vpm.permissionEpoch(TOKEN)).to.be.gt(epoch);
      await collection.transfer(TOKEN, owner.address);
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
    });

    it('documents unobserved atomic owner round-trip limitation of observed mode', async function () {
      expect(await vpm.ownershipNonceSupported()).to.equal(false);
      const helper = await deploy('VPMAtomicRoundTrip');
      await helper.roundTrip(collection.address, TOKEN, other.address, owner.address);
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(true);
    });

    it('documents that rejected forwarding cannot persist an owner observation', async function () {
      const helper = await deploy('VPMAtomicRoundTrip');
      await helper.roundTripWithRejectedObservation(
        collection.address,
        vpm.address,
        TOKEN,
        other.address,
        owner.address,
      );
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(true);
    });

    it('invalidates atomic round-trips with a collection-owned transfer nonce', async function () {
      const tracked = await deploy('MockNonceTrackedCollection');
      await tracked.mint(TOKEN, owner.address, logic.address);
      const source = await deploy('LegacyBAP578StateResolver', tracked.address);
      const resolver = await deploy('NonceTrackedStateResolver', source.address);
      const manager = await proxyFor(resolver);
      await manager.createVault(TOKEN, VAULT, '');
      await manager.grantPermission(TOKEN, VAULT, operator.address, WRITE, 0, '');
      expect(await manager.ownershipNonceSupported()).to.equal(true);
      expect(await manager.bap578()).to.equal(tracked.address);
      const helper = await deploy('VPMAtomicRoundTrip');
      await helper.roundTrip(tracked.address, TOKEN, other.address, owner.address);
      expect(await manager.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
      await manager.syncAgentState(TOKEN);
      expect(await manager.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
      await manager.grantPermission(TOKEN, VAULT, operator.address, WRITE, 0, 'renewed');
      expect(await manager.canForward(TOKEN, VAULT, operator.address)).to.equal(true);
      await helper.roundTripWithRejectedObservation(
        tracked.address,
        manager.address,
        TOKEN,
        other.address,
        owner.address,
      );
      expect(await manager.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
    });
  });

  describe('pause and active status', function () {
    beforeEach(async function () {
      await vpm.grantPermission(TOKEN, VAULT, operator.address, WRITE, 0, '');
    });

    it('blocks issuance and forwarding while paused but permits revocation, reset and sync', async function () {
      await expect(vpm.connect(other).pause()).to.be.reverted;
      await vpm.pause();
      expect(await vpm.paused()).to.equal(true);
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
      expect((await vpm.checkPermission(TOKEN, VAULT, operator.address, WRITE))[0]).to.equal(true);
      await expect(vpm.createVault(TOKEN, 'new', '')).to.be.reverted;
      await expect(vpm.grantPermission(TOKEN, VAULT, peer.address, WRITE, 0, '')).to.be.reverted;
      await expect(forwardAs()).to.be.reverted;
      await vpm.revokePermission(TOKEN, VAULT, operator.address);
      await vpm.resetPermissions(TOKEN);
      await vpm.syncAgentState(TOKEN);
      await executeGovernance(vpm, 'unpause');
      expect(await vpm.canForward(TOKEN, VAULT, owner.address)).to.equal(true);
    });

    it('keeps grants while collection status or global pause blocks execution', async function () {
      await collection.setActive(TOKEN, false);
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
      expect((await vpm.checkPermission(TOKEN, VAULT, operator.address, WRITE))[0]).to.equal(true);
      await expect(forwardAs()).to.be.reverted;
      await collection.setActive(TOKEN, true);
      await collection.setPaused(true);
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
      await expect(forwardAs()).to.be.reverted;
      await collection.setPaused(false);
      expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(true);
    });
  });

  describe('authenticated forwarding context and action outcome', function () {
    beforeEach(async function () {
      await vpm.grantPermission(TOKEN, VAULT, operator.address, WRITE, 0, '');
    });

    it('lets a downstream policy authenticate operator, destination, token and namespace', async function () {
      const policy = await deploy(
        'VPMContextOperatorPolicy',
        vpm.address,
        operator.address,
        ethers.utils.id(VAULT),
      );
      const guarded = await deploy('VPMContextPolicyLogic', vpm.address, policy.address);
      await collection.setLogic(TOKEN, guarded.address);
      await vpm.grantPermission(TOKEN, VAULT, operator.address, WRITE, 0, 'new module consent');
      await expectContextCleared();
      await forwardAs();
      expect(await guarded.lastAccessor()).to.equal(operator.address);
      expect(await guarded.lastVault()).to.equal(ethers.utils.id(VAULT));
      expect(await guarded.callCount()).to.equal(1);
      await expectContextCleared();
      await expect(guarded.connect(operator).handleAction(TOKEN, 'check', '0x')).to.be.reverted;
      await expect(policy.connect(operator).authorize(TOKEN)).to.be.reverted;
      await vpm.grantPermission(TOKEN, VAULT, peer.address, WRITE, 0, '');
      await expect(forwardAs(peer)).to.be.revertedWith('policy: wrong accessor');
      await expectContextCleared();
      await vpm.createVault(TOKEN, 'social', '');
      await vpm.grantPermission(TOKEN, 'social', operator.address, WRITE, 0, '');
      await expect(
        vpm.connect(operator).forwardHandleAction(TOKEN, 'social', 'check', '0x'),
      ).to.be.revertedWith('policy: wrong namespace');
      await expectContextCleared();
    });

    it('records false results without rolling back logic side effects', async function () {
      await logic.configure(1, vpm.address);
      const payload = ethers.utils.defaultAbiCoder.encode(['string'], ['declined']);
      const [success, result] = await vpm
        .connect(operator)
        .callStatic.forwardHandleAction(TOKEN, VAULT, 'reject', payload);
      expect(success).to.equal(false);
      expect(result).to.equal(payload);
      await expect(forwardAs(operator, 'reject', payload))
        .to.emit(vpm, 'ActionResult')
        .withArgs(
          TOKEN,
          ethers.utils.id(VAULT),
          operator.address,
          logic.address,
          false,
          ethers.utils.keccak256(payload),
        );
      expect(await logic.callCount()).to.equal(1);
      await expectContextCleared();
    });

    it('records successful result hash and clears context after dispatch', async function () {
      const payload = '0x010203';
      await expect(forwardAs(operator, 'check', payload))
        .to.emit(vpm, 'ActionResult')
        .withArgs(
          TOKEN,
          ethers.utils.id(VAULT),
          operator.address,
          logic.address,
          true,
          ethers.utils.keccak256(payload),
        );
      await expectContextCleared();
    });

    for (const [mode, description] of [
      [2, 'empty'],
      [3, 'short'],
      [4, 'invalid bool'],
      [5, 'invalid offset'],
    ]) {
      it(`reverts atomically on ${description} downstream return data`, async function () {
        await logic.configure(mode, vpm.address);
        await expect(forwardAs()).to.be.reverted;
        expect(await logic.callCount()).to.equal(0);
        await expectContextCleared();
      });
    }

    it('bubbles a downstream custom error unchanged and rolls back state', async function () {
      await logic.configure(6, vpm.address);
      await expect(forwardAs()).to.be.revertedWithCustomError(logic, 'ActionDeclined').withArgs(17);
      expect(await logic.callCount()).to.equal(0);
      await expectContextCleared();
    });

    it('bubbles panic and empty revert data without committing events or state', async function () {
      await logic.configure(7, ethers.constants.AddressZero);
      await expect(forwardAs()).to.be.revertedWithPanic(0x12);
      expect(await logic.callCount()).to.equal(0);
      await logic.configure(8, vpm.address);
      await expect(forwardAs()).to.be.revertedWithoutReason();
      expect(await logic.callCount()).to.equal(0);
      await expectContextCleared();
    });

    it('rejects zero and EOA logic both in canForward and dispatch', async function () {
      for (const destination of [ethers.constants.AddressZero, other.address]) {
        await collection.setLogic(TOKEN, destination);
        expect(await vpm.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
        await expect(forwardAs()).to.be.reverted;
        // Implicit owner ADMIN remains current across module changes, so these
        // assertions isolate dispatch readiness from stale delegate invalidation.
        expect((await vpm.checkPermission(TOKEN, VAULT, owner.address, ADMIN))[0]).to.equal(true);
        expect(await vpm.canForward(TOKEN, VAULT, owner.address)).to.equal(false);
        await expect(forwardAs(owner)).to.be.revertedWith(
          destination === ethers.constants.AddressZero
            ? 'VPM: no logic bound'
            : 'VPM: logic has no code',
        );
      }
    });

    it('blocks reentrant forwarding even when the logic itself holds WRITE', async function () {
      await vpm.grantPermission(TOKEN, VAULT, logic.address, WRITE, 0, '');
      await logic.configure(9, vpm.address);
      await forwardAs();
      expect(await logic.nestedRejected()).to.equal(true);
      expect(await logic.callCount()).to.equal(1);
      await expectContextCleared();
    });

    it('blocks cross-function permission mutations during forwarding', async function () {
      await vpm.grantPermission(TOKEN, VAULT, logic.address, ADMIN, 0, '');
      await logic.configure(10, vpm.address);
      await forwardAs();
      expect(await logic.nestedRejected()).to.equal(true);
      expect((await vpm.checkPermission(TOKEN, VAULT, logic.address, ADMIN))[0]).to.equal(true);
      await logic.configure(11, vpm.address);
      await forwardAs();
      expect(await logic.nestedRejected()).to.equal(true);
      await expectContextCleared();
    });
  });

  describe('actual collection adapter integration', function () {
    it('resolves actual BAP578 and enforces its active/global pause flags', async function () {
      const factory = await ethers.getContractFactory('BAP578');
      const legacy = await upgrades.deployProxy(factory, ['Agent', 'AGT', peer.address], {
        kind: 'uups',
      });
      await legacy.deployed();
      const metadata = ['', '', '', '', '', ethers.constants.HashZero];
      await legacy.createAgent(owner.address, logic.address, 'ipfs://conformance', metadata);
      const source = await deploy('LegacyBAP578StateResolver', legacy.address);
      const manager = await proxyFor(source);
      expect(await manager.bap578()).to.equal(legacy.address);
      await manager.createVault(1, VAULT, '');
      await manager.grantPermission(1, VAULT, operator.address, WRITE, 0, '');
      await manager.connect(operator).forwardHandleAction(1, VAULT, 'check', '0x');
      await legacy.setAgentStatus(1, false);
      expect(await manager.canForward(1, VAULT, operator.address)).to.equal(false);
      await expect(manager.connect(operator).forwardHandleAction(1, VAULT, 'check', '0x')).to.be
        .reverted;
      await legacy.setAgentStatus(1, true);
      await legacy.setPaused(true);
      expect(await manager.canForward(1, VAULT, operator.address)).to.equal(false);
      await legacy.setPaused(false);
      expect(await manager.canForward(1, VAULT, operator.address)).to.equal(true);
    });

    it('resolves actual CLAWNFA, status changes, collection pause and ownership', async function () {
      const token = await deploy('MockERC20Balance');
      const nfa = await deploy('NFA', token.address, 10000);
      await token.setBalance(owner.address, ethers.utils.parseUnits('10000', 18));
      const request = { wallet: owner.address, nonce: 0, expiry: (await timestamp()) + 3600 };
      const network = await ethers.provider.getNetwork();
      const signature = await owner._signTypedData(
        {
          name: 'Non-Fungible Agent',
          version: '1',
          chainId: network.chainId,
          verifyingContract: nfa.address,
        },
        {
          MintRequest: [
            { name: 'wallet', type: 'address' },
            { name: 'nonce', type: 'uint256' },
            { name: 'expiry', type: 'uint256' },
          ],
        },
        request,
      );
      await nfa.mint(request, signature);
      await nfa.setAllowedLogicContract(logic.address, true);
      await nfa.setLogicAddress(0, logic.address);
      const source = await deploy('CLAWNFAStateResolver', nfa.address);
      const manager = await proxyFor(source);
      await manager.createVault(0, VAULT, '');
      await manager.grantPermission(0, VAULT, operator.address, WRITE, 0, '');
      await manager.connect(operator).forwardHandleAction(0, VAULT, 'check', '0x');
      await nfa.pause(0);
      expect(await manager.canForward(0, VAULT, operator.address)).to.equal(false);
      await expect(manager.connect(operator).forwardHandleAction(0, VAULT, 'check', '0x')).to.be
        .reverted;
      await nfa.unpause(0);
      await nfa.setPaused(true);
      expect(await manager.canForward(0, VAULT, operator.address)).to.equal(false);
      await nfa.setPaused(false);
      expect(await manager.canForward(0, VAULT, operator.address)).to.equal(true);
      await nfa.transferFrom(owner.address, other.address, 0);
      expect(await manager.canForward(0, VAULT, operator.address)).to.equal(false);
      expect(await manager.canForward(0, VAULT, other.address)).to.equal(true);
      await nfa.connect(other).terminate(0);
      expect(await manager.canForward(0, VAULT, other.address)).to.equal(false);
    });
  });

  describe('resolver failures and ownership profile consistency', function () {
    async function configurableManager(supportsNonce = false, nonce = 0) {
      const resolver = await deploy(
        'VPMConfigurableResolver',
        collection.address,
        owner.address,
        logic.address,
        supportsNonce,
      );
      await resolver.configureState(owner.address, logic.address, true, nonce);
      const manager = await proxyFor(resolver);
      await manager.createVault(TOKEN, VAULT, '');
      await manager.grantPermission(TOKEN, VAULT, operator.address, WRITE, 0, '');
      return { resolver, manager };
    }

    for (const [mode, description] of [
      [1, 'reverting'],
      [2, 'empty'],
      [3, 'invalid bool'],
    ]) {
      it(`fails closed on ${description} resolver output without exposing forwarding context`, async function () {
        const { resolver, manager } = await configurableManager();
        await resolver.configureReturn(mode);
        await expect(manager.canForward(TOKEN, VAULT, operator.address)).to.be.reverted;
        await expect(manager.checkPermission(TOKEN, VAULT, operator.address, WRITE)).to.be.reverted;
        await expect(manager.connect(operator).forwardHandleAction(TOKEN, VAULT, 'check', '0x')).to
          .be.reverted;
        await expect(manager.syncAgentState(TOKEN)).to.be.reverted;
        expect(await manager.permissionEpoch(TOKEN)).to.equal(0);
        expect(await logic.callCount()).to.equal(0);
        await expectContextCleared(manager);
      });
    }

    it('rejects zero-owner resolver output instead of inferring an authority', async function () {
      const { resolver, manager } = await configurableManager();
      await resolver.configureState(ethers.constants.AddressZero, logic.address, true, 0);
      await expect(manager.canForward(TOKEN, VAULT, operator.address)).to.be.reverted;
      await expect(manager.checkPermission(TOKEN, VAULT, owner.address, ADMIN)).to.be.reverted;
      await expect(manager.connect(operator).forwardHandleAction(TOKEN, VAULT, 'check', '0x')).to.be
        .reverted;
      await expectContextCleared(manager);
    });

    it('rejects a nonzero ownership nonce from a profile declaring no nonce support', async function () {
      const { resolver, manager } = await configurableManager();
      expect(await manager.ownershipNonceSupported()).to.equal(false);
      await resolver.configureState(owner.address, logic.address, true, 1);
      await expect(manager.checkPermission(TOKEN, VAULT, operator.address, WRITE)).to.be.reverted;
      await expect(manager.syncAgentState(TOKEN)).to.be.reverted;
      await expect(manager.connect(operator).forwardHandleAction(TOKEN, VAULT, 'check', '0x')).to.be
        .reverted;
      expect(await logic.callCount()).to.equal(0);
      await expectContextCleared(manager);
    });

    it('rejects authoritative nonce decrease without advancing epoch or dispatching', async function () {
      const { resolver, manager } = await configurableManager(true, 10);
      expect(await manager.ownershipNonceSupported()).to.equal(true);
      await resolver.configureState(owner.address, logic.address, true, 9);
      await expect(manager.canForward(TOKEN, VAULT, operator.address)).to.be.reverted;
      await expect(manager.checkPermission(TOKEN, VAULT, operator.address, WRITE)).to.be.reverted;
      await expect(manager.syncAgentState(TOKEN)).to.be.reverted;
      await expect(manager.connect(operator).forwardHandleAction(TOKEN, VAULT, 'check', '0x')).to.be
        .reverted;
      expect(await manager.permissionEpoch(TOKEN)).to.equal(0);
      expect(await logic.callCount()).to.equal(0);
      await expectContextCleared(manager);
      await resolver.configureState(owner.address, logic.address, true, 11);
      expect(await manager.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
      await manager.syncAgentState(TOKEN);
      expect(await manager.permissionEpoch(TOKEN)).to.equal(1);
    });

    it('does not manufacture nonce protection for a collection lacking the counter', async function () {
      const legacy = await deploy('LegacyBAP578StateResolver', collection.address);
      const nonceProfile = await deploy('NonceTrackedStateResolver', legacy.address);
      const manager = await proxyFor(nonceProfile);
      expect(await manager.ownershipNonceSupported()).to.equal(true);
      await expect(manager.createVault(TOKEN, VAULT, '')).to.be.reverted;
      await expectContextCleared(manager);
    });

    it('exposes the pinned collection and resolver through public profile getters', async function () {
      const { resolver, manager } = await configurableManager();
      expect(await manager.collection()).to.equal(collection.address);
      expect(await manager.bap578()).to.equal(collection.address);
      expect(await manager.resolver()).to.equal(resolver.address);
      expect(await manager.ownershipNonceSupported()).to.equal(false);
      expect(await manager.paused()).to.equal(false);
    });
  });

  describe('upgrade and initialization safety', function () {
    it('locks implementation initialization and rejects invalid resolver addresses', async function () {
      const implementation = await deploy('AgentExecutionPermissionManagerReferenceV1');
      const governance = vpm._testGovernance;
      await expect(
        implementation.initialize(await vpm.resolver(), governance.timelock.address, owner.address),
      ).to.be.reverted;
      await expect(
        vpm.initializeLegacyCompatibility(
          await vpm.resolver(),
          governance.timelock.address,
          owner.address,
        ),
      ).to.be.reverted;
      for (const invalid of [ethers.constants.AddressZero, other.address]) {
        await expect(deployExecutionManager(invalid, { governance })).to.be.reverted;
      }
    });

    it('rejects zero and EOA resolver addresses and explicit resolver collection metadata', async function () {
      const governance = vpm._testGovernance;
      for (const invalid of [ethers.constants.AddressZero, other.address]) {
        await expect(deployExecutionManager(invalid, { strict: true, governance })).to.be.reverted;
        const resolver = await deploy(
          'VPMConfigurableResolver',
          invalid,
          owner.address,
          logic.address,
          false,
        );
        await expect(proxyFor(resolver)).to.be.reverted;
      }
      await expect(proxyFor(logic)).to.be.reverted;
    });

    it('preserves root and delegated grants, governance and resolver across delayed upgrade', async function () {
      await grantAdmin();
      await child();
      const resolver = await vpm.resolver();
      const grantBefore = await vpm.getGrant(TOKEN, VAULT, operator.address);
      const implementation = await deploy('VPMConformanceUpgrade');
      await expect(vpm.connect(other).upgradeTo(implementation.address)).to.be.reverted;
      await expect(vpm.upgradeTo(implementation.address)).to.be.reverted;
      await executeGovernance(vpm, 'upgradeTo', [implementation.address]);
      const upgraded = (await ethers.getContractFactory('VPMConformanceUpgrade')).attach(
        vpm.address,
      );
      expect(await upgraded.conformanceVersion()).to.equal(2);
      expect(await upgraded.owner()).to.equal(vpm._testGovernance.timelock.address);
      expect(await upgraded.bap578()).to.equal(collection.address);
      expect(await upgraded.resolver()).to.equal(resolver);
      expect(await upgraded.vaultExists(TOKEN, VAULT)).to.equal(true);
      expect(await upgraded.canForward(TOKEN, VAULT, operator.address)).to.equal(true);
      expect(await upgraded.getGrant(TOKEN, VAULT, operator.address)).to.deep.equal(grantBefore);
      await upgraded.revokePermission(TOKEN, VAULT, admin.address);
      expect(await upgraded.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
    });
  });
});
