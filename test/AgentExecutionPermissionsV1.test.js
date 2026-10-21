const { expect } = require('chai');
const { ethers } = require('hardhat');
const { deployExecutionManager, executeGovernance } = require('./helpers/execution-v1');

describe('AgentExecutionPermissionsV1 authoritative execution binding', function () {
  const TOKEN = 1;
  const VAULT = 'default';
  const READ = 1;
  const WRITE = 2;
  const ADMIN = 3;
  let owner, operator, admin, child, peer, intermediate;
  let collection, moduleA, moduleB, source, resolver, manager;

  async function deploy(name, ...args) {
    const contract = await (await ethers.getContractFactory(name)).deploy(...args);
    await contract.deployed();
    return contract;
  }

  async function grantRoles(target = manager) {
    await target.grantPermission(TOKEN, VAULT, operator.address, WRITE, 0, 'owner WRITE');
    await target.grantPermission(TOKEN, VAULT, peer.address, READ, 0, 'owner READ');
    await target.grantPermission(TOKEN, VAULT, admin.address, ADMIN, 0, 'owner ADMIN');
    await target.connect(admin).grantPermission(TOKEN, VAULT, child.address, WRITE, 0, 'child');
  }

  async function expectAllDelegatesInvalid(target = manager) {
    for (const [signer, role] of [
      [operator, WRITE],
      [peer, READ],
      [admin, ADMIN],
      [child, WRITE],
    ]) {
      expect((await target.checkPermission(TOKEN, VAULT, signer.address, role))[0]).to.equal(false);
      expect(await target.canForward(TOKEN, VAULT, signer.address)).to.equal(false);
    }
    await expect(
      target.connect(admin).grantPermission(TOKEN, VAULT, child.address, WRITE, 0, 'stale'),
    ).to.be.reverted;
    await expect(target.connect(operator).forwardHandleAction(TOKEN, VAULT, 'act', '0x')).to.be
      .reverted;
  }

  beforeEach(async function () {
    [owner, operator, admin, child, peer, intermediate] = await ethers.getSigners();
    collection = await deploy('FaultInjectedRevisionERC721');
    moduleA = await deploy('RevisionModuleV1');
    moduleB = await deploy('RevisionModuleV2');
    await collection.mint(TOKEN, owner.address, moduleA.address);
    source = await deploy('LegacyBAP578StateResolver', collection.address);
    resolver = await deploy('AuthoritativeStateResolver', source.address);
    manager = await deployExecutionManager(resolver, { strict: true });
    await manager.createVault(TOKEN, VAULT, 'execution-bound namespace');
    await grantRoles();
  });

  it('pins both authoritative capabilities in the strict profile', async function () {
    expect(await manager.protectionProfile()).to.equal(0);
    expect(await manager.ownershipNonceSupported()).to.equal(true);
    expect(await manager.executionRevisionSupported()).to.equal(true);
    expect(await manager.collection()).to.equal(collection.address);
    expect(await manager.resolver()).to.equal(resolver.address);
    expect(await manager.canForward(TOKEN, VAULT, operator.address)).to.equal(true);
  });

  it('rejects observed-owner and ownership-only adapters without silently falling back', async function () {
    const governance = manager._testGovernance;
    await expect(deployExecutionManager(source, { strict: true, governance })).to.be.revertedWith(
      'VPM: strict counters required',
    );
    const ownershipOnly = await deploy('NonceTrackedStateResolver', source.address);
    expect(await ownershipOnly.supportsOwnershipNonce()).to.equal(true);
    expect(await ownershipOnly.supportsExecutionRevision()).to.equal(false);
    await expect(
      deployExecutionManager(ownershipOnly, { strict: true, governance }),
    ).to.be.revertedWith('VPM: strict counters required');
    const executionOnly = await deploy('ExecutionRevisionOnlyResolver', source.address);
    await expect(
      deployExecutionManager(executionOnly, { strict: true, governance }),
    ).to.be.revertedWith('VPM: strict counters required');
  });

  it('allows weaker profiles only through the separately named compatibility initializer', async function () {
    const legacy = await deployExecutionManager(source);
    expect(await legacy.protectionProfile()).to.equal(1);
    expect(await legacy.ownershipNonceSupported()).to.equal(false);
    expect(await legacy.executionRevisionSupported()).to.equal(false);
    await legacy.createVault(TOKEN, VAULT, 'explicit compatibility');
    expect(await legacy.canForward(TOKEN, VAULT, owner.address)).to.equal(true);
    await expect(
      legacy.initialize(resolver.address, legacy._testGovernance.timelock.address, owner.address),
    ).to.be.reverted;
  });

  it('reads actual collection counters without inventing history for an unsupported collection', async function () {
    const state = await resolver.getAgentState(TOKEN);
    expect(state.ownershipNonce).to.equal(await collection.ownershipNonce(TOKEN));
    expect(state.executionRevision).to.equal(await collection.executionRevision(TOKEN));
    const unsupported = await deploy('MockBAP578ForVPM');
    await unsupported.mint(TOKEN, owner.address, moduleA.address);
    const legacySource = await deploy('LegacyBAP578StateResolver', unsupported.address);
    const invalidWrapper = await deploy('AuthoritativeStateResolver', legacySource.address);
    await expect(invalidWrapper.getAgentState(TOKEN)).to.be.reverted;
    const invalidManager = await deployExecutionManager(invalidWrapper, { strict: true });
    await expect(invalidManager.createVault(TOKEN, VAULT, 'not manufactured')).to.be.reverted;
  });

  it('invalidates every role after an actual ERC721 transfer and requires new-owner consent', async function () {
    const nonce = await collection.ownershipNonce(TOKEN);
    await collection.transferFrom(owner.address, intermediate.address, TOKEN);
    expect(await collection.ownershipNonce(TOKEN)).to.equal(nonce.add(1));
    await expectAllDelegatesInvalid();
    expect(await manager.canForward(TOKEN, VAULT, intermediate.address)).to.equal(true);
    await expect(manager.grantPermission(TOKEN, VAULT, operator.address, WRITE, 0, 'seller')).to.be
      .reverted;
    await manager
      .connect(intermediate)
      .grantPermission(TOKEN, VAULT, operator.address, WRITE, 0, 'buyer');
    expect(await manager.canForward(TOKEN, VAULT, operator.address)).to.equal(true);
    expect(await manager.canForward(TOKEN, VAULT, admin.address)).to.equal(false);
  });

  it('detects an atomic ownership A-to-B-to-A round trip with no intervening observation', async function () {
    const nonce = await collection.ownershipNonce(TOKEN);
    const epoch = await manager.permissionEpoch(TOKEN);
    await collection.roundTripOwner(TOKEN, intermediate.address);
    expect(await collection.ownerOf(TOKEN)).to.equal(owner.address);
    expect(await collection.ownershipNonce(TOKEN)).to.equal(nonce.add(2));
    await expectAllDelegatesInvalid();
    await manager.syncAgentState(TOKEN);
    expect(await manager.permissionEpoch(TOKEN)).to.equal(epoch.add(1));
    await grantRoles();
    expect(await manager.canForward(TOKEN, VAULT, child.address)).to.equal(true);
  });

  it('never restores pre-burn grants when the same token is reminted to the same owner', async function () {
    const nonce = await collection.ownershipNonce(TOKEN);
    await collection.burn(TOKEN);
    await expect(manager.canForward(TOKEN, VAULT, operator.address)).to.be.reverted;
    await collection.mint(TOKEN, owner.address, moduleA.address);
    expect(await collection.ownershipNonce(TOKEN)).to.equal(nonce.add(2));
    await expectAllDelegatesInvalid();
    await manager.grantPermission(TOKEN, VAULT, admin.address, ADMIN, 0, 'fresh root');
    expect(await manager.canForward(TOKEN, VAULT, child.address)).to.equal(false);
  });

  it('invalidates READ, WRITE, ADMIN and delegated children when the module changes', async function () {
    const revision = await collection.executionRevision(TOKEN);
    await collection.setLogic(TOKEN, moduleB.address);
    expect(await collection.executionRevision(TOKEN)).to.equal(revision.add(1));
    await expectAllDelegatesInvalid();
    expect(await manager.canForward(TOKEN, VAULT, owner.address)).to.equal(true);
    await manager.grantPermission(TOKEN, VAULT, admin.address, ADMIN, 0, 'fresh ADMIN');
    expect(await manager.canForward(TOKEN, VAULT, child.address)).to.equal(false);
    await manager
      .connect(admin)
      .grantPermission(TOKEN, VAULT, child.address, WRITE, 0, 'fresh child');
    expect(await manager.canForward(TOKEN, VAULT, child.address)).to.equal(true);
  });

  it('detects an atomic logic A-to-B-to-A round trip despite an unchanged final address', async function () {
    const revision = await collection.executionRevision(TOKEN);
    await collection.roundTripLogic(TOKEN, moduleB.address);
    expect((await collection.agentStates(TOKEN)).logicAddress).to.equal(moduleA.address);
    expect(await collection.executionRevision(TOKEN)).to.equal(revision.add(2));
    await expectAllDelegatesInvalid();
    await grantRoles();
    expect(await manager.canForward(TOKEN, VAULT, operator.address)).to.equal(true);
  });

  it('atomically binds same-address proxy upgrades to the collection execution revision', async function () {
    const proxy = await deploy(
      'RevisionTrackedModuleProxy',
      moduleA.address,
      collection.address,
      TOKEN,
    );
    await collection.setLogic(TOKEN, proxy.address);
    await grantRoles();
    const proxyCode = await ethers.provider.getCode(proxy.address);
    const proxyModule = await ethers.getContractAt('RevisionModuleV1', proxy.address);
    expect(await proxyModule.version()).to.equal(1);
    const revision = await collection.executionRevision(TOKEN);
    await expect(proxy.upgradeTo(moduleB.address)).to.be.reverted;
    await collection.upgradeExecutionModule(TOKEN, moduleB.address);
    expect(await ethers.provider.getCode(proxy.address)).to.equal(proxyCode);
    expect((await collection.agentStates(TOKEN)).logicAddress).to.equal(proxy.address);
    expect(await proxyModule.version()).to.equal(2);
    expect(await collection.executionRevision(TOKEN)).to.equal(revision.add(1));
    await expectAllDelegatesInvalid();
    await manager.grantPermission(TOKEN, VAULT, operator.address, WRITE, 0, 'reviewed version 2');
    expect(
      (
        await manager
          .connect(operator)
          .callStatic.forwardHandleAction(TOKEN, VAULT, 'act', '0x1234')
      )[1],
    ).to.equal('0x1234');
  });

  it('does not increment a revision when an invalid proxy upgrade reverts atomically', async function () {
    const proxy = await deploy(
      'RevisionTrackedModuleProxy',
      moduleA.address,
      collection.address,
      TOKEN,
    );
    await collection.setLogic(TOKEN, proxy.address);
    await grantRoles();
    const revision = await collection.executionRevision(TOKEN);
    await expect(collection.upgradeExecutionModule(TOKEN, intermediate.address)).to.be.reverted;
    expect(await collection.executionRevision(TOKEN)).to.equal(revision);
    expect(await manager.canForward(TOKEN, VAULT, operator.address)).to.equal(true);
  });

  it('does not resurrect grants after upgrading a proxy implementation back to its old version', async function () {
    const proxy = await deploy(
      'RevisionTrackedModuleProxy',
      moduleA.address,
      collection.address,
      TOKEN,
    );
    await collection.setLogic(TOKEN, proxy.address);
    await grantRoles();
    await collection.upgradeExecutionModule(TOKEN, moduleB.address);
    await collection.upgradeExecutionModule(TOKEN, moduleA.address);
    expect(
      await (await ethers.getContractAt('RevisionModuleV1', proxy.address)).version(),
    ).to.equal(1);
    await expectAllDelegatesInvalid();
  });

  it('fails closed if an advertised authoritative ownership counter decreases', async function () {
    await collection.roundTripOwner(TOKEN, intermediate.address);
    await manager.syncAgentState(TOKEN);
    const revision = await collection.executionRevision(TOKEN);
    await collection.setCountersForTest(TOKEN, 1, revision);
    await expect(manager.syncAgentState(TOKEN)).to.be.reverted;
    await expect(manager.canForward(TOKEN, VAULT, owner.address)).to.be.reverted;
    await expect(
      manager.grantPermission(TOKEN, VAULT, operator.address, WRITE, 0, 'cannot recover trust'),
    ).to.be.reverted;
  });

  it('fails closed if an advertised authoritative execution revision decreases', async function () {
    await collection.setLogic(TOKEN, moduleB.address);
    await manager.syncAgentState(TOKEN);
    await collection.setCountersForTest(TOKEN, await collection.ownershipNonce(TOKEN), 1);
    await expect(manager.syncAgentState(TOKEN)).to.be.reverted;
    await expect(manager.canForward(TOKEN, VAULT, owner.address)).to.be.reverted;
  });

  it('rejects a changed owner when an authoritative collection fails to advance its nonce', async function () {
    await collection.transferWithoutNonceForTest(TOKEN, intermediate.address);
    await expect(manager.syncAgentState(TOKEN)).to.be.reverted;
    await expect(manager.canForward(TOKEN, VAULT, intermediate.address)).to.be.reverted;
  });

  it('rejects a changed module when an authoritative collection fails to advance its revision', async function () {
    await collection.setLogicWithoutRevisionForTest(TOKEN, moduleB.address);
    await expect(manager.syncAgentState(TOKEN)).to.be.reverted;
    await expect(manager.canForward(TOKEN, VAULT, owner.address)).to.be.reverted;
  });

  it('commits one monotonic epoch advance when ownership and execution both changed', async function () {
    const epoch = await manager.permissionEpoch(TOKEN);
    await collection.setLogic(TOKEN, moduleB.address);
    await collection.transferFrom(owner.address, intermediate.address, TOKEN);
    await expect(manager.syncAgentState(TOKEN)).to.emit(manager, 'AgentEpochAdvanced');
    expect(await manager.permissionEpoch(TOKEN)).to.equal(epoch.add(1));
    await manager.syncAgentState(TOKEN);
    expect(await manager.permissionEpoch(TOKEN)).to.equal(epoch.add(1));
  });

  it('preserves the explicitly weaker unobserved-round-trip limitation in compatibility mode', async function () {
    const legacy = await deployExecutionManager(source);
    await legacy.createVault(TOKEN, VAULT, 'weaker observed-state profile');
    await grantRoles(legacy);
    await collection.setLogic(TOKEN, moduleB.address);
    expect(await legacy.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
    await expect(legacy.connect(operator).forwardHandleAction(TOKEN, VAULT, 'act', '0x')).to.be
      .reverted;
    await collection.setLogic(TOKEN, moduleA.address);
    expect(await legacy.canForward(TOKEN, VAULT, operator.address)).to.equal(true);
    await collection.roundTripOwner(TOKEN, intermediate.address);
    expect(await legacy.canForward(TOKEN, VAULT, operator.address)).to.equal(true);
    await legacy.resetPermissions(TOKEN);
    expect(await legacy.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
  });

  it('irreversibly invalidates compatibility grants when a changed module is successfully observed', async function () {
    const legacy = await deployExecutionManager(source);
    await legacy.createVault(TOKEN, VAULT, 'explicit compatibility');
    await grantRoles(legacy);
    await collection.setLogic(TOKEN, moduleB.address);
    await legacy.syncAgentState(TOKEN);
    await collection.setLogic(TOKEN, moduleA.address);
    await legacy.syncAgentState(TOKEN);
    await expectAllDelegatesInvalid(legacy);
  });

  it('authenticates the entry ownership nonce and execution revision in forwarding context', async function () {
    const contextLogic = await deploy('RevisionContextLogic', manager.address);
    await collection.setLogic(TOKEN, contextLogic.address);
    await grantRoles();
    await manager.connect(operator).forwardHandleAction(TOKEN, VAULT, 'act', '0xabcd');
    expect(await contextLogic.lastOwnershipNonce()).to.equal(
      await collection.ownershipNonce(TOKEN),
    );
    expect(await contextLogic.lastExecutionRevision()).to.equal(
      await collection.executionRevision(TOKEN),
    );
    const cleared = await manager.getForwardingContext();
    expect(cleared.ownershipNonce).to.equal(0);
    expect(cleared.executionRevision).to.equal(0);
    await expect(contextLogic.handleAction(TOKEN, 'fake', '0x')).to.be.reverted;
  });

  it('distinguishes canonical data permissions from versioned execution permissions by name and interface', async function () {
    const probe = await deploy('PermissionInterfaceIdentityProbe');
    const executionId = await probe.executionInterfaceId();
    const dataId = await probe.dataAccessInterfaceId();
    expect(executionId).not.to.equal(dataId);
    expect(await manager.supportsInterface(executionId)).to.equal(true);
    expect(await manager.supportsInterface(dataId)).to.equal(false);
    expect(await manager.supportsInterface('0x01ffc9a7')).to.equal(true);
    expect(await manager.supportsInterface('0xffffffff')).to.equal(false);
    expect(await manager.extensionId()).to.equal(
      ethers.utils.id('bap578.agent-execution-permissions.v1'),
    );
    expect(await manager.extensionVersion()).to.equal(1);
    expect((await probe.executionEnums()).map(Number)).to.deep.equal([0, 1, 2, 3]);
    expect((await probe.dataAccessEnums()).map(Number)).to.deep.equal([0, 1, 2, 3]);
    expect(
      manager.interface.functions['delegateAccess(uint256,address,uint8,uint256,bytes)'],
    ).to.equal(undefined);
    const oldInterface = new ethers.utils.Interface([
      'function delegateAccess(uint256,address,uint8,uint256,bytes)',
    ]);
    await expect(
      owner.sendTransaction({
        to: manager.address,
        data: oldInterface.encodeFunctionData('delegateAccess', [
          TOKEN,
          operator.address,
          1,
          0,
          '0x',
        ]),
      }),
    ).to.be.reverted;
  });

  it('allows the guardian only to pause, with delayed governance required to unpause', async function () {
    const governance = manager._testGovernance;
    expect(await manager.owner()).to.equal(governance.timelock.address);
    expect(await manager.governance()).to.equal(governance.timelock.address);
    expect(await manager.governanceMinDelay()).to.equal(48 * 60 * 60);
    await expect(manager.connect(operator).pause()).to.be.reverted;
    await manager.connect(governance.guardian).pause();
    await expect(manager.connect(governance.guardian).unpause()).to.be.reverted;
    expect(await manager.paused()).to.equal(true);
    await manager.resetPermissions(TOKEN);
    await manager.syncAgentState(TOKEN);
    await executeGovernance(manager, 'unpause', []);
    expect(await manager.paused()).to.equal(false);
  });
});
