const { expect } = require('chai');
const { ethers, upgrades } = require('hardhat');
const { deployExecutionManager } = require('./helpers/execution-v1');

describe('VaultPermissionManager security: collection profiles', function () {
  const TOKEN = 1;
  const VAULT = 'default';
  const WRITE = 2;
  let owner, operator, peer, logic;

  async function deploy(name, ...args) {
    const instance = await (await ethers.getContractFactory(name)).deploy(...args);
    await instance.deployed();
    return instance;
  }

  async function managerFor(collection, tracked = false) {
    let resolver = await deploy('LegacyBAP578StateResolver', collection.address);
    if (tracked) resolver = await deploy('NonceTrackedStateResolver', resolver.address);
    const manager = await deployExecutionManager(resolver);
    await manager.createVault(TOKEN, VAULT, 'security profile');
    await manager.grantPermission(TOKEN, VAULT, operator.address, WRITE, 0, '');
    return manager;
  }

  async function legacyCollection() {
    const collection = await upgrades.deployProxy(
      await ethers.getContractFactory('BAP578'),
      ['Security profile', 'SP', peer.address],
      { kind: 'uups' },
    );
    await collection.deployed();
    // Upstream free mints cannot transfer. Use an actual paid transferable agent.
    await collection.setFreeMintsPerUser(0);
    const metadata = ['', '', '', '', '', ethers.constants.HashZero];
    await collection.createAgent(owner.address, logic.address, 'ipfs://security', metadata, {
      value: await collection.MINT_FEE(),
    });
    return collection;
  }

  beforeEach(async function () {
    [owner, operator, peer] = await ethers.getSigners();
    logic = await deploy('VPMRawReturnLogic');
  });

  it('reproduces the disclosed observed-owner round trip through a real safe-transfer callback', async function () {
    const collection = await legacyCollection();
    const manager = await managerFor(collection);
    const receiver = await deploy('VPMTransferBackReceiver', manager.address, false);
    await collection['safeTransferFrom(address,address,uint256)'](
      owner.address,
      receiver.address,
      TOKEN,
    );
    expect(await collection.ownerOf(TOKEN)).to.equal(owner.address);
    expect(await manager.permissionEpoch(TOKEN)).to.equal(0);
    expect(await manager.canForward(TOKEN, VAULT, operator.address)).to.equal(true);
  });

  it('keeps legacy grants invalid when the real receiver commits an intermediate observation', async function () {
    const collection = await legacyCollection();
    const manager = await managerFor(collection);
    const receiver = await deploy('VPMTransferBackReceiver', manager.address, true);
    await collection['safeTransferFrom(address,address,uint256)'](
      owner.address,
      receiver.address,
      TOKEN,
    );
    expect(await collection.ownerOf(TOKEN)).to.equal(owner.address);
    expect(await manager.permissionEpoch(TOKEN)).to.equal(1);
    expect(await manager.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
    await manager.syncAgentState(TOKEN);
    expect(await manager.permissionEpoch(TOKEN)).to.equal(2);
    expect(await manager.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
  });

  it('commits actual owner changes when the new owner grants on a surviving namespace', async function () {
    const collection = await legacyCollection();
    const manager = await managerFor(collection);
    await collection.transferFrom(owner.address, peer.address, TOKEN);
    await manager.connect(peer).grantPermission(TOKEN, VAULT, operator.address, WRITE, 0, '');
    await collection.connect(peer).transferFrom(peer.address, owner.address, TOKEN);
    expect(await manager.vaultExists(TOKEN, VAULT)).to.equal(true);
    expect(await manager.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
    expect(await manager.canForward(TOKEN, VAULT, owner.address)).to.equal(true);
  });

  it('detects a real ERC721 receiver round trip without an intermediate manager transaction in nonce mode', async function () {
    const collection = await deploy('VPMNonceLifecycleCollection');
    await collection.mint(TOKEN, owner.address, logic.address);
    const manager = await managerFor(collection, true);
    const receiver = await deploy('VPMTransferBackReceiver', manager.address, false);
    await collection['safeTransferFrom(address,address,uint256)'](
      owner.address,
      receiver.address,
      TOKEN,
    );
    expect(await collection.ownershipNonce(TOKEN)).to.equal(3);
    expect(await manager.permissionEpoch(TOKEN)).to.equal(0);
    expect(await manager.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
    await expect(manager.connect(operator).forwardHandleAction(TOKEN, VAULT, 'probe', '0x')).to.be
      .reverted;
    expect(await logic.callCount()).to.equal(0);
    // A rejected action is not an epoch commit, but cannot erase the NFT counter.
    expect(await manager.permissionEpoch(TOKEN)).to.equal(0);
  });

  it('invalidates a grant when the authoritative counter advances on a self transfer', async function () {
    const collection = await deploy('VPMNonceLifecycleCollection');
    await collection.mint(TOKEN, owner.address, logic.address);
    const manager = await managerFor(collection, true);
    await collection.transferFrom(owner.address, owner.address, TOKEN);
    expect(await collection.ownerOf(TOKEN)).to.equal(owner.address);
    expect(await manager.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
    await manager.syncAgentState(TOKEN);
    expect(await manager.permissionEpoch(TOKEN)).to.equal(1);
    expect(await manager.canForward(TOKEN, VAULT, owner.address)).to.equal(true);
  });

  it('denies burned agents and never revives their grants after counter-preserving same-owner remint', async function () {
    const collection = await deploy('VPMNonceLifecycleCollection');
    await collection.mint(TOKEN, owner.address, logic.address);
    const manager = await managerFor(collection, true);
    await collection.burn(TOKEN);
    await expect(manager.canForward(TOKEN, VAULT, operator.address)).to.be.reverted;
    await expect(manager.syncAgentState(TOKEN)).to.be.reverted;
    await expect(manager.connect(operator).forwardHandleAction(TOKEN, VAULT, 'probe', '0x')).to.be
      .reverted;
    await collection.mint(TOKEN, owner.address, logic.address);
    expect(await collection.ownershipNonce(TOKEN)).to.equal(3);
    expect(await manager.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
    await manager.syncAgentState(TOKEN);
    expect(await manager.permissionEpoch(TOKEN)).to.equal(1);
    await manager.grantPermission(TOKEN, VAULT, operator.address, WRITE, 0, 'fresh incarnation');
    expect(await manager.canForward(TOKEN, VAULT, operator.address)).to.equal(true);
  });

  it('does not treat an approved ERC721 operator as the NFT owner in the ACL', async function () {
    const collection = await legacyCollection();
    const manager = await managerFor(collection);
    await collection.approve(peer.address, TOKEN);
    await expect(manager.connect(peer).createVault(TOKEN, 'other', '')).to.be.reverted;
    await expect(
      manager.connect(peer).grantPermission(TOKEN, VAULT, operator.address, WRITE, 0, ''),
    ).to.be.reverted;
    expect(await manager.canForward(TOKEN, VAULT, peer.address)).to.equal(false);
    await collection.connect(peer).transferFrom(owner.address, peer.address, TOKEN);
    expect(await manager.canForward(TOKEN, VAULT, peer.address)).to.equal(true);
    expect(await manager.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
  });
});
