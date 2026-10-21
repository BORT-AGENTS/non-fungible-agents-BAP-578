const { expect } = require('chai');
const { ethers } = require('hardhat');
const { deployLegacyManager } = require('./helpers/execution-v1');

describe('VaultPermissionManager stock ABI compatibility', function () {
  const TOKEN_ID = 1;
  const VAULT_ID = 'default';
  let owner, operator, bap578, vpm, logic;

  beforeEach(async function () {
    [owner, operator] = await ethers.getSigners();
    const BAP578 = await ethers.getContractFactory('MockBAP578ForVPM');
    bap578 = await BAP578.deploy();
    await bap578.deployed();

    vpm = await deployLegacyManager(bap578);

    // This fixture declares (bool, bytes) independently of ILogicModuleForwardable.
    const Logic = await ethers.getContractFactory('MockTupleReturningLogic');
    logic = await Logic.deploy(vpm.address);
    await logic.deployed();
    await bap578.mint(TOKEN_ID, owner.address, logic.address);
    await vpm.createVault(TOKEN_ID, VAULT_ID, '');
    await vpm.grantPermission(TOKEN_ID, VAULT_ID, operator.address, 2, 0, '');
  });

  it('preserves a successful action result and forwards the original inputs', async function () {
    const payload = ethers.utils.defaultAbiCoder.encode(['uint256', 'uint256'], [123, 456]);
    const [success, result] = await vpm
      .connect(operator)
      .callStatic.forwardHandleAction(TOKEN_ID, VAULT_ID, 'check_balance', payload);
    expect(success).to.equal(true);
    expect(result).to.equal(payload);

    await expect(
      vpm.connect(operator).forwardHandleAction(TOKEN_ID, VAULT_ID, 'check_balance', payload),
    )
      .to.emit(vpm, 'ActionForwarded')
      .withArgs(TOKEN_ID, ethers.utils.id(VAULT_ID), operator.address, 'check_balance');
    expect(await logic.lastTokenId()).to.equal(TOKEN_ID);
    expect(await logic.lastAction()).to.equal('check_balance');
    expect(await logic.lastData()).to.equal(payload);
    expect(await logic.callCount()).to.equal(1);
  });

  it('preserves a false success flag and its nonempty failure details without reverting', async function () {
    const payload = ethers.utils.defaultAbiCoder.encode(['string'], ['Action declined']);
    const [success, result] = await vpm
      .connect(operator)
      .callStatic.forwardHandleAction(TOKEN_ID, VAULT_ID, 'reject', payload);
    expect(success).to.equal(false);
    expect(result).to.equal(payload);

    await vpm.connect(operator).forwardHandleAction(TOKEN_ID, VAULT_ID, 'reject', payload);
    expect(await logic.callCount()).to.equal(1);
    expect(await logic.lastData()).to.equal(payload);
  });

  it('preserves an empty result alongside the success flag', async function () {
    const [success, result] = await vpm
      .connect(operator)
      .callStatic.forwardHandleAction(TOKEN_ID, VAULT_ID, 'check_balance', '0x');
    expect(success).to.equal(true);
    expect(result).to.equal('0x');
  });

  it('preserves a large result without truncating or misdecoding its ABI offset', async function () {
    const payload = ethers.utils.hexlify(Array.from({ length: 513 }, (_, i) => i % 256));
    const [success, result] = await vpm
      .connect(operator)
      .callStatic.forwardHandleAction(TOKEN_ID, VAULT_ID, 'get_campaign_status', payload);
    expect(success).to.equal(true);
    expect(ethers.utils.hexDataLength(result)).to.equal(513);
    expect(result).to.equal(payload);
  });

  it('bubbles a stock-shaped logic revert without recording a forwarded action', async function () {
    await expect(
      vpm.connect(operator).forwardHandleAction(TOKEN_ID, VAULT_ID, 'revert', '0x'),
    ).to.be.revertedWith('logic: action reverted');
    expect(await logic.callCount()).to.equal(0);
  });

  it('requires fresh owner consent before routing a delegate to a replacement module', async function () {
    await vpm.connect(operator).forwardHandleAction(TOKEN_ID, VAULT_ID, 'check_balance', '0x');
    const Logic = await ethers.getContractFactory('MockTupleReturningLogic');
    const replacement = await Logic.deploy(vpm.address);
    await replacement.deployed();
    await bap578.setLogic(TOKEN_ID, replacement.address);

    expect(await vpm.canForward(TOKEN_ID, VAULT_ID, operator.address)).to.equal(false);
    await expect(
      vpm.connect(operator).forwardHandleAction(TOKEN_ID, VAULT_ID, 'check_balance', '0x'),
    ).to.be.revertedWith('VPM: caller lacks WRITE');
    expect(await replacement.callCount()).to.equal(0);
    await vpm.grantPermission(TOKEN_ID, VAULT_ID, operator.address, 2, 0, 'new module consent');
    await vpm.connect(operator).forwardHandleAction(TOKEN_ID, VAULT_ID, 'check_balance', '0x');
    expect(await logic.callCount()).to.equal(1);
    expect(await replacement.callCount()).to.equal(1);
    expect(await replacement.lastTokenId()).to.equal(TOKEN_ID);
  });
});
