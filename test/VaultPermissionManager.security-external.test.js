const { expect } = require('chai');
const { ethers } = require('hardhat');
const { deployExecutionManager, deployLegacyManager } = require('./helpers/execution-v1');

describe('VaultPermissionManager adversarial external calls', function () {
  const TOKEN = 7;
  const VAULT = 'default';
  let owner, operator, receiver, collection, manager;

  async function deploy(name, ...args) {
    const contract = await (await ethers.getContractFactory(name)).deploy(...args);
    await contract.deployed();
    return contract;
  }

  async function cleared() {
    const context = await manager.getForwardingContext();
    expect(context.tokenId).to.equal(0);
    expect(context.vaultIdHash).to.equal(ethers.constants.HashZero);
    expect(context.accessor).to.equal(ethers.constants.AddressZero);
    expect(context.logicAddress).to.equal(ethers.constants.AddressZero);
    expect(context.ownershipNonce).to.equal(0);
    expect(context.executionRevision).to.equal(0);
  }

  async function forward(action = 'probe', data = '0x', overrides = {}) {
    return manager.connect(operator).forwardHandleAction(TOKEN, VAULT, action, data, overrides);
  }

  beforeEach(async function () {
    [owner, operator, receiver] = await ethers.getSigners();
    collection = await deploy('MockBAP578ForVPM');
    manager = await deployLegacyManager(collection);
    await collection.mint(TOKEN, owner.address, ethers.constants.AddressZero);
    await manager.createVault(TOKEN, VAULT, 'external-call review');
    await manager.grantPermission(TOKEN, VAULT, operator.address, 2, 0, '');
  });

  async function boundaryLogic() {
    const callback = await deploy('VPMContextCallbackProbe');
    const policy = await deploy(
      'VPMContextOperatorPolicy',
      manager.address,
      operator.address,
      ethers.utils.id(VAULT),
    );
    const logic = await deploy(
      'VPMExternalBoundaryLogic',
      manager.address,
      callback.address,
      policy.address,
    );
    await collection.setLogic(TOKEN, logic.address);
    await manager.grantPermission(TOKEN, VAULT, operator.address, 2, 0, 'module consent');
    return { logic, callback, policy };
  }

  it('does not turn readable live context into callback authority', async function () {
    const { logic, callback } = await boundaryLogic();
    // Even an independently authorized callback cannot start nested forwarding.
    await manager.grantPermission(TOKEN, VAULT, callback.address, 2, 0, 'callback');
    await forward('callback');
    expect(await callback.observedLiveContext()).to.equal(true);
    expect(await callback.directActionAccepted()).to.equal(false);
    expect(await callback.nestedForwardAccepted()).to.equal(false);
    expect(await callback.policyAccepted()).to.equal(false);
    expect(await logic.callCount()).to.equal(1);
    expect(await logic.lastAccessor()).to.equal(operator.address);
    await cleared();
  });

  it('rejects a lookalike forwarder even when it supplies matching context', async function () {
    const { logic } = await boundaryLogic();
    const spoof = await deploy('VPMContextSpoofingForwarder');
    expect(await spoof.callStatic.impersonate(logic.address, TOKEN, operator.address)).to.equal(
      false,
    );
    await spoof.impersonate(logic.address, TOKEN, operator.address);
    expect(await logic.callCount()).to.equal(0);
    await cleared();
  });

  it('authenticates the bound proxy address rather than its implementation address', async function () {
    const { logic } = await boundaryLogic();
    const proxy = await deploy('VPMBoundaryLogicProxy', logic.address);
    await collection.setLogic(TOKEN, proxy.address);
    await manager.grantPermission(TOKEN, VAULT, operator.address, 2, 0, 'proxy consent');
    await forward();
    const proxiedLogic = logic.attach(proxy.address);
    expect(await proxiedLogic.callCount()).to.equal(1);
    expect(await proxiedLogic.lastAccessor()).to.equal(operator.address);
    expect(await proxiedLogic.lastContextLogic()).to.equal(proxy.address);
    expect(await logic.callCount()).to.equal(0);
    await cleared();
  });

  it('enforces the documented entry snapshot when the module separately changes NFT ownership', async function () {
    const { logic } = await boundaryLogic();
    const initialEpoch = await manager.permissionEpoch(TOKEN);
    const payload = ethers.utils.defaultAbiCoder.encode(
      ['address', 'address'],
      [collection.address, receiver.address],
    );
    await forward('change-owner', payload);
    expect(await collection.ownerOf(TOKEN)).to.equal(receiver.address);
    expect(await logic.callCount()).to.equal(1);
    expect(await manager.permissionEpoch(TOKEN)).to.equal(initialEpoch);
    expect(await manager.canForward(TOKEN, VAULT, operator.address)).to.equal(false);
    expect(await manager.canForward(TOKEN, VAULT, receiver.address)).to.equal(true);
    await expect(forward()).to.be.revertedWith('VPM: caller lacks WRITE');
    await manager.syncAgentState(TOKEN);
    expect(await manager.permissionEpoch(TOKEN)).to.equal(initialEpoch.add(1));
    await cleared();
  });

  it('documents that decodable overlapping return offsets are accepted without a strict ABI validator', async function () {
    const logic = await deploy('VPMHostileReturnLogic');
    await collection.setLogic(TOKEN, logic.address);
    await manager.grantPermission(TOKEN, VAULT, operator.address, 2, 0, 'module consent');
    await logic.configure(1);
    const [success, result] = await manager
      .connect(operator)
      .callStatic.forwardHandleAction(TOKEN, VAULT, 'probe', '0x');
    expect(success).to.equal(true);
    expect(result).to.equal('0x00');
    await expect(forward())
      .to.emit(manager, 'ActionResult')
      .withArgs(
        TOKEN,
        ethers.utils.id(VAULT),
        operator.address,
        logic.address,
        true,
        ethers.utils.keccak256('0x00'),
      );
    expect(await logic.callCount()).to.equal(1);
    await cleared();
  });

  it('documents that trailing return words are ignored by Solidity ABI decoding', async function () {
    const logic = await deploy('VPMHostileReturnLogic');
    await collection.setLogic(TOKEN, logic.address);
    await manager.grantPermission(TOKEN, VAULT, operator.address, 2, 0, 'module consent');
    await logic.configure(2);
    const [success, result] = await manager
      .connect(operator)
      .callStatic.forwardHandleAction(TOKEN, VAULT, 'probe', '0x');
    expect(success).to.equal(true);
    expect(result).to.equal('0x');
    await forward();
    expect(await logic.callCount()).to.equal(1);
    await cleared();
  });

  it('rejects a state-writing resolver through STATICCALL despite matching return selectors', async function () {
    const logic = await deploy('VPMHostileReturnLogic');
    const resolver = await deploy(
      'VPMStateWritingResolver',
      collection.address,
      owner.address,
      logic.address,
    );
    const guarded = await deployExecutionManager(resolver);
    await expect(guarded.createVault(TOKEN, VAULT, '')).to.be.reverted;
    await expect(guarded.syncAgentState(TOKEN)).to.be.reverted;
    expect(await resolver.writes()).to.equal(0);
    expect(await guarded.vaultExists(TOKEN, VAULT)).to.equal(false);
    expect(await guarded.permissionEpoch(TOKEN)).to.equal(0);
    await resolver.getAgentState(TOKEN);
    expect(await resolver.writes()).to.equal(1);
  });

  for (const [mode, kind] of [
    [3, 'return'],
    [4, 'revert'],
  ]) {
    it(`rolls back atomically when oversized ${kind} data exhausts the transaction gas`, async function () {
      const logic = await deploy('VPMHostileReturnLogic');
      await collection.setLogic(TOKEN, logic.address);
      await manager.grantPermission(TOKEN, VAULT, operator.address, 2, 0, 'module consent');
      await logic.configure(mode);
      await expect(forward('probe', '0x', { gasLimit: 3000000 })).to.be.reverted;
      expect(await logic.callCount()).to.equal(0);
      await cleared();
      // There is no persistent manager lock: an ordinary later dispatch still works.
      await logic.configure(0);
      await forward();
      expect(await logic.callCount()).to.equal(1);
      await cleared();
    });
  }
});
