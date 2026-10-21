const { expect } = require('chai');
const { ethers, upgrades } = require('hardhat');

describe('AgentPermissionTimelock governance', function () {
  const DELAY = 172800;
  const ZERO = ethers.constants.HashZero;
  let owner, outsider, proposer, timelock, target, serial;

  async function deploy(name, ...args) {
    const instance = await (await ethers.getContractFactory(name)).deploy(...args);
    await instance.deployed();
    return instance;
  }

  function salt() {
    return ethers.utils.id(`governance-operation-${serial++}`);
  }

  async function relay(destination, data, council = proposer) {
    await council.connect(owner).approve(destination, data);
    await council.connect(outsider).approve(destination, data);
    return council.execute(destination, data);
  }

  async function queue(
    destination,
    data,
    delay = DELAY,
    predecessor = ZERO,
    operationSalt = salt(),
  ) {
    const encoded = timelock.interface.encodeFunctionData('schedule', [
      destination,
      0,
      data,
      predecessor,
      operationSalt,
      delay,
    ]);
    await relay(timelock.address, encoded);
    return { destination, data, predecessor, operationSalt };
  }

  async function execute(operation, signer = outsider) {
    return timelock
      .connect(signer)
      .execute(
        operation.destination,
        0,
        operation.data,
        operation.predecessor,
        operation.operationSalt,
      );
  }

  async function advance(seconds = DELAY) {
    await ethers.provider.send('evm_increaseTime', [seconds]);
    await ethers.provider.send('evm_mine');
  }

  function setValue(value) {
    return target.interface.encodeFunctionData('setValue', [value]);
  }

  beforeEach(async function () {
    [owner, outsider] = await ethers.getSigners();
    serial = 0;
    proposer = await deploy('VPMTestCouncil', [owner.address, outsider.address], 2);
    timelock = await deploy('AgentPermissionTimelock', DELAY, proposer.address);
    target = await deploy('APMGovernanceTarget', timelock.address);
  });

  it('pins the 48-hour floor, contract proposer, self administration, and open execution', async function () {
    expect(await timelock.MINIMUM_DELAY()).to.equal(DELAY);
    expect(await timelock.getMinDelay()).to.equal(DELAY);
    expect(await timelock.governanceType()).to.equal(
      ethers.utils.id('BAP578.AgentPermissionTimelock.v1'),
    );
    const admin = await timelock.TIMELOCK_ADMIN_ROLE();
    expect(await timelock.hasRole(admin, timelock.address)).to.equal(true);
    expect(await timelock.hasRole(admin, owner.address)).to.equal(false);
    expect(await timelock.hasRole(admin, proposer.address)).to.equal(false);
    expect(await timelock.hasRole(await timelock.PROPOSER_ROLE(), proposer.address)).to.equal(true);
    expect(await timelock.hasRole(await timelock.CANCELLER_ROLE(), proposer.address)).to.equal(
      true,
    );
    expect(
      await timelock.hasRole(await timelock.EXECUTOR_ROLE(), ethers.constants.AddressZero),
    ).to.equal(true);
  });

  it('rejects a short initial delay and an EOA or absent proposer', async function () {
    const factory = await ethers.getContractFactory('AgentPermissionTimelock');
    await expect(factory.deploy(DELAY - 1, proposer.address)).to.be.revertedWith(
      'APM governance: delay below floor',
    );
    await expect(factory.deploy(DELAY, owner.address)).to.be.revertedWith(
      'APM governance: proposer must be contract',
    );
    await expect(factory.deploy(DELAY, ethers.constants.AddressZero)).to.be.revertedWith(
      'APM governance: proposer must be contract',
    );
  });

  it('rejects threshold-one, threshold-too-large, zero-owner, and duplicate-owner profiles', async function () {
    const factory = await ethers.getContractFactory('AgentPermissionTimelock');
    for (const [owners, threshold, reason] of [
      [[owner.address, outsider.address], 1, 'invalid council threshold'],
      [[owner.address, outsider.address], 3, 'invalid council threshold'],
      [[owner.address, ethers.constants.AddressZero], 2, 'zero council owner'],
      [[owner.address, owner.address], 2, 'duplicate council owner'],
    ]) {
      const invalid = await deploy('APMInvalidCouncil', owners, threshold);
      await expect(factory.deploy(DELAY, invalid.address)).to.be.revertedWith(
        `APM governance: ${reason}`,
      );
    }
  });

  it('requires two distinct approvals for each proposal, without approval replay', async function () {
    const payload = timelock.interface.encodeFunctionData('schedule', [
      target.address,
      0,
      setValue(5),
      ZERO,
      salt(),
      DELAY,
    ]);
    await expect(proposer.execute(timelock.address, payload)).to.be.revertedWith(
      'test council: insufficient approvals',
    );
    await proposer.connect(owner).approve(timelock.address, payload);
    await proposer.connect(owner).approve(timelock.address, payload);
    await expect(proposer.execute(timelock.address, payload)).to.be.revertedWith(
      'test council: insufficient approvals',
    );
    await proposer.connect(outsider).approve(timelock.address, payload);
    await proposer.execute(timelock.address, payload);
    await expect(proposer.execute(timelock.address, payload)).to.be.revertedWith(
      'test council: insufficient approvals',
    );
  });

  it('revalidates a weakened council profile for both single and batch scheduling', async function () {
    await proposer.setThreshold(1);
    const single = timelock.interface.encodeFunctionData('schedule', [
      target.address,
      0,
      setValue(5),
      ZERO,
      salt(),
      DELAY,
    ]);
    const batch = timelock.interface.encodeFunctionData('scheduleBatch', [
      [target.address],
      [0],
      [setValue(6)],
      ZERO,
      salt(),
      DELAY,
    ]);
    await expect(relay(timelock.address, single)).to.be.revertedWith(
      'APM governance: invalid council threshold',
    );
    await expect(relay(timelock.address, batch)).to.be.revertedWith(
      'APM governance: invalid council threshold',
    );
  });

  it('rejects direct proposer, executor, role-admin, target, and delay-update bypasses', async function () {
    await expect(timelock.schedule(target.address, 0, setValue(1), ZERO, salt(), DELAY)).to.be
      .reverted;
    await expect(timelock.execute(target.address, 0, setValue(1), ZERO, salt())).to.be.revertedWith(
      'TimelockController: operation is not ready',
    );
    await expect(timelock.grantRole(await timelock.PROPOSER_ROLE(), outsider.address)).to.be
      .reverted;
    await expect(timelock.updateDelay(DELAY * 2)).to.be.revertedWith(
      'TimelockController: caller must be timelock',
    );
    await expect(target.setValue(1)).to.be.revertedWith('test target: governance only');
    const direct = timelock.interface.encodeFunctionData('grantRole', [
      await timelock.TIMELOCK_ADMIN_ROLE(),
      proposer.address,
    ]);
    await expect(relay(timelock.address, direct)).to.be.reverted;
  });

  it('does not let the proposer schedule below the floor', async function () {
    await expect(queue(target.address, setValue(1), DELAY - 1)).to.be.revertedWith(
      'TimelockController: insufficient delay',
    );
  });

  it('lets anyone execute only after the full delay and rejects replay', async function () {
    const op = await queue(target.address, setValue(7));
    await expect(execute(op)).to.be.revertedWith('TimelockController: operation is not ready');
    await advance(DELAY);
    await execute(op);
    expect(await target.value()).to.equal(7);
    await expect(execute(op)).to.be.revertedWith('TimelockController: operation is not ready');
  });

  it('enforces the floor even on a delayed self-update', async function () {
    const op = await queue(
      timelock.address,
      timelock.interface.encodeFunctionData('updateDelay', [DELAY - 1]),
    );
    await advance();
    await expect(execute(op)).to.be.revertedWith(
      'TimelockController: underlying transaction reverted',
    );
    expect(await timelock.getMinDelay()).to.equal(DELAY);
  });

  it('delays raising and lowering the delay and schedules against the updated value', async function () {
    const raised = DELAY * 2;
    const raise = await queue(
      timelock.address,
      timelock.interface.encodeFunctionData('updateDelay', [raised]),
    );
    await expect(execute(raise)).to.be.reverted;
    await advance();
    await execute(raise);
    expect(await timelock.getMinDelay()).to.equal(raised);
    await expect(queue(target.address, setValue(2), DELAY)).to.be.revertedWith(
      'TimelockController: insufficient delay',
    );
    const lower = await queue(
      timelock.address,
      timelock.interface.encodeFunctionData('updateDelay', [DELAY]),
      raised,
    );
    await advance(DELAY);
    await expect(execute(lower)).to.be.reverted;
    await advance(DELAY);
    await execute(lower);
    expect(await timelock.getMinDelay()).to.equal(DELAY);
  });

  it('cannot appoint an external role admin even through delayed governance', async function () {
    const op = await queue(
      timelock.address,
      timelock.interface.encodeFunctionData('grantRole', [
        await timelock.TIMELOCK_ADMIN_ROLE(),
        outsider.address,
      ]),
    );
    await advance();
    await expect(execute(op)).to.be.revertedWith(
      'TimelockController: underlying transaction reverted',
    );
    expect(await timelock.hasRole(await timelock.TIMELOCK_ADMIN_ROLE(), outsider.address)).to.equal(
      false,
    );
  });

  it('cannot revoke its required self-admin role through delayed governance', async function () {
    const op = await queue(
      timelock.address,
      timelock.interface.encodeFunctionData('revokeRole', [
        await timelock.TIMELOCK_ADMIN_ROLE(),
        timelock.address,
      ]),
    );
    await advance();
    await expect(execute(op)).to.be.revertedWith(
      'TimelockController: underlying transaction reverted',
    );
    expect(await timelock.hasRole(await timelock.TIMELOCK_ADMIN_ROLE(), timelock.address)).to.equal(
      true,
    );
  });

  it('does not permit an unused DEFAULT_ADMIN_ROLE through delayed governance', async function () {
    const op = await queue(
      timelock.address,
      timelock.interface.encodeFunctionData('grantRole', [ZERO, outsider.address]),
    );
    await advance();
    await expect(execute(op)).to.be.revertedWith(
      'TimelockController: underlying transaction reverted',
    );
    expect(await timelock.hasRole(ZERO, outsider.address)).to.equal(false);
  });

  it('allows delayed proposer changes without granting role-administration power', async function () {
    const role = await timelock.PROPOSER_ROLE();
    const replacement = await deploy('VPMTestCouncil', [owner.address, outsider.address], 2);
    const op = await queue(
      timelock.address,
      timelock.interface.encodeFunctionData('grantRole', [role, replacement.address]),
    );
    await advance();
    await execute(op);
    expect(await timelock.hasRole(role, replacement.address)).to.equal(true);
    await relay(
      timelock.address,
      timelock.interface.encodeFunctionData('schedule', [
        target.address,
        0,
        setValue(9),
        ZERO,
        salt(),
        DELAY,
      ]),
      replacement,
    );
    await expect(
      relay(
        timelock.address,
        timelock.interface.encodeFunctionData('grantRole', [role, owner.address]),
        replacement,
      ),
    ).to.be.reverted;
    await expect(timelock.connect(outsider).execute(target.address, 0, setValue(9), ZERO, ZERO)).to
      .be.reverted;
  });

  it('cannot replace contract-only proposers with an EOA through delayed role changes', async function () {
    const op = await queue(
      timelock.address,
      timelock.interface.encodeFunctionData('grantRole', [
        await timelock.PROPOSER_ROLE(),
        outsider.address,
      ]),
    );
    await advance();
    await expect(execute(op)).to.be.revertedWith(
      'TimelockController: underlying transaction reverted',
    );
    expect(await timelock.hasRole(await timelock.PROPOSER_ROLE(), outsider.address)).to.equal(
      false,
    );
  });

  it('keeps batch scheduling subject to the same delay and atomic execution', async function () {
    const batchSalt = salt();
    const targets = [target.address, target.address];
    const values = [0, 0];
    const payloads = [setValue(10), setValue(11)];
    const encode = (delay) =>
      timelock.interface.encodeFunctionData('scheduleBatch', [
        targets,
        values,
        payloads,
        ZERO,
        batchSalt,
        delay,
      ]);
    await expect(relay(timelock.address, encode(DELAY - 1))).to.be.revertedWith(
      'TimelockController: insufficient delay',
    );
    await relay(timelock.address, encode(DELAY));
    await expect(
      timelock.connect(outsider).executeBatch(targets, values, payloads, ZERO, batchSalt),
    ).to.be.reverted;
    await advance();
    await timelock.connect(outsider).executeBatch(targets, values, payloads, ZERO, batchSalt);
    expect(await target.value()).to.equal(11);
  });

  it('requires a completed predecessor and lets the proposer cancel pending operations', async function () {
    const first = await queue(target.address, setValue(1));
    const id = await timelock.hashOperation(
      first.destination,
      0,
      first.data,
      ZERO,
      first.operationSalt,
    );
    const second = await queue(target.address, setValue(2), DELAY, id);
    await advance();
    await expect(execute(second)).to.be.revertedWith('TimelockController: missing dependency');
    await execute(first);
    await execute(second);
    expect(await target.value()).to.equal(2);
    const third = await queue(target.address, setValue(3));
    const thirdId = await timelock.hashOperation(
      third.destination,
      0,
      third.data,
      ZERO,
      third.operationSalt,
    );
    await expect(timelock.cancel(thirdId)).to.be.reverted;
    await relay(timelock.address, timelock.interface.encodeFunctionData('cancel', [thirdId]));
    await advance();
    await expect(execute(third)).to.be.revertedWith('TimelockController: operation is not ready');
  });

  it('has one exact runtime code hash independent of constructor state', async function () {
    const secondProposer = await deploy('VPMTestCouncil', [owner.address, outsider.address], 2);
    const second = await deploy('AgentPermissionTimelock', DELAY * 2, secondProposer.address);
    const firstCode = await ethers.provider.getCode(timelock.address);
    const secondCode = await ethers.provider.getCode(second.address);
    expect(ethers.utils.keccak256(firstCode)).to.equal(ethers.utils.keccak256(secondCode));
  });

  it('registers only timelocks created by that factory, after successful construction', async function () {
    const factory = await deploy('AgentPermissionTimelockFactory');
    expect(await factory.isGovernance(timelock.address)).to.equal(false);
    const receipt = await (await factory.createTimelock(DELAY, proposer.address)).wait();
    const created = receipt.events.find((event) => event.event === 'TimelockCreated').args;
    expect(created.proposerCouncil).to.equal(proposer.address);
    expect(created.delay).to.equal(DELAY);
    expect(await factory.isGovernance(created.governance)).to.equal(true);
    expect(await ethers.provider.getCode(created.governance)).not.to.equal('0x');
    const other = await deploy('AgentPermissionTimelockFactory');
    expect(await other.isGovernance(created.governance)).to.equal(false);
    await expect(factory.createTimelock(DELAY - 1, proposer.address)).to.be.revertedWith(
      'APM governance: delay below floor',
    );
  });

  describe('execution-manager integration', function () {
    let manager, guardian, collection, resolver, logic;

    beforeEach(async function () {
      [, , guardian] = await ethers.getSigners();
      collection = await deploy('MockBAP578ForVPM');
      logic = await deploy('APMGovernanceCallbackLogic');
      await collection.mint(1, owner.address, logic.address);
      resolver = await deploy('LegacyBAP578StateResolver', collection.address);
      const managerFactory = await ethers.getContractFactory(
        'AgentExecutionPermissionManagerReferenceV1',
      );
      const implementation = managerFactory.attach(
        await upgrades.deployImplementation(managerFactory, { kind: 'uups' }),
      );
      const governanceFactory = await ethers.getContractAt(
        'AgentPermissionTimelockFactory',
        await implementation.governanceFactory(),
      );
      const receipt = await (
        await governanceFactory.createTimelock(DELAY, proposer.address)
      ).wait();
      timelock = await ethers.getContractAt(
        'AgentPermissionTimelock',
        receipt.events.find((event) => event.event === 'TimelockCreated').args.governance,
      );
      manager = await upgrades.deployProxy(
        managerFactory,
        [resolver.address, timelock.address, guardian.address],
        { initializer: 'initializeLegacyCompatibility', kind: 'uups' },
      );
      await manager.deployed();
      await manager.createVault(1, 'default', 'governance fixture');
    });

    it('pins factory-created timelock as owner and rejects a metadata-spoofing governor', async function () {
      expect(await manager.owner()).to.equal(timelock.address);
      expect(await manager.governance()).to.equal(timelock.address);
      expect(await manager.governanceMinDelay()).to.equal(DELAY);
      const fake = await deploy('APMFakeGovernance');
      await expect(
        upgrades.deployProxy(
          await ethers.getContractFactory('AgentExecutionPermissionManagerReferenceV1'),
          [resolver.address, fake.address, guardian.address],
          { initializer: 'initializeLegacyCompatibility', kind: 'uups' },
        ),
      ).to.be.revertedWith('VPM: unregistered governance');
    });

    it('rejects valid standalone and other-factory timelocks with the same council and delay', async function () {
      const foreignFactory = await deploy('AgentPermissionTimelockFactory');
      const foreignReceipt = await (
        await foreignFactory.createTimelock(DELAY, proposer.address)
      ).wait();
      const foreign = foreignReceipt.events.find((event) => event.event === 'TimelockCreated').args
        .governance;
      const standalone = await deploy('AgentPermissionTimelock', DELAY, proposer.address);
      for (const governance of [standalone.address, foreign]) {
        await expect(
          upgrades.deployProxy(
            await ethers.getContractFactory('AgentExecutionPermissionManagerReferenceV1'),
            [resolver.address, governance, guardian.address],
            { initializer: 'initializeLegacyCompatibility', kind: 'uups' },
          ),
        ).to.be.revertedWith('VPM: unregistered governance');
      }
    });

    it('gives the guardian only immediate pause, with delayed unpause and guardian changes', async function () {
      await manager.connect(guardian).pause();
      expect(await manager.paused()).to.equal(true);
      await expect(manager.connect(guardian).unpause()).to.be.reverted;
      await expect(manager.connect(guardian).setPauseGuardian(owner.address)).to.be.reverted;
      await expect(manager.unpause()).to.be.reverted;
      const op = await queue(manager.address, manager.interface.encodeFunctionData('unpause'));
      await expect(execute(op)).to.be.reverted;
      await advance();
      await execute(op);
      expect(await manager.paused()).to.equal(false);
      const changed = await queue(
        manager.address,
        manager.interface.encodeFunctionData('setPauseGuardian', [outsider.address]),
      );
      await advance();
      await execute(changed);
      expect(await manager.pauseGuardian()).to.equal(outsider.address);
      await expect(manager.connect(guardian).pause()).to.be.reverted;
      await manager.connect(outsider).pause();
    });

    it('cannot move ownership out of the timelock or renounce it, even after delay', async function () {
      for (const data of [
        manager.interface.encodeFunctionData('transferOwnership', [owner.address]),
        manager.interface.encodeFunctionData('renounceOwnership'),
      ]) {
        const op = await queue(manager.address, data);
        await advance();
        await expect(execute(op)).to.be.reverted;
        expect(await manager.owner()).to.equal(timelock.address);
      }
    });

    for (const method of ['upgradeTo', 'upgradeToAndCall']) {
      it(`requires delayed multisig ${method} and blocks its ready operation during dispatch`, async function () {
        const initialFactory = await manager.governanceFactory();
        const implementation = await deploy('VPMConformanceUpgrade');
        const args =
          method === 'upgradeTo'
            ? [implementation.address]
            : [
                implementation.address,
                implementation.interface.encodeFunctionData('conformanceVersion'),
              ];
        await expect(manager[method](...args)).to.be.reverted;
        const data = manager.interface.encodeFunctionData(method, args);
        await expect(relay(manager.address, data)).to.be.reverted;
        const op = await queue(manager.address, data);
        await expect(execute(op)).to.be.reverted;
        await advance();
        const id = await timelock.hashOperation(manager.address, 0, data, ZERO, op.operationSalt);
        await logic.setCallback(
          timelock.address,
          timelock.interface.encodeFunctionData('execute', [
            manager.address,
            0,
            data,
            ZERO,
            op.operationSalt,
          ]),
        );
        await manager.forwardHandleAction(1, 'default', 'upgrade-during-dispatch', '0x');
        expect(await logic.callbackSucceeded()).to.equal(false);
        expect(await timelock.isOperationReady(id)).to.equal(true);
        await execute(op);
        expect(await upgrades.erc1967.getImplementationAddress(manager.address)).to.equal(
          implementation.address,
        );
        expect(await timelock.isOperationDone(id)).to.equal(true);
        expect(await manager.vaultExists(1, 'default')).to.equal(true);
        expect(await implementation.attach(manager.address).conformanceVersion()).to.equal(2);
        expect(await manager.governanceFactory()).to.equal(initialFactory);
        const pinnedFactory = await ethers.getContractAt(
          'AgentPermissionTimelockFactory',
          initialFactory,
        );
        expect(await pinnedFactory.isGovernance(await manager.owner())).to.equal(true);
      });
    }
  });
});
