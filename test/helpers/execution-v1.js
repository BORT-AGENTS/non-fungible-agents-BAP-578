const { ethers, upgrades } = require('hardhat');

const MIN_DELAY = 48 * 60 * 60;

async function deployGovernance(options = {}) {
  const signers = await ethers.getSigners();
  const councilSigners = options.councilSigners || signers.slice(0, 2);
  const guardian = options.guardian || signers[0];
  const council = await (
    await ethers.getContractFactory('VPMTestCouncil')
  ).deploy(
    councilSigners.map((signer) => signer.address),
    2,
  );
  await council.deployed();
  let timelock;
  if (options.governanceFactory) {
    const governanceFactory =
      typeof options.governanceFactory === 'string'
        ? await ethers.getContractAt('AgentPermissionTimelockFactory', options.governanceFactory)
        : options.governanceFactory;
    const predicted = await governanceFactory.callStatic.createTimelock(MIN_DELAY, council.address);
    await (await governanceFactory.createTimelock(MIN_DELAY, council.address)).wait();
    timelock = await ethers.getContractAt('AgentPermissionTimelock', predicted);
  } else {
    // Standalone governors are useful in governor-unit tests. Manager fixtures
    // must create their governor through the implementation's registered factory.
    timelock = await (
      await ethers.getContractFactory('AgentPermissionTimelock')
    ).deploy(MIN_DELAY, council.address);
    await timelock.deployed();
  }
  return { timelock, council, councilSigners, guardian, operationCount: 0 };
}

async function deployExecutionManager(resolver, options = {}) {
  const factory =
    options.factory ||
    (await ethers.getContractFactory('AgentExecutionPermissionManagerReferenceV1'));
  const implementationAddress = await upgrades.deployImplementation(factory, { kind: 'uups' });
  const implementation = factory.attach(implementationAddress);
  const governance =
    options.governance ||
    (await deployGovernance({
      ...options,
      governanceFactory: await implementation.governanceFactory(),
    }));
  const guardian = options.guardian || governance.guardian;
  const manager = await upgrades.deployProxy(
    factory,
    [resolver.address || resolver, governance.timelock.address, guardian.address || guardian],
    {
      initializer: options.strict ? 'initialize' : 'initializeLegacyCompatibility',
      kind: 'uups',
      redeployImplementation: 'never',
    },
  );
  await manager.deployed();
  manager._testGovernance = governance;
  return manager;
}

async function deployLegacyManager(collection, options = {}) {
  const resolver = await (
    await ethers.getContractFactory('LegacyBAP578StateResolver')
  ).deploy(collection.address || collection);
  await resolver.deployed();
  return deployExecutionManager(resolver, options);
}

async function executeGovernanceCall(governance, target, data) {
  const targetAddress = target.address || target;
  const predecessor = ethers.constants.HashZero;
  const salt = ethers.utils.id(`execution-v1-test-${governance.operationCount++}`);
  const delay = await governance.timelock.getMinDelay();
  const schedule = governance.timelock.interface.encodeFunctionData('schedule', [
    targetAddress,
    0,
    data,
    predecessor,
    salt,
    delay,
  ]);
  for (const signer of governance.councilSigners.slice(0, 2)) {
    await governance.council.connect(signer).approve(governance.timelock.address, schedule);
  }
  await governance.council.execute(governance.timelock.address, schedule);
  await ethers.provider.send('evm_increaseTime', [delay.toNumber()]);
  await ethers.provider.send('evm_mine');
  return governance.timelock.execute(targetAddress, 0, data, predecessor, salt);
}

async function executeGovernance(manager, functionName, args = []) {
  return executeGovernanceCall(
    manager._testGovernance,
    manager,
    manager.interface.encodeFunctionData(functionName, args),
  );
}

module.exports = {
  MIN_DELAY,
  deployGovernance,
  deployExecutionManager,
  deployLegacyManager,
  executeGovernance,
  executeGovernanceCall,
};
