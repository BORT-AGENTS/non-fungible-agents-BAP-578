# BAP-578 Agent Execution Permissions V1

Status: proposal for review. This draft defines on-chain execution delegation and a reference implementation for **new deployments**. It changes the ABI, storage and behavior of the earlier PR reference. Existing proxies require a separate migration assessment; existing NFT collections are unchanged.

MUST, MUST NOT, SHOULD, SHOULD NOT and MAY express requirements. Requirements specific to the supplied reference are identified separately from the core interface.

## 1. Interface identity and compatibility

Published [BAP-578 section 4.6](https://github.com/bnb-chain/BEPs/blob/master/BAPs/BAP-578.md#46-vault-permission-system) defines `IVaultPermissionManager` for off-chain agent-data access. Its declaration is preserved in `contracts/extensions/IVaultPermissionManager.sol`; signature validation and an off-chain data service are not implemented here.

Execution delegation uses `IAgentExecutionPermissionsV1`, implemented by `AgentExecutionPermissionManagerReferenceV1`. It MUST NOT substitute for the published data-access interface.

| Interface | Permission enum, in wire order | Main entry points |
| --- | --- | --- |
| Published data access `IVaultPermissionManager` | READ_ONLY=0, WRITE=1, ADMIN=2, FULL_CONTROL=3 | `delegateAccess`, `revokeAccess`, `verifyAccess` |
| Execution V1 `IAgentExecutionPermissionsV1` | NONE=0, READ=1, WRITE=2, ADMIN=3 | `grantPermission`, `revokePermission`, `forwardHandleAction` |

Numeric enum values MUST NOT be cast or automatically translated between these APIs: the same number can have different meanings. Any bridge requires a separate authorization design, explicit mapping and tests. None is supplied, and the reference neither implements nor advertises the data-access selectors.

Execution V1 exposes `extensionId() == keccak256("bap578.agent-execution-permissions.v1")`, `extensionVersion() == 1`, and ERC-165 support for `IAgentExecutionPermissionsV1` and ERC-165 itself. It MUST NOT advertise the data-access interface ID unless it implements that API. Discovery reports declared behavior; it does not verify correctness. Reference initialization functions are excluded from the core interface ID, allowing constructor-based immutable implementations.

## 2. Meaning of permissions

A vault name identifies an access-control namespace. Names such as `social`, `trading` or `memory` do not create custody accounts, partition balances, encrypt data or restrict actions. Applications MUST NOT advertise these properties unless an enforced policy provides them.

WRITE authorizes the complete `handleAction` surface of the consented execution module/version. ADMIN includes WRITE and READ, with bounded child delegation as defined in section 7. READ is an authorization signal for applications that enforce it. Public blockchain data remains public; this extension supplies neither confidential-data access nor the published off-chain data API.

Applications MUST enforce any advertised budget, recipient, asset, outbound-call, credential or action restrictions on the operations actually executed. The manager controls its own forwarding path; independent direct-call and custody authorizations remain in force. The extension itself grants no ERC721 transfer, approval, listing or logic-update power. Any such powers held separately by a module remain part of the disclosed trust boundary.

## 3. Protection profiles and explicit initialization

`protectionProfile()` returns STRICT=0 or LEGACY_COMPATIBILITY=1. Deployments MUST publish it with `ownershipNonceSupported()` and `executionRevisionSupported()`.

| Reference initializer | Required behavior |
| --- | --- |
| `initialize(resolver, governance, guardian)` | STRICT. Both authoritative counter capabilities MUST be true. Otherwise initialization reverts, with no fallback. |
| `initializeLegacyCompatibility(resolver, governance, guardian)` | Explicit opt-in to weaker guarantees. Each supported counter is still checked. Unsupported counters MUST be zero. |

Both reference initializers are one-time and MUST run atomically with proxy creation. The implementation locks its own initialization. The resolver and its reported collection MUST have code. The resolver and selected capabilities are pinned, with no ordinary resolver/profile setter. The manager starts unpaused. Governance comes from the implementation's trusted factory (section 10); the initializer caller retains no upgrade authority.

STRICT requires collection and upgrade-controller behavior that satisfies both counter requirements below. Deployments MUST verify every relevant transfer and execution-upgrade path; a resolver flag, interface ID or wrapper is insufficient evidence. They MUST NOT label a compatibility deployment STRICT or claim complete transfer/version protection when a required counter is unavailable.

## 4. Resolvers and authoritative counters

`IAgentStateResolver` returns the following fixed tuple:

```solidity
struct AgentState {
    address owner;
    address logicAddress;
    bool active;
    uint256 ownershipNonce;
    uint256 executionRevision;
}
```

The resolver exposes `collection()`, `supportsOwnershipNonce()`, `supportsExecutionRevision()` and `getAgentState(tokenId)`. It is a trusted state authority. Unknown agents MUST revert or return a zero owner, which the manager rejects. Resolver reverts, decoding failures, unsupported nonzero counters and decreasing supported counters MUST fail closed. A changed owner without a greater supported ownership nonce, or a changed logic address without a greater supported execution revision, MUST be rejected. Dishonest reporting can remain undetectable despite a declared capability.

An authoritative ownership nonce MUST advance on every ownership change, including changes within one transaction and token burn/recreation. It MUST NOT reset, decrease or reuse a prior value for a later token incarnation.

An authoritative execution revision MUST advance on every change to the selected execution identity/version, including module A to B to A and implementation changes behind the same proxy. It MUST NOT reset or reuse an older value. Every actual upgrade authority MUST participate. Revision advancement MUST precede entry into changed untrusted module code, and upgrade failure MUST roll it back atomically. A collection counter disconnected from an independently governed proxy cannot provide this guarantee. Neither an address comparison nor a proxy's own code hash identifies its implementation version.

The version boundary MUST be documented. A revision does not freeze external dependencies, oracles, balances, storage or application behavior. Dependencies and their governance remain separate trust assumptions.

The supplied resolvers are:

- `LegacyBAP578StateResolver`: canonical `ownerOf`, upstream `agentStates` tuple, agent activity and collection pause. Both counter capabilities are false.
- `CLAWNFAStateResolver`: canonical `ownerOf`, matching `getState` layout, Active status and collection pause. Both counter capabilities are false.
- `NonceTrackedStateResolver`: reads the actual collection ownership nonce and preserves its source's execution capability. It does not add execution-version protection.
- `AuthoritativeStateResolver`: reads `ownershipNonce(tokenId)` and `executionRevision(tokenId)` from the actual collection; its source supplies owner, module and lifecycle. It cannot supply missing counters or coordinate an independent upgrade path.

A mismatched collection ABI MUST use a matching resolver. Selector equality does not establish a compatible tuple layout. Collection and resolver upgrades can change reported truth and MUST be disclosed.

## 5. Execution binding, epochs and fresh consent

Each token has one committed `permissionEpoch`, shared across namespaces. The manager snapshots owner, module address and supported counters. Any current mismatch MUST immediately disable every old delegated tier, including ADMIN and its children, before state synchronization. The current NFT owner retains implicit authority when state resolution is valid.

`syncAgentState(tokenId)` is permissionless and commits the observation. A successfully committed change of owner, module address or supported counter MUST advance the epoch. Views and reverted calls never commit. `permissionEpoch()` returns monotonic stored state. `AgentEpochAdvanced` may contain equal previous/current owner addresses after an execution change or ownership round trip.

All delegated grants MUST bind to the consented execution state and MUST NOT follow a different module/version automatically. After a committed execution change, the owner must issue fresh root grants before ADMIN can create children. In a correctly implemented authoritative profile, returning to an earlier module/version MUST NOT revive old grants. This draft provides no option to inherit future upgrades automatically.

Only the current NFT owner may call `resetPermissions(tokenId)`. It commits current state and additionally advances the epoch, invalidating all delegated grants across namespaces. Namespaces and owner authority survive the reset, which remains available while paused.

### Explicit compatibility limits

Without an authoritative ownership counter, owner A to B to A can revive prior grants if no observation was committed while B owned the NFT. Without an authoritative execution revision, module A to B to A can do the same; an implementation upgrade behind an unchanged proxy can also be invisible. A successful intermediate sync or owner reset prevents old records from returning. Views and reverted attempts do not.

Applications MUST disclose these limits for each unsupported capability. An indexer cannot guarantee observation between atomic changes. Compatibility mode rejects a currently different owner/module, checks supported counters and invalidates old committed epochs. Existing collections can use this weaker mode without an upgrade.

## 6. Namespace and NFT-owner authority

Only the current NFT owner may create a namespace. Empty names MUST be rejected. Its key is `keccak256(bytes(vaultId))`, using exact bytes and case without Unicode normalization. Descriptions are public event metadata.

Namespaces survive ownership and execution changes. On an existing namespace the current owner has implicit ADMIN with no expiry and may forward without a self-grant. No implicit permission exists for a missing namespace. ERC721 approvals alone do not give ACL-owner authority.

Explicit grants to zero, the grantor or the current NFT owner MUST be rejected. NONE MUST use revocation. A new finite expiry MUST be strictly in the future; zero means no expiry. A grant remains valid through its exact expiry second.

## 7. Bounded ADMIN delegation and raw records

Only the NFT owner may issue or renew ADMIN. An ADMIN may grant READ or WRITE on the same token and namespace. It cannot grant ADMIN, renew itself or grant access beyond its own finite expiry. An ADMIN with a finite expiry cannot issue a permanent child.

Each child records its parent ADMIN and the root grant's generation. The parent must remain valid ADMIN in the same epoch and generation. Revoking, expiring, replacing, renewing or downgrading the parent invalidates its old children. Regranting the same address MUST NOT restore them. The generation counter survives deletion.

ADMIN may replace or revoke its own children and revoke itself. It cannot overwrite or revoke current-epoch owner-issued records, peer ADMIN grants or peer-issued children. The NFT owner may resolve any record conflict. Older-epoch records confer no authority.

`getGrant` returns raw storage: `level, expiry, epoch, parentAdmin, parentGeneration, generation, exists`. Deleted records may retain a nonzero generation counter; expired or invalidated records may still exist. Indexers MUST compute effective validity from current state and parent lineage. Parent or epoch invalidation need not emit individual child revocations.

## 8. Forwarding, readiness and context

The module ABI is:

```solidity
function handleAction(uint256 tokenId, string calldata action, bytes calldata data)
    external returns (bool success, bytes memory result);
```

The manager preserves the decoded Boolean and result bytes exactly, excluding original wire encoding and unused trailing data. Return types do not change the selector; a single-`bytes` decoder is incompatible.

`checkPermission` evaluates effective ACL authority, freshness, epoch, tier, expiry and parent validity. It can report authority while lifecycle or pause blocks execution. `canForward` also checks manager pause, agent/collection activity and callable logic. Resolver failures can revert. Neither guarantees that a later transaction or downstream policy will succeed. Forwarding MUST repeat these checks.

Checks apply at dispatch entry. The reference requires no post-call equality of owner, lifecycle or module state. A separately authorized downstream contract can change those systems during execution. Strong counters block stale subsequent dispatches but do not constrain an action already entered.

During the call, `getForwardingContext()` contains `tokenId, vaultIdHash, accessor, logicAddress, ownershipNonce, executionRevision`. The manager sets it before the external call and clears it before every normal return, including false. It is all zero outside dispatch, and reversion rolls it back. Context records entry state; it is not continuous authorization. Unsupported counters are zero.

A module MUST authenticate the configured manager as `msg.sender`, then verify its own destination and token before trusting context:

```solidity
require(msg.sender == trustedManager, "untrusted forwarder");
IAgentExecutionPermissionsV1.ForwardContext memory c =
    IAgentExecutionPermissionsV1(trustedManager).getForwardingContext();
require(c.logicAddress == address(this) && c.tokenId == tokenId, "wrong context");
// Validate c.accessor, c.vaultIdHash, action/data and actual outbound operations.
```

Public context does not authenticate a callback or fake forwarder. For a proxied module, the destination is the proxy address. An IPolicyGuard integration advertising per-operator rules MUST use the authenticated accessor rather than substitute the manager address. The policy MUST validate the operations actually executed.

Forwarding and custom permission/state/pause mutations MUST share a reentrancy guard. The reference also blocks both inherited UUPS upgrade paths during active dispatch, including callbacks that execute ready timelock operations.

## 9. Results, ABI failures and resources

`ActionForwarded` records dispatch. A normal return emits `ActionResult(tokenId, vaultIdHash, accessor, logicAddress, success, keccak256(result))`, hashing the decoded result bytes. Neither event alone establishes application success: false is preserved and can accompany persistent downstream changes.

A logic revert or decoder-rejected output MUST revert the transaction, rolling back state, context, synchronization and events. Revert details propagate when gas and memory permit. Solidity decoding accepts some noncanonical output, including overlapping offsets or unused trailing words; the reference adds no canonical-encoding check. See the [Solidity ABI specification](https://docs.soliditylang.org/en/v0.8.28/abi-spec.html#strict-encoding-mode).

The reference imposes no independent return-data or call-gas limit. A resolver or module can exhaust transaction resources. Rollback guarantees neither availability nor exact error details. Resource policies remain application-defined.

Other execution events are `VaultCreated`, `PermissionGranted`, `PermissionRevoked`, `AgentEpochAdvanced`, `PermissionsReset`, `ManagerPauseChanged` and `PauseGuardianChanged`. ABI field order and indexing are defined by `IAgentExecutionPermissionsV1`. Descriptions and action metadata are public.

## 10. Governance and emergency authority

Core implementations MAY be immutable or governed. They MUST expose the manager governance profile and publish the separate control/upgrade authorities of the manager, collection, resolver and module. One component's immutability says nothing about the others. Constructor-based implementations need not provide the reference initialization methods.

The reference uses governed UUPS. Its implementation constructor deploys an immutable, non-upgradeable `AgentPermissionTimelockFactory`. Initialization accepts only concrete `AgentPermissionTimelock` instances created and registered by that factory. The registry has no owner, arbitrary-registration setter, upgrade path or external-admin override. Governance authentication relies on this creation path.

Deployment proceeds by preparing the implementation and factory, creating the timelock through that factory, then atomically initializing the proxy with that governor. Other-factory timelocks and lookalikes are rejected. Ownership is pinned to the governor; inherited ownership transfer and renunciation cannot move authority to an immediate EOA. Delayed implementation replacement can still change these rules.

`AgentPermissionTimelock` is self-administered with a 48-hour minimum delay floor. Delay changes pass through the timelock and cannot lower that floor. External timelock/default admins are prohibited. Scheduling, batching, role changes, upgrades and trust-root changes provide no immediate admin route.

Proposer councils MUST have code and a Safe-compatible profile: a threshold of at least two, no more than the owner count, and at most 256 distinct nonzero owners. The reference checks this at deployment, proposer grants and scheduling. These getters do not prove signature enforcement. Deployment review MUST verify council code, signer policy, enabled modules, guards, fallback handlers, upgrade authority and alternate execution paths. The simplified test council MUST NOT be deployed as a production multisig.

Anyone may execute an approved operation after its delay. Knowing the target/payload permits neither early execution nor rescheduling. Emergency guardians may immediately `pause()` but cannot unpause, upgrade, replace the guardian or change permissions through governance authority. Only delayed governance may `unpause()` or `setPauseGuardian()`.

Manager pause blocks namespace creation, grants and forwarding. Revocation, owner reset and synchronization remain available. Collection inactivity/pause blocks forwarding without deleting grants; unpause can restore still-valid grants. Pause neither vetoes ready governance operations nor restarts their waiting period. Approved delayed upgrades remain executable.

Lost council keys or removal of all usable proposer/executor routes can prevent recovery. The timelock does not guarantee governance liveness, and an approved upgrade can intentionally replace authorization semantics. Deployments MUST disclose these trust and availability limits.

## 11. Deployment disclosure and compatibility boundary

A deployment MUST publish:

- Chain, collection, manager proxy/implementation, extension ID/version and resolver.
- STRICT or explicit compatibility profile, both counter capabilities and audited counter sources.
- Execution-version boundary and every participating upgrade controller.
- Governance, factory and council addresses, delay and guardian.
- Separate collection, resolver and module upgrade authorities.

Custom deployments MUST declare their governance mode rather than claim the reference's timelock properties.

Before use, verify bytecode, council configuration, authoritative counter paths, downstream trusted-manager settings and application policies. Capability flags do not establish these facts. This draft requires fresh deployment and explicit operator grants. Existing collections and permission managers are unchanged; a proxy migration requires its own storage-layout, ABI, governance and migration assessment.

## 12. Conformance and test map

| Area | Required evidence | Test family |
| --- | --- | --- |
| Interface separation | Correct independent enums/selectors, execution identity/version and ERC165, no data-access impersonation | `AgentExecutionPermissionsV1.test.js` |
| Strong profiles | No fallback; actual ownership and execution counters, module A-B-A, same-address proxy upgrade, all-tier invalidation and fresh owner grants | `AgentExecutionPermissionsV1.test.js` |
| Counter faults | Decreases, unsupported values, changed identity without counter advance, missing collection surfaces | Execution V1 and conformance tests |
| Governance | Council validation, delay floor, role/batch/predecessor/replay behavior, factory authentication, guardian separation, both UUPS paths and active-dispatch rejection | `AgentPermissionTimelock.test.js` |
| ACL rules | Owner authority, finite parents, generation non-resurrection, peer protection, reset, token/namespace isolation | Existing permission and conformance tests |
| Independent sequences | Deterministic mixed delegation/revocation/transfer/reset/expiry checks against a separate model | `VaultPermissionManager.security-sequences.test.js` |
| Real collection compatibility | Correct BAP/CLAW layouts and lifecycle, real ERC721 approvals/callbacks, disclosed weak history limits, nonce burn/remint | Profile and conformance tests |
| Dispatch boundary | Exact tuple values, true/false results, proxy/context authentication, reentry, static resolvers, decoder failures, accepted noncanonical output, resource rollback | ABI integration and external-call tests |

Historical test filenames refer to execution permissions, not an implementation of the published data-access API. Tests establish their specific assertions, not absence of vulnerabilities or BNB Chain acceptance. This draft has no independent audit certification. Independent review and a deployment-specific security assessment remain necessary before production endorsement.
