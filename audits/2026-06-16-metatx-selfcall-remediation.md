# Security Review & Remediation — Meta‑Transaction Self‑Call Privilege Escalation

**Subject:** Colony Network smart contracts (fork maintained by Deed3Labs)
**Component:** Meta‑transaction dispatch (`executeMetaTransaction`) over the `EtherRouter` / DSAuth proxy
**Branch reviewed / remediated:** `security/metatx-proxy-admin-guard` (off `develop`)
**Prepared for:** Deed3Labs — ClearHQ deployment (Base, Base Sepolia)
**Date:** 2026‑06‑16
**Classification of lead issue:** **CRITICAL** (CVSS 3.1 ≈ 9.3 — `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`)
**Status:** Remediated; full‑tree **compile + targeted regression test are green in CI** (GitHub Actions `security-check`). Full suite / Base Sepolia replay / independent audit still required — see §7.

---

## 1. Executive summary

On **2026‑05‑13** an attacker drained ShapeShift's *FOX Colony* on Arbitrum (~**$182,700** across two transactions) by abusing Colony's native meta‑transaction facility to **hijack the colony's proxy resolver** and then execute arbitrary code in the colony's storage context. Blockaid publicly noted that *every* Colony deployment exposing `executeMetaTransaction` on top of `EtherRouter`, on any chain, shares the vector.

This review (a) confirms the root cause against the source, (b) **identifies a second, previously‑undisclosed instance of the same vulnerability class on `ColonyNetwork`**, (c) verifies that colony logic, extension logic, and the meta‑transaction token are *not* affected, and (d) supplies and documents a minimal two‑part remediation plus a regression test.

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| **F‑1** | Meta‑tx self‑call → `EtherRouter`/DSAuth proxy‑admin takeover (the exploited bug) | Critical | Fixed (part 1) |
| **F‑2** | Meta‑tx self‑call → `ColonyNetwork` admin functions (found in this review) | Critical | Fixed (part 2) |
| **F‑3** | Vestigial `address(this)` self‑trust in `DSAuthMeta.isAuthorized` | Informational | Hardening recommended |
| **A‑1** | Extension contracts (CoinMachine, OneTxPayment, VotingReputation, …) | No finding | Reviewed |

---

## 2. Background — the incident

A colony's on‑chain address is an **`EtherRouter`** (an upgradeable proxy). It `delegatecall`s into a `Resolver`, which maps a 4‑byte selector to the live logic contract. Changing the resolver therefore changes *all* of the colony's logic. `EtherRouter.setResolver(address)` is the legitimate upgrade hook and is gated by dappsys **`DSAuth`**.

Colony also offers gasless UX via native meta‑transactions: a relayer submits `executeMetaTransaction(user, payload, sig)` and the contract executes `payload` "as" `user`.

The attacker combined the two: they meta‑relayed a `setResolver` call that repointed the colony at an attacker‑controlled contract, then drained the colony through the proxy's `delegatecall` fallback.

---

## 3. Scope & methodology

**In scope:** `contracts/common/BasicMetaTransaction.sol`, `contracts/common/MetaTransactionMsgSender.sol`, `contracts/EtherRouter.sol` (and `contracts/common/EtherRouter.sol`), `lib/dappsys/auth.sol` (DSAuth), `contracts/colony/ColonyStorage.sol`, `contracts/common/CommonStorage.sol`, `contracts/colonyNetwork/*`, `contracts/extensions/*`, `contracts/metaTxToken/*`.

**Method:** manual source review of the authorization and proxy‑dispatch paths; enumeration of every contract that (a) inherits `BasicMetaTransaction` (i.e. exposes the self‑call) and (b) exposes any function authorized by raw `msg.sender` under DSAuth's self‑trust rule. Dynamic testing was performed in code (regression suite authored) but **not executed in the review environment** (no Solidity toolchain / restricted egress) — see §7.

---

## 4. Root‑cause analysis

### 4.1 The self‑call
`executeMetaTransaction` dispatches the user's payload by calling the contract **on itself**:

```solidity
(success, returnData) = address(this).call(
  abi.encodePacked(_payload, METATRANSACTION_FLAG, _user)
);
```

Because this is an **external call to `address(this)`**, the *inner* call runs with **`msg.sender == address(this)`**. The signer `_user` is appended to calldata so that meta‑aware functions can recover the real sender via `msgSender()`.

### 4.2 The self‑trust
`executeMetaTransaction` does **not** require the signer to hold any permission — it only checks that `_user` signed the payload. Anyone can therefore sign and relay their *own* meta‑transaction.

dappsys `DSAuth` (`lib/dappsys/auth.sol`) authorizes calls as follows:

```solidity
modifier auth virtual { require(isAuthorized(msg.sender, msg.sig), "ds-auth-unauthorized"); _; }

function isAuthorized(address src, bytes4 sig) internal view returns (bool) {
    if (src == address(this)) { return true; }   // ← unconditional self‑trust
    else if (src == owner)    { return true; }
    ...
}
```

The critical interaction: any contract whose `auth` modifier checks **raw `msg.sender`** (DSAuth's default) treats the meta‑transaction self‑call (`msg.sender == address(this)`) as fully authorized — **bypassing the meta‑aware `msgSender()` entirely**.

### 4.3 Why some contracts are safe and others are not

| Contract | `auth` resolves caller via | `address(this)` self‑trust reachable? | Exploitable via meta‑tx |
|---|---|---|---|
| Colony logic (`ColonyStorage`) | `msgSender()` (override) | No (override drops it) | **No** |
| `EtherRouter` proxy (`setResolver`/`setOwner`/`setAuthority`) | raw `msg.sender` (DSAuth) | **Yes** | **YES → F‑1** |
| `ColonyNetwork` logic (`CommonStorage`) | raw `msg.sender` (DSAuth, *not* overridden) | **Yes** | **YES → F‑2** |
| Extension logic | colony roles via `msgSender()` | n/a (no DSAuth `auth` used) | No (A‑1) |
| `MetaTxToken` (`DSAuthMeta`) | `msgSender()` (modifier) | Unreachable (modifier passes `msgSender()`) | No (F‑3 is dead code) |

---

## 5. Findings

### F‑1 — Meta‑transaction self‑call → proxy‑admin takeover  *(Critical — exploited 2026‑05‑13)*

**Affected:** `EtherRouter.setResolver(address)` and the inherited DSAuth `setOwner(address)` / `setAuthority(address)` on every `EtherRouter`‑fronted contract (colonies, the network, and each installed extension).

**Attack (resolver hijack):**
1. Attacker crafts `payload = setResolver(EVIL)` and signs a meta‑transaction over it (no permission required).
2. `colony.executeMetaTransaction(ATTACKER, payload, sig)` → `address(this).call(payload …)`.
3. Inner call hits `EtherRouter.setResolver` with `msg.sender == address(this)`; DSAuth self‑trust authorizes it.
4. Resolver now points at `EVIL`; every subsequent call `delegatecall`s attacker code in the colony's storage → **funds drained**.

`setOwner`/`setAuthority` give equivalent takeover (attacker becomes owner / installs a permissive authority).

**Remediation (part 1):** reject the proxy‑admin selectors inside `executeMetaTransaction`, *before* the self‑call. Because the legitimate upgrade path is never a meta‑transaction, this has no functional impact. See §6.1.

---

### F‑2 — Meta‑transaction self‑call → `ColonyNetwork` admin functions  *(Critical — identified in this review)*

**Affected:** `ColonyNetwork` (and any other `CommonStorage`‑based contract that exposes `executeMetaTransaction`). `CommonStorage` is `is DSAuth, MetaTransactionMsgSender` and **does not override `auth`** — so the network's `auth`‑guarded admin functions (`setTokenLocking`, `initialise`, `addColonyVersion`, `addNetworkColonyVersion`, `startTokenAuction`, reputation‑mining setters, bridge setters, …) inherit the same raw‑`msg.sender` self‑trust.

**Attack:** `colonyNetwork.executeMetaTransaction(ATTACKER, setTokenLocking(EVIL), sig)` → self‑call → `msg.sender == address(this)` → DSAuth self‑trust → executes. The colony‑level fix (`ColonyStorage`'s override) does **not** cover the network; the part‑1 selector blocklist does **not** cover these (non‑proxy) selectors.

**Remediation (part 2):** give `CommonStorage` the same meta‑safe `auth` override that `ColonyStorage` already uses — authorize via `msgSender()` and **drop** the `address(this)` self‑trust. See §6.2.

---

### F‑3 — Vestigial self‑trust in `DSAuthMeta.isAuthorized`  *(Informational)*

`DSAuthMeta.isAuthorized` retains `if (src == address(this)) return true;`. It is currently **unreachable for exploitation** because `DSAuthMeta.auth` passes `msgSender()` (which resolves to the appended `_user` during a meta‑tx self‑call, never `address(this)`). It is nonetheless a latent footgun; recommend deleting the branch so the property is structural, not incidental.

---

### A‑1 — Extension contracts  *(No finding)*

All contracts under `contracts/extensions/` that inherit `BasicMetaTransaction` (CoinMachine, OneTxPayment, FundingQueue, TokenSupplier, Whitelist, EvaluatedExpenditure, VotingReputation, and the `ColonyExtensionMeta` base) were reviewed. **None uses the bare DSAuth `auth` modifier on any function**; they authorize via the colony's role system through `msgSender()` (e.g. `colony.hasInheritedUserRole(msgSender(), …)`). Their only DSAuth self‑trust surface is the proxy‑admin trio on their own `EtherRouter`, which is covered by part‑1. **No additional fix required.**

---

## 6. Remediation (applied on `security/metatx-proxy-admin-guard`)

### 6.1 Part 1 — `contracts/common/BasicMetaTransaction.sol`
Block the EtherRouter/DSAuth proxy‑admin selectors from ever being dispatched through a meta‑transaction:

```solidity
interface IProxyAdminSelectors {
  function setResolver(address) external;
  function setOwner(address) external;
  function setAuthority(address) external;
}
// …
bytes4 private constant PROXY_ADMIN_SET_RESOLVER  = IProxyAdminSelectors.setResolver.selector;
bytes4 private constant PROXY_ADMIN_SET_OWNER     = IProxyAdminSelectors.setOwner.selector;
bytes4 private constant PROXY_ADMIN_SET_AUTHORITY = IProxyAdminSelectors.setAuthority.selector;
// … inside executeMetaTransaction, after signature verification:
require(_payload.length >= 4, "colony-metatx-payload-too-short");
bytes4 targetSig;
assembly { targetSig := mload(add(_payload, 0x20)) }
require(
  targetSig != PROXY_ADMIN_SET_RESOLVER &&
  targetSig != PROXY_ADMIN_SET_OWNER &&
  targetSig != PROXY_ADMIN_SET_AUTHORITY,
  "colony-metatx-admin-selector-forbidden"
);
```

### 6.2 Part 2 — `contracts/common/CommonStorage.sol`
Make the network's authorization meta‑aware and self‑trust‑free (mirrors `ColonyStorage`):

```solidity
modifier auth() virtual override {
  require(authorizedSender(msgSender(), msg.sig), "ds-auth-unauthorized");
  _;
}
function authorizedSender(address src, bytes4 sig) internal view returns (bool) {
  if (src == owner) { return true; }
  else if (authority == DSAuthority(0)) { return false; }
  else { return authority.canCall(src, address(this), sig); }
}
```

### 6.3 Regression test — `test/contracts-network/metatx-admin-selfcall-guard.js`
Asserts: meta‑relayed `setResolver`/`setOwner`/`setAuthority` revert (`colony-metatx-admin-selector-forbidden`) and the resolver is unchanged; a legitimate non‑admin meta‑transaction from a permitted signer still succeeds; a meta‑relayed `ColonyNetwork.setTokenLocking` reverts (`ds-auth-unauthorized`).

---

## 7. Verification status (read this before deploying)

The fix has been **compiled against the full contract tree, and the regression test passes**, in CI (GitHub Actions `security-check` on `Deed3Labs/colonyNetwork` — green): the meta‑relayed `setResolver`/`setOwner`/`setAuthority` revert and the resolver is unchanged; the network `setTokenLocking` self‑call is rejected and its state is unchanged; and a legitimate non‑admin meta‑transaction still succeeds. The override‑chain compiled without needing an `override(CommonStorage)` change. (CI caught and the maintainer fixed two issues en route: a `DSAuthority(address(0))` cast and a test assertion string.) Before any deployment the maintainer MUST still:

1. Run the **full test suite** — the CI above runs only compilation plus the targeted regression test — with particular attention to network **`initialise` / upgrade / cross‑chain** flows (part 2 changes authorization on the network's critical path).
2. Deploy to **Base Sepolia** and **replay the exploit** (sign an attacker meta‑tx calling `setResolver` against a live colony) to confirm an on‑chain revert.
3. Commission an **independent third‑party audit** of the meta‑tx / auth / proxy surface. This review found a second critical instance (F‑2) by manual inspection; that is evidence the area warrants external eyes, not a clean bill.

---

## 8. Residual risk & recommendations

- **Selector blocklist is exact, not categorical.** Part 1 enumerates the three known self‑trusting proxy selectors. Part 2 (categorical, via `msgSender()`) is the durable defense for logic functions. New `EtherRouter`/DSAuth admin functions, if ever added, must be added to the blocklist.
- **Defense in depth (optional):** removing `if (src == address(this)) return true;` from `lib/dappsys/auth.sol` would neutralize the entire class at the root, but it touches the shared proxy/upgrade path and must be validated against every legitimate self‑call — treat as a separate, fully‑tested change.
- **F‑3:** delete the dead self‑trust branch in `DSAuthMeta`.
- **Deployment posture:** deploy fresh, fixed contracts (do not build on the abandoned, unpatched live deployment); maintainer retains upgrade keys, so future issues can be resolved via resolver upgrade.

---

## 9. Conclusion

The vulnerability exploited against FOX Colony is **fully root‑caused** and a **minimal, targeted remediation** is in place for both the disclosed vector (F‑1) and a second critical instance discovered during this review (F‑2). Colony logic, extension logic, and the meta‑transaction token were verified **not** to be affected. Subject to the verification gate in §7 — compilation, full test suite, a Base Sepolia exploit‑replay, and an independent audit — the fork is sound to deploy. This document should be read **together with** the passing CI run that fulfills §7; on its own it certifies the analysis and the fix, not their execution.

---

### Appendix A — changed files
```
contracts/common/BasicMetaTransaction.sol  | +37
contracts/common/CommonStorage.sol         | +26  −1
test/contracts-network/metatx-admin-selfcall-guard.js  | (new)
```

### Appendix B — error signatures introduced
- `colony-metatx-admin-selector-forbidden` — meta‑tx targeted a proxy‑admin selector (F‑1).
- `colony-metatx-payload-too-short` — meta‑tx payload shorter than a 4‑byte selector.
- `ds-auth-unauthorized` — (existing) now also raised for self‑call attempts on `CommonStorage` admin functions (F‑2).
