/* globals artifacts */

// Regression tests for the meta-transaction self-call privilege-escalation that was exploited
// against ShapeShift's FOX Colony on Arbitrum (2026-05-13, ~$182K).
//
// Root cause: executeMetaTransaction dispatches its payload via address(this).call(...), so the
// inner call runs with msg.sender == address(this). DSAuth (used by the EtherRouter proxy and,
// for the network, via CommonStorage) authorizes any caller where msg.sender == address(this).
// Without the fixes, anyone could meta-relay setResolver/setOwner/setAuthority (proxy takeover ->
// resolver hijack -> full drain) or, on the ColonyNetwork, its admin functions.
//
// Fixes under test:
//   1. BasicMetaTransaction.executeMetaTransaction blocks the EtherRouter/DSAuth admin selectors.
//   2. CommonStorage overrides `auth` to use msgSender() and drop the address(this) self-trust,
//      protecting ColonyNetwork's admin functions.

const chai = require("chai");
const bnChai = require("bn-chai");

const { checkErrorRevert, expectEvent } = require("../../helpers/test-helper");
const { getMetaTransactionParameters, setupRandomColony } = require("../../helpers/test-data-generator");

const { expect } = chai;
chai.use(bnChai(web3.utils.BN));

const EtherRouter = artifacts.require("EtherRouter");
const IColonyNetwork = artifacts.require("IColonyNetwork");
const Resolver = artifacts.require("Resolver");

contract("Meta-transaction security: admin self-call guard", (accounts) => {
  const ROOT = accounts[0];
  const ATTACKER = accounts[5];
  const RELAYER = accounts[6];

  let colonyNetwork;
  let colony;
  let colonyRouter;
  let originalResolver;

  before(async () => {
    const cnAddress = (await EtherRouter.deployed()).address;
    colonyNetwork = await IColonyNetwork.at(cnAddress);
  });

  beforeEach(async () => {
    ({ colony } = await setupRandomColony(colonyNetwork));
    // A colony's address IS an EtherRouter proxy.
    colonyRouter = await EtherRouter.at(colony.address);
    originalResolver = await colonyRouter.resolver();
  });

  // ATTACKER signs and relays an arbitrary payload against an EtherRouter-fronted contract.
  async function relayAsAttacker(target, txData) {
    const { r, s, v } = await getMetaTransactionParameters(txData, ATTACKER, target.address);
    return target.executeMetaTransaction(ATTACKER, txData, r, s, v, { from: RELAYER });
  }

  describe("colony — EtherRouter / DSAuth proxy-admin trio", () => {
    it("blocks a meta-relayed setResolver (the resolver-hijack drain vector)", async () => {
      const evilResolver = await Resolver.new();
      const txData = colonyRouter.contract.methods.setResolver(evilResolver.address).encodeABI();

      await checkErrorRevert(relayAsAttacker(colony, txData), "colony-metatx-admin-selector-forbidden");

      // The resolver must be untouched.
      expect(await colonyRouter.resolver()).to.equal(originalResolver);
    });

    it("blocks a meta-relayed setOwner (proxy takeover)", async () => {
      const txData = colonyRouter.contract.methods.setOwner(ATTACKER).encodeABI();
      await checkErrorRevert(relayAsAttacker(colony, txData), "colony-metatx-admin-selector-forbidden");
      expect(await colonyRouter.owner()).to.not.equal(ATTACKER);
    });

    it("blocks a meta-relayed setAuthority (proxy takeover)", async () => {
      const txData = colonyRouter.contract.methods.setAuthority(ATTACKER).encodeABI();
      await checkErrorRevert(relayAsAttacker(colony, txData), "colony-metatx-admin-selector-forbidden");
    });

    it("still allows a legitimate (non-admin) meta-transaction from a permitted signer", async () => {
      // ROOT created the colony in setupRandomColony and holds the Root role.
      const txData = colony.contract.methods.setRewardInverse(50).encodeABI();
      const { r, s, v } = await getMetaTransactionParameters(txData, ROOT, colony.address);

      await expectEvent(
        colony.executeMetaTransaction(ROOT, txData, r, s, v, { from: RELAYER }),
        "ColonyRewardInverseSet",
        [ROOT, 50],
      );
    });
  });

  describe("ColonyNetwork — CommonStorage auth (no address(this) self-trust)", () => {
    it("blocks a meta-relayed network admin function (setTokenLocking) by an unauthorized signer", async () => {
      const tokenLockingBefore = await colonyNetwork.getTokenLocking();
      const txData = colonyNetwork.contract.methods.setTokenLocking(ATTACKER).encodeABI();

      // CommonStorage's overridden `auth` resolves the signer via msgSender() (== ATTACKER, no
      // permission) and no longer self-trusts address(this), so the inner self-call reverts with
      // `ds-auth-unauthorized`. executeMetaTransaction surfaces any failed self-call as its generic
      // wrapper, so that is the revert the caller observes; the state-unchanged assertion below
      // confirms the admin function did NOT execute (without the fix it would succeed).
      await checkErrorRevert(relayAsAttacker(colonyNetwork, txData), "colony-metatx-function-call-unsuccessful");

      expect(await colonyNetwork.getTokenLocking()).to.equal(tokenLockingBefore);
    });
  });
});
