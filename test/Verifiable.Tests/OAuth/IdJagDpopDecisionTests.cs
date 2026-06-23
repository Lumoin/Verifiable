using Verifiable.OAuth.IdJag;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Unit coverage for <see cref="IdJagDpopDecision"/> — the
/// draft-ietf-oauth-identity-assertion-authz-grant §9.8.1.2 proof-of-possession decision matrix.
/// Each test pins one cell of the matrix (grant key-bound × DPoP proof presented × RS requires
/// sender-constrained) to its outcome.
/// </summary>
[TestClass]
internal sealed class IdJagDpopDecisionTests
{
    private const string KeyA = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    private const string KeyB = "bXZ8q3xg7Qe9mC2pT1rL4uV6wX8yZ0aB2cD4eF6gH8";


    [TestMethod]
    public void NoBindingNoProofIsBearer()
    {
        IdJagDpopDecision decision = IdJagDpopDecision.Evaluate(
            grantKeyThumbprint: null, presentedKeyThumbprint: null, resourceServerRequiresSenderConstrained: false);

        Assert.AreEqual(IdJagDpopDecisionKind.BearerToken, decision.Kind);
        Assert.IsFalse(decision.IsRejected);
        Assert.IsNull(decision.BoundKeyThumbprint);
    }


    [TestMethod]
    public void NoBindingWithProofIsSenderConstrainedToProofKey()
    {
        IdJagDpopDecision decision = IdJagDpopDecision.Evaluate(
            grantKeyThumbprint: null, presentedKeyThumbprint: KeyA, resourceServerRequiresSenderConstrained: false);

        Assert.AreEqual(IdJagDpopDecisionKind.SenderConstrainedToken, decision.Kind);
        Assert.AreEqual(KeyA, decision.BoundKeyThumbprint);
    }


    [TestMethod]
    public void BoundGrantWithMatchingProofIsSenderConstrained()
    {
        IdJagDpopDecision decision = IdJagDpopDecision.Evaluate(
            grantKeyThumbprint: KeyA, presentedKeyThumbprint: KeyA, resourceServerRequiresSenderConstrained: false);

        Assert.AreEqual(IdJagDpopDecisionKind.SenderConstrainedToken, decision.Kind);
        Assert.AreEqual(KeyA, decision.BoundKeyThumbprint);
    }


    [TestMethod]
    public void BoundGrantWithoutProofIsRejectProofRequired()
    {
        IdJagDpopDecision decision = IdJagDpopDecision.Evaluate(
            grantKeyThumbprint: KeyA, presentedKeyThumbprint: null, resourceServerRequiresSenderConstrained: false);

        Assert.AreEqual(IdJagDpopDecisionKind.RejectProofRequired, decision.Kind);
        Assert.IsTrue(decision.IsRejected);
    }


    [TestMethod]
    public void BoundGrantWithMismatchedProofIsRejectKeyMismatch()
    {
        IdJagDpopDecision decision = IdJagDpopDecision.Evaluate(
            grantKeyThumbprint: KeyA, presentedKeyThumbprint: KeyB, resourceServerRequiresSenderConstrained: false);

        Assert.AreEqual(IdJagDpopDecisionKind.RejectKeyMismatch, decision.Kind);
        Assert.IsTrue(decision.IsRejected);
    }


    [TestMethod]
    public void NoBindingNoProofWithConstraintRequiredIsReject()
    {
        IdJagDpopDecision decision = IdJagDpopDecision.Evaluate(
            grantKeyThumbprint: null, presentedKeyThumbprint: null, resourceServerRequiresSenderConstrained: true);

        Assert.AreEqual(IdJagDpopDecisionKind.RejectSenderConstrainedRequired, decision.Kind);
        Assert.IsTrue(decision.IsRejected);
    }


    [TestMethod]
    public void NoBindingWithProofSatisfiesConstraintRequirement()
    {
        IdJagDpopDecision decision = IdJagDpopDecision.Evaluate(
            grantKeyThumbprint: null, presentedKeyThumbprint: KeyA, resourceServerRequiresSenderConstrained: true);

        Assert.AreEqual(IdJagDpopDecisionKind.SenderConstrainedToken, decision.Kind);
        Assert.AreEqual(KeyA, decision.BoundKeyThumbprint);
    }
}
