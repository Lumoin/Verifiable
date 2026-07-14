using Verifiable.Core.Model.Mdoc;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Mdoc;

/// <summary>
/// Tests for <see cref="MdocMsoValidityValidator"/> — the MSO temporal
/// gate alongside <see cref="MdocMsoDigestBindingValidator"/> on the
/// verifier side.
/// </summary>
/// <remarks>
/// <para>
/// All times here are explicit <see cref="DateTimeOffset"/> constants —
/// no <c>UtcNow</c> calls per the project's deterministic-time rule.
/// </para>
/// </remarks>
[TestClass]
internal sealed class MdocMsoValidityValidatorTests
{
    //Family anchor: not a clean single-call TestClock.CanonicalEpoch offset
    //(2026-06-01T12:00:00Z is 5 months 12 hours after this signed instant),
    //so the one-year window anchors itself.
    private static readonly DateTimeOffset Signed = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset ValidFrom = Signed;
    private static readonly DateTimeOffset ValidUntil = Signed.AddYears(1);

    //Bit-identical to TestClock.CanonicalEpoch (2026-06-01T12:00:00Z).
    private static readonly DateTimeOffset MidWindow = TestClock.CanonicalEpoch;
    private static readonly DateTimeOffset BeforeWindow = ValidFrom.AddSeconds(-1);
    private static readonly DateTimeOffset AfterWindow = ValidUntil.AddSeconds(1);


    [TestMethod]
    public void ValidationTimeInsideWindowReturnsSuccess()
    {
        MdocValidityInfo info = new(Signed, ValidFrom, ValidUntil);

        MdocValidityResult result = MdocMsoValidityValidator.Validate(info, MidWindow);

        Assert.IsTrue(result.IsValid);
        Assert.AreEqual(MdocValidityFailureReason.None, result.FailureReason);
        Assert.IsFalse(result.ExpectedUpdateAtOrPast);
    }


    [TestMethod]
    public void ValidationTimeAtValidFromReturnsSuccess()
    {
        //Boundary inclusion: now == validFrom is valid (closed lower bound).
        MdocValidityInfo info = new(Signed, ValidFrom, ValidUntil);

        MdocValidityResult result = MdocMsoValidityValidator.Validate(info, ValidFrom);

        Assert.IsTrue(result.IsValid);
    }


    [TestMethod]
    public void ValidationTimeAtValidUntilReturnsSuccess()
    {
        //Boundary inclusion: now == validUntil is valid (closed upper bound).
        MdocValidityInfo info = new(Signed, ValidFrom, ValidUntil);

        MdocValidityResult result = MdocMsoValidityValidator.Validate(info, ValidUntil);

        Assert.IsTrue(result.IsValid);
    }


    [TestMethod]
    public void ValidationTimeBeforeValidFromFailsAsNotYetValid()
    {
        MdocValidityInfo info = new(Signed, ValidFrom, ValidUntil);

        MdocValidityResult result = MdocMsoValidityValidator.Validate(info, BeforeWindow);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(MdocValidityFailureReason.NotYetValid, result.FailureReason);
    }


    [TestMethod]
    public void ValidationTimeAfterValidUntilFailsAsExpired()
    {
        MdocValidityInfo info = new(Signed, ValidFrom, ValidUntil);

        MdocValidityResult result = MdocMsoValidityValidator.Validate(info, AfterWindow);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(MdocValidityFailureReason.Expired, result.FailureReason);
    }


    [TestMethod]
    public void SignedAfterValidFromFailsAsLifecycleViolation()
    {
        //Signed > validFrom is malformed regardless of validation time.
        DateTimeOffset signedLate = ValidFrom.AddDays(1);
        MdocValidityInfo info = new(signedLate, ValidFrom, ValidUntil);

        MdocValidityResult result = MdocMsoValidityValidator.Validate(info, MidWindow);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(MdocValidityFailureReason.SignedAfterValidFrom, result.FailureReason);
    }


    [TestMethod]
    public void InvertedWindowFailsAsValidFromAfterValidUntil()
    {
        //validFrom > validUntil is structurally malformed.
        MdocValidityInfo info = new(
            signed: Signed,
            validFrom: ValidUntil,
            validUntil: ValidFrom);

        MdocValidityResult result = MdocMsoValidityValidator.Validate(info, MidWindow);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(MdocValidityFailureReason.ValidFromAfterValidUntil, result.FailureReason);
    }


    [TestMethod]
    public void ExpectedUpdatePastValidationTimeSurfacesAdvisoryOnSuccess()
    {
        //Issuer suggested refresh at June 1; we're at September 1 — still
        //inside the validity window, but past the hint. Result must be
        //valid AND surface the advisory.
        DateTimeOffset expectedUpdate = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);
        DateTimeOffset validationTime = new(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);

        MdocValidityInfo info = new(Signed, ValidFrom, ValidUntil, expectedUpdate);

        MdocValidityResult result = MdocMsoValidityValidator.Validate(info, validationTime);

        Assert.IsTrue(result.IsValid,
            "Past expectedUpdate is advisory; validation must still pass on a credential inside its main window.");
        Assert.IsTrue(result.ExpectedUpdateAtOrPast);
    }


    [TestMethod]
    public void ExpectedUpdateFutureDoesNotTriggerAdvisory()
    {
        DateTimeOffset expectedUpdate = new(2026, 12, 1, 0, 0, 0, TimeSpan.Zero);

        MdocValidityInfo info = new(Signed, ValidFrom, ValidUntil, expectedUpdate);

        MdocValidityResult result = MdocMsoValidityValidator.Validate(info, MidWindow);

        Assert.IsTrue(result.IsValid);
        Assert.IsFalse(result.ExpectedUpdateAtOrPast,
            "expectedUpdate is in the future relative to validation time; no advisory.");
    }


    [TestMethod]
    public void NullExpectedUpdateDoesNotTriggerAdvisory()
    {
        MdocValidityInfo info = new(Signed, ValidFrom, ValidUntil, expectedUpdate: null);

        MdocValidityResult result = MdocMsoValidityValidator.Validate(info, MidWindow);

        Assert.IsTrue(result.IsValid);
        Assert.IsFalse(result.ExpectedUpdateAtOrPast);
    }


    [TestMethod]
    public void FailedFactoryRejectsNoneReason()
    {
        //Defensive: the Failed factory shouldn't accept None as a reason —
        //a result is either successful (use Success) or failed (use a real
        //reason). Catching the misuse keeps the result type's invariant
        //honest.
        Assert.ThrowsExactly<ArgumentException>(() =>
            MdocValidityResult.Failed(MdocValidityFailureReason.None));
    }


    [TestMethod]
    public void ResultToStringSurfacesAdvisoryWhenPresent()
    {
        MdocValidityResult successPlain = MdocValidityResult.Success();
        MdocValidityResult successAdvisory = MdocValidityResult.Success(expectedUpdateAtOrPast: true);
        MdocValidityResult failed = MdocValidityResult.Failed(MdocValidityFailureReason.Expired);

        Assert.AreEqual("Valid", successPlain.ToString());
        Assert.Contains("refresh", successAdvisory.ToString());
        Assert.Contains("Expired", failed.ToString());
    }
}
