using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Microsoft;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Keys;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "SymmetricKey ownership transfers from CreateHmacKey() to the InProcessKeySet via AddCurrent/AddIncoming; the keyset is held in a using and disposes all materials.")]
[TestClass]
internal sealed class DpopRotationTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly DateTimeOffset NowInstant = TestClock.CanonicalEpoch.AddDays(-18);
    private static readonly TenantId TestTenant = new("test-tenant");
    private static readonly Uri DefaultAudience = new("https://issuer.test/abcd1234");

    private FakeTimeProvider TimeProvider { get; } = new(NowInstant);


    [TestMethod]
    public async Task NonceUnderRetiringKidStillValidatesDuringOverlapWindow()
    {
        //RFC 9449 §10 — rotating the HMAC key must not invalidate nonces still
        //in flight. The keyset keeps retired keys in the Retiring slot for the
        //overlap window; nonces signed under the retired kid still validate
        //while a fresh issuance under the new Current kid is wire-distinguishable.
        using InProcessKeySet keySet = new();
        KeyId kidA = new("kid-A");
        keySet.AddCurrent(kidA, CreateHmacKey());

        string nonceUnderA = await IssueAsync(keySet).ConfigureAwait(false);

        //Rotate: kid-A → Retiring, kid-B → Current.
        KeyId kidB = new("kid-B");
        keySet.AddIncoming(kidB, CreateHmacKey());
        keySet.PromoteIncomingToCurrent(kidB);
        keySet.RetireCurrent(kidA);

        DpopNonceValidationResult retiredResult = await ValidateAsync(keySet, nonceUnderA).ConfigureAwait(false);

        Assert.IsTrue(retiredResult.IsSuccess,
            $"Nonce issued under Retiring kid must still validate; got {retiredResult.FailureReason}.");
        Assert.AreEqual("kid-A", retiredResult.Payload!.Kid);

        //Fresh issuance under the rotated keyset picks up the new Current kid.
        string nonceUnderB = await IssueAsync(keySet).ConfigureAwait(false);

        DpopNonceValidationResult currentResult = await ValidateAsync(keySet, nonceUnderB).ConfigureAwait(false);

        Assert.IsTrue(currentResult.IsSuccess);
        Assert.AreEqual("kid-B", currentResult.Payload!.Kid);
    }


    [TestMethod]
    public async Task NonceUnderHistoricalKidNoLongerValidates()
    {
        //After a key is archived from Retiring to Historical, nonces signed
        //under it are rejected — the slot-membership check excludes Historical.
        using InProcessKeySet keySet = new();
        KeyId kidA = new("kid-A");
        keySet.AddCurrent(kidA, CreateHmacKey());

        string nonceUnderA = await IssueAsync(keySet).ConfigureAwait(false);

        KeyId kidB = new("kid-B");
        keySet.AddIncoming(kidB, CreateHmacKey());
        keySet.PromoteIncomingToCurrent(kidB);
        keySet.RetireCurrent(kidA);
        keySet.ArchiveRetiring(kidA);

        DpopNonceValidationResult result = await ValidateAsync(keySet, nonceUnderA).ConfigureAwait(false);

        Assert.AreEqual(DpopNonceValidationFailureReason.UnknownKid, result.FailureReason,
            "Nonce signed under a Historical kid must be rejected.");
    }


    private async Task<string> IssueAsync(InProcessKeySet keySet) =>
        await DefaultDpopNonceIssuance.IssueAsync(
            DefaultAudience,
            TestTenant,
            new ExchangeContext(),
            (tenantId, ctx, ct) => ValueTask.FromResult(keySet.Snapshot()),
            selectHmacKey: null,
            (kid, tenantId, ctx, ct) => ValueTask.FromResult(keySet.ResolveMaterial(kid)),
            TimeProvider,
            TestHostShell.Base64UrlEncoder,
            System.Security.Cryptography.RandomNumberGenerator.Fill,
            TestHostShell.MemoryPool,
            TestContext.CancellationToken).ConfigureAwait(false);


    private async Task<DpopNonceValidationResult> ValidateAsync(
        InProcessKeySet keySet, string nonce) =>
        await DefaultDpopNonceValidation.ValidateAsync(
            nonce,
            DefaultAudience,
            TestTenant,
            new ExchangeContext(),
            (tenantId, ctx, ct) => ValueTask.FromResult(keySet.Snapshot()),
            (kid, tenantId, ctx, ct) => ValueTask.FromResult(keySet.ResolveMaterial(kid)),
            TimeProvider,
            WellKnownDpopValues.DefaultNonceValidityWindow,
            TestHostShell.Base64UrlDecoder,
            TestHostShell.MemoryPool,
            TestContext.CancellationToken).ConfigureAwait(false);


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "SymmetricKeyMemory ownership transfers to the returned SymmetricKey, which is owned by the InProcessKeySet for the lifetime of the test.")]
    private static SymmetricKey CreateHmacKey()
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(32);
        SymmetricKeyMemory material;
        try
        {
            RandomNumberGenerator.Fill(owner.Memory.Span[..32]);
            material = new SymmetricKeyMemory(owner, CryptoTags.HmacSha256Key);
        }
        catch
        {
            owner.Dispose();
            throw;
        }

        return new SymmetricKey(
            material,
            Guid.NewGuid().ToString("N"),
            MicrosoftHmacFunctions.ComputeHmacAsync,
            MicrosoftHmacFunctions.VerifyHmacAsync);
    }
}
