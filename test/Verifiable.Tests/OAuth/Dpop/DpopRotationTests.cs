using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Microsoft;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth.Dpop;

[TestClass]
internal sealed class DpopRotationTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly DateTimeOffset NowInstant = new(2026, 5, 14, 12, 0, 0, TimeSpan.Zero);
    private static readonly TenantId TestTenant = new("test-tenant");
    private static readonly Uri DefaultAudience = new("https://issuer.test/abcd1234");

    private FakeTimeProvider TimeProvider { get; } = new(NowInstant);


    [TestMethod]
    public async Task NonceUnderRetiredKidStillValidatesDuringOverlapWindow()
    {
        //RFC 9449 §10 — rotating the HMAC key must not invalidate nonces still
        //in flight. The resolver keeps retired keys for the overlap window;
        //nonces signed under the retired kid still validate while a fresh
        //issuance under the current kid is wire-distinguishable.
        using SymmetricKey keyA = CreateHmacKey();
        InProcessHmacKeyResolver resolver = new(keyA, "kid-A");

        string nonceUnderA = await DefaultDpopNonceIssuance.IssueAsync(
            DefaultAudience,
            TestTenant,
            new RequestContext(),
            resolver.ResolveAsync,
            TimeProvider,
            TestHostShell.Base64UrlEncoder,
            TestHostShell.MemoryPool,
            TestContext.CancellationToken).ConfigureAwait(false);

        using SymmetricKey keyB = CreateHmacKey();
        resolver.Rotate(keyB, "kid-B");

        DpopNonceValidationResult retiredResult = await DefaultDpopNonceValidation.ValidateAsync(
            nonceUnderA,
            DefaultAudience,
            TestTenant,
            new RequestContext(),
            resolver.ResolveAsync,
            TimeProvider,
            WellKnownDpopValues.DefaultNonceValidityWindow,
            TestHostShell.Base64UrlDecoder,
            TestHostShell.MemoryPool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(retiredResult.IsSuccess,
            $"Nonce issued under retired kid must still validate; got {retiredResult.FailureReason}.");
        Assert.AreEqual("kid-A", retiredResult.Payload!.Kid);

        //Fresh issuance under the rotated resolver picks up the new kid.
        string nonceUnderB = await DefaultDpopNonceIssuance.IssueAsync(
            DefaultAudience,
            TestTenant,
            new RequestContext(),
            resolver.ResolveAsync,
            TimeProvider,
            TestHostShell.Base64UrlEncoder,
            TestHostShell.MemoryPool,
            TestContext.CancellationToken).ConfigureAwait(false);

        DpopNonceValidationResult currentResult = await DefaultDpopNonceValidation.ValidateAsync(
            nonceUnderB,
            DefaultAudience,
            TestTenant,
            new RequestContext(),
            resolver.ResolveAsync,
            TimeProvider,
            WellKnownDpopValues.DefaultNonceValidityWindow,
            TestHostShell.Base64UrlDecoder,
            TestHostShell.MemoryPool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(currentResult.IsSuccess);
        Assert.AreEqual("kid-B", currentResult.Payload!.Kid);
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "SymmetricKeyMemory ownership transfers to the returned SymmetricKey, which the caller disposes.")]
    private static SymmetricKey CreateHmacKey()
    {
        IMemoryOwner<byte> owner = SensitiveMemoryPool<byte>.Shared.Rent(32);
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
