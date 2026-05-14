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
internal sealed class DefaultDpopNonceIssuanceAndValidationTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly DateTimeOffset NowInstant = new(2026, 5, 14, 12, 0, 0, TimeSpan.Zero);
    private static readonly TenantId TestTenant = new("test-tenant");
    private static readonly Uri DefaultAudience = new("https://issuer.test/abcd1234");

    private FakeTimeProvider TimeProvider { get; } = new(NowInstant);


    [TestMethod]
    public async Task IssueAsyncProducesValidatableNonce()
    {
        using SymmetricKey hmacKey = CreateHmacKey();
        InProcessHmacKeyResolver resolver = new(hmacKey, "kid-1");

        string nonce = await IssueAsync(resolver, DefaultAudience).ConfigureAwait(false);
        DpopNonceValidationResult result = await ValidateAsync(resolver, nonce, DefaultAudience)
            .ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess,
            $"Roundtrip must succeed; got {result.FailureReason}.");
        Assert.IsNotNull(result.Payload);
        Assert.AreEqual("kid-1", result.Payload.Kid);
        Assert.AreEqual(NowInstant.ToUnixTimeSeconds(),
            result.Payload.IssuedAt.ToUnixTimeSeconds());
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsMalformedNonce()
    {
        using SymmetricKey hmacKey = CreateHmacKey();
        InProcessHmacKeyResolver resolver = new(hmacKey, "kid-1");

        DpopNonceValidationResult result = await ValidateAsync(
            resolver, "not-a-nonce", DefaultAudience).ConfigureAwait(false);

        Assert.AreEqual(DpopNonceValidationFailureReason.Malformed, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsTamperedNonce()
    {
        using SymmetricKey hmacKey = CreateHmacKey();
        InProcessHmacKeyResolver resolver = new(hmacKey, "kid-1");

        string nonce = await IssueAsync(resolver, DefaultAudience).ConfigureAwait(false);

        //Decode, flip a byte inside the HMAC tag region (the last 32 bytes),
        //re-encode. Tampering after the encoded boundary catches the HMAC
        //verification path specifically.
        using IMemoryOwner<byte> decoded = TestHostShell.Base64UrlDecoder(nonce, TestHostShell.MemoryPool);
        Memory<byte> bytes = decoded.Memory[..ComputeNonceByteLength("kid-1")];
        int tamperOffset = bytes.Length - WellKnownDpopValues.NonceHmacTagByteLength / 2;
        bytes.Span[tamperOffset] ^= 0xFF;
        string tampered = TestHostShell.Base64UrlEncoder(bytes.Span);

        DpopNonceValidationResult result = await ValidateAsync(
            resolver, tampered, DefaultAudience).ConfigureAwait(false);

        Assert.AreEqual(DpopNonceValidationFailureReason.HmacMismatch, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsExpiredNonce()
    {
        using SymmetricKey hmacKey = CreateHmacKey();
        InProcessHmacKeyResolver resolver = new(hmacKey, "kid-1");

        string nonce = await IssueAsync(resolver, DefaultAudience).ConfigureAwait(false);

        //Advance past the validity window.
        TimeProvider.Advance(WellKnownDpopValues.DefaultNonceValidityWindow + TimeSpan.FromSeconds(1));

        DpopNonceValidationResult result = await ValidateAsync(resolver, nonce, DefaultAudience)
            .ConfigureAwait(false);

        Assert.AreEqual(DpopNonceValidationFailureReason.Expired, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsAudienceMismatch()
    {
        using SymmetricKey hmacKey = CreateHmacKey();
        InProcessHmacKeyResolver resolver = new(hmacKey, "kid-1");

        string nonce = await IssueAsync(resolver, DefaultAudience).ConfigureAwait(false);

        DpopNonceValidationResult result = await ValidateAsync(
            resolver,
            nonce,
            new Uri("https://attacker.example.com/token")).ConfigureAwait(false);

        Assert.AreEqual(DpopNonceValidationFailureReason.AudienceMismatch, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsUnknownKid()
    {
        using SymmetricKey issuerKey = CreateHmacKey();
        InProcessHmacKeyResolver issuingResolver = new(issuerKey, "kid-issuing");

        string nonce = await IssueAsync(issuingResolver, DefaultAudience).ConfigureAwait(false);

        //A second resolver with a non-overlapping kid set rejects the nonce
        //because the embedded kid is unknown to it.
        using SymmetricKey otherKey = CreateHmacKey();
        InProcessHmacKeyResolver foreignResolver = new(otherKey, "kid-foreign");

        DpopNonceValidationResult result = await ValidateAsync(
            foreignResolver, nonce, DefaultAudience).ConfigureAwait(false);

        Assert.AreEqual(DpopNonceValidationFailureReason.UnknownKid, result.FailureReason);
    }


    private async Task<string> IssueAsync(
        InProcessHmacKeyResolver resolver,
        Uri audience) =>
        await DefaultDpopNonceIssuance.IssueAsync(
            audience,
            TestTenant,
            new RequestContext(),
            resolver.ResolveAsync,
            TimeProvider,
            TestHostShell.Base64UrlEncoder,
            TestHostShell.MemoryPool,
            TestContext.CancellationToken).ConfigureAwait(false);


    private async Task<DpopNonceValidationResult> ValidateAsync(
        InProcessHmacKeyResolver resolver,
        string presentedNonce,
        Uri expectedAudience) =>
        await DefaultDpopNonceValidation.ValidateAsync(
            presentedNonce,
            expectedAudience,
            TestTenant,
            new RequestContext(),
            resolver.ResolveAsync,
            TimeProvider,
            WellKnownDpopValues.DefaultNonceValidityWindow,
            TestHostShell.Base64UrlDecoder,
            TestHostShell.MemoryPool,
            TestContext.CancellationToken).ConfigureAwait(false);


    private static int ComputeNonceByteLength(string kid) =>
        1 + System.Text.Encoding.UTF8.GetByteCount(kid)
            + WellKnownDpopValues.NonceIssuedAtByteLength
            + WellKnownDpopValues.NonceAudienceHashByteLength
            + WellKnownDpopValues.NonceRandomByteLength
            + WellKnownDpopValues.NonceHmacTagByteLength;


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
