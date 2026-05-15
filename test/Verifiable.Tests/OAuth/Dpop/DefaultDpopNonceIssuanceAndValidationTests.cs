using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Microsoft;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Keys;
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
        InProcessKeySet<HmacKey> keySet = CreateKeySet("kid-1");

        string nonce = await IssueAsync(keySet, DefaultAudience).ConfigureAwait(false);
        DpopNonceValidationResult result = await ValidateAsync(keySet, nonce, DefaultAudience)
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
        InProcessKeySet<HmacKey> keySet = CreateKeySet("kid-1");

        DpopNonceValidationResult result = await ValidateAsync(
            keySet, "not-a-nonce", DefaultAudience).ConfigureAwait(false);

        Assert.AreEqual(DpopNonceValidationFailureReason.Malformed, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsTamperedNonce()
    {
        InProcessKeySet<HmacKey> keySet = CreateKeySet("kid-1");

        string nonce = await IssueAsync(keySet, DefaultAudience).ConfigureAwait(false);

        //Decode, flip a byte inside the HMAC tag region (the last 32 bytes),
        //re-encode. Tampering after the encoded boundary catches the HMAC
        //verification path specifically.
        using IMemoryOwner<byte> decoded = TestHostShell.Base64UrlDecoder(nonce, TestHostShell.MemoryPool);
        Memory<byte> bytes = decoded.Memory[..ComputeNonceByteLength("kid-1")];
        int tamperOffset = bytes.Length - WellKnownDpopValues.NonceHmacTagByteLength / 2;
        bytes.Span[tamperOffset] ^= 0xFF;
        string tampered = TestHostShell.Base64UrlEncoder(bytes.Span);

        DpopNonceValidationResult result = await ValidateAsync(
            keySet, tampered, DefaultAudience).ConfigureAwait(false);

        Assert.AreEqual(DpopNonceValidationFailureReason.HmacMismatch, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsExpiredNonce()
    {
        InProcessKeySet<HmacKey> keySet = CreateKeySet("kid-1");

        string nonce = await IssueAsync(keySet, DefaultAudience).ConfigureAwait(false);

        //Advance past the validity window.
        TimeProvider.Advance(WellKnownDpopValues.DefaultNonceValidityWindow + TimeSpan.FromSeconds(1));

        DpopNonceValidationResult result = await ValidateAsync(keySet, nonce, DefaultAudience)
            .ConfigureAwait(false);

        Assert.AreEqual(DpopNonceValidationFailureReason.Expired, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsAudienceMismatch()
    {
        InProcessKeySet<HmacKey> keySet = CreateKeySet("kid-1");

        string nonce = await IssueAsync(keySet, DefaultAudience).ConfigureAwait(false);

        DpopNonceValidationResult result = await ValidateAsync(
            keySet,
            nonce,
            new Uri("https://attacker.example.com/token")).ConfigureAwait(false);

        Assert.AreEqual(DpopNonceValidationFailureReason.AudienceMismatch, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsUnknownKid()
    {
        InProcessKeySet<HmacKey> issuingKeySet = CreateKeySet("kid-issuing");

        string nonce = await IssueAsync(issuingKeySet, DefaultAudience).ConfigureAwait(false);

        //A second keyset with a non-overlapping kid set rejects the nonce
        //because the embedded kid is unknown to it.
        InProcessKeySet<HmacKey> foreignKeySet = CreateKeySet("kid-foreign");

        DpopNonceValidationResult result = await ValidateAsync(
            foreignKeySet, nonce, DefaultAudience).ConfigureAwait(false);

        Assert.AreEqual(DpopNonceValidationFailureReason.UnknownKid, result.FailureReason);
    }


    private async Task<string> IssueAsync(
        InProcessKeySet<HmacKey> keySet,
        Uri audience) =>
        await DefaultDpopNonceIssuance.IssueAsync(
            audience,
            TestTenant,
            new RequestContext(),
            (tenantId, ctx, ct) => ValueTask.FromResult(keySet.Snapshot()),
            selectHmacKey: null,
            (kid, tenantId, ctx, ct) => ValueTask.FromResult(keySet.ResolveByKid(kid)),
            TimeProvider,
            TestHostShell.Base64UrlEncoder,
            TestHostShell.MemoryPool,
            TestContext.CancellationToken).ConfigureAwait(false);


    private async Task<DpopNonceValidationResult> ValidateAsync(
        InProcessKeySet<HmacKey> keySet,
        string presentedNonce,
        Uri expectedAudience) =>
        await DefaultDpopNonceValidation.ValidateAsync(
            presentedNonce,
            expectedAudience,
            TestTenant,
            new RequestContext(),
            (tenantId, ctx, ct) => ValueTask.FromResult(keySet.Snapshot()),
            (kid, tenantId, ctx, ct) => ValueTask.FromResult(keySet.ResolveByKid(kid)),
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


    private static InProcessKeySet<HmacKey> CreateKeySet(string kid)
    {
        SymmetricKey material = CreateHmacKey();
        HmacKey key = new() { Kid = kid, Material = material };
        return new InProcessKeySet<HmacKey>(new KeySet<HmacKey> { Current = [key] });
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "SymmetricKeyMemory ownership transfers to the returned SymmetricKey, which is owned by the test's InProcessKeySet.")]
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
