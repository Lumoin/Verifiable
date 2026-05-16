using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.OAuth.Dpop;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth.Dpop;

[TestClass]
internal sealed class DpopProofValidationTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly DateTimeOffset NowInstant = new(2026, 5, 13, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan IatSkew = TimeSpan.FromSeconds(30);
    private const string DefaultMethod = "POST";
    private const string DefaultUrl = "https://as.example.com/token";

    private FakeTimeProvider TimeProvider { get; } = new(NowInstant);


    [TestMethod]
    public async Task ValidateAsyncSucceedsOnFreshProof()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofAsync(key, BuildClaims()).ConfigureAwait(false);

        DpopValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Validation must succeed; got {result.FailureReason}.");
        Assert.IsNotNull(result.Claims);
        Assert.IsNotNull(result.JwkThumbprint);
        Assert.AreEqual(
            DpopJwkUtilities.ComputeThumbprint(keys.PublicKey, WellKnownJwaValues.Es256,
                TestSetup.Base64UrlEncoder, SensitiveMemoryPool<byte>.Shared),
            result.JwkThumbprint);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsMalformedProof()
    {
        DpopValidationResult result = await ValidateAsync("not-a-jws").ConfigureAwait(false);
        Assert.AreEqual(DpopValidationFailureReason.Malformed, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsWrongTyp()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        //Build with a non-DPoP typ in the header by hand-spliced header dict.
        string proof = await BuildProofWithCustomHeaderAsync(key, BuildClaims(),
            header => new Dictionary<string, object>(header)
            {
                [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt
            }).ConfigureAwait(false);

        DpopValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
        Assert.AreEqual(DpopValidationFailureReason.InvalidTyp, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsUnacceptableAlg()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        //Force header to advertise a non-ECDSA alg. The signature was made with
        //ES256 but the header lies — validator should reject on alg shape before
        //attempting signature verification.
        string proof = await BuildProofWithCustomHeaderAsync(key, BuildClaims(),
            header => new Dictionary<string, object>(header)
            {
                [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Hs256
            }).ConfigureAwait(false);

        DpopValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
        Assert.AreEqual(DpopValidationFailureReason.InvalidAlg, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsMissingJwkInHeader()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofWithCustomHeaderAsync(key, BuildClaims(),
            header =>
            {
                Dictionary<string, object> tampered = new(header);
                tampered.Remove(WellKnownJoseHeaderNames.Jwk);
                return tampered;
            }).ConfigureAwait(false);

        DpopValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
        Assert.IsTrue(
            result.FailureReason is DpopValidationFailureReason.InvalidJwk
                or DpopValidationFailureReason.Malformed,
            $"Expected InvalidJwk or Malformed; got {result.FailureReason}.");
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsBadSignature()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofAsync(key, BuildClaims()).ConfigureAwait(false);

        //Tamper one byte of the signature by flipping a middle character of the
        //base64url signature segment. The middle of a base64url string carries
        //full 6-bit groups, so any base64url character substitutes to another
        //base64url character without breaking decode validity -- the resulting
        //bytes verify false, which is what this test asserts. The previous
        //last-character substitution was non-deterministic: only A/Q/g/w are
        //valid as the trailing single-byte position, so randomly-generated
        //signatures ending in 'A' had no valid neighbour and threw
        //FormatException at decode time.
        int signatureStart = proof.LastIndexOf('.') + 1;
        int tamperIndex = signatureStart + (proof.Length - signatureStart) / 2;
        char tampered = proof[tamperIndex] == 'A' ? 'B' : 'A';
        string tamperedProof = string.Concat(
            proof.AsSpan(0, tamperIndex), tampered.ToString(), proof.AsSpan(tamperIndex + 1));

        DpopValidationResult result = await ValidateAsync(tamperedProof).ConfigureAwait(false);
        Assert.AreEqual(DpopValidationFailureReason.SignatureFailed, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsWrongHtm()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofAsync(key, BuildClaims() with { Htm = "GET" }).ConfigureAwait(false);

        DpopValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
        Assert.AreEqual(DpopValidationFailureReason.HtmMismatch, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsWrongHtu()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofAsync(key, BuildClaims() with { Htu = "https://attacker.example.com/token" }).ConfigureAwait(false);

        DpopValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
        Assert.AreEqual(DpopValidationFailureReason.HtuMismatch, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsOldIat()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        DpopProofClaims claims = BuildClaims() with { Iat = NowInstant - TimeSpan.FromMinutes(5) };
        string proof = await BuildProofAsync(key, claims).ConfigureAwait(false);

        DpopValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
        Assert.AreEqual(DpopValidationFailureReason.IatOutOfWindow, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsFutureIat()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        DpopProofClaims claims = BuildClaims() with { Iat = NowInstant + TimeSpan.FromMinutes(5) };
        string proof = await BuildProofAsync(key, claims).ConfigureAwait(false);

        DpopValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
        Assert.AreEqual(DpopValidationFailureReason.IatOutOfWindow, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsMissingNonceWhenRequired()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofAsync(key, BuildClaims()).ConfigureAwait(false);

        DpopValidationResult result = await ValidateAsync(
            proof, expectedNonce: "expected-nonce", nonceRequired: true).ConfigureAwait(false);
        Assert.AreEqual(DpopValidationFailureReason.NonceMissing, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsMismatchedNonce()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofAsync(key, BuildClaims() with { Nonce = "wrong-nonce" }).ConfigureAwait(false);

        DpopValidationResult result = await ValidateAsync(
            proof, expectedNonce: "expected-nonce", nonceRequired: true).ConfigureAwait(false);
        Assert.AreEqual(DpopValidationFailureReason.NonceMismatch, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsMismatchedAth()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofAsync(key, BuildClaims() with { Ath = "wrong-ath" }).ConfigureAwait(false);

        DpopValidationResult result = await ValidateAsync(
            proof, accessToken: "presented-token").ConfigureAwait(false);
        Assert.AreEqual(DpopValidationFailureReason.AthMismatch, result.FailureReason);
    }


    private static DpopProofClaims BuildClaims() => new()
    {
        Htm = DefaultMethod,
        Htu = DefaultUrl,
        Iat = NowInstant,
        Jti = Guid.NewGuid().ToString("N")
    };


    private async Task<string> BuildProofAsync(DpopKey key, DpopProofClaims claims) =>
        await DpopProofConstruction.BuildAsync(
            claims,
            key,
            TestSetup.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctions.SignP256Async,
            SensitiveMemoryPool<byte>.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);


    private async Task<string> BuildProofWithCustomHeaderAsync(
        DpopKey key,
        DpopProofClaims claims,
        Func<IReadOnlyDictionary<string, object>, IReadOnlyDictionary<string, object>> headerTransform)
    {
        DpopJwsPartSerializer customSerializer = DpopTestSupport.Serializer with
        {
            SerializeHeader = header =>
                headerTransform(DpopTestSupport.SerializeHeader(header))
        };

        return await DpopProofConstruction.BuildAsync(
            claims,
            key,
            TestSetup.Base64UrlEncoder,
            customSerializer,
            MicrosoftCryptographicFunctions.SignP256Async,
            SensitiveMemoryPool<byte>.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private async Task<DpopValidationResult> ValidateAsync(
        string proof,
        string? expectedNonce = null,
        bool nonceRequired = false,
        string? accessToken = null)
    {
        DpopProofValidationRequest request = new()
        {
            Proof = proof,
            HttpMethod = DefaultMethod,
            HttpUrl = DefaultUrl,
            ExpectedNonce = expectedNonce,
            NonceRequired = nonceRequired,
            AccessToken = accessToken
        };

        return await DpopProofValidation.ValidateAsync(
            request,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            DpopTestSupport.Parser,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            TimeProvider,
            SensitiveMemoryPool<byte>.Shared,
            IatSkew,
            TestContext.CancellationToken).ConfigureAwait(false);
    }
}
