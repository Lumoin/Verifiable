using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Siop;
using Verifiable.OAuth.Siop.Wallet;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// SIOPv2 with post-quantum key material: the Self-Issued OP signs with ML-DSA (FIPS 204)
/// and the subject is the thumbprint of an Algorithm Key Pair (<c>kty</c> <c>AKP</c>) JWK.
/// The issuance and validation primitives are algorithm-agnostic — the JWS <c>alg</c> comes
/// off the key's <see cref="Tag"/> through the registry, the <c>sub_jwk</c> through the JWK
/// converters — so the same code path that serves P-256 serves ML-DSA-44/65/87, including the
/// AKP-specific thumbprint canon where <c>alg</c> IS a required member.
/// </summary>
[TestClass]
internal sealed class SiopPostQuantumTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    private const string ClientId = "https://verifier.example.org/cb";
    private const string RequestNonce = "n-0S6_WzA2Mj";

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer PayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);


    [TestMethod]
    [DataRow("ML-DSA-44")]
    [DataRow("ML-DSA-65")]
    [DataRow("ML-DSA-87")]
    public async Task SelfIssuedIdTokenRoundTripsWithMlDsa(string algorithm)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = CreateKeys(algorithm);
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        string idToken = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
            subjectPrivate, subjectPublic, ClientId, RequestNonce,
            issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
            TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        string[] allowedAlgorithms = [algorithm];
        SelfIssuedIdTokenValidationResult result = await SelfIssuedIdTokenValidation.ValidateAsync(
            idToken, ClientId, RequestNonce, allowedAlgorithms, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid,
            $"A Self-Issued ID Token signed with {algorithm} must validate end to end.");
        Assert.AreEqual(SiopSubjectSyntaxType.JwkThumbprint, result.SubjectSyntaxType);
        Assert.IsTrue(result.IsSignatureValid);
        Assert.IsTrue(result.IsSubjectConfirmed,
            "The AKP thumbprint (alg/kty/pub canon) must bind the subject to the key.");

        //The subject IS the RFC 9278 thumbprint URI of the AKP JWK — recomputable from
        //the public key alone.
        IReadOnlyDictionary<string, string> akpJwk = DpopJwkUtilities.ToJwk(
            subjectPublic, algorithm, TestSetup.Base64UrlEncoder);
        string expectedThumbprint = DpopJwkUtilities.ComputeThumbprintFromJwk(
            akpJwk, TestSetup.Base64UrlEncoder, Pool);
        Assert.AreEqual(
            SiopSubjectSyntaxTypes.JwkThumbprintSha256Prefix + expectedThumbprint,
            result.Subject);
    }


    [TestMethod]
    public async Task RejectsAkpSubJwkCarryingPrivateKeyMaterial()
    {
        //The AKP private member is 'priv' — a published sub_jwk carrying it must fail the
        //bare-public-key shape check exactly like an EC 'd' would.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = CreateKeys("ML-DSA-65");
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(subjectPrivate.Tag);
        IReadOnlyDictionary<string, string> akpJwk = DpopJwkUtilities.ToJwk(
            subjectPublic, algorithm, TestSetup.Base64UrlEncoder);
        string thumbprint = DpopJwkUtilities.ComputeThumbprintFromJwk(
            akpJwk, TestSetup.Base64UrlEncoder, Pool);
        string sub = SiopSubjectSyntaxTypes.JwkThumbprintSha256Prefix + thumbprint;

        Dictionary<string, object> leakySubJwk = new(StringComparer.Ordinal);
        foreach(KeyValuePair<string, string> member in akpJwk)
        {
            leakySubJwk[member.Key] = member.Value;
        }

        leakySubJwk[WellKnownJwkMemberNames.Priv] = "bm90LWEtcmVhbC1wcml2YXRlLWtleQ";

        JwtHeader header = new(capacity: 2)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt
        };
        JwtPayload payload = new(capacity: 7)
        {
            [WellKnownJwtClaimNames.Iss] = sub,
            [WellKnownJwtClaimNames.Sub] = sub,
            [WellKnownJwtClaimNames.Aud] = ClientId,
            [WellKnownJwtClaimNames.Nonce] = RequestNonce,
            [WellKnownJwtClaimNames.Iat] = TimeProvider.GetUtcNow().ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = TimeProvider.GetUtcNow().AddMinutes(5).ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.SubJwk] = leakySubJwk
        };

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            subjectPrivate, HeaderSerializer, PayloadSerializer,
            TestSetup.Base64UrlEncoder, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
        string idToken = JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);

        string[] allowedAlgorithms = [algorithm];
        SelfIssuedIdTokenValidationResult result = await SelfIssuedIdTokenValidation.ValidateAsync(
            idToken, ClientId, RequestNonce, allowedAlgorithms, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSubJwkShapeValid,
            "An AKP sub_jwk carrying 'priv' is not a bare public key.");
        Assert.IsFalse(result.IsValid);
    }


    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateKeys(
        string algorithm) => algorithm switch
        {
            "ML-DSA-44" => TestKeyMaterialProvider.CreateMlDsa44KeyMaterial(),
            "ML-DSA-65" => TestKeyMaterialProvider.CreateMlDsa65KeyMaterial(),
            "ML-DSA-87" => TestKeyMaterialProvider.CreateMlDsa87KeyMaterial(),
            _ => throw new ArgumentException($"Unknown algorithm '{algorithm}'.", nameof(algorithm))
        };
}
