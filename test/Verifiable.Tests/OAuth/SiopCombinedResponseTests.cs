using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Text;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Microsoft;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Siop;
using Verifiable.OAuth.Siop.Wallet;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The SIOPv2 §12 / OID4VP combined response: the wallet answers one authorization request
/// with BOTH a Self-Issued ID Token (<c>id_token</c>, authenticating the End-User) and a
/// Verifiable Presentation (<c>vp_token</c>, carrying issuer-attested claims), each bound to
/// the SAME <c>nonce</c> and Client ID per SIOPv2 §12. The verifier validates the two
/// artifacts with their production primitives — <see cref="SelfIssuedIdTokenValidation"/> and
/// <see cref="SdJwtVpTokenVerification"/> — and the test proves the bindings hold together and
/// fail together under replay.
/// </summary>
/// <remarks>
/// SIOPv2 §2.2.1: the cryptographic keys within the Verifiable Presentation and for signing
/// the Self-Issued ID Token are not necessarily related — exercised here deliberately: the
/// SIOP subject key is a fresh P-256 pair while the credential's holder binding is an Ed25519
/// key, and the verifier makes no assumption connecting them.
/// </remarks>
[TestClass]
internal sealed class SiopCombinedResponseTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private const string VerifierClientId = "https://verifier.example.com";
    private const string RequestNonce = "n-combined-0S6_WzA2Mj";

    private const string IssuerId = "https://issuer.example.com";
    private const string IssuerKeyId = "did:web:issuer.example.com#key-1";

    private static readonly string[] AllowedAlgorithms = [WellKnownJwaValues.Es256];

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer PayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);


    [TestMethod]
    public async Task CombinedResponseBindsIdTokenAndVpTokenToTheSameTransaction()
    {
        //=== Issuance time (out of band): the End-User holds an issuer-attested PID. ===
        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync("Alice", "Smith").ConfigureAwait(false);

        using(holderPrivateKey)
        using(issuerPublicKey)
        {
            //=== Wallet side: one transaction (nonce + client id) yields both artifacts. ===
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> siopKeys =
                TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
            using PublicKeyMemory siopPublic = siopKeys.PublicKey;
            using PrivateKeyMemory siopPrivate = siopKeys.PrivateKey;

            string idToken = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
                siopPrivate, siopPublic, VerifierClientId, RequestNonce,
                issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
                TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

            string vpToken = await PresentWithKeyBindingAsync(
                serializedSdJwt, holderPrivateKey, RequestNonce, VerifierClientId)
                .ConfigureAwait(false);

            //=== Verifier side: both artifacts validate, both bound to this transaction. ===
            SelfIssuedIdTokenValidationResult idTokenResult = await SelfIssuedIdTokenValidation.ValidateAsync(
                idToken, VerifierClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
                resolveDidVerificationKey: null,
                TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(idTokenResult.IsValid, "The Self-Issued ID Token must validate per SIOPv2 §11.1.");

            VpTokenParsed parsed = await VerifyPresentationAsync(vpToken, issuerPublicKey).ConfigureAwait(false);

            Assert.IsTrue(parsed.CredentialSignatureValid, "The issuer-signed credential must verify.");
            Assert.IsTrue(parsed.KbJwtSignatureValid, "The KB-JWT must verify against the cnf holder key.");
            Assert.IsTrue(parsed.SdHashValid, "The KB-JWT sd_hash must match the presented disclosures.");

            //SIOPv2 §12: the Verifiable Presentation MUST be bound to the nonce provided by
            //the RP and to the RP's Client ID — the same values the ID Token echoes.
            Assert.AreEqual(RequestNonce, parsed.KbJwtNonce);
            Assert.AreEqual(VerifierClientId, parsed.KbJwtAud);
            Assert.AreEqual(RequestNonce, idTokenResult.Nonce);

            //SIOPv2 §2.2.1: the SIOP subject key and the credential's holder key are
            //unrelated — the ID Token's subject is the P-256 thumbprint URI, not anything
            //derived from the credential's Ed25519 cnf binding.
            Assert.StartsWith(SiopSubjectSyntaxTypes.JwkThumbprintSha256Prefix, idTokenResult.Subject);
        }
    }


    [TestMethod]
    public async Task ReplayedCombinedResponseFailsBothNonceBindings()
    {
        //An attacker replays artifacts minted for an earlier transaction against a fresh
        //request: the signatures still verify, but BOTH nonce bindings miss — the §12 / §11.1
        //checks are what stop the replay, on each artifact independently.
        const string StaleNonce = "n-earlier-transaction";

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync("Alice", "Smith").ConfigureAwait(false);

        using(holderPrivateKey)
        using(issuerPublicKey)
        {
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> siopKeys =
                TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
            using PublicKeyMemory siopPublic = siopKeys.PublicKey;
            using PrivateKeyMemory siopPrivate = siopKeys.PrivateKey;

            string staleIdToken = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
                siopPrivate, siopPublic, VerifierClientId, StaleNonce,
                issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
                TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

            string staleVpToken = await PresentWithKeyBindingAsync(
                serializedSdJwt, holderPrivateKey, StaleNonce, VerifierClientId)
                .ConfigureAwait(false);

            SelfIssuedIdTokenValidationResult idTokenResult = await SelfIssuedIdTokenValidation.ValidateAsync(
                staleIdToken, VerifierClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
                resolveDidVerificationKey: null,
                TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

            //The token is cryptographically intact — only the transaction binding fails.
            Assert.IsTrue(idTokenResult.IsSignatureValid);
            Assert.IsFalse(idTokenResult.IsNonceValid);
            Assert.IsFalse(idTokenResult.IsValid);

            VpTokenParsed parsed = await VerifyPresentationAsync(staleVpToken, issuerPublicKey).ConfigureAwait(false);

            Assert.IsTrue(parsed.KbJwtSignatureValid);
            Assert.AreNotEqual(RequestNonce, parsed.KbJwtNonce,
                "The verifier's §12 nonce comparison must detect the replayed presentation.");
        }
    }


    /// <summary>
    /// Issues an EUDI PID SD-JWT VC with the holder's Ed25519 public key in <c>cnf.jwk</c> —
    /// the issuance-time half every presentation builds on.
    /// </summary>
    private async ValueTask<(string SerializedSdJwt, PrivateKeyMemory HolderPrivateKey, PublicKeyMemory IssuerPublicKey)>
        IssuePidCredentialAsync(string givenName, string familyName)
    {
        var issuerKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory issuerPrivateKey = issuerKeys.PrivateKey;

        var holderKeys = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublicKey = holderKeys.PublicKey;

        Dictionary<string, object> holderJwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            holderPublicKey.Tag.Get<CryptoAlgorithm>(),
            holderPublicKey.Tag.Get<Purpose>(),
            holderPublicKey.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);

        JwtPayload payload = JwtPayload.ForSdJwtVcIssuance(
            issuer: IssuerId,
            verifiableCredentialType: EudiPid.SdJwtVct,
            issuedAt: TimeProvider.GetUtcNow(),
            holderConfirmation: holderJwk,
            claims:
            [
                new(EudiPid.SdJwt.GivenName, givenName),
                new(EudiPid.SdJwt.FamilyName, familyName)
            ]);

        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.GivenName}"),
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.FamilyName}")
        };

        SdTokenResult result = await payload.IssueSdJwtAsync(
            c => JsonSerializerExtensions.SerializeToUtf8Bytes(c, TestSetup.DefaultSerializationOptions),
            SdJwtIssuance.IssueVerboseAsync,
            disclosablePaths, TestSalts.DefaultGenerator(),
            issuerPrivateKey, IssuerKeyId, Pool,
            mediaType: WellKnownMediaTypes.Jwt.VcSdJwt,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string compactJws = Encoding.UTF8.GetString(result.SignedToken.Span);
        using SdToken<string> issuedToken = new(compactJws, result.Disclosures.ToList());
        string serializedSdJwt = SdJwtSerializer.SerializeToken(issuedToken, TestSetup.Base64UrlEncoder);

        return (serializedSdJwt, holderKeys.PrivateKey, issuerKeys.PublicKey);
    }


    /// <summary>
    /// The wallet-side presentation step: parse the stored SD-JWT, sign a KB-JWT over its hash
    /// input with the holder key — bound to the request's <c>nonce</c> and the verifier's
    /// Client ID — and serialise the presentation with key binding per RFC 9901 §4.3. The same
    /// composition <c>TestWallet</c> and the production wallet client run.
    /// </summary>
    private async ValueTask<string> PresentWithKeyBindingAsync(
        string sdJwtWithoutKb, PrivateKeyMemory holderPrivateKey, string nonce, string audience)
    {
        using SdToken<string> token = SdJwtSerializer.ParseToken(
            sdJwtWithoutKb, TestSetup.Base64UrlDecoder, Pool, TestSalts.TestSaltTag);

        string hashInput = SdJwtSerializer.GetSdJwtForHashing(token, TestSetup.Base64UrlEncoder);

        string compactKbJwt = await KbJwtIssuance.IssueAsync(
            Encoding.UTF8.GetBytes(hashInput),
            holderPrivateKey,
            nonce,
            audience,
            TimeProvider.GetUtcNow(),
            TestSetup.Base64UrlEncoder,
            HeaderSerializer,
            PayloadSerializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        using SdToken<string> tokenWithKb = token.WithKeyBinding(compactKbJwt, Pool);

        return SdJwtSerializer.SerializeToken(tokenWithKb, TestSetup.Base64UrlEncoder);
    }


    private async ValueTask<VpTokenParsed> VerifyPresentationAsync(
        string vpToken, PublicKeyMemory issuerPublicKey)
    {
        PublicKeyMemory? IssuerLookup(string iss) =>
            string.Equals(iss, IssuerId, StringComparison.Ordinal) ? issuerPublicKey : null;

        return await SdJwtVpTokenVerification.VerifyAsync(
            vpToken,
            "pid",
            static s => SdJwtSerializer.ParseToken(
                s, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, TestSalts.TestSaltTag),
            static t => SdJwtSerializer.GetSdJwtForHashing(t, TestSetup.Base64UrlEncoder),
            IssuerLookup,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            Pool,
            saltReuseSeam: null,
            TestContext.CancellationToken).ConfigureAwait(false);
    }
}
