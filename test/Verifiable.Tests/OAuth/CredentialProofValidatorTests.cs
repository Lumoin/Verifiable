using Microsoft.Extensions.Time.Testing;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Oid4Vci.Wallet;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The library primitive <see cref="CredentialProofValidator"/> performing the OID4VCI 1.0
/// Appendix F.4 Credential Issuer proof-validation checks over an Appendix F.1
/// <c>openid4vci-proof+jwt</c> holder key proof. The happy path mints with the PRODUCTION minter
/// <see cref="Oid4VciProofIssuance.BuildJwtProofAsync"/> so the validator and the wallet minter
/// round-trip; each negative test exercises one §F.4 MUST, quoting the normative sentence it
/// proves.
/// </summary>
[TestClass]
internal sealed class CredentialProofValidatorTests
{
    public TestContext TestContext { get; set; } = null!;

    private static DateTimeOffset NowInstant { get; } = TestClock.CanonicalEpoch;
    private static TimeSpan IatSkew { get; } = TimeSpan.FromMinutes(5);
    private const string Audience = "https://credential-issuer.example.com";
    private const string CredentialNonce = "c-nonce-LarRGSbmUPYtRYO6BQ4yn8";

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>
    /// The three public key parameters <see href="https://www.rfc-editor.org/rfc/rfc8037#section-2">RFC
    /// 8037 §2</see> defines for an OKP key, in ordinal order.
    /// </summary>
    private static string[] OkpPublicJwkMemberNames { get; } = ["crv", "kty", "x"];

    /// <summary>
    /// The public key parameters <see href="https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1">RFC
    /// 7518 §6.3.1</see> defines for an RSA key beside <c>kty</c>, in ordinal order.
    /// </summary>
    private static string[] RsaPublicJwkMemberNames { get; } = ["e", "kty", "n"];

    private FakeTimeProvider TimeProvider { get; } = new(NowInstant);

    //A JOSE-correct serializer that does NOT escape '+' (the character in
    //openid4vci-proof+jwt). RFC 7515 JWT headers carry it literally, the same relaxed escaping
    //the library's JCS canonical writer uses; the general-purpose escaping options would emit
    //"+" and break the typ contract a real Credential Issuer reads.
    private static System.Text.Json.JsonSerializerOptions JoseSerializationOptions { get; } =
        new(TestSetup.DefaultSerializationOptions)
        {
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, JoseSerializationOptions);

    private static JwtPayloadSerializer PayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, JoseSerializationOptions);


    /// <summary>
    /// Happy path: a proof minted by the production minter, bound to the issuer <c>aud</c> and the
    /// <c>c_nonce</c>, validates and yields the RFC 7638 thumbprint of the holder key.
    /// </summary>
    [TestMethod]
    public async Task ValidatesAFreshProductionMintedProof()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;

        string proof = await MintAsync(holderPrivate, holderPublic).ConfigureAwait(false);

        CredentialProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, $"Validation must succeed; got {result.FailureReason}.");
        Assert.AreEqual(Audience, result.Audience);
        Assert.AreEqual(CredentialNonce, result.Nonce);

        //The bound key is the holder key: its RFC 7638 thumbprint, the value the issued
        //Credential binds to.
        string expectedThumbprint = JwkThumbprintFor(holderPublic);
        Assert.AreEqual(expectedThumbprint, result.BoundKeyThumbprint);
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-F.1">Appendix
    /// F.1</see>: "<c>jwk</c>: OPTIONAL. JOSE Header containing the key material the new Credential is to
    /// be bound to." An Ed25519 holder key is an OKP key, and
    /// <see href="https://www.rfc-editor.org/rfc/rfc8037#section-2">RFC 8037 §2</see> defines its
    /// public form by exactly three parameters — "the three public key fields ... "crv", "kty", and
    /// "x"" — so the proof header's <c>jwk</c> carries those three and no EC <c>y</c> member, and the
    /// proof validates.
    /// </summary>
    [TestMethod]
    public async Task ValidatesAFreshProductionMintedProofWithAnEd25519HolderKey()
    {
        var keys = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;

        string proof = await MintAsync(holderPrivate, holderPublic).ConfigureAwait(false);

        Assert.AreSequenceEqual(
            OkpPublicJwkMemberNames,
            ReadHeaderJwkMemberNames(proof),
            "RFC 8037 §2: an OKP public key is kty, crv and x; the header jwk must carry no other member.");

        CredentialProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, $"Validation must succeed for an Ed25519 holder key; got {result.FailureReason}.");
        Assert.AreEqual(JwkThumbprintFor(holderPublic), result.BoundKeyThumbprint);
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-F.1">Appendix
    /// F.1</see>: "<c>jwk</c>: OPTIONAL. JOSE Header containing the key material the new Credential is to
    /// be bound to." An RSA holder key's public form is
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1">RFC 7518 §6.3.1</see>'s
    /// "n" (Modulus) and "e" (Exponent) parameters beside <c>kty</c>, so the proof header's <c>jwk</c>
    /// carries those three and no EC member, and the proof validates.
    /// </summary>
    [TestMethod]
    public async Task ValidatesAFreshProductionMintedProofWithAnRsaHolderKey()
    {
        var keys = TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;

        string proof = await MintAsync(holderPrivate, holderPublic).ConfigureAwait(false);

        Assert.AreSequenceEqual(
            RsaPublicJwkMemberNames,
            ReadHeaderJwkMemberNames(proof),
            "RFC 7518 §6.3.1: an RSA public key is kty, n and e; the header jwk must carry no other member.");

        CredentialProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, $"Validation must succeed for an RSA holder key; got {result.FailureReason}.");
        Assert.AreEqual(JwkThumbprintFor(holderPublic), result.BoundKeyThumbprint);
    }


    /// <summary>
    /// Reads the member names of the <c>jwk</c> object in a compact proof JWT's protected header, in
    /// ordinal order, so a test can assert the exact public-key parameter set the header carries.
    /// </summary>
    /// <param name="compactProof">The compact-serialized proof JWT.</param>
    /// <returns>The header <c>jwk</c> object's member names, ordinally sorted.</returns>
    private static string[] ReadHeaderJwkMemberNames(string compactProof)
    {
        string headerSegment = compactProof[..compactProof.IndexOf('.', StringComparison.Ordinal)];
        using System.Buffers.IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(headerSegment, Pool);
        using System.Text.Json.JsonDocument header = System.Text.Json.JsonDocument.Parse(headerBytes.Memory);

        return [.. header.RootElement
            .GetProperty(WellKnownJoseHeaderNames.Jwk)
            .EnumerateObject()
            .Select(static member => member.Name)
            .Order(StringComparer.Ordinal)];
    }


    /// <summary>
    /// §F.4: "the key proof is explicitly typed using header parameters as defined for that proof
    /// type" — §F.1 fixes that to <c>typ: openid4vci-proof+jwt</c>.
    /// </summary>
    [TestMethod]
    public async Task RejectsWrongTyp()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;

        string proof = await MintTamperedAsync(holderPrivate, holderPublic,
            tamperHeader: h => h[WellKnownJoseHeaderNames.Typ] = "jwt").ConfigureAwait(false);

        CredentialProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
        Assert.AreEqual(CredentialProofValidationFailureReason.InvalidTyp, result.FailureReason);
    }


    /// <summary>
    /// §F.1: "alg ... It MUST NOT be none or an identifier for a symmetric algorithm (MAC)".
    /// </summary>
    [TestMethod]
    public async Task RejectsAlgNone()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;

        string proof = await MintTamperedAsync(holderPrivate, holderPublic,
            tamperHeader: h => h[WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.None).ConfigureAwait(false);

        CredentialProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
        Assert.AreEqual(CredentialProofValidationFailureReason.InvalidAlg, result.FailureReason);
    }


    /// <summary>
    /// §F.4: "is supported by the application, and is acceptable per local policy" — an <c>alg</c>
    /// outside the issuer's accepted set is rejected even though it is a valid asymmetric algorithm.
    /// </summary>
    [TestMethod]
    public async Task RejectsAlgNotInAcceptedSet()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;

        string proof = await MintAsync(holderPrivate, holderPublic).ConfigureAwait(false);

        //The proof is ES256, but the issuer only accepts ES384.
        CredentialProofValidationResult result = await ValidateAsync(
            proof, acceptableAlgorithms: [WellKnownJwaValues.Es384]).ConfigureAwait(false);
        Assert.AreEqual(CredentialProofValidationFailureReason.InvalidAlg, result.FailureReason);
    }


    /// <summary>
    /// §F.4: "the header parameter does not contain a private key" — a <c>jwk</c> carrying the EC
    /// private scalar <c>d</c> is rejected before the key is reconstructed or the signature checked.
    /// </summary>
    [TestMethod]
    public async Task RejectsJwkContainingPrivateKey()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;

        string proof = await MintTamperedAsync(holderPrivate, holderPublic,
            tamperHeader: h =>
            {
                var jwk = new Dictionary<string, object>(
                    (Dictionary<string, object>)h[Oid4VciCredentialParameterNames.Jwk], StringComparer.Ordinal)
                {
                    [WellKnownJwkMemberNames.D] = "cHJpdmF0ZS1zY2FsYXI"
                };
                h[Oid4VciCredentialParameterNames.Jwk] = jwk;
            }).ConfigureAwait(false);

        CredentialProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
        Assert.AreEqual(CredentialProofValidationFailureReason.JwkContainsPrivateKey, result.FailureReason);
    }


    /// <summary>
    /// §F.1: <c>kid</c> "MUST NOT be present if jwk or x5c is present" (and conversely) — a proof
    /// naming two of the mutually-exclusive key references is rejected.
    /// </summary>
    [TestMethod]
    public async Task RejectsMultipleKeyReferences()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;

        //Both jwk and kid present — §F.1 mutual exclusivity violated.
        string proof = await MintTamperedAsync(holderPrivate, holderPublic,
            tamperHeader: h => h["kid"] = "did:example:123#key-1").ConfigureAwait(false);

        CredentialProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
        Assert.AreEqual(CredentialProofValidationFailureReason.InvalidKeyReference, result.FailureReason);
    }


    /// <summary>
    /// §F.4: "the signature on the key proof verifies with the public key contained in the header
    /// parameter" — a proof with a tampered signature is rejected.
    /// </summary>
    [TestMethod]
    public async Task RejectsTamperedSignature()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;

        string proof = await MintAsync(holderPrivate, holderPublic).ConfigureAwait(false);

        //Flip a middle character of the signature segment — stays base64url-valid, verifies false.
        int signatureStart = proof.LastIndexOf('.', StringComparison.Ordinal) + 1;
        int tamperIndex = signatureStart + ((proof.Length - signatureStart) / 2);
        char tampered = proof[tamperIndex] == 'A' ? 'B' : 'A';
        string tamperedProof = string.Concat(
            proof.AsSpan(0, tamperIndex), tampered.ToString(), proof.AsSpan(tamperIndex + 1));

        CredentialProofValidationResult result = await ValidateAsync(tamperedProof).ConfigureAwait(false);
        Assert.AreEqual(CredentialProofValidationFailureReason.SignatureFailed, result.FailureReason);
    }


    /// <summary>
    /// A proof whose header segment is not decodable base64url is rejected as <c>Malformed</c>, not
    /// surfaced as an escaping exception — the header decode fails closed on untrusted input.
    /// </summary>
    [TestMethod]
    public async Task RejectsMalformedHeaderSegment()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;

        string proof = await MintAsync(holderPrivate, holderPublic).ConfigureAwait(false);

        //Put an out-of-alphabet character in the header segment — every base64url decoder rejects it.
        //The validator must map this to Malformed rather than let the decoder's exception escape.
        string[] parts = proof.Split('.');
        Assert.HasCount(3, parts);
        string malformedProof = string.Join('.',
            string.Concat(parts[0].AsSpan(0, parts[0].Length - 1), "!"),
            parts[1],
            parts[2]);

        CredentialProofValidationResult result = await ValidateAsync(malformedProof).ConfigureAwait(false);
        Assert.AreEqual(CredentialProofValidationFailureReason.Malformed, result.FailureReason);
    }


    /// <summary>
    /// §F.1: "aud: REQUIRED (string). The value of this claim MUST be the Credential Issuer
    /// Identifier" — a proof whose <c>aud</c> is a different issuer is rejected.
    /// </summary>
    [TestMethod]
    public async Task RejectsAudienceMismatch()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;

        string proof = await MintAsync(
            holderPrivate, holderPublic, audience: "https://attacker-issuer.example.com").ConfigureAwait(false);

        CredentialProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
        Assert.AreEqual(CredentialProofValidationFailureReason.AudienceMismatch, result.FailureReason);
    }


    /// <summary>
    /// §F.4: "the creation time of the JWT ... is within an acceptable window" — a proof minted
    /// well before the window opened (stale) is rejected.
    /// </summary>
    [TestMethod]
    public async Task RejectsStaleIat()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;

        string proof = await MintAsync(
            holderPrivate, holderPublic, issuedAt: NowInstant - TimeSpan.FromHours(1)).ConfigureAwait(false);

        CredentialProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
        Assert.AreEqual(CredentialProofValidationFailureReason.IatOutOfWindow, result.FailureReason);
    }


    /// <summary>
    /// §F.4: "the creation time of the JWT ... is within an acceptable window" — a proof minted
    /// in the future beyond the skew is rejected.
    /// </summary>
    [TestMethod]
    public async Task RejectsFutureIat()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;

        string proof = await MintAsync(
            holderPrivate, holderPublic, issuedAt: NowInstant + TimeSpan.FromHours(1)).ConfigureAwait(false);

        CredentialProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
        Assert.AreEqual(CredentialProofValidationFailureReason.IatOutOfWindow, result.FailureReason);
    }


    /// <summary>
    /// §F.4: "if the server has a Nonce Endpoint, the nonce in the key proof matches the
    /// server-provided c_nonce value" — a proof echoing a different nonce is rejected, and the
    /// reason maps to <c>invalid_nonce</c>.
    /// </summary>
    [TestMethod]
    public async Task RejectsNonceMismatch()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;

        string proof = await MintAsync(
            holderPrivate, holderPublic, nonce: "c-nonce-stale-value").ConfigureAwait(false);

        CredentialProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
        Assert.AreEqual(CredentialProofValidationFailureReason.NonceMismatch, result.FailureReason);
    }


    /// <summary>
    /// §F.1: "nonce ... It MUST be present when the issuer has a Nonce Endpoint" — a proof carrying
    /// no <c>nonce</c> when one is required is rejected, mapping to <c>invalid_nonce</c>.
    /// </summary>
    [TestMethod]
    public async Task RejectsAbsentNonceWhenRequired()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;

        string proof = await MintTamperedAsync(holderPrivate, holderPublic,
            tamperPayload: p => p.Remove(WellKnownJwtClaimNames.Nonce)).ConfigureAwait(false);

        CredentialProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
        Assert.AreEqual(CredentialProofValidationFailureReason.NonceMissing, result.FailureReason);
    }


    /// <summary>
    /// §8.2 <c>proofs</c> batch: a mix of valid and one invalid entry — the batch result flags the
    /// bad entry at its position while the valid entries pass.
    /// </summary>
    [TestMethod]
    public async Task ValidatesProofsBatchFlaggingTheBadEntry()
    {
        var keysA = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory publicA = keysA.PublicKey;
        using PrivateKeyMemory privateA = keysA.PrivateKey;

        var keysB = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory publicB = keysB.PublicKey;
        using PrivateKeyMemory privateB = keysB.PrivateKey;

        string goodA = await MintAsync(privateA, publicA).ConfigureAwait(false);
        string badNonce = await MintAsync(privateB, publicB, nonce: "c-nonce-stale-value").ConfigureAwait(false);

        IReadOnlyList<CredentialProofValidationResult> results =
            await CredentialProofValidator.ValidateBatchAsync(
                [goodA, badNonce],
                Audience,
                CredentialNonce,
                nonceRequired: true,
                isProofSigningAlgAcceptable: static _ => true,
                resolveProofKey: null,
                x509Verification: null,
                [],
                TestSetup.Base64UrlEncoder,
                TestSetup.Base64UrlDecoder,
                TimeProvider,
                Pool,
                IatSkew,
                TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(2, results);
        Assert.IsTrue(results[0].IsValid, $"Entry 0 must validate; got {results[0].FailureReason}.");
        Assert.AreEqual(CredentialProofValidationFailureReason.NonceMismatch, results[1].FailureReason);
    }


    /// <summary>
    /// RFC 7515 §4: "The Header Parameter names within the JOSE Header ... MUST be unique." A
    /// header repeating the <c>jwk</c> member is rejected as <c>Malformed</c> before the key is
    /// reconstructed; the same header and payload with the duplicate removed validate. The header
    /// and payload are built by hand, never through <see cref="HeaderSerializer"/> or
    /// <see cref="PayloadSerializer"/>, and signed over their exact bytes with the project's own
    /// signing primitive, so only the header well-formedness gate — not an invalid signature — can
    /// be responsible for the refusal.
    /// </summary>
    [TestMethod]
    public async Task RejectsProofHeaderWithDuplicateJwkMember()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(holderPrivate.Tag);
        JsonWebKey jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            holderPublic.Tag.Get<CryptoAlgorithm>(),
            holderPublic.Tag.Get<Purpose>(),
            holderPublic.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);
        string jwkJson =
            "{\"kty\":\"" + jwk.Kty + "\",\"crv\":\"" + jwk.Crv + "\",\"x\":\"" + jwk.X + "\",\"y\":\"" + jwk.Y + "\"}";

        string payloadJson =
            "{\"aud\":\"" + Audience + "\",\"nonce\":\"" + CredentialNonce + "\"," +
            $"\"iat\":{NowInstant.ToUnixTimeSeconds()}}}";

        string duplicateHeaderJson =
            "{\"alg\":\"" + algorithm + "\",\"typ\":\"" + Oid4VciProofIssuance.ProofJwtType + "\"," +
            "\"jwk\":" + jwkJson + ",\"jwk\":" + jwkJson + "}";

        string duplicateProof = await SignRawAsync(holderPrivate, duplicateHeaderJson, payloadJson).ConfigureAwait(false);

        CredentialProofValidationResult duplicateResult = await ValidateAsync(duplicateProof).ConfigureAwait(false);
        Assert.AreEqual(CredentialProofValidationFailureReason.Malformed, duplicateResult.FailureReason);

        string singleHeaderJson =
            "{\"alg\":\"" + algorithm + "\",\"typ\":\"" + Oid4VciProofIssuance.ProofJwtType + "\"," +
            "\"jwk\":" + jwkJson + "}";

        string acceptedProof = await SignRawAsync(holderPrivate, singleHeaderJson, payloadJson).ConfigureAwait(false);

        CredentialProofValidationResult acceptedResult = await ValidateAsync(acceptedProof).ConfigureAwait(false);

        Assert.IsTrue(acceptedResult.IsValid,
            $"the same proof without the duplicate must validate; got {acceptedResult.FailureReason}.");
    }


    //Signs a hand-built header/payload JSON pair over their exact UTF-8 bytes with the project's
    //signing primitive, never through HeaderSerializer/PayloadSerializer — proves the well-formedness
    //gate's refusal is independent of how a JSON serializer would itself react to a repeated member.
    private static async Task<string> SignRawAsync(PrivateKeyMemory signingKey, string headerJson, string payloadJson)
    {
        string headerB64 = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(headerJson));
        string payloadB64 = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(payloadJson));
        byte[] signingInput = Encoding.ASCII.GetBytes($"{headerB64}.{payloadB64}");

        using Signature signature = await signingKey.SignAsync(signingInput, Pool).ConfigureAwait(false);
        string signatureB64 = TestSetup.Base64UrlEncoder(signature.AsReadOnlySpan());

        return $"{headerB64}.{payloadB64}.{signatureB64}";
    }


    //Mints a §F.1 jwt proof with the PRODUCTION minter, bound to the issuer aud and the c_nonce.
    private async Task<string> MintAsync(
        PrivateKeyMemory holderPrivate,
        PublicKeyMemory holderPublic,
        string audience = Audience,
        string nonce = CredentialNonce,
        DateTimeOffset? issuedAt = null) =>
        await Oid4VciProofIssuance.BuildJwtProofAsync(
            holderPrivate,
            holderPublic,
            audience,
            nonce,
            issuedAt ?? NowInstant,
            HeaderSerializer,
            PayloadSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);


    //Mints a jwt proof whose header/payload are transformed before signing, so a single §F.4 MUST
    //can be violated while everything else stays well-formed. Mirrors the §F.1 header/claim shape
    //the production minter produces.
    private async Task<string> MintTamperedAsync(
        PrivateKeyMemory holderPrivate,
        PublicKeyMemory holderPublic,
        Action<Dictionary<string, object>>? tamperHeader = null,
        Action<Dictionary<string, object>>? tamperPayload = null)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(holderPrivate.Tag);
        JsonWebKey jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            holderPublic.Tag.Get<CryptoAlgorithm>(),
            holderPublic.Tag.Get<Purpose>(),
            holderPublic.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);

        Dictionary<string, object> header = new(StringComparer.Ordinal)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = Oid4VciProofIssuance.ProofJwtType,
            [Oid4VciCredentialParameterNames.Jwk] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownJwkMemberNames.Kty] = jwk.Kty!,
                [WellKnownJwkMemberNames.Crv] = jwk.Crv!,
                [WellKnownJwkMemberNames.X] = jwk.X!,
                [WellKnownJwkMemberNames.Y] = jwk.Y!
            }
        };

        Dictionary<string, object> payload = new(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Aud] = Audience,
            [WellKnownJwtClaimNames.Nonce] = CredentialNonce,
            [WellKnownJwtClaimNames.Iat] = NowInstant.ToUnixTimeSeconds()
        };

        tamperHeader?.Invoke(header);
        tamperPayload?.Invoke(payload);

        UnsignedJwt unsigned = new(new(header), new(payload));
        using JwsMessage jws = await unsigned.SignAsync(
            holderPrivate, HeaderSerializer, PayloadSerializer,
            TestSetup.Base64UrlEncoder, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
    }


    //Validates a single proof through the registry-resolving overload (the verifier is resolved
    //from the reconstructed holder key's algorithm), bound to the issuer aud + the c_nonce.
    private async Task<CredentialProofValidationResult> ValidateAsync(
        string proof, IReadOnlyCollection<string>? acceptableAlgorithms = null)
    {
        Func<string, bool> isAlgAcceptable = acceptableAlgorithms is null
            ? static _ => true
            : new HashSet<string>(acceptableAlgorithms, StringComparer.Ordinal).Contains;

        return await CredentialProofValidator.ValidateAsync(
            new CredentialProofValidationRequest
            {
                Proof = proof,
                ExpectedAudience = Audience,
                ExpectedNonce = CredentialNonce,
                NonceRequired = true
            },
            isAlgAcceptable,
            resolveProofKey: null,
            x509Verification: null,
            [],
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            TimeProvider,
            Pool,
            IatSkew,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    //The RFC 7638 thumbprint of the holder key, computed off its JWK projection — the bound-key
    //value a successful validation returns.
    private static string JwkThumbprintFor(PublicKeyMemory holderPublic) =>
        Verifiable.OAuth.Dpop.DpopJwkUtilities.ComputeThumbprint(
            holderPublic,
            CryptoFormatConversions.DefaultTagToJwaConverter(holderPublic.Tag),
            TestSetup.Base64UrlEncoder,
            Pool);
}
