using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Text;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Verifies <see cref="KeyAttestationVerifier"/> against an OID4VCI 1.0 Appendix D.1 key attestation
/// (<c>key-attestation+jwt</c>): the signature against the Wallet-Provider key its JOSE header
/// references (the §F.1 <c>jwk</c>/<c>x5c</c>/<c>kid</c> modes, via the shared
/// <see cref="Oid4VciHeaderKeyResolution"/>), the <c>exp</c> freshness, and the <c>nonce</c>. This is
/// the verifying counterpart of the structural-only <see cref="KeyAttestationParser"/>; the attestation
/// is signed by a Wallet-Provider key distinct from the attested keys it carries.
/// </summary>
[TestClass]
internal sealed class KeyAttestationVerifierTests
{
    public TestContext TestContext { get; set; } = null!;

    private static DateTimeOffset NowInstant { get; } = TestClock.CanonicalEpoch;
    private static TimeSpan ClockSkew { get; } = TimeSpan.FromMinutes(5);
    private const string AttestationNonce = "attestation-nonce-7Qm2";

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private FakeTimeProvider TimeProvider { get; } = new(NowInstant);

    /// <summary>A JOSE-correct serializer that does NOT escape '+' (the character in key-attestation+jwt).</summary>
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
    /// Appendix D.1 jwk happy path: an attestation whose JOSE header embeds the Wallet-Provider public
    /// key, signed by the matching private key, verifies; the result carries the parsed attestation.
    /// </summary>
    [TestMethod]
    public async Task JwkAttestationVerifies()
    {
        var wp = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory wpPublic = wp.PublicKey;
        using PrivateKeyMemory wpPrivate = wp.PrivateKey;

        string attestation = await MintJwkAttestationAsync(wpPrivate, wpPublic, NowInstant.AddHours(1), AttestationNonce)
            .ConfigureAwait(false);

        KeyAttestationVerificationResult result = await VerifyAsync(attestation).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, $"a genuine jwk attestation must verify; got {result.FailureReason}.");
        Assert.IsNotNull(result.Attestation);
        Assert.IsNotNull(result.Attestation.AttestedKeysJson);
        Assert.AreEqual(AttestationNonce, result.Attestation.Nonce);
    }


    /// <summary>
    /// Appendix D.1: "the signature on the attestation verifies". A tampered body breaks the signature,
    /// so an attestation whose payload was altered after signing is rejected with
    /// <see cref="KeyAttestationVerificationFailureReason.SignatureFailed"/>.
    /// </summary>
    [TestMethod]
    public async Task TamperedAttestationFailsSignature()
    {
        var wp = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory wpPublic = wp.PublicKey;
        using PrivateKeyMemory wpPrivate = wp.PrivateKey;

        string attestation = await MintJwkAttestationAsync(wpPrivate, wpPublic, NowInstant.AddHours(1), AttestationNonce)
            .ConfigureAwait(false);

        //Alter the nonce value inside the payload's JSON text — a content-level edit, not a byte flip,
        //so the payload stays well-formed JSON and the structural parse still succeeds; only the
        //signature no longer matches the altered signing input.
        string[] parts = attestation.Split('.');
        string payloadJson;
        using(IMemoryOwner<byte> payloadBytes = TestSetup.Base64UrlDecoder(parts[1], Pool))
        {
            payloadJson = Encoding.UTF8.GetString(payloadBytes.Memory.Span).TrimEnd('\0');
        }

        string tamperedJson = payloadJson.Replace(AttestationNonce, "attestation-nonce-tampered", StringComparison.Ordinal);
        string tamperedPayload = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(tamperedJson));
        string tampered = $"{parts[0]}.{tamperedPayload}.{parts[2]}";

        KeyAttestationVerificationResult result = await VerifyAsync(tampered).ConfigureAwait(false);

        Assert.AreEqual(KeyAttestationVerificationFailureReason.SignatureFailed, result.FailureReason);
    }


    /// <summary>
    /// Appendix D.1: a past <c>exp</c> (beyond the skew leniency) expires the attestation and its
    /// attested keys, so it is rejected with <see cref="KeyAttestationVerificationFailureReason.Expired"/>.
    /// </summary>
    [TestMethod]
    public async Task ExpiredAttestationRejected()
    {
        var wp = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory wpPublic = wp.PublicKey;
        using PrivateKeyMemory wpPrivate = wp.PrivateKey;

        string attestation = await MintJwkAttestationAsync(wpPrivate, wpPublic, NowInstant.AddHours(-1), AttestationNonce)
            .ConfigureAwait(false);

        KeyAttestationVerificationResult result = await VerifyAsync(attestation).ConfigureAwait(false);

        Assert.AreEqual(KeyAttestationVerificationFailureReason.Expired, result.FailureReason);
    }


    /// <summary>
    /// Appendix D.1: when the Issuer supplied a nonce, an attestation echoing a different value is
    /// rejected with <see cref="KeyAttestationVerificationFailureReason.NonceMismatch"/>.
    /// </summary>
    [TestMethod]
    public async Task NonceMismatchRejected()
    {
        var wp = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory wpPublic = wp.PublicKey;
        using PrivateKeyMemory wpPrivate = wp.PrivateKey;

        string attestation = await MintJwkAttestationAsync(wpPrivate, wpPublic, NowInstant.AddHours(1), "a-different-nonce")
            .ConfigureAwait(false);

        KeyAttestationVerificationResult result = await VerifyAsync(attestation).ConfigureAwait(false);

        Assert.AreEqual(KeyAttestationVerificationFailureReason.NonceMismatch, result.FailureReason);
    }


    /// <summary>
    /// Appendix D.1: when the Issuer required a nonce but the attestation carries none, it is rejected
    /// with <see cref="KeyAttestationVerificationFailureReason.NonceMissing"/>.
    /// </summary>
    [TestMethod]
    public async Task NonceMissingRejectedWhenRequired()
    {
        var wp = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory wpPublic = wp.PublicKey;
        using PrivateKeyMemory wpPrivate = wp.PrivateKey;

        string attestation = await MintJwkAttestationAsync(wpPrivate, wpPublic, NowInstant.AddHours(1), nonce: null)
            .ConfigureAwait(false);

        KeyAttestationVerificationResult result = await VerifyAsync(attestation).ConfigureAwait(false);

        Assert.AreEqual(KeyAttestationVerificationFailureReason.NonceMissing, result.FailureReason);
    }


    /// <summary>
    /// The unsigned two-part form the structural parser also accepts cannot be verified and is rejected
    /// with <see cref="KeyAttestationVerificationFailureReason.NotSigned"/>.
    /// </summary>
    [TestMethod]
    public async Task UnsignedTwoPartAttestationRejected()
    {
        var wp = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory wpPublic = wp.PublicKey;
        using PrivateKeyMemory wpPrivate = wp.PrivateKey;

        string attestation = await MintJwkAttestationAsync(wpPrivate, wpPublic, NowInstant.AddHours(1), AttestationNonce)
            .ConfigureAwait(false);

        //Drop the signature segment, leaving the unsigned header.payload form.
        string[] parts = attestation.Split('.');
        string unsigned = parts[0] + "." + parts[1];

        KeyAttestationVerificationResult result = await VerifyAsync(unsigned).ConfigureAwait(false);

        Assert.AreEqual(KeyAttestationVerificationFailureReason.NotSigned, result.FailureReason);
    }


    /// <summary>
    /// The application can reject an otherwise-valid algorithm by policy; a genuine attestation whose
    /// <c>alg</c> the policy predicate refuses is rejected with
    /// <see cref="KeyAttestationVerificationFailureReason.InvalidAlg"/>.
    /// </summary>
    [TestMethod]
    public async Task UnacceptableAlgRejected()
    {
        var wp = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory wpPublic = wp.PublicKey;
        using PrivateKeyMemory wpPrivate = wp.PrivateKey;

        string attestation = await MintJwkAttestationAsync(wpPrivate, wpPublic, NowInstant.AddHours(1), AttestationNonce)
            .ConfigureAwait(false);

        KeyAttestationVerificationResult result = await KeyAttestationVerifier.VerifyAsync(
            attestation,
            AttestationNonce,
            nonceRequired: true,
            isAttestationSigningAlgAcceptable: static _ => false,
            resolveWalletProviderKey: null,
            x509Verification: null,
            context: [],
            TestSetup.Base64UrlDecoder,
            TimeProvider,
            Pool,
            ClockSkew,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(KeyAttestationVerificationFailureReason.InvalidAlg, result.FailureReason);
    }


    /// <summary>
    /// Appendix D.1 x5c mode: an attestation whose header carries the [leaf, ca] chain — leaf key
    /// signing — verifies when the chain's CA is wired as a trust anchor on the context.
    /// </summary>
    [TestMethod]
    public async Task X5cAttestationVerifiesAgainstWiredAnchors()
    {
        using CertificateChainMaterial chain =
            TestCertificateChainProvider.CreateFreshP256ChainMaterial("wallet-provider.example.com", TimeProvider);

        string attestation = await MintX5cAttestationAsync(chain, NowInstant.AddHours(1), AttestationNonce)
            .ConfigureAwait(false);

        Oid4VciProofX509Verification x509 = BuildX509Verification();
        IReadOnlyList<PkiCertificateMemory> anchors = ParseAnchor(chain);
        try
        {
            ExchangeContext context = [];
            context.SetX509TrustAnchors(anchors);
            context.SetValidationTime(NowInstant);

            KeyAttestationVerificationResult result = await KeyAttestationVerifier.VerifyAsync(
                attestation,
                AttestationNonce,
                nonceRequired: true,
                isAttestationSigningAlgAcceptable: static _ => true,
                resolveWalletProviderKey: null,
                x509Verification: x509,
                context,
                TestSetup.Base64UrlDecoder,
                TimeProvider,
                Pool,
                ClockSkew,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(result.IsValid, $"x5c attestation must verify; got {result.FailureReason}.");
        }
        finally
        {
            DisposeAll(anchors);
        }
    }


    /// <summary>
    /// Appendix D.1 x5c negative: a self-consistent chain whose CA is NOT among the wired anchors does
    /// not chain to a trust anchor, so the Wallet-Provider key is unresolved and the attestation is
    /// rejected with <see cref="KeyAttestationVerificationFailureReason.KeyReferenceUnresolved"/>.
    /// </summary>
    [TestMethod]
    public async Task X5cAttestationFailsForeignAnchors()
    {
        using CertificateChainMaterial chain =
            TestCertificateChainProvider.CreateFreshP256ChainMaterial("wallet-provider.example.com", TimeProvider);
        using CertificateChainMaterial otherChain =
            TestCertificateChainProvider.CreateFreshP256ChainMaterial("other.example.com", TimeProvider);

        string attestation = await MintX5cAttestationAsync(chain, NowInstant.AddHours(1), AttestationNonce)
            .ConfigureAwait(false);

        Oid4VciProofX509Verification x509 = BuildX509Verification();
        IReadOnlyList<PkiCertificateMemory> foreignAnchors = ParseAnchor(otherChain);
        try
        {
            ExchangeContext context = [];
            context.SetX509TrustAnchors(foreignAnchors);
            context.SetValidationTime(NowInstant);

            KeyAttestationVerificationResult result = await KeyAttestationVerifier.VerifyAsync(
                attestation,
                AttestationNonce,
                nonceRequired: true,
                isAttestationSigningAlgAcceptable: static _ => true,
                resolveWalletProviderKey: null,
                x509Verification: x509,
                context,
                TestSetup.Base64UrlDecoder,
                TimeProvider,
                Pool,
                ClockSkew,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(KeyAttestationVerificationFailureReason.KeyReferenceUnresolved, result.FailureReason);
        }
        finally
        {
            DisposeAll(foreignAnchors);
        }
    }


    /// <summary>
    /// Appendix D.1 kid mode: an attestation referencing the Wallet-Provider key by <c>kid</c> resolves
    /// through the wired resolver to that key and verifies.
    /// </summary>
    [TestMethod]
    public async Task KidAttestationVerifiesThroughResolver()
    {
        var wp = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory wpPublic = wp.PublicKey;
        using PrivateKeyMemory wpPrivate = wp.PrivateKey;

        const string Kid = "https://wallet-provider.example.com/keys#wp-1";
        string attestation = await MintKidAttestationAsync(wpPrivate, Kid, NowInstant.AddHours(1), AttestationNonce)
            .ConfigureAwait(false);

        ValueTask<PublicKeyMemory?> resolver(string kid, string algorithm, ExchangeContext context, CancellationToken ct) => string.Equals(kid, Kid, StringComparison.Ordinal)
                ? ValueTask.FromResult<PublicKeyMemory?>(CopyPublicKey(wpPublic))
                : ValueTask.FromResult<PublicKeyMemory?>(null);

        KeyAttestationVerificationResult result = await KeyAttestationVerifier.VerifyAsync(
            attestation,
            AttestationNonce,
            nonceRequired: true,
            isAttestationSigningAlgAcceptable: static _ => true,
            resolveWalletProviderKey: resolver,
            x509Verification: null,
            context: [],
            TestSetup.Base64UrlDecoder,
            TimeProvider,
            Pool,
            ClockSkew,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, $"kid attestation must verify; got {result.FailureReason}.");
    }


    /// <summary>
    /// Appendix D.1 kid negative: a <c>kid</c> the wired resolver cannot dereference yields no key, so
    /// the reference is unresolved and the attestation is rejected.
    /// </summary>
    [TestMethod]
    public async Task KidAttestationWithUnresolvableKidFailsClosed()
    {
        var wp = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory wpPublic = wp.PublicKey;
        using PrivateKeyMemory wpPrivate = wp.PrivateKey;

        string attestation = await MintKidAttestationAsync(
            wpPrivate, "https://wallet-provider.example.com/keys#unknown", NowInstant.AddHours(1), AttestationNonce)
            .ConfigureAwait(false);

        static ValueTask<PublicKeyMemory?> resolver(string kid, string algorithm, ExchangeContext context, CancellationToken ct) => ValueTask.FromResult<PublicKeyMemory?>(null);

        KeyAttestationVerificationResult result = await KeyAttestationVerifier.VerifyAsync(
            attestation,
            AttestationNonce,
            nonceRequired: true,
            isAttestationSigningAlgAcceptable: static _ => true,
            resolveWalletProviderKey: resolver,
            x509Verification: null,
            context: [],
            TestSetup.Base64UrlDecoder,
            TimeProvider,
            Pool,
            ClockSkew,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(KeyAttestationVerificationFailureReason.KeyReferenceUnresolved, result.FailureReason);
    }


    /// <summary>
    /// RFC 7515 §4: "The Header Parameter names within the JOSE Header ... MUST be unique." A
    /// header repeating the <c>kid</c> member is rejected as <c>Malformed</c> before the
    /// Wallet-Provider key is resolved; the same header and payload with the duplicate removed
    /// verify. The header and payload are built by hand, never through
    /// <see cref="HeaderSerializer"/> or <see cref="PayloadSerializer"/>, and signed over their
    /// exact bytes with the project's own signing primitive, so only the header well-formedness
    /// gate — not an invalid signature — can be responsible for the refusal.
    /// </summary>
    [TestMethod]
    public async Task RejectsAttestationHeaderWithDuplicateKidMember()
    {
        var wp = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory wpPublic = wp.PublicKey;
        using PrivateKeyMemory wpPrivate = wp.PrivateKey;

        const string Kid = "https://wallet-provider.example.com/keys#wp-1";
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(wpPrivate.Tag);
        DateTimeOffset expiresAt = NowInstant.AddHours(1);

        string payloadJson =
            "{\"attested_keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\"," +
            "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\"," +
            "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}]," +
            $"\"iat\":{NowInstant.ToUnixTimeSeconds()},\"exp\":{expiresAt.ToUnixTimeSeconds()}," +
            $"\"nonce\":\"{AttestationNonce}\"}}";

        string duplicateHeaderJson =
            "{\"alg\":\"" + algorithm + "\",\"typ\":\"key-attestation+jwt\"," +
            "\"kid\":\"" + Kid + "\",\"kid\":\"" + Kid + "\"}";

        string duplicateAttestation =
            await SignRawAsync(wpPrivate, duplicateHeaderJson, payloadJson).ConfigureAwait(false);

        KeyAttestationVerificationResult duplicateResult =
            await VerifyAsync(duplicateAttestation).ConfigureAwait(false);
        Assert.AreEqual(KeyAttestationVerificationFailureReason.Malformed, duplicateResult.FailureReason);

        string singleHeaderJson =
            "{\"alg\":\"" + algorithm + "\",\"typ\":\"key-attestation+jwt\",\"kid\":\"" + Kid + "\"}";

        string acceptedAttestation =
            await SignRawAsync(wpPrivate, singleHeaderJson, payloadJson).ConfigureAwait(false);

        ValueTask<PublicKeyMemory?> resolver(string kid, string algorithm, ExchangeContext context, CancellationToken ct) =>
            string.Equals(kid, Kid, StringComparison.Ordinal)
                ? ValueTask.FromResult<PublicKeyMemory?>(CopyPublicKey(wpPublic))
                : ValueTask.FromResult<PublicKeyMemory?>(null);

        KeyAttestationVerificationResult acceptedResult = await KeyAttestationVerifier.VerifyAsync(
            acceptedAttestation,
            AttestationNonce,
            nonceRequired: true,
            isAttestationSigningAlgAcceptable: static _ => true,
            resolveWalletProviderKey: resolver,
            x509Verification: null,
            context: [],
            TestSetup.Base64UrlDecoder,
            TimeProvider,
            Pool,
            ClockSkew,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(acceptedResult.IsValid,
            $"the same attestation without the duplicate must verify; got {acceptedResult.FailureReason}.");
    }


    /// <summary>
    /// A constrained attestation whose <c>key_storage</c> and <c>user_authentication</c> arrays each
    /// carry a value the caller's accepted-value sets also carry validates:
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4">OID4VCI
    /// 1.0 §12.2.4</see>'s constraint arrays are "accepted by the Credential Issuer" membership sets, so
    /// at least one match on each side is enough.
    /// </summary>
    [TestMethod]
    public void SatisfiedConstraintsValidate()
    {
        KeyAttestation attestation = BuildAttestation(
            keyStorageJson: "[\"iso_18045_moderate\",\"iso_18045_high\"]",
            userAuthenticationJson: "[\"iso_18045_basic\"]");

        KeyAttestationVerificationResult result = KeyAttestationVerifier.CheckAssuranceConstraints(
            attestation, ["iso_18045_high"], ["iso_18045_basic"], Pool);

        Assert.IsTrue(result.IsValid, $"a matching attested value on each side must satisfy both constraints; got {result.FailureReason}.");
        Assert.AreSame(attestation, result.Attestation);
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-D.2">OID4VCI
    /// 1.0 Appendix D.2</see>: <c>iso_18045_high</c> "MUST be used when key storage or user
    /// authentication is resistant to attack with attack potential 'High'", equivalent to VAN.5, while
    /// <c>iso_18045_moderate</c> "MUST be used when ... 'Moderate'", equivalent to VAN.4 — two DISTINCT
    /// bands, never one ranking the other satisfies. An attestation whose <c>key_storage</c> is only
    /// <c>iso_18045_high</c> does not satisfy a constraint listing only <c>iso_18045_moderate</c>: the
    /// check is membership, not ordering.
    /// </summary>
    [TestMethod]
    public void KeyStorageConstraintUnsatisfiedWhenNoAttestedValueIsAccepted()
    {
        KeyAttestation attestation = BuildAttestation(keyStorageJson: "[\"iso_18045_high\"]", userAuthenticationJson: null);

        KeyAttestationVerificationResult result = KeyAttestationVerifier.CheckAssuranceConstraints(
            attestation, ["iso_18045_moderate"], acceptedUserAuthenticationValues: null, pool: Pool);

        Assert.AreEqual(KeyAttestationVerificationFailureReason.KeyStorageConstraintUnsatisfied, result.FailureReason);
    }


    /// <summary>
    /// The same membership rule applies to <c>user_authentication</c>: an attestation whose value is
    /// <c>iso_18045_basic</c> does not satisfy a constraint listing only <c>iso_18045_high</c>.
    /// </summary>
    [TestMethod]
    public void UserAuthenticationConstraintUnsatisfiedWhenNoAttestedValueIsAccepted()
    {
        KeyAttestation attestation = BuildAttestation(keyStorageJson: null, userAuthenticationJson: "[\"iso_18045_basic\"]");

        KeyAttestationVerificationResult result = KeyAttestationVerifier.CheckAssuranceConstraints(
            attestation, acceptedKeyStorageValues: null, ["iso_18045_high"], Pool);

        Assert.AreEqual(KeyAttestationVerificationFailureReason.UserAuthenticationConstraintUnsatisfied, result.FailureReason);
    }


    /// <summary>
    /// A non-empty constraint asks a membership question of the attested array; an attested value that
    /// is not itself a well-formed JSON array of strings cannot answer that question, so it fails with
    /// <see cref="KeyAttestationVerificationFailureReason.AssuranceConstraintValuesMalformed"/> rather
    /// than a silent unsatisfied.
    /// </summary>
    [TestMethod]
    public void MalformedAttestedArrayAnswersAssuranceConstraintValuesMalformed()
    {
        KeyAttestation attestation = BuildAttestation(keyStorageJson: "\"iso_18045_moderate\"", userAuthenticationJson: null);

        KeyAttestationVerificationResult result = KeyAttestationVerifier.CheckAssuranceConstraints(
            attestation, ["iso_18045_moderate"], acceptedUserAuthenticationValues: null, pool: Pool);

        Assert.AreEqual(KeyAttestationVerificationFailureReason.AssuranceConstraintValuesMalformed, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4">OID4VCI
    /// 1.0 §12.2.4</see>: <c>key_storage</c> and <c>user_authentication</c> are each "OPTIONAL. A
    /// non-empty array" — an absent constraint (here, both are <see langword="null"/>) constrains
    /// nothing, whatever the attestation carries, including when it carries nothing at all.
    /// </summary>
    [TestMethod]
    public void AbsentConstraintIsSatisfiedByAnyAttestation()
    {
        KeyAttestation attestation = BuildAttestation(keyStorageJson: null, userAuthenticationJson: null);

        KeyAttestationVerificationResult result = KeyAttestationVerifier.CheckAssuranceConstraints(
            attestation, acceptedKeyStorageValues: null, acceptedUserAuthenticationValues: null, pool: Pool);

        Assert.IsTrue(result.IsValid, $"an absent constraint must constrain nothing; got {result.FailureReason}.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-D.2">OID4VCI
    /// 1.0 Appendix D.2</see>: "Specifications that extend this list MUST choose collision-resistant
    /// values", and when ISO 18045 is not used "ecosystems may define their own values", "RECOMMENDED"
    /// to be a URL — compared the same membership way as the four built-in values, by ordinal string
    /// equality.
    /// </summary>
    [TestMethod]
    public void EcosystemDefinedUrlValueMatchesByOrdinalEquality()
    {
        const string EcosystemValue = "https://issuer.example/assurance/enhanced";
        KeyAttestation attestation = BuildAttestation(keyStorageJson: $"[\"{EcosystemValue}\"]", userAuthenticationJson: null);

        KeyAttestationVerificationResult matching = KeyAttestationVerifier.CheckAssuranceConstraints(
            attestation, [EcosystemValue], acceptedUserAuthenticationValues: null, pool: Pool);

        Assert.IsTrue(matching.IsValid, $"an identical ecosystem-defined URL must match; got {matching.FailureReason}.");

        KeyAttestationVerificationResult differentlyCased = KeyAttestationVerifier.CheckAssuranceConstraints(
            attestation, [EcosystemValue.ToUpperInvariant()], acceptedUserAuthenticationValues: null, pool: Pool);

        Assert.AreEqual(KeyAttestationVerificationFailureReason.KeyStorageConstraintUnsatisfied, differentlyCased.FailureReason,
            "the comparison is ordinal, so a differently-cased URL must not match.");
    }


    //A minimal already-verified KeyAttestation, standing in for KeyAttestationVerifier.VerifyAsync's
    //output — CheckAssuranceConstraints takes the verified record directly, so no JWS is minted here.
    private static KeyAttestation BuildAttestation(string? keyStorageJson, string? userAuthenticationJson) =>
        new()
        {
            AttestedKeysJson = "[{\"kty\":\"EC\",\"crv\":\"P-256\"," +
                "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\"," +
                "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}]",
            KeyStorageJson = keyStorageJson,
            UserAuthenticationJson = userAuthenticationJson
        };


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


    //Mints an Appendix D.1 attestation whose JOSE header embeds the Wallet-Provider public key (jwk
    //mode), signed by the Wallet-Provider private key.
    private async Task<string> MintJwkAttestationAsync(
        PrivateKeyMemory wpPrivate, PublicKeyMemory wpPublic, DateTimeOffset expiresAt, string? nonce)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(wpPrivate.Tag);
        JsonWebKey jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            wpPublic.Tag.Get<CryptoAlgorithm>(),
            wpPublic.Tag.Get<Purpose>(),
            wpPublic.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);

        Dictionary<string, object> header = new(StringComparer.Ordinal)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = AttestationProofParameterNames.KeyAttestationJwtType,
            [WellKnownJoseHeaderNames.Jwk] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownJwkMemberNames.Kty] = jwk.Kty!,
                [WellKnownJwkMemberNames.Crv] = jwk.Crv!,
                [WellKnownJwkMemberNames.X] = jwk.X!,
                [WellKnownJwkMemberNames.Y] = jwk.Y!
            }
        };

        return await SignAttestationAsync(wpPrivate, header, expiresAt, nonce).ConfigureAwait(false);
    }


    //Mints an Appendix D.1 attestation whose JOSE header carries the [leaf, ca] x5c chain, signed by
    //the chain's leaf private key (x5c mode).
    private async Task<string> MintX5cAttestationAsync(
        CertificateChainMaterial chain, DateTimeOffset expiresAt, string? nonce)
    {
        string leafBase64 = Convert.ToBase64String(chain.LeafDerBytes.AsReadOnlyMemory().ToArray());
        string caBase64 = Convert.ToBase64String(chain.CaDerBytes.AsReadOnlyMemory().ToArray());
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(chain.LeafSigningKey.Tag);

        Dictionary<string, object> header = new(StringComparer.Ordinal)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = AttestationProofParameterNames.KeyAttestationJwtType,
            [WellKnownJwkMemberNames.X5c] = new[] { leafBase64, caBase64 }
        };

        return await SignAttestationAsync(chain.LeafSigningKey, header, expiresAt, nonce).ConfigureAwait(false);
    }


    //Mints an Appendix D.1 attestation whose JOSE header references the Wallet-Provider key by kid,
    //signed by that key (kid mode).
    private async Task<string> MintKidAttestationAsync(
        PrivateKeyMemory wpPrivate, string kid, DateTimeOffset expiresAt, string? nonce)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(wpPrivate.Tag);

        Dictionary<string, object> header = new(StringComparer.Ordinal)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = AttestationProofParameterNames.KeyAttestationJwtType,
            [WellKnownJwkMemberNames.Kid] = kid
        };

        return await SignAttestationAsync(wpPrivate, header, expiresAt, nonce).ConfigureAwait(false);
    }


    //Signs the supplied header with an Appendix D.1 body (the REQUIRED attested_keys array plus iat,
    //exp, and an optional nonce) and serializes the compact JWS.
    private async Task<string> SignAttestationAsync(
        PrivateKeyMemory signingKey, Dictionary<string, object> header, DateTimeOffset expiresAt, string? nonce)
    {
        Dictionary<string, object> payload = new(StringComparer.Ordinal)
        {
            [AttestationProofParameterNames.AttestedKeys] = new object[]
            {
                new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    [WellKnownJwkMemberNames.Kty] = "EC",
                    [WellKnownJwkMemberNames.Crv] = "P-256",
                    [WellKnownJwkMemberNames.X] = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                    [WellKnownJwkMemberNames.Y] = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
                }
            },
            [WellKnownJwtClaimNames.Iat] = NowInstant.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = expiresAt.ToUnixTimeSeconds()
        };

        if(nonce is not null)
        {
            payload[WellKnownJwtClaimNames.Nonce] = nonce;
        }

        UnsignedJwt unsigned = new(new(header), new(payload));
        using JwsMessage jws = await unsigned.SignAsync(
            signingKey, HeaderSerializer, PayloadSerializer,
            TestSetup.Base64UrlEncoder, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
    }


    //The registry-resolving verifier overload, bound to the attestation nonce, with no kid/x5c seam
    //(the jwk mode is self-contained).
    private async Task<KeyAttestationVerificationResult> VerifyAsync(string attestation) =>
        await KeyAttestationVerifier.VerifyAsync(
            attestation,
            AttestationNonce,
            nonceRequired: true,
            isAttestationSigningAlgAcceptable: static _ => true,
            resolveWalletProviderKey: null,
            x509Verification: null,
            context: [],
            TestSetup.Base64UrlDecoder,
            TimeProvider,
            Pool,
            ClockSkew,
            TestContext.CancellationToken).ConfigureAwait(false);


    private static Oid4VciProofX509Verification BuildX509Verification() =>
        new()
        {
            ParseX5c = MicrosoftX509Functions.ParseX5c,
            ValidateChain = MicrosoftX509Functions.ValidateChainAsync,
            MemoryPool = Pool
        };


    private static IReadOnlyList<PkiCertificateMemory> ParseAnchor(CertificateChainMaterial chain) =>
        MicrosoftX509Functions.ParseX5c(
            [Convert.ToBase64String(chain.CaDerBytes.AsReadOnlyMemory().ToArray())], Pool);


    //A defensive copy of the Wallet-Provider public key so the verifier's dispose does not free the
    //test-owned key.
    private static PublicKeyMemory CopyPublicKey(PublicKeyMemory source)
    {
        ReadOnlySpan<byte> material = source.AsReadOnlySpan();
        IMemoryOwner<byte> owner = Pool.Rent(material.Length);
        material.CopyTo(owner.Memory.Span);

        return new PublicKeyMemory(owner, source.Tag);
    }


    private static void DisposeAll(IReadOnlyList<PkiCertificateMemory> anchors)
    {
        foreach(PkiCertificateMemory anchor in anchors)
        {
            anchor.Dispose();
        }
    }
}
