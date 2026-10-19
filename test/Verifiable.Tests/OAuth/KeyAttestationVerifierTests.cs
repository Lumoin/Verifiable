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
            (Dictionary<string, object?>)header, JoseSerializationOptions);

    private static JwtPayloadSerializer PayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object?>)payload, JoseSerializationOptions);


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
            KeyAttestationProofUse.NotStated,
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
                KeyAttestationProofUse.NotStated,
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
                KeyAttestationProofUse.NotStated,
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
            KeyAttestationProofUse.NotStated,
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
            KeyAttestationProofUse.NotStated,
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
            await SignRawAsync(wpPrivate, duplicateHeaderJson, payloadJson, TestContext.CancellationToken).ConfigureAwait(false);

        KeyAttestationVerificationResult duplicateResult =
            await VerifyAsync(duplicateAttestation).ConfigureAwait(false);
        Assert.AreEqual(KeyAttestationVerificationFailureReason.Malformed, duplicateResult.FailureReason);

        string singleHeaderJson =
            "{\"alg\":\"" + algorithm + "\",\"typ\":\"key-attestation+jwt\",\"kid\":\"" + Kid + "\"}";

        string acceptedAttestation =
            await SignRawAsync(wpPrivate, singleHeaderJson, payloadJson, TestContext.CancellationToken).ConfigureAwait(false);

        ValueTask<PublicKeyMemory?> resolver(string kid, string algorithm, ExchangeContext context, CancellationToken ct) =>
            string.Equals(kid, Kid, StringComparison.Ordinal)
                ? ValueTask.FromResult<PublicKeyMemory?>(CopyPublicKey(wpPublic))
                : ValueTask.FromResult<PublicKeyMemory?>(null);

        KeyAttestationVerificationResult acceptedResult = await KeyAttestationVerifier.VerifyAsync(
            acceptedAttestation,
            KeyAttestationProofUse.NotStated,
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
    /// OID4VCI 1.0 Appendix D.1 has <c>exp</c> an Integer "for the time at which the key attestation and the key(s) it is
    /// attesting expire", a NumericDate (RFC 7519 Section 2). A signed attestation whose <c>exp</c> is present and is no
    /// NumericDate - a string of digits, a count no clock represents, a literal - is refused through verification as
    /// <see cref="KeyAttestationVerificationFailureReason.Malformed"/>, never verified as one carrying no expiry.
    /// </summary>
    /// <param name="exp">The <c>exp</c> member's JSON value.</param>
    /// <returns>A task completing once the attestation is judged.</returns>
    [TestMethod]
    [DataRow("\"1893456000\"")]
    [DataRow("1e400")]
    [DataRow("true")]
    [DataRow("null")]
    public async Task AnAttestationWhoseExpIsNoNumericDateIsRefused(string exp)
    {
        var result = await VerifyHandBuiltAttestationAsync($"\"iat\":{NowInstant.ToUnixTimeSeconds()},\"exp\":{exp},", KeyAttestationProofUse.NotStated).ConfigureAwait(false);

        Assert.AreEqual(KeyAttestationVerificationFailureReason.Malformed, result.FailureReason, $"exp {exp}");
    }


    /// <summary>
    /// OID4VCI 1.0 Appendix D.1 has <c>iat</c> an Integer "for the time at which the key attestation was issued", a NumericDate
    /// (RFC 7519 Section 2). A signed attestation whose <c>iat</c> is present and is no NumericDate - a string of digits, a count
    /// no clock represents, an object - is refused through verification as
    /// <see cref="KeyAttestationVerificationFailureReason.Malformed"/>.
    /// </summary>
    /// <param name="iat">The <c>iat</c> member's JSON value.</param>
    /// <returns>A task completing once the attestation is judged.</returns>
    [TestMethod]
    [DataRow("\"1700000000\"")]
    [DataRow("1e400")]
    [DataRow("{}")]
    public async Task AnAttestationWhoseIatIsNoNumericDateIsRefused(string iat)
    {
        var result = await VerifyHandBuiltAttestationAsync($"\"iat\":{iat},\"exp\":{NowInstant.AddHours(1).ToUnixTimeSeconds()},", KeyAttestationProofUse.NotStated).ConfigureAwait(false);

        Assert.AreEqual(KeyAttestationVerificationFailureReason.Malformed, result.FailureReason, $"iat {iat}");
    }


    /// <summary>
    /// OID4VCI 1.0 Appendix D.1 has each of <c>iat</c> and <c>exp</c> an "Integer for the time ...": a signed attestation whose
    /// <c>exp</c> or <c>iat</c> carries a fraction is refused as <see cref="KeyAttestationVerificationFailureReason.Malformed"/>,
    /// never truncated to the second before it; the integral control beside each, signed and verified the same way, verifies and
    /// carries both dates as written.
    /// </summary>
    /// <returns>A task completing once the attestations are judged.</returns>
    [TestMethod]
    public async Task AnAttestationWhoseDatesCarryAFractionIsRefusedAndItsIntegralControlVerifies()
    {
        var issuedAt = NowInstant.ToUnixTimeSeconds();
        var expiresAt = NowInstant.AddHours(1).ToUnixTimeSeconds();

        var fractionalExp = await VerifyHandBuiltAttestationAsync($"\"iat\":{issuedAt},\"exp\":{expiresAt}.5,", KeyAttestationProofUse.NotStated).ConfigureAwait(false);
        var fractionalIat = await VerifyHandBuiltAttestationAsync($"\"iat\":{issuedAt}.5,\"exp\":{expiresAt},", KeyAttestationProofUse.NotStated).ConfigureAwait(false);
        var integral = await VerifyHandBuiltAttestationAsync($"\"iat\":{issuedAt},\"exp\":{expiresAt},", KeyAttestationProofUse.NotStated).ConfigureAwait(false);

        Assert.AreEqual(KeyAttestationVerificationFailureReason.Malformed, fractionalExp.FailureReason, "An exp with a fraction is no integer.");
        Assert.AreEqual(KeyAttestationVerificationFailureReason.Malformed, fractionalIat.FailureReason, "An iat with a fraction is no integer.");
        Assert.IsTrue(integral.IsValid, $"An attestation with integral dates verifies; got {integral.FailureReason}.");
        Assert.IsNotNull(integral.Attestation, "A verified attestation is carried.");
        Assert.IsNotNull(integral.Attestation.ExpiresAt, "The attestation carries its exp.");
        Assert.AreEqual(0, integral.Attestation.IssuedAt.CompareTo(NumericDate.FromUnixTimeSeconds(issuedAt)), "The iat is carried as written.");
        Assert.AreEqual(0, integral.Attestation.ExpiresAt.CompareTo(NumericDate.FromUnixTimeSeconds(expiresAt)), "The exp is carried as written.");
    }


    /// <summary>
    /// OID4VCI 1.0 Appendix D.1 has <c>iat</c> REQUIRED: a signed attestation omitting it is refused as
    /// <see cref="KeyAttestationVerificationFailureReason.Malformed"/>, whatever use it is verified for.
    /// </summary>
    /// <param name="proofUse">The use the attestation is verified for.</param>
    /// <returns>A task completing once the attestation is judged.</returns>
    [TestMethod]
    [DataRow(KeyAttestationProofUse.NotStated)]
    [DataRow(KeyAttestationProofUse.JwtProof)]
    [DataRow(KeyAttestationProofUse.AttestationProof)]
    public async Task AnAttestationOmittingIatIsRefused(KeyAttestationProofUse proofUse)
    {
        var result = await VerifyHandBuiltAttestationAsync($"\"exp\":{NowInstant.AddHours(1).ToUnixTimeSeconds()},", proofUse).ConfigureAwait(false);

        Assert.AreEqual(KeyAttestationVerificationFailureReason.Malformed, result.FailureReason, proofUse.ToString());
    }


    /// <summary>
    /// OID4VCI 1.0 Appendix D.1 has <c>exp</c> OPTIONAL and "MUST be present if the attestation is used with the JWT proof type":
    /// a signed attestation omitting it is refused as <see cref="KeyAttestationVerificationFailureReason.ExpiryNotPresented"/>
    /// when verified for that use, and verifies, carrying no expiry, when verified for the attestation proof type or for a use the
    /// caller does not state; the same attestation carrying an <c>exp</c> verifies for the JWT proof type.
    /// </summary>
    /// <param name="proofUse">The use the attestation is verified for.</param>
    /// <param name="omittedExpRefused">Whether the attestation omitting exp is refused.</param>
    /// <returns>A task completing once the attestations are judged.</returns>
    [TestMethod]
    [DataRow(KeyAttestationProofUse.JwtProof, true)]
    [DataRow(KeyAttestationProofUse.AttestationProof, false)]
    [DataRow(KeyAttestationProofUse.NotStated, false)]
    public async Task AnOmittedExpIsRefusedOnlyForTheJwtProofUse(KeyAttestationProofUse proofUse, bool omittedExpRefused)
    {
        var issuedAt = NowInstant.ToUnixTimeSeconds();

        var undated = await VerifyHandBuiltAttestationAsync($"\"iat\":{issuedAt},", proofUse).ConfigureAwait(false);
        var dated = await VerifyHandBuiltAttestationAsync($"\"iat\":{issuedAt},\"exp\":{NowInstant.AddHours(1).ToUnixTimeSeconds()},", proofUse).ConfigureAwait(false);

        Assert.AreEqual(omittedExpRefused ? KeyAttestationVerificationFailureReason.ExpiryNotPresented : null, undated.FailureReason, proofUse.ToString());
        Assert.IsTrue(omittedExpRefused || undated.Attestation is { ExpiresAt: null }, "An attestation verified without exp carries no expiry of its own.");
        Assert.IsTrue(dated.IsValid, $"The attestation carrying exp verifies for {proofUse}; got {dated.FailureReason}.");
    }


    /// <summary>
    /// A signed attestation one of whose segments is no base64url text (RFC 7515 section 7.1) is no attestation: the structural
    /// parser answers it as none and the verifier refuses it as <see cref="KeyAttestationVerificationFailureReason.Malformed"/>,
    /// the decoder's refusal being the one failure read as malformed input.
    /// </summary>
    /// <param name="segment">The segment written as no base64url text: 0 the header, 1 the body.</param>
    /// <returns>A task completing once the attestation is judged.</returns>
    [TestMethod]
    [DataRow(0, DisplayName = "The header segment")]
    [DataRow(1, DisplayName = "The body segment")]
    public async Task AnAttestationSegmentOfNoBase64UrlTextIsMalformed(int segment)
    {
        var dates = $"\"iat\":{NowInstant.ToUnixTimeSeconds()},\"exp\":{NowInstant.AddHours(1).ToUnixTimeSeconds()},";

        string notBase64Url(string attestation)
        {
            var segments = attestation.Split('.');
            segments[segment] = "*no*base64url*";

            return string.Join('.', segments);
        }

        var result = await VerifyHandBuiltAttestationAsync(dates, KeyAttestationProofUse.JwtProof, notBase64Url, TestSetup.Base64UrlDecoder).ConfigureAwait(false);
        var control = await VerifyHandBuiltAttestationAsync(dates, KeyAttestationProofUse.JwtProof).ConfigureAwait(false);
        var parsed = KeyAttestationParser.TryParse(notBase64Url($"{Base64UrlOf("{}")}.{Base64UrlOf("{}")}.c2ln"), TestSetup.Base64UrlDecoder, Pool, out var attestation);

        Assert.AreEqual(KeyAttestationVerificationFailureReason.Malformed, result.FailureReason);
        Assert.IsTrue(control.IsValid, $"The same attestation with every segment base64url text verifies; got {control.FailureReason}.");
        Assert.IsFalse(parsed, "The structural parser answers a segment of no base64url text as no attestation.");
        Assert.IsNull(attestation);
    }


    /// <summary>
    /// A failure of the base64url decoder other than its refusal of the text - here one the decoder raises as an invalid operation
    /// once the structural parser has read both segments, at the verifier's own reading of the header - is a fault of the
    /// decoder, never read as a malformed attestation: it surfaces to the caller as the exception it is.
    /// </summary>
    /// <returns>A task completing once the fault has surfaced.</returns>
    [TestMethod]
    public async Task ADecoderFaultSurfacesAndIsNeverReadAsAMalformedAttestation()
    {
        var dates = $"\"iat\":{NowInstant.ToUnixTimeSeconds()},\"exp\":{NowInstant.AddHours(1).ToUnixTimeSeconds()},";
        var decodings = 0;

        IMemoryOwner<byte> faultingDecoder(ReadOnlySpan<char> text, BaseMemoryPool pool) =>
            ++decodings <= 2 ? TestSetup.Base64UrlDecoder(text, pool) : throw new InvalidOperationException("The decoder's own fault.");

        var fault = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () => await VerifyHandBuiltAttestationAsync(
            dates, KeyAttestationProofUse.JwtProof, static attestation => attestation, faultingDecoder).ConfigureAwait(false));

        Assert.AreEqual("The decoder's own fault.", fault.Message);
    }


    /// <summary>
    /// The use an attestation is verified for decides whether its <c>exp</c> is required (OID4VCI 1.0 Appendix D.1): a value of no
    /// use <see cref="KeyAttestationProofUse"/> defines is refused as an argument out of its range, never read as a use that
    /// requires no expiry.
    /// </summary>
    /// <returns>A task completing once the refusal is observed.</returns>
    [TestMethod]
    public async Task AProofUseOfNoDefinedValueIsRefused()
    {
        var undefinedUse = (KeyAttestationProofUse)99;

        var refusal = await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(async () => await VerifyHandBuiltAttestationAsync(
            $"\"iat\":{NowInstant.ToUnixTimeSeconds()},", undefinedUse).ConfigureAwait(false));

        Assert.AreEqual("proofUse", refusal.ParamName);
    }


    /// <summary>The base64url text of a JSON text's UTF-8 bytes.</summary>
    /// <param name="json">The JSON text.</param>
    /// <returns>The base64url text.</returns>
    private static string Base64UrlOf(string json) => TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(json));


    /// <summary>
    /// Signs, over their exact bytes, a header referencing the Wallet-Provider key by <c>kid</c> and a body carrying the attested
    /// keys, the date members given and the nonce, and verifies it through the resolver that dereferences that <c>kid</c>, for the
    /// use given.
    /// </summary>
    /// <param name="dateMembers">The body's date members as JSON text, each followed by a comma.</param>
    /// <param name="proofUse">The use the attestation is verified for.</param>
    /// <returns>The verification result.</returns>
    private Task<KeyAttestationVerificationResult> VerifyHandBuiltAttestationAsync(string dateMembers, KeyAttestationProofUse proofUse) =>
        VerifyHandBuiltAttestationAsync(dateMembers, proofUse, static attestation => attestation, TestSetup.Base64UrlDecoder);


    /// <summary>
    /// Signs, over their exact bytes, a header referencing the Wallet-Provider key by <c>kid</c> and a body carrying the attested
    /// keys, the date members given and the nonce, has <paramref name="alter"/> rewrite the signed compact attestation, and
    /// verifies the result through the resolver that dereferences that <c>kid</c>, for the use given, decoding its segments with
    /// <paramref name="base64UrlDecoder"/>.
    /// </summary>
    /// <param name="dateMembers">The body's date members as JSON text, each followed by a comma.</param>
    /// <param name="proofUse">The use the attestation is verified for.</param>
    /// <param name="alter">Rewrites the signed compact attestation before it is verified.</param>
    /// <param name="base64UrlDecoder">The decoder the verifier decodes the segments with.</param>
    /// <returns>The verification result.</returns>
    private async Task<KeyAttestationVerificationResult> VerifyHandBuiltAttestationAsync(
        string dateMembers, KeyAttestationProofUse proofUse, Func<string, string> alter, DecodeDelegate base64UrlDecoder)
    {
        var wp = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var wpPublic = wp.PublicKey;
        using var wpPrivate = wp.PrivateKey;

        const string Kid = "https://wallet-provider.example.com/keys#wp-1";
        var algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(wpPrivate.Tag);

        var payloadJson =
            "{\"attested_keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\"," +
            "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\"," +
            "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}]," +
            dateMembers +
            $"\"nonce\":\"{AttestationNonce}\"}}";

        var headerJson = "{\"alg\":\"" + algorithm + "\",\"typ\":\"key-attestation+jwt\",\"kid\":\"" + Kid + "\"}";
        var attestation = alter(await SignRawAsync(wpPrivate, headerJson, payloadJson, TestContext.CancellationToken).ConfigureAwait(false));

        ValueTask<PublicKeyMemory?> resolver(string kid, string algorithm, ExchangeContext context, CancellationToken ct) =>
            string.Equals(kid, Kid, StringComparison.Ordinal)
                ? ValueTask.FromResult<PublicKeyMemory?>(CopyPublicKey(wpPublic))
                : ValueTask.FromResult<PublicKeyMemory?>(null);

        return await KeyAttestationVerifier.VerifyAsync(
            attestation,
            proofUse,
            AttestationNonce,
            nonceRequired: true,
            isAttestationSigningAlgAcceptable: static _ => true,
            resolveWalletProviderKey: resolver,
            x509Verification: null,
            context: [],
            base64UrlDecoder,
            TimeProvider,
            Pool,
            ClockSkew,
            TestContext.CancellationToken).ConfigureAwait(false);
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
            UserAuthenticationJson = userAuthenticationJson,
            IssuedAt = NowInstant
        };


    //Signs a hand-built header/payload JSON pair over their exact UTF-8 bytes with the project's
    //signing primitive, never through HeaderSerializer/PayloadSerializer — proves the well-formedness
    //gate's refusal is independent of how a JSON serializer would itself react to a repeated member.
    private static async Task<string> SignRawAsync(PrivateKeyMemory signingKey, string headerJson, string payloadJson, CancellationToken cancellationToken)
    {
        string headerB64 = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(headerJson));
        string payloadB64 = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(payloadJson));
        byte[] signingInput = Encoding.ASCII.GetBytes($"{headerB64}.{payloadB64}");

        using var signature = await signingKey.SignAsync(signingInput, Pool, cancellationToken).ConfigureAwait(false);
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

        Dictionary<string, object?> header = new(StringComparer.Ordinal)
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

        Dictionary<string, object?> header = new(StringComparer.Ordinal)
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

        Dictionary<string, object?> header = new(StringComparer.Ordinal)
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
        PrivateKeyMemory signingKey, Dictionary<string, object?> header, DateTimeOffset expiresAt, string? nonce)
    {
        Dictionary<string, object?> payload = new(StringComparer.Ordinal)
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
            KeyAttestationProofUse.NotStated,
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
