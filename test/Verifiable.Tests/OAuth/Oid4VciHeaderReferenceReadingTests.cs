using Microsoft.Extensions.Time.Testing;
using System.Security;
using System.Text;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests the reading of an OID4VCI JWS's key reference (Appendix F.1: exactly one of <c>jwk</c>, <c>kid</c> and <c>x5c</c>) from its
/// protected header's decoded members, over key attestations (Appendix D.1) and <c>jwt</c> key proofs (Appendix F.1) a Wallet
/// writes by hand and signs once: a reference whose name is written with an escape is the member it decodes to (RFC 8259 section
/// 8.3), so an escaped reference is found and an escaped one beside a plain one is two references; and the fault boundary of the
/// reference's resolution - the reconstruction's and the decoder's refusal of a <c>jwk</c>, the <c>x5c</c> parser's and chain
/// validator's refusals answered, every other failure of a delegate the caller supplied, cancellation among them, surfacing.
/// </summary>
[TestClass]
internal sealed class Oid4VciHeaderReferenceReadingTests
{
    /// <summary>The per-test context, source of the cancellation token every asynchronous call takes.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>The instant the attestations and proofs are issued and judged at.</summary>
    private static DateTimeOffset NowInstant { get; } = TestClock.CanonicalEpoch;

    /// <summary>The nonce the attestations echo.</summary>
    private const string AttestationNonce = "attestation-nonce-escaped";

    /// <summary>The key identifier a <c>kid</c> reference names.</summary>
    private const string Kid = "https://wallet-provider.example.com/keys#wp-1";

    /// <summary>The Credential Issuer the proofs are addressed to.</summary>
    private const string Audience = "https://issuer.example.com";

    /// <summary>The pool every reading rents from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The clock the dates are judged by.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(NowInstant);


    /// <summary>
    /// Appendix F.1 and RFC 8259 section 8.3: the key reference is read by its decoded name. An attestation whose <c>jwk</c> or
    /// <c>kid</c> name is written with an escape references its key by that member, and verifies; one carrying an escaped
    /// <c>jwk</c> beside a plain <c>kid</c>, or a plain <c>jwk</c> beside an escaped <c>x5c</c>, carries two references, which
    /// Appendix F.1's mutual exclusivity refuses, though a reading of the raw names finds one.
    /// </summary>
    /// <param name="headerCase">The references the header carries.</param>
    /// <param name="isValid">Whether the attestation verifies, else is refused as an invalid key reference.</param>
    /// <returns>A task completing once the attestation is verified.</returns>
    [TestMethod]
    [DataRow("escaped-jwk", true, DisplayName = "An escaped jwk")]
    [DataRow("escaped-kid", true, DisplayName = "An escaped kid")]
    [DataRow("escaped-jwk-beside-kid", false, DisplayName = "An escaped jwk beside a plain kid")]
    [DataRow("jwk-beside-escaped-x5c", false, DisplayName = "A plain jwk beside an escaped x5c")]
    public async Task AnAttestationsKeyReferenceIsReadByItsDecodedName(string headerCase, bool isValid)
    {
        var wp = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var wpPublic = wp.PublicKey;
        using var wpPrivate = wp.PrivateKey;
        var jwk = JwkJsonOf(wpPublic);

        var references = headerCase switch
        {
            "escaped-jwk" => "\"\\u006awk\":" + jwk,
            "escaped-kid" => "\"\\u006bid\":\"" + Kid + "\"",
            "escaped-jwk-beside-kid" => "\"\\u006awk\":" + jwk + ",\"kid\":\"" + Kid + "\"",
            "jwk-beside-escaped-x5c" => "\"jwk\":" + jwk + ",\"\\u0078\\u0035c\":[\"MIIB\"]",
            _ => throw new ArgumentOutOfRangeException(nameof(headerCase), headerCase, "No header is named so.")
        };

        var attestation = await WriteAttestationAsync(wpPrivate, references).ConfigureAwait(false);

        var result = await VerifyAttestationAsync(attestation, ResolverOf(wpPublic), x509Verification: null, [], TestSetup.Base64UrlDecoder).ConfigureAwait(false);

        if(isValid)
        {
            Assert.IsTrue(result.IsValid, $"{headerCase}: {result.FailureReason}");

            return;
        }

        Assert.AreEqual(KeyAttestationVerificationFailureReason.InvalidKeyReference, result.FailureReason, headerCase);
    }


    /// <summary>
    /// The same reading for a <c>jwt</c> key proof (Appendix F.1): a proof whose <c>jwk</c> name is written with an escape is
    /// verified under that key; one carrying it beside a plain <c>kid</c> carries two references and is refused.
    /// </summary>
    /// <param name="headerCase">The references the header carries.</param>
    /// <param name="isValid">Whether the proof is valid, else refused as an invalid key reference.</param>
    /// <returns>A task completing once the proof is validated.</returns>
    [TestMethod]
    [DataRow("escaped-jwk", true, DisplayName = "An escaped jwk")]
    [DataRow("escaped-jwk-beside-kid", false, DisplayName = "An escaped jwk beside a plain kid")]
    public async Task AProofsKeyReferenceIsReadByItsDecodedName(string headerCase, bool isValid)
    {
        var holder = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var holderPublic = holder.PublicKey;
        using var holderPrivate = holder.PrivateKey;
        var jwk = JwkJsonOf(holderPublic);

        var references = headerCase switch
        {
            "escaped-jwk" => "\"\\u006awk\":" + jwk,
            "escaped-jwk-beside-kid" => "\"\\u006awk\":" + jwk + ",\"kid\":\"" + Kid + "\"",
            _ => throw new ArgumentOutOfRangeException(nameof(headerCase), headerCase, "No header is named so.")
        };

        var proof = await SignAsync(
            holderPrivate,
            "{\"alg\":\"ES256\",\"typ\":\"openid4vci-proof+jwt\"," + references + "}",
            "{\"aud\":\"" + Audience + "\",\"iat\":" + NowInstant.ToUnixTimeSeconds() + ",\"nonce\":\"c-nonce\"}").ConfigureAwait(false);

        var result = await CredentialProofValidator.ValidateAsync(
            new CredentialProofValidationRequest
            {
                Proof = proof,
                ExpectedAudience = Audience,
                ExpectedNonce = "c-nonce",
                NonceRequired = true
            },
            static _ => true,
            (kid, _, _, _) => ValueTask.FromResult<PublicKeyMemory?>(string.Equals(kid, Kid, StringComparison.Ordinal) ? CopyOf(holderPublic) : null),
            x509Verification: null,
            [],
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            TimeProvider,
            Pool,
            TimeSpan.FromMinutes(5),
            TestContext.CancellationToken).ConfigureAwait(false);

        if(isValid)
        {
            Assert.IsTrue(result.IsValid, $"{headerCase}: {result.FailureReason}");

            return;
        }

        Assert.AreEqual(CredentialProofValidationFailureReason.InvalidKeyReference, result.FailureReason, headerCase);
    }


    /// <summary>
    /// The resolution of an <c>x5c</c> reference answers the parser's refusal of the chain (its <see cref="FormatException"/>,
    /// <see cref="ParseX5cDelegate"/>'s contract) and the validator's refusal of it (its <see cref="SecurityException"/>,
    /// <see cref="ValidateCertificateChainAsyncDelegate"/>'s contract) as an unresolved key reference; any other exception of
    /// either delegate the caller supplied - an <see cref="InvalidOperationException"/>, the validator's cancellation - surfaces as
    /// the fault it is, never as an unresolved reference.
    /// </summary>
    /// <param name="faultCase">The delegate and the exception it fails with.</param>
    /// <returns>A task completing once the attestation is judged.</returns>
    [TestMethod]
    [DataRow("parser-refusal", DisplayName = "The parser refuses the chain")]
    [DataRow("parser-fault", DisplayName = "The parser fails")]
    [DataRow("validator-refusal", DisplayName = "The validator refuses the chain")]
    [DataRow("validator-cancellation", DisplayName = "The validator is cancelled")]
    public async Task AnX5cDelegatesRefusalIsUnresolvedAndItsFaultSurfaces(string faultCase)
    {
        var wp = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var wpPublic = wp.PublicKey;
        using var wpPrivate = wp.PrivateKey;
        var attestation = await WriteAttestationAsync(wpPrivate, "\"x5c\":[\"MIIB\"]").ConfigureAwait(false);

        ParseX5cDelegate parse = faultCase switch
        {
            "parser-refusal" => static (_, _) => throw new FormatException("No base64 DER certificate."),
            "parser-fault" => static (_, _) => throw new InvalidOperationException("The parser failed."),
            _ => static (_, _) => []
        };

        ValidateCertificateChainAsyncDelegate validate = faultCase switch
        {
            "validator-refusal" => static (_, _, _, _, _, _) => throw new SecurityException("The chain does not validate."),
            "validator-cancellation" => static (_, _, _, _, _, _) => throw new OperationCanceledException("The validation was cancelled."),
            _ => static (_, _, _, _, _, _) => throw new InvalidOperationException("No validation is reached.")
        };

        var x509 = new Oid4VciProofX509Verification { ParseX5c = parse, ValidateChain = validate, MemoryPool = Pool };
        var context = new ExchangeContext();
        context.SetX509TrustAnchors([]);
        context.SetValidationTime(NowInstant);

        switch(faultCase)
        {
            case "parser-fault":
                _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
                    () => VerifyAttestationAsync(attestation, resolveWalletProviderKey: null, x509, context, TestSetup.Base64UrlDecoder)).ConfigureAwait(false);
                break;
            case "validator-cancellation":
                _ = await Assert.ThrowsExactlyAsync<OperationCanceledException>(
                    () => VerifyAttestationAsync(attestation, resolveWalletProviderKey: null, x509, context, TestSetup.Base64UrlDecoder)).ConfigureAwait(false);
                break;
            default:
                var result = await VerifyAttestationAsync(attestation, resolveWalletProviderKey: null, x509, context, TestSetup.Base64UrlDecoder).ConfigureAwait(false);
                Assert.AreEqual(KeyAttestationVerificationFailureReason.KeyReferenceUnresolved, result.FailureReason, faultCase);
                break;
        }
    }


    /// <summary>
    /// The reconstruction of a <c>jwk</c> reference answers the decoder's refusal of a coordinate as no base64url text, its
    /// <see cref="FormatException"/>, as an invalid key reference; any other exception of the decoder the caller supplied surfaces
    /// as the fault it is.
    /// </summary>
    /// <param name="faultCase">The exception the decoder fails with on the key's <c>x</c>.</param>
    /// <returns>A task completing once the attestation is judged.</returns>
    [TestMethod]
    [DataRow("decoder-refusal", DisplayName = "The decoder refuses the coordinate")]
    [DataRow("decoder-fault", DisplayName = "The decoder fails on the coordinate")]
    public async Task AJwkCoordinateDecoderFaultSurfacesAndItsRefusalIsAnInvalidReference(string faultCase)
    {
        var wp = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var wpPublic = wp.PublicKey;
        using var wpPrivate = wp.PrivateKey;
        var attestation = await WriteAttestationAsync(wpPrivate, "\"jwk\":" + JwkJsonOf(wpPublic)).ConfigureAwait(false);
        var x = XOf(wpPublic);

        DecodeDelegate decoder = faultCase is "decoder-refusal"
            ? (source, pool) => source.SequenceEqual(x) ? throw new FormatException("No base64url text.") : TestSetup.Base64UrlDecoder(source, pool)
            : (source, pool) => source.SequenceEqual(x) ? throw new InvalidOperationException("The decoder failed.") : TestSetup.Base64UrlDecoder(source, pool);

        if(faultCase is "decoder-refusal")
        {
            var result = await VerifyAttestationAsync(attestation, resolveWalletProviderKey: null, x509Verification: null, [], decoder).ConfigureAwait(false);

            Assert.AreEqual(KeyAttestationVerificationFailureReason.InvalidKeyReference, result.FailureReason);

            return;
        }

        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => VerifyAttestationAsync(attestation, resolveWalletProviderKey: null, x509Verification: null, [], decoder)).ConfigureAwait(false);
    }


    /// <summary>Verifies an attestation for no stated proof use, its nonce the one the rows write.</summary>
    /// <param name="attestation">The attestation.</param>
    /// <param name="resolveWalletProviderKey">The <c>kid</c> resolver, or <see langword="null"/>.</param>
    /// <param name="x509Verification">The <c>x5c</c> parser and validator, or <see langword="null"/>.</param>
    /// <param name="context">The per-request context.</param>
    /// <param name="decoder">The decoder.</param>
    /// <returns>The verification result.</returns>
    private async Task<KeyAttestationVerificationResult> VerifyAttestationAsync(
        string attestation,
        KeyAttestationVerifier.ResolveWalletProviderKeyDelegate? resolveWalletProviderKey,
        Oid4VciProofX509Verification? x509Verification,
        ExchangeContext context,
        DecodeDelegate decoder) =>
        await KeyAttestationVerifier.VerifyAsync(
            attestation,
            KeyAttestationProofUse.NotStated,
            AttestationNonce,
            nonceRequired: true,
            isAttestationSigningAlgAcceptable: static _ => true,
            resolveWalletProviderKey,
            x509Verification,
            context,
            decoder,
            TimeProvider,
            Pool,
            TimeSpan.FromMinutes(5),
            TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>A <c>kid</c> resolver answering a copy of the key given for <see cref="Kid"/> and no key otherwise.</summary>
    /// <param name="key">The key.</param>
    /// <returns>The resolver.</returns>
    private static KeyAttestationVerifier.ResolveWalletProviderKeyDelegate ResolverOf(PublicKeyMemory key) =>
        (kid, _, _, _) => ValueTask.FromResult<PublicKeyMemory?>(string.Equals(kid, Kid, StringComparison.Ordinal) ? CopyOf(key) : null);


    /// <summary>
    /// The Wallet Provider writes an attestation by hand - the protected header's <c>alg</c> and <c>typ</c> followed by the
    /// reference members given, a body of one attested key, <c>iat</c>, <c>exp</c> and the nonce - and signs it once.
    /// </summary>
    /// <param name="signingKey">The Wallet Provider's key.</param>
    /// <param name="references">The header's reference members' JSON text.</param>
    /// <returns>The compact attestation.</returns>
    private Task<string> WriteAttestationAsync(PrivateKeyMemory signingKey, string references) =>
        SignAsync(
            signingKey,
            "{\"alg\":\"ES256\",\"typ\":\"key-attestation+jwt\"," + references + "}",
            "{\"attested_keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}],"
                + "\"iat\":" + NowInstant.ToUnixTimeSeconds() + ",\"exp\":" + NowInstant.AddHours(1).ToUnixTimeSeconds() + ",\"nonce\":\"" + AttestationNonce + "\"}");


    /// <summary>Signs a header and a claims set written by hand over their exact UTF-8 bytes.</summary>
    /// <param name="signingKey">The key.</param>
    /// <param name="headerJson">The header's JSON text.</param>
    /// <param name="payloadJson">The claims set's JSON text.</param>
    /// <returns>The compact JWS.</returns>
    private async Task<string> SignAsync(PrivateKeyMemory signingKey, string headerJson, string payloadJson)
    {
        var signingInput = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(headerJson)) + "." + TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(payloadJson));

        using var signature = await signingKey.SignAsync(Encoding.ASCII.GetBytes(signingInput), Pool, TestContext.CancellationToken).ConfigureAwait(false);

        return signingInput + "." + TestSetup.Base64UrlEncoder(signature.AsReadOnlySpan());
    }


    /// <summary>The JSON text of the public JWK of a P-256 key.</summary>
    /// <param name="key">The key.</param>
    /// <returns>The JWK's JSON text.</returns>
    private static string JwkJsonOf(PublicKeyMemory key)
    {
        var jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(key.Tag.Get<CryptoAlgorithm>(), key.Tag.Get<Purpose>(), key.AsReadOnlySpan(), TestSetup.Base64UrlEncoder);

        return "{\"kty\":\"" + jwk.Kty + "\",\"crv\":\"" + jwk.Crv + "\",\"x\":\"" + jwk.X + "\",\"y\":\"" + jwk.Y + "\"}";
    }


    /// <summary>The base64url <c>x</c> of the public JWK of a P-256 key.</summary>
    /// <param name="key">The key.</param>
    /// <returns>The coordinate's text.</returns>
    private static string XOf(PublicKeyMemory key) =>
        CryptoFormatConversions.DefaultAlgorithmToJwkConverter(key.Tag.Get<CryptoAlgorithm>(), key.Tag.Get<Purpose>(), key.AsReadOnlySpan(), TestSetup.Base64UrlEncoder).X
            ?? throw new InvalidOperationException("A P-256 JWK carries its x coordinate.");


    /// <summary>A copy of a public key the verification owns and disposes, the row keeping its own.</summary>
    /// <param name="source">The key.</param>
    /// <returns>The copy.</returns>
    private static PublicKeyMemory CopyOf(PublicKeyMemory source)
    {
        var material = source.AsReadOnlySpan();
        var owner = Pool.Rent(material.Length);
        material.CopyTo(owner.Memory.Span);

        return new PublicKeyMemory(owner, source.Tag);
    }
}
