using System.Buffers;
using Microsoft.Extensions.Time.Testing;
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

    private static readonly DateTimeOffset NowInstant = TestClock.CanonicalEpoch;
    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);
    private const string AttestationNonce = "attestation-nonce-7Qm2";

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private FakeTimeProvider TimeProvider { get; } = new(NowInstant);

    /// <summary>A JOSE-correct serializer that does NOT escape '+' (the character in key-attestation+jwt).</summary>
    private static readonly System.Text.Json.JsonSerializerOptions JoseSerializationOptions =
        new(TestSetup.DefaultSerializationOptions)
        {
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, JoseSerializationOptions);

    private static readonly JwtPayloadSerializer PayloadSerializer =
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
        Assert.IsNotNull(result.Attestation!.AttestedKeysJson);
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

        //Flip one character of the payload segment; the embedded jwk is intact so resolution succeeds
        //but the signature no longer matches the altered signing input.
        string[] parts = attestation.Split('.');
        char[] payload = parts[1].ToCharArray();
        payload[0] = payload[0] == 'A' ? 'B' : 'A';
        parts[1] = new string(payload);
        string tampered = string.Join('.', parts);

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
            context: new ExchangeContext(),
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
            ExchangeContext context = new();
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
            ExchangeContext context = new();
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

        KeyAttestationVerifier.ResolveWalletProviderKeyDelegate resolver =
            (kid, algorithm, context, ct) => string.Equals(kid, Kid, StringComparison.Ordinal)
                ? ValueTask.FromResult<PublicKeyMemory?>(CopyPublicKey(wpPublic))
                : ValueTask.FromResult<PublicKeyMemory?>(null);

        KeyAttestationVerificationResult result = await KeyAttestationVerifier.VerifyAsync(
            attestation,
            AttestationNonce,
            nonceRequired: true,
            isAttestationSigningAlgAcceptable: static _ => true,
            resolveWalletProviderKey: resolver,
            x509Verification: null,
            context: new ExchangeContext(),
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

        KeyAttestationVerifier.ResolveWalletProviderKeyDelegate resolver =
            (kid, algorithm, context, ct) => ValueTask.FromResult<PublicKeyMemory?>(null);

        KeyAttestationVerificationResult result = await KeyAttestationVerifier.VerifyAsync(
            attestation,
            AttestationNonce,
            nonceRequired: true,
            isAttestationSigningAlgAcceptable: static _ => true,
            resolveWalletProviderKey: resolver,
            x509Verification: null,
            context: new ExchangeContext(),
            TestSetup.Base64UrlDecoder,
            TimeProvider,
            Pool,
            ClockSkew,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(KeyAttestationVerificationFailureReason.KeyReferenceUnresolved, result.FailureReason);
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

        UnsignedJwt unsigned = new(new JwtHeader(header), new JwtPayload(payload));
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
            context: new ExchangeContext(),
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
