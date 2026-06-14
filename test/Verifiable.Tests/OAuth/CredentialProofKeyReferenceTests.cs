using System.Buffers;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Oid4Vci.Wallet;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The OID4VCI 1.0 Appendix F.1 <c>kid</c> and <c>x5c</c> key-reference modes of a <c>jwt</c> key
/// proof, resolved by <see cref="CredentialProofValidator"/>. Appendix F.1 defines exactly one of
/// <c>jwk</c>/<c>kid</c>/<c>x5c</c> in the JOSE header; the embedded-<c>jwk</c> mode is covered by
/// <see cref="CredentialProofValidatorTests"/>, and these tests cover the two reference modes —
/// each driving §F.4: "The Credential Issuer MUST validate that the JWT used as a proof is actually
/// signed by a key identified in the JOSE Header through either kid, jwk or x5c element."
/// </summary>
/// <remarks>
/// The <c>x5c</c> resolution composes the EXISTING X.509 surface
/// (<see cref="MicrosoftX509Functions.ParseX5c"/> + <see cref="MicrosoftX509Functions.ValidateChainAsync"/>),
/// the same platform functions the OID4VP x509 JAR-key resolvers compose, with the trust anchors and
/// validity instant carried on the threaded <see cref="ExchangeContext"/>. The <c>kid</c> resolution
/// goes through the application-supplied <see cref="CredentialProofValidator.ResolveProofKeyDelegate"/>
/// seam.
/// </remarks>
[TestClass]
internal sealed class CredentialProofKeyReferenceTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly DateTimeOffset NowInstant = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan IatSkew = TimeSpan.FromMinutes(5);
    private const string Audience = "https://credential-issuer.example.com";
    private const string CredentialNonce = "c-nonce-LarRGSbmUPYtRYO6BQ4yn8";

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private FakeTimeProvider TimeProvider { get; } = new(NowInstant);

    //A JOSE-correct serializer that does NOT escape '+' (the character in openid4vci-proof+jwt),
    //mirroring CredentialProofValidatorTests so the typ contract a real Credential Issuer reads
    //survives serialization.
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
    /// §F.1 x5c happy path. §F.1: "x5c: OPTIONAL. JOSE Header containing at least one certificate
    /// where the first certificate contains the key that the Credential is to be bound to,
    /// additional certificates may also be present." A proof whose header carries the [leaf, ca]
    /// x5c chain — leaf key signing — resolves to the leaf public key and verifies when the chain's
    /// CA is wired as a trust anchor on the context.
    /// </summary>
    [TestMethod]
    public async Task X5cProofVerifiesAgainstWiredTrustAnchors()
    {
        using CertificateChainMaterial chain =
            TestCertificateChainProvider.CreateFreshP256ChainMaterial("holder.example.com", TimeProvider);

        string proof = await MintX5cProofAsync(chain).ConfigureAwait(false);

        Oid4VciProofX509Verification x509 = BuildX509Verification();
        IReadOnlyList<PkiCertificateMemory> anchors = ParseAnchor(chain);
        try
        {
            ExchangeContext context = new();
            context.SetX509TrustAnchors(anchors);
            context.SetValidationTime(NowInstant);

            CredentialProofValidationResult result = await ValidateAsync(
                proof, x509Verification: x509, context: context).ConfigureAwait(false);

            Assert.IsTrue(result.IsValid, $"x5c proof must validate; got {result.FailureReason}.");
            Assert.AreEqual(Audience, result.Audience);
            Assert.AreEqual(CredentialNonce, result.Nonce);
        }
        finally
        {
            DisposeAll(anchors);
        }
    }


    /// <summary>
    /// §F.1 x5c negative. §F.4: "The Credential Issuer MUST validate that the JWT used as a proof is
    /// actually signed by a key identified in the JOSE Header through either kid, jwk or x5c
    /// element." A correctly self-consistent x5c chain whose CA is NOT among the wired trust anchors
    /// does not chain to a trust anchor, so the key reference is unresolved and the proof is rejected.
    /// </summary>
    [TestMethod]
    public async Task X5cProofFailsWhenChainDoesNotValidateToAnchors()
    {
        using CertificateChainMaterial chain =
            TestCertificateChainProvider.CreateFreshP256ChainMaterial("holder.example.com", TimeProvider);

        //A DIFFERENT chain whose CA is the trust anchor — the proof's chain cannot validate to it.
        using CertificateChainMaterial otherChain =
            TestCertificateChainProvider.CreateFreshP256ChainMaterial("other.example.com", TimeProvider);

        string proof = await MintX5cProofAsync(chain).ConfigureAwait(false);

        Oid4VciProofX509Verification x509 = BuildX509Verification();
        IReadOnlyList<PkiCertificateMemory> foreignAnchors = ParseAnchor(otherChain);
        try
        {
            ExchangeContext context = new();
            context.SetX509TrustAnchors(foreignAnchors);
            context.SetValidationTime(NowInstant);

            CredentialProofValidationResult result = await ValidateAsync(
                proof, x509Verification: x509, context: context).ConfigureAwait(false);

            Assert.AreEqual(CredentialProofValidationFailureReason.KeyReferenceUnresolved, result.FailureReason);
        }
        finally
        {
            DisposeAll(foreignAnchors);
        }
    }


    /// <summary>
    /// §F.1 x5c unwired seam. §F.1: x5c "MUST NOT be present if kid or jwk is present" — it is the
    /// sole key reference, so with no <see cref="Oid4VciProofX509Verification"/> seam wired the
    /// library cannot resolve it and rejects the proof as invalid_proof (KeyReferenceUnresolved)
    /// rather than crashing.
    /// </summary>
    [TestMethod]
    public async Task X5cProofWithUnwiredSeamFailsClosed()
    {
        using CertificateChainMaterial chain =
            TestCertificateChainProvider.CreateFreshP256ChainMaterial("holder.example.com", TimeProvider);

        string proof = await MintX5cProofAsync(chain).ConfigureAwait(false);

        CredentialProofValidationResult result = await ValidateAsync(
            proof, x509Verification: null, context: new ExchangeContext()).ConfigureAwait(false);

        Assert.AreEqual(CredentialProofValidationFailureReason.KeyReferenceUnresolved, result.FailureReason);
    }


    /// <summary>
    /// §F.1 kid happy path. §F.1: "kid: OPTIONAL. JOSE Header containing the key ID. If the
    /// Credential is to be bound to a DID, the kid refers to a DID URL which identifies a particular
    /// key in the DID Document that the Credential is to be bound to." A proof referencing its key by
    /// <c>kid</c> resolves through the wired resolver to the holder public key and verifies.
    /// </summary>
    [TestMethod]
    public async Task KidProofVerifiesThroughWiredResolver()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;

        const string Kid = "did:example:holder-42#key-1";
        string proof = await MintKidProofAsync(holderPrivate, Kid).ConfigureAwait(false);

        //The wired resolver maps the expected kid to the holder public key — the issuer-side
        //dereference the deployment owns. A copy is returned because the validator disposes the key.
        CredentialProofValidator.ResolveProofKeyDelegate resolver =
            (kid, algorithm, context, ct) => string.Equals(kid, Kid, StringComparison.Ordinal)
                ? ValueTask.FromResult<PublicKeyMemory?>(CopyPublicKey(holderPublic))
                : ValueTask.FromResult<PublicKeyMemory?>(null);

        CredentialProofValidationResult result = await ValidateAsync(
            proof, resolveProofKey: resolver, context: new ExchangeContext()).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, $"kid proof must validate; got {result.FailureReason}.");
        Assert.AreEqual(Audience, result.Audience);
        Assert.AreEqual(CredentialNonce, result.Nonce);
    }


    /// <summary>
    /// §F.1 kid negative. §F.4: the JWT MUST be "signed by a key identified in the JOSE Header" — a
    /// proof whose <c>kid</c> the wired resolver cannot dereference yields no key, so the reference is
    /// unresolved and the proof is rejected as invalid_proof.
    /// </summary>
    [TestMethod]
    public async Task KidProofWithUnresolvableKidFailsClosed()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;

        string proof = await MintKidProofAsync(holderPrivate, "did:example:unknown#key-9").ConfigureAwait(false);

        //The resolver does not recognise the kid — it returns null, which is KeyReferenceUnresolved.
        CredentialProofValidator.ResolveProofKeyDelegate resolver =
            (kid, algorithm, context, ct) => ValueTask.FromResult<PublicKeyMemory?>(null);

        CredentialProofValidationResult result = await ValidateAsync(
            proof, resolveProofKey: resolver, context: new ExchangeContext()).ConfigureAwait(false);

        Assert.AreEqual(CredentialProofValidationFailureReason.KeyReferenceUnresolved, result.FailureReason);
    }


    /// <summary>
    /// §F.1 kid unwired seam. §F.1: kid "MUST NOT be present if jwk or x5c is present" — it is the
    /// sole key reference, so with no resolver wired the library cannot resolve it and rejects the
    /// proof as invalid_proof (KeyReferenceUnresolved) rather than crashing.
    /// </summary>
    [TestMethod]
    public async Task KidProofWithUnwiredResolverFailsClosed()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;

        string proof = await MintKidProofAsync(holderPrivate, "did:example:holder-42#key-1").ConfigureAwait(false);

        CredentialProofValidationResult result = await ValidateAsync(
            proof, resolveProofKey: null, context: new ExchangeContext()).ConfigureAwait(false);

        Assert.AreEqual(CredentialProofValidationFailureReason.KeyReferenceUnresolved, result.FailureReason);
    }


    //Mints a §F.1 jwt proof whose JOSE header carries the [leaf, ca] x5c chain (no jwk), signed by
    //the chain's leaf private key — the x5c reference mode. Mirrors the §F.1 claim shape the
    //production minter produces.
    private async Task<string> MintX5cProofAsync(CertificateChainMaterial chain)
    {
        string leafBase64 = Convert.ToBase64String(chain.LeafDerBytes.AsReadOnlyMemory().ToArray());
        string caBase64 = Convert.ToBase64String(chain.CaDerBytes.AsReadOnlyMemory().ToArray());
        string[] x5cValues = [leafBase64, caBase64];

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(chain.LeafSigningKey.Tag);

        Dictionary<string, object> header = new(StringComparer.Ordinal)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = Oid4VciProofIssuance.ProofJwtType,
            [WellKnownJwkMemberNames.X5c] = x5cValues
        };

        return await SignProofAsync(chain.LeafSigningKey, header).ConfigureAwait(false);
    }


    //Mints a §F.1 jwt proof whose JOSE header carries a kid (no jwk), signed by the holder key —
    //the kid reference mode.
    private async Task<string> MintKidProofAsync(PrivateKeyMemory holderPrivate, string kid)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(holderPrivate.Tag);

        Dictionary<string, object> header = new(StringComparer.Ordinal)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = Oid4VciProofIssuance.ProofJwtType,
            [WellKnownJwkMemberNames.Kid] = kid
        };

        return await SignProofAsync(holderPrivate, header).ConfigureAwait(false);
    }


    //Signs the supplied header with the §F.1 aud/nonce/iat payload and serializes the compact JWS.
    private async Task<string> SignProofAsync(PrivateKeyMemory signingKey, Dictionary<string, object> header)
    {
        Dictionary<string, object> payload = new(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Aud] = Audience,
            [WellKnownJwtClaimNames.Nonce] = CredentialNonce,
            [WellKnownJwtClaimNames.Iat] = NowInstant.ToUnixTimeSeconds()
        };

        UnsignedJwt unsigned = new(new JwtHeader(header), new JwtPayload(payload));
        using JwsMessage jws = await unsigned.SignAsync(
            signingKey, HeaderSerializer, PayloadSerializer,
            TestSetup.Base64UrlEncoder, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
    }


    //The registry-resolving validator overload, bound to the issuer aud + the c_nonce, with the
    //kid/x5c seams supplied by the caller.
    private async Task<CredentialProofValidationResult> ValidateAsync(
        string proof,
        CredentialProofValidator.ResolveProofKeyDelegate? resolveProofKey = null,
        Oid4VciProofX509Verification? x509Verification = null,
        ExchangeContext? context = null) =>
        await CredentialProofValidator.ValidateAsync(
            new CredentialProofValidationRequest
            {
                Proof = proof,
                ExpectedAudience = Audience,
                ExpectedNonce = CredentialNonce,
                NonceRequired = true
            },
            isProofSigningAlgAcceptable: static _ => true,
            resolveProofKey,
            x509Verification,
            context ?? new ExchangeContext(),
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            TimeProvider,
            Pool,
            IatSkew,
            TestContext.CancellationToken).ConfigureAwait(false);


    //The x5c seam wired with the SAME platform X.509 functions the OID4VP x509 JAR-key resolvers
    //compose — ParseX5c + ValidateChainAsync — never re-rolled.
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


    //A defensive copy of the holder public key so the validator's dispose does not free the
    //test-owned key. PublicKeyMemory owns its IMemoryOwner, so the copy rents its own buffer.
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
