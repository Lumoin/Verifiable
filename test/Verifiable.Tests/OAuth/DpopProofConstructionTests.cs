using Microsoft.Extensions.Time.Testing;
using Verifiable.JCose;
using Verifiable.OAuth.Dpop;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

[TestClass]
internal sealed class DpopProofConstructionTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(
        new DateTimeOffset(2026, 5, 13, 12, 0, 0, TimeSpan.Zero));


    [TestMethod]
    public async Task BuildAsyncProducesThreeSegmentJws()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        DpopProofClaims claims = BuildClaims();

        string proof = await DpopProofConstruction.BuildAsync(
            claims,
            key,
            TestSetup.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        string[] parts = proof.Split('.');
        Assert.HasCount(3, parts);
        Assert.IsFalse(string.IsNullOrEmpty(parts[0]));
        Assert.IsFalse(string.IsNullOrEmpty(parts[1]));
        Assert.IsFalse(string.IsNullOrEmpty(parts[2]));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.6">RFC 9449 Section 11.6</see>: "Implementers MUST
    /// ensure that only asymmetric digital signature algorithms (such as ES256) that are deemed secure can be used for
    /// signing DPoP proofs. In particular, the algorithm none MUST NOT be allowed." A client asked to build a DPoP proof
    /// with a DPoP key whose declared algorithm is <c>none</c> is refused with an <see cref="ArgumentException"/>: no
    /// proof declaring <c>alg</c> <c>none</c> is built.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ClientRefusesToBuildAProofUnderTheAlgorithmNoneAsync()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var publicKey = keys.PublicKey;
        using var privateKey = keys.PrivateKey;

        _ = await Assert.ThrowsAsync<ArgumentException>(() => BuildProofWithKeyAsync(() => new DpopKey(keys, "none"))).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>, of the proof's
    /// <c>alg</c>: "An identifier for a JWS asymmetric digital signature algorithm from [IANA.JOSE.ALGS]. It MUST NOT be
    /// none or an identifier for a symmetric algorithm (Message Authentication Code (MAC))." and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.6">Section 11.6</see>: "Implementers MUST ensure
    /// that only asymmetric digital signature algorithms (such as ES256) that are deemed secure can be used for signing
    /// DPoP proofs." A JWS <c>alg</c> value is case-sensitive
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515 Section 4.1.1</see>), so a spelling
    /// in another case, or with a trailing space, identifies no registered algorithm. A client asked to build a DPoP
    /// proof with a DPoP key declaring any identifier other than an asymmetric JWS signature algorithm is refused with
    /// an <see cref="ArgumentException"/> naming the <c>alg</c> parameter: no proof is built under it. The rows:
    /// <c>none</c> and <c>NONE</c>; the MAC identifiers <c>HS256</c>, <c>HS384</c> and <c>HS512</c>; the JWE
    /// identifiers <c>RSA-OAEP</c>, <c>dir</c> and <c>A256GCM</c>; the unregistered <c>foo</c>; <c>ES256</c> with a
    /// trailing space; and <c>es256</c>.
    /// </summary>
    /// <param name="alg">The algorithm the DPoP key declares.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("none")]
    [DataRow("NONE")]
    [DataRow("HS256")]
    [DataRow("HS384")]
    [DataRow("HS512")]
    [DataRow("RSA-OAEP")]
    [DataRow("dir")]
    [DataRow("A256GCM")]
    [DataRow("foo")]
    [DataRow("ES256 ")]
    [DataRow("es256")]
    public async Task ClientRefusesToBuildAProofUnderAnIdentifierOtherThanAnAsymmetricSignatureAlgorithmAsync(string alg)
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var publicKey = keys.PublicKey;
        using var privateKey = keys.PrivateKey;

        ArgumentException refusal = await Assert.ThrowsAsync<ArgumentException>(() => BuildProofWithKeyAsync(() => new DpopKey(keys, alg))).ConfigureAwait(false);
        Assert.AreEqual("alg", refusal.ParamName);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>, of the proof's
    /// <c>alg</c>: "An identifier for a JWS asymmetric digital signature algorithm from [IANA.JOSE.ALGS]." A client
    /// asked to build a DPoP proof with a P-256 DPoP key declaring <c>ES256</c> builds it, and the proof's protected
    /// header declares <c>alg</c> <c>ES256</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ClientBuildsAProofUnderAnAsymmetricSignatureAlgorithmAsync()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var publicKey = keys.PublicKey;
        using var privateKey = keys.PrivateKey;

        string proof = await BuildProofWithKeyAsync(() => new DpopKey(keys, WellKnownJwaValues.Es256)).ConfigureAwait(false);

        Assert.AreEqual(WellKnownJwaValues.Es256, DecodeHeader(proof).Alg);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>, of the proof's
    /// <c>alg</c>: "An identifier for a JWS asymmetric digital signature algorithm from [IANA.JOSE.ALGS]." A client
    /// constructs a DPoP key declaring each asymmetric JWS signature algorithm identifier, the identifiers the DPoP header
    /// factory writes and the servers' proof validation admits (the ECDSA identifiers <c>ES256</c>, <c>ES384</c>,
    /// <c>ES512</c> and <c>ES256K</c>, the Brainpool ECDSA identifier <c>ESB256</c>, the RSA PKCS#1 v1.5 identifiers
    /// <c>RS256</c>, <c>RS384</c> and <c>RS512</c>, the RSA-PSS identifiers <c>PS256</c>, <c>PS384</c> and <c>PS512</c>,
    /// <c>EdDSA</c>, the fully-specified <c>Ed25519</c>, and <c>ML-DSA-44</c>), and the DPoP key carries the identifier as
    /// declared.
    /// </summary>
    /// <param name="alg">The algorithm the DPoP key declares.</param>
    [TestMethod]
    [DataRow("ES256")]
    [DataRow("ES384")]
    [DataRow("ES512")]
    [DataRow("ES256K")]
    [DataRow("ESB256")]
    [DataRow("RS256")]
    [DataRow("RS384")]
    [DataRow("RS512")]
    [DataRow("PS256")]
    [DataRow("PS384")]
    [DataRow("PS512")]
    [DataRow("EdDSA")]
    [DataRow("Ed25519")]
    [DataRow("ML-DSA-44")]
    public void ClientAcceptsADpopKeyDeclaringAnAsymmetricSignatureAlgorithm(string alg)
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var publicKey = keys.PublicKey;
        using var privateKey = keys.PrivateKey;

        DpopKey? key = null;
        ArgumentException? refusal = null;
        try
        {
            key = new(keys, alg);
        }
        catch(ArgumentException exception)
        {
            refusal = exception;
        }

        Assert.IsNull(refusal, $"A DPoP key declaring {alg} is accepted; it was refused: {refusal?.Message}");
        Assert.IsNotNull(key);
        Assert.AreEqual(alg, key.Alg);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>, of the JOSE Header of
    /// a DPoP proof: "alg: An identifier for a JWS asymmetric digital signature algorithm from [IANA.JOSE.ALGS]. It MUST
    /// NOT be none or an identifier for a symmetric algorithm (Message Authentication Code (MAC))." The factory that
    /// writes a header typed <c>dpop+jwt</c> refuses an identifier other than an asymmetric JWS signature algorithm with
    /// an <see cref="ArgumentException"/> naming the <c>algorithm</c> parameter, so no such header is written. The rows:
    /// <c>none</c>, the MAC identifier <c>HS256</c>, and the JWE identifier <c>RSA-OAEP</c>.
    /// </summary>
    /// <param name="algorithm">The algorithm the header would declare.</param>
    [TestMethod]
    [DataRow("none")]
    [DataRow("HS256")]
    [DataRow("RSA-OAEP")]
    public void DpopHeaderFactoryRefusesAnAlgorithmOtherThanAnAsymmetricSignatureAlgorithm(string algorithm)
    {
        Dictionary<string, object> jwk = new(StringComparer.Ordinal) { [WellKnownJwkMemberNames.Kty] = "EC" };

        ArgumentException refusal = Assert.ThrowsExactly<ArgumentException>(() => JwtHeader.ForDpop(algorithm, jwk));

        Assert.AreEqual("algorithm", refusal.ParamName);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>: "The JOSE Header of a
    /// DPoP JWT MUST contain at least the following parameters: typ: A field with the value dpop+jwt ... alg: An
    /// identifier for a JWS asymmetric digital signature algorithm from [IANA.JOSE.ALGS] ... jwk: Represents the public
    /// key chosen by the client". The factory asked for a header declaring an asymmetric JWS signature algorithm
    /// identifier the client's DPoP key also accepts writes <c>typ</c> <c>dpop+jwt</c>, that <c>alg</c> and the given
    /// <c>jwk</c>. The rows: <c>ES256</c>, the Brainpool ECDSA identifier <c>ESB256</c>, the fully-specified
    /// <c>Ed25519</c> and <c>ML-DSA-44</c>.
    /// </summary>
    /// <param name="algorithm">The algorithm the header declares.</param>
    [TestMethod]
    [DataRow("ES256")]
    [DataRow("ESB256")]
    [DataRow("Ed25519")]
    [DataRow("ML-DSA-44")]
    public void DpopHeaderFactoryWritesAnAsymmetricSignatureAlgorithm(string algorithm)
    {
        Dictionary<string, object> jwk = new(StringComparer.Ordinal) { [WellKnownJwkMemberNames.Kty] = "EC" };

        JwtHeader? header = null;
        ArgumentException? refusal = null;
        try
        {
            header = JwtHeader.ForDpop(algorithm, jwk);
        }
        catch(ArgumentException exception)
        {
            refusal = exception;
        }

        Assert.IsNull(refusal, $"The factory writes a header declaring {algorithm}; it refused: {refusal?.Message}");
        Assert.IsNotNull(header);
        Assert.AreEqual(WellKnownMediaTypes.Jwt.DpopJwt, header[WellKnownJoseHeaderNames.Typ]);
        Assert.AreEqual(algorithm, header[WellKnownJoseHeaderNames.Alg]);
        Assert.AreSame(jwk, header[WellKnownJoseHeaderNames.Jwk]);
    }


    /// <summary>Builds a DPoP proof with the DPoP key <paramref name="createKey"/> makes.</summary>
    /// <param name="createKey">Makes the DPoP key the proof is built with.</param>
    /// <returns>The compact proof.</returns>
    private async Task<string> BuildProofWithKeyAsync(Func<DpopKey> createKey) =>
        await DpopProofConstruction.BuildAsync(
            BuildClaims(),
            createKey(),
            TestSetup.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);


    [TestMethod]
    public async Task BuildAsyncEmitsTypDpopJwtInHeader()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await DpopProofConstruction.BuildAsync(
            BuildClaims(),
            key,
            TestSetup.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        DpopProofHeader header = DecodeHeader(proof);
        Assert.AreEqual(WellKnownDpopValues.ProofTypeHeader, header.Typ);
        Assert.AreEqual(WellKnownJwaValues.Es256, header.Alg);
    }


    [TestMethod]
    public async Task BuildAsyncEmbedsCorrectJwkForP256Key()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var publicKey = keys.PublicKey;
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await DpopProofConstruction.BuildAsync(
            BuildClaims(),
            key,
            TestSetup.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        IReadOnlyDictionary<string, string> expectedJwk = DpopJwkUtilities.ToJwk(
            publicKey, WellKnownJwaValues.Es256, TestSetup.Base64UrlEncoder);

        DpopProofHeader header = DecodeHeader(proof);
        Assert.AreEqual(expectedJwk[WellKnownJwkMemberNames.Kty], header.Jwk[WellKnownJwkMemberNames.Kty]);
        Assert.AreEqual(expectedJwk[WellKnownJwkMemberNames.Crv], header.Jwk[WellKnownJwkMemberNames.Crv]);
        Assert.AreEqual(expectedJwk[WellKnownJwkMemberNames.X], header.Jwk[WellKnownJwkMemberNames.X]);
        Assert.AreEqual(expectedJwk[WellKnownJwkMemberNames.Y], header.Jwk[WellKnownJwkMemberNames.Y]);
    }


    [TestMethod]
    public async Task BuildAsyncOmitsNonceClaimWhenNotProvided()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await DpopProofConstruction.BuildAsync(
            BuildClaims(),
            key,
            TestSetup.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        DpopProofClaims parsed = DecodeClaims(proof);
        Assert.IsNull(parsed.Nonce);
        Assert.IsNull(parsed.Ath);
    }


    [TestMethod]
    public async Task BuildAsyncIncludesNonceAndAthWhenProvided()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        DpopProofClaims claims = BuildClaims() with
        {
            Nonce = "fresh-nonce",
            Ath = "fake-ath-hash"
        };

        string proof = await DpopProofConstruction.BuildAsync(
            claims,
            key,
            TestSetup.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        DpopProofClaims parsed = DecodeClaims(proof);
        Assert.AreEqual("fresh-nonce", parsed.Nonce);
        Assert.AreEqual("fake-ath-hash", parsed.Ath);
    }


    private DpopProofClaims BuildClaims() => new()
    {
        Htm = WellKnownHttpMethods.Post,
        Htu = "https://as.example.com/token",
        Iat = TimeProvider.GetUtcNow(),
        Jti = Guid.NewGuid().ToString("N")
    };


    private static DpopProofHeader DecodeHeader(string proof)
    {
        string[] parts = proof.Split('.');
        using System.Buffers.IMemoryOwner<byte> bytes = TestSetup.Base64UrlDecoder(parts[0], BaseMemoryPool.Shared);
        return DpopTestSupport.ParseHeaderJson(bytes.Memory);
    }


    private static DpopProofClaims DecodeClaims(string proof)
    {
        string[] parts = proof.Split('.');
        using System.Buffers.IMemoryOwner<byte> bytes = TestSetup.Base64UrlDecoder(parts[1], BaseMemoryPool.Shared);
        return DpopTestSupport.ParseClaimsJson(bytes.Memory);
    }
}
