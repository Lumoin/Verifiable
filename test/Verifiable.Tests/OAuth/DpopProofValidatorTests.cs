using Microsoft.Extensions.Time.Testing;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth.Dpop;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

[TestClass]
internal sealed class DpopProofValidatorTests
{
    public TestContext TestContext { get; set; } = null!;

    private static DateTimeOffset NowInstant { get; } = TestClock.CanonicalEpoch.AddDays(-19);
    private static TimeSpan IatSkew { get; } = TimeSpan.FromSeconds(30);
    private const string DefaultMethod = "POST";
    private const string DefaultUrl = "https://as.example.com/token";

    private FakeTimeProvider TimeProvider { get; } = new(NowInstant);


    [TestMethod]
    public async Task ValidateAsyncSucceedsOnFreshProof()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofAsync(key, BuildClaims()).ConfigureAwait(false);

        var result = await ValidateAsync(
            proof,
            expectedNonce: null,
            nonceRequired: false,
            accessToken: null,
            verifier: DpopTestSupport.Es256Verification,
            httpUrl: DefaultUrl).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Validation must succeed; got {result.FailureReason}.");
        Assert.IsNotNull(result.Claims);
        Assert.IsNotNull(result.JwkThumbprint);
        Assert.AreEqual(
            DpopJwkUtilities.ComputeThumbprint(keys.PublicKey, WellKnownJwaValues.Es256,
                TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared),
            result.JwkThumbprint);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 §4.2</see>: "The JOSE
    /// Header of a DPoP JWT MUST contain at least the following parameters: ... typ ... alg ... jwk"
    /// and "The payload of a DPoP proof MUST contain at least the following claims: ... jti ... htm
    /// ... htu ... iat". A proof built with <see cref="DpopJwsPartSerializerJson.Default"/> validates
    /// through <see cref="DpopProofValidator"/>, and its header and claims carry exactly those
    /// members — no more, no fewer — when no nonce or access token is in flight.
    /// </summary>
    [TestMethod]
    public async Task DefaultSerializerProofValidatesAndCarriesExactlyTheRfc9449Members()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);
        DpopProofClaims claims = BuildClaims();

        string proof = await DpopProofConstruction.BuildAsync(
            claims,
            key,
            TestSetup.Base64UrlEncoder,
            DpopJwsPartSerializerJson.Default,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        var result = await ValidateAsync(
            proof,
            expectedNonce: null,
            nonceRequired: false,
            accessToken: null,
            verifier: DpopTestSupport.Es256Verification,
            httpUrl: DefaultUrl).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"A proof built with the default serializer must validate; got {result.FailureReason}.");

        string[] parts = proof.Split('.');
        Assert.HasCount(3, parts);

        HashSet<string> headerMembers = MemberNames(parts[0]);
        HashSet<string> payloadMembers = MemberNames(parts[1]);

        HashSet<string> expectedHeaderMembers = new(StringComparer.Ordinal)
        {
            WellKnownJoseHeaderNames.Typ, WellKnownJwkMemberNames.Alg, WellKnownJoseHeaderNames.Jwk
        };
        HashSet<string> expectedPayloadMembers = new(StringComparer.Ordinal)
        {
            WellKnownJwtClaimNames.Jti, WellKnownJwtClaimNames.Htm, WellKnownJwtClaimNames.Htu, WellKnownJwtClaimNames.Iat
        };

        Assert.IsTrue(expectedHeaderMembers.SetEquals(headerMembers),
            $"The header must carry exactly typ, alg, jwk; got [{string.Join(", ", headerMembers)}].");
        Assert.IsTrue(expectedPayloadMembers.SetEquals(payloadMembers),
            $"The payload must carry exactly jti, htm, htu, iat; got [{string.Join(", ", payloadMembers)}].");
    }


    //Decodes a base64url JWS segment and returns the set of its top-level JSON member names.
    private static HashSet<string> MemberNames(string base64UrlSegment)
    {
        using System.Buffers.IMemoryOwner<byte> bytes = TestSetup.Base64UrlDecoder(base64UrlSegment, BaseMemoryPool.Shared);
        using System.Text.Json.JsonDocument document = System.Text.Json.JsonDocument.Parse(bytes.Memory);

        HashSet<string> names = new(StringComparer.Ordinal);
        foreach(System.Text.Json.JsonProperty property in document.RootElement.EnumerateObject())
        {
            _ = names.Add(property.Name);
        }

        return names;
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsMalformedProof()
    {
        var result = await ValidateAsync(
            "not-a-jws",
            expectedNonce: null,
            nonceRequired: false,
            accessToken: null,
            verifier: DpopTestSupport.Es256Verification,
            httpUrl: DefaultUrl).ConfigureAwait(false);
        Assert.AreEqual(DpopProofValidationFailureReason.Malformed, result.FailureReason);
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

        var result = await ValidateAsync(
            proof,
            expectedNonce: null,
            nonceRequired: false,
            accessToken: null,
            verifier: DpopTestSupport.Es256Verification,
            httpUrl: DefaultUrl).ConfigureAwait(false);
        Assert.AreEqual(DpopProofValidationFailureReason.InvalidTyp, result.FailureReason);
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

        var result = await ValidateAsync(
            proof,
            expectedNonce: null,
            nonceRequired: false,
            accessToken: null,
            verifier: DpopTestSupport.Es256Verification,
            httpUrl: DefaultUrl).ConfigureAwait(false);
        Assert.AreEqual(DpopProofValidationFailureReason.InvalidAlg, result.FailureReason);
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
                _ = tampered.Remove(WellKnownJoseHeaderNames.Jwk);
                return tampered;
            }).ConfigureAwait(false);

        var result = await ValidateAsync(
            proof,
            expectedNonce: null,
            nonceRequired: false,
            accessToken: null,
            verifier: DpopTestSupport.Es256Verification,
            httpUrl: DefaultUrl).ConfigureAwait(false);
        Assert.IsTrue(
            result.FailureReason is DpopProofValidationFailureReason.InvalidJwk
                or DpopProofValidationFailureReason.Malformed,
            $"Expected InvalidJwk or Malformed; got {result.FailureReason}.");
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsJwkContainingPrivateKey()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        //RFC 9449 §4.2: the jwk header MUST be a public key. Splice an EC private
        //scalar ('d') into the jwk; the validator rejects it before signature checks.
        string proof = await BuildProofWithCustomHeaderAsync(key, BuildClaims(),
            header =>
            {
                Dictionary<string, object> tampered = new(header);
                var jwk = new Dictionary<string, object>(
                    (IReadOnlyDictionary<string, object>)tampered[WellKnownJoseHeaderNames.Jwk],
                    StringComparer.Ordinal)
                {
                    [WellKnownJwkMemberNames.D] = "cHJpdmF0ZS1zY2FsYXI"
                };
                tampered[WellKnownJoseHeaderNames.Jwk] = jwk;

                return tampered;
            }).ConfigureAwait(false);

        var result = await ValidateAsync(
            proof,
            expectedNonce: null,
            nonceRequired: false,
            accessToken: null,
            verifier: DpopTestSupport.Es256Verification,
            httpUrl: DefaultUrl).ConfigureAwait(false);
        Assert.AreEqual(DpopProofValidationFailureReason.JwkContainsPrivateKey, result.FailureReason);
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
        int signatureStart = proof.LastIndexOf('.', StringComparison.Ordinal) + 1;
        int tamperIndex = signatureStart + ((proof.Length - signatureStart) / 2);
        char tampered = proof[tamperIndex] == 'A' ? 'B' : 'A';
        string tamperedProof = string.Concat(
            proof.AsSpan(0, tamperIndex), tampered.ToString(), proof.AsSpan(tamperIndex + 1));

        var result = await ValidateAsync(
            tamperedProof,
            expectedNonce: null,
            nonceRequired: false,
            accessToken: null,
            verifier: DpopTestSupport.Es256Verification,
            httpUrl: DefaultUrl).ConfigureAwait(false);
        Assert.AreEqual(DpopProofValidationFailureReason.SignatureFailed, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsWrongHtm()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofAsync(key, BuildClaims() with { Htm = "GET" }).ConfigureAwait(false);

        var result = await ValidateAsync(
            proof,
            expectedNonce: null,
            nonceRequired: false,
            accessToken: null,
            verifier: DpopTestSupport.Es256Verification,
            httpUrl: DefaultUrl).ConfigureAwait(false);
        Assert.AreEqual(DpopProofValidationFailureReason.HtmMismatch, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsWrongHtu()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofAsync(key, BuildClaims() with { Htu = "https://attacker.example.com/token" }).ConfigureAwait(false);

        var result = await ValidateAsync(
            proof,
            expectedNonce: null,
            nonceRequired: false,
            accessToken: null,
            verifier: DpopTestSupport.Es256Verification,
            httpUrl: DefaultUrl).ConfigureAwait(false);
        Assert.AreEqual(DpopProofValidationFailureReason.HtuMismatch, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsOldIat()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        DpopProofClaims claims = BuildClaims() with { Iat = NowInstant - TimeSpan.FromMinutes(5) };
        string proof = await BuildProofAsync(key, claims).ConfigureAwait(false);

        var result = await ValidateAsync(
            proof,
            expectedNonce: null,
            nonceRequired: false,
            accessToken: null,
            verifier: DpopTestSupport.Es256Verification,
            httpUrl: DefaultUrl).ConfigureAwait(false);
        Assert.AreEqual(DpopProofValidationFailureReason.IatOutOfWindow, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsFutureIat()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        DpopProofClaims claims = BuildClaims() with { Iat = NowInstant + TimeSpan.FromMinutes(5) };
        string proof = await BuildProofAsync(key, claims).ConfigureAwait(false);

        var result = await ValidateAsync(
            proof,
            expectedNonce: null,
            nonceRequired: false,
            accessToken: null,
            verifier: DpopTestSupport.Es256Verification,
            httpUrl: DefaultUrl).ConfigureAwait(false);
        Assert.AreEqual(DpopProofValidationFailureReason.IatOutOfWindow, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 §4.3</see> check 11: the creation time of the
    /// proof is within an acceptable window, judged against the <c>iat</c> as written: one ten nanoseconds before the window's
    /// lower bound lies outside it, where taking its remainder up to the next tick put it onto the bound and admitted it; one at
    /// the bound lies inside it.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncJudgesTheFreshnessLowerBoundExactly()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        var key = new DpopKey(keys, WellKnownJwaValues.Es256);
        var lowerBound = (NowInstant - IatSkew - DateTimeOffset.UnixEpoch).Ticks / (decimal)TimeSpan.TicksPerSecond;

        var tenNanosecondsStale = await BuildProofAsync(key, BuildClaims() with { Iat = NumericDate.Of(lowerBound - 0.00000001m)! }).ConfigureAwait(false);
        var refused = await ValidateAsync(
            tenNanosecondsStale,
            expectedNonce: null,
            nonceRequired: false,
            accessToken: null,
            verifier: DpopTestSupport.Es256Verification,
            httpUrl: DefaultUrl).ConfigureAwait(false);

        Assert.AreEqual(DpopProofValidationFailureReason.IatOutOfWindow, refused.FailureReason, "An iat ten nanoseconds before the window is outside it.");

        var atTheBound = await BuildProofAsync(key, BuildClaims() with { Iat = NumericDate.Of(lowerBound)! }).ConfigureAwait(false);
        var admitted = await ValidateAsync(
            atTheBound,
            expectedNonce: null,
            nonceRequired: false,
            accessToken: null,
            verifier: DpopTestSupport.Es256Verification,
            httpUrl: DefaultUrl).ConfigureAwait(false);

        Assert.IsTrue(admitted.IsSuccess, $"An iat at the window's lower bound is inside it; got {admitted.FailureReason}.");
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsMissingNonceWhenRequired()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofAsync(key, BuildClaims()).ConfigureAwait(false);

        var result = await ValidateAsync(
            proof,
            expectedNonce: "expected-nonce",
            nonceRequired: true,
            accessToken: null,
            verifier: DpopTestSupport.Es256Verification,
            httpUrl: DefaultUrl).ConfigureAwait(false);
        Assert.AreEqual(DpopProofValidationFailureReason.NonceMissing, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsMismatchedNonce()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofAsync(key, BuildClaims() with { Nonce = "wrong-nonce" }).ConfigureAwait(false);

        var result = await ValidateAsync(
            proof,
            expectedNonce: "expected-nonce",
            nonceRequired: true,
            accessToken: null,
            verifier: DpopTestSupport.Es256Verification,
            httpUrl: DefaultUrl).ConfigureAwait(false);
        Assert.AreEqual(DpopProofValidationFailureReason.NonceMismatch, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsMismatchedAth()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofAsync(key, BuildClaims() with { Ath = "wrong-ath" }).ConfigureAwait(false);

        var result = await ValidateAsync(
            proof,
            expectedNonce: null,
            nonceRequired: false,
            accessToken: "presented-token",
            verifier: DpopTestSupport.Es256Verification,
            httpUrl: DefaultUrl).ConfigureAwait(false);
        Assert.AreEqual(DpopProofValidationFailureReason.AthMismatch, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 §4.3</see>: "servers SHOULD
    /// employ syntax-based normalization (Section 6.2.2 of [RFC3986]) ... before comparing the htu
    /// claim." and <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.1">RFC 3986
    /// §6.2.2.1</see>: "the hexadecimal digits within a percent-encoding triplet (e.g., "%3a" versus
    /// "%3A") are case-insensitive". A proof whose <c>htu</c> writes an encoded reserved character with
    /// lower-case hexadecimal digits where the request URI writes them in upper case names the same
    /// target, and the validator accepts it. The validator is called directly, since a protected
    /// endpoint's path carries no encoded reserved character a request could vary.
    /// </summary>
    /// <param name="htu">The proof's <c>htu</c>.</param>
    /// <param name="requestUrl">The target URI of the request.</param>
    [TestMethod]
    [DataRow("https://rs.example.com/a%3ab", "https://rs.example.com/a%3Ab")]
    [DataRow("https://rs.example.com/a%2fb", "https://rs.example.com/a%2Fb")]
    public async Task ValidateAsyncMatchesAnHtuWhosePercentEncodingDiffersOnlyInHexCaseAsync(string htu, string requestUrl)
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofAsync(key, BuildClaims() with { Htu = htu }).ConfigureAwait(false);
        var result = await ValidateAsync(
            proof,
            expectedNonce: null,
            nonceRequired: false,
            accessToken: null,
            verifier: DpopTestSupport.Es256Verification,
            httpUrl: requestUrl).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"The htu names the same target; got {result.FailureReason}.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-2.2">RFC 3986 §2.2</see>: "URIs that
    /// differ in the replacement of a reserved character with its corresponding percent-encoded octet are
    /// not equivalent." and <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449
    /// §4.3</see> item 9: "The htu claim matches the HTTP URI value for the HTTP request". A proof whose
    /// <c>htu</c> encodes a reserved character (<c>%3A</c>, <c>%2F</c>) where the request URI carries
    /// the character itself names another target and is refused with
    /// <see cref="DpopProofValidationFailureReason.HtuMismatch"/>.
    /// </summary>
    /// <param name="htu">The proof's <c>htu</c>.</param>
    /// <param name="requestUrl">The target URI of the request.</param>
    [TestMethod]
    [DataRow("https://rs.example.com/a%3Ab", "https://rs.example.com/a:b")]
    [DataRow("https://rs.example.com/a%2Fb", "https://rs.example.com/a/b")]
    public async Task ValidateAsyncRefusesAnHtuEncodingAReservedCharacterTheRequestCarriesLiterallyAsync(string htu, string requestUrl)
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofAsync(key, BuildClaims() with { Htu = htu }).ConfigureAwait(false);
        var result = await ValidateAsync(
            proof,
            expectedNonce: null,
            nonceRequired: false,
            accessToken: null,
            verifier: DpopTestSupport.Es256Verification,
            httpUrl: requestUrl).ConfigureAwait(false);

        Assert.AreEqual(DpopProofValidationFailureReason.HtuMismatch, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 §4.3</see> item 2: "The DPoP
    /// HTTP request header field value is a single and well-formed JWT." A proof whose signature segment
    /// makes it longer than <see cref="Jws.DefaultMaxJwsLength"/>, the longest compact JWS the library
    /// verifies, is answered by <see cref="DpopProofValidator.ValidateAsync"/> as a failure,
    /// <see cref="DpopProofValidationFailureReason.Malformed"/>, never an exception. The validator is
    /// public and is called directly here; <see cref="UserInfoEndpointTests.UserInfoRefusesADpopProofLongerThanTheVerifiedMaximumAsync"/>
    /// presents such a proof to an endpoint over the wire.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncAnswersAProofLongerThanTheVerifiedMaximumAsMalformedAsync()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofAsync(key, BuildClaims()).ConfigureAwait(false);
        string oversizedProof = proof + new string('A', Jws.DefaultMaxJwsLength);

        var result = await ValidateAsync(
            oversizedProof,
            expectedNonce: null,
            nonceRequired: false,
            accessToken: null,
            verifier: DpopTestSupport.Es256Verification,
            httpUrl: DefaultUrl).ConfigureAwait(false);

        Assert.AreEqual(DpopProofValidationFailureReason.Malformed, result.FailureReason);
    }


    //RFC 9449 §4.2 non-ECDSA algorithms — proof built with RS256 / PS256 /
    //EdDSA must pass validation when paired with the matching verification
    //delegate. End-to-end shape: real key material, real construction with
    //the correct signing function, real validation with the correct
    //verification function.

    [TestMethod]
    public async Task ValidateAsyncSucceedsOnFreshProofWithRs256()
    {
        var keys = TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Rs256);

        string proof = await DpopProofConstruction.BuildAsync(
            BuildClaims(),
            key,
            TestSetup.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctionsAdapter.SignRsaSha256Pkcs1Async,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        var result = await ValidateAsync(
            proof,
            expectedNonce: null,
            nonceRequired: false,
            accessToken: null,
            verifier: new JwsAlgorithmVerification(WellKnownJwaValues.Rs256, MicrosoftCryptographicFunctionsAdapter.VerifyRsaSha256Pkcs1Async),
            httpUrl: DefaultUrl).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"RS256 proof validation must succeed; got {result.FailureReason}.");
        Assert.AreEqual(
            DpopJwkUtilities.ComputeThumbprint(keys.PublicKey, WellKnownJwaValues.Rs256,
                TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared),
            result.JwkThumbprint);
    }


    [TestMethod]
    public async Task ValidateAsyncSucceedsOnFreshProofWithPs256()
    {
        var keys = TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Ps256);

        string proof = await DpopProofConstruction.BuildAsync(
            BuildClaims(),
            key,
            TestSetup.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctionsAdapter.SignRsaSha256PssAsync,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        var result = await ValidateAsync(
            proof,
            expectedNonce: null,
            nonceRequired: false,
            accessToken: null,
            verifier: new JwsAlgorithmVerification(WellKnownJwaValues.Ps256, MicrosoftCryptographicFunctionsAdapter.VerifyRsaSha256PssAsync),
            httpUrl: DefaultUrl).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"PS256 proof validation must succeed; got {result.FailureReason}.");
        Assert.AreEqual(
            DpopJwkUtilities.ComputeThumbprint(keys.PublicKey, WellKnownJwaValues.Ps256,
                TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared),
            result.JwkThumbprint);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.1">RFC 8725 Section 3.1</see>: "The library MUST ensure
    /// that the "alg" or "enc" header specifies the same algorithm that is used for the cryptographic operation." A proof
    /// signed with RSASSA-PKCS1-v1_5 and SHA-256 beneath a header naming PS256 over the same RSA key is refused as
    /// <see cref="DpopProofValidationFailureReason.InvalidAlg"/> under a supplied RS256 verification, which would verify the
    /// signature: the header names an algorithm the verification never performs. The same key's proof declaring RS256
    /// validates under the same verification, so the refusal is the binding's and not the key's.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncRefusesAPs256HeaderOverAnRs256SignatureUnderASuppliedRs256Verification()
    {
        var keys = TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial();
        var declaredKey = new DpopKey(keys, WellKnownJwaValues.Rs256);
        var mislabelledKey = new DpopKey(keys, WellKnownJwaValues.Ps256);

        var declared = await DpopProofConstruction.BuildAsync(
            BuildClaims(),
            declaredKey,
            TestSetup.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctionsAdapter.SignRsaSha256Pkcs1Async,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        var declaredResult = await ValidateAsync(
            declared,
            expectedNonce: null,
            nonceRequired: false,
            accessToken: null,
            verifier: new JwsAlgorithmVerification(WellKnownJwaValues.Rs256, MicrosoftCryptographicFunctionsAdapter.VerifyRsaSha256Pkcs1Async),
            httpUrl: DefaultUrl).ConfigureAwait(false);

        Assert.IsTrue(declaredResult.IsSuccess, $"The RS256 proof validates under the RS256 verification; got {declaredResult.FailureReason}.");

        var mislabelled = await DpopProofConstruction.BuildAsync(
            BuildClaims(),
            mislabelledKey,
            TestSetup.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctionsAdapter.SignRsaSha256Pkcs1Async,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        var mislabelledResult = await ValidateAsync(
            mislabelled,
            expectedNonce: null,
            nonceRequired: false,
            accessToken: null,
            verifier: new JwsAlgorithmVerification(WellKnownJwaValues.Rs256, MicrosoftCryptographicFunctionsAdapter.VerifyRsaSha256Pkcs1Async),
            httpUrl: DefaultUrl).ConfigureAwait(false);

        Assert.AreEqual(DpopProofValidationFailureReason.InvalidAlg, mislabelledResult.FailureReason,
            "A PS256 header names an algorithm the supplied RS256 verification never performs.");
    }


    [TestMethod]
    public async Task ValidateAsyncSucceedsOnFreshProofWithEdDsa()
    {
        var keys = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.EdDsa);

        string proof = await DpopProofConstruction.BuildAsync(
            BuildClaims(),
            key,
            TestSetup.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            BouncyCastleCryptographicFunctionsAdapter.SignEd25519Async,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        var result = await ValidateAsync(
            proof,
            expectedNonce: null,
            nonceRequired: false,
            accessToken: null,
            verifier: new JwsAlgorithmVerification(WellKnownJwaValues.EdDsa, BouncyCastleCryptographicFunctionsAdapter.VerifyEd25519Async),
            httpUrl: DefaultUrl).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"EdDSA proof validation must succeed; got {result.FailureReason}.");
        Assert.AreEqual(
            DpopJwkUtilities.ComputeThumbprint(keys.PublicKey, WellKnownJwaValues.EdDsa,
                TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared),
            result.JwkThumbprint);
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
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);


    private async Task<string> BuildProofWithCustomHeaderAsync(
        DpopKey key,
        DpopProofClaims claims,
        Func<IReadOnlyDictionary<string, object>, IReadOnlyDictionary<string, object>> headerTransform)
    {
        DpopJwsPartSerializer customSerializer = DpopJwsPartSerializerJson.Default with
        {
            SerializeHeader = header =>
                headerTransform(DpopJwsPartSerializerJson.Default.SerializeHeader(header))
        };

        return await DpopProofConstruction.BuildAsync(
            claims,
            key,
            TestSetup.Base64UrlEncoder,
            customSerializer,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Validates <paramref name="proof"/> with <see cref="DpopProofValidator.ValidateAsync"/> against a
    /// POST to <paramref name="httpUrl"/> on the fake clock.
    /// </summary>
    /// <param name="proof">The compact DPoP proof.</param>
    /// <param name="expectedNonce">The nonce the server provided, or <see langword="null"/> for none.</param>
    /// <param name="nonceRequired">Whether the request requires a nonce.</param>
    /// <param name="accessToken">The access token <c>ath</c> is checked against, or <see langword="null"/> for none.</param>
    /// <param name="verifier">The verification bound to the algorithm it performs.</param>
    /// <param name="httpUrl">The target URI of the request.</param>
    /// <returns>The validation result.</returns>
    private async Task<DpopProofValidationResult> ValidateAsync(
        string proof,
        string? expectedNonce,
        bool nonceRequired,
        string? accessToken,
        JwsAlgorithmVerification verifier,
        string httpUrl)
    {
        DpopProofValidationRequest request = new()
        {
            Proof = proof,
            HttpMethod = DefaultMethod,
            HttpUrl = httpUrl,
            ExpectedNonce = expectedNonce,
            NonceRequired = nonceRequired,
            AccessToken = accessToken
        };

        return await DpopProofValidator.ValidateAsync(
            request,
            verifier,
            DpopTestSupport.Parser,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            TimeProvider,
            BaseMemoryPool.Shared,
            IatSkew,
            TestContext.CancellationToken).ConfigureAwait(false);
    }
}
