using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
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

        DpopProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);

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

        DpopProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"A proof built with the default serializer must validate; got {result.FailureReason}.");

        string[] parts = proof.Split('.');
        Assert.HasCount(3, parts);

        HashSet<string> headerMembers = MemberNames(parts[0]);
        HashSet<string> payloadMembers = MemberNames(parts[1]);

        HashSet<string> expectedHeaderMembers = new(StringComparer.Ordinal)
        {
            WellKnownJoseHeaderNames.Typ, WellKnownJoseHeaderNames.Alg, WellKnownJoseHeaderNames.Jwk
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
        DpopProofValidationResult result = await ValidateAsync("not-a-jws").ConfigureAwait(false);
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

        DpopProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
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
                [WellKnownJoseHeaderNames.Alg] = WellKnownJwaValues.Hs256
            }).ConfigureAwait(false);

        DpopProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
        Assert.AreEqual(DpopProofValidationFailureReason.InvalidAlg, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>: "5. The alg JOSE
    /// Header Parameter indicates a registered asymmetric digital signature algorithm [IANA.JOSE.ALGS], is not none, is
    /// supported by the application, and is acceptable per local policy. 6. The JWT signature verifies with the public
    /// key contained in the jwk JOSE Header Parameter.", the signature verifying under the algorithm the header names
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.1">RFC 8725 Section 3.1</see>: "The library MUST
    /// ensure that the "alg" or "enc" header specifies the same algorithm that is used for the cryptographic
    /// operation."). A proof whose header names an asymmetric JWS signature algorithm identifier that is not an algorithm
    /// of the public key its <c>jwk</c> carries is refused as <see cref="DpopProofValidationFailureReason.InvalidAlg"/>,
    /// though that public key's own ES256 signature covers the header, where the receiver names no accepted algorithms.
    /// The rows, each over a P-256 public key: <c>ES384</c>, <c>RS256</c>, the Brainpool ECDSA identifier
    /// <c>ESB256</c>, <c>ML-DSA-44</c> and the fully-specified <c>Ed25519</c>.
    /// </summary>
    /// <param name="declaredAlgorithm">The algorithm the header names over a P-256 key's ES256 signature.</param>
    [TestMethod]
    [DataRow("ES384")]
    [DataRow("RS256")]
    [DataRow("ESB256")]
    [DataRow("ML-DSA-44")]
    [DataRow("Ed25519")]
    public async Task ValidateAsyncRejectsAnAlgThatIsNotOfTheProofKey(string declaredAlgorithm)
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofWithCustomHeaderAsync(key, BuildClaims(),
            header => new Dictionary<string, object>(header)
            {
                [WellKnownJoseHeaderNames.Alg] = declaredAlgorithm
            }).ConfigureAwait(false);

        DpopProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
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

        DpopProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
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

        DpopProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
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

        DpopProofValidationResult result = await ValidateAsync(tamperedProof).ConfigureAwait(false);
        Assert.AreEqual(DpopProofValidationFailureReason.SignatureFailed, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsWrongHtm()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofAsync(key, BuildClaims() with { Htm = "GET" }).ConfigureAwait(false);

        DpopProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
        Assert.AreEqual(DpopProofValidationFailureReason.HtmMismatch, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsWrongHtu()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofAsync(key, BuildClaims() with { Htu = "https://attacker.example.com/token" }).ConfigureAwait(false);

        DpopProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
        Assert.AreEqual(DpopProofValidationFailureReason.HtuMismatch, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>: "servers SHOULD employ
    /// syntax-based normalization (Section 6.2.2 of [RFC3986]) and scheme-based normalization (Section 6.2.3 of
    /// [RFC3986]) before comparing the htu claim." The form of
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2">RFC 3986 Section 6.2.2</see>: the scheme and host
    /// "should be normalized to lowercase" and the hexadecimal digits of a percent-encoding "should be normalized to use
    /// uppercase letters for the digits A-F" (Section 6.2.2.1); "These URIs should be normalized by decoding any
    /// percent-encoded octet that corresponds to an unreserved character, as described in Section 2.3." (Section 6.2.2.2),
    /// every other percent-encoding kept; dot segments removed (Section 6.2.2.3); an explicit default port removed and
    /// "a URI that uses the generic syntax for authority with an empty path should be normalized to a path of "/""
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.3">Section 6.2.3</see>); and no query or fragment
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>, htu: "without query
    /// and fragment parts"). The host is kept as written, a host in Unicode and its punycode form compared as written. A
    /// target URI normalized once is the expected text; normalized again it is the same text; parsed again its original
    /// string is the same text. The rows name each rule.
    /// </summary>
    /// <param name="target">The target URI as a request names it.</param>
    /// <param name="expected">The target URI in its normalized form.</param>
    [TestMethod]
    [DataRow("https://rs.example/a%20", "https://rs.example/a%20", DisplayName = "an encoded space ending the path")]
    [DataRow("https://rs.example/a%20%20", "https://rs.example/a%20%20", DisplayName = "two encoded spaces ending the path")]
    [DataRow("https://rs.example/%20", "https://rs.example/%20", DisplayName = "an encoded space alone")]
    [DataRow("https://rs.example/a%41b", "https://rs.example/aAb", DisplayName = "an encoded unreserved letter")]
    [DataRow("https://rs.example/a%7e%5F", "https://rs.example/a~_", DisplayName = "an encoded tilde and underscore")]
    [DataRow("https://rs.example/%E2%82%AC", "https://rs.example/%E2%82%AC", DisplayName = "an encoded character outside US-ASCII")]
    [DataRow("https://rs.example/a%e2%82%ac", "https://rs.example/a%E2%82%AC", DisplayName = "lower-case hexadecimal digits outside US-ASCII")]
    [DataRow("https://rs.example/a%7Bb", "https://rs.example/a%7Bb", DisplayName = "an encoded character outside the unreserved set")]
    [DataRow("https://rs.example/a/./b/../c", "https://rs.example/a/c", DisplayName = "dot segments")]
    [DataRow("https://RS.example:443/p", "https://rs.example/p", DisplayName = "the host's case and the default port")]
    [DataRow("https://rs.example/items/a%2Fb", "https://rs.example/items/a%2Fb", DisplayName = "an encoded reserved slash")]
    [DataRow("https://rs.example/items/a%2fb", "https://rs.example/items/a%2Fb", DisplayName = "an encoded reserved slash in lower case")]
    [DataRow("https://rs.example", "https://rs.example/", DisplayName = "an empty path")]
    [DataRow("https://rs.example/p?q=1", "https://rs.example/p", DisplayName = "a query")]
    [DataRow("https://rs.example/p#f", "https://rs.example/p", DisplayName = "a fragment")]
    [DataRow("https://[::1]:8443/p", "https://[::1]:8443/p", DisplayName = "an IPv6 literal with a port")]
    [DataRow("https://b\u00FCcher.example/p", "https://b\u00FCcher.example/p", DisplayName = "a host in Unicode")]
    [DataRow("https://xn--bcher-kva.example/p", "https://xn--bcher-kva.example/p", DisplayName = "a host in punycode")]
    [DataRow("http://rs.example:80/p", "http://rs.example/p", DisplayName = "the http default port")]
    public void NormalizeTargetUriAnswersOneReparseSafeFormOfATarget(string target, string expected)
    {
        string normalized = DpopProofValidator.NormalizeTargetUri(target);

        Assert.AreEqual(expected, normalized, "The target is read in its normalized form.");
        Assert.AreEqual(normalized, DpopProofValidator.NormalizeTargetUri(normalized), "The normalized form normalized again is itself.");
        Assert.AreEqual(normalized, new Uri(normalized).OriginalString, "The normalized form parsed again keeps its text.");
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsOldIat()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        DpopProofClaims claims = BuildClaims() with { Iat = NowInstant - TimeSpan.FromMinutes(5) };
        string proof = await BuildProofAsync(key, claims).ConfigureAwait(false);

        DpopProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
        Assert.AreEqual(DpopProofValidationFailureReason.IatOutOfWindow, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsFutureIat()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        DpopProofClaims claims = BuildClaims() with { Iat = NowInstant + TimeSpan.FromMinutes(5) };
        string proof = await BuildProofAsync(key, claims).ConfigureAwait(false);

        DpopProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);
        Assert.AreEqual(DpopProofValidationFailureReason.IatOutOfWindow, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsMissingNonceWhenRequired()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofAsync(key, BuildClaims()).ConfigureAwait(false);

        DpopProofValidationResult result = await ValidateAsync(
            proof, expectedNonce: "expected-nonce", nonceRequired: true).ConfigureAwait(false);
        Assert.AreEqual(DpopProofValidationFailureReason.NonceMissing, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsMismatchedNonce()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofAsync(key, BuildClaims() with { Nonce = "wrong-nonce" }).ConfigureAwait(false);

        DpopProofValidationResult result = await ValidateAsync(
            proof, expectedNonce: "expected-nonce", nonceRequired: true).ConfigureAwait(false);
        Assert.AreEqual(DpopProofValidationFailureReason.NonceMismatch, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidateAsyncRejectsMismatchedAth()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofAsync(key, BuildClaims() with { Ath = "wrong-ath" }).ConfigureAwait(false);

        DpopProofValidationResult result = await ValidateAsync(
            proof, accessToken: "presented-token").ConfigureAwait(false);
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
        DpopProofValidationResult result = await ValidateAsync(proof, httpUrl: requestUrl).ConfigureAwait(false);

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
        DpopProofValidationResult result = await ValidateAsync(proof, httpUrl: requestUrl).ConfigureAwait(false);

        Assert.AreEqual(DpopProofValidationFailureReason.HtuMismatch, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 §4.3</see> item 2: "The DPoP
    /// HTTP request header field value is a single and well-formed JWT." A proof whose signature segment
    /// makes it longer than <see cref="Jws.DefaultMaxJwsLength"/>, the longest compact JWS the library
    /// verifies, is answered by <see cref="DpopProofValidator"/> as a failure,
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

        DpopProofValidationResult result = await ValidateAsync(oversizedProof).ConfigureAwait(false);

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

        DpopProofValidationResult result = await ValidateAsync(
            proof, verifier: MicrosoftCryptographicFunctionsAdapter.VerifyRsaSha256Pkcs1Async).ConfigureAwait(false);

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

        DpopProofValidationResult result = await ValidateAsync(
            proof, verifier: MicrosoftCryptographicFunctionsAdapter.VerifyRsaSha256PssAsync).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"PS256 proof validation must succeed; got {result.FailureReason}.");
        Assert.AreEqual(
            DpopJwkUtilities.ComputeThumbprint(keys.PublicKey, WellKnownJwaValues.Ps256,
                TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared),
            result.JwkThumbprint);
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

        DpopProofValidationResult result = await ValidateAsync(
            proof, verifier: BouncyCastleCryptographicFunctionsAdapter.VerifyEd25519Async).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"EdDSA proof validation must succeed; got {result.FailureReason}.");
        Assert.AreEqual(
            DpopJwkUtilities.ComputeThumbprint(keys.PublicKey, WellKnownJwaValues.EdDsa,
                TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared),
            result.JwkThumbprint);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9864#section-4.1.1">RFC 9864 Section 4.1.1</see>: "Algorithm Name:
    /// Ed25519 Algorithm Description: EdDSA using the Ed25519 parameter set in Section 5.1 of [RFC8032]", an asymmetric
    /// JWS signature algorithm (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section
    /// 4.2</see>). A proof built with a DPoP key declaring <c>Ed25519</c> over an Ed25519 key pair validates when the
    /// receiver accepts the algorithms <see cref="WellKnownDpopValues.SupportedSigningAlgorithms"/> names, and the result
    /// carries the thumbprint of that public key.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ValidateAsyncSucceedsOnFreshProofWithEd25519()
    {
        var keys = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        using PublicKeyMemory publicKey = keys.PublicKey;
        using PrivateKeyMemory privateKey = keys.PrivateKey;
        DpopKey key = new(keys, WellKnownJwaValues.Ed25519);

        string proof = await DpopProofConstruction.BuildAsync(
            BuildClaims(),
            key,
            TestSetup.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            BouncyCastleCryptographicFunctionsAdapter.SignEd25519Async,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        DpopProofValidationResult result = await ValidateAsync(
            proof, verifier: BouncyCastleCryptographicFunctionsAdapter.VerifyEd25519Async,
            acceptedAlgorithms: WellKnownDpopValues.SupportedSigningAlgorithms).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Ed25519 proof validation must succeed; got {result.FailureReason}.");
        Assert.AreEqual(
            DpopJwkUtilities.ComputeThumbprint(keys.PublicKey, WellKnownJwaValues.Ed25519,
                TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared),
            result.JwkThumbprint);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>, of the proof's
    /// <c>alg</c>: "It MUST NOT be none or an identifier for a symmetric algorithm (Message Authentication Code (MAC))."
    /// A proof whose header declares <c>none</c> or the MAC identifier <c>HS256</c> over a P-256 public key's ES256
    /// signature is refused as <see cref="DpopProofValidationFailureReason.InvalidAlg"/>, as the DPoP header factory and
    /// the client's DPoP key refuse that identifier, the receiver's accepted algorithms naming it or not: the identifier
    /// is no asymmetric signature algorithm, and no algorithm of the proof's public key either.
    /// </summary>
    /// <param name="declaredAlgorithm">The algorithm the header declares over a P-256 DPoP key's ES256 signature.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("none")]
    [DataRow("HS256")]
    public async Task ValidateAsyncRefusesNoneOrAMacIdentifierEvenWhereTheAcceptedAlgorithmsNameItAsync(string declaredAlgorithm)
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory publicKey = keys.PublicKey;
        using PrivateKeyMemory privateKey = keys.PrivateKey;
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofWithCustomHeaderAsync(key, BuildClaims(),
            header => new Dictionary<string, object>(header)
            {
                [WellKnownJoseHeaderNames.Alg] = declaredAlgorithm
            }).ConfigureAwait(false);

        DpopProofValidationResult result = await ValidateAsync(proof, acceptedAlgorithms: [declaredAlgorithm]).ConfigureAwait(false);

        Assert.AreEqual(DpopProofValidationFailureReason.InvalidAlg, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 5: "The alg JOSE
    /// Header Parameter indicates a registered asymmetric digital signature algorithm [IANA.JOSE.ALGS], is not none, is
    /// supported by the application, and is acceptable per local policy." A proof whose header declares an asymmetric
    /// JWS signature algorithm identifier that the DPoP header factory writes and the client's DPoP key accepts, over a
    /// P-256 public key's ES256 signature, is refused as <see cref="DpopProofValidationFailureReason.InvalidAlg"/> where
    /// the receiver accepts the list <see cref="WellKnownDpopValues.SupportedSigningAlgorithms"/>, which does not name
    /// it: the factories and the validator agree on the identifier, and the validator refuses the proof, the identifier
    /// being no algorithm of the proof's public key as well. The rows: the Brainpool ECDSA identifier <c>ESB256</c> and
    /// <c>ML-DSA-44</c>.
    /// </summary>
    /// <param name="declaredAlgorithm">The algorithm the header declares over a P-256 DPoP key's ES256 signature.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("ESB256")]
    [DataRow("ML-DSA-44")]
    public async Task ValidateAsyncRefusesAnIdentifierTheDefaultAcceptedAlgorithmsDoNotNameAsync(string declaredAlgorithm)
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory publicKey = keys.PublicKey;
        using PrivateKeyMemory privateKey = keys.PrivateKey;
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofWithCustomHeaderAsync(key, BuildClaims(),
            header => new Dictionary<string, object>(header)
            {
                [WellKnownJoseHeaderNames.Alg] = declaredAlgorithm
            }).ConfigureAwait(false);

        DpopProofValidationResult result = await ValidateAsync(
            proof, acceptedAlgorithms: WellKnownDpopValues.SupportedSigningAlgorithms).ConfigureAwait(false);

        Assert.AreEqual(DpopProofValidationFailureReason.InvalidAlg, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 5: "The alg JOSE
    /// Header Parameter indicates a registered asymmetric digital signature algorithm [IANA.JOSE.ALGS], is not none, is
    /// supported by the application, and is acceptable per local policy.", each accepted identifier compared exactly, as
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515 Section 4.1.1</see> says: "The "alg"
    /// value is a case-sensitive ASCII string containing a StringOrURI value." A valid ES256 proof over its own P-256
    /// public key is refused as <see cref="DpopProofValidationFailureReason.InvalidAlg"/> where the receiver accepts
    /// <c>ES384</c> alone, where it accepts the empty list, and where it accepts <c>es256</c> alone, and validates where
    /// it accepts <c>ES256</c>.
    /// </summary>
    /// <param name="acceptedAlgorithms">The accepted identifiers, space-separated; the empty string for the empty list.</param>
    /// <param name="isAccepted">Whether the proof validates under that list.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("ES384", false, DisplayName = "ES384 alone")]
    [DataRow("", false, DisplayName = "the empty list")]
    [DataRow("es256", false, DisplayName = "es256 alone")]
    [DataRow("ES256", true, DisplayName = "ES256 alone")]
    public async Task ValidateAsyncRefusesAnIdentifierOutsideTheAcceptedAlgorithmsAsync(string acceptedAlgorithms, bool isAccepted)
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory publicKey = keys.PublicKey;
        using PrivateKeyMemory privateKey = keys.PrivateKey;
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofAsync(key, BuildClaims()).ConfigureAwait(false);
        DpopProofValidationResult result = await ValidateAsync(
            proof, acceptedAlgorithms: acceptedAlgorithms.Split(' ', StringSplitOptions.RemoveEmptyEntries)).ConfigureAwait(false);

        if(isAccepted)
        {
            Assert.IsTrue(result.IsSuccess, $"The proof validates under the list; got {result.FailureReason}.");

            return;
        }

        Assert.AreEqual(DpopProofValidationFailureReason.InvalidAlg, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 6: "The JWT
    /// signature verifies with the public key contained in the jwk JOSE Header Parameter.", the signature validated as
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 Section 5.2</see> step 8 says: "Validate
    /// the JWS Signature against the JWS Signing Input ... in the manner defined for the algorithm being used". A fresh
    /// proof signed under the algorithm by a key pair of its family validates through the provider the cryptographic
    /// function registry serves for the family of the public key the proof's <c>jwk</c> carries, no verification bound
    /// by the caller. The rows: <c>ES256</c> over P-256, <c>ES256K</c> over secp256k1, <c>Ed25519</c> and <c>EdDSA</c>
    /// over Ed25519, and over RSA each RSA identifier, its signature made under the scheme it names
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.3">RFC 7518 Section 3.3</see>, RSASSA-PKCS1-v1_5:
    /// <c>RS256</c>, <c>RS384</c>, <c>RS512</c>; <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.5">Section
    /// 3.5</see>, RSASSA-PSS: <c>PS256</c>, <c>PS384</c>, <c>PS512</c>).
    /// </summary>
    /// <param name="algorithm">The JWS <c>alg</c> the proof is signed under.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("ES256")]
    [DataRow("ES256K")]
    [DataRow("Ed25519")]
    [DataRow("EdDSA")]
    [DataRow("RS256")]
    [DataRow("RS384")]
    [DataRow("RS512")]
    [DataRow("PS256")]
    [DataRow("PS384")]
    [DataRow("PS512")]
    public async Task ValidateAsyncVerifiesThroughTheProviderTheRegistryServesForTheProofKeysFamilyAsync(string algorithm)
    {
        (PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> Keys, SigningDelegate Sign) family = algorithm switch
        {
            "ES256" => (TestKeyMaterialProvider.CreateFreshP256KeyMaterial(),
                MicrosoftCryptographicFunctionsAdapter.SignP256Async),
            "ES256K" => (TestKeyMaterialProvider.CreateFreshSecp256k1KeyMaterial(),
                BouncyCastleCryptographicFunctionsAdapter.SignSecp256k1Async),
            "Ed25519" or "EdDSA" => (TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial(),
                BouncyCastleCryptographicFunctionsAdapter.SignEd25519Async),
            "RS256" => (TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial(),
                MicrosoftCryptographicFunctionsAdapter.SignRsaSha256Pkcs1Async),
            "RS384" => (TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial(),
                MicrosoftCryptographicFunctionsAdapter.SignRsaSha384Pkcs1Async),
            "RS512" => (TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial(),
                MicrosoftCryptographicFunctionsAdapter.SignRsaSha512Pkcs1Async),
            "PS256" => (TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial(),
                MicrosoftCryptographicFunctionsAdapter.SignRsaSha256PssAsync),
            "PS384" => (TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial(),
                MicrosoftCryptographicFunctionsAdapter.SignRsaSha384PssAsync),
            "PS512" => (TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial(),
                MicrosoftCryptographicFunctionsAdapter.SignRsaSha512PssAsync),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "No such algorithm row.")
        };
        using PublicKeyMemory publicKey = family.Keys.PublicKey;
        using PrivateKeyMemory privateKey = family.Keys.PrivateKey;
        DpopKey key = new(family.Keys, algorithm);

        string proof = await DpopProofConstruction.BuildAsync(
            BuildClaims(),
            key,
            TestSetup.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            family.Sign,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        DpopProofValidationResult result = await ValidateThroughTheRegistryAsync(proof).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"The {algorithm} proof validates through the registry's provider; got {result.FailureReason}.");
        Assert.AreEqual(
            DpopJwkUtilities.ComputeThumbprint(family.Keys.PublicKey, algorithm, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared),
            result.JwkThumbprint);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 Section 5.2</see>, step 8: "Validate the
    /// JWS Signature against the JWS Signing Input ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' ||
    /// BASE64URL(JWS Payload)) in the manner defined for the algorithm being used, which MUST be accurately represented
    /// by the value of the "alg" (algorithm) Header Parameter, which MUST be present.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.1">RFC 8725 Section 3.1</see>: "The library MUST
    /// ensure that the "alg" or "enc" header specifies the same algorithm that is used for the cryptographic operation."
    /// A proof over an RSA public key whose header names an RSA identifier and whose signature is RSASSA-PKCS1-v1_5 with
    /// SHA-256, the scheme of <c>RS256</c>, is no signature under the identifier it names: validated with no
    /// verification bound by the caller, under a receiver that accepts that identifier, it is refused as
    /// <see cref="DpopProofValidationFailureReason.SignatureFailed"/>. The rows: the header names <c>PS256</c>, and the
    /// header names <c>RS384</c>.
    /// </summary>
    /// <param name="declaredAlgorithm">The RSA identifier the header names over an RSASSA-PKCS1-v1_5 SHA-256 signature.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("PS256")]
    [DataRow("RS384")]
    public async Task ValidateAsyncRefusesAnRsaProofSignedUnderAnotherSchemeThanItsAlgNamesAsync(string declaredAlgorithm)
    {
        var keys = TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial();
        using PublicKeyMemory publicKey = keys.PublicKey;
        using PrivateKeyMemory privateKey = keys.PrivateKey;
        DpopKey key = new(keys, declaredAlgorithm);

        string proof = await DpopProofConstruction.BuildAsync(
            BuildClaims(),
            key,
            TestSetup.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctionsAdapter.SignRsaSha256Pkcs1Async,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        DpopProofValidationResult result = await ValidateThroughTheRegistryAsync(proof, acceptedAlgorithms: [declaredAlgorithm]).ConfigureAwait(false);

        Assert.AreEqual(DpopProofValidationFailureReason.SignatureFailed, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 Section 5.2</see>, step 8: "Validate the
    /// JWS Signature against the JWS Signing Input ... in the manner defined for the algorithm being used, which MUST be
    /// accurately represented by the value of the "alg" (algorithm) Header Parameter, which MUST be present.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.1">RFC 8725 Section 3.1</see>: "The library MUST
    /// ensure that the "alg" or "enc" header specifies the same algorithm that is used for the cryptographic operation."
    /// A caller that binds its own verification primitive hands it the public key's octets and no algorithm, so the
    /// primitive decides the scheme it verifies under; a caller that accepts <c>PS256</c> binds the RSASSA-PSS with
    /// SHA-256 primitive (<see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.5">RFC 7518 Section 3.5</see>).
    /// With that primitive bound, a proof over an RSA public key whose header names <c>PS256</c> validates where its
    /// signature is RSASSA-PSS with SHA-256, and is refused as
    /// <see cref="DpopProofValidationFailureReason.SignatureFailed"/> where its signature is RSASSA-PKCS1-v1_5 with
    /// SHA-256, the scheme of <c>RS256</c>.
    /// </summary>
    /// <param name="isSignedUnderTheNamedScheme">Whether the signature is RSASSA-PSS with SHA-256, the scheme <c>PS256</c> names.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(true, DisplayName = "signed RSASSA-PSS with SHA-256")]
    [DataRow(false, DisplayName = "signed RSASSA-PKCS1-v1_5 with SHA-256")]
    public async Task ValidateAsyncVerifiesAPs256ProofUnderTheSchemeOfTheBoundPrimitiveAsync(bool isSignedUnderTheNamedScheme)
    {
        var keys = TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial();
        using PublicKeyMemory publicKey = keys.PublicKey;
        using PrivateKeyMemory privateKey = keys.PrivateKey;
        DpopKey key = new(keys, WellKnownJwaValues.Ps256);
        SigningDelegate sign = isSignedUnderTheNamedScheme switch
        {
            true => MicrosoftCryptographicFunctionsAdapter.SignRsaSha256PssAsync,
            false => MicrosoftCryptographicFunctionsAdapter.SignRsaSha256Pkcs1Async
        };

        string proof = await DpopProofConstruction.BuildAsync(
            BuildClaims(),
            key,
            TestSetup.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            sign,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        DpopProofValidationResult result = await ValidateAsync(
            proof, verifier: MicrosoftCryptographicFunctionsAdapter.VerifyRsaSha256PssAsync,
            acceptedAlgorithms: [WellKnownJwaValues.Ps256]).ConfigureAwait(false);

        if(isSignedUnderTheNamedScheme)
        {
            Assert.IsTrue(result.IsSuccess, $"The PS256 proof signed RSASSA-PSS validates under the bound primitive; got {result.FailureReason}.");

            return;
        }

        Assert.AreEqual(DpopProofValidationFailureReason.SignatureFailed, result.FailureReason);
    }


    /// <summary>
    /// The answer of the registry form to a <c>jwk</c> whose material is no public key it names canonically, or whose
    /// family is not the family of the header's <c>alg</c>, each row's reason the first check that refuses it. An RSA
    /// <c>e</c> with a leading zero octet (<see href="https://www.rfc-editor.org/rfc/rfc7518#section-2">RFC 7518 Section
    /// 2</see>, Base64urlUInt: "The octet sequence MUST utilize the minimum number of octets needed to represent the
    /// value.") reconstructs the public key whose canonical <c>e</c> has no such octet, so the thumbprints differ:
    /// <see cref="DpopProofValidationFailureReason.InvalidJwk"/>. A <c>jwk</c> whose <c>crv</c> is <c>secp256k1</c>
    /// under the header <c>alg</c> <c>ES256</c> reconstructs a secp256k1 public key, which <c>ES256</c> does not name
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.1">RFC 8725 Section 3.1</see>: "each key MUST be
    /// used with exactly one algorithm, and this MUST be checked when the cryptographic operation is performed."), so the
    /// check of the <c>alg</c> against the public key's family refuses first:
    /// <see cref="DpopProofValidationFailureReason.InvalidAlg"/>. A P-256 <c>x</c> of 31 octets
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.2">RFC 7518 Section 6.2.1.2</see>: "The length
    /// of this octet string MUST be the full size of a coordinate for the curve specified in the "crv" parameter.")
    /// reconstructs no point: <see cref="DpopProofValidationFailureReason.InvalidJwk"/>. An empty <c>n</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1.1">RFC 7518 Section 6.3.1.1</see>: "The "n"
    /// (modulus) parameter contains the modulus value for the RSA public key. It is represented as a
    /// Base64urlUInt-encoded value.", and an empty octet sequence encodes no modulus) and an
    /// <c>e</c> of zero (<see href="https://www.rfc-editor.org/rfc/rfc7518#section-2">RFC 7518 Section 2</see>: "Zero
    /// is represented as BASE64URL(single zero-valued octet), which is "AA"."; <see href="https://www.rfc-editor.org/rfc/rfc8017#section-3.1">RFC
    /// 8017 Section 3.1</see>: "the RSA public exponent e is an integer between 3 and n - 1") reconstruct no RSA public
    /// key:
    /// <see cref="DpopProofValidationFailureReason.InvalidJwk"/>. The header <c>alg</c> <c>ES256</c> over an RSA
    /// <c>jwk</c>, and the header <c>alg</c> <c>RS256</c> over a P-256 <c>jwk</c>, name an algorithm of another family
    /// than the public key's (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 Section 5.2</see>,
    /// step 8: "in the manner defined for the algorithm being used, which MUST be accurately represented by the value of
    /// the "alg" (algorithm) Header Parameter"): <see cref="DpopProofValidationFailureReason.InvalidAlg"/>.
    /// </summary>
    /// <param name="material">Which hostile or cross-family material the proof carries.</param>
    /// <param name="expectedReason">The reason the registry form answers.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("rsa-e-with-a-leading-zero", DpopProofValidationFailureReason.InvalidJwk, DisplayName = "an RSA e with a leading zero octet")]
    [DataRow("secp256k1-under-es256", DpopProofValidationFailureReason.InvalidAlg, DisplayName = "a secp256k1 jwk under the alg ES256")]
    [DataRow("p256-x-of-31-octets", DpopProofValidationFailureReason.InvalidJwk, DisplayName = "a P-256 x of 31 octets")]
    [DataRow("rsa-n-empty", DpopProofValidationFailureReason.InvalidJwk, DisplayName = "an empty RSA n")]
    [DataRow("rsa-e-of-zero", DpopProofValidationFailureReason.InvalidJwk, DisplayName = "an RSA e of zero")]
    [DataRow("es256-over-rsa", DpopProofValidationFailureReason.InvalidAlg, DisplayName = "the alg ES256 over an RSA jwk")]
    [DataRow("rs256-over-p256", DpopProofValidationFailureReason.InvalidAlg, DisplayName = "the alg RS256 over a P-256 jwk")]
    public async Task ValidateAsyncRefusesHostileOrCrossFamilyJwkMaterialThroughTheRegistryAsync(string material, DpopProofValidationFailureReason expectedReason)
    {
        (PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> Keys, string Algorithm, SigningDelegate Sign, Action<Dictionary<string, object>> Rewrite) row = material switch
        {
            "rsa-e-with-a-leading-zero" => (TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial(), WellKnownJwaValues.Rs256,
                MicrosoftCryptographicFunctionsAdapter.SignRsaSha256Pkcs1Async,
                static header => RespellJwkMember(header, WellKnownJwkMemberNames.E, PrependZeroOctet)),
            "secp256k1-under-es256" => (TestKeyMaterialProvider.CreateFreshSecp256k1KeyMaterial(), WellKnownJwaValues.Es256K,
                BouncyCastleCryptographicFunctionsAdapter.SignSecp256k1Async,
                static header => header[WellKnownJoseHeaderNames.Alg] = WellKnownJwaValues.Es256),
            "p256-x-of-31-octets" => (TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async,
                static header => RespellJwkMember(header, WellKnownJwkMemberNames.X, DropLastOctet)),
            "rsa-n-empty" => (TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial(), WellKnownJwaValues.Rs256,
                MicrosoftCryptographicFunctionsAdapter.SignRsaSha256Pkcs1Async,
                static header => RespellJwkMember(header, WellKnownJwkMemberNames.N, static _ => string.Empty)),
            "rsa-e-of-zero" => (TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial(), WellKnownJwaValues.Rs256,
                MicrosoftCryptographicFunctionsAdapter.SignRsaSha256Pkcs1Async,
                static header => RespellJwkMember(header, WellKnownJwkMemberNames.E, static _ => ZeroBase64UrlUInt)),
            "es256-over-rsa" => (TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial(), WellKnownJwaValues.Rs256,
                MicrosoftCryptographicFunctionsAdapter.SignRsaSha256Pkcs1Async,
                static header => header[WellKnownJoseHeaderNames.Alg] = WellKnownJwaValues.Es256),
            "rs256-over-p256" => (TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async,
                static header => header[WellKnownJoseHeaderNames.Alg] = WellKnownJwaValues.Rs256),
            _ => throw new ArgumentOutOfRangeException(nameof(material), material, "No such material row.")
        };
        using PublicKeyMemory publicKey = row.Keys.PublicKey;
        using PrivateKeyMemory privateKey = row.Keys.PrivateKey;
        DpopKey key = new(row.Keys, row.Algorithm);

        string proof = await BuildProofWithCustomHeaderAsync(key, BuildClaims(),
            header =>
            {
                Dictionary<string, object> rewritten = new(header);
                row.Rewrite(rewritten);

                return rewritten;
            },
            row.Sign).ConfigureAwait(false);
        DpopProofValidationResult result = await ValidateThroughTheRegistryAsync(proof).ConfigureAwait(false);

        Assert.AreEqual(expectedReason, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.2">RFC 7517 Section 4.2</see>: "The "use" (public key
    /// use) parameter identifies the intended use of the public key. The "use" parameter is employed to indicate whether
    /// a public key is used for encrypting data or verifying the signature on data.", its values "sig" (signature) and
    /// "enc" (encryption), and "The "use" value is a case-sensitive string.";
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 6: "The JWT
    /// signature verifies with the public key contained in the jwk JOSE Header Parameter." A proof signed under
    /// <c>ES256</c> by its P-256 key pair whose <c>jwk</c> declares a <c>use</c> other than the string <c>sig</c> carries
    /// no public key declared for verifying a signature, so it is refused as
    /// <see cref="DpopProofValidationFailureReason.InvalidJwk"/> in either form of validation: the registry form, no
    /// verification bound by the caller, and the form whose caller binds a P-256 verification. The rows: <c>use</c> the
    /// string <c>enc</c>, the JSON number <c>1</c>, and the JSON array <c>["sig"]</c>, each under both forms.
    /// </summary>
    /// <param name="declaredUse">The <c>use</c> the <c>jwk</c> declares, as its JSON text.</param>
    /// <param name="isRegistryForm">Whether the proof is validated with no verification bound by the caller.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("\"enc\"", true, DisplayName = "use enc, the registry form")]
    [DataRow("\"enc\"", false, DisplayName = "use enc, the form with a bound verification")]
    [DataRow("1", true, DisplayName = "use a JSON number, the registry form")]
    [DataRow("1", false, DisplayName = "use a JSON number, the form with a bound verification")]
    [DataRow("[\"sig\"]", true, DisplayName = "use a JSON array, the registry form")]
    [DataRow("[\"sig\"]", false, DisplayName = "use a JSON array, the form with a bound verification")]
    public async Task ValidateAsyncRefusesAJwkDeclaredForAnotherUseThanSignatureAsync(string declaredUse, bool isRegistryForm)
    {
        object use = declaredUse switch
        {
            "\"enc\"" => WellKnownJwkValues.UseEnc,
            "1" => 1,
            "[\"sig\"]" => new List<object> { WellKnownJwkValues.UseSig },
            _ => throw new ArgumentOutOfRangeException(nameof(declaredUse), declaredUse, "No such use row.")
        };
        string proof = await BuildProofDeclaringUseAsync(use).ConfigureAwait(false);
        DpopProofValidationResult result = isRegistryForm switch
        {
            true => await ValidateThroughTheRegistryAsync(proof).ConfigureAwait(false),
            false => await ValidateAsync(proof).ConfigureAwait(false)
        };

        Assert.AreEqual(DpopProofValidationFailureReason.InvalidJwk, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.2">RFC 7517 Section 4.2</see>: "The "use" (public key
    /// use) parameter identifies the intended use of the public key.", with the value "sig" (signature);
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 6: "The JWT
    /// signature verifies with the public key contained in the jwk JOSE Header Parameter." A proof signed under
    /// <c>ES256</c> by its P-256 key pair whose <c>jwk</c> declares the public key for signatures validates in either
    /// form of validation: the registry form, no verification bound by the caller, and the form whose caller binds a
    /// P-256 verification.
    /// </summary>
    /// <param name="isRegistryForm">Whether the proof is validated with no verification bound by the caller.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(true, DisplayName = "the registry form")]
    [DataRow(false, DisplayName = "the form with a bound verification")]
    public async Task ValidateAsyncVerifiesAJwkDeclaredForSignatureAsync(bool isRegistryForm)
    {
        string proof = await BuildProofDeclaringUseAsync(WellKnownJwkValues.UseSig).ConfigureAwait(false);
        DpopProofValidationResult result = isRegistryForm switch
        {
            true => await ValidateThroughTheRegistryAsync(proof).ConfigureAwait(false),
            false => await ValidateAsync(proof).ConfigureAwait(false)
        };

        Assert.IsTrue(result.IsSuccess, $"A proof whose jwk declares use sig validates; got {result.FailureReason}.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7638#section-3">RFC 7638 Section 3</see>: "Construct a JSON object
    /// [RFC7159] containing only the required members of a JWK representing the key and with no whitespace or line
    /// breaks before or after any syntactic elements and with the required members ordered lexicographically by the
    /// Unicode [UNICODE] code points of the member names. (This JSON object is itself a legal JWK representation of the
    /// key.)" A proof's <c>jwk</c> that is no such representation of the public key that verifies the proof names that
    /// public key under a thumbprint of its own spelling, so it is refused as
    /// <see cref="DpopProofValidationFailureReason.InvalidJwk"/>, the proof's own signature by that key pair over the
    /// re-spelled header notwithstanding. The rows: an ES256 proof whose <c>jwk</c> carries no <c>crv</c> and names its
    /// own <c>alg</c> <c>ES256</c> (<see href="https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1">RFC 7518 Section 6.2.1</see>: "The following
    /// members MUST be present for all Elliptic Curve public keys: o "crv" o "x""); an RS256 proof whose <c>n</c> carries
    /// a leading zero octet (<see href="https://www.rfc-editor.org/rfc/rfc7518#section-2">RFC 7518 Section 2</see>,
    /// Base64urlUInt: "The octet sequence MUST utilize the minimum number of octets needed to represent the value.");
    /// and an Ed25519 proof whose <c>x</c> is 31 octets (<see href="https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5">RFC
    /// 8032 Section 5.1.5</see>: "The 32-byte public key is generated by the following steps.").
    /// </summary>
    /// <param name="respelling">Which re-spelling of the <c>jwk</c> the proof carries.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("crv-absent", DisplayName = "an EC jwk without crv")]
    [DataRow("n-with-a-leading-zero", DisplayName = "an RSA n with a leading zero octet")]
    [DataRow("x-of-31-octets", DisplayName = "an Ed25519 x of 31 octets")]
    public async Task ValidateAsyncRefusesAJwkThatIsNoCanonicalRepresentationOfItsPublicKeyAsync(string respelling)
    {
        (PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> Keys, string Algorithm, SigningDelegate Sign, VerificationDelegate Verify, Action<Dictionary<string, object>> Respell) row = respelling switch
        {
            "crv-absent" => (TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async, MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
                DropCrvNamingEs256),
            "n-with-a-leading-zero" => (TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial(), WellKnownJwaValues.Rs256,
                MicrosoftCryptographicFunctionsAdapter.SignRsaSha256Pkcs1Async, MicrosoftCryptographicFunctionsAdapter.VerifyRsaSha256Pkcs1Async,
                static jwk => jwk[WellKnownJwkMemberNames.N] = PrependZeroOctet((string)jwk[WellKnownJwkMemberNames.N])),
            "x-of-31-octets" => (TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial(), WellKnownJwaValues.Ed25519,
                BouncyCastleCryptographicFunctionsAdapter.SignEd25519Async, BouncyCastleCryptographicFunctionsAdapter.VerifyEd25519Async,
                static jwk => jwk[WellKnownJwkMemberNames.X] = DropLastOctet((string)jwk[WellKnownJwkMemberNames.X])),
            _ => throw new ArgumentOutOfRangeException(nameof(respelling), respelling, "No such re-spelling row.")
        };
        using PublicKeyMemory publicKey = row.Keys.PublicKey;
        using PrivateKeyMemory privateKey = row.Keys.PrivateKey;
        DpopKey key = new(row.Keys, row.Algorithm);

        string proof = await BuildProofWithCustomHeaderAsync(key, BuildClaims(),
            header =>
            {
                Dictionary<string, object> respelled = new(header);
                Dictionary<string, object> jwk = new(
                    (IReadOnlyDictionary<string, object>)respelled[WellKnownJoseHeaderNames.Jwk], StringComparer.Ordinal);
                row.Respell(jwk);
                respelled[WellKnownJoseHeaderNames.Jwk] = jwk;

                return respelled;
            },
            row.Sign).ConfigureAwait(false);
        DpopProofValidationResult result = await ValidateAsync(proof, verifier: row.Verify).ConfigureAwait(false);

        Assert.AreEqual(DpopProofValidationFailureReason.InvalidJwk, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7638#section-3.2">RFC 7638 Section 3.2</see>: "Only the required
    /// members of a key's representation are used when computing its JWK Thumbprint value." An ES256 proof whose
    /// <c>jwk</c> carries a <c>kid</c> beside the required members of its P-256 public key validates, and the result
    /// carries the thumbprint of that public key.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ValidateAsyncVerifiesAJwkCarryingAKidBesideItsRequiredMembersAsync()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory publicKey = keys.PublicKey;
        using PrivateKeyMemory privateKey = keys.PrivateKey;
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await BuildProofWithCustomHeaderAsync(key, BuildClaims(),
            header =>
            {
                Dictionary<string, object> declared = new(header);
                declared[WellKnownJoseHeaderNames.Jwk] = new Dictionary<string, object>(
                    (IReadOnlyDictionary<string, object>)declared[WellKnownJoseHeaderNames.Jwk], StringComparer.Ordinal)
                {
                    [WellKnownJwkMemberNames.Kid] = "dpop-key-1"
                };

                return declared;
            }).ConfigureAwait(false);
        DpopProofValidationResult result = await ValidateAsync(proof).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"A proof whose jwk carries a kid validates; got {result.FailureReason}.");
        Assert.AreEqual(
            DpopJwkUtilities.ComputeThumbprint(keys.PublicKey, WellKnownJwaValues.Es256, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared),
            result.JwkThumbprint);
    }


    /// <summary>
    /// Builds an ES256 proof by a fresh P-256 key pair whose <c>jwk</c> carries the member <c>use</c> with
    /// <paramref name="use"/> beside the members of its public key.
    /// </summary>
    /// <param name="use">The <c>use</c> value the <c>jwk</c> declares, of whatever JSON type it is written in.</param>
    /// <returns>The compact proof.</returns>
    private async Task<string> BuildProofDeclaringUseAsync(object use)
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory publicKey = keys.PublicKey;
        using PrivateKeyMemory privateKey = keys.PrivateKey;
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        return await BuildProofWithCustomHeaderAsync(key, BuildClaims(),
            header =>
            {
                Dictionary<string, object> declared = new(header);
                declared[WellKnownJoseHeaderNames.Jwk] = new Dictionary<string, object>(
                    (IReadOnlyDictionary<string, object>)declared[WellKnownJoseHeaderNames.Jwk], StringComparer.Ordinal)
                {
                    [WellKnownJwkMemberNames.Use] = use
                };

                return declared;
            }).ConfigureAwait(false);
    }


    /// <summary>
    /// The base64url text of the octets <paramref name="encoded"/> decodes to with one zero octet before them, the
    /// spelling of the same unsigned integer in one octet more than its minimum.
    /// </summary>
    /// <param name="encoded">The member's base64url text.</param>
    /// <returns>The base64url text of the octets after a leading zero octet.</returns>
    private static string PrependZeroOctet(string encoded)
    {
        using System.Buffers.IMemoryOwner<byte> decoded = TestSetup.Base64UrlDecoder(encoded, BaseMemoryPool.Shared);
        ReadOnlySpan<byte> octets = decoded.Memory.Span;
        using System.Buffers.IMemoryOwner<byte> prefixed = BaseMemoryPool.Shared.Rent(octets.Length + 1);
        Span<byte> written = prefixed.Memory.Span[..(octets.Length + 1)];
        written[0] = 0;
        octets.CopyTo(written[1..]);

        return TestSetup.Base64UrlEncoder(written);
    }


    /// <summary>
    /// The Base64urlUInt spelling of zero, <see href="https://www.rfc-editor.org/rfc/rfc7518#section-2">RFC 7518 Section
    /// 2</see>: "Zero is represented as BASE64URL(single zero-valued octet), which is "AA"."
    /// </summary>
    private static string ZeroBase64UrlUInt => "AA";


    /// <summary>
    /// Replaces the member <paramref name="member"/> of the <c>jwk</c> in a serialized protected
    /// <paramref name="header"/> with what <paramref name="respell"/> makes of its text.
    /// </summary>
    /// <param name="header">The serialized protected header, rewritten in place.</param>
    /// <param name="member">The <c>jwk</c> member re-spelled.</param>
    /// <param name="respell">Makes the member's new text from its text.</param>
    private static void RespellJwkMember(Dictionary<string, object> header, string member, Func<string, string> respell)
    {
        Dictionary<string, object> jwk = new(
            (IReadOnlyDictionary<string, object>)header[WellKnownJoseHeaderNames.Jwk], StringComparer.Ordinal);
        jwk[member] = respell((string)jwk[member]);
        header[WellKnownJoseHeaderNames.Jwk] = jwk;
    }


    /// <summary>Removes <c>crv</c> from an EC <paramref name="jwk"/> and names <c>ES256</c> as its own <c>alg</c>.</summary>
    /// <param name="jwk">The <c>jwk</c> members, rewritten in place.</param>
    private static void DropCrvNamingEs256(Dictionary<string, object> jwk)
    {
        _ = jwk.Remove(WellKnownJwkMemberNames.Crv);
        jwk[WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256;
    }


    /// <summary>The base64url text of the octets <paramref name="encoded"/> decodes to, less the last one.</summary>
    /// <param name="encoded">The member's base64url text.</param>
    /// <returns>The base64url text of every octet but the last.</returns>
    private static string DropLastOctet(string encoded)
    {
        using System.Buffers.IMemoryOwner<byte> decoded = TestSetup.Base64UrlDecoder(encoded, BaseMemoryPool.Shared);

        return TestSetup.Base64UrlEncoder(decoded.Memory.Span[..^1]);
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


    /// <summary>
    /// Builds a proof whose serialized protected header <paramref name="headerTransform"/> rewrites before signing,
    /// signed by <paramref name="key"/> with <paramref name="sign"/>, or with the P-256 signing function when none is
    /// given.
    /// </summary>
    /// <param name="key">The DPoP key that signs the proof.</param>
    /// <param name="claims">The proof's claims.</param>
    /// <param name="headerTransform">Rewrites the serialized protected header.</param>
    /// <param name="sign">The signing function of the DPoP key's family, or <see langword="null"/> for P-256.</param>
    /// <returns>The compact proof.</returns>
    private async Task<string> BuildProofWithCustomHeaderAsync(
        DpopKey key,
        DpopProofClaims claims,
        Func<IReadOnlyDictionary<string, object>, IReadOnlyDictionary<string, object>> headerTransform,
        SigningDelegate? sign = null)
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
            sign ?? MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Validates <paramref name="proof"/> with the overload of <see cref="DpopProofValidator"/> that takes a
    /// <see cref="VerificationDelegate"/> against a
    /// POST to <paramref name="httpUrl"/> (the default token URL when none is given) on the fake clock.
    /// </summary>
    /// <param name="proof">The compact DPoP proof.</param>
    /// <param name="expectedNonce">The nonce the server provided, or <see langword="null"/>.</param>
    /// <param name="nonceRequired">Whether the request requires a nonce.</param>
    /// <param name="accessToken">The access token <c>ath</c> is checked against, or <see langword="null"/>.</param>
    /// <param name="verifier">The verification function, or <see langword="null"/> for P-256.</param>
    /// <param name="httpUrl">The target URI of the request, or <see langword="null"/> for the default.</param>
    /// <param name="acceptedAlgorithms">The <c>alg</c> values the receiver accepts, or <see langword="null"/> for none named.</param>
    /// <returns>The validation result.</returns>
    private async Task<DpopProofValidationResult> ValidateAsync(
        string proof,
        string? expectedNonce = null,
        bool nonceRequired = false,
        string? accessToken = null,
        VerificationDelegate? verifier = null,
        string? httpUrl = null,
        IReadOnlyList<string>? acceptedAlgorithms = null)
    {
        DpopProofValidationRequest request = new()
        {
            Proof = proof,
            HttpMethod = DefaultMethod,
            HttpUrl = httpUrl ?? DefaultUrl,
            ExpectedNonce = expectedNonce,
            NonceRequired = nonceRequired,
            AccessToken = accessToken,
            AcceptedAlgorithms = acceptedAlgorithms
        };

        return await DpopProofValidator.ValidateAsync(
            request,
            verifier ?? MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            DpopTestSupport.Parser,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            TimeProvider,
            BaseMemoryPool.Shared,
            IatSkew,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Validates <paramref name="proof"/> with the overload of <see cref="DpopProofValidator"/> that takes no
    /// <see cref="VerificationDelegate"/>, so the provider the test setup's registry serves for the tag of the proof's
    /// public key verifies it, against a POST to the default token URL on the fake clock.
    /// </summary>
    /// <param name="proof">The compact DPoP proof.</param>
    /// <param name="acceptedAlgorithms">The <c>alg</c> values the receiver accepts, or <see langword="null"/> for none named.</param>
    /// <returns>The validation result.</returns>
    private async Task<DpopProofValidationResult> ValidateThroughTheRegistryAsync(string proof, IReadOnlyList<string>? acceptedAlgorithms = null)
    {
        DpopProofValidationRequest request = new()
        {
            Proof = proof,
            HttpMethod = DefaultMethod,
            HttpUrl = DefaultUrl,
            NonceRequired = false,
            AcceptedAlgorithms = acceptedAlgorithms
        };

        return await DpopProofValidator.ValidateAsync(
            request,
            DpopTestSupport.Parser,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            TimeProvider,
            BaseMemoryPool.Shared,
            IatSkew,
            TestContext.CancellationToken).ConfigureAwait(false);
    }
}
