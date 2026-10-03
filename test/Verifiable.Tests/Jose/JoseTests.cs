using System.Buffers;
using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

using static Verifiable.JCose.CryptoFormatConversionsExtensions;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Tests for JOSE operations using both registry-based and explicit function APIs.
/// </summary>
[TestClass]
internal sealed class JoseTests
{
    /// <summary>
    /// Test context for accessing test information and cancellation token.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task SignAndVerifyWithExplicitFunctionSucceeds()
    {
        var header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256, [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt };
        var payload = new Dictionary<string, object> { [WellKnownJwtClaimNames.Sub] = "1234567890", ["name"] = "Test User" };

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        Assert.IsNotNull(jws);
        string[] parts = jws.Split('.');
        Assert.HasCount(3, parts);

        bool isValid = await Jws.VerifyAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "Signature verification should succeed.");
    }


    [TestMethod]
    public async Task SignAndVerifyWithResolverBinderSucceeds()
    {
        JwtHeader header = new() { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256, [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt };
        JwtPayload payload = new() { [WellKnownJwtClaimNames.Sub] = "resolver-test", ["name"] = "Resolver Test" };

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var resolverState = new TestResolverState(
            privateKey.AsReadOnlySpan().ToArray(),
            publicKey.AsReadOnlySpan().ToArray());

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared,
            resolverState,
            ResolvePrivateKeyMaterial,
            0,
            BindPrivateKey,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        Assert.IsNotNull(jws);
        string[] parts = jws.Split('.');
        Assert.HasCount(3, parts);

        bool isValid = await Jws.VerifyAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            BaseMemoryPool.Shared,
            resolverState,
            ResolvePublicKeyMaterial,
            0,
            BindPublicKey,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "Signature verification with resolver/binder should succeed.");
    }


    [TestMethod]
    public async Task SignAndVerifyWithP384ExplicitFunctionSucceeds()
    {
        var header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es384, [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt };
        var payload = new Dictionary<string, object> { [WellKnownJwtClaimNames.Sub] = "user-384", [WellKnownJwtClaimNames.Iat] = 1234567890 };

        var keyPair = TestKeyMaterialProvider.CreateP384KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP384Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        bool isValid = await Jws.VerifyAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP384Async,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "P-384 signature verification should succeed.");
    }


    [TestMethod]
    public async Task SignAndVerifyWithP521ExplicitFunctionSucceeds()
    {
        var header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es512, [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt };
        var payload = new Dictionary<string, object> { [WellKnownJwtClaimNames.Sub] = "user-521", [WellKnownJwtClaimNames.Exp] = 9999999999 };

        var keyPair = TestKeyMaterialProvider.CreateP521KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP521Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        bool isValid = await Jws.VerifyAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP521Async,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "P-521 signature verification should succeed.");
    }


    [TestMethod]
    public async Task VerifyWithWrongKeyFails()
    {
        var header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256, [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt };
        var payload = new Dictionary<string, object> { [WellKnownJwtClaimNames.Sub] = "test" };

        //Use one key pair for signing.
        var signingKeyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var signingPublicKey = signingKeyPair.PublicKey;
        using var signingPrivateKey = signingKeyPair.PrivateKey;

        //Create a different key pair for verification (wrong key).
        var wrongKeyPair = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var wrongPublicKey = wrongKeyPair.PublicKey;
        using var wrongPrivateKey = wrongKeyPair.PrivateKey;

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            signingPrivateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        bool isValid = await Jws.VerifyAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            wrongPublicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(isValid, "Verification with wrong key should fail.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 Section 5.2</see>: "If any of
    /// the listed steps fails, then the signature or MAC cannot be validated." The first of those steps parses
    /// the JWS Compact Serialization, which
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-7.1">RFC 7515 Section 7.1</see> gives as three
    /// base64url parts joined by two periods. A presented compact JWS of two or of four parts, or one longer than
    /// <see cref="Jws.DefaultMaxJwsLength"/> (this library's own guard against a large allocation, stated by no
    /// specification), cannot be validated: the explicit-function, the registry and the resolver overloads of
    /// <see cref="Jws.VerifyAsync(string, DecodeDelegate, BaseMemoryPool, PublicKeyMemory, VerificationDelegate, int, CryptoEventSink?, CancellationToken)"/>
    /// answer <see langword="false"/>, those of
    /// <see cref="Jws.VerifyAndDecodeAsync(string, DecodeDelegate, JwtPartDecoder, BaseMemoryPool, PublicKeyMemory, VerificationDelegate, int, CryptoEventSink?, CancellationToken)"/>
    /// answer a result that is not valid with an empty header and payload, and none raises anything, since the
    /// input is the presenter's, not the caller's.
    /// </summary>
    /// <param name="shape">The presented shape: <c>oversized</c>, <c>twoParts</c> or <c>fourParts</c>.</param>
    [TestMethod]
    [DataRow("oversized")]
    [DataRow("twoParts")]
    [DataRow("fourParts")]
    public async Task JwsVerifyAnswersFalseForOversizedOrMisshapenInput(string shape)
    {
        var header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256, [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt };
        var payload = new Dictionary<string, object> { [WellKnownJwtClaimNames.Sub] = "presented-shape-test" };

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);
        int signatureStart = jws.LastIndexOf('.', StringComparison.Ordinal) + 1;
        string presented = shape switch
        {
            "oversized" => jws + new string('A', Jws.DefaultMaxJwsLength + 1 - jws.Length),
            "twoParts" => jws[..(signatureStart - 1)],
            "fourParts" => jws + "." + jws[signatureStart..],
            _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, "No such presented shape.")
        };

        if(shape == "oversized")
        {
            Assert.AreEqual(Jws.DefaultMaxJwsLength + 1, presented.Length);
        }

        await AssertEveryBodyRefusesAsync(presented, publicKey, privateKey, shape, DecodeJwtPart).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 Section 5.2</see>, step 3: "Verify
    /// that the resulting octet sequence is a UTF-8-encoded representation of a completely valid JSON object
    /// conforming to RFC 7159 [RFC7159]; let the JWS Protected Header be this JSON object." A presented compact JWS
    /// whose protected header decodes to the JSON array <c>[]</c> (the segment <c>W10</c>), correctly signed over
    /// its signing input, cannot be validated: every verify body of <see cref="Jws"/> (the explicit-function, the
    /// registry and the resolver overloads of <c>VerifyAsync</c> and of <c>VerifyAndDecodeAsync</c>) answers not
    /// verified, the decode bodies with an empty header and payload, and none raises anything, the caller's part
    /// decoder included.
    /// </summary>
    [TestMethod]
    public async Task JwsVerifyAnswersFalseForAProtectedHeaderThatIsNotAJsonObject()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        string presented = await SignOverSegmentsAsync(
            EncodeSegment("[]"), EncodeSegment("""{"sub":"header-shape-test"}"""), privateKey, MicrosoftCryptographicFunctionsAdapter.SignP256Async).ConfigureAwait(false);

        Assert.IsTrue(presented.StartsWith("W10.", StringComparison.Ordinal), "The protected header segment is the base64url of the JSON array [].");

        await AssertEveryBodyRefusesAsync(presented, publicKey, privateKey, "array header", DecodeJwtPart).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 Section 5.2</see>, step 3: "Verify
    /// that the resulting octet sequence is a UTF-8-encoded representation of a completely valid JSON object
    /// conforming to RFC 7159 [RFC7159]; let the JWS Protected Header be this JSON object." A presented compact JWS
    /// whose protected header decodes to octets that are not JSON at all, correctly signed over its signing input,
    /// cannot be validated: every verify body of <see cref="Jws"/> answers not verified, the decode bodies with an
    /// empty header and payload, and none raises anything, the caller's part decoder included.
    /// </summary>
    [TestMethod]
    public async Task JwsVerifyAnswersFalseForAProtectedHeaderThatIsNotJson()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        string presented = await SignOverSegmentsAsync(
            EncodeSegment("not json"), EncodeSegment("""{"sub":"header-shape-test"}"""), privateKey, MicrosoftCryptographicFunctionsAdapter.SignP256Async).ConfigureAwait(false);

        await AssertEveryBodyRefusesAsync(presented, publicKey, privateKey, "non-JSON header", DecodeJwtPart).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-7.2">RFC 7519 Section 7.2</see>, step 10: "Verify
    /// that the resulting octet sequence is a UTF-8-encoded representation of a completely valid JSON object
    /// conforming to RFC 7159 [RFC7159]; let the JWT Claims Set be this JSON object." A presented compact JWS whose
    /// payload decodes to octets that are not JSON (<c>not json</c>), or to a JSON value that is not an object
    /// (<c>[]</c>), correctly signed over its signing input, carries no JWT Claims Set: the bodies that read the
    /// payload as one (the three overloads of <c>VerifyAndDecodeAsync</c> and the resolver overload of
    /// <c>VerifyAsync</c>, which hands the decoded payload to the caller's resolver) answer not verified, the
    /// decode bodies with an empty header and payload, and none raises anything. The part decoder of this row
    /// raises <see cref="System.Text.Json.JsonException"/> for a JSON value that is not an object, so the row
    /// shows that such a value never reaches the caller's part decoder.
    /// </summary>
    /// <param name="claimsSet">The text of the presented payload.</param>
    [TestMethod]
    [DataRow("not json")]
    [DataRow("[]")]
    public async Task JwsDecodeAnswersFalseForAPayloadThatIsNotAJsonObject(string claimsSet)
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        string presented = await SignOverSegmentsAsync(
            EncodeSegment("""{"alg":"ES256","typ":"JWT"}"""), EncodeSegment(claimsSet), privateKey, MicrosoftCryptographicFunctionsAdapter.SignP256Async).ConfigureAwait(false);

        await AssertEveryDecodingBodyRefusesAsync(presented, publicKey, privateKey, claimsSet, DecodeJwtPart).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC 7515 Section 2</see>, JWS Payload: "The
    /// sequence of octets to be secured -- a.k.a. the message.  The payload can contain an arbitrary sequence of
    /// octets." A compact JWS whose payload is not JSON (<c>not json</c>, and the empty payload), correctly signed
    /// over its signing input, verifies through the bodies that read no part as JSON: the explicit-function and the
    /// registry overloads of <c>VerifyAsync</c> answer <see langword="true"/>.
    /// </summary>
    /// <param name="payload">The text of the payload.</param>
    [TestMethod]
    [DataRow("not json")]
    [DataRow("")]
    public async Task JwsVerifyAnswersTrueForASignedPayloadThatIsNotJson(string payload)
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        string presented = await SignOverSegmentsAsync(
            EncodeSegment("""{"alg":"ES256","typ":"JWT"}"""), EncodeSegment(payload), privateKey, MicrosoftCryptographicFunctionsAdapter.SignP256Async).ConfigureAwait(false);

        bool isVerifiedByExplicitFunction = await Jws.VerifyAsync(
            presented,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(isVerifiedByExplicitFunction, $"A correctly signed payload '{payload}' verifies through the explicit function.");

        bool isVerifiedByRegistry = await Jws.VerifyAsync(
            presented,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(isVerifiedByRegistry, $"A correctly signed payload '{payload}' verifies through the registry.");
    }


    /// <summary>
    /// The decoder-refusal boundary, for a protected header. <see href="https://www.rfc-editor.org/rfc/rfc8259#section-9">RFC
    /// 8259 Section 9</see>: "An implementation may set limits on the range and precision of numbers." and "An
    /// implementation may set limits on the length and character contents of strings."
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.2">RFC 8259 Section 8.2</see> says of an unpaired
    /// surrogate such as "\uDEAD": "The behavior of software that receives JSON texts containing such values is
    /// unpredictable; for example, implementations might return different values for the length of a string value
    /// or even suffer fatal runtime exceptions." The library's own part decoder <see cref="JwtPartJson.Default"/>
    /// sets such limits: it refuses with <see cref="FormatException"/> a number no type it reads holds, and an
    /// escaped unpaired surrogate; it refuses an empty member name too, a limit of that decoder's own, which no
    /// specification requires. Each shape is well-formed UTF-8 JSON that passes the library's JSON gate, so the
    /// part decoder is asked and refuses it. A protected header of such a shape, correctly signed over its signing
    /// input, is answered by every body that decodes it: the resolver overload of <c>VerifyAsync</c> and the three
    /// overloads of <c>VerifyAndDecodeAsync</c>, each with <see cref="JwtPartJson.Default"/>, answer not verified,
    /// the decode bodies with an empty header and payload, and none raises anything.
    /// </summary>
    /// <param name="shape">The member the header carries after <c>alg</c>.</param>
    [TestMethod]
    [DataRow("numberOutsideDecimal")]
    [DataRow("emptyMemberName")]
    [DataRow("loneSurrogateEscape")]
    public async Task JwsDecodeAnswersNotVerifiedForAProtectedHeaderTheDefaultPartDecoderRefuses(string shape)
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        string presented = await SignOverSegmentsAsync(
            TestSetup.Base64UrlEncoder(JsonObjectTheDefaultPartDecoderRefuses("\"alg\":\"ES256\"", shape)),
            EncodeSegment("""{"sub":"header-shape-test"}"""),
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async).ConfigureAwait(false);

        await AssertEveryDecodingBodyRefusesAsync(presented, publicKey, privateKey, shape, JwtPartJson.Default).ConfigureAwait(false);
    }


    /// <summary>
    /// The decoder-refusal boundary, for a claims set. <see href="https://www.rfc-editor.org/rfc/rfc8259#section-9">RFC
    /// 8259 Section 9</see>: "An implementation may set limits on the range and precision of numbers." and "An
    /// implementation may set limits on the length and character contents of strings."
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.2">RFC 8259 Section 8.2</see> says of an unpaired
    /// surrogate such as "\uDEAD": "The behavior of software that receives JSON texts containing such values is
    /// unpredictable; for example, implementations might return different values for the length of a string value
    /// or even suffer fatal runtime exceptions." The library's own part decoder <see cref="JwtPartJson.Default"/>
    /// sets such limits: it refuses with <see cref="FormatException"/> a number no type it reads holds, and an
    /// escaped unpaired surrogate; it refuses an empty member name too, a limit of that decoder's own, which no
    /// specification requires. Each shape is well-formed UTF-8 JSON that passes the library's JSON gate, so the
    /// part decoder is asked and refuses it. A claims set of such a shape, correctly signed over its signing input,
    /// is answered by every body that decodes it: the resolver overload of <c>VerifyAsync</c> and the three
    /// overloads of <c>VerifyAndDecodeAsync</c>, each with <see cref="JwtPartJson.Default"/>, answer not verified,
    /// the decode bodies with an empty header and payload, and none raises anything.
    /// </summary>
    /// <param name="shape">The member the claims set carries after <c>sub</c>.</param>
    [TestMethod]
    [DataRow("numberOutsideDecimal")]
    [DataRow("emptyMemberName")]
    [DataRow("loneSurrogateEscape")]
    public async Task JwsDecodeAnswersNotVerifiedForAClaimsSetTheDefaultPartDecoderRefuses(string shape)
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        string presented = await SignOverSegmentsAsync(
            EncodeSegment("""{"alg":"ES256","typ":"JWT"}"""),
            TestSetup.Base64UrlEncoder(JsonObjectTheDefaultPartDecoderRefuses("\"sub\":\"claims-set-shape-test\"", shape)),
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async).ConfigureAwait(false);

        await AssertEveryDecodingBodyRefusesAsync(presented, publicKey, privateKey, shape, JwtPartJson.Default).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 Section 5.2</see>, step 3: "Verify
    /// that the resulting octet sequence is a UTF-8-encoded representation of a completely valid JSON object
    /// conforming to RFC 7159 [RFC7159]; let the JWS Protected Header be this JSON object." A presented compact JWS
    /// whose protected header carries the octet 0xFF inside a string, which no UTF-8 sequence holds, correctly
    /// signed over its signing input, cannot be validated by a body that decodes no part either: the
    /// explicit-function and the registry overloads of <c>VerifyAsync</c> answer <see langword="false"/>.
    /// </summary>
    [TestMethod]
    public async Task JwsVerifyAnswersFalseForASignedProtectedHeaderThatIsNotUtf8()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        string presented = await SignOverSegmentsAsync(
            TestSetup.Base64UrlEncoder(JsonObjectTheDefaultPartDecoderRefuses("\"alg\":\"ES256\"", "octetNotUtf8")),
            EncodeSegment("""{"sub":"header-encoding-test"}"""),
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async).ConfigureAwait(false);

        bool isVerifiedByExplicitFunction = await Jws.VerifyAsync(
            presented,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(isVerifiedByExplicitFunction, "A protected header that is not UTF-8 does not verify through the explicit function.");

        bool isVerifiedByRegistry = await Jws.VerifyAsync(
            presented,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(isVerifiedByRegistry, "A protected header that is not UTF-8 does not verify through the registry.");
    }


    /// <summary>
    /// The UTF-8 gate, for a protected header.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 Section 5.2</see>, step 3: "Verify
    /// that the resulting octet sequence is a UTF-8-encoded representation of a completely valid JSON object
    /// conforming to RFC 7159 [RFC7159]; let the JWS Protected Header be this JSON object." A presented protected
    /// header that carries the octet 0xFF inside a string, which no UTF-8 sequence holds, correctly signed over its
    /// signing input, cannot be validated, and the library's gate refuses it before any part decoder is asked:
    /// the resolver overload of <c>VerifyAsync</c> and the three overloads of <c>VerifyAndDecodeAsync</c>, each
    /// with a part decoder that faults if it is asked, answer not verified, the decode bodies with an empty header
    /// and payload, and none raises anything.
    /// </summary>
    [TestMethod]
    public async Task JwsDecodeAnswersNotVerifiedForAProtectedHeaderThatIsNotUtf8()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        string presented = await SignOverSegmentsAsync(
            TestSetup.Base64UrlEncoder(JsonObjectTheDefaultPartDecoderRefuses("\"alg\":\"ES256\"", "octetNotUtf8")),
            EncodeSegment("""{"sub":"header-encoding-test"}"""),
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async).ConfigureAwait(false);

        await AssertEveryDecodingBodyRefusesAsync(presented, publicKey, privateKey, "header not UTF-8", NeverAskedPartDecoder).ConfigureAwait(false);
    }


    /// <summary>
    /// The UTF-8 gate, for a claims set.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-7.2">RFC 7519 Section 7.2</see>, step 10: "Verify
    /// that the resulting octet sequence is a UTF-8-encoded representation of a completely valid JSON object
    /// conforming to RFC 7159 [RFC7159]; let the JWT Claims Set be this JSON object." A presented claims set that
    /// carries the octet 0xFF inside a string, which no UTF-8 sequence holds, correctly signed over its signing
    /// input, is no JWT Claims Set, and the library's gate refuses it before any part decoder is asked: the
    /// resolver overload of <c>VerifyAsync</c> and the three overloads of <c>VerifyAndDecodeAsync</c>, each with a
    /// part decoder that faults if it is asked, answer not verified, the decode bodies with an empty header and
    /// payload, and none raises anything.
    /// </summary>
    [TestMethod]
    public async Task JwsDecodeAnswersNotVerifiedForAClaimsSetThatIsNotUtf8()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        string presented = await SignOverSegmentsAsync(
            EncodeSegment("""{"alg":"ES256","typ":"JWT"}"""),
            TestSetup.Base64UrlEncoder(JsonObjectTheDefaultPartDecoderRefuses("\"sub\":\"claims-set-encoding-test\"", "octetNotUtf8")),
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async).ConfigureAwait(false);

        await AssertEveryDecodingBodyRefusesAsync(presented, publicKey, privateKey, "claims set not UTF-8", NeverAskedPartDecoder).ConfigureAwait(false);
    }


    /// <summary>
    /// A <see cref="JwtPartDecoder"/> that faults with <see cref="InvalidOperationException"/> whenever it is asked,
    /// so a row that hands it to the decoding bodies shows that the library's gate refused the part before any
    /// part decoder ran: a fault would propagate out of the body.
    /// </summary>
    /// <param name="part">The part octets, never read.</param>
    /// <returns>Never returns.</returns>
    private static IReadOnlyDictionary<string, object> NeverAskedPartDecoder(ReadOnlySpan<byte> part) =>
        throw new InvalidOperationException("The part decoder is asked only for a part that passed the gate.");


    /// <summary>
    /// The octets of a JSON object: an opening brace, <paramref name="leadingMember"/>, and the member
    /// <paramref name="shape"/> names. Two boundaries are exercised. <c>octetNotUtf8</c> is not UTF-8, so the
    /// library's JSON gate refuses it (RFC 7515 Section 5.2 step 3, RFC 7519 Section 7.2 step 10) and no part
    /// decoder is asked. <c>numberOutsideDecimal</c>, <c>emptyMemberName</c> and <c>loneSurrogateEscape</c> are
    /// well-formed UTF-8 JSON the gate passes, which <see cref="JwtPartJson.Default"/> refuses with
    /// <see cref="FormatException"/> within the limits RFC 8259 lets an implementation set (the empty member name
    /// as that decoder's own limit).
    /// </summary>
    /// <param name="leadingMember">The first member, as JSON text.</param>
    /// <param name="shape">
    /// <c>numberOutsideDecimal</c> (<c>"x":1e400</c>), <c>emptyMemberName</c> (<c>"":1</c>),
    /// <c>loneSurrogateEscape</c> (<c>"x":"\ud800"</c>) or <c>octetNotUtf8</c> (the octet 0xFF inside a string).
    /// </param>
    /// <returns>The octets of the object.</returns>
    private static byte[] JsonObjectTheDefaultPartDecoderRefuses(string leadingMember, string shape)
    {
        byte[] refusedMember = shape switch
        {
            "numberOutsideDecimal" => [.. "\"x\":1e400"u8],
            "emptyMemberName" => [.. "\"\":1"u8],
            "loneSurrogateEscape" => [.. "\"x\":\"\\ud800\""u8],
            "octetNotUtf8" => [.. "\"x\":\""u8, 0xFF, .. "\""u8],
            _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, "No such refused shape.")
        };

        return [.. "{"u8, .. Encoding.UTF8.GetBytes(leadingMember), .. ","u8, .. refusedMember, .. "}"u8];
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 Section 5.2</see>, step 6:
    /// "Base64url-decode the encoded representation of the JWS Payload, following the restriction that no line
    /// breaks, whitespace, or other additional characters have been used." and "If any of the listed steps fails,
    /// then the signature or MAC cannot be validated." A presented compact JWS whose payload segment is not
    /// base64url (<c>!</c>), correctly signed over its verbatim signing input with the project's P-256 provider,
    /// cannot be validated: every verify body of <see cref="Jws"/> answers not verified, the explicit compact
    /// <c>VerifyAsync</c> included, which checks the segment before the backend is asked, and none raises anything.
    /// </summary>
    [TestMethod]
    public async Task JwsVerifyAnswersFalseForASignedPayloadSegmentThatIsNotBase64Url()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        string presented = await SignOverSegmentsAsync(
            EncodeSegment("""{"alg":"ES256","typ":"JWT"}"""), "!", privateKey, MicrosoftCryptographicFunctionsAdapter.SignP256Async).ConfigureAwait(false);

        await AssertEveryBodyRefusesAsync(presented, publicKey, privateKey, "non-base64url payload segment", DecodeJwtPart).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC 7515 Section 2</see>, Base64url Encoding:
    /// "Base64 encoding using the URL- and filename-safe character set defined in Section 5 of RFC 4648 [RFC4648],
    /// with all trailing '=' characters omitted (as permitted by Section 3.2) and without the inclusion of any line
    /// breaks, whitespace, or other additional characters." A presented compact JWS whose signature segment
    /// carries the padding <c>==</c> or <c>=</c>, whose payload segment carries the padding its length would take,
    /// whose payload segment spells its octets with <c>+</c> and <c>/</c> in place of <c>-</c> and <c>_</c>, or
    /// whose signature or payload segment has a length of 1 modulo 4, which no base64url encoding has, is not that
    /// encoding: every verify body of <see cref="Jws"/> answers it as not verified and raises nothing, whatever the
    /// caller's decoder accepts. Each shape starts from a correctly signed JWS that verifies, and a respelled payload
    /// segment is signed over in its presented spelling.
    /// </summary>
    /// <param name="shape">The presented spelling of the correctly signed JWS.</param>
    [TestMethod]
    [DataRow("signaturePaddedTwice")]
    [DataRow("signaturePaddedOnce")]
    [DataRow("payloadPadded")]
    [DataRow("standardAlphabet")]
    [DataRow("signatureLengthOneModFour")]
    [DataRow("payloadLengthOneModFour")]
    public async Task JwsVerifyAnswersFalseForASegmentThatIsNotUnpaddedBase64Url(string shape)
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        string headerSegment = EncodeSegment(SegmentFormHeader);
        string payloadSegment = EncodeSegment(SegmentFormClaimsSet);
        Assert.AreEqual(2, payloadSegment.Length % 4, "The payload segment's length takes two padding characters.");
        Assert.Contains("-", payloadSegment, StringComparison.Ordinal, "The payload segment holds a character the standard alphabet spells as '+'.");
        string wholeGroupsPayloadSegment = EncodeSegment(SegmentFormWholeGroupsClaimsSet);
        Assert.AreEqual(0, wholeGroupsPayloadSegment.Length % 4, "The whole-groups payload segment is groups of four characters.");

        string signed = await SignAndAssertVerifiesAsync(headerSegment, payloadSegment, publicKey, privateKey).ConfigureAwait(false);
        Assert.AreEqual(2, (signed.Length - signed.LastIndexOf('.', StringComparison.Ordinal) - 1) % 4, "The 64-octet signature segment is 86 characters.");

        string presented = shape switch
        {
            "signaturePaddedTwice" => signed + "==",
            "signaturePaddedOnce" => signed + "=",
            "payloadPadded" => await SignOverSegmentsAsync(headerSegment, payloadSegment + "==", privateKey, MicrosoftCryptographicFunctionsAdapter.SignP256Async).ConfigureAwait(false),
            "standardAlphabet" => await SignOverSegmentsAsync(headerSegment, payloadSegment.Replace('-', '+').Replace('_', '/'), privateKey, MicrosoftCryptographicFunctionsAdapter.SignP256Async).ConfigureAwait(false),
            "signatureLengthOneModFour" => signed + "AAA",
            "payloadLengthOneModFour" => await SignOverSegmentsAsync(headerSegment, wholeGroupsPayloadSegment + "A", privateKey, MicrosoftCryptographicFunctionsAdapter.SignP256Async).ConfigureAwait(false),
            _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, "No such presented spelling.")
        };

        await AssertEveryBodyRefusesAsync(presented, publicKey, privateKey, shape, DecodeJwtPart, TolerantBase64UrlDecoder).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 Section 5.2</see>, step 2:
    /// "Base64url-decode the encoded representation of the JWS Protected Header, following the restriction that no
    /// line breaks, whitespace, or other additional characters have been used." Steps 6 and 7 place the same
    /// restriction on the JWS Payload and the JWS Signature, and "If any of the listed steps fails, then the
    /// signature or MAC cannot be validated." A presented compact JWS whose signature segment carries a space or a
    /// line feed inside it or a tab after it, whose protected header segment carries a space inside it (the JWS
    /// signed over that verbatim segment), or whose signature segment is white space alone cannot be validated:
    /// every verify body of <see cref="Jws"/> answers it as not verified and raises nothing, whatever the caller's
    /// decoder skips. Each shape starts from a correctly signed JWS that verifies.
    /// </summary>
    /// <param name="shape">The presented spelling of the correctly signed JWS.</param>
    [TestMethod]
    [DataRow("signatureSpaceInside")]
    [DataRow("signatureLineFeedInside")]
    [DataRow("signatureTabAfter")]
    [DataRow("headerSpaceInside")]
    [DataRow("signatureWhiteSpaceOnly")]
    public async Task JwsVerifyAnswersFalseForASegmentWithWhiteSpace(string shape)
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        string headerSegment = EncodeSegment(SegmentFormHeader);
        string payloadSegment = EncodeSegment(SegmentFormClaimsSet);
        string signed = await SignAndAssertVerifiesAsync(headerSegment, payloadSegment, publicKey, privateKey).ConfigureAwait(false);
        int signatureStart = signed.LastIndexOf('.', StringComparison.Ordinal) + 1;

        string presented = shape switch
        {
            "signatureSpaceInside" => signed.Insert(signatureStart + 40, " "),
            "signatureLineFeedInside" => signed.Insert(signatureStart + 40, "\n"),
            "signatureTabAfter" => signed + "\t",
            "headerSpaceInside" => await SignOverSegmentsAsync(headerSegment.Insert(8, " "), payloadSegment, privateKey, MicrosoftCryptographicFunctionsAdapter.SignP256Async).ConfigureAwait(false),
            "signatureWhiteSpaceOnly" => signed[..signatureStart] + "    ",
            _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, "No such presented spelling.")
        };

        await AssertEveryBodyRefusesAsync(presented, publicKey, privateKey, shape, DecodeJwtPart, TolerantBase64UrlDecoder).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC 7515 Section 2</see> defines the base64url
    /// encoding a compact JWS segment is. A 64-octet signature is 86 characters: 84 characters carry 63 octets, and
    /// the last two carry the 64th, the last character two bits of that octet and four bits that carry no octet; an
    /// encoder writes those four bits as zero. A
    /// signature segment whose last character sets one of them decodes, under a decoder that ignores them, to the
    /// same signature, so it would be a second presented string for one JWS: this library answers it as a segment
    /// that is not the encoding, a rule of its own. Every verify body of <see cref="Jws"/> answers such a
    /// correctly signed JWS as not verified and raises nothing, whatever the caller's decoder ignores.
    /// </summary>
    [TestMethod]
    public async Task JwsVerifyAnswersFalseForASignatureSegmentWhoseUnusedBitsAreSet()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        string signed = await SignAndAssertVerifiesAsync(EncodeSegment(SegmentFormHeader), EncodeSegment(SegmentFormClaimsSet), publicKey, privateKey).ConfigureAwait(false);
        Assert.AreEqual(2, (signed.Length - signed.LastIndexOf('.', StringComparison.Ordinal) - 1) % 4, "The 64-octet signature segment is 86 characters.");

        int lastValue = Base64UrlAlphabet.IndexOf(signed[^1], StringComparison.Ordinal);
        Assert.AreEqual(0, lastValue & 0x0F, "The encoder wrote the four bits that carry no octet as zero.");
        string presented = signed[..^1] + Base64UrlAlphabet[lastValue | 0x01];

        await AssertEveryBodyRefusesAsync(presented, publicKey, privateKey, "unused bits set", DecodeJwtPart, TolerantBase64UrlDecoder).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 Section 5.2</see>, step 7:
    /// "Base64url-decode the encoded representation of the JWS Signature, following the restriction that no line
    /// breaks, whitespace, or other additional characters have been used." A non-empty signature segment is the
    /// encoding of at least one octet, so a caller's decoder that answers no octets for the signature segment of a
    /// correctly signed compact JWS has decoded no JWS Signature, and "If any of the listed steps fails, then the
    /// signature or MAC cannot be validated.": every verify body of <see cref="Jws"/> answers not verified and
    /// raises nothing, the resolver bodies included, which hand the decoded signature to the bound public key in a
    /// buffer of their own.
    /// </summary>
    [TestMethod]
    public async Task JwsVerifyAnswersFalseWhenTheDecoderAnswersNoOctetsForASegment()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        string signed = await SignAndAssertVerifiesAsync(EncodeSegment(SegmentFormHeader), EncodeSegment(SegmentFormClaimsSet), publicKey, privateKey).ConfigureAwait(false);
        string signatureSegment = signed[(signed.LastIndexOf('.', StringComparison.Ordinal) + 1)..];

        //The caller's decoder answers no octets for the signature segment and decodes every other segment.
        IMemoryOwner<byte> decoder(ReadOnlySpan<char> source, BaseMemoryPool pool) => source.SequenceEqual(signatureSegment.AsSpan())
            ? new NoOctetsOwner()
            : TestSetup.Base64UrlDecoder(source, pool);

        await AssertEveryBodyRefusesAsync(signed, publicKey, privateKey, "signature segment of no octets", DecodeJwtPart, decoder).ConfigureAwait(false);
    }


    /// <summary>
    /// The owner a misbehaving decoder answers for a segment it decodes to no octets: its memory is empty and
    /// disposing it releases nothing.
    /// </summary>
    private sealed class NoOctetsOwner: IMemoryOwner<byte>
    {
        /// <summary>The empty memory of no octets.</summary>
        public Memory<byte> Memory => Memory<byte>.Empty;

        /// <summary>Releases nothing, since the owner holds no buffer.</summary>
        public void Dispose()
        {
        }
    }


    /// <summary>The protected header of the rows that respell a segment of a correctly signed JWS.</summary>
    private static string SegmentFormHeader { get; } = """{"alg":"ES256","typ":"JWT"}""";


    /// <summary>
    /// The claims set of the rows that respell a segment of a correctly signed JWS: its base64url segment holds a
    /// <c>-</c> and has a length of 2 modulo 4.
    /// </summary>
    private static string SegmentFormClaimsSet { get; } = """{"sub":"segment-form-test","note":"~~~"}""";


    /// <summary>
    /// The claims set of the row that lengthens a payload segment to 1 modulo 4: its 27 octets encode to a
    /// base64url segment of whole groups of four characters, so one character after it carries no whole octet.
    /// </summary>
    private static string SegmentFormWholeGroupsClaimsSet { get; } = """{"sub":"segment-form-test"}""";


    /// <summary>The 64 characters of the base64url alphabet, each at the index of its value.</summary>
    private static string Base64UrlAlphabet { get; } = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";


    /// <summary>
    /// Signs the verbatim segments with the P-256 <paramref name="privateKey"/> and asserts that the compact JWS
    /// verifies through the explicit-function <c>VerifyAsync</c>, so a row that respells a segment starts from a
    /// correctly signed JWS that verifies.
    /// </summary>
    /// <param name="headerSegment">The protected header segment.</param>
    /// <param name="payloadSegment">The payload segment.</param>
    /// <param name="publicKey">The P-256 public key.</param>
    /// <param name="privateKey">The P-256 private key.</param>
    /// <returns>The compact JWS.</returns>
    private async Task<string> SignAndAssertVerifiesAsync(string headerSegment, string payloadSegment, PublicKeyMemory publicKey, PrivateKeyMemory privateKey)
    {
        string signed = await SignOverSegmentsAsync(headerSegment, payloadSegment, privateKey, MicrosoftCryptographicFunctionsAdapter.SignP256Async).ConfigureAwait(false);

        bool isVerified = await Jws.VerifyAsync(
            signed,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(isVerified, "The correctly signed compact JWS verifies before a segment is respelled.");

        return signed;
    }


    /// <summary>
    /// A <see cref="DecodeDelegate"/> that accepts more spellings of one octet sequence than
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC 7515 Section 2</see> defines: it reads
    /// <c>+</c> and <c>/</c> as <c>-</c> and <c>_</c>, ignores a lone alphabet character after the last whole group
    /// of four (six bits, no whole octet), ignores the bits of the last character that carry no octet, and otherwise
    /// decodes as <see cref="TestSetup.Base64UrlDecoder"/> does, padding and white space included. The shape of a
    /// caller's decoder that is more lenient than the compact serialization allows.
    /// </summary>
    /// <param name="source">The segment.</param>
    /// <param name="pool">The pool the decoded octets are rented from.</param>
    /// <returns>The decoded octets.</returns>
    private static IMemoryOwner<byte> TolerantBase64UrlDecoder(ReadOnlySpan<char> source, BaseMemoryPool pool)
    {
        char[] spelled = source.ToArray();
        int alphabetCount = 0;
        int lastAlphabetIndex = -1;
        for(int i = 0; i < spelled.Length; ++i)
        {
            spelled[i] = spelled[i] switch
            {
                '+' => '-',
                '/' => '_',
                _ => spelled[i]
            };

            if(Base64UrlAlphabet.Contains(spelled[i], StringComparison.Ordinal))
            {
                ++alphabetCount;
                lastAlphabetIndex = i;
            }
        }

        //A lone alphabet character after the last whole group of four carries no whole octet; this decoder drops it.
        if(alphabetCount % 4 == 1)
        {
            spelled = [.. spelled.AsSpan(0, lastAlphabetIndex), .. spelled.AsSpan(lastAlphabetIndex + 1)];
        }

        int unusedBits = (spelled.Length % 4) switch
        {
            2 => 0x0F,
            3 => 0x03,
            _ => 0x00
        };

        int lastValue = spelled.Length == 0 ? -1 : Base64UrlAlphabet.IndexOf(spelled[^1], StringComparison.Ordinal);
        if(unusedBits != 0 && lastValue >= 0)
        {
            spelled[^1] = Base64UrlAlphabet[lastValue & ~unusedBits];
        }

        return TestSetup.Base64UrlDecoder(spelled, pool);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.3">RFC 8725 Section 3.3</see>: "All
    /// cryptographic operations used in the JWT MUST be validated and the entire JWT MUST be rejected if any of
    /// them fail to validate." A presented compact JWS whose Ed25519 signature is 63 octets, not the 64 an Ed25519
    /// signature has, does not validate: the resolver overloads of <c>VerifyAsync</c> and
    /// <c>VerifyAndDecodeAsync</c>, binding the public key to a real Ed25519 backend, answer not verified and
    /// raise nothing, whether the backend answers the length as a failed verification (BouncyCastle, the provider
    /// the test registry wires) or refuses it with an exception (Libsodium), the same boundary the explicit bodies
    /// apply to the verification.
    /// </summary>
    /// <param name="providerName">The Ed25519 backend the binder binds: <c>BouncyCastle</c> or <c>Libsodium</c>.</param>
    [TestMethod]
    [DataRow("BouncyCastle")]
    [DataRow("Libsodium")]
    public async Task JwsResolverVerifyAnswersFalseForAnEd25519SignatureOfTheWrongLength(string providerName)
    {
        VerificationDelegate verification = providerName switch
        {
            "BouncyCastle" => BouncyCastleCryptographicFunctionsAdapter.VerifyEd25519Async,
            "Libsodium" => LibsodiumCryptographicFunctionsAdapter.VerifyEd25519Async,
            _ => throw new ArgumentOutOfRangeException(nameof(providerName), providerName, "No such Ed25519 provider.")
        };

        var keyPair = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        string signed = await SignOverSegmentsAsync(
            EncodeSegment("""{"alg":"EdDSA","typ":"JWT"}"""), EncodeSegment("""{"sub":"signature-length-test"}"""), privateKey, BouncyCastleCryptographicFunctionsAdapter.SignEd25519Async).ConfigureAwait(false);

        int signatureStart = signed.LastIndexOf('.', StringComparison.Ordinal) + 1;
        using IMemoryOwner<byte> signature = TestSetup.Base64UrlDecoder(signed.AsSpan(signatureStart), BaseMemoryPool.Shared);
        Assert.HasCount(64, signature.Memory.ToArray());
        string presented = signed[..signatureStart] + TestSetup.Base64UrlEncoder(signature.Memory.Span[..63]);

        var resolverState = new TestResolverState(
            privateKey.AsReadOnlySpan().ToArray(),
            publicKey.AsReadOnlySpan().ToArray(),
            CryptoTags.Ed25519PublicKey);

        bool isVerifiedByResolver = await Jws.VerifyAsync(
            presented,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            BaseMemoryPool.Shared,
            resolverState,
            ResolvePublicKeyMaterial,
            verification,
            BindPublicKeyWith,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        JwsVerificationResult decodedByResolver = await Jws.VerifyAndDecodeAsync(
            presented,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            BaseMemoryPool.Shared,
            resolverState,
            ResolvePublicKeyMaterial,
            verification,
            BindPublicKeyWith,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(isVerifiedByResolver, $"A 63-octet Ed25519 signature does not verify through the resolver bound to {providerName}.");
        Assert.IsFalse(decodedByResolver.IsValid, $"A 63-octet Ed25519 signature does not decode as verified through the resolver bound to {providerName}.");
    }


    /// <summary>
    /// A <see cref="DecodeDelegate"/> reports base64url it refuses with <see cref="FormatException"/> (the
    /// .NET <c>Base64Url</c> decoders), which the verify bodies answer as not verified. Any other exception is a
    /// fault of the caller's decoder, not a property of the presented input, so it propagates out of every
    /// verify body that decodes a segment: the explicit-function, the registry and the resolver overloads of
    /// <c>VerifyAsync</c> and of <c>VerifyAndDecodeAsync</c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.3">RFC 8725 Section 3.3</see> asks that the
    /// JWT be rejected when an operation fails to validate; a decoder that faults has validated nothing, and
    /// answering it as a token the verifier rejects would hide the fault.
    /// </summary>
    [TestMethod]
    public async Task JwsVerifyPropagatesADecoderFaultOutsideMalformedInput()
    {
        var header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256, [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt };
        var payload = new Dictionary<string, object> { [WellKnownJwtClaimNames.Sub] = "decoder-fault-test" };

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        await AssertEveryBodyPropagatesAsync<InvalidOperationException>(jws, FaultingDecoder, publicKey, privateKey, FaultingDecoderMessage).ConfigureAwait(false);
    }


    /// <summary>
    /// A <see cref="DecodeDelegate"/> refuses base64url it cannot decode with <see cref="FormatException"/>, and
    /// an empty segment is answered as malformed before any decoder is asked. An
    /// <see cref="ArgumentOutOfRangeException"/> a decoder raises for a non-empty segment is no refusal of the
    /// presented input but a fault of the caller's decoder (an argument it mishandles), so it propagates out of
    /// every verify body that decodes a segment: the explicit-function, the registry and the resolver overloads
    /// of <c>VerifyAsync</c> and of <c>VerifyAndDecodeAsync</c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.3">RFC 8725 Section 3.3</see>: "All
    /// cryptographic operations used in the JWT MUST be validated and the entire JWT MUST be rejected if any of
    /// them fail to validate." A decoder that faults has validated nothing, and answering its fault as a JWT the
    /// verifier rejects would hide the fault.
    /// </summary>
    [TestMethod]
    public async Task JwsVerifyPropagatesAnArgumentFaultOfTheDecoder()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        string jws = await SignOverSegmentsAsync(
            EncodeSegment("""{"alg":"ES256","typ":"JWT"}"""), EncodeSegment("""{"sub":"decoder-argument-fault-test"}"""), privateKey, MicrosoftCryptographicFunctionsAdapter.SignP256Async).ConfigureAwait(false);

        await AssertEveryBodyPropagatesAsync<ArgumentOutOfRangeException>(jws, ArgumentFaultingDecoder, publicKey, privateKey, ArgumentFaultingDecoderMessage).ConfigureAwait(false);
    }


    /// <summary>
    /// Presents <paramref name="jws"/> with <paramref name="decoder"/> to every compact verify body of
    /// <see cref="Jws"/> under the P-256 <paramref name="publicKey"/> and asserts, straight after each call, that
    /// the body raised exactly <typeparamref name="TException"/> with <paramref name="expectedMessage"/>.
    /// </summary>
    /// <typeparam name="TException">The exception the decoder raises.</typeparam>
    /// <param name="jws">The presented compact JWS.</param>
    /// <param name="decoder">The faulting decode delegate.</param>
    /// <param name="publicKey">The P-256 public key.</param>
    /// <param name="privateKey">The P-256 private key, carried in the resolver state as the fixture's resolvers expect.</param>
    /// <param name="expectedMessage">The message of the decoder's fault.</param>
    /// <returns>A task that completes when every body was asserted.</returns>
    private async Task AssertEveryBodyPropagatesAsync<TException>(string jws, DecodeDelegate decoder, PublicKeyMemory publicKey, PrivateKeyMemory privateKey, string expectedMessage)
        where TException : Exception
    {
        var resolverState = new TestResolverState(
            privateKey.AsReadOnlySpan().ToArray(),
            publicKey.AsReadOnlySpan().ToArray());

        CancellationToken cancellationToken = TestContext.CancellationToken;

        TException byExplicitFunction = await Assert.ThrowsExactlyAsync<TException>(async () =>
            await Jws.VerifyAsync(jws, decoder, BaseMemoryPool.Shared, publicKey, MicrosoftCryptographicFunctionsAdapter.VerifyP256Async, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        Assert.AreEqual(expectedMessage, byExplicitFunction.Message);

        TException byRegistry = await Assert.ThrowsExactlyAsync<TException>(async () =>
            await Jws.VerifyAsync(jws, decoder, BaseMemoryPool.Shared, publicKey, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        Assert.AreEqual(expectedMessage, byRegistry.Message);

        TException byResolver = await Assert.ThrowsExactlyAsync<TException>(async () =>
            await Jws.VerifyAsync(jws, decoder, DecodeJwtPart, BaseMemoryPool.Shared, resolverState, ResolvePublicKeyMaterial, 0, BindPublicKey, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        Assert.AreEqual(expectedMessage, byResolver.Message);

        TException decodeByExplicitFunction = await Assert.ThrowsExactlyAsync<TException>(async () =>
            await Jws.VerifyAndDecodeAsync(jws, decoder, DecodeJwtPart, BaseMemoryPool.Shared, publicKey, MicrosoftCryptographicFunctionsAdapter.VerifyP256Async, Jws.DefaultMaxJwsLength, cancellationToken: cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        Assert.AreEqual(expectedMessage, decodeByExplicitFunction.Message);

        TException decodeByRegistry = await Assert.ThrowsExactlyAsync<TException>(async () =>
            await Jws.VerifyAndDecodeAsync(jws, decoder, DecodeJwtPart, BaseMemoryPool.Shared, publicKey, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        Assert.AreEqual(expectedMessage, decodeByRegistry.Message);

        TException decodeByResolver = await Assert.ThrowsExactlyAsync<TException>(async () =>
            await Jws.VerifyAndDecodeAsync(jws, decoder, DecodeJwtPart, BaseMemoryPool.Shared, resolverState, ResolvePublicKeyMaterial, 0, BindPublicKey, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        Assert.AreEqual(expectedMessage, decodeByResolver.Message);
    }


    /// <summary>The message of the fault <see cref="FaultingDecoder"/> raises.</summary>
    private static string FaultingDecoderMessage { get; } = "The decoder faulted on its own state.";


    /// <summary>The message of the fault <see cref="ArgumentFaultingDecoder"/> raises, as the exception renders it.</summary>
    private static string ArgumentFaultingDecoderMessage { get; } = "The decoder mishandled its own argument. (Parameter 'source')";


    /// <summary>
    /// A <see cref="DecodeDelegate"/> that faults on every non-empty segment with an
    /// <see cref="ArgumentOutOfRangeException"/>, an exception no base64url decoder raises for input it refuses:
    /// the shape of a caller's decoder that mishandles an argument.
    /// </summary>
    /// <param name="source">The segment, never decoded.</param>
    /// <param name="pool">The pool, never rented from.</param>
    /// <returns>Never returns.</returns>
    private static IMemoryOwner<byte> ArgumentFaultingDecoder(ReadOnlySpan<char> source, BaseMemoryPool pool) =>
        throw new ArgumentOutOfRangeException(nameof(source), "The decoder mishandled its own argument.");


    /// <summary>
    /// A <see cref="DecodeDelegate"/> that faults on every segment with an <see cref="InvalidOperationException"/>,
    /// an exception no base64url decoder raises for input it refuses: the shape of a caller's decoder whose own
    /// state is broken.
    /// </summary>
    /// <param name="source">The segment, never read.</param>
    /// <param name="pool">The pool, never rented from.</param>
    /// <returns>Never returns.</returns>
    private static IMemoryOwner<byte> FaultingDecoder(ReadOnlySpan<char> source, BaseMemoryPool pool) =>
        throw new InvalidOperationException(FaultingDecoderMessage);


    /// <summary>
    /// Presents <paramref name="presented"/> to every compact verify body of <see cref="Jws"/> under the P-256
    /// <paramref name="publicKey"/> and asserts each answer straight after its own call: the explicit-function
    /// and the registry overloads of <c>VerifyAsync</c> answer <see langword="false"/>, and then every body that
    /// decodes a part refuses as <see cref="AssertEveryDecodingBodyRefusesAsync"/> asserts. The explicit function
    /// and the resolver's binder use the project's P-256 provider, the registry overloads the test registry's.
    /// </summary>
    /// <param name="presented">The presented compact JWS.</param>
    /// <param name="publicKey">The P-256 public key the JWS is verified under.</param>
    /// <param name="privateKey">The P-256 private key, carried in the resolver state as the fixture's resolvers expect.</param>
    /// <param name="shape">The presented shape, named in the failure messages.</param>
    /// <param name="partDecoder">The part decoder the decoding bodies are given.</param>
    /// <param name="base64UrlDecoder">
    /// The base64url decoder every body is given, or <see langword="null"/> for <see cref="TestSetup.Base64UrlDecoder"/>.
    /// </param>
    /// <returns>A task that completes when every body was asserted.</returns>
    private async Task AssertEveryBodyRefusesAsync(string presented, PublicKeyMemory publicKey, PrivateKeyMemory privateKey, string shape, JwtPartDecoder partDecoder, DecodeDelegate? base64UrlDecoder = null)
    {
        DecodeDelegate decoder = base64UrlDecoder ?? TestSetup.Base64UrlDecoder;

        bool isVerifiedByExplicitFunction = await Jws.VerifyAsync(
            presented,
            decoder,
            BaseMemoryPool.Shared,
            publicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(isVerifiedByExplicitFunction, $"A presented '{shape}' compact JWS does not verify through the explicit function.");

        bool isVerifiedByRegistry = await Jws.VerifyAsync(
            presented,
            decoder,
            BaseMemoryPool.Shared,
            publicKey,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(isVerifiedByRegistry, $"A presented '{shape}' compact JWS does not verify through the registry.");

        await AssertEveryDecodingBodyRefusesAsync(presented, publicKey, privateKey, shape, partDecoder, decoder).ConfigureAwait(false);
    }


    /// <summary>
    /// Presents <paramref name="presented"/> to every compact verify body of <see cref="Jws"/> that decodes a part
    /// with <paramref name="partDecoder"/> and asserts each answer straight after its own call: the resolver
    /// overload of <c>VerifyAsync</c> answers <see langword="false"/>, and the explicit-function, the registry and
    /// the resolver overloads of <c>VerifyAndDecodeAsync</c> answer a result that is not valid with an empty header
    /// and payload.
    /// </summary>
    /// <param name="presented">The presented compact JWS.</param>
    /// <param name="publicKey">The P-256 public key the JWS is verified under.</param>
    /// <param name="privateKey">The P-256 private key, carried in the resolver state as the fixture's resolvers expect.</param>
    /// <param name="shape">The presented shape, named in the failure messages.</param>
    /// <param name="partDecoder">The part decoder the bodies are given.</param>
    /// <param name="base64UrlDecoder">
    /// The base64url decoder every body is given, or <see langword="null"/> for <see cref="TestSetup.Base64UrlDecoder"/>.
    /// </param>
    /// <returns>A task that completes when every body was asserted.</returns>
    private async Task AssertEveryDecodingBodyRefusesAsync(string presented, PublicKeyMemory publicKey, PrivateKeyMemory privateKey, string shape, JwtPartDecoder partDecoder, DecodeDelegate? base64UrlDecoder = null)
    {
        DecodeDelegate decoder = base64UrlDecoder ?? TestSetup.Base64UrlDecoder;

        var resolverState = new TestResolverState(
            privateKey.AsReadOnlySpan().ToArray(),
            publicKey.AsReadOnlySpan().ToArray());

        bool isVerifiedByResolver = await Jws.VerifyAsync(
            presented,
            decoder,
            partDecoder,
            BaseMemoryPool.Shared,
            resolverState,
            ResolvePublicKeyMaterial,
            0,
            BindPublicKey,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(isVerifiedByResolver, $"A presented '{shape}' compact JWS does not verify through the resolver.");

        JwsVerificationResult decodedByExplicitFunction = await Jws.VerifyAndDecodeAsync(
            presented,
            decoder,
            partDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            Jws.DefaultMaxJwsLength,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        AssertUndecoded(decodedByExplicitFunction, shape, "the explicit function");

        JwsVerificationResult decodedByRegistry = await Jws.VerifyAndDecodeAsync(
            presented,
            decoder,
            partDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            TestContext.CancellationToken).ConfigureAwait(false);
        AssertUndecoded(decodedByRegistry, shape, "the registry");

        JwsVerificationResult decodedByResolver = await Jws.VerifyAndDecodeAsync(
            presented,
            decoder,
            partDecoder,
            BaseMemoryPool.Shared,
            resolverState,
            ResolvePublicKeyMaterial,
            0,
            BindPublicKey,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        AssertUndecoded(decodedByResolver, shape, "the resolver");
    }


    /// <summary>
    /// Asserts that a <c>VerifyAndDecodeAsync</c> body answered a result that is not valid with an empty header
    /// and payload for the presented <paramref name="shape"/>.
    /// </summary>
    /// <param name="result">The body's answer.</param>
    /// <param name="shape">The presented shape, named in the failure messages.</param>
    /// <param name="body">The body, named in the failure messages.</param>
    private static void AssertUndecoded(JwsVerificationResult result, string shape, string body)
    {
        Assert.IsFalse(result.IsValid, $"A presented '{shape}' compact JWS does not decode as verified through {body}.");
        Assert.IsEmpty(result.Header, $"A presented '{shape}' compact JWS decodes no header through {body}.");
        Assert.IsEmpty(result.Payload, $"A presented '{shape}' compact JWS decodes no payload through {body}.");
    }


    /// <summary>Encodes the UTF-8 octets of <paramref name="text"/> as one base64url segment.</summary>
    /// <param name="text">The segment's text.</param>
    /// <returns>The base64url segment.</returns>
    private static string EncodeSegment(string text) => TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(text));


    /// <summary>
    /// Signs the verbatim signing input <c>headerSegment.payloadSegment</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.1">RFC 7515 Section 5.1</see>) with
    /// <paramref name="signing"/> and answers the compact JWS, so a segment the library would never produce
    /// carries a signature that is correct over exactly those octets.
    /// </summary>
    /// <param name="headerSegment">The protected header segment as presented.</param>
    /// <param name="payloadSegment">The payload segment as presented.</param>
    /// <param name="privateKey">The signing private key.</param>
    /// <param name="signing">The project's signing function for <paramref name="privateKey"/>.</param>
    /// <returns>The compact JWS <c>headerSegment.payloadSegment.signature</c>.</returns>
    private async Task<string> SignOverSegmentsAsync(string headerSegment, string payloadSegment, PrivateKeyMemory privateKey, SigningDelegate signing)
    {
        string signingInput = headerSegment + "." + payloadSegment;
        (Signature signature, CryptoEvent? _) = await signing(
            privateKey.AsReadOnlyMemory(), Encoding.ASCII.GetBytes(signingInput), BaseMemoryPool.Shared, context: null, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using(signature)
        {
            return signingInput + "." + TestSetup.Base64UrlEncoder(signature.AsReadOnlySpan());
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.3">RFC 8725 Section 3.3</see>: "All
    /// cryptographic operations used in the JWT MUST be validated and the entire JWT MUST be rejected if any of
    /// them fail to validate." A public key handed to a registry overload can come from the presenter (a public key read from a
    /// token header); for an X25519 key agreement public key, a pair the registry serves no verification function for,
    /// the registry overloads of <see cref="Jws.VerifyAsync(JwsMessage, EncodeDelegate, PublicKeyMemory, BaseMemoryPool, CancellationToken)"/>,
    /// <see cref="Jws.VerifyAsync(string, DecodeDelegate, BaseMemoryPool, PublicKeyMemory, int, CancellationToken)"/>
    /// and <see cref="Jws.VerifyAndDecodeAsync(string, DecodeDelegate, JwtPartDecoder, BaseMemoryPool, PublicKeyMemory, int, CancellationToken)"/>
    /// answer not verified and raise nothing; the decode keeps the decoded header for inspection.
    /// </summary>
    [TestMethod]
    public async Task JwsVerifyAnswersFalseForAPublicKeyTheRegistryDoesNotServe()
    {
        var header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256, [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt };
        var payload = new Dictionary<string, object> { [WellKnownJwtClaimNames.Sub] = "unserved-pair-test" };

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var exchangeKeyPair = TestKeyMaterialProvider.CreateX25519KeyMaterial();
        using var exchangePublicKey = exchangeKeyPair.PublicKey;
        using var exchangePrivateKey = exchangeKeyPair.PrivateKey;

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        bool isMessageVerified = await Jws.VerifyAsync(
            jwsMessage,
            TestSetup.Base64UrlEncoder,
            exchangePublicKey,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        bool isCompactVerified = await Jws.VerifyAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            exchangePublicKey,
            Jws.DefaultMaxJwsLength,
            TestContext.CancellationToken).ConfigureAwait(false);

        JwsVerificationResult decoded = await Jws.VerifyAndDecodeAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            BaseMemoryPool.Shared,
            exchangePublicKey,
            Jws.DefaultMaxJwsLength,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(isMessageVerified, "A JWS message does not verify under a public key the registry does not serve.");
        Assert.IsFalse(isCompactVerified, "A compact JWS does not verify under a public key the registry does not serve.");
        Assert.IsFalse(decoded.IsValid, "A compact JWS does not decode as verified under a public key the registry does not serve.");
        Assert.AreEqual("unserved-pair-test", decoded.Payload[WellKnownJwtClaimNames.Sub]?.ToString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-8.1.2">RFC 8017 Section 8.1.2</see>
    /// (RSASSA-PSS-VERIFY) and <see href="https://www.rfc-editor.org/rfc/rfc8017#section-8.2.2">Section 8.2.2</see>
    /// (RSASSA-PKCS1-V1_5-VERIFY), step 1: "Length checking: If the length of the signature S is not k octets,
    /// output "invalid signature" and stop." A presented compact JWS whose RSA signature is 257 octets under a
    /// 2048-bit modulus (k is 256) does not verify: the explicit compact <c>VerifyAsync</c> with the BouncyCastle
    /// RSASSA-PSS and RSASSA-PKCS1-v1_5 verification functions answers <see langword="false"/> and raises nothing.
    /// </summary>
    /// <param name="scheme">The RSA signature scheme: <c>Pss</c> or <c>Pkcs1</c>.</param>
    [TestMethod]
    [DataRow("Pss")]
    [DataRow("Pkcs1")]
    public async Task JwsVerifyAnswersFalseForAnRsaSignatureThatIsNotTheModulusLength(string scheme)
    {
        var keyPair = TestKeyMaterialProvider.CreateRsa2048KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        string presented = EncodeSegment($$"""{"alg":"{{RsaJoseAlgorithmName(scheme)}}"}""") + "." + EncodeSegment("""{"sub":"rsa-signature-length-test"}""") + "." + TestSetup.Base64UrlEncoder(Enumerable.Repeat((byte)0x01, 257).ToArray());

        bool isVerified = await Jws.VerifyAsync(
            presented,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            BouncyCastleRsaVerification(scheme),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(isVerified, $"A 257-octet RSA signature under a 2048-bit modulus does not verify through the BouncyCastle {scheme} verifier.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-5.2.2">RFC 8017 Section 5.2.2</see> (RSAVP1), step
    /// 1: "If the signature representative s is not between 0 and n - 1, output "signature representative out of
    /// range" and stop." <see href="https://www.rfc-editor.org/rfc/rfc8017#section-8.1.2">Section 8.1.2</see>, step
    /// 2.b: "If RSAVP1 output "signature representative out of range", output "invalid signature" and stop."
    /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-8.2.2">Section 8.2.2</see> has the same step for
    /// RSASSA-PKCS1-v1_5. A presented compact JWS whose RSA signature is 256 octets of 0xFF, the modulus length of a
    /// 2048-bit modulus and not below the modulus, does not verify: the explicit compact <c>VerifyAsync</c> with the
    /// BouncyCastle RSASSA-PSS and RSASSA-PKCS1-v1_5 verification functions answers <see langword="false"/> and
    /// raises nothing.
    /// </summary>
    /// <param name="scheme">The RSA signature scheme: <c>Pss</c> or <c>Pkcs1</c>.</param>
    [TestMethod]
    [DataRow("Pss")]
    [DataRow("Pkcs1")]
    public async Task JwsVerifyAnswersFalseForAnRsaSignatureNotBelowTheModulus(string scheme)
    {
        var keyPair = TestKeyMaterialProvider.CreateRsa2048KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        string presented = EncodeSegment($$"""{"alg":"{{RsaJoseAlgorithmName(scheme)}}"}""") + "." + EncodeSegment("""{"sub":"rsa-signature-range-test"}""") + "." + TestSetup.Base64UrlEncoder(Enumerable.Repeat((byte)0xFF, 256).ToArray());

        bool isVerified = await Jws.VerifyAsync(
            presented,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            BouncyCastleRsaVerification(scheme),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(isVerified, $"An RSA signature not below the modulus does not verify through the BouncyCastle {scheme} verifier.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.3">RFC 8725 Section 3.3</see>: "All
    /// cryptographic operations used in the JWT MUST be validated and the entire JWT MUST be rejected if any of
    /// them fail to validate." The public key a verify body is handed can be read from presented content (a header
    /// <c>jwk</c>). The octets <c>30 03 02 01</c> are not exactly a DER RSAPublicKey
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8017#appendix-A.1.1">RFC 8017 Appendix A.1.1</see>; the
    /// SEQUENCE announces three content octets and two follow), so the second arm of the rule the BouncyCastle
    /// provider's class summary states reads them as the bare modulus they spell under the exponent 65537, a 30-bit
    /// integer that <see cref="RsaUtilities.IsValidPublicKey"/> refuses as below its 1024-bit floor; that is no RSA
    /// public key a signature can be validated under:
    /// <see cref="Jws.VerifySignatureAsync(string, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, EncodeDelegate, VerificationDelegate, ReadOnlyMemory{byte}, BaseMemoryPool, CancellationToken)"/>
    /// with the BouncyCastle RSASSA-PSS and RSASSA-PKCS1-v1_5 verification functions answers
    /// <see langword="false"/> and raises nothing.
    /// </summary>
    /// <param name="scheme">The RSA signature scheme: <c>Pss</c> or <c>Pkcs1</c>.</param>
    /// <returns>A task that completes when the answer was asserted.</returns>
    [TestMethod]
    [DataRow("Pss")]
    [DataRow("Pkcs1")]
    public async Task JwsVerifyAnswersFalseForRsaPublicKeyOctetsThatSpellATooSmallModulus(string scheme)
    {
        bool isVerified = await Jws.VerifySignatureAsync(
            EncodeSegment($$"""{"alg":"{{RsaJoseAlgorithmName(scheme)}}"}"""),
            Encoding.UTF8.GetBytes("""{"sub":"rsa-public-key-encoding-test"}"""),
            new byte[256],
            TestSetup.Base64UrlEncoder,
            BouncyCastleRsaVerification(scheme),
            new byte[] { 0x30, 0x03, 0x02, 0x01 },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(isVerified, $"RSA public key octets that are no RSA public key do not verify through the BouncyCastle {scheme} verifier.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.3">RFC 8725 Section 3.3</see>: "All
    /// cryptographic operations used in the JWT MUST be validated and the entire JWT MUST be rejected if any of
    /// them fail to validate." <see href="https://www.rfc-editor.org/rfc/rfc8017#section-3.1">RFC 8017 Section
    /// 3.1</see> gives the RSA modulus n and the public exponent e as positive integers. The DER RSAPublicKey
    /// <c>30 08 02 01 80 02 03 01 00 01</c> carries the modulus -128 and is no RSA public key a signature can be
    /// validated under: <see cref="Jws.VerifySignatureAsync(string, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, EncodeDelegate, VerificationDelegate, ReadOnlyMemory{byte}, BaseMemoryPool, CancellationToken)"/>
    /// with the BouncyCastle RSASSA-PSS and RSASSA-PKCS1-v1_5 verification functions answers
    /// <see langword="false"/> and raises nothing.
    /// </summary>
    /// <param name="scheme">The RSA signature scheme: <c>Pss</c> or <c>Pkcs1</c>.</param>
    [TestMethod]
    [DataRow("Pss")]
    [DataRow("Pkcs1")]
    public async Task JwsVerifyAnswersFalseForAnRsaPublicKeyWithANegativeModulus(string scheme)
    {
        bool isVerified = await Jws.VerifySignatureAsync(
            EncodeSegment($$"""{"alg":"{{RsaJoseAlgorithmName(scheme)}}"}"""),
            Encoding.UTF8.GetBytes("""{"sub":"rsa-public-key-modulus-test"}"""),
            new byte[256],
            TestSetup.Base64UrlEncoder,
            BouncyCastleRsaVerification(scheme),
            new byte[] { 0x30, 0x08, 0x02, 0x01, 0x80, 0x02, 0x03, 0x01, 0x00, 0x01 },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(isVerified, $"An RSA public key with a negative modulus does not verify through the BouncyCastle {scheme} verifier.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.3">RFC 8725 Section 3.3</see>: "All
    /// cryptographic operations used in the JWT MUST be validated and the entire JWT MUST be rejected if any of
    /// them fail to validate." A P-256 public key is a SEC1 point of 33 octets (compressed) or 65 octets
    /// (uncompressed); the public key a verify body is handed can be read from presented content, and an empty
    /// one, or one of 32 octets, is no point a signature can be validated under:
    /// <see cref="Jws.VerifySignatureAsync(string, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, EncodeDelegate, VerificationDelegate, ReadOnlyMemory{byte}, BaseMemoryPool, CancellationToken)"/>
    /// with the BouncyCastle P-256 verification function answers <see langword="false"/> and raises nothing.
    /// </summary>
    /// <param name="length">The length of the presented public key, in octets.</param>
    [TestMethod]
    [DataRow(0)]
    [DataRow(32)]
    public async Task JwsVerifyAnswersFalseForAnEllipticCurvePublicKeyOfNoEncodedLength(int length)
    {
        byte[] publicKeyOctets = new byte[length];
        if(length > 0)
        {
            publicKeyOctets[0] = 0x02;
        }

        bool isVerified = await Jws.VerifySignatureAsync(
            EncodeSegment("""{"alg":"ES256"}"""),
            Encoding.UTF8.GetBytes("""{"sub":"elliptic-curve-public-key-length-test"}"""),
            new byte[64],
            TestSetup.Base64UrlEncoder,
            BouncyCastleCryptographicFunctionsAdapter.VerifyP256Async,
            publicKeyOctets,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(isVerified, $"A P-256 public key of {length} octets does not verify through the BouncyCastle verifier.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.4">RFC 7518 Section 3.4</see>, for ES256: "The
    /// JWS Signature value MUST be a 64-octet sequence.  If it is not a 64-octet sequence, the validation has
    /// failed." <see href="https://www.rfc-editor.org/rfc/rfc8812#section-3.2">RFC 8812 Section 3.2</see> gives
    /// ES256K the same form: "The resulting 64-octet sequence is the JWS Signature or COSE signature value." A
    /// correctly signed compact JWS whose ECDSA signature carries one octet after its two components does not
    /// verify, for secp256k1 and for brainpoolP256r1 (whose ECDSA signature is the same two components of the
    /// curve's size): the explicit compact <c>VerifyAsync</c> with the BouncyCastle verification function, and the
    /// registry <c>VerifyAsync</c>, which the test registry serves for both curves through BouncyCastle, answer
    /// <see langword="false"/>; the signature without the octet verifies. The header presents <c>ES256K</c> for
    /// secp256k1 and the label <c>ESB256</c> for brainpoolP256r1, which
    /// <see href="https://www.rfc-editor.org/rfc/rfc9864#section-2.1">RFC 9864 Section 2.1</see> registers for COSE
    /// only; these bodies do not read the header's <c>alg</c>, so the label binds nothing here.
    /// </summary>
    /// <param name="curve">The curve: <c>Secp256k1</c> or <c>BrainpoolP256r1</c>.</param>
    [TestMethod]
    [DataRow("Secp256k1")]
    [DataRow("BrainpoolP256r1")]
    public async Task JwsVerifyAnswersFalseForAnEcdsaSignatureOneOctetTooLong(string curve)
    {
        var keyPair = curve switch
        {
            "Secp256k1" => TestKeyMaterialProvider.CreateSecp256k1KeyMaterial(),
            "BrainpoolP256r1" => TestKeyMaterialProvider.CreateBrainpoolP256r1KeyMaterial(),
            _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "No such curve.")
        };

        SigningDelegate signing = curve switch
        {
            "Secp256k1" => BouncyCastleCryptographicFunctionsAdapter.SignSecp256k1Async,
            "BrainpoolP256r1" => BouncyCastleCryptographicFunctionsAdapter.SignBrainpoolP256r1Async,
            _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "No such curve.")
        };

        VerificationDelegate verification = curve switch
        {
            "Secp256k1" => BouncyCastleCryptographicFunctionsAdapter.VerifySecp256k1Async,
            "BrainpoolP256r1" => BouncyCastleCryptographicFunctionsAdapter.VerifyBrainpoolP256r1Async,
            _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "No such curve.")
        };

        string algorithmName = curve switch
        {
            "Secp256k1" => "ES256K",
            "BrainpoolP256r1" => "ESB256",
            _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "No such curve.")
        };

        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        string signed = await SignOverSegmentsAsync(
            EncodeSegment($$"""{"alg":"{{algorithmName}}"}"""), EncodeSegment("""{"sub":"ecdsa-signature-length-test"}"""), privateKey, signing).ConfigureAwait(false);

        bool isSignedVerified = await Jws.VerifyAsync(
            signed,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            verification,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(isSignedVerified, $"The correctly signed {curve} compact JWS verifies.");

        int signatureStart = signed.LastIndexOf('.', StringComparison.Ordinal) + 1;
        using IMemoryOwner<byte> signature = TestSetup.Base64UrlDecoder(signed.AsSpan(signatureStart), BaseMemoryPool.Shared);
        Assert.HasCount(64, signature.Memory.ToArray());
        string presented = signed[..signatureStart] + TestSetup.Base64UrlEncoder([.. signature.Memory.Span, 0x00]);

        bool isVerifiedByExplicitFunction = await Jws.VerifyAsync(
            presented,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            verification,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(isVerifiedByExplicitFunction, $"A 65-octet {curve} signature does not verify through the explicit function.");

        bool isVerifiedByRegistry = await Jws.VerifyAsync(
            presented,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(isVerifiedByRegistry, $"A 65-octet {curve} signature does not verify through the registry.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-5.2.2">RFC 8017 Section 5.2.2</see> (RSAVP1), step
    /// 1: "If the signature representative s is not between 0 and n - 1, output "signature representative out of
    /// range" and stop." 0 is in that range and RSAVP1 maps it to itself, which is no RSASSA-PSS encoded message
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8017#section-8.1.2">Section 8.1.2</see>), so a presented compact
    /// JWS whose <c>PS256</c> signature segment is 256 zero octets under a 2048-bit RSA public key does not verify:
    /// every compact verify body of <see cref="Jws"/> answers it as not verified and raises nothing, the explicit and
    /// the resolver bodies with the BouncyCastle RSASSA-PSS verification function, the registry bodies with the
    /// function the test registry serves for an RSASSA-PSS SHA-256 public key.
    /// </summary>
    /// <returns>A task that completes when the answer was asserted.</returns>
    [TestMethod]
    public async Task JwsVerifyAnswersFalseForAPs256SignatureOfZeroOctets()
    {
        var keyPair = TestKeyMaterialProvider.CreateRsa2048KeyMaterial();
        using var rsaPublicKey = keyPair.PublicKey;
        using var rsaPrivateKey = keyPair.PrivateKey;

        IMemoryOwner<byte> publicKeyOwner = BaseMemoryPool.Shared.Rent(rsaPublicKey.AsReadOnlySpan().Length);
        rsaPublicKey.AsReadOnlySpan().CopyTo(publicKeyOwner.Memory.Span);
        using var publicKey = new PublicKeyMemory(publicKeyOwner, CryptoTags.RsaSha256PssPublicKey);

        string presented = EncodeSegment("""{"alg":"PS256"}""") + "." + EncodeSegment("""{"sub":"rsa-signature-zero-test"}""") + "." + TestSetup.Base64UrlEncoder(new byte[256]);

        await AssertEveryBodyDoesNotVerifyAsync(presented, publicKey, BouncyCastleCryptographicFunctionsAdapter.VerifyRsaSha256PssAsync, "PS256 signature of zero octets").ConfigureAwait(false);
    }


    /// <summary>
    /// Presents <paramref name="presented"/>, a well-formed compact JWS whose signature does not verify, to every
    /// compact verify body of <see cref="Jws"/> under <paramref name="publicKey"/> and asserts each answer straight
    /// after its own call: the explicit-function, the registry and the resolver overloads of <c>VerifyAsync</c>
    /// answer <see langword="false"/>, and those of <c>VerifyAndDecodeAsync</c> a result that is not valid. The
    /// explicit bodies and the resolver's binder use <paramref name="verification"/>, the registry bodies the
    /// function the test registry serves for the public key's tag.
    /// </summary>
    /// <param name="presented">The presented compact JWS.</param>
    /// <param name="publicKey">The public key the JWS is verified under.</param>
    /// <param name="verification">The verification function of the explicit bodies and the binder.</param>
    /// <param name="shape">The presented shape, named in the failure messages.</param>
    /// <returns>A task that completes when every body was asserted.</returns>
    private async Task AssertEveryBodyDoesNotVerifyAsync(string presented, PublicKeyMemory publicKey, VerificationDelegate verification, string shape)
    {
        CancellationToken cancellationToken = TestContext.CancellationToken;
        var resolverState = new TestResolverState([], publicKey.AsReadOnlySpan().ToArray(), publicKey.Tag);

        bool isVerifiedByExplicitFunction = await Jws.VerifyAsync(
            presented, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, publicKey, verification, cancellationToken: cancellationToken).ConfigureAwait(false);
        Assert.IsFalse(isVerifiedByExplicitFunction, $"A presented '{shape}' compact JWS does not verify through the explicit function.");

        bool isVerifiedByRegistry = await Jws.VerifyAsync(
            presented, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, publicKey, cancellationToken).ConfigureAwait(false);
        Assert.IsFalse(isVerifiedByRegistry, $"A presented '{shape}' compact JWS does not verify through the registry.");

        bool isVerifiedByResolver = await Jws.VerifyAsync(
            presented, TestSetup.Base64UrlDecoder, DecodeJwtPart, BaseMemoryPool.Shared, resolverState, ResolvePublicKeyMaterial, verification, BindPublicKeyWith, cancellationToken: cancellationToken).ConfigureAwait(false);
        Assert.IsFalse(isVerifiedByResolver, $"A presented '{shape}' compact JWS does not verify through the resolver.");

        JwsVerificationResult decodedByExplicitFunction = await Jws.VerifyAndDecodeAsync(
            presented, TestSetup.Base64UrlDecoder, DecodeJwtPart, BaseMemoryPool.Shared, publicKey, verification, Jws.DefaultMaxJwsLength, cancellationToken: cancellationToken).ConfigureAwait(false);
        Assert.IsFalse(decodedByExplicitFunction.IsValid, $"A presented '{shape}' compact JWS does not decode as verified through the explicit function.");

        JwsVerificationResult decodedByRegistry = await Jws.VerifyAndDecodeAsync(
            presented, TestSetup.Base64UrlDecoder, DecodeJwtPart, BaseMemoryPool.Shared, publicKey, cancellationToken).ConfigureAwait(false);
        Assert.IsFalse(decodedByRegistry.IsValid, $"A presented '{shape}' compact JWS does not decode as verified through the registry.");

        JwsVerificationResult decodedByResolver = await Jws.VerifyAndDecodeAsync(
            presented, TestSetup.Base64UrlDecoder, DecodeJwtPart, BaseMemoryPool.Shared, resolverState, ResolvePublicKeyMaterial, verification, BindPublicKeyWith, cancellationToken: cancellationToken).ConfigureAwait(false);
        Assert.IsFalse(decodedByResolver.IsValid, $"A presented '{shape}' compact JWS does not decode as verified through the resolver.");
    }


    /// <summary>
    /// The BouncyCastle RSA verification function with SHA-256 for <paramref name="scheme"/>.
    /// </summary>
    /// <param name="scheme"><c>Pss</c> for RSASSA-PSS or <c>Pkcs1</c> for RSASSA-PKCS1-v1_5.</param>
    /// <returns>The verification function.</returns>
    private static VerificationDelegate BouncyCastleRsaVerification(string scheme) => scheme switch
    {
        "Pss" => BouncyCastleCryptographicFunctionsAdapter.VerifyRsaSha256PssAsync,
        "Pkcs1" => BouncyCastleCryptographicFunctionsAdapter.VerifyRsaSha256Pkcs1Async,
        _ => throw new ArgumentOutOfRangeException(nameof(scheme), scheme, "No such RSA signature scheme.")
    };


    /// <summary>
    /// The JOSE <c>alg</c> name of the SHA-256 RSA signature <paramref name="scheme"/>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.1">RFC 7518 Section 3.1</see>): <c>PS256</c> for
    /// RSASSA-PSS, <c>RS256</c> for RSASSA-PKCS1-v1_5. The rows present it in the header so the header names the
    /// case it drives; the bodies these rows call do not read the header's <c>alg</c>.
    /// </summary>
    /// <param name="scheme"><c>Pss</c> for RSASSA-PSS or <c>Pkcs1</c> for RSASSA-PKCS1-v1_5.</param>
    /// <returns>The JOSE algorithm name.</returns>
    private static string RsaJoseAlgorithmName(string scheme) => scheme switch
    {
        "Pss" => "PS256",
        "Pkcs1" => "RS256",
        _ => throw new ArgumentOutOfRangeException(nameof(scheme), scheme, "No such RSA signature scheme.")
    };


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.3">RFC 8725 Section 3.3</see>: "All
    /// cryptographic operations used in the JWT MUST be validated and the entire JWT MUST be rejected if any of
    /// them fail to validate." A registry overload of <see cref="Jws"/> resolves its verification function through
    /// the process-wide <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>; one that has not
    /// been initialized validates nothing, and that is the deployment's composition, never presented input, so
    /// every registry overload of <c>VerifyAsync</c> (for a message and for a compact JWS, with the default and an
    /// explicit bound) and of <c>VerifyAndDecodeAsync</c> throws <see cref="InvalidOperationException"/> naming the
    /// registry, before any resolution, rather than answering a quiet <see langword="false"/>. The row initializes
    /// the registry with no matchers, runs alone, and restores the test registry in <c>finally</c>.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    public async Task JwsRegistryOverloadsThrowOverAnUninitializedRegistry()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var header = new Dictionary<string, object> { ["alg"] = "ES256", ["typ"] = "JWT" };
        var payload = new Dictionary<string, object> { ["sub"] = "uninitialized-registry-test" };

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        CancellationToken cancellationToken = TestContext.CancellationToken;
        try
        {
            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.Initialize(null!, null!);
            Assert.IsFalse(CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.IsInitialized);

            InvalidOperationException byMessage = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
                await Jws.VerifyAsync(jwsMessage, TestSetup.Base64UrlEncoder, publicKey, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
            Assert.AreEqual(UninitializedRegistryMessage, byMessage.Message);

            InvalidOperationException byCompact = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
                await Jws.VerifyAsync(jws, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, publicKey, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
            Assert.AreEqual(UninitializedRegistryMessage, byCompact.Message);

            InvalidOperationException byCompactWithBound = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
                await Jws.VerifyAsync(jws, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, publicKey, Jws.DefaultMaxJwsLength, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
            Assert.AreEqual(UninitializedRegistryMessage, byCompactWithBound.Message);

            InvalidOperationException byDecode = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
                await Jws.VerifyAndDecodeAsync(jws, TestSetup.Base64UrlDecoder, DecodeJwtPart, BaseMemoryPool.Shared, publicKey, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
            Assert.AreEqual(UninitializedRegistryMessage, byDecode.Message);

            InvalidOperationException byDecodeWithBound = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
                await Jws.VerifyAndDecodeAsync(jws, TestSetup.Base64UrlDecoder, DecodeJwtPart, BaseMemoryPool.Shared, publicKey, Jws.DefaultMaxJwsLength, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
            Assert.AreEqual(UninitializedRegistryMessage, byDecodeWithBound.Message);
        }
        finally
        {
            TestSetup.Setup();
        }
    }


    /// <summary>The message the registry overloads of <see cref="Jws"/> throw over a registry that has not been initialized.</summary>
    private static string UninitializedRegistryMessage { get; } =
        "The cryptographic function registry has not been initialized. Call CryptoFunctionRegistry.Initialize() during application startup.";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 Section 5.2</see>: "If any of the
    /// listed steps fails, then the signature or MAC cannot be validated." Step 8 validates the JWS Signature "in
    /// the manner defined for the algorithm being used", which takes a public key. The resolver is handed the
    /// presented header and payload, so a resolver that holds no public key for the presented <c>kid</c> answers
    /// none, and no signature can be validated: the resolver overload of <c>VerifyAsync</c> answers
    /// <see langword="false"/>, that of <c>VerifyAndDecodeAsync</c> a result that is not valid with the decoded
    /// header and payload, and neither raises anything.
    /// </summary>
    [TestMethod]
    public async Task JwsResolverAnswersNotVerifiedWhenTheResolverAnswersNoPublicKey()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        string presented = await SignOverSegmentsAsync(
            EncodeSegment("""{"alg":"ES256","kid":"no-such-public-key"}"""), EncodeSegment("""{"sub":"no-public-key-test"}"""), privateKey, MicrosoftCryptographicFunctionsAdapter.SignP256Async).ConfigureAwait(false);

        bool isVerifiedByResolver = await Jws.VerifyAsync(
            presented,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            BaseMemoryPool.Shared,
            0,
            ResolveNoPublicKeyMaterial,
            0,
            BindPublicKey,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(isVerifiedByResolver, "A resolver that answers no public key makes the resolver VerifyAsync answer false.");

        JwsVerificationResult decodedByResolver = await Jws.VerifyAndDecodeAsync(
            presented,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            BaseMemoryPool.Shared,
            0,
            ResolveNoPublicKeyMaterial,
            0,
            BindPublicKey,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(decodedByResolver.IsValid, "A resolver that answers no public key makes the resolver VerifyAndDecodeAsync answer a result that is not valid.");
        Assert.AreEqual("no-such-public-key", decodedByResolver.Header["kid"]?.ToString());
        Assert.AreEqual("no-public-key-test", decodedByResolver.Payload["sub"]?.ToString());
    }


    /// <summary>
    /// A resolver that answers no public key answers a value; one that faults is the caller's own dependency
    /// failing, not a property of the presented input, so its exception propagates out of the resolver overloads
    /// of <c>VerifyAsync</c> and <c>VerifyAndDecodeAsync</c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.3">RFC 8725 Section 3.3</see>: "All
    /// cryptographic operations used in the JWT MUST be validated and the entire JWT MUST be rejected if any of
    /// them fail to validate." A resolver that faults has validated nothing, and answering its fault as a JWT the
    /// verifier rejects would hide the fault.
    /// </summary>
    [TestMethod]
    public async Task JwsResolverPropagatesAFaultOfTheResolver()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        string presented = await SignOverSegmentsAsync(
            EncodeSegment("""{"alg":"ES256","typ":"JWT"}"""), EncodeSegment("""{"sub":"resolver-fault-test"}"""), privateKey, MicrosoftCryptographicFunctionsAdapter.SignP256Async).ConfigureAwait(false);

        CancellationToken cancellationToken = TestContext.CancellationToken;

        InvalidOperationException byVerify = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
            await Jws.VerifyAsync(presented, TestSetup.Base64UrlDecoder, DecodeJwtPart, BaseMemoryPool.Shared, 0, ResolveFaulting, 0, BindPublicKey, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        Assert.AreEqual(FaultingResolverMessage, byVerify.Message);

        InvalidOperationException byDecode = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
            await Jws.VerifyAndDecodeAsync(presented, TestSetup.Base64UrlDecoder, DecodeJwtPart, BaseMemoryPool.Shared, 0, ResolveFaulting, 0, BindPublicKey, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        Assert.AreEqual(FaultingResolverMessage, byDecode.Message);
    }


    /// <summary>The message of the fault <see cref="ResolveFaulting"/> raises.</summary>
    private static string FaultingResolverMessage { get; } = "The resolver faulted on its own state.";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8032#section-5.1.7">RFC 8032 Section 5.1.7</see>, step 1:
    /// "Decode the public key A as point A'.  If any of the decodings fail (including S being out of range), the
    /// signature is invalid." <see href="https://www.rfc-editor.org/rfc/rfc8032#section-5.1.3">Section 5.1.3</see>:
    /// "Decoding a point, given as a 32-octet string, is a little more complicated." An Ed25519 public key is
    /// 32 octets; an empty one, one of 31 octets and one of 33 octets (the correct public key and one octet after
    /// it) are no 32-octet string, so a correctly signed compact JWS does not verify under them:
    /// <see cref="Jws.VerifySignatureAsync(string, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, EncodeDelegate, VerificationDelegate, ReadOnlyMemory{byte}, BaseMemoryPool, CancellationToken)"/>
    /// with the BouncyCastle Ed25519 verification function answers <see langword="false"/> and raises nothing; the
    /// 32-octet public key verifies.
    /// </summary>
    /// <param name="length">The length of the presented public key, in octets.</param>
    [TestMethod]
    [DataRow(0)]
    [DataRow(31)]
    [DataRow(33)]
    public async Task JwsVerifyAnswersFalseForAnEd25519PublicKeyThatIsNot32Octets(int length)
    {
        var keyPair = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        string headerSegment = EncodeSegment("""{"alg":"Ed25519"}""");
        byte[] payload = Encoding.UTF8.GetBytes("""{"sub":"ed25519-public-key-length-test"}""");
        string signed = await SignOverSegmentsAsync(headerSegment, TestSetup.Base64UrlEncoder(payload), privateKey, BouncyCastleCryptographicFunctionsAdapter.SignEd25519Async).ConfigureAwait(false);
        int signatureStart = signed.LastIndexOf('.', StringComparison.Ordinal) + 1;
        using IMemoryOwner<byte> signature = TestSetup.Base64UrlDecoder(signed.AsSpan(signatureStart), BaseMemoryPool.Shared);

        byte[] publicKeyOctets = publicKey.AsReadOnlySpan().ToArray();
        Assert.HasCount(32, publicKeyOctets);

        bool isSignedVerified = await Jws.VerifySignatureAsync(
            headerSegment, payload, signature.Memory, TestSetup.Base64UrlEncoder, BouncyCastleCryptographicFunctionsAdapter.VerifyEd25519Async, publicKeyOctets, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(isSignedVerified, "The correctly signed compact JWS verifies under the 32-octet public key.");

        byte[] presentedPublicKey = length switch
        {
            0 => [],
            31 => publicKeyOctets[..31],
            33 => [.. publicKeyOctets, 0],
            _ => throw new ArgumentOutOfRangeException(nameof(length), length, "No such public key length.")
        };

        bool isVerified = await Jws.VerifySignatureAsync(
            headerSegment, payload, signature.Memory, TestSetup.Base64UrlEncoder, BouncyCastleCryptographicFunctionsAdapter.VerifyEd25519Async, presentedPublicKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(isVerified, $"An Ed25519 public key of {length} octets does not verify through the BouncyCastle verifier.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.3">RFC 8725 Section 3.3</see>: "All
    /// cryptographic operations used in the JWT MUST be validated and the entire JWT MUST be rejected if any of
    /// them fail to validate." An ML-DSA-44 public key has one encoded length; an empty one and one with an octet
    /// after a correct public key are no ML-DSA-44 public key, and a correctly signed compact JWS does not verify
    /// under them: <see cref="Jws.VerifySignatureAsync(string, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, EncodeDelegate, VerificationDelegate, ReadOnlyMemory{byte}, BaseMemoryPool, CancellationToken)"/>
    /// with the BouncyCastle ML-DSA-44 verification function answers <see langword="false"/> and raises nothing.
    /// The BouncyCastle verification function answers <see langword="false"/> for such a public key itself, so this
    /// row pins the answer through <c>Jws</c>; the provider's own row holds the provider's answer.
    /// </summary>
    /// <param name="shape">The presented public key: <c>empty</c> or <c>oneOctetLonger</c>.</param>
    [TestMethod]
    [DataRow("empty")]
    [DataRow("oneOctetLonger")]
    public async Task JwsVerifyAnswersFalseForAnMlDsaPublicKeyOfTheWrongLength(string shape)
    {
        var keyPair = TestKeyMaterialProvider.CreateMlDsa44KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        string headerSegment = EncodeSegment("""{"alg":"ML-DSA-44"}""");
        byte[] payload = Encoding.UTF8.GetBytes("""{"sub":"ml-dsa-public-key-length-test"}""");
        string signed = await SignOverSegmentsAsync(headerSegment, TestSetup.Base64UrlEncoder(payload), privateKey, BouncyCastleCryptographicFunctionsAdapter.SignMlDsa44Async).ConfigureAwait(false);
        int signatureStart = signed.LastIndexOf('.', StringComparison.Ordinal) + 1;
        using IMemoryOwner<byte> signature = TestSetup.Base64UrlDecoder(signed.AsSpan(signatureStart), BaseMemoryPool.Shared);

        byte[] publicKeyOctets = publicKey.AsReadOnlySpan().ToArray();
        byte[] presentedPublicKey = shape switch
        {
            "empty" => [],
            "oneOctetLonger" => [.. publicKeyOctets, 0],
            _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, "No such public key shape.")
        };

        bool isVerified = await Jws.VerifySignatureAsync(
            headerSegment, payload, signature.Memory, TestSetup.Base64UrlEncoder, BouncyCastleCryptographicFunctionsAdapter.VerifyMlDsa44Async, presentedPublicKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(isVerified, $"An ML-DSA-44 public key that is '{shape}' does not verify through the BouncyCastle verifier.");
    }


    /// <summary>
    /// The <see cref="JwsMessage"/>-based <c>VerifyAsync</c> overload shares the compact-string overload's
    /// documented contract that "callers depend on VerifyAsync returning false, never throwing, on untrusted
    /// input" (see the guard in <see cref="Jws.VerifyAsync(string, DecodeDelegate, BaseMemoryPool, PublicKeyMemory, VerificationDelegate, int, CryptoEventSink?, CancellationToken)"/>).
    /// A resolved <see cref="VerificationDelegate"/> can throw while parsing attacker-tampered key material (for
    /// example an application's verification function, or a platform that does not serve the curve raising
    /// <see cref="PlatformNotSupportedException"/>) rather than answer a graceful rejection, and this overload must
    /// fail closed to <see langword="false"/> instead of letting that exception escape.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncWithJwsMessageReturnsFalseWhenVerificationDelegateThrows()
    {
        var header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256, [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt };
        var payload = new Dictionary<string, object> { [WellKnownJwtClaimNames.Sub] = "throwing-delegate-test" };

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        bool isValid = await Jws.VerifyAsync(
            jwsMessage,
            TestSetup.Base64UrlEncoder,
            publicKey,
            ThrowingVerificationDelegate,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(isValid, "A verification delegate that throws on tampered/untrusted key material must fail closed to false, never escape as an exception.");
    }


    /// <summary>
    /// <see cref="Jws.VerifySignatureAsync(string, ReadOnlyMemory{byte}, bool, ReadOnlyMemory{byte}, EncodeDelegate, VerificationDelegate, ReadOnlyMemory{byte}, BaseMemoryPool, CryptoEventSink?, CancellationToken)"/>
    /// shares the same fail-closed contract as the other <c>Jws</c> verify overloads: a resolved
    /// <see cref="VerificationDelegate"/> that throws while parsing attacker-tampered key material must not let
    /// that exception escape past the guard — it must be treated as "signature does not verify".
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureAsyncReturnsFalseWhenVerificationDelegateThrows()
    {
        var header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256, [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt };
        var payload = new Dictionary<string, object> { [WellKnownJwtClaimNames.Sub] = "verify-signature-throwing-delegate-test" };

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        JwsSignatureComponent signatureComponent = jwsMessage.Signatures[0];

        bool isValid = await Jws.VerifySignatureAsync(
            signatureComponent.Protected,
            jwsMessage.Payload,
            base64UrlPayload: true,
            signatureComponent.SignatureBytes,
            TestSetup.Base64UrlEncoder,
            ThrowingVerificationDelegate,
            publicKey.AsReadOnlyMemory(),
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(isValid, "A verification delegate that throws on tampered/untrusted key material must fail closed to false, never escape as an exception.");
    }


    /// <summary>
    /// The explicit-<see cref="VerificationDelegate"/> compact-string
    /// <see cref="Jws.VerifyAndDecodeAsync(string, DecodeDelegate, JwtPartDecoder, BaseMemoryPool, PublicKeyMemory, VerificationDelegate, int, CryptoEventSink?, CancellationToken)"/>
    /// overload shares the same fail-closed contract as the other <c>Jws</c> verify overloads: a resolved
    /// <see cref="VerificationDelegate"/> that throws while parsing attacker-tampered key material must not let
    /// that exception escape past the guard — it must be treated as "signature does not verify", returning an
    /// invalid <see cref="JwsVerificationResult"/> rather than throwing.
    /// </summary>
    [TestMethod]
    public async Task VerifyAndDecodeAsyncWithCompactStringReturnsFalseWhenVerificationDelegateThrows()
    {
        var header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256, [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt };
        var payload = new Dictionary<string, object> { [WellKnownJwtClaimNames.Sub] = "verify-and-decode-throwing-delegate-test" };

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        JwsVerificationResult result = await Jws.VerifyAndDecodeAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            BaseMemoryPool.Shared,
            publicKey,
            ThrowingVerificationDelegate,
            Jws.DefaultMaxJwsLength,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A verification delegate that throws on tampered/untrusted key material must fail closed to an invalid result, never escape as an exception.");
    }


    /// <summary>
    /// Simulates a resolved verification backend rejecting attacker-tampered key material with an exception
    /// (for example an application's verification function raising <see cref="PlatformNotSupportedException"/>)
    /// instead of a graceful "not verified" result — the shape every <c>Jws</c> verify overload's fail-closed
    /// guard exists to catch. Shared across the guard tests above.
    /// </summary>
    private static ValueTask<(bool IsVerified, CryptoEvent? Event)> ThrowingVerificationDelegate(
        ReadOnlyMemory<byte> dataToVerify,
        ReadOnlyMemory<byte> signature,
        ReadOnlyMemory<byte> publicKeyMaterial,
        FrozenDictionary<string, object>? context = null,
        CancellationToken cancellationToken = default)
        => throw new PlatformNotSupportedException("Simulated tampered EC point rejection.");


    [TestMethod]
    public async Task VerifyAndDecodeWithResolverBinderReturnsHeaderAndPayload()
    {
        var header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256, [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt };
        var payload = new Dictionary<string, object> { [WellKnownJwtClaimNames.Sub] = "decode-test", ["custom"] = "value" };

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var resolverState = new TestResolverState(
            privateKey.AsReadOnlySpan().ToArray(),
            publicKey.AsReadOnlySpan().ToArray());

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        JwsVerificationResult result = await Jws.VerifyAndDecodeAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            BaseMemoryPool.Shared,
            resolverState,
            ResolvePublicKeyMaterial,
            0,
            BindPublicKey,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "Signature should be valid.");
        Assert.AreEqual(WellKnownJwaValues.Es256, result.Header[WellKnownJwkMemberNames.Alg]?.ToString());
        Assert.AreEqual("decode-test", result.Payload[WellKnownJwtClaimNames.Sub]?.ToString());
        Assert.AreEqual("value", result.Payload["custom"]?.ToString());
    }


    [TestMethod]
    public async Task ResolverReturningNullThrowsInvalidOperationException()
    {
        JwtHeader header = new() { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256, [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt };
        JwtPayload payload = new() { [WellKnownJwtClaimNames.Sub] = "null-test" };
        CancellationToken cancellationToken = TestContext.CancellationToken;

        _ = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            _ = await Jws.SignAsync(
                header,
                payload,
                JwtWireFixtures.EncodeJwtPart,
                TestSetup.Base64UrlEncoder,
                BaseMemoryPool.Shared,
                0,
                (context, pool, state, ct) => ValueTask.FromResult<PrivateKeyMemory?>(null),
                0,
                (material, state, ct) => throw new InvalidOperationException("Binder should not be called."),
                cancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    [TestMethod]
    public void CryptoFormatConversionsMapsEs256Correctly()
    {
        Tag signingTag = GetSigningTag(WellKnownJwaValues.Es256);
        Tag verificationTag = GetVerificationTag(WellKnownJwaValues.Es256);

        Assert.AreEqual(CryptoAlgorithm.P256, signingTag.Get<CryptoAlgorithm>());
        Assert.AreEqual(Purpose.Signing, signingTag.Get<Purpose>());

        Assert.AreEqual(CryptoAlgorithm.P256, verificationTag.Get<CryptoAlgorithm>());
        Assert.AreEqual(Purpose.Verification, verificationTag.Get<Purpose>());
    }


    [TestMethod]
    public void CryptoFormatConversionsThrowsForUnsupportedAlgorithm()
    {
        _ = Assert.Throws<NotSupportedException>(() => GetSigningTag("UNSUPPORTED"));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC 7515 Section 2</see>, Base64url Encoding:
    /// "Note that the base64url encoding of the empty octet sequence is the empty string." A non-empty input that
    /// holds white space alone encodes no octet sequence, so the suite's base64url decoder
    /// <see cref="TestSetup.Base64UrlDecoder"/> refuses it with <see cref="FormatException"/>, the refusal the
    /// <see cref="DecodeDelegate"/> contract names, and rents no buffer of no octets.
    /// </summary>
    /// <param name="source">The white space presented as base64url.</param>
    [TestMethod]
    [DataRow("  ")]
    [DataRow("    ")]
    public void SuiteBase64UrlDecoderRefusesAnInputThatDecodesToNoOctets(string source)
    {
        _ = Assert.ThrowsExactly<FormatException>(() => TestSetup.Base64UrlDecoder(source, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC 7515 Section 2</see>, Base64url Encoding:
    /// "Note that the base64url encoding of the empty octet sequence is the empty string." The <c>u</c> multibase
    /// form of a <c>did:key</c> public key carries a base64url payload after its prefix; a payload that is empty, a
    /// single character, or white space alone decodes to no octets, so
    /// <see cref="CryptoFormatConversions.DefaultBase58ToAlgorithmConverter"/> refuses it with
    /// <see cref="FormatException"/>, the refusal the <see cref="DecodeDelegate"/> contract names, and rents no
    /// buffer of no octets.
    /// </summary>
    /// <param name="multibasePublicKey">The presented <c>u</c> multibase public key.</param>
    [TestMethod]
    [DataRow("u")]
    [DataRow("uA")]
    [DataRow("u    ")]
    public void DidKeyBase64UrlPayloadOfNoOctetsIsRefused(string multibasePublicKey)
    {
        _ = Assert.ThrowsExactly<FormatException>(() =>
            CryptoFormatConversions.DefaultBase58ToAlgorithmConverter(multibasePublicKey, BaseMemoryPool.Shared, TestSetup.Base58Decoder));
    }


    /// <summary>
    /// State for test resolvers containing key material.
    /// </summary>
    /// <param name="PrivateKeyBytes">The private key octets the signing resolver answers.</param>
    /// <param name="PublicKeyBytes">The public key octets the verifying resolver answers.</param>
    /// <param name="PublicKeyTag">The tag the verifying resolver gives the public key; P-256 when <see langword="null"/>.</param>
    private sealed record TestResolverState(byte[] PrivateKeyBytes, byte[] PublicKeyBytes, Tag? PublicKeyTag = null);


    /// <summary>
    /// Test resolver that returns private key material from state.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership transfers to the caller (Jws.SignAsync) which disposes via PrivateKey.")]
    private static ValueTask<PrivateKeyMemory?> ResolvePrivateKeyMaterial(
        JoseKeyContext context,
        BaseMemoryPool pool,
        TestResolverState state,
        CancellationToken cancellationToken)
    {
        IMemoryOwner<byte> memoryOwner = pool.Rent(state.PrivateKeyBytes.Length);
        state.PrivateKeyBytes.CopyTo(memoryOwner.Memory.Span);

        return ValueTask.FromResult<PrivateKeyMemory?>(new PrivateKeyMemory(memoryOwner, CryptoTags.P256PrivateKey));
    }


    /// <summary>
    /// Test resolver that returns public key material from state.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership transfers to the caller (Jws.VerifyAsync) which disposes via PublicKey.")]
    private static ValueTask<PublicKeyMemory?> ResolvePublicKeyMaterial(
        JoseKeyContext context,
        BaseMemoryPool pool,
        TestResolverState state,
        CancellationToken cancellationToken)
    {
        IMemoryOwner<byte> memoryOwner = pool.Rent(state.PublicKeyBytes.Length);
        state.PublicKeyBytes.CopyTo(memoryOwner.Memory.Span);

        return ValueTask.FromResult<PublicKeyMemory?>(new PublicKeyMemory(memoryOwner, state.PublicKeyTag ?? CryptoTags.P256PublicKey));
    }


    /// <summary>
    /// A resolver that holds no public key for any presented context and answers none: the shape of a resolver
    /// asked for a <c>kid</c> it does not hold.
    /// </summary>
    /// <param name="context">The presented header and payload, never read.</param>
    /// <param name="pool">The pool, never rented from.</param>
    /// <param name="state">The resolver state, never read.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>No public key material.</returns>
    private static ValueTask<PublicKeyMemory?> ResolveNoPublicKeyMaterial(
        JoseKeyContext context,
        BaseMemoryPool pool,
        int state,
        CancellationToken cancellationToken) => ValueTask.FromResult<PublicKeyMemory?>(null);


    /// <summary>
    /// A resolver that faults on every presented context with an <see cref="InvalidOperationException"/>: the
    /// shape of a caller's resolver whose own state is broken.
    /// </summary>
    /// <param name="context">The presented header and payload, never read.</param>
    /// <param name="pool">The pool, never rented from.</param>
    /// <param name="state">The resolver state, never read.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Never returns.</returns>
    private static ValueTask<PublicKeyMemory?> ResolveFaulting(
        JoseKeyContext context,
        BaseMemoryPool pool,
        int state,
        CancellationToken cancellationToken) => throw new InvalidOperationException(FaultingResolverMessage);


    /// <summary>
    /// Test binder that binds signing function to private key material.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership transfers to the caller (Jws.SignAsync) which disposes the returned PrivateKey.")]
    private static ValueTask<PrivateKey> BindPrivateKey(
        PrivateKeyMemory material,
        int state,
        CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(new PrivateKey(material, "test-key", MicrosoftCryptographicFunctionsAdapter.SignP256Async));
    }


    /// <summary>
    /// Test binder that binds verification function to public key material.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership transfers to the caller (Jws.VerifyAsync) which disposes the returned PublicKey.")]
    private static ValueTask<PublicKey> BindPublicKey(
        PublicKeyMemory material,
        int state,
        CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(new PublicKey(material, "test-key", MicrosoftCryptographicFunctionsAdapter.VerifyP256Async));
    }


    /// <summary>
    /// Test binder that binds the verification function its state names to public key material, so a row
    /// chooses the backend the resolver overloads verify through.
    /// </summary>
    /// <param name="material">The resolved public key material.</param>
    /// <param name="verification">The verification function the public key is bound to.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The bound public key, which the verify body disposes.</returns>
    private static async ValueTask<PublicKey> BindPublicKeyWith(
        PublicKeyMemory material,
        VerificationDelegate verification,
        CancellationToken cancellationToken)
    {
        await ValueTask.CompletedTask.ConfigureAwait(false);

        return new PublicKey(material, "test-public-key", verification);
    }


    /// <summary>
    /// Decodes UTF-8 JSON bytes to a dictionary.
    /// </summary>
    private static Dictionary<string, object> DecodeJwtPart(ReadOnlySpan<byte> bytes)
    {
        string json = Encoding.UTF8.GetString(bytes);
        return JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(json, TestSetup.DefaultSerializationOptions)!;
    }
}
