using System.Buffers;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// Coverage for <see cref="JAdESProtectedHeaderJson"/> — the JAdES JWS Protected Header ↔ JSON-object codec.
/// Proves the aggregate round-trips through <see cref="JAdESProtectedHeaderJson.Encode"/>/<see
/// cref="JAdESProtectedHeaderJson.Decode"/> and that <see cref="JAdESProtectedHeaderJson.Decode"/> fails
/// closed (returns <see langword="null"/>, never throws) on malformed input.
/// </summary>
[TestClass]
internal sealed class JAdESProtectedHeaderJsonTests
{
    private static string[] ExpectedCriticalLabels { get; } = ["sigD"];
    private static string[] ExpectedHttpHeaderNames { get; } = ["content-type", "digest"];



    /// <summary>
    /// A header carrying a representative spread of clause 5.1/5.2 members round-trips through
    /// <see cref="JAdESProtectedHeaderJson.Encode"/> (producing the base64url wire TEXT) then
    /// <see cref="JAdESProtectedHeaderJson.Decode"/> (consuming the base64url-decoded JSON bytes), preserving
    /// every member's semantic value.
    /// </summary>
    [TestMethod]
    public void ProtectedHeaderRoundTripsThroughEncodeAndDecode()
    {
        using JAdESProtectedHeaders headers = new(
            algorithm: "ES256",
            contentType: "application/json",
            keyId: "key-1",
            x5u: new Uri("https://example.org/cert"),
            criticalLabels: ["sigD"],
            b64: false,
            issuedAt: new JAdESClaimedSigningTime(DateTimeOffset.FromUnixTimeSeconds(1700000000)),
            sigD: new JAdESHttpHeadersReference(["content-type", "digest"]));

        using EncodedJoseProtectedHeader encoded = JAdESProtectedHeaderJson.Encode(headers, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string base64UrlText = Encoding.ASCII.GetString(encoded.AsReadOnlySpan()[..encoded.Length]);

        using IMemoryOwner<byte> jsonBytes = TestSetup.Base64UrlDecoder(base64UrlText, BaseMemoryPool.Shared);
        using JAdESProtectedHeaders? decoded = JAdESProtectedHeaderJson.Decode(jsonBytes.Memory.Span, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

        Assert.IsNotNull(decoded);
        Assert.AreEqual("ES256", decoded.Algorithm);
        Assert.AreEqual("application/json", decoded.ContentType);
        Assert.AreEqual("key-1", decoded.KeyId);
        Assert.AreEqual(new Uri("https://example.org/cert"), decoded.X5U);
        Assert.AreSequenceEqual(ExpectedCriticalLabels, decoded.CriticalLabels);
        Assert.IsNotNull(decoded.B64);
        Assert.IsFalse(decoded.B64.Value);
        Assert.AreEqual(1700000000L, decoded.IssuedAt?.Value.ToUnixTimeSeconds());
        Assert.IsInstanceOfType<JAdESHttpHeadersReference>(decoded.SigD);
        Assert.AreSequenceEqual(ExpectedHttpHeaderNames, ((JAdESHttpHeadersReference)decoded.SigD!).HeaderNames);
    }


    /// <summary>
    /// <c>x5t#S256</c> (RFC 7515 §4.1.8, base64url) round-trips
    /// byte-exact.
    /// </summary>
    [TestMethod]
    public void X5tHashS256RoundTripsThroughBase64Url()
    {
        byte[] digestBytes = [1, 2, 3, 4, 5, 6, 7, 8];
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(digestBytes.Length);
        digestBytes.CopyTo(owner.Memory);
        using var digest = new DigestValue(owner, CryptoTags.Sha256Digest);
        using JAdESProtectedHeaders headers = new(algorithm: "ES256", x5tHashS256: digest);

        using EncodedJoseProtectedHeader encoded = JAdESProtectedHeaderJson.Encode(headers, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string base64UrlText = Encoding.ASCII.GetString(encoded.AsReadOnlySpan()[..encoded.Length]);
        using IMemoryOwner<byte> jsonBytes = TestSetup.Base64UrlDecoder(base64UrlText, BaseMemoryPool.Shared);
        using JAdESProtectedHeaders? decoded = JAdESProtectedHeaderJson.Decode(jsonBytes.Memory.Span, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

        Assert.IsNotNull(decoded);
        Assert.IsNotNull(decoded.X5tHashS256);
        Assert.AreSequenceEqual(digestBytes, decoded.X5tHashS256.AsReadOnlySpan().ToArray());
    }


    /// <summary>
    /// A JAdES <c>digAlg</c> is always textual — an IANA Named Information Hash Algorithm Registry identifier
    /// (ETSI TS 119 182-1 V1.2.1, clauses 5.2.2.2/5.2.7.1) — so encoding an <c>x5t#o</c> thumbprint carrying an
    /// <see cref="AdESDigestAlgorithmIntegerIdentifier"/> (the CB-AdES-only wire shape) is refused.
    /// </summary>
    [TestMethod]
    public void EncodeThrowsWhenX5tHashOCarriesAnIntegerDigestAlgorithmIdentifier()
    {
        byte[] digestBytes = [1, 2, 3, 4, 5, 6, 7, 8];
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(digestBytes.Length);
        digestBytes.CopyTo(owner.Memory);
        using var digest = new DigestValue(owner, CryptoTags.Sha256Digest);
        using var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digest);
        using JAdESProtectedHeaders headers = new(algorithm: "ES256", x5tHashO: thumbprint);

        FormatException exception = Assert.ThrowsExactly<FormatException>(
            () => JAdESProtectedHeaderJson.Encode(headers, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared));

        Assert.IsTrue(exception.Message.Contains("5.2.2.2", StringComparison.Ordinal));
        Assert.IsTrue(exception.Message.Contains("5.2.7.1", StringComparison.Ordinal));
    }


    /// <summary>A header missing the mandatory <c>alg</c> member (JA-5.1.2-01) fails closed as <see langword="null"/>.</summary>
    [TestMethod]
    public void DecodeFailsClosedWhenAlgIsMissing()
    {
        byte[] json = Encoding.UTF8.GetBytes("""{"cty":"application/json"}""");

        JAdESProtectedHeaders? decoded = JAdESProtectedHeaderJson.Decode(json, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

        Assert.IsNull(decoded);
    }


    /// <summary>Malformed JSON fails closed as <see langword="null"/> rather than letting a <see cref="System.Text.Json.JsonException"/> escape.</summary>
    [TestMethod]
    public void DecodeFailsClosedOnMalformedJson()
    {
        byte[] json = Encoding.UTF8.GetBytes("{not-valid-json");

        JAdESProtectedHeaders? decoded = JAdESProtectedHeaderJson.Decode(json, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

        Assert.IsNull(decoded);
    }


    /// <summary>A JSON array (not an object) at the top level fails closed as <see langword="null"/>.</summary>
    [TestMethod]
    public void DecodeFailsClosedWhenRootIsNotAnObject()
    {
        byte[] json = Encoding.UTF8.GetBytes("""["alg","ES256"]""");

        JAdESProtectedHeaders? decoded = JAdESProtectedHeaderJson.Decode(json, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

        Assert.IsNull(decoded);
    }


    /// <summary>
    /// Regression: a header carrying a valid <c>x5t#S256</c> digest (successfully decoded into a
    /// pool-rented <see cref="DigestValue"/>) followed by a malformed <c>sigD</c> (the <c>HttpHeaders</c>
    /// mechanism with an empty <c>pars</c> array, which <see cref="JAdESHttpHeadersReference"/>'s own
    /// constructor rejects) fails closed with zero outstanding pool rentals — the already-decoded
    /// <c>x5t#S256</c> carrier must not leak when the LATER <c>sigD</c> decode throws.
    /// </summary>
    [TestMethod]
    public void DecodeDisposesEarlierDecodedMembersWhenALaterSigDDecodeThrows()
    {
        using var meteredPool = new MeteredHousePool();

        string digestText = TestSetup.Base64UrlEncoder(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
        byte[] json = Encoding.UTF8.GetBytes(
            "{\"alg\":\"ES256\",\"x5t#S256\":\"" + digestText +
            "\",\"sigD\":{\"mId\":\"http://uri.etsi.org/19182/HttpHeaders\",\"pars\":[]}}");

        JAdESProtectedHeaders? decoded = JAdESProtectedHeaderJson.Decode(json, TestSetup.Base64UrlDecoder, meteredPool.Pool);

        Assert.IsNull(decoded);
        Assert.AreEqual(0, meteredPool.OutstandingCount,
            "The already-decoded x5t#S256 DigestValue must not leak when the later sigD decode throws.");
    }


    /// <summary>
    /// Regression: a <c>sigX5ts</c> array carrying two valid entries followed by a malformed one
    /// (missing the required <c>digAlg</c> member) fails closed with zero outstanding pool rentals — the two
    /// already-decoded <see cref="AdESCertificateThumbprint"/> entries' pooled digests must not leak when the
    /// array's third element throws mid-collection.
    /// </summary>
    [TestMethod]
    public void DecodeDisposesEarlierSigX5tsEntriesWhenABadElementThrowsMidCollection()
    {
        using var meteredPool = new MeteredHousePool();

        byte[] json = Encoding.UTF8.GetBytes(
            """{"alg":"ES256","sigX5ts":[{"digAlg":"SHA-256","digVal":"AQIDBA=="},{"digAlg":"SHA-256","digVal":"BQYHCA=="},{"digVal":"AAAA"}]}""");

        JAdESProtectedHeaders? decoded = JAdESProtectedHeaderJson.Decode(json, TestSetup.Base64UrlDecoder, meteredPool.Pool);

        Assert.IsNull(decoded);
        Assert.AreEqual(0, meteredPool.OutstandingCount,
            "The two already-decoded sigX5ts entries must not leak when the third element's decode throws.");
    }
}
