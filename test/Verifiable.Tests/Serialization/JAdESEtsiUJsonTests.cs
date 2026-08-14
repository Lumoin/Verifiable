using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// Coverage for <see cref="JAdESEtsiUJson"/> — the JAdES <c>etsiU</c> unprotected-header codec: whole-array
/// incorporation-mode duality detection, byte-exact base64url wire-text preservation, clear-JSON typed decode,
/// and the creation-side dictionary projection.
/// </summary>
[TestClass]
internal sealed class JAdESEtsiUJsonTests
{
    /// <summary>
    /// Base64url incorporation: each array element's own wire TEXT is captured byte-exact, and
    /// <see cref="JAdESUnsignedHeaderElement.Kind"/> is correctly detected from the base64url-decoded content
    /// without corrupting the preserved wire text (the document's own base64url spelling, ruled read
    /// consistently for the wire form this test exercises).
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.3.1-04, JA-5.3.1-06, JA-5.3.1-09.
    /// </remarks>
    [TestMethod]
    public void TryParseBase64UrlModeCapturesWireTextByteExact()
    {
        string sigTstElement = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes("""{"sigTst":{"tstTokens":[{"val":"AAAA"}]}}"""));
        string cSigElement = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes("""{"cSig":{"anything":true}}"""));
        byte[] etsiUJson = Encoding.UTF8.GetBytes($"[\"{sigTstElement}\",\"{cSigElement}\"]");

        bool success = JAdESEtsiUJson.TryParse(etsiUJson, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, out JAdESUnsignedHeaders? result);
        using JAdESUnsignedHeaders? disposable = result;

        Assert.IsTrue(success);
        Assert.IsNotNull(result);
        Assert.AreEqual(JAdESEtsiUIncorporationMode.Base64Url, result.Mode);
        Assert.HasCount(2, result);

        Assert.AreEqual(JAdESUnsignedHeaderElement.SignatureTimestampKind, result[0].Kind);
        var sigTst = (JAdESUnsignedHeaderElementSignatureTimestamp)result[0];
        var opaque = (JAdESOpaqueUnsignedValue<AdESTimestampContainer>)sigTst.Carriage;
        Assert.AreEqual(sigTstElement, Encoding.ASCII.GetString(opaque.WireText.AsReadOnlySpan()));

        Assert.AreEqual(JAdESUnsignedHeaderElement.CounterSignatureKind, result[1].Kind);
        var cSig = (JAdESUnsignedHeaderElementCounterSignature)result[1];
        Assert.AreEqual(cSigElement, Encoding.ASCII.GetString(cSig.WireText.AsReadOnlySpan()));
    }


    /// <summary>Clear-JSON incorporation decodes each element into its typed Pki model.</summary>
    [TestMethod]
    public void TryParseClearJsonModeDecodesTypedValue()
    {
        byte[] etsiUJson = Encoding.UTF8.GetBytes(
            """[{"sigTst":{"tstTokens":[{"val":"AAAA"}]}},{"xVals":[{"x509Cert":{"val":"AAAA"}}]}]""");

        bool success = JAdESEtsiUJson.TryParse(etsiUJson, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, out JAdESUnsignedHeaders? result);
        using JAdESUnsignedHeaders? disposable = result;

        Assert.IsTrue(success);
        Assert.IsNotNull(result);
        Assert.AreEqual(JAdESEtsiUIncorporationMode.ClearJson, result.Mode);
        Assert.HasCount(2, result);

        var sigTst = (JAdESUnsignedHeaderElementSignatureTimestamp)result[0];
        var sigTstValue = (JAdESClearUnsignedValue<AdESTimestampContainer>)sigTst.Carriage;
        Assert.HasCount(1, sigTstValue.Value.TstTokens);

        var xVals = (JAdESUnsignedHeaderElementCertificateValues)result[1];
        var xValsValue = (JAdESClearUnsignedValue<JAdESCertificateValues>)xVals.Carriage;
        Assert.HasCount(1, xValsValue.Value.Items);
        Assert.IsInstanceOfType<JAdESX509Certificate>(xValsValue.Value.Items[0]);
    }


    /// <summary>A mixed array (one base64url element, one clear-JSON element) is a fail-closed violation (JA-5.3.1-10/-11).</summary>
    [TestMethod]
    public void TryParseFailsClosedOnMixedIncorporationMode()
    {
        string base64UrlElement = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes("""{"cSig":{}}"""));
        byte[] etsiUJson = Encoding.UTF8.GetBytes(
            "[\"" + base64UrlElement + "\"," + """{"xVals":[{"x509Cert":{"val":"AAAA"}}]}]""");

        bool success = JAdESEtsiUJson.TryParse(etsiUJson, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, out JAdESUnsignedHeaders? result);
        using JAdESUnsignedHeaders? disposable = result;

        Assert.IsFalse(success);
        Assert.IsNull(result);
    }


    /// <summary>A non-array top-level value fails closed.</summary>
    [TestMethod]
    public void TryParseFailsClosedOnNonArrayInput()
    {
        byte[] etsiUJson = Encoding.UTF8.GetBytes("""{"not":"an array"}""");

        bool success = JAdESEtsiUJson.TryParse(etsiUJson, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, out JAdESUnsignedHeaders? result);
        using JAdESUnsignedHeaders? disposable = result;

        Assert.IsFalse(success);
        Assert.IsNull(result);
    }


    /// <summary>An empty array fails closed (JA-5.3.1-07: etsiU shall be a non-empty array).</summary>
    [TestMethod]
    public void TryParseFailsClosedOnEmptyArray()
    {
        byte[] etsiUJson = Encoding.UTF8.GetBytes("[]");

        bool success = JAdESEtsiUJson.TryParse(etsiUJson, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, out JAdESUnsignedHeaders? result);
        using JAdESUnsignedHeaders? disposable = result;

        Assert.IsFalse(success);
        Assert.IsNull(result);
    }


    /// <summary>An element that is neither a JSON string nor a JSON object fails the whole parse closed.</summary>
    [TestMethod]
    public void TryParseFailsClosedOnNonStringNonObjectElement()
    {
        byte[] etsiUJson = Encoding.UTF8.GetBytes("[42]");

        bool success = JAdESEtsiUJson.TryParse(etsiUJson, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, out JAdESUnsignedHeaders? result);
        using JAdESUnsignedHeaders? disposable = result;

        Assert.IsFalse(success);
        Assert.IsNull(result);
    }


    /// <summary>An unterminated array fails closed rather than throwing an index-out-of-range exception.</summary>
    [TestMethod]
    public void TryParseFailsClosedOnUnterminatedArray()
    {
        string incompleteElement = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes("""{"cSig":{}}"""));
        byte[] etsiUJson = Encoding.UTF8.GetBytes("[\"" + incompleteElement);

        bool success = JAdESEtsiUJson.TryParse(etsiUJson, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, out JAdESUnsignedHeaders? result);
        using JAdESUnsignedHeaders? disposable = result;

        Assert.IsFalse(success);
        Assert.IsNull(result);
    }


    /// <summary>Round-tripping a base64url-mode parse through <see cref="JAdESEtsiUJson.Encode"/> reproduces the exact same wire strings.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.3.1-08.
    /// </remarks>
    [TestMethod]
    public void Base64UrlModeRoundTripsParseThenEncodeByteExact()
    {
        string element1 = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes("""{"sigTst":{"tstTokens":[{"val":"AAAA"}]}}"""));
        string element2 = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes("""{"cSig":{}}"""));
        byte[] etsiUJson = Encoding.UTF8.GetBytes($"[\"{element1}\",\"{element2}\"]");

        bool success = JAdESEtsiUJson.TryParse(etsiUJson, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, out JAdESUnsignedHeaders? result);
        using JAdESUnsignedHeaders? disposable = result;
        Assert.IsTrue(success);

        IReadOnlyDictionary<string, object>? projected = JAdESEtsiUJson.Encode(result);

        Assert.IsNotNull(projected);
        var list = (List<object>)projected[WellKnownJAdESHeaderNames.EtsiU];
        Assert.AreEqual(element1, list[0]);
        Assert.AreEqual(element2, list[1]);
    }


    /// <summary>Encoding a base64url-mode container projects each element as a plain JSON string.</summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "wireText's ownership transfers into element, then into the 'using headers' container, which disposes the whole chain.")]
    public void EncodeProjectsBase64UrlModeElementsAsStrings()
    {
        PooledMemory wireText = PooledMemory.FromBytes(Encoding.ASCII.GetBytes("eyJjU2lnIjp7fX0"), BaseMemoryPool.Shared, CryptoTags.JoseEncodedUnsignedHeaderElement);
        var element = new JAdESUnsignedHeaderElementCounterSignature(wireText);
        using var headers = new JAdESUnsignedHeaders(JAdESEtsiUIncorporationMode.Base64Url, [element]);

        IReadOnlyDictionary<string, object>? projected = JAdESEtsiUJson.Encode(headers);

        Assert.IsNotNull(projected);
        var list = (List<object>)projected[WellKnownJAdESHeaderNames.EtsiU];
        Assert.HasCount(1, list);
        Assert.AreEqual("eyJjU2lnIjp7fX0", list[0]);
    }


    /// <summary>Encoding a clear-JSON-mode container projects each typed element as a nested <c>{Kind: value}</c> dictionary.</summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "digest/thumbprint/collection/element's ownership transfers step-by-step into the 'using headers' container, which disposes the whole chain.")]
    public void EncodeProjectsClearJsonModeElementsAsNestedObjects()
    {
        byte[] digestBytes = [1, 2, 3, 4];
        IMemoryOwner<byte> digestOwner = BaseMemoryPool.Shared.Rent(digestBytes.Length);
        digestBytes.CopyTo(digestOwner.Memory);
        var digest = new DigestValue(digestOwner, CryptoTags.Sha256Digest);
        var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("SHA-256"), digest);
        var collection = new JAdESCertificateReferenceCollection([thumbprint]);
        var element = new JAdESUnsignedHeaderElementCertificateReferences(new JAdESClearUnsignedValue<JAdESCertificateReferenceCollection>(collection));
        using var headers = new JAdESUnsignedHeaders(JAdESEtsiUIncorporationMode.ClearJson, [element]);

        IReadOnlyDictionary<string, object>? projected = JAdESEtsiUJson.Encode(headers);

        Assert.IsNotNull(projected);
        var list = (List<object>)projected[WellKnownJAdESHeaderNames.EtsiU];
        Assert.HasCount(1, list);
        var entry = (Dictionary<string, object>)list[0];
        Assert.IsTrue(entry.ContainsKey(JAdESUnsignedHeaderElement.CertificateReferencesKind));
        var xRefs = (List<object>)entry[JAdESUnsignedHeaderElement.CertificateReferencesKind];
        Assert.HasCount(1, xRefs);
        var thumbprintDict = (Dictionary<string, object>)xRefs[0];
        Assert.AreEqual("SHA-256", thumbprintDict[JAdESWireNames.CertificateThumbprintHashAlgorithm]);
        Assert.AreEqual(Convert.ToBase64String(digestBytes), thumbprintDict[JAdESWireNames.CertificateThumbprintDigest]);
    }


    /// <summary>Encoding a <see langword="null"/> container yields <see langword="null"/> — no unprotected header at all.</summary>
    [TestMethod]
    public void EncodeReturnsNullForNullContainer()
    {
        IReadOnlyDictionary<string, object>? projected = JAdESEtsiUJson.Encode(null);

        Assert.IsNull(projected);
    }
}
