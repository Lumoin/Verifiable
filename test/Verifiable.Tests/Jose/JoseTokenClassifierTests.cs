using System.Buffers;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Tests <see cref="JoseTokenClassifier"/> against happy-path and hostile
/// inputs.
/// </summary>
/// <remarks>
/// <para>
/// The classifier is the first parsing surface a token-aware caller invokes
/// on attacker-controlled bytes. Tests cover the structural cases that
/// production callers (OAuth dispatch, SD-JWT consumers, OID4VCI proof
/// validators) rely on, and the hostile-input cases an attacker may supply
/// to confuse classification.
/// </para>
/// <para>
/// The classifier is purely structural — it does not verify JWS signatures
/// or decrypt JWE ciphertexts. Tests assert only the classification verdict;
/// downstream verification is the consumer's concern.
/// </para>
/// </remarks>
[TestClass]
internal sealed class JoseTokenClassifierTests
{
    public TestContext TestContext { get; set; } = null!;


    private static Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>> HeaderDeserializer
    {
        get;
    } = static bytes => JsonSerializer.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
            ?? throw new FormatException("Header JSON parsed to null.");

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;


    [TestMethod]
    public async Task EmptyInputClassifiesAsMalformed()
    {
        JoseTokenShape result = await JoseTokenClassifier.ClassifyAsync(
            string.Empty,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<MalformedShape>(result,
            "Empty input must classify as MalformedShape.");
        MalformedShape malformed = (MalformedShape)result;
        Assert.IsFalse(string.IsNullOrWhiteSpace(malformed.Reason),
            "MalformedShape.Reason must be a stable, non-empty string.");
    }


    [TestMethod]
    public async Task SingleSegmentClassifiesAsOpaque()
    {
        const string token = "abc123refresh";

        JoseTokenShape result = await JoseTokenClassifier.ClassifyAsync(
            token,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<OpaqueShape>(result,
            "A single-segment non-empty string must classify as OpaqueShape.");
        OpaqueShape opaque = (OpaqueShape)result;
        Assert.AreEqual(token, opaque.Value,
            "OpaqueShape must carry the original input verbatim.");
    }


    [TestMethod]
    public async Task TwoSegmentClassifiesAsOpaque()
    {
        //Two-segment strings are not JWS (3) or JWE (5); they fall through to opaque.
        const string token = "header.payload";

        JoseTokenShape result = await JoseTokenClassifier.ClassifyAsync(
            token,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<OpaqueShape>(result,
            "A two-segment string is neither JWS nor JWE shape; must classify as OpaqueShape.");
    }


    [TestMethod]
    public async Task FourSegmentClassifiesAsOpaque()
    {
        //Four-segment strings fall between JWS (3) and JWE (5); not a recognized shape.
        const string token = "a.b.c.d";

        JoseTokenShape result = await JoseTokenClassifier.ClassifyAsync(
            token,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<OpaqueShape>(result,
            "A four-segment string must classify as OpaqueShape (not a recognized JOSE shape).");
    }


    [TestMethod]
    public async Task SixSegmentClassifiesAsOpaque()
    {
        const string token = "a.b.c.d.e.f";

        JoseTokenShape result = await JoseTokenClassifier.ClassifyAsync(
            token,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<OpaqueShape>(result,
            "A six-segment string must classify as OpaqueShape (not a recognized JOSE shape).");
    }


    [TestMethod]
    public async Task ThreeSegmentWithValidJwsHeaderClassifiesAsJws()
    {
        string token = BuildJwsCompact(
            new Dictionary<string, object>
            {
                ["alg"] = "ES256",
                ["typ"] = "JWT",
                ["kid"] = "did:example:issuer#key-1"
            },
            payload: "{}",
            signature: [0x01, 0x02, 0x03, 0x04]);

        JoseTokenShape result = await JoseTokenClassifier.ClassifyAsync(
            token,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<JwsShape>(result,
            "Valid 3-segment JWS-shaped input must classify as JwsShape.");
        JwsShape jws = (JwsShape)result;

        try
        {
            UnverifiedJwsSignature signature = jws.Message.Signatures[0];
            Assert.AreEqual(WellKnownJwaValues.Es256, signature.ClaimedAlgorithm,
                "Classifier must surface the unverified alg header value.");
        }
        finally
        {
            jws.Message.Dispose();
        }
    }


    [TestMethod]
    public async Task FiveSegmentWithValidJweHeaderClassifiesAsJwe()
    {
        string token = BuildJweCompact(new Dictionary<string, object>
        {
            ["alg"] = "ECDH-ES",
            ["enc"] = "A128GCM"
        });

        JoseTokenShape result = await JoseTokenClassifier.ClassifyAsync(
            token,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<JweShape>(result,
            "Valid 5-segment JWE-shaped input with enc claim must classify as JweShape.");
        JweShape jwe = (JweShape)result;
        Assert.AreEqual(WellKnownJweEncryptionAlgorithms.A128Gcm, jwe.Token.Header["enc"],
            "Classifier must surface the parsed enc value from the unauthenticated header.");
        Assert.AreEqual(token, jwe.Token.Value,
            "JweShape.Token.Value must carry the original input verbatim.");
    }


    [TestMethod]
    public async Task ThreeSegmentWithEncClaimInHeaderClassifiesAsMalformed()
    {
        //A 3-segment string whose header carries an enc claim is structurally
        //inconsistent: 3 segments suggest JWS, the enc claim suggests JWE. The
        //classifier must reject this rather than accept it as either shape.
        string token = BuildJwsCompact(
            new Dictionary<string, object>
            {
                ["alg"] = "ECDH-ES",
                ["enc"] = "A128GCM"
            },
            payload: "{}",
            signature: [0x01]);

        JoseTokenShape result = await JoseTokenClassifier.ClassifyAsync(
            token,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<MalformedShape>(result,
            "Three-segment string with enc claim must classify as MalformedShape — segment-count and header are inconsistent.");
    }


    [TestMethod]
    public async Task FiveSegmentWithoutEncClaimClassifiesAsMalformed()
    {
        //A 5-segment string whose header lacks an enc claim is structurally
        //inconsistent: 5 segments suggest JWE, missing enc says it isn't.
        string token = BuildJweCompact(new Dictionary<string, object>
        {
            ["alg"] = "ECDH-ES"
        });

        JoseTokenShape result = await JoseTokenClassifier.ClassifyAsync(
            token,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<MalformedShape>(result,
            "Five-segment string without enc claim must classify as MalformedShape.");
    }


    [TestMethod]
    public async Task ThreeSegmentWithMalformedBase64UrlHeaderClassifiesAsMalformed()
    {
        //First segment is not valid Base64Url (contains characters outside the alphabet).
        const string token = "!!!not-base64url!!!.payload.signature";

        JoseTokenShape result = await JoseTokenClassifier.ClassifyAsync(
            token,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<MalformedShape>(result,
            "Three-segment string with non-Base64Url header must classify as MalformedShape, not throw.");
    }


    [TestMethod]
    public async Task FiveSegmentWithMalformedBase64UrlHeaderClassifiesAsMalformed()
    {
        const string token = "!!!not-base64url!!!.b.c.d.e";

        JoseTokenShape result = await JoseTokenClassifier.ClassifyAsync(
            token,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<MalformedShape>(result,
            "Five-segment string with non-Base64Url header must classify as MalformedShape, not throw.");
    }


    [TestMethod]
    public async Task ThreeSegmentWithHeaderThatParsesToJsonArrayClassifiesAsMalformed()
    {
        //A JSON array decodes successfully but is not a JSON object — classification
        //must reject this rather than accept it as a valid header.
        string headerB64 = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes("[1,2,3]"));
        string token = $"{headerB64}.cGF5bG9hZA.c2lnbmF0dXJl";

        JoseTokenShape result = await JoseTokenClassifier.ClassifyAsync(
            token,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<MalformedShape>(result,
            "Three-segment string with header that parses to a JSON array must classify as MalformedShape.");
    }


    [TestMethod]
    public async Task ThreeSegmentWithAlgNoneHeaderStillClassifiesAsJws()
    {
        //alg=none is a known confusion attack vector on naive verifiers, but
        //classification is purely structural — it must classify as JwsShape
        //regardless of alg value, surfacing the claimed alg for downstream
        //verification to reject. The classifier does not enforce alg policy.
        //
        //Note: the signature segment is non-empty here (bogus bytes) because
        //JwsParsing.ParseCompact, the upstream parser, rejects empty
        //signature segments as structurally invalid. That is correct
        //upstream policy; the classifier surfaces the resulting parse
        //failure as MalformedShape. The test is concerned with alg-policy,
        //not signature-byte-presence, so we provide attacker-controlled
        //bytes in the signature segment to keep the parse path happy.
        string token = BuildJwsCompact(
            new Dictionary<string, object>
            {
                ["alg"] = "none"
            },
            payload: "{}",
            signature: [0xDE, 0xAD, 0xBE, 0xEF]);

        JoseTokenShape result = await JoseTokenClassifier.ClassifyAsync(
            token,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<JwsShape>(result,
            "alg=none must still classify structurally as JwsShape; alg policy is the verifier's concern, not the classifier's.");

        JwsShape jws = (JwsShape)result;
        try
        {
            Assert.AreEqual("none", jws.Message.Signatures[0].ClaimedAlgorithm,
                "ClaimedAlgorithm must surface the attacker-supplied value verbatim.");
        }
        finally
        {
            jws.Message.Dispose();
        }
    }


    [TestMethod]
    public async Task CancelledTokenThrowsOperationCanceled()
    {
        using CancellationTokenSource cts = new();
        await cts.CancelAsync().ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(
            async () => await JoseTokenClassifier.ClassifyAsync(
                "any.token.string",
                TestSetup.Base64UrlDecoder,
                HeaderDeserializer,
                Pool,
                cts.Token).ConfigureAwait(false)).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task ClassifierIsDeterministicAcrossRepeatedInvocations()
    {
        //Calling the classifier with the same input must produce the same
        //classification on repeated calls. No timing or state dependency.
        string token = BuildJwsCompact(
            new Dictionary<string, object> { ["alg"] = "ES256" },
            payload: "{}",
            signature: [0x01, 0x02]);

        JoseTokenShape first = await JoseTokenClassifier.ClassifyAsync(
            token,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        JoseTokenShape second = await JoseTokenClassifier.ClassifyAsync(
            token,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<JwsShape>(first, "First classification must produce JwsShape.");
        Assert.IsInstanceOfType<JwsShape>(second, "Second classification must produce JwsShape.");

        try
        {
            Assert.AreEqual(
                ((JwsShape)first).Message.Signatures[0].ClaimedAlgorithm,
                ((JwsShape)second).Message.Signatures[0].ClaimedAlgorithm,
                "Repeated classification of the same input must produce the same alg surface.");
        }
        finally
        {
            ((JwsShape)first).Message.Dispose();
            ((JwsShape)second).Message.Dispose();
        }
    }


    /// <summary>
    /// Builds a 3-segment compact JWS string from a header dictionary,
    /// payload string, and raw signature bytes.
    /// </summary>
    private static string BuildJwsCompact(
        IReadOnlyDictionary<string, object> header,
        string payload,
        byte[] signature)
    {
        byte[] headerJson = JsonSerializer.SerializeToUtf8Bytes(header, TestSetup.DefaultSerializationOptions);
        string headerB64 = TestSetup.Base64UrlEncoder(headerJson);
        string payloadB64 = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(payload));
        string signatureB64 = TestSetup.Base64UrlEncoder(signature);

        return $"{headerB64}.{payloadB64}.{signatureB64}";
    }


    /// <summary>
    /// Builds a 5-segment compact JWE string from a header dictionary. The
    /// remaining segments are placeholder bytes — sufficient for structural
    /// classification but not for actual decryption.
    /// </summary>
    private static string BuildJweCompact(IReadOnlyDictionary<string, object> header)
    {
        byte[] headerJson = JsonSerializer.SerializeToUtf8Bytes(
            header, TestSetup.DefaultSerializationOptions);
        string headerB64 = TestSetup.Base64UrlEncoder(headerJson);
        string encryptedKeyB64 = TestSetup.Base64UrlEncoder([0x01, 0x02]);
        string ivB64 = TestSetup.Base64UrlEncoder([0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C]);
        string ciphertextB64 = TestSetup.Base64UrlEncoder([0x0D, 0x0E, 0x0F]);
        string tagB64 = TestSetup.Base64UrlEncoder([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F]);

        return $"{headerB64}.{encryptedKeyB64}.{ivB64}.{ciphertextB64}.{tagB64}";
    }
}