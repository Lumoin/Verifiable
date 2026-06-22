using System.Buffers;
using System.Text;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography.Aead;

/// <summary>
/// Tests the JSON-serialization classification path of <see cref="JoseTokenClassifier"/> per
/// RFC 7516 §9: a token beginning with '{' is classified by its top-level members rather than by
/// compact segment count. A <c>ciphertext</c> member marks a JWE — general when a
/// <c>recipients</c> array is present (RFC 7516 §7.2.1), flattened when a top-level
/// <c>encrypted_key</c> is present (§7.2.2). A <c>payload</c>/<c>signatures</c>/<c>signature</c>
/// member marks a JWS (RFC 7515 §7.2). An object carrying both forms, neither form, or a
/// <c>ciphertext</c> with no recipient/encrypted_key is structurally ambiguous and classifies as
/// <see cref="MalformedShape"/>.
/// </summary>
/// <remarks>
/// The classifier is the first attacker-controlled-input boundary, so a truncated or otherwise
/// malformed JSON object must produce a <see cref="MalformedShape"/> rather than throw. The
/// JSON path reads members from the raw token bytes and does not exercise the Base64Url decoder
/// or header deserializer, but the entry method signature still requires them.
/// </remarks>
[TestClass]
internal sealed class JoseTokenClassifierJsonTests
{
    public TestContext TestContext { get; set; } = null!;


    private static Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>> HeaderDeserializer
    {
        get;
    } = static bytes => JsonSerializer.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
            ?? throw new FormatException("Header JSON parsed to null.");

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;


    private async Task<JoseTokenShape> ClassifyAsync(string token)
    {
        return await JoseTokenClassifier.ClassifyAsync(
            token,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task ClassifyJson_GeneralJwe()
    {
        const string token = "{\"protected\":\"eyJlbmMiOiJBMjU2R0NNIn0\",\"recipients\":[{\"encrypted_key\":\"YWJj\"}],\"iv\":\"aXY\",\"ciphertext\":\"Y3Q\",\"tag\":\"dGFn\"}";

        JoseTokenShape result = await ClassifyAsync(token).ConfigureAwait(false);

        Assert.IsInstanceOfType<GeneralJweShape>(result,
            "An object with 'ciphertext' and a 'recipients' array is the general JWE JSON form (RFC 7516 §7.2.1).");
        Assert.AreEqual(token, ((GeneralJweShape)result).Value,
            "GeneralJweShape must carry the original wire string verbatim.");
    }


    [TestMethod]
    public async Task ClassifyJson_FlattenedJwe()
    {
        const string token = "{\"protected\":\"eyJlbmMiOiJBMjU2R0NNIn0\",\"encrypted_key\":\"YWJj\",\"iv\":\"aXY\",\"ciphertext\":\"Y3Q\",\"tag\":\"dGFn\"}";

        JoseTokenShape result = await ClassifyAsync(token).ConfigureAwait(false);

        Assert.IsInstanceOfType<FlattenedJweShape>(result,
            "An object with 'ciphertext' and a top-level 'encrypted_key' (no 'recipients') is the flattened JWE JSON form (RFC 7516 §7.2.2).");
        Assert.AreEqual(token, ((FlattenedJweShape)result).Value,
            "FlattenedJweShape must carry the original wire string verbatim.");
    }


    [TestMethod]
    public async Task ClassifyJson_GeneralJws()
    {
        const string token = "{\"payload\":\"eyJ9\",\"signatures\":[{\"protected\":\"eyJhbGciOiJFUzI1NiJ9\",\"signature\":\"YWJj\"}]}";

        JoseTokenShape result = await ClassifyAsync(token).ConfigureAwait(false);

        Assert.IsInstanceOfType<GeneralJwsShape>(result,
            "An object with 'payload' and a 'signatures' array is the general JWS JSON form (RFC 7515 §7.2.1).");
        Assert.AreEqual(token, ((GeneralJwsShape)result).Value,
            "GeneralJwsShape must carry the original wire string verbatim.");
    }


    [TestMethod]
    public async Task ClassifyJson_FlattenedJws()
    {
        const string token = "{\"payload\":\"eyJ9\",\"protected\":\"eyJhbGciOiJFUzI1NiJ9\",\"signature\":\"YWJj\"}";

        JoseTokenShape result = await ClassifyAsync(token).ConfigureAwait(false);

        Assert.IsInstanceOfType<FlattenedJwsShape>(result,
            "An object with 'payload' and a top-level 'signature' (no 'signatures' array) is the flattened JWS JSON form (RFC 7515 §7.2.2).");
        Assert.AreEqual(token, ((FlattenedJwsShape)result).Value,
            "FlattenedJwsShape must carry the original wire string verbatim.");
    }


    [TestMethod]
    public async Task ClassifyJson_BothJwsAndJwe_IsMalformed()
    {
        //RFC 7516 §9 makes the JWS and JWE JSON forms mutually exclusive: a 'payload' member and a
        //'ciphertext' member in one object is structurally ambiguous.
        const string token = "{\"payload\":\"eyJ9\",\"ciphertext\":\"Y3Q\",\"recipients\":[{\"encrypted_key\":\"YWJj\"}]}";

        JoseTokenShape result = await ClassifyAsync(token).ConfigureAwait(false);

        Assert.IsInstanceOfType<MalformedShape>(result,
            "An object carrying both JWS and JWE members must classify as MalformedShape (RFC 7516 §9).");
    }


    [TestMethod]
    public async Task ClassifyJson_CiphertextButNoRecipientOrEncryptedKey_IsMalformed()
    {
        //A JWE with neither a 'recipients' array nor a top-level 'encrypted_key' cannot be placed
        //into either the general or flattened form.
        const string token = "{\"protected\":\"eyJlbmMiOiJBMjU2R0NNIn0\",\"iv\":\"aXY\",\"ciphertext\":\"Y3Q\",\"tag\":\"dGFn\"}";

        JoseTokenShape result = await ClassifyAsync(token).ConfigureAwait(false);

        Assert.IsInstanceOfType<MalformedShape>(result,
            "A JWE JSON object with neither 'recipients' nor a top-level 'encrypted_key' must classify as MalformedShape.");
    }


    [TestMethod]
    public async Task ClassifyJson_NeitherJwsNorJwe_IsMalformed()
    {
        //An object with no JWS member and no 'ciphertext' member is neither serialization form.
        const string token = "{\"foo\":\"bar\",\"baz\":1}";

        JoseTokenShape result = await ClassifyAsync(token).ConfigureAwait(false);

        Assert.IsInstanceOfType<MalformedShape>(result,
            "A JSON object that is neither a JWS nor a JWE must classify as MalformedShape.");
    }


    [TestMethod]
    public async Task ClassifyJson_LeadingWhitespaceBeforeBraceRoutesToJson()
    {
        //RFC 7516 §9 routing inspects the first non-whitespace character. Leading whitespace before
        //'{' still routes to the JSON path, so a well-formed general JWE body lands on a JSON shape
        //rather than the compact (segment-count) path.
        const string token = "   \r\n\t{\"protected\":\"eyJlbmMiOiJBMjU2R0NNIn0\",\"recipients\":[{\"encrypted_key\":\"YWJj\"}],\"iv\":\"aXY\",\"ciphertext\":\"Y3Q\",\"tag\":\"dGFn\"}";

        JoseTokenShape result = await ClassifyAsync(token).ConfigureAwait(false);

        Assert.IsInstanceOfType<GeneralJweShape>(result,
            "Leading whitespace before '{' must route to the JSON classification path (RFC 7516 §9).");
    }


    [TestMethod]
    public async Task ClassifyJson_MalformedJsonDoesNotThrow()
    {
        //The classifier is an attacker-controlled-input boundary: a truncated JSON object must
        //produce a MalformedShape, never an escaping exception.
        const string token = "{\"ciphertext\":";

        JoseTokenShape result = await ClassifyAsync(token).ConfigureAwait(false);

        Assert.IsInstanceOfType<MalformedShape>(result,
            "A truncated JSON object must classify as MalformedShape rather than throw.");
    }
}
