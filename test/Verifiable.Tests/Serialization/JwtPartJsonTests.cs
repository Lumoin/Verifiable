using System.Text;
using Verifiable.JCose;
using Verifiable.Json;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// Coverage for <see cref="JwtPartJson.Default"/> — the library's shipped general
/// <see cref="JwtPartDecoder"/> default. Proves the two properties the four test-side hand-rolled
/// copies it replaces (<c>JCoseCryptoEventSinkForwardingTests</c>, <c>SiopRequestUriFlowTests</c>,
/// <c>SiopRealWireFlowTests</c>) never enforced on their own: a well-formed part round-trips, and a
/// malformed one fails closed with <see cref="FormatException"/> rather than letting
/// <see cref="System.Text.Json.JsonException"/> — a <see cref="System.Text.Json"/> type — cross out of
/// this leaf into the serialization-agnostic <c>Verifiable.JCose</c> verify path.
/// </summary>
[TestClass]
internal sealed class JwtPartJsonTests
{
    /// <summary>A well-formed JWT part decodes to its claim dictionary.</summary>
    [TestMethod]
    public void WellFormedPartDecodesToClaimsDictionary()
    {
        byte[] bytes = Encoding.UTF8.GetBytes("""{"iss":"https://issuer.example","sub":"user-1"}""");

        IReadOnlyDictionary<string, object> claims = JwtPartJson.Default(bytes);

        Assert.AreEqual("https://issuer.example", claims["iss"].ToString());
        Assert.AreEqual("user-1", claims["sub"].ToString());
    }


    /// <summary>
    /// Malformed JSON fails closed with <see cref="FormatException"/> — the
    /// <see cref="System.Text.Json.JsonException"/> the decoder catches internally never escapes this
    /// leaf. The four hand-rolled test copies this default replaces called
    /// <c>JsonSerializer.Deserialize</c> directly with no such translation, so a malformed part would
    /// have thrown the framework's own <see cref="System.Text.Json.JsonException"/> instead.
    /// </summary>
    [TestMethod]
    public void MalformedJsonThrowsFormatExceptionNotJsonException()
    {
        byte[] bytes = Encoding.UTF8.GetBytes("{not-valid-json");

        FormatException exception = Assert.ThrowsExactly<FormatException>(() => JwtPartJson.Default(bytes));
        _ = Assert.IsInstanceOfType<System.Text.Json.JsonException>(exception.InnerException);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7">RFC 7519 Section 4.1.7</see>: "The
    /// "jti" value is a case-sensitive string.";
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2">Section 4.1.2</see>: "The "sub" value
    /// is a case-sensitive string containing a StringOrURI value."; and
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.2">RFC 8693 Section 4.2</see>: "The value
    /// of the "scope" claim is a JSON string containing a space-separated list of scopes associated with the
    /// token, in the format described in Section 3.3 of [RFC6749]." A <c>jti</c>, <c>scope</c> and
    /// <c>sub</c> whose text reads as a date decode through <see cref="JwtPartJson.Default"/> as the
    /// <see cref="string"/> sent, each the same text.
    /// </summary>
    [TestMethod]
    public void DateShapedJtiScopeSubDecodeAsStrings()
    {
        byte[] bytes = Encoding.UTF8.GetBytes("""{"jti":"2026-10-01","scope":"2026-10-01T12:00:00Z","sub":"2026-10-01"}""");

        IReadOnlyDictionary<string, object> claims = JwtPartJson.Default(bytes);

        Assert.AreEqual("2026-10-01", Assert.IsInstanceOfType<string>(claims["jti"]));
        Assert.AreEqual("2026-10-01T12:00:00Z", Assert.IsInstanceOfType<string>(claims["scope"]));
        Assert.AreEqual("2026-10-01", Assert.IsInstanceOfType<string>(claims["sub"]));
    }


    /// <summary>A JSON <c>null</c> part fails closed with <see cref="FormatException"/> rather than returning a null claim set.</summary>
    [TestMethod]
    public void JsonNullThrowsFormatException()
    {
        byte[] bytes = Encoding.UTF8.GetBytes("null");

        _ = Assert.ThrowsExactly<FormatException>(() => JwtPartJson.Default(bytes));
    }
}
