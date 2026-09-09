using System.Globalization;
using System.Text.Json;
using Verifiable.OAuth;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The RFC 6749 error-response assertions every OAuth/OID4VP wire refusal test shares: reading the wire
/// <c>error</c>/<c>error_description</c> pair out of a refusal's diagnostic text, and checking the HTTP
/// status code that text names.
/// </summary>
internal static class OAuthErrorAssertions
{
    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 Section 4.1.2.1</see>:
    /// "error: REQUIRED. ... error_description: OPTIONAL. Human-readable ASCII [USASCII] text providing
    /// additional information". Reads the JSON object starting at <paramref name="refusalMessage"/>'s first
    /// <c>{</c>, so a caller may pass either a raw error response body or a diagnostic string the body is
    /// embedded in.
    /// </summary>
    /// <param name="refusalMessage">The refusal's diagnostic text or raw response body containing the error response's JSON object.</param>
    /// <returns>The wire <c>error</c> and <c>error_description</c> values.</returns>
    public static (string Error, string Description) ReadOAuthErrorBody(string refusalMessage)
    {
        int bodyStart = refusalMessage.IndexOf('{', StringComparison.Ordinal);
        Assert.IsGreaterThan(-1, bodyStart,
            "RFC 6749 Section 4.1.2.1: the refusal the wallet read is a JSON object.");

        using JsonDocument document = JsonDocument.Parse(refusalMessage[bodyStart..]);

        Assert.AreEqual(JsonValueKind.Object, document.RootElement.ValueKind,
            "RFC 6749 Section 4.1.2.1: the error response body is a JSON object.");
        Assert.IsTrue(
            document.RootElement.TryGetProperty(OAuthRequestParameterNames.Error, out JsonElement error),
            "RFC 6749 Section 4.1.2.1: error is REQUIRED in the error response.");
        Assert.IsTrue(
            document.RootElement.TryGetProperty(
                OAuthRequestParameterNames.ErrorDescription, out JsonElement description),
            "RFC 6749 Section 4.1.2.1's OPTIONAL error_description is the sentence the Response URI answers with.");

        return (error.GetString()!, description.GetString()!);
    }


    /// <summary>
    /// Asserts that <paramref name="refusalMessage"/> names <paramref name="expected"/> as the HTTP status
    /// code the underlying wire response answered with — the diagnostic text a resolver or fetch failure's
    /// exception carries.
    /// </summary>
    /// <param name="expected">The HTTP status code the refusal is expected to name.</param>
    /// <param name="refusalMessage">The refusal's diagnostic text.</param>
    /// <param name="message">The assertion failure message.</param>
    public static void AssertWireStatusCode(int expected, string refusalMessage, string message)
    {
        Assert.Contains(
            $"returned status {expected.ToString(CultureInfo.InvariantCulture)}",
            refusalMessage,
            StringComparison.Ordinal,
            message);
    }
}
