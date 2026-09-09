using System.Text;
using Verifiable.OAuth;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Pins the client-authentication metadata members of
/// <see cref="AuthorizationServerMetadataParameterNames"/> to their exact RFC 8414 §2 wire
/// spellings and proves each member's UTF-8 span, interned string and <c>Is&lt;Member&gt;</c>
/// predicate agree. The discovery document advertises the token endpoint's client-authentication
/// methods and the JWS algorithms that sign the client-assertion JWT through these members, so a
/// typo silently breaks interoperability with the RFC 8414 registry.
/// </summary>
[TestClass]
internal sealed class AuthorizationServerMetadataParameterNamesTests
{
    /// <summary>
    /// The signing-alg member spells its exact registry name and its UTF-8 span agrees with the
    /// interned string: <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414, Section 2</see>
    /// registers "token_endpoint_auth_signing_alg_values_supported" as the "JSON array containing a
    /// list of the JWS signing algorithms ("alg" values) supported by the token endpoint for the
    /// signature on the JWT [JWT] used to authenticate the client".
    /// </summary>
    [TestMethod]
    public void TokenEndpointAuthSigningAlgValuesSupportedSpellsItsRegistryName()
    {
        Assert.AreEqual(
            "token_endpoint_auth_signing_alg_values_supported",
            AuthorizationServerMetadataParameterNames.TokenEndpointAuthSigningAlgValuesSupported,
            "RFC 8414 §2 registers the member as token_endpoint_auth_signing_alg_values_supported.");
        Assert.AreEqual(
            "token_endpoint_auth_signing_alg_values_supported",
            Encoding.UTF8.GetString(AuthorizationServerMetadataParameterNames.TokenEndpointAuthSigningAlgValuesSupportedUtf8),
            "The UTF-8 source span MUST decode to the same registry name as the interned string.");
    }

    /// <summary>
    /// The <c>Is</c> predicate for the signing-alg member matches only the exact registry name
    /// ordinally: <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414, Section 2</see>'s
    /// member name is a JSON object name, so a case-folded or suffixed lookalike is a different
    /// name and MUST NOT match.
    /// </summary>
    [TestMethod]
    public void IsTokenEndpointAuthSigningAlgValuesSupportedIsExactAndOrdinal()
    {
        Assert.IsTrue(
            AuthorizationServerMetadataParameterNames.IsTokenEndpointAuthSigningAlgValuesSupported(
                "token_endpoint_auth_signing_alg_values_supported"),
            "The predicate MUST match the exact registry name.");
        Assert.IsFalse(
            AuthorizationServerMetadataParameterNames.IsTokenEndpointAuthSigningAlgValuesSupported(
                "TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED"),
            "The predicate MUST be ordinal (case-sensitive) and reject the upper-cased name.");
        Assert.IsFalse(
            AuthorizationServerMetadataParameterNames.IsTokenEndpointAuthSigningAlgValuesSupported(
                "token_endpoint_auth_signing_alg_values_supported_x"),
            "The predicate MUST be exact and reject a suffixed near-miss.");
    }

    /// <summary>
    /// The methods member spells its exact registry name and its <c>Is</c> predicate matches only
    /// that name ordinally: <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414, Section 2</see>
    /// registers "token_endpoint_auth_methods_supported" as the "JSON array containing a list of
    /// client authentication methods supported by this token endpoint".
    /// </summary>
    [TestMethod]
    public void TokenEndpointAuthMethodsSupportedSpellsItsRegistryNameAndPredicateIsExact()
    {
        Assert.AreEqual(
            "token_endpoint_auth_methods_supported",
            AuthorizationServerMetadataParameterNames.TokenEndpointAuthMethodsSupported,
            "RFC 8414 §2 registers the member as token_endpoint_auth_methods_supported.");
        Assert.AreEqual(
            "token_endpoint_auth_methods_supported",
            Encoding.UTF8.GetString(AuthorizationServerMetadataParameterNames.TokenEndpointAuthMethodsSupportedUtf8),
            "The UTF-8 source span MUST decode to the same registry name as the interned string.");
        Assert.IsTrue(
            AuthorizationServerMetadataParameterNames.IsTokenEndpointAuthMethodsSupported(
                "token_endpoint_auth_methods_supported"),
            "The predicate MUST match the exact registry name.");
        Assert.IsFalse(
            AuthorizationServerMetadataParameterNames.IsTokenEndpointAuthMethodsSupported(
                "TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED"),
            "The predicate MUST be ordinal (case-sensitive) and reject the upper-cased name.");
        Assert.IsFalse(
            AuthorizationServerMetadataParameterNames.IsTokenEndpointAuthMethodsSupported(
                "token_endpoint_auth_methods_supported_x"),
            "The predicate MUST be exact and reject a suffixed near-miss.");
    }
}
