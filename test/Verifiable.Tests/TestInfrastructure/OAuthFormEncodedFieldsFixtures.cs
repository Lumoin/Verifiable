using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared request-field fixtures for tests that call the OAuth client library's
/// <see cref="AuthCodeClient"/> surface directly (bypassing <see cref="AuthCodeFlowDriver"/>) and
/// need a start that carries a scope the library never supplies on the caller's behalf. A test
/// whose own subject is the library's scope default keeps composing
/// <see cref="OAuthFormEncodedFields.Empty"/> itself.
/// </summary>
internal static class OAuthFormEncodedFieldsFixtures
{
    /// <summary>
    /// A single <c>scope</c> field naming <see cref="WellKnownScopes.OpenId"/>: what a test asks
    /// for when the behaviour under test needs a granted scope (an ID Token, a scope-requiring
    /// policy profile) but is not itself about which scope the caller named.
    /// </summary>
    public static OAuthFormEncodedFields OpenIdScope { get; } = new(
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        });
}
