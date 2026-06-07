using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Attaches the <see cref="OAuthDynamicRegistrationClient"/> sub-client to
/// <see cref="OAuthClient"/> via a Pattern 5 extension block.
/// </summary>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "C# extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class OAuthDynamicRegistrationClientExtensions
{
    extension(OAuthClient client)
    {
        /// <summary>
        /// The dynamic-registration sub-client. Each access materialises a
        /// fresh <see cref="OAuthDynamicRegistrationClient"/> struct over
        /// the client's infrastructure.
        /// </summary>
        public OAuthDynamicRegistrationClient DynamicRegistration => new(client.Infrastructure);
    }
}
