using System.Diagnostics.CodeAnalysis;
using Verifiable.OAuth.Introspection;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Attaches the <see cref="TokenIntrospectionClient"/> sub-client to <see cref="OAuthClient"/> via a Pattern 5
/// extension block, so a protected resource reaches the RFC 7662 introspection operation as
/// <c>client.Introspection.IntrospectAsync(...)</c>.
/// </summary>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "C# extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class TokenIntrospectionClientExtensions
{
    extension(OAuthClient client)
    {
        /// <summary>
        /// The token introspection sub-client. Each access materialises a fresh <see cref="TokenIntrospectionClient"/>
        /// struct over the client's infrastructure; the struct is cheap (one reference field) and carries no per-call
        /// state of its own.
        /// </summary>
        public TokenIntrospectionClient Introspection => new(client.Infrastructure);
    }
}
