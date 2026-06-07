using System.Diagnostics.CodeAnalysis;
using Verifiable.OAuth.AuthCode;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Attaches the <see cref="AuthCodeClient"/> sub-client to
/// <see cref="OAuthClient"/> via a Pattern 5 extension block. Adding a new
/// protocol surface is a new extension file, never a code change on
/// <see cref="OAuthClient"/> itself.
/// </summary>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "C# extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class AuthCodeClientExtensions
{
    extension(OAuthClient client)
    {
        /// <summary>
        /// The Authorization Code sub-client. Each access materialises a
        /// fresh <see cref="AuthCodeClient"/> struct over the client's
        /// infrastructure; the struct is cheap (one reference field) and
        /// carries no per-call state of its own.
        /// </summary>
        public AuthCodeClient AuthCode => new(client.Infrastructure);
    }
}
