using System.Diagnostics.CodeAnalysis;
using Verifiable.OAuth.IdJag;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Attaches the <see cref="IdJagClient"/> sub-client to <see cref="OAuthClient"/> via a Pattern 5
/// extension block. Adding a new protocol surface is a new extension file, never a code change on
/// <see cref="OAuthClient"/> itself.
/// </summary>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "C# extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class IdJagClientExtensions
{
    extension(OAuthClient client)
    {
        /// <summary>
        /// The Identity Assertion JWT Authorization Grant (ID-JAG) sub-client. Each access materialises a
        /// fresh <see cref="IdJagClient"/> struct over the client's infrastructure; the struct is cheap
        /// (one reference field) and carries no per-call state of its own.
        /// </summary>
        public IdJagClient IdJag => new(client.Infrastructure);
    }
}
