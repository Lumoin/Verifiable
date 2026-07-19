using System.Diagnostics;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Resolves whether <paramref name="issuer"/> identifies an authorization server the client trusts and
/// has configured under a UNIQUE issuer identifier, per
/// <see href="https://www.rfc-editor.org/rfc/rfc9207#section-4">RFC 9207 §4</see>. The application owns
/// the authorization-server configuration store; this delegate is the library's seam into it. Returning
/// <see langword="true"/> asserts BOTH that the issuer is one the client trusts AND that it is the sole
/// authorization server the application configured under that identifier — the §4 "MUST NOT allow
/// multiple authorization servers to use the same issuer identifier" guarantee the application enforces
/// in how it answers this resolver. Mirrors <see cref="ClientRegistration"/>'s design: the library does
/// not supply a registration store.
/// </summary>
/// <param name="issuer">
/// The issuer identifier to resolve, compared by ordinal (RFC 8414 §3.3 / RFC 9207 §2.4) equality.
/// </param>
public delegate bool KnownAuthorizationServerIssuerResolver(string issuer);


/// <summary>
/// Client-side <see href="https://www.rfc-editor.org/rfc/rfc9207">RFC 9207</see> authorization-response
/// issuer validation over an application-owned authorization-server store, reached through a
/// <see cref="KnownAuthorizationServerIssuerResolver"/>.
/// </summary>
[DebuggerDisplay("AuthorizationServerIssuerValidation")]
public static class AuthorizationServerIssuerValidation
{
    /// <summary>
    /// The <see href="https://www.rfc-editor.org/rfc/rfc9207#section-2.4">RFC 9207 §2.4</see> mix-up
    /// defense: <see langword="true"/> only when <paramref name="responseIssuer"/> both identifies a
    /// known, uniquely-configured authorization server (per
    /// <paramref name="isKnownAuthorizationServerIssuer"/>) AND is identical, by ordinal string
    /// comparison, to <paramref name="expectedIssuer"/> — the authorization server the request was sent
    /// to. Shares the ordinal comparison rule with
    /// <see cref="AuthorizationServerMetadataValidation.IsIssuerMatch"/>. This composes with, rather than
    /// replaces, the per-flow callback issuer check already performed against a single flow's recorded
    /// issuer; it additionally requires the issuer to be a positively KNOWN, uniquely-claimed
    /// authorization server, closing the case where the application's own configuration is the source of
    /// a shared issuer identifier.
    /// </summary>
    /// <param name="responseIssuer">
    /// The <c>iss</c> an authorization response carried, decoded from its
    /// <c>application/x-www-form-urlencoded</c> wire form per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-B">RFC 6749 Appendix B</see>.
    /// <see langword="null"/> or whitespace-only — an effectively absent <c>iss</c> — is never valid and
    /// does not throw: this validates untrusted wire input and must reject malformed input rather than
    /// fault on it.
    /// </param>
    /// <param name="expectedIssuer">The issuer of the authorization server the request was sent under.</param>
    /// <param name="isKnownAuthorizationServerIssuer">
    /// The application's resolver over its own authorization-server store; see
    /// <see cref="KnownAuthorizationServerIssuerResolver"/>.
    /// </param>
    public static bool IsAuthorizationResponseIssuerValid(
        string? responseIssuer,
        Uri expectedIssuer,
        KnownAuthorizationServerIssuerResolver isKnownAuthorizationServerIssuer)
    {
        ArgumentNullException.ThrowIfNull(expectedIssuer);
        ArgumentNullException.ThrowIfNull(isKnownAuthorizationServerIssuer);

        return !string.IsNullOrWhiteSpace(responseIssuer)
            && isKnownAuthorizationServerIssuer(responseIssuer)
            && AuthorizationServerMetadataValidation.IsIssuerIdentifierMatch(responseIssuer, expectedIssuer);
    }
}
