using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Exact-match comparison of a requested <c>redirect_uri</c> against a client's registered set,
/// per <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1">RFC 9700 §2.1</see> and
/// draft-ietf-oauth-client-id-metadata-document-02 §4.2: "the authorization server MUST ensure
/// that the redirect URL in an authorization request is an exact match, using simple string
/// comparison, of a registered redirect URL."
/// </summary>
/// <remarks>
/// <see cref="Uri.Equals(object?)"/> (and the <c>ImmutableHashSet&lt;Uri&gt;.Contains</c> lookup a
/// <c>Uri</c>-keyed set performs) is insufficient here: <see cref="Uri"/> normalizes a default port
/// out of its equality and identity computation (<c>https://app.example/cb</c> and
/// <c>https://app.example:443/cb</c> compare equal) and case-folds percent-encoded octets during
/// parsing, so two redirect URIs that differ only in port elision or percent-encoding case collapse
/// to the "same" <see cref="Uri"/> even though they are different octet sequences on the wire. RFC
/// 3986 §6.2.1 simple string comparison — and this specification's exact-match requirement — treats
/// them as distinct; an attacker registering (or a client presenting) the normalized-equivalent form
/// must not bypass the registered-redirect-URI allowlist. Comparison is therefore on
/// <see cref="Uri.OriginalString"/>, ordinally, never through <see cref="Uri"/> equality.
/// </remarks>
[DebuggerDisplay("RedirectUriMatching")]
public static class RedirectUriMatching
{
    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="requested"/>'s original string is an
    /// ordinal exact match of at least one entry in <paramref name="registered"/>'s original
    /// strings.
    /// </summary>
    /// <param name="registered">The client's registered redirect URIs.</param>
    /// <param name="requested">The redirect URI presented on the request.</param>
    public static bool IsRegisteredExact(IReadOnlyCollection<Uri> registered, Uri requested)
    {
        ArgumentNullException.ThrowIfNull(registered);
        ArgumentNullException.ThrowIfNull(requested);

        foreach(Uri candidate in registered)
        {
            if(string.Equals(candidate.OriginalString, requested.OriginalString, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
