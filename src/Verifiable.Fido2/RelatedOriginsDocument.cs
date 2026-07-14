using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// The JSON document a relying party hosts at the <c>webauthn</c> well-known URL so a WebAuthn client can
/// enable a credential to be created and used across a limited set of related origins, per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-related-origins">W3C Web Authentication Level 3,
/// section 5.11: Using Web Authentication across related origins</see>.
/// </summary>
/// <remarks>
/// <para>
/// This type, together with <see cref="RelatedOrigins"/> and <see cref="WellKnownWebAuthnValues"/>, covers
/// only the relying-party-hostable half of section 5.11: choosing a common RP ID, and the shape/validity of
/// the document a relying party publishes. The client-run
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-validating-relation-origin">related origins validation
/// procedure (section 5.11.1)</see> — fetching this document without credentials or a referrer, walking
/// registrable origin labels, enforcing the client's minimum-five-labels support floor, and comparing
/// against the caller's origin — executes inside a WebAuthn client and has no server-side surface; this
/// library implements none of it.
/// </para>
/// </remarks>
[DebuggerDisplay("RelatedOriginsDocument(Origins={Origins.Count})")]
public sealed record RelatedOriginsDocument
{
    /// <summary>
    /// The <c>origins</c> member: one or more web origins related to the RP ID this document is hosted for.
    /// </summary>
    /// <remarks>
    /// Section 5.11: "The top-level JSON object MUST contain a key named <c>origins</c> whose value MUST be
    /// an array of one or more strings containing web origins."
    /// </remarks>
    public required IReadOnlyList<string> Origins { get; init; }
}


/// <summary>
/// Validation helpers for the relying-party-hostable half of
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-related-origins">W3C Web Authentication Level 3,
/// section 5.11</see>: whether a string is a structurally valid web origin suitable for a
/// <see cref="RelatedOriginsDocument.Origins"/> entry, and whether a set of RP IDs configured across
/// ceremonies satisfies section 5.11's common-RP-ID requirement.
/// </summary>
public static class RelatedOrigins
{
    /// <summary>
    /// Whether <paramref name="candidate"/> is a structurally valid HTTPS web origin: an absolute URI whose
    /// scheme is exactly <c>https</c>, whose host is non-empty, and which carries nothing beyond the origin
    /// triple (scheme, host, port) — no path beyond the implicit root <c>/</c>, no query, no fragment, and
    /// no userinfo.
    /// </summary>
    /// <param name="candidate">The candidate origin string, e.g. one of section 5.11's worked-example
    /// entries: <c>"https://example.co.uk"</c>.</param>
    /// <returns><see langword="true"/> if <paramref name="candidate"/> is a structurally valid HTTPS origin;
    /// otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="candidate"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// <para>
    /// Checks <see cref="Uri.Scheme"/> against an explicit <c>https:</c> allowlist BEFORE trusting anything
    /// else <see cref="Uri.TryCreate(string, UriKind, out Uri)"/> reports: on some platforms a bare,
    /// scheme-less string such as <c>/relative</c> parses as an absolute <c>file:</c> URI rather than failing
    /// to parse, so accepting any successfully-parsed absolute <see cref="Uri"/> without also checking its
    /// scheme would let such a string masquerade as a valid web origin. The explicit scheme check rejects it
    /// regardless of that platform difference.
    /// </para>
    /// <para>
    /// This method performs no normalization: it does not lowercase the host, does not collapse an explicit
    /// default port (<c>https://example.com:443</c>) to its portless form, and returns the candidate's
    /// verdict only — never a canonicalized string. <see cref="Uri.Host"/> happens to report a DNS host in
    /// lowercase regardless of the candidate's original casing, so an upper-case host such as
    /// <c>https://EXAMPLE.COM</c> is still structurally valid; callers that need two origin strings to
    /// compare equal (for example, a relying party matching a fetched document's entries against a
    /// configured allowlist) are responsible for whatever normalization or exact-match policy they need,
    /// exactly as <see cref="Fido2AssertionChecks.CheckAssertionOrigin"/> already treats origin strings as
    /// opaque, exact-match values rather than normalizing them itself.
    /// </para>
    /// </remarks>
    public static bool IsValidOrigin(string candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);

        if(!Uri.TryCreate(candidate, UriKind.Absolute, out Uri? uri))
        {
            return false;
        }

        if(!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
        {
            return false;
        }

        return uri.Host.Length > 0
            && uri.UserInfo.Length == 0
            && string.Equals(uri.AbsolutePath, "/", StringComparison.Ordinal)
            && uri.Query.Length == 0
            && uri.Fragment.Length == 0;
    }


    /// <summary>
    /// Whether <paramref name="rpIds"/> names exactly one distinct RP ID (ordinal comparison) — the
    /// testable half of section 5.11's "Such Relying Parties MUST choose a common RP ID to use across all
    /// ceremonies from related origins."
    /// </summary>
    /// <param name="rpIds">The RP IDs configured across the ceremonies a relying party wants to check for a
    /// common RP ID.</param>
    /// <returns><see langword="true"/> if <paramref name="rpIds"/> is non-empty and every entry is ordinally
    /// equal to every other entry; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="rpIds"/> is <see langword="null"/>.</exception>
    public static bool HasSingleCommonRpId(IEnumerable<string> rpIds)
    {
        ArgumentNullException.ThrowIfNull(rpIds);

        HashSet<string> distinctRpIds = new(StringComparer.Ordinal);
        foreach(string rpId in rpIds)
        {
            distinctRpIds.Add(rpId);
            if(distinctRpIds.Count > 1)
            {
                return false;
            }
        }

        return distinctRpIds.Count == 1;
    }
}
