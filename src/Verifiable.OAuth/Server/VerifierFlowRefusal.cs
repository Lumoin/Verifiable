using System;
using Verifiable.Core.StatusList;
using Verifiable.Server;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The cause a refused OID4VP or SIOPv2 §12 presentation is answered with. Selects the
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see> error code a
/// <c>direct_post</c> (or the SIOP response endpoint) answers with; OID4VP 1.0 §8.2 defines only the success
/// answer, so a refusal borrows the OAuth family's error vocabulary.
/// </summary>
public enum VerifierFlowRefusalKind
{
    /// <summary>
    /// The Authorization Response itself is not one a conformant Wallet would produce — an undecodable
    /// <c>response</c> JWE, an unparseable <c>vp_token</c> / SD-JWT / KB-JWT / mdoc / SD-CWT presentation, or a
    /// <c>vp_token</c> of the wrong shape. Answered as <c>invalid_request</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>: "The request is
    /// missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or
    /// is otherwise malformed."
    /// </summary>
    Malformed,

    /// <summary>
    /// A well-formed Authorization Response whose verification verdict is negative — a signature or holder-binding
    /// check failed, or the presented credential does not satisfy the Authorization Request's DCQL query (a wrong
    /// or absent credential type, a missing or over-disclosed claim, an unmet <c>trusted_authorities</c>
    /// constraint per OID4VP 1.0 §6.1.1). Answered as <c>invalid_request</c>.
    /// </summary>
    Unverifiable,

    /// <summary>
    /// The Verifier denies an otherwise well-formed and verifiable presentation on authorization grounds — a
    /// deployment's <see cref="CredentialStatusPolicy"/> refuses a determinable revoked or suspended status.
    /// Answered as <c>access_denied</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>: "The resource
    /// owner or authorization server denied the request."
    /// </summary>
    PolicyRefused,

    /// <summary>
    /// A presented credential's IETF Token Status List status could not be determined — the list's subject does
    /// not match the reference, the list has expired, or the index is out of range. An undeterminable status is
    /// not a pass, so it is answered as <c>invalid_request</c> like any other unverifiable presentation.
    /// </summary>
    StatusUndeterminable
}


/// <summary>
/// A client-facing refusal of an OID4VP or SIOPv2 §12 presentation: the <see cref="VerifierFlowRefusalKind"/>
/// that selects the RFC 6749 §4.1.2.1 error code and a wire-safe, generic <see cref="Description"/>. Carried on
/// <c>VerifierFlowFailedState.Refusal</c> so the <c>direct_post</c> endpoint answers HTTP 400 with the typed
/// error rather than 500; <see cref="Fail"/>'s log-only reason never reaches the wire.
/// </summary>
/// <remarks>
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-15.9">OID4VP 1.0 §15.9</see>:
/// "Error responses SHOULD avoid including sensitive or detailed contextual information that could be used to
/// infer the End-User's data." <see cref="Description"/> is therefore one fixed sentence per
/// <see cref="VerifierFlowRefusalKind"/> — no credential query id, no raw status value, no
/// revoked-vs-undeterminable distinction. That relying-party detail is typed separately (
/// <see cref="CredentialStatusRefusal"/>) and never rides this type.
/// </remarks>
public readonly record struct VerifierFlowRefusal
{
    /// <summary>The refusal class selecting the RFC 6749 §4.1.2.1 error code.</summary>
    public VerifierFlowRefusalKind Kind { get; }

    /// <summary>A wire-safe, non-revealing description carried in <c>error_description</c>.</summary>
    public string Description { get; }

    /// <summary>
    /// Creates a refusal, enforcing the RFC 6749 §4.1.2.1 <c>error_description</c> character rule by
    /// construction so no caller can compose a wire-unsafe description.
    /// </summary>
    /// <param name="kind">The refusal class selecting the RFC 6749 §4.1.2.1 error code.</param>
    /// <param name="description">A wire-safe, non-revealing description carried in <c>error_description</c>.</param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="description"/> is empty, all-whitespace, or contains a character outside
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>'s
    /// <c>%x20-21 / %x23-5B / %x5D-7E</c> set.
    /// </exception>
    public VerifierFlowRefusal(VerifierFlowRefusalKind kind, string description)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(description);
        EnsureWireSafeAscii(description);

        Kind = kind;
        Description = description;
    }

    /// <summary>
    /// The <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see> error code
    /// for <see cref="Kind"/>: <see cref="OAuthErrors.AccessDenied"/> for
    /// <see cref="VerifierFlowRefusalKind.PolicyRefused"/>, otherwise <see cref="OAuthErrors.InvalidRequest"/>.
    /// </summary>
    public string ErrorCode => Kind switch
    {
        VerifierFlowRefusalKind.PolicyRefused => OAuthErrors.AccessDenied,
        _ => OAuthErrors.InvalidRequest
    };

    /// <summary>
    /// Creates the refusal for <paramref name="kind"/> using its one fixed, generic wire description — the
    /// single home for the canonical per-kind text so every producer answers with the same wording.
    /// </summary>
    /// <param name="kind">The refusal class.</param>
    /// <returns>The refusal carrying <paramref name="kind"/>'s canonical <see cref="Description"/>.</returns>
    public static VerifierFlowRefusal For(VerifierFlowRefusalKind kind) =>
        new(kind, CanonicalDescription(kind));

    /// <summary>The one fixed, generic wire sentence for <paramref name="kind"/>. The single home <see cref="For"/> reads from.</summary>
    private static string CanonicalDescription(VerifierFlowRefusalKind kind) => kind switch
    {
        VerifierFlowRefusalKind.Malformed =>
            "The Authorization Response could not be parsed.",
        VerifierFlowRefusalKind.Unverifiable =>
            "The presentation could not be verified.",
        VerifierFlowRefusalKind.PolicyRefused =>
            "The presentation was refused by relying-party policy.",
        VerifierFlowRefusalKind.StatusUndeterminable =>
            "The presentation's credential status could not be determined.",
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown refusal kind.")
    };

    /// <summary>
    /// Enforces RFC 6749 §4.1.2.1's <c>error_description</c> character rule: "MUST NOT include characters
    /// outside the set %x20-21 / %x23-5B / %x5D-7E" (the printable US-ASCII range excluding the double-quote
    /// and backslash characters). Delegates to the single shared check
    /// <see cref="ErrorDescriptionCharset.IsConformant"/> already implements for the same RFC 6749 §4.1.2.1 /
    /// §5.2 rule OID4VCI 1.0 §8.3.1.2 and §11.1 restate verbatim, rather than re-testing the ranges here.
    /// </summary>
    private static void EnsureWireSafeAscii(string description)
    {
        if(!ErrorDescriptionCharset.IsConformant(description))
        {
            throw new ArgumentException(
                "The description contains a character outside RFC 6749 §4.1.2.1's error_description " +
                "character set (%x20-21 / %x23-5B / %x5D-7E).",
                nameof(description));
        }
    }
}
