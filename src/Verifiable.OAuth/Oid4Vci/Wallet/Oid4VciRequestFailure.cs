using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vci.Wallet;

/// <summary>
/// The failure value every <see cref="Oid4VciWalletClient"/> request answers on input the Wallet
/// does not control: the endpoint answered a structured OID4VCI error response, a success status
/// carried a body, content type, or size the section does not allow, or the outbound-fetch policy
/// refused the endpoint before any dial. One type carries the failure for every request kind, so
/// no request answers a shape its siblings do not.
/// </summary>
[DebuggerDisplay("Oid4VciRequestFailure Kind={Kind} StatusCode={StatusCode} ErrorCode={ErrorCode}")]
public sealed record Oid4VciRequestFailure
{
    /// <summary>Which of the three failure classes this request hit.</summary>
    public required Oid4VciRequestFailureKind Kind { get; init; }

    /// <summary>The endpoint the failing request addressed.</summary>
    public required Uri Endpoint { get; init; }

    /// <summary>
    /// The HTTP status code the endpoint answered with, or <see langword="null"/> when
    /// <see cref="Kind"/> is <see cref="Oid4VciRequestFailureKind.OutboundPolicyDenied"/> and no
    /// response was received.
    /// </summary>
    public required int? StatusCode { get; init; }

    /// <summary>
    /// The wire <c>error</c> code (for example <c>invalid_grant</c> or <c>invalid_proof</c>) when
    /// <see cref="Kind"/> is <see cref="Oid4VciRequestFailureKind.ErrorResponse"/> and the body
    /// carried one; otherwise <see langword="null"/>.
    /// </summary>
    public string? ErrorCode { get; init; }

    /// <summary>
    /// The wire <c>error_description</c> when <see cref="Kind"/> is
    /// <see cref="Oid4VciRequestFailureKind.ErrorResponse"/>; the violated rule, in the library's
    /// own words, when <see cref="Kind"/> is <see cref="Oid4VciRequestFailureKind.MalformedResponse"/>;
    /// the outbound-fetch deny reason when <see cref="Kind"/> is
    /// <see cref="Oid4VciRequestFailureKind.OutboundPolicyDenied"/>.
    /// </summary>
    public string? ErrorDescription { get; init; }
}


/// <summary>
/// The three ways an <see cref="Oid4VciWalletClient"/> request fails on input the Wallet does not
/// control.
/// </summary>
public enum Oid4VciRequestFailureKind
{
    /// <summary>
    /// The endpoint answered a status the request's own section does not name as success — the
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.3">§6.3</see>
    /// Token Error Response, the
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3.1">§8.3.1</see>
    /// Credential Error Response, the
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-9.3">§9.3</see>
    /// Deferred Credential Error Response, or the
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-11.3">§11.3</see>
    /// Notification Error Response shape when the body carried one. <see cref="Oid4VciRequestFailure.ErrorCode"/>
    /// and <see cref="Oid4VciRequestFailure.ErrorDescription"/> are <see langword="null"/> when the
    /// section defines no error body for the request — the §4.1.3 offer GET is one such case — so
    /// the status alone carries the refusal.
    /// </summary>
    ErrorResponse,

    /// <summary>
    /// The endpoint answered a success status, but the body, content type, or size breaks a rule
    /// the section names; <see cref="Oid4VciRequestFailure.ErrorDescription"/> names which one.
    /// </summary>
    MalformedResponse,

    /// <summary>
    /// The outbound-fetch policy refused the endpoint, or refused a redirect hop, before any dial
    /// reached it.
    /// </summary>
    OutboundPolicyDenied
}
