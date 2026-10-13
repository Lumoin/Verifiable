using System.Diagnostics;
using Verifiable.Core.Outbound;

namespace Verifiable.OAuth.Oid4Vci.Wallet;

/// <summary>
/// The failure value every <see cref="Oid4VciWalletClient"/> request answers on input the Wallet
/// does not control: the endpoint answered a structured OID4VCI error response, a success status
/// carried a body or content type the section does not allow, the outbound-fetch policy refused the
/// endpoint before any dial, the endpoint answered with a redirect the Wallet did not follow, the
/// guarded fetch refused the response's size, or the transport failed. One type carries the failure
/// for every request kind, so no request answers a shape its siblings do not.
/// </summary>
[DebuggerDisplay("Oid4VciRequestFailure Kind={Kind} StatusCode={StatusCode} ErrorCode={ErrorCode}")]
public sealed record Oid4VciRequestFailure
{
    /// <summary>Which failure class this request hit.</summary>
    public required Oid4VciRequestFailureKind Kind { get; init; }

    /// <summary>The endpoint the failing request addressed.</summary>
    public required Uri Endpoint { get; init; }

    /// <summary>The guarded fetch's size evidence for a TooLarge outcome.</summary>
    public OutboundResponseTooLarge? TooLarge { get; init; }

    /// <summary>The transport exception type for an Unreachable outcome.</summary>
    public Type? FailureKind { get; init; }

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
    /// <see cref="Oid4VciRequestFailureKind.OutboundPolicyDenied"/>; the refusal's summary when
    /// <see cref="Kind"/> is <see cref="Oid4VciRequestFailureKind.RedirectRefused"/>.
    /// </summary>
    public string? ErrorDescription { get; init; }

    /// <summary>
    /// The typed refusal when <see cref="Kind"/> is <see cref="Oid4VciRequestFailureKind.RedirectRefused"/>:
    /// the endpoint, the 3xx status and the <c>Location</c> value it sent; otherwise
    /// <see langword="null"/>.
    /// </summary>
    public OAuthRedirectRefused? RedirectRefusal { get; init; }
}


/// <summary>
/// The ways an <see cref="Oid4VciWalletClient"/> request fails on input the Wallet does not
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
    /// The endpoint answered a success status whose body or content type breaks a rule the section
    /// names, or an error response whose <c>error</c> is empty or holds a char outside RFC 6749
    /// Section 5.2's set <c>%x20-21 / %x23-5B / %x5D-7E</c>;
    /// <see cref="Oid4VciRequestFailure.ErrorDescription"/> names which one.
    /// </summary>
    MalformedResponse,

    /// <summary>
    /// The outbound-fetch policy refused the endpoint, or refused a redirect hop, before any dial
    /// reached it.
    /// </summary>
    OutboundPolicyDenied,

    /// <summary>
    /// The endpoint answered a request carrying a credential — the pre-authorized code, the access
    /// token, the key proof — with a redirect, an HTTP status of the 3xx class; the Wallet did not
    /// follow it and sent nothing further (<see cref="OAuthRedirectRefused"/>, carried as
    /// <see cref="Oid4VciRequestFailure.RedirectRefusal"/>).
    /// </summary>
    RedirectRefused,

    /// <summary>The guarded fetch refused the response's declared or observed size.</summary>
    TooLarge,

    /// <summary>The transport failed for a reason unrelated to size.</summary>
    Unreachable
}
