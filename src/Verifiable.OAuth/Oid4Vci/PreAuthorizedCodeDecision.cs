using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// The reason an application refused a Pre-Authorized Code grant at the
/// <see cref="Server.ValidatePreAuthorizedCodeDelegate"/> seam. The library maps each
/// reason to the OID4VCI 1.0 §6.3 Token Error Response code, since only the application
/// — which owns the pre-authorized code store and knows whether a Transaction Code was
/// expected — can distinguish these cases.
/// </summary>
public enum PreAuthorizedCodeDenialReason
{
    /// <summary>
    /// The Wallet presented the wrong Pre-Authorized Code, or the code has expired.
    /// Mapped to <see cref="OAuthErrors.InvalidGrant"/> per
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">OID4VCI 1.0 §6.3</see>.
    /// </summary>
    InvalidCode,

    /// <summary>
    /// The Authorization Server expects a Transaction Code (the Credential Offer carried a
    /// <c>tx_code</c> object) but the Wallet provided none. Mapped to
    /// <see cref="OAuthErrors.InvalidRequest"/> per OID4VCI 1.0 §6.3.
    /// </summary>
    TransactionCodeRequired,

    /// <summary>
    /// The Authorization Server does not expect a Transaction Code but the Wallet provided
    /// one. Mapped to <see cref="OAuthErrors.InvalidRequest"/> per OID4VCI 1.0 §6.3.
    /// </summary>
    TransactionCodeUnexpected,

    /// <summary>
    /// The Authorization Server expects a Transaction Code but the Wallet provided the
    /// wrong one. Mapped to <see cref="OAuthErrors.InvalidGrant"/> per OID4VCI 1.0 §6.3.
    /// </summary>
    TransactionCodeInvalid,

    /// <summary>
    /// The Wallet sent a Pre-Authorized Code with no <c>client_id</c> but the Authorization
    /// Server does not support anonymous access. Mapped to
    /// <see cref="OAuthErrors.InvalidClient"/> per OID4VCI 1.0 §6.3.
    /// </summary>
    ClientAuthenticationRequired
}


/// <summary>
/// An application's verdict on a Pre-Authorized Code grant, returned from the
/// <see cref="Server.ValidatePreAuthorizedCodeDelegate"/> seam. A grant carries the
/// <see cref="Subject"/> the issued Credential is about and the optional granted
/// <see cref="Scope"/>; a denial carries the <see cref="DenialReason"/> the library maps
/// to an OID4VCI 1.0 §6.3 Token Error Response code.
/// </summary>
/// <remarks>
/// The library owns only the wire shape — validating the <c>pre-authorized_code</c> and
/// <c>tx_code</c>, the access-token minting, and the §6.2 <c>Cache-Control: no-store</c>.
/// The application owns the code store created when the Credential Offer was minted, so it
/// is the only party that can tell a wrong code from a wrong Transaction Code, or know
/// whether a Transaction Code was expected at all.
/// </remarks>
[DebuggerDisplay("PreAuthorizedCodeDecision IsGranted={IsGranted} DenialReason={DenialReason}")]
public sealed record PreAuthorizedCodeDecision
{
    /// <summary>
    /// Whether the grant is authorized to proceed to access-token issuance.
    /// <see langword="false"/> fails the token request with the error mapped from
    /// <see cref="DenialReason"/>.
    /// </summary>
    public required bool IsGranted { get; init; }

    /// <summary>
    /// The subject identifier the issued Credential is about. Becomes the access token's
    /// <c>sub</c> claim. Required on a grant; ignored on a denial.
    /// </summary>
    public string? Subject { get; init; }

    /// <summary>
    /// The granted scope string, or <see langword="null"/> when issuance is requested
    /// through <c>authorization_details</c> rather than <c>scope</c>. Emitted as the token
    /// response's <c>scope</c> field when present.
    /// </summary>
    public string? Scope { get; init; }

    /// <summary>
    /// The reason a non-granted request was refused. Ignored when <see cref="IsGranted"/>
    /// is <see langword="true"/>; a denial with no reason set is treated as
    /// <see cref="PreAuthorizedCodeDenialReason.InvalidCode"/>.
    /// </summary>
    public PreAuthorizedCodeDenialReason? DenialReason { get; init; }

    /// <summary>
    /// An optional human-readable description carried into the error response's
    /// <c>error_description</c>. <see langword="null"/> falls back to a reason-specific
    /// default.
    /// </summary>
    public string? DenialDescription { get; init; }


    /// <summary>
    /// A grant verdict for the given <paramref name="subject"/> with the optional granted
    /// <paramref name="scope"/>.
    /// </summary>
    /// <param name="subject">The subject identifier the issued Credential is about.</param>
    /// <param name="scope">The granted scope string, or <see langword="null"/>.</param>
    /// <returns>A granted <see cref="PreAuthorizedCodeDecision"/>.</returns>
    public static PreAuthorizedCodeDecision Grant(string subject, string? scope = null)
    {
        return new PreAuthorizedCodeDecision
        {
            IsGranted = true,
            Subject = subject,
            Scope = scope
        };
    }


    /// <summary>
    /// A deny verdict with the given <paramref name="reason"/> and optional
    /// <paramref name="description"/>.
    /// </summary>
    /// <param name="reason">The reason the grant was refused.</param>
    /// <param name="description">An optional human-readable description.</param>
    /// <returns>A non-granted <see cref="PreAuthorizedCodeDecision"/>.</returns>
    public static PreAuthorizedCodeDecision Deny(
        PreAuthorizedCodeDenialReason reason, string? description = null)
    {
        return new PreAuthorizedCodeDecision
        {
            IsGranted = false,
            DenialReason = reason,
            DenialDescription = description
        };
    }
}
