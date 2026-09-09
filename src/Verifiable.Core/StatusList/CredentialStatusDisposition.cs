namespace Verifiable.Core.StatusList;

/// <summary>
/// What a presented credential's IETF Token Status List value means to a relying party
/// (<see href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-7.1">Token Status
/// List §7.1 "Status Types Values"</see>): the two named not-valid states, and the application-specific range
/// the specification leaves undefined. Derived from <see cref="CredentialStatusOutcome.Status"/>; never itself
/// the source of truth.
/// </summary>
public enum CredentialStatusDisposition
{
    /// <summary>
    /// Status <c>0x01</c> "INVALID": "the status of the Referenced Token is revoked, annulled, taken back,
    /// recalled or cancelled" (Token Status List §7.1).
    /// </summary>
    Revoked,

    /// <summary>
    /// Status <c>0x02</c> "SUSPENDED": "the status of the Referenced Token is temporarily invalid, hanging,
    /// debarred from privilege" (Token Status List §7.1).
    /// </summary>
    Suspended,

    /// <summary>
    /// Any other non-<see cref="StatusTypes.Valid"/> value — the application-specific range (<c>0x03</c>,
    /// <c>0x0C</c>-<c>0x0F</c>) or an unregistered value. §7.1 leaves the processing of these to the
    /// application; this disposition assigns none of them a meaning under which the credential is still valid.
    /// </summary>
    ApplicationSpecific
}
