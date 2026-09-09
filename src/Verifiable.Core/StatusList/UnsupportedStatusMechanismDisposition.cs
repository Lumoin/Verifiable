namespace Verifiable.Core.StatusList;

/// <summary>
/// What a verifier does with a presented credential whose <c>status</c> claim names only status
/// mechanisms it cannot evaluate — a <see cref="StatusClaim"/> whose
/// <see cref="StatusClaim.Mechanisms"/> is non-empty while its <see cref="StatusClaim.StatusList"/>
/// is <see langword="null"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">
/// Token Status List, Section 8.3</see> closes its validation steps with: "If any of these checks
/// fails, no statement about the status of the Referenced Token can be made and the Referenced Token
/// SHOULD be rejected." A status the verifier cannot read is exactly that case — the issuer gated
/// the token's validity on a mechanism the verifier does not implement, so no statement is possible.
/// </para>
/// <para>
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18">SD-JWT VC</see>
/// makes the same call the policy's: "If status is present in the verified payload
/// of the SD-JWT, the status SHOULD be checked. Verifier policy decides whether to reject or accept
/// a presentation of a SD-JWT VC based on the status of the Verifiable Digital Credential."
/// </para>
/// <para>
/// Because both are SHOULD rather than MUST, the rejection is the default and the acceptance is an
/// explicit opt-out rather than the other way round: the least-friction configuration is the secure
/// one, and a relying party that has its own out-of-band way to evaluate the named mechanisms asks
/// for <see cref="Surface"/> deliberately.
/// </para>
/// </remarks>
public enum UnsupportedStatusMechanismDisposition
{
    /// <summary>
    /// Refuse the presentation: no statement about the token's status can be made, so the
    /// presentation fails closed as an undeterminable status. The default.
    /// </summary>
    Refuse = 0,

    /// <summary>
    /// Accept the presentation and surface the mechanism names the issuer stated, leaving their
    /// evaluation to the relying party, which reads them from the verified credential's own
    /// <see cref="StatusClaim.Mechanisms"/>. No status outcome is recorded, because none was read.
    /// </summary>
    Surface = 1
}
