using Verifiable.JCose;

namespace Verifiable.Core.StatusList;

/// <summary>
/// The status-mechanism identifiers that can appear as members of a Referenced Token's
/// <c>status</c> claim — the JSON member names of the JOSE object per
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">
/// Token Status List, Section 6.1</see> and the CBOR text-string map keys of the COSE Status
/// structure per
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
/// Token Status List, Section 6.3</see>: "Each data item in the Status CBOR structure comprises a
/// key-value pair, where the key MUST be a CBOR text string (major type 3) specifying the
/// identifier of the status mechanism and the corresponding value defines its contents."
/// </summary>
/// <remarks>
/// The names are format-agnostic: the same identifier keys the JSON object and the CBOR map, so
/// every reader and writer of a <see cref="StatusClaim"/> — the JOSE span reader, the
/// System.Text.Json converter, and the CBOR leaf's Status-structure reader and writer — names a
/// mechanism from here rather than repeating its literal.
/// </remarks>
public static class StatusMechanismNames
{
    /// <summary>
    /// The <c>status_list</c> mechanism. Per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2">
    /// Token Status List, Section 6.2</see>: "status_list: REQUIRED when the status mechanism
    /// defined in this specification is used. It MUST specify a JSON Object that contains a
    /// reference to a Status List Token." Its value decodes to a <see cref="StatusListReference"/>.
    /// </summary>
    /// <remarks>
    /// A property rather than a <see langword="const"/> because the single home of the
    /// <c>status_list</c> literal is <see cref="WellKnownJwtClaimNames.StatusListUtf8"/> in the
    /// JOSE tier, whose interned string <see cref="WellKnownJwtClaimNames.StatusList"/> is a
    /// <see langword="static"/> <see langword="readonly"/> field: a compile-time constant cannot
    /// alias one. Readers therefore compare against this ordinally
    /// (<see cref="System.StringComparison.Ordinal"/>) instead of matching it as a constant
    /// pattern, and the literal itself exists exactly once in the tree.
    /// </remarks>
    public static string StatusList => WellKnownJwtClaimNames.StatusList;

    /// <summary>
    /// The <c>identifier_list</c> mechanism — the Attestation Revocation List mechanism named by
    /// the draft EU implementing act amending the EAA implementing regulations: "When implementing
    /// the identifier list mechanism, the status element shall contain the identifier_list element
    /// as set out in EAA-6.2.10.1-11." The mechanism's value shape is not modelled by this library:
    /// a reader records that the mechanism is present and skips its value; a structured view waits
    /// for the second edition of ISO/IEC 18013-5's own published text (under ballot as a DIS;
    /// expected publication 2026-11-30).
    /// </summary>
    /// <remarks>
    /// This identifier has no JOSE-tier claim-name registration to alias, so it is a
    /// <see langword="const"/> with its own single home here.
    /// </remarks>
    public const string IdentifierList = "identifier_list";
}
