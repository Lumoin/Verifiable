using System.Collections.Frozen;
using System.Globalization;
using System.Text;
using Verifiable.JCose;

namespace Verifiable.Core.StatusLists;

/// <summary>
/// Span-based reader for a JOSE Referenced Token's <c>status</c> claim — the mechanisms it names
/// and, when the Token Status List mechanism is among them, the <c>status_list</c> reference itself.
/// The JOSE twin of the CBOR/COSE Status-structure reader.
/// </summary>
/// <remarks>
/// <para>
/// Reads the UTF-8 JSON text of the <c>status</c> claim's object value with no serializer, through
/// the library's one reading of a JSON object's members, every name decoded once, so no spelling of a
/// name hides it. It reads over <see cref="JwkJsonReader"/> (the
/// JOSE-tier span primitives) in the same style as
/// <c>Verifiable.Core.Did.Methods.Peer.PeerDidServiceReader.TryRead</c> reading a peer DID service
/// block: this lives in <c>Verifiable.Core</c>, which both
/// <c>Verifiable.OAuth</c> and <c>Verifiable.Json</c> reference, so either tier can call it without a
/// second, re-derived parser.
/// </para>
/// <para>
/// "status: REQUIRED. The status (status) claim MUST specify a JSON Object that contains at least one
/// reference to a status mechanism."
/// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">Token Status List, Section 6.1</see>.
/// The object's top-level member names are the mechanism identifiers, so an object with no member is
/// not a status claim at all and is refused.
/// </para>
/// <para>
/// "status_list: REQUIRED when the status mechanism defined in this specification is used. It MUST
/// specify a JSON Object that contains a reference to a Status List Token. It MUST at least contain
/// the following claims: idx: REQUIRED. The idx (index) claim MUST specify a non-negative Integer
/// that represents the index to check for status information in the Status List for the current
/// Referenced Token. uri: REQUIRED. The uri (URI) claim MUST specify a String value that identifies
/// the Status List Token containing the status information for the Referenced Token. The value of uri
/// MUST be a URI conforming to [RFC3986]."
/// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2">Token Status List, Section 6.2</see>.
/// A <c>status_list</c> member that is present but does not meet those rules makes the whole claim
/// unreadable rather than degrading it to a claim naming an unmodelled mechanism.
/// </para>
/// </remarks>
public static class StatusClaimReader
{
    /// <summary>
    /// Reads a <c>status</c> claim's object value into its mechanism set and, when the
    /// <see cref="StatusMechanismNames.StatusList"/> mechanism is a top-level member, its decoded
    /// reference, through the library's one reading of a JSON object's members
    /// (<see cref="JwkJsonReader.ReadTopLevelMembers"/>): every member name and string value is read
    /// decoded once (RFC 8259 sections 7 and 8.3), so a mechanism, <c>status_list</c>, <c>uri</c> or
    /// <c>idx</c> name written with an escape is the name it decodes to.
    /// </summary>
    /// <param name="statusObjectUtf8Json">
    /// The UTF-8 JSON text of the <c>status</c> claim's value, braces included, as the claims set
    /// carrying it writes it. A value that is no JSON object, or an object carrying no member, is
    /// refused. A caller whose token carries no <c>status</c> member does not call this reader; it
    /// establishes that from the members of the claims set it read.
    /// </param>
    /// <param name="claim">On success, the claim as read; otherwise <see langword="null"/>.</param>
    /// <returns>
    /// <see langword="true"/> when the value is one JSON object carrying at least one top-level member
    /// (Section 6.1), repeating no member name at any depth and naming Unicode text throughout, and any
    /// <c>status_list</c> member is an object whose <c>uri</c> is a string conforming to RFC 3986 and whose
    /// <c>idx</c> is a non-negative integer (Section 6.2); <see langword="false"/> otherwise — never throws
    /// on this untrusted input.
    /// </returns>
    /// <remarks>
    /// Only top-level members are mechanisms: a <c>status_list</c> object nested inside another
    /// mechanism's value is that mechanism's own content and is neither named in
    /// <see cref="StatusClaim.Mechanisms"/> nor read as the reference. A repeated member name is
    /// refused outright: a duplicate lets a producer show one reader one mechanism and another reader a
    /// different one.
    /// </remarks>
    public static bool TryRead(ReadOnlySpan<byte> statusObjectUtf8Json, out StatusClaim? claim)
    {
        claim = null;

        if(JwkJsonReader.ReadTopLevelMembers(statusObjectUtf8Json) is not JsonTopLevelMembers { Members.Count: > 0 } members)
        {
            return false;
        }

        //The reader answers members only for an object repeating no name, so the decoded names go straight into the ordinal set
        //the claim stores.
        FrozenSet<string> mechanisms = members.Members.Select(static member => member.Name).ToFrozenSet(StringComparer.Ordinal);

        StatusListReference? statusList = null;
        if(members.Members.FirstOrDefault(static member => string.Equals(member.Name, StatusMechanismNames.StatusList, StringComparison.Ordinal)) is { } statusListMember)
        {
            if(statusListMember.Kind is not JsonTopLevelValueKind.Object
                || JwkJsonReader.ReadTopLevelMembers(Encoding.UTF8.GetBytes(statusListMember.Text)) is not JsonTopLevelMembers reference
                || reference.Find(StatusListMemberNames.Uri) is not JsonMemberString { Text: var uri }
                || !StatusListReference.IsConformingUri(uri)
                || reference.Find(StatusListMemberNames.Index) is not JsonMemberNumber { Spelling: var indexSpelling }
                || !int.TryParse(indexSpelling, NumberStyles.None, CultureInfo.InvariantCulture, out var index))
            {
                return false;
            }

            statusList = new StatusListReference(index, uri);
        }

        claim = new StatusClaim(statusList, mechanisms);

        return true;
    }
}
