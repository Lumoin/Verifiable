using System.Collections.Frozen;
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
    /// <returns>
    /// The claim as read (<see cref="StatusClaimRead"/>) when the value is one JSON object carrying at least one top-level member
    /// (Section 6.1), repeating no member name at any depth and naming Unicode text throughout, and any <c>status_list</c> member
    /// is an object whose <c>uri</c> is a string conforming to RFC 3986 and whose <c>idx</c> is a non-negative integer (Section
    /// 6.2) - an integer whatever its spelling, <c>3</c>, <c>3.0</c>, <c>3e0</c> and <c>-0</c> among them; the refusal of a
    /// value outside those rules (<see cref="StatusClaimRefused"/>); or, for a claim within them whose <c>idx</c> is a
    /// non-negative integer past the indices the library's status lists hold (<see cref="int.MaxValue"/>), the reference whose
    /// status the library cannot check (<see cref="StatusClaimIndexBeyondCapacity"/>), which is no malformed claim. Never throws
    /// on this untrusted input.
    /// </returns>
    /// <remarks>
    /// Only top-level members are mechanisms: a <c>status_list</c> object nested inside another
    /// mechanism's value is that mechanism's own content and is neither named in
    /// <see cref="StatusClaim.Mechanisms"/> nor read as the reference. A repeated member name is
    /// refused outright: a duplicate lets a producer show one reader one mechanism and another reader a
    /// different one.
    /// </remarks>
    public static StatusClaimReading Read(ReadOnlySpan<byte> statusObjectUtf8Json)
    {
        if(JwkJsonReader.ReadTopLevelMembers(statusObjectUtf8Json) is not JsonTopLevelMembers { Members.Count: > 0 } members)
        {
            return new StatusClaimRefused();
        }

        //The reader answers members only for an object repeating no name, so the decoded names go straight into the ordinal set
        //the claim stores.
        var mechanisms = members.Members.Select(static member => member.Name).ToFrozenSet(StringComparer.Ordinal);

        if(!mechanisms.Contains(StatusMechanismNames.StatusList))
        {
            return new StatusClaimRead(new StatusClaim(null, mechanisms));
        }

        var statusListMember = members.Members.Single(static member => WellKnownJwtClaimNames.IsStatusList(member.Name));
        if(statusListMember.Kind is not JsonTopLevelValueKind.Object
            || JwkJsonReader.ReadTopLevelMembers(Encoding.UTF8.GetBytes(statusListMember.Text)) is not JsonTopLevelMembers reference
            || reference.Find(StatusListMemberNames.Uri) is not JsonMemberString { Text: var uri }
            || !StatusListReference.IsConformingUri(uri)
            || reference.Find(StatusListMemberNames.Index) is not JsonMemberNumber { Spelling: var indexSpelling }
            || DecimalNumber.FromJsonNumber(Encoding.UTF8.GetBytes(indexSpelling)) is not { IsInteger: true } index
            || index.IsNegative)
        {
            return new StatusClaimRefused();
        }

        //Section 6.2 bounds the index from below alone; the library's status lists hold at most int.MaxValue + 1 entries, so an
        //index past that is a well-formed reference to an entry no list the library reads holds, whose status it cannot check.
        if(index.CompareTo(int.MaxValue) > 0 || index.ToClaimValue() is not long smallIndex)
        {
            return new StatusClaimIndexBeyondCapacity(uri, index);
        }

        return new StatusClaimRead(new StatusClaim(new StatusListReference((int)smallIndex, uri), mechanisms));
    }
}


/// <summary>What <see cref="StatusClaimReader.Read"/> answers for a <c>status</c> claim's value.</summary>
public abstract record StatusClaimReading;


/// <summary>The claim, read within Token Status List sections 6.1 and 6.2.</summary>
/// <param name="Claim">The claim.</param>
public sealed record StatusClaimRead(StatusClaim Claim) : StatusClaimReading;


/// <summary>
/// The value is outside Token Status List sections 6.1 and 6.2: no JSON object, an object naming no mechanism, repeating a member
/// name or naming no Unicode text, or a <c>status_list</c> that is no object of an RFC 3986 <c>uri</c> and a non-negative integer
/// <c>idx</c>.
/// </summary>
public sealed record StatusClaimRefused : StatusClaimReading;


/// <summary>
/// The value is within Token Status List sections 6.1 and 6.2, and its <c>status_list</c> names an index, a non-negative integer,
/// past the indices the library's status lists hold (<see cref="int.MaxValue"/>): a reference whose status the library cannot
/// check, never a malformed claim.
/// </summary>
/// <param name="ListLocation">The Status List Token's URI the reference names.</param>
/// <param name="Index">The index the reference names, as written.</param>
public sealed record StatusClaimIndexBeyondCapacity(string ListLocation, DecimalNumber Index) : StatusClaimReading;
