using System;
using System.Collections.Frozen;
using System.Collections.Generic;
using Verifiable.JCose;

namespace Verifiable.Core.StatusList;

/// <summary>
/// Span-based reader for a JOSE Referenced Token's <c>status</c> claim — the mechanisms it names
/// and, when the Token Status List mechanism is among them, the <c>status_list</c> reference itself.
/// The JOSE twin of the CBOR/COSE Status-structure reader.
/// </summary>
/// <remarks>
/// <para>
/// Operates directly on the UTF-8 bytes of the already-sliced <c>status</c> claim object with no
/// serializer and no re-encode of the payload: what it allocates is the claim it returns — the
/// mechanism-name set, the <c>uri</c> string, and the carrier itself — and nothing per byte scanned.
/// It reads over <see cref="JwkJsonReader"/> (the
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
    /// Reads an already-sliced <c>status</c> claim object into its mechanism set and, when the
    /// <see cref="StatusMechanismNames.StatusList"/> mechanism is a top-level member, its decoded
    /// reference.
    /// </summary>
    /// <param name="statusObjectUtf8Json">
    /// The UTF-8 JSON bytes between the braces of the <c>status</c> claim's object value. An empty
    /// span carries no member and is refused — which is the answer a caller wants for a claim that IS
    /// present but whose value is <c>{}</c> or is not an object at all, both of which slice to
    /// nothing. A caller whose token carries no <c>status</c> member does not call this reader; it
    /// establishes that by probing the member's presence, never by the emptiness of this span.
    /// </param>
    /// <param name="claim">On success, the claim as read; otherwise <see langword="null"/>.</param>
    /// <returns>
    /// <see langword="true"/> when the object carries at least one top-level member (Section 6.1),
    /// no top-level member name repeats, and any <c>status_list</c> member conforms to Section 6.2;
    /// <see langword="false"/> otherwise — never throws on this untrusted input.
    /// </returns>
    /// <remarks>
    /// Only top-level members are mechanisms: a <c>status_list</c> object nested inside another
    /// mechanism's value is that mechanism's own content and is neither named in
    /// <see cref="StatusClaim.Mechanisms"/> nor read as the reference. A repeated top-level member
    /// name is refused outright, the same posture <see cref="JwkJsonReader.HasDuplicateTopLevelKeys"/>
    /// exists for elsewhere: a duplicate lets a producer show one reader one mechanism and another
    /// reader a different one.
    /// </remarks>
    public static bool TryRead(ReadOnlySpan<byte> statusObjectUtf8Json, out StatusClaim? claim)
    {
        claim = null;

        if(JwkJsonReader.HasDuplicateTopLevelKeys(statusObjectUtf8Json))
        {
            return false;
        }

        List<string> memberNames = JwkJsonReader.GetTopLevelKeyNames(statusObjectUtf8Json);
        if(memberNames.Count == 0)
        {
            return false;
        }

        //The duplicate scan above already established that the names are distinct, so the member
        //names go straight into the ordinal set the claim stores — there is no intermediate
        //deduplicating set between the scan and the carrier.
        FrozenSet<string> mechanisms = memberNames.ToFrozenSet(StringComparer.Ordinal);

        StatusListReference? statusList = null;
        if(mechanisms.Contains(StatusMechanismNames.StatusList))
        {
            ReadOnlySpan<byte> statusListObject = JwkJsonReader.ExtractObjectContent(
                statusObjectUtf8Json, WellKnownJwtClaimNames.StatusListUtf8);
            if(statusListObject.IsEmpty)
            {
                return false;
            }

            string? uri = JwkJsonReader.ExtractStringValue(statusListObject, StatusListMemberNames.UriUtf8);
            if(uri is null || !StatusListReference.IsConformingUri(uri))
            {
                return false;
            }

            if(!JwkJsonReader.TryExtractLongValue(statusListObject, StatusListMemberNames.IndexUtf8, out long index)
                || index < 0
                || index > int.MaxValue)
            {
                return false;
            }

            statusList = new StatusListReference((int)index, uri);
        }

        claim = new StatusClaim(statusList, mechanisms);

        return true;
    }
}
