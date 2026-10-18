using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The claim set of a DPoP proof JWS per
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 §4.2</see>.
/// </summary>
/// <remarks>
/// All required claims are populated by the construction helper.
/// <see cref="Nonce"/> and <see cref="Ath"/> are populated conditionally —
/// <see cref="Nonce"/> when a server nonce is in flight, <see cref="Ath"/>
/// only on resource-server calls where an access token is being presented.
/// </remarks>
[DebuggerDisplay("DpopProofClaims htm={Htm,nq} htu={Htu,nq} jti={Jti,nq}")]
public sealed record DpopProofClaims
{
    /// <summary>The HTTP method of the request the proof authorizes, uppercase.</summary>
    public required string Htm { get; init; }

    /// <summary>
    /// The HTTP URI the proof authorizes — origin + path, no query and no
    /// fragment per RFC 9449 §4.2. The receiver computes the same
    /// normalization on its inbound URI and compares for equality.
    /// </summary>
    public required string Htu { get; init; }

    /// <summary>
    /// The proof's issuance time, the NumericDate as written (RFC 9449 section 4.2, RFC 7519 section 2): a received proof's
    /// <c>iat</c> keeps every digit, so the section 4.3 window judges it against each bound exactly, and a constructed proof
    /// writes the date it is given.
    /// </summary>
    public required NumericDate Iat { get; init; }

    /// <summary>
    /// A unique identifier for this proof, used by the receiver's replay
    /// cache. Per RFC 9449 §4.2 the value SHOULD be a high-entropy
    /// identifier (UUID, base64-encoded CSPRNG bytes).
    /// </summary>
    public required string Jti { get; init; }

    /// <summary>
    /// The server-issued nonce being echoed in this proof, or
    /// <see langword="null"/> if no nonce is in flight.
    /// </summary>
    public string? Nonce { get; init; }

    /// <summary>
    /// Base64url-encoded SHA-256 of the access token being presented, per
    /// RFC 9449 §4.3. Set on resource-server calls; <see langword="null"/>
    /// for token-endpoint proofs (where the access token is being requested,
    /// not presented).
    /// </summary>
    public string? Ath { get; init; }


    /// <summary>
    /// Reads the decoded claims set of a DPoP proof (RFC 9449 section 4.2), once, through the library's one reading of a JSON
    /// object's members (<see cref="JwkJsonReader.ReadTopLevelMembers"/>): <c>jti</c>, <c>htm</c> and <c>htu</c>, REQUIRED
    /// strings; <c>iat</c>, a REQUIRED NumericDate read as written (<see cref="JsonMemberNumber.ToNumericDate"/>, RFC 7519
    /// section 2); and <c>nonce</c> and <c>ath</c>, strings where carried. A claims set the reader refuses, a required claim
    /// absent, a claim of another kind and an <c>iat</c> naming no instant a clock represents are refused, each a typed reason
    /// (<see cref="DpopProofPartReading{TPart}"/>), in the order <c>jti</c>, <c>htm</c>, <c>htu</c>, <c>iat</c>, <c>nonce</c>,
    /// <c>ath</c>; the claims are judged by <see cref="DpopProofValidator"/>, never here. Never throws.
    /// </summary>
    /// <param name="json">The claims set's UTF-8 JSON bytes, the payload segment base64url-decoded.</param>
    /// <returns>The claims, or their refusal.</returns>
    public static DpopProofPartReading<DpopProofClaims> Read(ReadOnlySpan<byte> json)
    {
        var reading = JwkJsonReader.ReadTopLevelMembers(json);

        if(reading is not JsonTopLevelMembers members)
        {
            return new DpopProofPartRefused<DpopProofClaims>(new JwsPartDocumentRefusal(JwsPart.Payload, reading));
        }

        var jti = members.Find(WellKnownJwtClaimNames.Jti);

        if(jti is not JsonMemberString jtiText)
        {
            return StringMemberRefused(DpopProofMember.Jti, WellKnownJwtClaimNames.Jti, jti);
        }

        var htm = members.Find(WellKnownJwtClaimNames.Htm);

        if(htm is not JsonMemberString htmText)
        {
            return StringMemberRefused(DpopProofMember.Htm, WellKnownJwtClaimNames.Htm, htm);
        }

        var htu = members.Find(WellKnownJwtClaimNames.Htu);

        if(htu is not JsonMemberString htuText)
        {
            return StringMemberRefused(DpopProofMember.Htu, WellKnownJwtClaimNames.Htu, htu);
        }

        var iat = members.Find(WellKnownJwtClaimNames.Iat);

        if(iat is not JsonMemberNumber iatNumber || iatNumber.ToNumericDate() is not NumericDate issuedAt)
        {
            return new DpopProofPartRefused<DpopProofClaims>(new DpopProofMemberRefusal(
                DpopProofMember.Iat,
                WellKnownJwtClaimNames.Iat,
                iat,
                iat is JsonMemberAbsent ? DpopProofMemberDefect.Absent : DpopProofMemberDefect.NotANumericDate));
        }

        var nonce = members.Find(WellKnownJwtClaimNames.Nonce);

        if(nonce is not (JsonMemberAbsent or JsonMemberString))
        {
            return StringMemberRefused(DpopProofMember.Nonce, WellKnownJwtClaimNames.Nonce, nonce);
        }

        var ath = members.Find(WellKnownJwtClaimNames.Ath);

        if(ath is not (JsonMemberAbsent or JsonMemberString))
        {
            return StringMemberRefused(DpopProofMember.Ath, WellKnownJwtClaimNames.Ath, ath);
        }

        return new DpopProofPartRead<DpopProofClaims>(new DpopProofClaims
        {
            Jti = jtiText.Text,
            Htm = htmText.Text,
            Htu = htuText.Text,
            Iat = issuedAt,
            Nonce = (nonce as JsonMemberString)?.Text,
            Ath = (ath as JsonMemberString)?.Text
        });
    }


    /// <summary>The refusal of a claims set for a claim read as a string that is absent or of another kind.</summary>
    /// <param name="member">Which claim it is.</param>
    /// <param name="name">The claim's name.</param>
    /// <param name="carried">The claim as the reader answered it.</param>
    /// <returns>The refusal.</returns>
    private static DpopProofPartRefused<DpopProofClaims> StringMemberRefused(DpopProofMember member, string name, JsonMemberLookup carried) =>
        new(DpopProofMemberRefusal.ForStringMember(member, name, carried));
}
