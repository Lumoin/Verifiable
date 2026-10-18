using System.Diagnostics;
using System.Text;
using Verifiable.JCose;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The JWS protected header of a DPoP proof per
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 §4.2</see>.
/// </summary>
[DebuggerDisplay("DpopProofHeader alg={Alg,nq} typ={Typ,nq}")]
public sealed record DpopProofHeader
{
    /// <summary>
    /// The signing algorithm, e.g. <c>ES256</c>. Must match the type of
    /// the embedded <see cref="Jwk"/>.
    /// </summary>
    public required string Alg { get; init; }

    /// <summary>
    /// The type — always <c>dpop+jwt</c> per RFC 9449 §4.2.
    /// </summary>
    public string Typ { get; init; } = WellKnownDpopValues.ProofTypeHeader;

    /// <summary>
    /// The public key used to verify the proof, serialised as a JWK. The
    /// AS / RS extracts this, computes its RFC 7638 thumbprint, and
    /// compares to the access token's <c>cnf.jkt</c> binding.
    /// </summary>
    public required IReadOnlyDictionary<string, string> Jwk { get; init; }


    /// <summary>
    /// Reads the decoded protected header of a DPoP proof (RFC 9449 section 4.2), once, through the library's one reading of a
    /// JSON object's members (<see cref="JwkJsonReader.ReadTopLevelMembers"/>): its <c>alg</c>, <c>typ</c> and <c>jwk</c>, each
    /// REQUIRED, the first two strings and the third a JSON object every member of which is a string, read through the same
    /// reader. A header the reader refuses, a required member absent and a member of another kind are refused, each a typed
    /// reason (<see cref="DpopProofPartReading{TPart}"/>), in the order <c>alg</c>, <c>typ</c>, <c>jwk</c>; the members are
    /// judged by <see cref="DpopProofValidator"/>, never here. Members the section does not name are not read. Never throws.
    /// </summary>
    /// <param name="json">The header's UTF-8 JSON bytes, the protected header segment base64url-decoded.</param>
    /// <returns>The header, or its refusal.</returns>
    public static DpopProofPartReading<DpopProofHeader> Read(ReadOnlySpan<byte> json)
    {
        var reading = JwkJsonReader.ReadTopLevelMembers(json);

        if(reading is not JsonTopLevelMembers members)
        {
            return new DpopProofPartDocumentRefused<DpopProofHeader>(DpopProofPartPlace.ProtectedHeader, reading);
        }

        var alg = members.Find(WellKnownJoseHeaderNames.Alg);

        if(alg is not JsonMemberString algText)
        {
            return StringMemberRefused(DpopProofPartPlace.ProtectedHeader, WellKnownJoseHeaderNames.Alg, alg);
        }

        var typ = members.Find(WellKnownJoseHeaderNames.Typ);

        if(typ is not JsonMemberString typText)
        {
            return StringMemberRefused(DpopProofPartPlace.ProtectedHeader, WellKnownJoseHeaderNames.Typ, typ);
        }

        var jwk = members.Find(WellKnownJoseHeaderNames.Jwk);

        if(jwk is not JsonMemberOfOtherKind { Kind: JsonTopLevelValueKind.Object })
        {
            return new DpopProofPartMemberRefused<DpopProofHeader>(
                DpopProofPartPlace.ProtectedHeader,
                WellKnownJoseHeaderNames.Jwk,
                jwk,
                jwk is JsonMemberAbsent ? DpopProofMemberDefect.Absent : DpopProofMemberDefect.NotAnObject);
        }

        //The object's text as the header writes it is read by the same reader, so the key's members are read as the header's
        //are, and a member of it that is no string is refused rather than passed over.
        var jwkText = members.Members.First(static member => string.Equals(member.Name, WellKnownJoseHeaderNames.Jwk, StringComparison.Ordinal)).Text;
        var jwkReading = JwkJsonReader.ReadTopLevelMembers(Encoding.UTF8.GetBytes(jwkText));

        if(jwkReading is not JsonTopLevelMembers jwkMembers)
        {
            return new DpopProofPartDocumentRefused<DpopProofHeader>(DpopProofPartPlace.EmbeddedJwk, jwkReading);
        }

        var key = new Dictionary<string, string>(jwkMembers.Members.Count, StringComparer.Ordinal);

        foreach(var member in jwkMembers.Members)
        {
            if(member.Kind is not JsonTopLevelValueKind.String)
            {
                return new DpopProofPartMemberRefused<DpopProofHeader>(
                    DpopProofPartPlace.EmbeddedJwk, member.Name, jwkMembers.Find(member.Name), DpopProofMemberDefect.NotAString);
            }

            key[member.Name] = member.Text;
        }

        return new DpopProofPartRead<DpopProofHeader>(new DpopProofHeader { Alg = algText.Text, Typ = typText.Text, Jwk = key });
    }


    /// <summary>The refusal of a header for a member read as a string that is absent or of another kind.</summary>
    /// <param name="place">The object carrying the member.</param>
    /// <param name="name">The member's name.</param>
    /// <param name="carried">The member as the reader answered it.</param>
    /// <returns>The refusal.</returns>
    private static DpopProofPartMemberRefused<DpopProofHeader> StringMemberRefused(DpopProofPartPlace place, string name, JsonMemberLookup carried) =>
        new(place, name, carried, carried is JsonMemberAbsent ? DpopProofMemberDefect.Absent : DpopProofMemberDefect.NotAString);
}
