using System.Buffers.Text;
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
    /// The public key used to verify the proof, as the members of the JWK RFC 7517 section 4 and RFC 7518 section 6 define as
    /// strings: the members the key is reconstructed from and its RFC 7638 thumbprint computed over, which the AS / RS compares
    /// to the access token's <c>cnf.jkt</c> binding. A received proof's key is read by <see cref="Read"/>, which judges every
    /// member it knows by that member's own rule; its <c>key_ops</c>, <c>x5c</c> and <c>ext</c>, of other kinds, are judged and
    /// not carried here, since no check of RFC 9449 reads them, and a member no rule names is ignored (RFC 7517 section 4).
    /// </summary>
    public required IReadOnlyDictionary<string, string> Jwk { get; init; }


    /// <summary>
    /// Reads the decoded protected header of a DPoP proof (RFC 9449 section 4.2), once, through the library's one reading of a
    /// JSON object's members (<see cref="JwkJsonReader.ReadTopLevelMembers"/>): its <c>alg</c>, <c>typ</c> and <c>jwk</c>, each
    /// REQUIRED, the first two strings and the third a JSON object read by the same reader, each of whose members is judged by
    /// its own rule (RFC 7517 section 4, RFC 7518 section 6): a member defined as a string is a string, <c>key_ops</c> an array
    /// of strings, <c>x5c</c> a non-empty array of base64-encoded strings and <c>ext</c> a Boolean, a private or symmetric member
    /// is refused whatever its kind, and a member no rule names is ignored. A header the reader refuses, a required member
    /// absent and a known member of another kind - <c>null</c> among them - are refused, each a typed reason
    /// (<see cref="DpopProofPartRefused{TPart}"/>), in the order <c>alg</c>, <c>typ</c>, <c>jwk</c>, then the key's members in
    /// document order; the members are judged by <see cref="DpopProofValidator"/>, never here. Header members the section does not
    /// name are not read. Never throws on the bytes it is handed.
    /// </summary>
    /// <param name="json">The header's UTF-8 JSON bytes, the protected header segment base64url-decoded.</param>
    /// <returns>The header, or its refusal.</returns>
    /// <exception cref="InvalidOperationException">
    /// The <c>jwk</c> of a header the reader admitted read to no object: an invariant failure of the reader, never a refusal of
    /// the header.
    /// </exception>
    public static DpopProofPartReading<DpopProofHeader> Read(ReadOnlySpan<byte> json)
    {
        var reading = JwkJsonReader.ReadTopLevelMembers(json);

        if(reading is not JsonTopLevelMembers members)
        {
            return new DpopProofPartRefused<DpopProofHeader>(new JwsPartDocumentRefusal(JwsPart.ProtectedHeader, reading));
        }

        var alg = members.Find(WellKnownJoseHeaderNames.Alg);

        if(alg is not JsonMemberString algText)
        {
            return Refused(DpopProofMemberRefusal.ForStringMember(DpopProofMember.Alg, WellKnownJoseHeaderNames.Alg, alg));
        }

        var typ = members.Find(WellKnownJoseHeaderNames.Typ);

        if(typ is not JsonMemberString typText)
        {
            return Refused(DpopProofMemberRefusal.ForStringMember(DpopProofMember.Typ, WellKnownJoseHeaderNames.Typ, typ));
        }

        var jwk = members.Find(WellKnownJoseHeaderNames.Jwk);

        if(jwk is not JsonMemberOfOtherKind { Kind: JsonTopLevelValueKind.Object })
        {
            return Refused(new DpopProofMemberRefusal(
                DpopProofMember.Jwk,
                WellKnownJoseHeaderNames.Jwk,
                jwk,
                jwk is JsonMemberAbsent ? DpopProofMemberDefect.Absent : DpopProofMemberDefect.NotAnObject));
        }

        //The object's text as the header writes it is read by the same reader, whose judgement already admitted it as part of
        //the header, so the key's members are read as the header's are and each is judged by its own rule.
        var jwkText = members.Members.First(static member => WellKnownJoseHeaderNames.IsJwk(member.Name)).Text;

        if(JwkJsonReader.ReadTopLevelMembers(Encoding.UTF8.GetBytes(jwkText)) is not JsonTopLevelMembers jwkMembers)
        {
            throw new InvalidOperationException("The jwk of a header the reader admitted read to no object.");
        }

        var key = new Dictionary<string, string>(jwkMembers.Members.Count, StringComparer.Ordinal);

        foreach(var member in jwkMembers.Members)
        {
            if(EmbeddedKeyMemberDefectOf(member) is DpopProofMemberDefect defect)
            {
                return Refused(new DpopProofMemberRefusal(DpopProofMember.JwkMember, member.Name, jwkMembers.Find(member.Name), defect));
            }

            if(IsStringMember(member.Name))
            {
                key[member.Name] = member.Text;
            }
        }

        return new DpopProofPartRead<DpopProofHeader>(new DpopProofHeader { Alg = algText.Text, Typ = typText.Text, Jwk = key });
    }


    /// <summary>The refusal of a header for a member, as its reading answers it.</summary>
    /// <param name="refusal">The member's refusal.</param>
    /// <returns>The reading.</returns>
    private static DpopProofPartRefused<DpopProofHeader> Refused(DpopProofMemberRefusal refusal) => new(refusal);


    /// <summary>
    /// Why a member of the embedded key breaks the rule of its name, or <see langword="null"/> for one that keeps it or that no
    /// rule names: a private or symmetric member whatever its kind, then each known member by its kind.
    /// </summary>
    /// <param name="member">The member as the reader read it.</param>
    /// <returns>The defect, or <see langword="null"/>.</returns>
    private static DpopProofMemberDefect? EmbeddedKeyMemberDefectOf(JsonTopLevelMember member) => member.Name switch
    {
        var name when WellKnownJwkMemberNames.IsPrivateOrSymmetricMember(name) => DpopProofMemberDefect.PrivateKeyMaterial,
        var name when WellKnownJwkMemberNames.IsKeyOps(name) => IsArrayOfStrings(member) ? null : DpopProofMemberDefect.NotAnArrayOfStrings,
        var name when WellKnownJwkMemberNames.IsX5c(name) => IsCertificateChain(member) ? null : DpopProofMemberDefect.NotACertificateChain,
        var name when WellKnownJwkMemberNames.IsExt(name) =>
            member.Kind is JsonTopLevelValueKind.True or JsonTopLevelValueKind.False ? null : DpopProofMemberDefect.NotABoolean,
        var name when IsStringMember(name) => member.Kind is JsonTopLevelValueKind.String ? null : DpopProofMemberDefect.NotAString,
        _ => null
    };


    /// <summary>
    /// Whether a JWK member is one RFC 7517 section 4 or RFC 7518 section 6 defines as a string and carries a public key's
    /// value or metadata in: <c>kty</c>, <c>use</c>, <c>alg</c>, <c>kid</c>, <c>x5u</c>, <c>x5t</c>, <c>x5t#S256</c>, <c>crv</c>,
    /// <c>x</c>, <c>y</c>, <c>n</c>, <c>e</c>, and the <c>pub</c> of an AKP key.
    /// </summary>
    /// <param name="name">The member's name.</param>
    /// <returns><see langword="true"/> for such a member.</returns>
    private static bool IsStringMember(string name) =>
        WellKnownJwkMemberNames.IsKty(name)
        || WellKnownJwkMemberNames.IsUse(name)
        || WellKnownJwkMemberNames.IsAlg(name)
        || WellKnownJwkMemberNames.IsKid(name)
        || WellKnownJwkMemberNames.IsX5u(name)
        || WellKnownJwkMemberNames.IsX5t(name)
        || WellKnownJwkMemberNames.IsX5tHashS256(name)
        || WellKnownJwkMemberNames.IsCrv(name)
        || WellKnownJwkMemberNames.IsX(name)
        || WellKnownJwkMemberNames.IsY(name)
        || WellKnownJwkMemberNames.IsN(name)
        || WellKnownJwkMemberNames.IsE(name)
        || WellKnownJwkMemberNames.Equals(name, WellKnownJwkMemberNames.Pub);


    /// <summary>Whether a member is an array every element of which is a string (RFC 7517 section 4.3's <c>key_ops</c>).</summary>
    /// <param name="member">The member.</param>
    /// <returns><see langword="true"/> for such an array.</returns>
    private static bool IsArrayOfStrings(JsonTopLevelMember member) =>
        member.ArrayElements() is { } elements && elements.All(static element => element is JsonMemberString);


    /// <summary>
    /// Whether a member is a non-empty array of base64-encoded strings (RFC 7517 section 4.7's <c>x5c</c>: base64, "not
    /// base64url-encoded").
    /// </summary>
    /// <param name="member">The member.</param>
    /// <returns><see langword="true"/> for such an array.</returns>
    private static bool IsCertificateChain(JsonTopLevelMember member) =>
        member.ArrayElements() is { Count: > 0 } elements
        && elements.All(static element => element is JsonMemberString { Text: { Length: > 0 } text } && Base64.IsValid(text));
}
