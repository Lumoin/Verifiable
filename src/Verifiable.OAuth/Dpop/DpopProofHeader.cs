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
    /// member it knows by that member's own rule, the rules relating one member to another among them; its <c>key_ops</c>,
    /// <c>x5c</c> and <c>ext</c>, of other kinds, are held until those judgements are made and are not carried here, since no
    /// check of RFC 9449 reads them, and a member no rule names is ignored (RFC 7517 section 4).
    /// </summary>
    public required IReadOnlyDictionary<string, string> Jwk { get; init; }


    /// <summary>
    /// Reads the decoded protected header of a DPoP proof (RFC 9449 section 4.2), once, through the library's one reading of a
    /// JSON object's members (<see cref="JwkJsonReader.ReadTopLevelMembers"/>): its <c>alg</c>, <c>typ</c> and <c>jwk</c>, each
    /// REQUIRED, the first two strings and the third a JSON object read by the same reader, each of whose members is judged by
    /// its own rule (RFC 7517 section 4, RFC 7518 section 6): a member defined as a string is a string, <c>key_ops</c> an array
    /// of strings, <c>x5c</c> a non-empty array of strings and <c>ext</c> a Boolean, a private or symmetric member is refused
    /// whatever its kind, and a member no rule names is ignored. Once every member of the key is read, the rules that relate them
    /// are judged: a <c>key_ops</c> naming no operation twice and consistent with a <c>use</c> the key carries (RFC 7517 section
    /// 4.3), a use or an operation outside the known vocabulary refused as a relation not established rather than as an
    /// inconsistency, then an <c>x5c</c> whose every element is base64 text of a DER certificate and whose first certificate's key
    /// is the key the other members state (section 4.7, through <see cref="JwkCertificateChain"/>), a key whose agreement with a
    /// certificate's the library does not compare refused as a relation not established rather than as a mismatch. A header the reader refuses, a
    /// required member absent, a known member of another kind - <c>null</c> among them - and a key breaking a rule relating its
    /// members are refused, each a typed reason (<see cref="DpopProofPartRefused{TPart}"/>), in the order <c>alg</c>, <c>typ</c>,
    /// <c>jwk</c>, then the key's members in document order, then <c>key_ops</c> and <c>x5c</c>; what the claims name is judged by
    /// <see cref="DpopProofValidator"/>, never here. Header members the section does not name are not read. Never throws on the
    /// bytes it is handed.
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
        JsonTopLevelMember? keyOperations = null;
        JsonTopLevelMember? certificateChain = null;

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
            else if(WellKnownJwkMemberNames.IsKeyOps(member.Name))
            {
                keyOperations = member;
            }
            else if(WellKnownJwkMemberNames.IsX5c(member.Name))
            {
                certificateChain = member;
            }
        }

        //RFC 7517 sections 4.3 and 4.7 relate a key's members to one another, wherever in the key each is written, so they are
        //judged once every member is read: the operations against the use, the first certificate against the key.
        if(keyOperations is not null && KeyOperationsDefectOf(StringsOf(keyOperations), key) is DpopProofMemberDefect operationsDefect)
        {
            return Refused(new DpopProofMemberRefusal(
                DpopProofMember.JwkMember, keyOperations.Name, jwkMembers.Find(keyOperations.Name), operationsDefect));
        }

        if(certificateChain is not null && JwkCertificateChain.DefectOf(StringsOf(certificateChain), key) is JwkCertificateChainDefect chainDefect)
        {
            return Refused(new DpopProofMemberRefusal(
                DpopProofMember.JwkMember, certificateChain.Name, jwkMembers.Find(certificateChain.Name), MemberDefectOf(chainDefect)));
        }

        return new DpopProofPartRead<DpopProofHeader>(new DpopProofHeader { Alg = algText.Text, Typ = typText.Text, Jwk = key });
    }


    /// <summary>
    /// Why a key's operations break RFC 7517 section 4.3, or <see langword="null"/> when they keep it: an operation named twice;
    /// then, where the key carries a <c>use</c>, an operation of the known vocabulary the known use does not permit, an
    /// established inconsistency; then a use or an operation outside the known vocabulary, whose relation to the other the
    /// library does not establish. A key carrying no <c>use</c> has no relation between the two to judge, so any operation keeps
    /// the rule, one outside the known vocabulary included (RFC 7517 section 4.3 admits values beyond it).
    /// </summary>
    /// <param name="operations">The <c>key_ops</c> values, in document order.</param>
    /// <param name="key">The key's string members, its <c>use</c> among them where it carries one.</param>
    /// <returns>The defect, or <see langword="null"/>.</returns>
    private static DpopProofMemberDefect? KeyOperationsDefectOf(IReadOnlyList<string> operations, Dictionary<string, string> key)
    {
        if(operations.Distinct(StringComparer.Ordinal).Count() != operations.Count)
        {
            return DpopProofMemberDefect.RepeatedKeyOperation;
        }

        if(!key.TryGetValue(WellKnownJwkMemberNames.Use, out var use))
        {
            return null;
        }

        var relations = operations.Select(operation => RelationOf(use, operation)).ToList();

        return relations.Contains(KeyOperationRelation.Inconsistent) ? DpopProofMemberDefect.KeyOperationsInconsistentWithUse
            : relations.Contains(KeyOperationRelation.Unestablished) ? DpopProofMemberDefect.KeyOperationsRelationToUseUnestablished
            : null;
    }


    /// <summary>
    /// How a key operation relates to a key's <c>use</c> (RFC 7517 sections 4.2 and 4.3): <c>sig</c>, "signature", permits
    /// <c>sign</c> and <c>verify</c>; <c>enc</c>, "encryption", permits <c>encrypt</c>, <c>decrypt</c>, <c>wrapKey</c>,
    /// <c>unwrapKey</c>, <c>deriveKey</c> and <c>deriveBits</c>. An operation of that vocabulary a known use does not permit is
    /// inconsistent with it; a use or an operation outside the vocabulary has a relation the library does not establish.
    /// </summary>
    /// <param name="use">The key's <c>use</c>.</param>
    /// <param name="operation">One of its <c>key_ops</c>.</param>
    /// <returns>The relation.</returns>
    private static KeyOperationRelation RelationOf(string use, string operation)
    {
        var signing = WellKnownJwkValues.IsKeyOpsSign(operation) || WellKnownJwkValues.IsKeyOpsVerify(operation);
        var encryption = WellKnownJwkValues.IsKeyOpsEncrypt(operation)
            || WellKnownJwkValues.IsKeyOpsDecrypt(operation)
            || WellKnownJwkValues.IsKeyOpsWrapKey(operation)
            || WellKnownJwkValues.IsKeyOpsUnwrapKey(operation)
            || WellKnownJwkValues.IsKeyOpsDeriveKey(operation)
            || WellKnownJwkValues.IsKeyOpsDeriveBits(operation);

        return use switch
        {
            _ when !signing && !encryption => KeyOperationRelation.Unestablished,
            var value when WellKnownJwkValues.IsUseSig(value) => signing ? KeyOperationRelation.Permitted : KeyOperationRelation.Inconsistent,
            var value when WellKnownJwkValues.IsUseEnc(value) => encryption ? KeyOperationRelation.Permitted : KeyOperationRelation.Inconsistent,
            _ => KeyOperationRelation.Unestablished
        };
    }


    /// <summary>How one key operation relates to the key's <c>use</c>.</summary>
    private enum KeyOperationRelation
    {
        /// <summary>The use permits the operation.</summary>
        Permitted,

        /// <summary>Both are of the known vocabulary and the use does not permit the operation.</summary>
        Inconsistent,

        /// <summary>The use or the operation is outside the known vocabulary, so no relation between them is established.</summary>
        Unestablished
    }


    /// <summary>The member defect a refusal of a key's <c>x5c</c> is answered with.</summary>
    /// <param name="defect">Why the <c>x5c</c> is refused.</param>
    /// <returns>The member defect.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="defect"/> is none the judgement answers.</exception>
    private static DpopProofMemberDefect MemberDefectOf(JwkCertificateChainDefect defect) => defect switch
    {
        JwkCertificateChainDefect.NotBase64Text or JwkCertificateChainDefect.NotACertificate => DpopProofMemberDefect.NotACertificateChain,
        JwkCertificateChainDefect.FirstCertificateNotOfTheKey => DpopProofMemberDefect.CertificateNotOfTheKey,
        JwkCertificateChainDefect.KeyComparisonUnsupported => DpopProofMemberDefect.CertificateKeyRelationUnestablished,
        _ => throw new ArgumentOutOfRangeException(nameof(defect), defect, "The certificate chain's judgement answered a defect it never answers.")
    };


    /// <summary>The strings of a member already judged an array of strings, in document order.</summary>
    /// <param name="member">The member.</param>
    /// <returns>The strings.</returns>
    /// <exception cref="InvalidOperationException">The member is no array of strings, which its judgement refused: an invariant failure.</exception>
    private static IReadOnlyList<string> StringsOf(JsonTopLevelMember member) =>
        member.ArrayElements() is { } elements && elements.All(static element => element is JsonMemberString)
            ? [.. elements.Cast<JsonMemberString>().Select(static element => element.Text)]
            : throw new InvalidOperationException("A key member judged an array of strings read to none.");


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
        || WellKnownJwkMemberNames.IsPub(name);


    /// <summary>Whether a member is an array every element of which is a string (RFC 7517 section 4.3's <c>key_ops</c>).</summary>
    /// <param name="member">The member.</param>
    /// <returns><see langword="true"/> for such an array.</returns>
    private static bool IsArrayOfStrings(JsonTopLevelMember member) =>
        member.ArrayElements() is { } elements && elements.All(static element => element is JsonMemberString);


    /// <summary>
    /// Whether a member is of the kind RFC 7517 section 4.7's <c>x5c</c> is, a non-empty array of strings. Whether each string
    /// is base64 text decoding to a DER certificate is judged by the one authority of a JWK's certificate chain,
    /// <see cref="JwkCertificateChain.DefectOf"/>, once every member of the key is read.
    /// </summary>
    /// <param name="member">The member.</param>
    /// <returns><see langword="true"/> for such an array.</returns>
    private static bool IsCertificateChain(JsonTopLevelMember member) =>
        member.ArrayElements() is { Count: > 0 } elements && elements.All(static element => element is JsonMemberString);
}
