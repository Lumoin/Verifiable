using Verifiable.JCose;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The reading of one part of a DPoP proof (RFC 9449 section 4.2), its protected header (<see cref="DpopProofHeader.Read"/>) or its
/// claims set (<see cref="DpopProofClaims.Read"/>), each read once through the library's one reading of a JSON object's members
/// (<see cref="JwkJsonReader.ReadTopLevelMembers"/>): the part (<see cref="DpopProofPartRead{TPart}"/>), or its refusal
/// (<see cref="DpopProofPartRefused{TPart}"/>), which carries why - the JSON reader's refusal of the part's document
/// (<see cref="JwsPartDocumentRefusal"/>) or the refusal of a member the part requires or reads
/// (<see cref="DpopProofMemberRefusal"/>). No reading throws on the bytes it is handed. What the part's members name - the
/// freshness of <c>iat</c>, <c>htm</c> and <c>htu</c> against the request, <c>ath</c> against the access token, <c>nonce</c>
/// against the one provided, the key's thumbprint - is judged by <see cref="DpopProofValidator"/>, never by the reading.
/// </summary>
/// <typeparam name="TPart">The part read: <see cref="DpopProofHeader"/> or <see cref="DpopProofClaims"/>.</typeparam>
public abstract record DpopProofPartReading<TPart>;


/// <summary>The part, every member it requires present and of its kind.</summary>
/// <typeparam name="TPart">The part read.</typeparam>
/// <param name="Part">The part.</param>
public sealed record DpopProofPartRead<TPart>(TPart Part) : DpopProofPartReading<TPart>;


/// <summary>
/// The part is refused, for why its reading says: the JSON reader refused the document the part is
/// (<see cref="JwsPartDocumentRefusal"/>), or a member the part requires or reads is absent or of another kind than its rule
/// names (<see cref="DpopProofMemberRefusal"/>). The refusal is the one <see cref="DpopProofValidationResult.PartRefusal"/>
/// carries, whole, beside the validation's coarse category.
/// </summary>
/// <typeparam name="TPart">The part read.</typeparam>
/// <param name="Refusal">Why the part is refused.</param>
public sealed record DpopProofPartRefused<TPart>(JwsPartRefusal Refusal) : DpopProofPartReading<TPart>;


/// <summary>
/// A member a DPoP proof's part requires is absent, or a member it reads is carried as a value of another kind than its rule
/// names - RFC 9449 section 4.2 for the header's and the claims set's members, RFC 7517 section 4 and RFC 7518 section 6 for the
/// members of the key the header embeds - the member identified as the reading knows it, named as the object carrying it names
/// it, and carried as the JSON reader answered it. Every fact is fixed by the one construction, which refuses a member the
/// reading does not know; the segment (<see cref="Part"/>) and the object (<see cref="Place"/>) are derived from the member, so
/// no object initializer or <c>with</c> expression can make the three disagree.
/// </summary>
public sealed record DpopProofMemberRefusal : JwsPartRefusal
{
    /// <summary>Creates the refusal of a part for one of its members.</summary>
    /// <param name="member">Which member the refusal concerns, as the reading knows it.</param>
    /// <param name="memberName">The member's name as the object carrying it names it.</param>
    /// <param name="carried">
    /// The member as the JSON reader answered it (<see cref="JsonMemberLookup"/>): absent, a string with its decoded text, a
    /// number with its spelling, or a value of another kind naming which.
    /// </param>
    /// <param name="defect">Why the part is refused for the member.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="member"/> is none of the members a DPoP proof's reading knows.</exception>
    public DpopProofMemberRefusal(DpopProofMember member, string memberName, JsonMemberLookup carried, DpopProofMemberDefect defect)
    {
        ArgumentNullException.ThrowIfNull(memberName);
        ArgumentNullException.ThrowIfNull(carried);

        _ = PartOf(member);
        Member = member;
        MemberName = memberName;
        Carried = carried;
        Defect = defect;
    }


    /// <summary>Which member the refusal concerns, as the reading knows it.</summary>
    public DpopProofMember Member { get; }

    /// <summary>The member's name as the object carrying it names it.</summary>
    public string MemberName { get; }

    /// <summary>
    /// The member as the JSON reader answered it (<see cref="JsonMemberLookup"/>): absent, a string with its decoded text, a number
    /// with its spelling, or a value of another kind naming which.
    /// </summary>
    public JsonMemberLookup Carried { get; }

    /// <summary>Why the part is refused for the member.</summary>
    public DpopProofMemberDefect Defect { get; }

    /// <summary>The segment of the proof the member is carried in, derived from <see cref="Member"/>.</summary>
    public override JwsPart Part => PartOf(Member);


    /// <summary>
    /// The object of the proof carrying, or required to carry, the member, derived from <see cref="Member"/>, which a refusal
    /// is constructed with only as one of the members its reading knows (<see cref="PartOf"/> refuses any other).
    /// </summary>
    /// <exception cref="InvalidOperationException">The member is none the reading knows, which construction refused: an invariant failure.</exception>
    public DpopProofPartPlace Place => Member switch
    {
        DpopProofMember.Typ or DpopProofMember.Alg or DpopProofMember.Jwk => DpopProofPartPlace.ProtectedHeader,
        DpopProofMember.JwkMember => DpopProofPartPlace.EmbeddedJwk,
        DpopProofMember.Jti or DpopProofMember.Htm or DpopProofMember.Htu or DpopProofMember.Iat or DpopProofMember.Nonce or DpopProofMember.Ath =>
            DpopProofPartPlace.Claims,
        _ => throw new InvalidOperationException($"The member {Member} is none a DPoP proof's reading knows.")
    };


    /// <summary>
    /// The refusal of a part for a member read as a string that is absent or carried as a value of another kind, the one
    /// construction every string member of a header and of a claims set is refused by.
    /// </summary>
    /// <param name="member">Which member it is.</param>
    /// <param name="memberName">The member's name.</param>
    /// <param name="carried">The member as the JSON reader answered it.</param>
    /// <returns>The refusal.</returns>
    internal static DpopProofMemberRefusal ForStringMember(DpopProofMember member, string memberName, JsonMemberLookup carried) =>
        new(member, memberName, carried, carried is JsonMemberAbsent ? DpopProofMemberDefect.Absent : DpopProofMemberDefect.NotAString);


    /// <summary>
    /// The segment of the proof a member is carried in: the header's members and the embedded key's in the protected header, the
    /// claims set's in the payload. A member the reading does not know is refused, so no refusal is constructed for one.
    /// </summary>
    /// <param name="member">The member.</param>
    /// <returns>The segment.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="member"/> is none of the members a DPoP proof's reading knows.</exception>
    private static JwsPart PartOf(DpopProofMember member) => member switch
    {
        DpopProofMember.Typ or DpopProofMember.Alg or DpopProofMember.Jwk or DpopProofMember.JwkMember => JwsPart.ProtectedHeader,
        DpopProofMember.Jti or DpopProofMember.Htm or DpopProofMember.Htu or DpopProofMember.Iat or DpopProofMember.Nonce or DpopProofMember.Ath =>
            JwsPart.Payload,
        _ => throw new ArgumentOutOfRangeException(nameof(member), member, "The member is none a DPoP proof's reading knows.")
    };
}


/// <summary>The members of a DPoP proof its reading judges, each as the reading knows it.</summary>
public enum DpopProofMember
{
    /// <summary>The protected header's <c>typ</c> (RFC 9449 section 4.2), REQUIRED, a string.</summary>
    Typ,

    /// <summary>The protected header's <c>alg</c> (RFC 9449 section 4.2), REQUIRED, a string.</summary>
    Alg,

    /// <summary>The protected header's <c>jwk</c> (RFC 9449 section 4.2), REQUIRED, a JSON object.</summary>
    Jwk,

    /// <summary>A member of the key the header embeds as its <c>jwk</c>, named by <see cref="DpopProofMemberRefusal.MemberName"/>.</summary>
    JwkMember,

    /// <summary>The claims set's <c>jti</c> (RFC 9449 section 4.2), REQUIRED, a string.</summary>
    Jti,

    /// <summary>The claims set's <c>htm</c> (RFC 9449 section 4.2), REQUIRED, a string.</summary>
    Htm,

    /// <summary>The claims set's <c>htu</c> (RFC 9449 section 4.2), REQUIRED, a string.</summary>
    Htu,

    /// <summary>The claims set's <c>iat</c> (RFC 9449 section 4.2), REQUIRED, a NumericDate.</summary>
    Iat,

    /// <summary>The claims set's <c>nonce</c> (RFC 9449 section 4.2), a string where carried.</summary>
    Nonce,

    /// <summary>The claims set's <c>ath</c> (RFC 9449 section 4.2), a string where carried.</summary>
    Ath
}


/// <summary>The object of a DPoP proof a member refusal concerns.</summary>
public enum DpopProofPartPlace
{
    /// <summary>The JWS protected header (RFC 9449 section 4.2: <c>typ</c>, <c>alg</c>, <c>jwk</c>).</summary>
    ProtectedHeader,

    /// <summary>
    /// The public key the protected header embeds as its <c>jwk</c> (RFC 7517), each member read by its own rule: the members
    /// RFC 7517 section 4 and RFC 7518 section 6 define as strings as strings, <c>key_ops</c> as an array of strings,
    /// <c>x5c</c> as an array of base64-encoded certificates, <c>ext</c> as a Boolean, a private or symmetric member refused
    /// whatever its kind, and a member no rule names ignored.
    /// </summary>
    EmbeddedJwk,

    /// <summary>The JWT claims set (RFC 9449 section 4.2: <c>jti</c>, <c>htm</c>, <c>htu</c>, <c>iat</c>, and <c>ath</c> and <c>nonce</c> where carried).</summary>
    Claims
}


/// <summary>Why a DPoP proof's part is refused for one of its members.</summary>
public enum DpopProofMemberDefect
{
    /// <summary>A member RFC 9449 section 4.2 requires is absent: <c>typ</c>, <c>alg</c> or <c>jwk</c>, or <c>jti</c>, <c>htm</c>, <c>htu</c> or <c>iat</c>.</summary>
    Absent,

    /// <summary>
    /// A member read as a string is carried as a value of another kind, <c>null</c> among them: <c>typ</c>, <c>alg</c>,
    /// <c>jti</c>, <c>htm</c>, <c>htu</c>, a carried <c>nonce</c> or <c>ath</c>, or a member of the embedded <c>jwk</c> RFC 7517
    /// section 4 or RFC 7518 section 6 defines as a string (<c>kty</c>, <c>use</c>, <c>alg</c>, <c>kid</c>, <c>x5u</c>,
    /// <c>x5t</c>, <c>x5t#S256</c>, <c>crv</c>, <c>x</c>, <c>y</c>, <c>n</c>, <c>e</c>, and the <c>pub</c> of an AKP key).
    /// </summary>
    NotAString,

    /// <summary>The <c>jwk</c> is carried as a value that is no JSON object.</summary>
    NotAnObject,

    /// <summary>
    /// The <c>iat</c> is no NumericDate (RFC 7519 section 2): a value that is no JSON number, a string of digits among them, or a
    /// number naming an instant no clock represents.
    /// </summary>
    NotANumericDate,

    /// <summary>The embedded <c>jwk</c>'s <c>key_ops</c> is no array of strings (RFC 7517 section 4.3).</summary>
    NotAnArrayOfStrings,

    /// <summary>
    /// The embedded <c>jwk</c>'s <c>x5c</c> is no non-empty array of base64-encoded DER certificates (RFC 7517 section 4.7: "Each
    /// string in the array is a base64-encoded (Section 4 of [RFC4648] -- not base64url-encoded) DER [ITU.X690.2008] PKIX
    /// certificate value"): an empty array, an element of another kind, base64url or other text, or text decoding to bytes that
    /// are no X.509 certificate (RFC 5280 section 4.1) among them. Each element is read structurally; the certification of each
    /// certificate by the next is a matter of trust in the chain, which the reading does not judge.
    /// </summary>
    NotACertificateChain,

    /// <summary>The embedded <c>jwk</c>'s <c>ext</c> is no Boolean (the Web Cryptography API's <c>JsonWebKey</c> dictionary).</summary>
    NotABoolean,

    /// <summary>
    /// The embedded <c>jwk</c> carries private or symmetric key material (<c>d</c>, <c>p</c>, <c>q</c>, <c>dp</c>, <c>dq</c>,
    /// <c>qi</c>, <c>oth</c>, <c>k</c>, or the <c>priv</c> of an AKP key), whatever the kind of its value: RFC 9449 section 4.2
    /// has the key "a public key".
    /// </summary>
    PrivateKeyMaterial,

    /// <summary>
    /// The embedded <c>jwk</c>'s <c>key_ops</c> names an operation more than once (RFC 7517 section 4.3: "Duplicate key operation
    /// values MUST NOT be present in the array").
    /// </summary>
    RepeatedKeyOperation,

    /// <summary>
    /// The embedded <c>jwk</c> carries both <c>use</c> and <c>key_ops</c>, and they are established not to convey consistent
    /// information (RFC 7517 section 4.3: "if both are used, the information they convey MUST be consistent"): <c>sig</c>
    /// permits <c>sign</c> and <c>verify</c>, and <c>enc</c> the encryption, key wrapping and derivation operations, so an
    /// operation of that vocabulary the known use does not permit is inconsistent with it.
    /// </summary>
    KeyOperationsInconsistentWithUse,

    /// <summary>
    /// The embedded <c>jwk</c>'s <c>x5c</c> is a chain of certificates whose first certificate's key is established not to be the
    /// key the <c>jwk</c>'s other members represent (RFC 7517 section 4.7: "The key in the first certificate MUST match the public
    /// key represented by other members of the JWK").
    /// </summary>
    CertificateNotOfTheKey,

    /// <summary>
    /// The embedded <c>jwk</c> carries both <c>use</c> and <c>key_ops</c>, and the use or an operation is outside the vocabulary
    /// RFC 7517 sections 4.2 and 4.3 register (<c>sig</c> and <c>enc</c>; <c>sign</c>, <c>verify</c>, <c>encrypt</c>,
    /// <c>decrypt</c>, <c>wrapKey</c>, <c>unwrapKey</c>, <c>deriveKey</c>, <c>deriveBits</c>), so whether the two are consistent,
    /// which the section requires, is not established: a judgement not made, never an established inconsistency.
    /// </summary>
    KeyOperationsRelationToUseUnestablished,

    /// <summary>
    /// The embedded <c>jwk</c>'s <c>x5c</c> is a chain of DER certificates, but the key the <c>jwk</c>'s other members represent is
    /// of a type, curve or algorithm whose agreement with a certificate's key the library does not compare, so whether the first
    /// certificate's key is that key, which RFC 7517 section 4.7 requires, is not established: a judgement not made, never an
    /// established mismatch.
    /// </summary>
    CertificateKeyRelationUnestablished
}
