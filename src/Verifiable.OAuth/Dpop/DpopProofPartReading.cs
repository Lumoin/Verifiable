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
/// it, and carried as the JSON reader answered it.
/// </summary>
/// <param name="Member">Which member the refusal concerns, as the reading knows it.</param>
/// <param name="MemberName">The member's name as the object carrying it names it.</param>
/// <param name="Carried">
/// The member as the JSON reader answered it (<see cref="JsonMemberLookup"/>): absent, a string with its decoded text, a number
/// with its spelling, or a value of another kind naming which.
/// </param>
/// <param name="Defect">Why the part is refused for the member.</param>
public sealed record DpopProofMemberRefusal(
    DpopProofMember Member,
    string MemberName,
    JsonMemberLookup Carried,
    DpopProofMemberDefect Defect) : JwsPartRefusal(PartOf(Member))
{
    /// <summary>The object of the proof carrying, or required to carry, the member.</summary>
    public DpopProofPartPlace Place => Member switch
    {
        DpopProofMember.Typ or DpopProofMember.Alg or DpopProofMember.Jwk => DpopProofPartPlace.ProtectedHeader,
        DpopProofMember.JwkMember => DpopProofPartPlace.EmbeddedJwk,
        _ => DpopProofPartPlace.Claims
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


    /// <summary>The segment of the proof a member is carried in: the claims set's members in the payload, every other in the header.</summary>
    /// <param name="member">The member.</param>
    /// <returns>The segment.</returns>
    private static JwsPart PartOf(DpopProofMember member) => member switch
    {
        DpopProofMember.Typ or DpopProofMember.Alg or DpopProofMember.Jwk or DpopProofMember.JwkMember => JwsPart.ProtectedHeader,
        _ => JwsPart.Payload
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
    /// The embedded <c>jwk</c>'s <c>x5c</c> is no non-empty array of base64-encoded strings (RFC 7517 section 4.7: "Each string in
    /// the array is a base64-encoded (Section 4 of [RFC4648] -- not base64url-encoded) DER [ITU.X690.2008] PKIX certificate
    /// value", the first the certificate containing the key).
    /// </summary>
    NotACertificateChain,

    /// <summary>The embedded <c>jwk</c>'s <c>ext</c> is no Boolean (the Web Cryptography API's <c>JsonWebKey</c> dictionary).</summary>
    NotABoolean,

    /// <summary>
    /// The embedded <c>jwk</c> carries private or symmetric key material (<c>d</c>, <c>p</c>, <c>q</c>, <c>dp</c>, <c>dq</c>,
    /// <c>qi</c>, <c>oth</c>, <c>k</c>, or the <c>priv</c> of an AKP key), whatever the kind of its value: RFC 9449 section 4.2
    /// has the key "a public key".
    /// </summary>
    PrivateKeyMaterial
}
