using Verifiable.JCose;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The reading of one part of a DPoP proof (RFC 9449 section 4.2), its protected header (<see cref="DpopProofHeader.Read"/>) or its
/// claims set (<see cref="DpopProofClaims.Read"/>), each read once through the library's one reading of a JSON object's members
/// (<see cref="JwkJsonReader.ReadTopLevelMembers"/>): the part (<see cref="DpopProofPartRead{TPart}"/>), the refusal of a
/// document the JSON reader refuses (<see cref="DpopProofPartDocumentRefused{TPart}"/>), or the refusal of a member the part
/// requires or reads (<see cref="DpopProofPartMemberRefused{TPart}"/>). No reading throws on the bytes it is handed. What the
/// part's members name - the freshness of <c>iat</c>, <c>htm</c> and <c>htu</c> against the request, <c>ath</c> against the
/// access token, <c>nonce</c> against the one provided, the key's thumbprint - is judged by <see cref="DpopProofValidator"/>,
/// never by the reading.
/// </summary>
/// <typeparam name="TPart">The part read: <see cref="DpopProofHeader"/> or <see cref="DpopProofClaims"/>.</typeparam>
public abstract record DpopProofPartReading<TPart>;


/// <summary>The part, every member it requires present and of its kind.</summary>
/// <typeparam name="TPart">The part read.</typeparam>
/// <param name="Part">The part.</param>
public sealed record DpopProofPartRead<TPart>(TPart Part) : DpopProofPartReading<TPart>;


/// <summary>
/// The JSON reader refused the document a part, or the <c>jwk</c> its protected header embeds, is: no one well-formed JSON object
/// (<see cref="JsonNotOneObject"/>), an object repeating a member name (<see cref="JsonRepeatedMemberName"/>), or an object
/// holding a name or a string naming no Unicode text (<see cref="JsonUndecodableMember"/>), each carried as the reader answered
/// it.
/// </summary>
/// <typeparam name="TPart">The part read.</typeparam>
/// <param name="Place">The object the reader refused.</param>
/// <param name="Refusal">The reader's refusal.</param>
public sealed record DpopProofPartDocumentRefused<TPart>(DpopProofPartPlace Place, JsonTopLevelReading Refusal) : DpopProofPartReading<TPart>;


/// <summary>
/// A member the part requires is absent, or a member it reads is carried as a value of another kind than the one RFC 9449
/// section 4.2 names for it, the member named as the object carrying it names it and carried as the JSON reader answered it.
/// </summary>
/// <typeparam name="TPart">The part read.</typeparam>
/// <param name="Place">The object carrying, or required to carry, the member.</param>
/// <param name="MemberName">The member's name.</param>
/// <param name="Carried">
/// The member as the JSON reader answered it (<see cref="JsonMemberLookup"/>): absent, a string with its decoded text, a number
/// with its spelling, or a value of another kind naming which.
/// </param>
/// <param name="Defect">Why the part is refused for the member.</param>
public sealed record DpopProofPartMemberRefused<TPart>(
    DpopProofPartPlace Place,
    string MemberName,
    JsonMemberLookup Carried,
    DpopProofMemberDefect Defect) : DpopProofPartReading<TPart>;


/// <summary>The object of a DPoP proof a reading's refusal concerns.</summary>
public enum DpopProofPartPlace
{
    /// <summary>The JWS protected header (RFC 9449 section 4.2: <c>typ</c>, <c>alg</c>, <c>jwk</c>).</summary>
    ProtectedHeader,

    /// <summary>The public key the protected header embeds as its <c>jwk</c> (RFC 7517), every member of which is read as a string.</summary>
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
    /// A member read as a string is carried as a value of another kind: <c>typ</c>, <c>alg</c>, <c>jti</c>, <c>htm</c>, <c>htu</c>,
    /// a carried <c>nonce</c> or <c>ath</c>, or a member of the embedded <c>jwk</c>, whose members the proof's key is reconstructed
    /// and judged from as strings, so none of them is passed over unread.
    /// </summary>
    NotAString,

    /// <summary>The <c>jwk</c> is carried as a value that is no JSON object.</summary>
    NotAnObject,

    /// <summary>
    /// The <c>iat</c> is no NumericDate (RFC 7519 section 2): a value that is no JSON number, a string of digits among them, or a
    /// number naming an instant no clock represents.
    /// </summary>
    NotANumericDate
}
