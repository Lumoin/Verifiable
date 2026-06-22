using Verifiable.Cryptography.Text;


namespace Verifiable.JCose;

/// <summary>
/// JOSE-only header parameter NAMES — strings that appear as JSON keys in
/// JWS / JWE protected or unprotected headers per
/// <see href="https://www.rfc-editor.org/rfc/rfc7515">RFC 7515</see> and
/// <see href="https://www.rfc-editor.org/rfc/rfc7516">RFC 7516</see>,
/// and which are NOT also JWK members.
/// </summary>
/// <remarks>
/// <para>
/// Parameters that appear as both JWK members and JOSE header parameters
/// (<c>alg</c>, <c>kid</c>, <c>x5*</c>, <c>jwk</c>) live in
/// <see cref="WellKnownJwkMemberNames"/> — the strings are identical, so
/// one home avoids duplicate constants.
/// </para>
/// </remarks>
public static class WellKnownJoseHeaderNames
{
    /// <summary>The UTF-8 source literal of <see cref="Typ"/>.</summary>
    public static ReadOnlySpan<byte> TypUtf8 => "typ"u8;

    /// <summary>
    /// The <c>typ</c> (Type) header parameter per RFC 7515 §4.1.9. Declares the
    /// media type of the complete JWT/JWS/JWE.
    /// </summary>
    public static readonly string Typ = Utf8Constants.ToInternedString(TypUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Cty"/>.</summary>
    public static ReadOnlySpan<byte> CtyUtf8 => "cty"u8;

    /// <summary>
    /// The <c>cty</c> (Content Type) header parameter per RFC 7515 §4.1.10 and
    /// RFC 7519 §5.2. Used when the payload itself is a JWT (nested JWT case).
    /// </summary>
    public static readonly string Cty = Utf8Constants.ToInternedString(CtyUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Enc"/>.</summary>
    public static ReadOnlySpan<byte> EncUtf8 => "enc"u8;

    /// <summary>
    /// The <c>enc</c> (Encryption Algorithm) header parameter per RFC 7516 §4.1.2.
    /// Identifies the content encryption algorithm used to produce the ciphertext.
    /// </summary>
    public static readonly string Enc = Utf8Constants.ToInternedString(EncUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Epk"/>.</summary>
    public static ReadOnlySpan<byte> EpkUtf8 => "epk"u8;

    /// <summary>
    /// The <c>epk</c> (Ephemeral Public Key) header parameter per RFC 7518 §4.6.1.1.
    /// Carries the sender's ephemeral public key in ECDH key-agreement algorithms.
    /// </summary>
    public static readonly string Epk = Utf8Constants.ToInternedString(EpkUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Apu"/>.</summary>
    public static ReadOnlySpan<byte> ApuUtf8 => "apu"u8;

    /// <summary>
    /// The <c>apu</c> (Agreement PartyUInfo) header parameter per RFC 7518 §4.6.1.2.
    /// In OID4VP mdoc presentations the wallet carries its <c>mdoc_generated_nonce</c>
    /// (base64url) here per ISO/IEC 18013-7 §B.4.4 so the Verifier can reconstruct the
    /// SessionTranscript.
    /// </summary>
    public static readonly string Apu = Utf8Constants.ToInternedString(ApuUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Apv"/>.</summary>
    public static ReadOnlySpan<byte> ApvUtf8 => "apv"u8;

    /// <summary>
    /// The <c>apv</c> (Agreement PartyVInfo) header parameter per RFC 7518 §4.6.1.3.
    /// In DIDComm v2 this is the base64url encoding of the SHA-256 hash of the
    /// alphanumerically-sorted recipient <c>kid</c> list joined with <c>.</c>.
    /// </summary>
    public static readonly string Apv = Utf8Constants.ToInternedString(ApvUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Skid"/>.</summary>
    public static ReadOnlySpan<byte> SkidUtf8 => "skid"u8;

    /// <summary>
    /// The <c>skid</c> (Sender Key ID) header parameter per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04#section-2.2.1">draft-madden-jose-ecdh-1pu-04 §2.2.1</see>.
    /// A hint identifying which of the sender's keys authenticated the JWE. In DIDComm v2
    /// this is a DID URL to the sender's <c>keyAgreement</c> verification method; its value
    /// is resolvable from <c>apu</c> when <c>skid</c> is absent.
    /// </summary>
    public static readonly string Skid = Utf8Constants.ToInternedString(SkidUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Jwk"/>.</summary>
    public static ReadOnlySpan<byte> JwkUtf8 => "jwk"u8;

    /// <summary>
    /// The <c>jwk</c> (JSON Web Key) header parameter per RFC 7515 §4.1.3.
    /// Carries the public key used to verify the JWS. MUST NOT contain private
    /// key components.
    /// </summary>
    public static readonly string Jwk = Utf8Constants.ToInternedString(JwkUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Jwt"/>.</summary>
    public static ReadOnlySpan<byte> JwtUtf8 => "jwt"u8;

    /// <summary>
    /// The <c>jwt</c> JOSE header parameter used to carry a Verifier Attestation
    /// JWT in a signed Authorization Request Object per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-12">OID4VP 1.0 §12</see>.
    /// </summary>
    public static readonly string Jwt = Utf8Constants.ToInternedString(JwtUtf8);


    /// <summary>Whether <paramref name="name"/> is <see cref="Typ"/>.</summary>
    public static bool IsTyp(string name) => Equals(name, Typ);

    /// <summary>Whether <paramref name="name"/> is <see cref="Cty"/>.</summary>
    public static bool IsCty(string name) => Equals(name, Cty);

    /// <summary>Whether <paramref name="name"/> is <see cref="Enc"/>.</summary>
    public static bool IsEnc(string name) => Equals(name, Enc);

    /// <summary>Whether <paramref name="name"/> is <see cref="Epk"/>.</summary>
    public static bool IsEpk(string name) => Equals(name, Epk);

    /// <summary>Whether <paramref name="name"/> is <see cref="Apu"/>.</summary>
    public static bool IsApu(string name) => Equals(name, Apu);

    /// <summary>Whether <paramref name="name"/> is <see cref="Apv"/>.</summary>
    public static bool IsApv(string name) => Equals(name, Apv);

    /// <summary>Whether <paramref name="name"/> is <see cref="Skid"/>.</summary>
    public static bool IsSkid(string name) => Equals(name, Skid);

    /// <summary>Whether <paramref name="name"/> is <see cref="Jwk"/>.</summary>
    public static bool IsJwk(string name) => Equals(name, Jwk);

    /// <summary>Whether <paramref name="name"/> is <see cref="Jwt"/>.</summary>
    public static bool IsJwt(string name) => Equals(name, Jwt);


    /// <summary>
    /// Returns the interned constant for a known JOSE header parameter name,
    /// or the original string if unrecognized.
    /// </summary>
    public static string GetCanonicalizedValue(string name) => name switch
    {
        _ when IsTyp(name) => Typ,
        _ when IsCty(name) => Cty,
        _ when IsEnc(name) => Enc,
        _ when IsEpk(name) => Epk,
        _ when IsApu(name) => Apu,
        _ when IsApv(name) => Apv,
        _ when IsSkid(name) => Skid,
        _ when IsJwk(name) => Jwk,
        _ when IsJwt(name) => Jwt,
        _ => name
    };


    /// <summary>
    /// Compares two JOSE header parameter names for equality. Comparison is
    /// case-sensitive per RFC 7515.
    /// </summary>
    public static bool Equals(string nameA, string nameB) =>
        object.ReferenceEquals(nameA, nameB) || StringComparer.Ordinal.Equals(nameA, nameB);
}
