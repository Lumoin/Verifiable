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
    /// <summary>
    /// The <c>typ</c> (Type) header parameter per RFC 7515 §4.1.9. Declares the
    /// media type of the complete JWT/JWS/JWE.
    /// </summary>
    public static readonly string Typ = "typ";

    /// <summary>
    /// The <c>cty</c> (Content Type) header parameter per RFC 7515 §4.1.10 and
    /// RFC 7519 §5.2. Used when the payload itself is a JWT (nested JWT case).
    /// </summary>
    public static readonly string Cty = "cty";

    /// <summary>
    /// The <c>enc</c> (Encryption Algorithm) header parameter per RFC 7516 §4.1.2.
    /// Identifies the content encryption algorithm used to produce the ciphertext.
    /// </summary>
    public static readonly string Enc = "enc";

    /// <summary>
    /// The <c>epk</c> (Ephemeral Public Key) header parameter per RFC 7518 §4.6.1.1.
    /// Carries the sender's ephemeral public key in ECDH key-agreement algorithms.
    /// </summary>
    public static readonly string Epk = "epk";

    /// <summary>
    /// The <c>apu</c> (Agreement PartyUInfo) header parameter per RFC 7518 §4.6.1.2.
    /// In OID4VP mdoc presentations the wallet carries its <c>mdoc_generated_nonce</c>
    /// (base64url) here per ISO/IEC 18013-7 §B.4.4 so the Verifier can reconstruct the
    /// SessionTranscript.
    /// </summary>
    public static readonly string Apu = "apu";

    /// <summary>
    /// The <c>jwk</c> (JSON Web Key) header parameter per RFC 7515 §4.1.3.
    /// Carries the public key used to verify the JWS. MUST NOT contain private
    /// key components.
    /// </summary>
    public static readonly string Jwk = "jwk";

    /// <summary>
    /// The <c>jwt</c> JOSE header parameter used to carry a Verifier Attestation
    /// JWT in a signed Authorization Request Object per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-12">OID4VP 1.0 §12</see>.
    /// </summary>
    public static readonly string Jwt = "jwt";


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
