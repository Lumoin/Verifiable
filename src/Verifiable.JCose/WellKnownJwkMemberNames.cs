namespace Verifiable.JCose;

/// <summary>
/// Well-known JWK member NAMES — strings that appear as JSON keys in JWK
/// objects per <see href="https://www.rfc-editor.org/rfc/rfc7517">RFC 7517</see>
/// and JWA per <see href="https://www.rfc-editor.org/rfc/rfc7518">RFC 7518</see>.
/// Several of these (<c>alg</c>, <c>kid</c>, <c>x5*</c>) also appear as JOSE
/// header parameter names per RFC 7515; the same constant is reused at both
/// call sites since the strings are identical.
/// </summary>
/// <remarks>
/// These are the NAMES of JWK members (<c>"kty"</c>, <c>"crv"</c>, <c>"use"</c>,
/// <c>"alg"</c>), not their VALUES. Values like <c>"EC"</c>, <c>"P-256"</c>,
/// <c>"sig"</c>, <c>"ES256"</c> live in <see cref="WellKnownJwkValues"/>,
/// <see cref="WellKnownCurveValues"/>, <see cref="WellKnownKeyTypeValues"/>,
/// or <see cref="WellKnownJwaValues"/>.
/// </remarks>
public static class WellKnownJwkMemberNames
{
    /// <summary>
    /// The <c>alg</c> (Algorithm) parameter — JWK member per RFC 7517 §4.4 and
    /// JWS/JWE header parameter per RFC 7515 §4.1.1.
    /// </summary>
    public static readonly string Alg = "alg";

    /// <summary>
    /// The <c>crv</c> (Curve) parameter per RFC 7518 §6.2.1.1 — identifies the
    /// cryptographic curve used with an EC or OKP JWK.
    /// </summary>
    public static readonly string Crv = "crv";

    /// <summary>The <c>d</c> (ECC / OKP Private Key) parameter per RFC 7518 §6.2.2.1.</summary>
    public static readonly string D = "d";

    /// <summary>The <c>dp</c> (RSA Private Key) first-factor CRT exponent parameter per RFC 7518 §6.3.2.6.</summary>
    public static readonly string Dp = "dp";

    /// <summary>The <c>dq</c> (RSA Private Key) second-factor CRT exponent parameter per RFC 7518 §6.3.2.7.</summary>
    public static readonly string Dq = "dq";

    /// <summary>The <c>e</c> (RSA Public Key) exponent parameter per RFC 7518 §6.3.1.2.</summary>
    public static readonly string E = "e";

    /// <summary>The <c>k</c> (Symmetric Key Value) parameter per RFC 7518 §6.4.1.</summary>
    public static readonly string K = "k";

    /// <summary>The <c>key_ops</c> (Key Operations) parameter per RFC 7517 §4.3.</summary>
    public static readonly string KeyOps = "key_ops";

    /// <summary>The <c>keys</c> top-level member of a JWK Set document per RFC 7517 §5.1.</summary>
    public static readonly string Keys = "keys";

    /// <summary>
    /// The <c>kid</c> (Key ID) parameter — JWK member per RFC 7517 §4.5 and
    /// JWS/JWE header parameter per RFC 7515 §4.1.4.
    /// </summary>
    public static readonly string Kid = "kid";

    /// <summary>The <c>kty</c> (Key Type) parameter per RFC 7517 §4.1.</summary>
    public static readonly string Kty = "kty";

    /// <summary>The <c>n</c> (RSA Public Key) modulus parameter per RFC 7518 §6.3.1.1.</summary>
    public static readonly string N = "n";

    /// <summary>The <c>p</c> (RSA Private Key) first-prime-factor parameter per RFC 7518 §6.3.2.4.</summary>
    public static readonly string P = "p";

    /// <summary>
    /// The <c>pub</c> parameter for post-quantum JWK representations — applies to
    /// <c>kty=AKP</c> keys (ML-DSA-44/65/87) where the public key is raw bytes rather
    /// than named-curve coordinates or RSA factors. See
    /// <see href="https://datatracker.ietf.org/doc/draft-ietf-jose-pqc-kem">JOSE Post-Quantum Drafts</see>.
    /// </summary>
    public static readonly string Pub = "pub";

    /// <summary>The <c>q</c> (RSA Private Key) second-prime-factor parameter per RFC 7518 §6.3.2.5.</summary>
    public static readonly string Q = "q";

    /// <summary>The <c>qi</c> (RSA Private Key) first-CRT-coefficient parameter per RFC 7518 §6.3.2.8.</summary>
    public static readonly string Qi = "qi";

    /// <summary>
    /// The <c>use</c> (Public Key Use) parameter per RFC 7517 §4.2. Distinguishes
    /// keys intended for signature/MAC computation from keys intended for encryption.
    /// </summary>
    public static readonly string Use = "use";

    /// <summary>The <c>x</c> (EC / OKP Public Key) x-coordinate parameter per RFC 7518 §6.2.1.2.</summary>
    public static readonly string X = "x";

    /// <summary>
    /// The <c>x5c</c> (X.509 Certificate Chain) parameter — JWK member per RFC 7517 §4.7
    /// and JWS/JWE header parameter per RFC 7515 §4.1.6.
    /// </summary>
    public static readonly string X5c = "x5c";

    /// <summary>
    /// The <c>x5t</c> (X.509 SHA-1 Thumbprint) parameter — JWK member per RFC 7517 §4.8
    /// and JWS/JWE header parameter per RFC 7515 §4.1.7.
    /// </summary>
    public static readonly string X5t = "x5t";

    /// <summary>
    /// The <c>x5t#S256</c> (X.509 SHA-256 Thumbprint) parameter — JWK member per RFC 7517 §4.9
    /// and JWS/JWE header parameter per RFC 7515 §4.1.8.
    /// </summary>
    public static readonly string X5tHashS256 = "x5t#S256";

    /// <summary>
    /// The <c>x5u</c> (X.509 URL) parameter — JWK member per RFC 7517 §4.6 and
    /// JWS/JWE header parameter per RFC 7515 §4.1.5.
    /// </summary>
    public static readonly string X5u = "x5u";

    /// <summary>The <c>y</c> (EC Public Key) y-coordinate parameter per RFC 7518 §6.2.1.3.</summary>
    public static readonly string Y = "y";


    /// <summary>Whether <paramref name="name"/> is <see cref="Alg"/>.</summary>
    public static bool IsAlg(string name) => Equals(name, Alg);

    /// <summary>Whether <paramref name="name"/> is <see cref="Crv"/>.</summary>
    public static bool IsCrv(string name) => Equals(name, Crv);

    /// <summary>Whether <paramref name="name"/> is <see cref="D"/>.</summary>
    public static bool IsD(string name) => Equals(name, D);

    /// <summary>Whether <paramref name="name"/> is <see cref="Dp"/>.</summary>
    public static bool IsDp(string name) => Equals(name, Dp);

    /// <summary>Whether <paramref name="name"/> is <see cref="Dq"/>.</summary>
    public static bool IsDq(string name) => Equals(name, Dq);

    /// <summary>Whether <paramref name="name"/> is <see cref="E"/>.</summary>
    public static bool IsE(string name) => Equals(name, E);

    /// <summary>Whether <paramref name="name"/> is <see cref="K"/>.</summary>
    public static bool IsK(string name) => Equals(name, K);

    /// <summary>Whether <paramref name="name"/> is <see cref="KeyOps"/>.</summary>
    public static bool IsKeyOps(string name) => Equals(name, KeyOps);

    /// <summary>Whether <paramref name="name"/> is <see cref="Keys"/>.</summary>
    public static bool IsKeys(string name) => Equals(name, Keys);

    /// <summary>Whether <paramref name="name"/> is <see cref="Kid"/>.</summary>
    public static bool IsKid(string name) => Equals(name, Kid);

    /// <summary>Whether <paramref name="name"/> is <see cref="Kty"/>.</summary>
    public static bool IsKty(string name) => Equals(name, Kty);

    /// <summary>Whether <paramref name="name"/> is <see cref="N"/>.</summary>
    public static bool IsN(string name) => Equals(name, N);

    /// <summary>Whether <paramref name="name"/> is <see cref="P"/>.</summary>
    public static bool IsP(string name) => Equals(name, P);

    /// <summary>Whether <paramref name="name"/> is <see cref="Q"/>.</summary>
    public static bool IsQ(string name) => Equals(name, Q);

    /// <summary>Whether <paramref name="name"/> is <see cref="Qi"/>.</summary>
    public static bool IsQi(string name) => Equals(name, Qi);

    /// <summary>Whether <paramref name="name"/> is <see cref="Use"/>.</summary>
    public static bool IsUse(string name) => Equals(name, Use);

    /// <summary>Whether <paramref name="name"/> is <see cref="X"/>.</summary>
    public static bool IsX(string name) => Equals(name, X);

    /// <summary>Whether <paramref name="name"/> is <see cref="X5c"/>.</summary>
    public static bool IsX5c(string name) => Equals(name, X5c);

    /// <summary>Whether <paramref name="name"/> is <see cref="X5t"/>.</summary>
    public static bool IsX5t(string name) => Equals(name, X5t);

    /// <summary>Whether <paramref name="name"/> is <see cref="X5tHashS256"/>.</summary>
    public static bool IsX5tHashS256(string name) => Equals(name, X5tHashS256);

    /// <summary>Whether <paramref name="name"/> is <see cref="X5u"/>.</summary>
    public static bool IsX5u(string name) => Equals(name, X5u);

    /// <summary>Whether <paramref name="name"/> is <see cref="Y"/>.</summary>
    public static bool IsY(string name) => Equals(name, Y);


    /// <summary>
    /// Returns the interned constant for a known JWK member name, or the
    /// original string if unrecognized.
    /// </summary>
    public static string GetCanonicalizedValue(string name) => name switch
    {
        _ when IsAlg(name) => Alg,
        _ when IsCrv(name) => Crv,
        _ when IsD(name) => D,
        _ when IsDp(name) => Dp,
        _ when IsDq(name) => Dq,
        _ when IsE(name) => E,
        _ when IsK(name) => K,
        _ when IsKeyOps(name) => KeyOps,
        _ when IsKeys(name) => Keys,
        _ when IsKid(name) => Kid,
        _ when IsKty(name) => Kty,
        _ when IsN(name) => N,
        _ when IsP(name) => P,
        _ when IsQ(name) => Q,
        _ when IsQi(name) => Qi,
        _ when IsUse(name) => Use,
        _ when IsX(name) => X,
        _ when IsX5c(name) => X5c,
        _ when IsX5t(name) => X5t,
        _ when IsX5tHashS256(name) => X5tHashS256,
        _ when IsX5u(name) => X5u,
        _ when IsY(name) => Y,
        _ => name
    };


    /// <summary>
    /// Compares two JWK member names for equality. Comparison is case-sensitive
    /// per RFC 7517.
    /// </summary>
    public static bool Equals(string nameA, string nameB) =>
        object.ReferenceEquals(nameA, nameB) || StringComparer.Ordinal.Equals(nameA, nameB);
}
