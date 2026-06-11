using Verifiable.Cryptography.Text;


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
    /// <summary>The UTF-8 source literal of <see cref="Alg"/>.</summary>
    public static ReadOnlySpan<byte> AlgUtf8 => "alg"u8;

    /// <summary>
    /// The <c>alg</c> (Algorithm) parameter — JWK member per RFC 7517 §4.4 and
    /// JWS/JWE header parameter per RFC 7515 §4.1.1.
    /// </summary>
    public static readonly string Alg = Utf8Constants.ToInternedString(AlgUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Crv"/>.</summary>
    public static ReadOnlySpan<byte> CrvUtf8 => "crv"u8;

    /// <summary>
    /// The <c>crv</c> (Curve) parameter per RFC 7518 §6.2.1.1 — identifies the
    /// cryptographic curve used with an EC or OKP JWK.
    /// </summary>
    public static readonly string Crv = Utf8Constants.ToInternedString(CrvUtf8);

    /// <summary>The UTF-8 source literal of <see cref="D"/>.</summary>
    public static ReadOnlySpan<byte> DUtf8 => "d"u8;

    /// <summary>The <c>d</c> (ECC / OKP Private Key) parameter per RFC 7518 §6.2.2.1.</summary>
    public static readonly string D = Utf8Constants.ToInternedString(DUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Dp"/>.</summary>
    public static ReadOnlySpan<byte> DpUtf8 => "dp"u8;

    /// <summary>The <c>dp</c> (RSA Private Key) first-factor CRT exponent parameter per RFC 7518 §6.3.2.6.</summary>
    public static readonly string Dp = Utf8Constants.ToInternedString(DpUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Dq"/>.</summary>
    public static ReadOnlySpan<byte> DqUtf8 => "dq"u8;

    /// <summary>The <c>dq</c> (RSA Private Key) second-factor CRT exponent parameter per RFC 7518 §6.3.2.7.</summary>
    public static readonly string Dq = Utf8Constants.ToInternedString(DqUtf8);

    /// <summary>The UTF-8 source literal of <see cref="E"/>.</summary>
    public static ReadOnlySpan<byte> EUtf8 => "e"u8;

    /// <summary>The <c>e</c> (RSA Public Key) exponent parameter per RFC 7518 §6.3.1.2.</summary>
    public static readonly string E = Utf8Constants.ToInternedString(EUtf8);

    /// <summary>The UTF-8 source literal of <see cref="K"/>.</summary>
    public static ReadOnlySpan<byte> KUtf8 => "k"u8;

    /// <summary>The <c>k</c> (Symmetric Key Value) parameter per RFC 7518 §6.4.1.</summary>
    public static readonly string K = Utf8Constants.ToInternedString(KUtf8);

    /// <summary>The UTF-8 source literal of <see cref="KeyOps"/>.</summary>
    public static ReadOnlySpan<byte> KeyOpsUtf8 => "key_ops"u8;

    /// <summary>The <c>key_ops</c> (Key Operations) parameter per RFC 7517 §4.3.</summary>
    public static readonly string KeyOps = Utf8Constants.ToInternedString(KeyOpsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Keys"/>.</summary>
    public static ReadOnlySpan<byte> KeysUtf8 => "keys"u8;

    /// <summary>The <c>keys</c> top-level member of a JWK Set document per RFC 7517 §5.1.</summary>
    public static readonly string Keys = Utf8Constants.ToInternedString(KeysUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Kid"/>.</summary>
    public static ReadOnlySpan<byte> KidUtf8 => "kid"u8;

    /// <summary>
    /// The <c>kid</c> (Key ID) parameter — JWK member per RFC 7517 §4.5 and
    /// JWS/JWE header parameter per RFC 7515 §4.1.4.
    /// </summary>
    public static readonly string Kid = Utf8Constants.ToInternedString(KidUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Kty"/>.</summary>
    public static ReadOnlySpan<byte> KtyUtf8 => "kty"u8;

    /// <summary>The <c>kty</c> (Key Type) parameter per RFC 7517 §4.1.</summary>
    public static readonly string Kty = Utf8Constants.ToInternedString(KtyUtf8);

    /// <summary>The UTF-8 source literal of <see cref="N"/>.</summary>
    public static ReadOnlySpan<byte> NUtf8 => "n"u8;

    /// <summary>The <c>n</c> (RSA Public Key) modulus parameter per RFC 7518 §6.3.1.1.</summary>
    public static readonly string N = Utf8Constants.ToInternedString(NUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Oth"/>.</summary>
    public static ReadOnlySpan<byte> OthUtf8 => "oth"u8;

    /// <summary>The <c>oth</c> (RSA Private Key) other-primes-info array parameter per RFC 7518 §6.3.2.7.</summary>
    public static readonly string Oth = Utf8Constants.ToInternedString(OthUtf8);

    /// <summary>The UTF-8 source literal of <see cref="P"/>.</summary>
    public static ReadOnlySpan<byte> PUtf8 => "p"u8;

    /// <summary>The <c>p</c> (RSA Private Key) first-prime-factor parameter per RFC 7518 §6.3.2.4.</summary>
    public static readonly string P = Utf8Constants.ToInternedString(PUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Pub"/>.</summary>
    public static ReadOnlySpan<byte> PubUtf8 => "pub"u8;

    /// <summary>
    /// The <c>pub</c> parameter for post-quantum JWK representations — applies to
    /// <c>kty=AKP</c> keys (ML-DSA-44/65/87) where the public key is raw bytes rather
    /// than named-curve coordinates or RSA factors. See
    /// <see href="https://datatracker.ietf.org/doc/draft-ietf-jose-pqc-kem">JOSE Post-Quantum Drafts</see>.
    /// </summary>
    public static readonly string Pub = Utf8Constants.ToInternedString(PubUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Priv"/>.</summary>
    public static ReadOnlySpan<byte> PrivUtf8 => "priv"u8;

    /// <summary>
    /// The <c>priv</c> (AKP private key) parameter of an Algorithm Key Pair JWK
    /// (<c>kty</c> <c>AKP</c>, e.g. ML-DSA). A published JWK must never carry it.
    /// </summary>
    public static readonly string Priv = Utf8Constants.ToInternedString(PrivUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Q"/>.</summary>
    public static ReadOnlySpan<byte> QUtf8 => "q"u8;

    /// <summary>The <c>q</c> (RSA Private Key) second-prime-factor parameter per RFC 7518 §6.3.2.5.</summary>
    public static readonly string Q = Utf8Constants.ToInternedString(QUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Qi"/>.</summary>
    public static ReadOnlySpan<byte> QiUtf8 => "qi"u8;

    /// <summary>The <c>qi</c> (RSA Private Key) first-CRT-coefficient parameter per RFC 7518 §6.3.2.8.</summary>
    public static readonly string Qi = Utf8Constants.ToInternedString(QiUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Use"/>.</summary>
    public static ReadOnlySpan<byte> UseUtf8 => "use"u8;

    /// <summary>
    /// The <c>use</c> (Public Key Use) parameter per RFC 7517 §4.2. Distinguishes
    /// keys intended for signature/MAC computation from keys intended for encryption.
    /// </summary>
    public static readonly string Use = Utf8Constants.ToInternedString(UseUtf8);

    /// <summary>The UTF-8 source literal of <see cref="X"/>.</summary>
    public static ReadOnlySpan<byte> XUtf8 => "x"u8;

    /// <summary>The <c>x</c> (EC / OKP Public Key) x-coordinate parameter per RFC 7518 §6.2.1.2.</summary>
    public static readonly string X = Utf8Constants.ToInternedString(XUtf8);

    /// <summary>The UTF-8 source literal of <see cref="X5c"/>.</summary>
    public static ReadOnlySpan<byte> X5cUtf8 => "x5c"u8;

    /// <summary>
    /// The <c>x5c</c> (X.509 Certificate Chain) parameter — JWK member per RFC 7517 §4.7
    /// and JWS/JWE header parameter per RFC 7515 §4.1.6.
    /// </summary>
    public static readonly string X5c = Utf8Constants.ToInternedString(X5cUtf8);

    /// <summary>The UTF-8 source literal of <see cref="X5t"/>.</summary>
    public static ReadOnlySpan<byte> X5tUtf8 => "x5t"u8;

    /// <summary>
    /// The <c>x5t</c> (X.509 SHA-1 Thumbprint) parameter — JWK member per RFC 7517 §4.8
    /// and JWS/JWE header parameter per RFC 7515 §4.1.7.
    /// </summary>
    public static readonly string X5t = Utf8Constants.ToInternedString(X5tUtf8);

    /// <summary>The UTF-8 source literal of <see cref="X5tHashS256"/>.</summary>
    public static ReadOnlySpan<byte> X5tHashS256Utf8 => "x5t#S256"u8;

    /// <summary>
    /// The <c>x5t#S256</c> (X.509 SHA-256 Thumbprint) parameter — JWK member per RFC 7517 §4.9
    /// and JWS/JWE header parameter per RFC 7515 §4.1.8.
    /// </summary>
    public static readonly string X5tHashS256 = Utf8Constants.ToInternedString(X5tHashS256Utf8);

    /// <summary>The UTF-8 source literal of <see cref="X5u"/>.</summary>
    public static ReadOnlySpan<byte> X5uUtf8 => "x5u"u8;

    /// <summary>
    /// The <c>x5u</c> (X.509 URL) parameter — JWK member per RFC 7517 §4.6 and
    /// JWS/JWE header parameter per RFC 7515 §4.1.5.
    /// </summary>
    public static readonly string X5u = Utf8Constants.ToInternedString(X5uUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Y"/>.</summary>
    public static ReadOnlySpan<byte> YUtf8 => "y"u8;

    /// <summary>The <c>y</c> (EC Public Key) y-coordinate parameter per RFC 7518 §6.2.1.3.</summary>
    public static readonly string Y = Utf8Constants.ToInternedString(YUtf8);


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


    /// <summary>
    /// The private / secret JWK members: the EC/OKP private scalar
    /// (<see cref="D"/>), the RSA private factors (<see cref="D"/>, <see cref="P"/>,
    /// <see cref="Q"/>, <see cref="Dp"/>, <see cref="Dq"/>, <see cref="Qi"/>,
    /// <see cref="Oth"/>), the symmetric key value (<see cref="K"/>), and the AKP
    /// private key (<see cref="Priv"/>, e.g. ML-DSA). A PUBLISHED JWK — a DPoP proof
    /// header, a SIOPv2 <c>sub_jwk</c>, a federation Entity Statement <c>jwks</c>, a
    /// discovery-document key — must carry none of these.
    /// </summary>
    public static IReadOnlyList<string> PrivateAndSymmetricMembers { get; } =
        [D, P, Q, Dp, Dq, Qi, Oth, K, Priv];

    private static readonly HashSet<string> PrivateAndSymmetricMemberSet =
        new(PrivateAndSymmetricMembers, StringComparer.Ordinal);


    /// <summary>
    /// Whether <paramref name="name"/> is one of the private / symmetric JWK
    /// members in <see cref="PrivateAndSymmetricMembers"/>.
    /// </summary>
    public static bool IsPrivateOrSymmetricMember(string name) =>
        PrivateAndSymmetricMemberSet.Contains(name);


    /// <summary>
    /// Whether any name in <paramref name="memberNames"/> is a private or symmetric
    /// JWK member — i.e. the JWK carries non-public key material. Works off member
    /// NAMES, so it serves any JWK representation (string- or object-valued maps):
    /// pass the map's <c>Keys</c>.
    /// </summary>
    public static bool ContainsPrivateOrSymmetricMember(IEnumerable<string> memberNames)
    {
        ArgumentNullException.ThrowIfNull(memberNames);

        foreach(string name in memberNames)
        {
            if(PrivateAndSymmetricMemberSet.Contains(name))
            {
                return true;
            }
        }

        return false;
    }
}
