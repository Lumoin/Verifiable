namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Parsed view of a COSE_Key per RFC 9052 §7, carried inside
/// <see cref="MdocDeviceKeyInfo.DeviceKey"/> on the wallet binding side of
/// an MSO.
/// </summary>
/// <remarks>
/// <para>
/// COSE_Key uses integer-keyed maps unlike JWK's string-keyed maps. The
/// well-known parameters per IANA COSE Key Common / Key Type registries:
/// <c>1 = kty</c>, <c>3 = alg</c>, <c>-1 = crv</c> (for EC/OKP keys),
/// <c>-2 = x</c>, <c>-3 = y</c> (uncompressed EC point components),
/// <c>-4 = d</c> (private scalar; absent on the device-public side).
/// </para>
/// <para>
/// This carrier is read-only and format-agnostic — the CBOR reader fills
/// it from the on-wire bytes. Application-side conversion to a typed
/// <c>PublicKeyMemory</c> tagged with the right
/// <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/> flows
/// through <c>CoseKeyToAlgorithmDelegate</c> at the conversions layer; the
/// MSO data model holds the parsed parameters verbatim so digest binding
/// and downstream key resolution stay independent.
/// </para>
/// </remarks>
public sealed class MdocCoseKey
{
    /// <summary>
    /// Initializes a COSE_Key view from its parsed parameters.
    /// </summary>
    /// <param name="kty">
    /// The <c>kty</c> (key type) parameter — IANA COSE Key Types registry value.
    /// <c>1 = OKP</c> (Ed25519/X25519), <c>2 = EC2</c> (NIST/Brainpool/secp256k1),
    /// <c>3 = RSA</c>, <c>4 = Symmetric</c>.
    /// </param>
    /// <param name="alg">
    /// The optional <c>alg</c> parameter — IANA COSE Algorithms registry value.
    /// <see langword="null"/> when the issuer leaves algorithm choice to
    /// out-of-band negotiation.
    /// </param>
    /// <param name="curve">
    /// The optional <c>crv</c> parameter — IANA COSE Elliptic Curves registry value.
    /// <c>1 = P-256</c>, <c>2 = P-384</c>, <c>3 = P-521</c>, <c>6 = Ed25519</c>,
    /// <c>7 = Ed448</c>, plus Brainpool / secp256k1 assignments. <see langword="null"/>
    /// for non-EC/non-OKP key types.
    /// </param>
    /// <param name="x">
    /// The X coordinate for EC2 keys, or the public-key bytes for OKP keys.
    /// <see langword="null"/> when the key type does not carry an X parameter.
    /// </param>
    /// <param name="y">
    /// The Y coordinate for EC2 keys. <see langword="null"/> for OKP keys (which
    /// have no Y) and for compressed EC2 forms (where Y is encoded as a bool
    /// indicating sign — this layer treats that as out of scope and surfaces it
    /// in <see cref="EncodedYCompressionSign"/>).
    /// </param>
    /// <param name="encodedYCompressionSign">
    /// Carries the parsed bool when the COSE_Key emits Y in its compressed
    /// (sign-bit) form rather than as an uncompressed coordinate.
    /// <see langword="null"/> for the uncompressed-coordinate path.
    /// </param>
    public MdocCoseKey(
        int kty,
        int? alg = null,
        int? curve = null,
        ReadOnlyMemory<byte>? x = null,
        ReadOnlyMemory<byte>? y = null,
        bool? encodedYCompressionSign = null)
    {
        Kty = kty;
        Alg = alg;
        Curve = curve;
        X = x;
        Y = y;
        EncodedYCompressionSign = encodedYCompressionSign;
    }


    /// <summary>The <c>kty</c> (key type) parameter, IANA COSE Key Types registry value.</summary>
    public int Kty { get; }

    /// <summary>The optional <c>alg</c> parameter, IANA COSE Algorithms registry value.</summary>
    public int? Alg { get; }

    /// <summary>The optional <c>crv</c> parameter, IANA COSE Elliptic Curves registry value.</summary>
    public int? Curve { get; }

    /// <summary>The X coordinate for EC2 keys, or the public-key bytes for OKP keys.</summary>
    public ReadOnlyMemory<byte>? X { get; }

    /// <summary>The Y coordinate for EC2 keys in uncompressed form.</summary>
    public ReadOnlyMemory<byte>? Y { get; }

    /// <summary>The Y compression sign for EC2 keys in compressed form.</summary>
    public bool? EncodedYCompressionSign { get; }
}


/// <summary>
/// IANA-registered <c>kty</c> values for COSE_Key per RFC 9052 §7.1.
/// </summary>
public static class MdocCoseKeyTypes
{
    /// <summary>Octet Key Pair — Ed25519/Ed448/X25519/X448.</summary>
    public const int Okp = 1;

    /// <summary>EC2 — double-coordinate EC curves (NIST P-curves, secp256k1, Brainpool).</summary>
    public const int Ec2 = 2;

    /// <summary>RSA — RSA key.</summary>
    public const int Rsa = 3;

    /// <summary>Symmetric — symmetric key.</summary>
    public const int Symmetric = 4;
}


/// <summary>
/// IANA-registered <c>crv</c> (curve) values for COSE_Key per the COSE
/// Elliptic Curves registry.
/// </summary>
public static class MdocCoseKeyCurves
{
    /// <summary>NIST P-256 (secp256r1).</summary>
    public const int P256 = 1;

    /// <summary>NIST P-384 (secp384r1).</summary>
    public const int P384 = 2;

    /// <summary>NIST P-521 (secp521r1).</summary>
    public const int P521 = 3;

    /// <summary>X25519 for ECDH per RFC 7748.</summary>
    public const int X25519 = 4;

    /// <summary>X448 for ECDH per RFC 7748.</summary>
    public const int X448 = 5;

    /// <summary>Ed25519 for EdDSA per RFC 8032.</summary>
    public const int Ed25519 = 6;

    /// <summary>Ed448 for EdDSA per RFC 8032.</summary>
    public const int Ed448 = 7;

    /// <summary>secp256k1 per RFC 8812.</summary>
    public const int Secp256k1 = 8;

    /// <summary>Brainpool P-256r1 per the COSE registration alongside RFC 9784.</summary>
    public const int BrainpoolP256r1 = 256;

    /// <summary>Brainpool P-320r1 per the COSE registration alongside RFC 9784.</summary>
    public const int BrainpoolP320r1 = 257;

    /// <summary>Brainpool P-384r1 per the COSE registration alongside RFC 9784.</summary>
    public const int BrainpoolP384r1 = 258;

    /// <summary>Brainpool P-512r1 per the COSE registration alongside RFC 9784.</summary>
    public const int BrainpoolP512r1 = 259;
}


/// <summary>
/// IANA-registered COSE_Key common parameter integer labels per RFC 9052 §7.1.
/// </summary>
public static class MdocCoseKeyParameters
{
    /// <summary>The <c>kty</c> label (1).</summary>
    public const int Kty = 1;

    /// <summary>The <c>kid</c> label (2).</summary>
    public const int Kid = 2;

    /// <summary>The <c>alg</c> label (3).</summary>
    public const int Alg = 3;

    /// <summary>The <c>key_ops</c> label (4).</summary>
    public const int KeyOps = 4;

    /// <summary>The <c>Base IV</c> label (5).</summary>
    public const int BaseIv = 5;

    /// <summary>The <c>crv</c> label (-1) for EC2 and OKP key types.</summary>
    public const int Crv = -1;

    /// <summary>The <c>x</c> label (-2) for EC2 and OKP key types.</summary>
    public const int X = -2;

    /// <summary>The <c>y</c> label (-3) for EC2 key types.</summary>
    public const int Y = -3;

    /// <summary>The <c>d</c> label (-4) for the private scalar (absent on public keys).</summary>
    public const int D = -4;
}
