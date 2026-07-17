using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.JCose;

/// <summary>
/// Parsed view of a COSE_Key per RFC 9052 §7, carried inside
/// <c>MdocDeviceKeyInfo.DeviceKey</c> on the wallet binding side of
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
/// For RSA keys (<c>kty = 3</c>), <see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>
/// overloads the same integer labels: <c>-1 = n</c> (modulus) and
/// <c>-2 = e</c> (exponent), surfaced here as <see cref="N"/> and
/// <see cref="E"/> rather than <see cref="X"/> and <see cref="Y"/>.
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
/// <para>
/// <strong>Equality.</strong> Two <see cref="CoseKey"/> instances are equal when every scalar
/// parameter matches and every memory-backed parameter is byte-for-byte equal — the same
/// content-equality posture <c>PublicKeyJwk</c> (the closest structural sibling, a parsed key
/// view) applies to its own dictionary-backed parameters, rather than the reference/alias
/// equality a synthesized comparison of <see cref="ReadOnlyMemory{T}"/> members would give two
/// independently parsed views of the same wire key.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class CoseKey: IEquatable<CoseKey>
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
    /// <param name="n">
    /// The RSA modulus per <see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>
    /// label <c>-1</c>. <see langword="null"/> when <see cref="Kty"/> is not RSA (<c>3</c>).
    /// </param>
    /// <param name="e">
    /// The RSA public exponent per <see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>
    /// label <c>-2</c>. <see langword="null"/> when <see cref="Kty"/> is not RSA (<c>3</c>).
    /// </param>
    public CoseKey(
        int kty,
        int? alg = null,
        int? curve = null,
        ReadOnlyMemory<byte>? x = null,
        ReadOnlyMemory<byte>? y = null,
        bool? encodedYCompressionSign = null,
        ReadOnlyMemory<byte>? n = null,
        ReadOnlyMemory<byte>? e = null)
    {
        Kty = kty;
        Alg = alg;
        Curve = curve;
        X = x;
        Y = y;
        EncodedYCompressionSign = encodedYCompressionSign;
        N = n;
        E = e;
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

    /// <summary>
    /// The RSA modulus, label <c>-1</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>.
    /// Meaningful when <see cref="Kty"/> is RSA (<c>3</c>).
    /// </summary>
    public ReadOnlyMemory<byte>? N { get; }

    /// <summary>
    /// The RSA public exponent, label <c>-2</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>.
    /// Meaningful when <see cref="Kty"/> is RSA (<c>3</c>).
    /// </summary>
    public ReadOnlyMemory<byte>? E { get; }


    /// <summary>
    /// Determines whether this instance and <paramref name="other"/> carry the same COSE_Key
    /// parameters: equal scalar values and byte-for-byte equal memory-backed values.
    /// </summary>
    /// <param name="other">The other instance to compare against.</param>
    /// <returns>
    /// <see langword="true"/> if every parameter matches; otherwise <see langword="false"/>.
    /// </returns>
    public bool Equals([NotNullWhen(true)] CoseKey? other)
    {
        return other is not null
            && Kty == other.Kty
            && Alg == other.Alg
            && Curve == other.Curve
            && EncodedYCompressionSign == other.EncodedYCompressionSign
            && MemoryValuesEqual(X, other.X)
            && MemoryValuesEqual(Y, other.Y)
            && MemoryValuesEqual(N, other.N)
            && MemoryValuesEqual(E, other.E);

        //Compares two optional memory-backed parameters by content rather than by the reference
        //identity ReadOnlyMemory{T}'s own default equality would use, treating "absent" as equal
        //only to "absent".
        static bool MemoryValuesEqual(ReadOnlyMemory<byte>? left, ReadOnlyMemory<byte>? right)
        {
            if(left is null || right is null)
            {
                return left is null && right is null;
            }

            return left.Value.Span.SequenceEqual(right.Value.Span);
        }
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj)
    {
        return obj is CoseKey other && Equals(other);
    }


    /// <summary>
    /// Computes a hash code consistent with <see cref="Equals(CoseKey?)"/>. The memory-backed
    /// parameters contribute their lengths rather than their contents — two equal keys always
    /// have equal lengths, so this remains consistent with equality while avoiding hashing
    /// potentially large key material.
    /// </summary>
    /// <returns>The hash code.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.Add(Kty);
        hash.Add(Alg);
        hash.Add(Curve);
        hash.Add(EncodedYCompressionSign);
        hash.Add(X?.Length ?? -1);
        hash.Add(Y?.Length ?? -1);
        hash.Add(N?.Length ?? -1);
        hash.Add(E?.Length ?? -1);

        return hash.ToHashCode();
    }


    /// <summary>
    /// Determines whether two <see cref="CoseKey"/> instances carry the same COSE_Key parameters.
    /// </summary>
    public static bool operator ==(CoseKey? left, CoseKey? right) =>
        left is null ? right is null : left.Equals(right);


    /// <summary>
    /// Determines whether two <see cref="CoseKey"/> instances carry different COSE_Key parameters.
    /// </summary>
    public static bool operator !=(CoseKey? left, CoseKey? right) => !(left == right);


    /// <inheritdoc/>
    public override string ToString() => DebuggerDisplay;


    /// <summary>
    /// A debugger-friendly summary of the key type, algorithm, curve, and the key-material
    /// parameters that apply to <see cref="Kty"/>.
    /// </summary>
    private string DebuggerDisplay
    {
        get
        {
            string keyMaterial = Kty switch
            {
                CoseKeyTypes.Rsa => $"N={N?.Length ?? 0} bytes, E={E?.Length ?? 0} bytes",
                CoseKeyTypes.Ec2 => $"X={X?.Length ?? 0} bytes, Y={Y?.Length ?? 0} bytes",
                CoseKeyTypes.Okp => $"X={X?.Length ?? 0} bytes",
                _ => "no key material"
            };

            return $"CoseKey(Kty={Kty}, Alg={Alg}, Curve={Curve}, {keyMaterial})";
        }
    }
}


/// <summary>
/// IANA-registered <c>kty</c> values for COSE_Key per RFC 9052 §7.1.
/// </summary>
public static class CoseKeyTypes
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
public static class CoseKeyCurves
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

    /// <summary>Brainpool P-256r1 per the COSE registration alongside RFC 9864.</summary>
    public const int BrainpoolP256r1 = 256;

    /// <summary>Brainpool P-320r1 per the COSE registration alongside RFC 9864.</summary>
    public const int BrainpoolP320r1 = 257;

    /// <summary>Brainpool P-384r1 per the COSE registration alongside RFC 9864.</summary>
    public const int BrainpoolP384r1 = 258;

    /// <summary>Brainpool P-512r1 per the COSE registration alongside RFC 9864.</summary>
    public const int BrainpoolP512r1 = 259;
}


/// <summary>
/// IANA-registered COSE_Key common parameter integer labels per RFC 9052 §7.1.
/// </summary>
public static class CoseKeyParameters
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

    /// <summary>
    /// The RSA modulus label (-1), overloading <see cref="Crv"/> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>.
    /// </summary>
    public const int RsaN = -1;

    /// <summary>
    /// The RSA public exponent label (-2), overloading <see cref="X"/> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>.
    /// </summary>
    public const int RsaE = -2;

    /// <summary>
    /// The RSA private exponent label (-3) per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>.
    /// A public key carrying this label MUST be rejected by parsers; the
    /// CBOR-layer enforcement lands with the upcoming codec switch.
    /// </summary>
    public const int RsaD = -3;

    /// <summary>
    /// The RSA first prime factor label (-4) per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>.
    /// A public key carrying this label MUST be rejected by parsers; the
    /// CBOR-layer enforcement lands with the upcoming codec switch.
    /// </summary>
    public const int RsaP = -4;

    /// <summary>
    /// The RSA second prime factor label (-5) per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>.
    /// A public key carrying this label MUST be rejected by parsers; the
    /// CBOR-layer enforcement lands with the upcoming codec switch.
    /// </summary>
    public const int RsaQ = -5;

    /// <summary>
    /// The RSA first factor CRT exponent label (-6) per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>.
    /// A public key carrying this label MUST be rejected by parsers; the
    /// CBOR-layer enforcement lands with the upcoming codec switch.
    /// </summary>
    public const int RsaDP = -6;

    /// <summary>
    /// The RSA second factor CRT exponent label (-7) per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>.
    /// A public key carrying this label MUST be rejected by parsers; the
    /// CBOR-layer enforcement lands with the upcoming codec switch.
    /// </summary>
    public const int RsaDQ = -7;

    /// <summary>
    /// The RSA first CRT coefficient label (-8) per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>.
    /// A public key carrying this label MUST be rejected by parsers; the
    /// CBOR-layer enforcement lands with the upcoming codec switch.
    /// </summary>
    public const int RsaQInv = -8;

    /// <summary>
    /// The RSA other primes info label (-9) per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>.
    /// A public key carrying this label MUST be rejected by parsers; the
    /// CBOR-layer enforcement lands with the upcoming codec switch.
    /// </summary>
    public const int RsaOther = -9;

    /// <summary>
    /// The RSA additional prime factor label (-10) per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>.
    /// A public key carrying this label MUST be rejected by parsers; the
    /// CBOR-layer enforcement lands with the upcoming codec switch.
    /// </summary>
    public const int RsaRI = -10;

    /// <summary>
    /// The RSA additional factor CRT exponent label (-11) per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>.
    /// A public key carrying this label MUST be rejected by parsers; the
    /// CBOR-layer enforcement lands with the upcoming codec switch.
    /// </summary>
    public const int RsaDI = -11;

    /// <summary>
    /// The RSA additional factor CRT coefficient label (-12) per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>.
    /// A public key carrying this label MUST be rejected by parsers; the
    /// CBOR-layer enforcement lands with the upcoming codec switch.
    /// </summary>
    public const int RsaTI = -12;
}
