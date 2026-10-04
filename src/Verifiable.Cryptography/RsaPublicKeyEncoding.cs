using System.Formats.Asn1;
using System.Numerics;

namespace Verifiable.Cryptography;

/// <summary>
/// Converts RSA public keys between their unsigned big-endian parameters and the DER PKCS#1
/// <c>RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }</c> representation.
/// Every conversion retains both parameters. A format that carries a DER key (<see cref="Decode"/>)
/// is read as exactly that DER; a public key the library holds is read by <see cref="DecodeKeyMaterial"/>,
/// where octets that are not exactly a DER key are the bare modulus they spell under 65537.
/// </summary>
public static class RsaPublicKeyEncoding
{
    /// <summary>The public exponent 65537 a bare modulus is read under, as unsigned big-endian octets.</summary>
    private static ReadOnlySpan<byte> BareModulusExponent => [0x01, 0x00, 0x01];


    /// <summary>
    /// Reads an RSA public key the library holds by the one rule both verification providers read it by: octets
    /// that are exactly one DER PKCS#1 <c>RSAPublicKey</c> keep the modulus and the public exponent they carry, and any
    /// other octets are the bare modulus they spell under the public exponent 65537, written in its minimum number of
    /// octets. Either reading is held to the necessary RSA conditions <see cref="Decode"/> holds a DER key to: a
    /// positive modulus and an odd exponent with <c>3 &lt;= e &lt; n</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8017#section-3.1">RFC 8017 Section 3.1</see>). A key that carries
    /// its exponent is never read under 65537.
    /// </summary>
    /// <param name="publicKey">The public key octets as the library holds them.</param>
    /// <returns>The modulus and public exponent.</returns>
    /// <exception cref="RsaPublicKeyException">
    /// An exact DER key whose modulus or exponent is invalid, or a bare modulus that is empty, begins with a zero
    /// octet or does not exceed 65537.
    /// </exception>
    public static (byte[] Modulus, byte[] Exponent) DecodeKeyMaterial(ReadOnlySpan<byte> publicKey)
    {
        if(TryReadSequence(publicKey, out BigInteger derModulus, out BigInteger derExponent))
        {
            Validate(derModulus, derExponent);

            return (derModulus.ToByteArray(isUnsigned: true, isBigEndian: true),
                derExponent.ToByteArray(isUnsigned: true, isBigEndian: true));
        }

        if(publicKey.IsEmpty || publicKey[0] == 0)
        {
            throw new RsaPublicKeyException(RsaPublicKeyFailureKind.MalformedEncoding,
                "A bare RSA modulus must be written in its minimum number of octets.");
        }

        Validate(
            new BigInteger(publicKey, isUnsigned: true, isBigEndian: true),
            new BigInteger(BareModulusExponent, isUnsigned: true, isBigEndian: true));

        return (publicKey.ToArray(), BareModulusExponent.ToArray());
    }


    /// <summary>
    /// Reads octets that are exactly one DER SEQUENCE of two INTEGERs, the shape of an <c>RSAPublicKey</c>, with nothing
    /// before or after either INTEGER and nothing after the SEQUENCE.
    /// </summary>
    /// <param name="publicKey">The octets to read.</param>
    /// <param name="modulus">The first INTEGER, when read.</param>
    /// <param name="exponent">The second INTEGER, when read.</param>
    /// <returns><see langword="true"/> when the octets are exactly that SEQUENCE.</returns>
    private static bool TryReadSequence(ReadOnlySpan<byte> publicKey, out BigInteger modulus, out BigInteger exponent)
    {
        modulus = BigInteger.Zero;
        exponent = BigInteger.Zero;
        try
        {
            AsnReader reader = new(publicKey.ToArray(), AsnEncodingRules.DER);
            AsnReader sequence = reader.ReadSequence();
            modulus = sequence.ReadInteger();
            exponent = sequence.ReadInteger();
            sequence.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();

            return true;
        }
        catch(AsnContentException)
        {
            return false;
        }
    }


    /// <summary>Encodes the supplied modulus and public exponent as a DER PKCS#1 public key.</summary>
    /// <param name="modulus">The unsigned big-endian modulus.</param>
    /// <param name="publicExponent">The unsigned big-endian public exponent.</param>
    /// <returns>The DER encoding carrying both supplied parameters.</returns>
    /// <exception cref="RsaPublicKeyException">The modulus is not positive or the exponent is invalid.</exception>
    public static byte[] Encode(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> publicExponent)
    {
        BigInteger n = new(modulus, isUnsigned: true, isBigEndian: true);
        BigInteger e = new(publicExponent, isUnsigned: true, isBigEndian: true);
        Validate(n, e);

        AsnWriter writer = new(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteInteger(n);
            writer.WriteInteger(e);
        }

        return writer.Encode();
    }


    /// <summary>
    /// Reads exactly one DER PKCS#1 public key and returns both unsigned big-endian parameters.
    /// Malformed DER and invalid exponents are refused without interpreting the input as a bare modulus.
    /// </summary>
    /// <param name="publicKey">The DER-encoded RSA public key.</param>
    /// <returns>The modulus and public exponent.</returns>
    /// <exception cref="RsaPublicKeyException">The encoding, modulus, or public exponent is invalid.</exception>
    public static (byte[] Modulus, byte[] Exponent) Decode(ReadOnlySpan<byte> publicKey)
    {
        if(!TryReadSequence(publicKey, out BigInteger modulus, out BigInteger exponent))
        {
            throw new RsaPublicKeyException(RsaPublicKeyFailureKind.MalformedEncoding,
                "An RSA public key must be a DER sequence containing exactly its modulus and public exponent.");
        }

        Validate(modulus, exponent);

        return (modulus.ToByteArray(isUnsigned: true, isBigEndian: true),
            exponent.ToByteArray(isUnsigned: true, isBigEndian: true));
    }


    /// <summary>
    /// Checks the public exponent's necessary RSA conditions: odd and <c>3 &lt;= e &lt; n</c>.
    /// Modulus-size policies remain with the caller; the prime factors are not available here.
    /// </summary>
    /// <param name="modulus">The modulus.</param>
    /// <param name="publicExponent">The public exponent.</param>
    private static void Validate(BigInteger modulus, BigInteger publicExponent)
    {
        if(modulus.Sign <= 0)
        {
            throw new RsaPublicKeyException(RsaPublicKeyFailureKind.InvalidModulus,
                "The RSA modulus must be positive.");
        }

        if(publicExponent < 3 || publicExponent.IsEven || publicExponent >= modulus)
        {
            throw new RsaPublicKeyException(RsaPublicKeyFailureKind.InvalidPublicExponent,
                "The RSA public exponent must be odd and satisfy 3 <= e < n.");
        }
    }
}
