using System.Formats.Asn1;
using System.Numerics;

namespace Verifiable.Cryptography;

/// <summary>
/// Converts RSA public keys between their unsigned big-endian parameters and the DER PKCS#1
/// <c>RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }</c> representation.
/// Every conversion retains both parameters; a bare modulus does not identify a public key.
/// </summary>
public static class RsaPublicKeyEncoding
{
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
        try
        {
            AsnReader reader = new(publicKey.ToArray(), AsnEncodingRules.DER);
            AsnReader sequence = reader.ReadSequence();
            BigInteger modulus = sequence.ReadInteger();
            BigInteger exponent = sequence.ReadInteger();
            sequence.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();
            Validate(modulus, exponent);

            return (modulus.ToByteArray(isUnsigned: true, isBigEndian: true),
                exponent.ToByteArray(isUnsigned: true, isBigEndian: true));
        }
        catch(AsnContentException exception)
        {
            throw new RsaPublicKeyException(RsaPublicKeyFailureKind.MalformedEncoding,
                "An RSA public key must be a DER sequence containing exactly its modulus and public exponent.", exception);
        }
    }


    /// <summary>
    /// Which necessary RSA condition the supplied unsigned big-endian parameters break, read without an exception: a modulus that
    /// is not positive, or a public exponent that is not odd with <c>3 &lt;= e &lt; n</c>; <see langword="null"/> when they break
    /// none. Modulus-size policies remain with the caller; the prime factors are not available here.
    /// </summary>
    /// <param name="modulus">The unsigned big-endian modulus.</param>
    /// <param name="publicExponent">The unsigned big-endian public exponent.</param>
    /// <returns>The broken condition, or <see langword="null"/>.</returns>
    public static RsaPublicKeyFailureKind? ParameterDefectOf(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> publicExponent) =>
        DefectOf(new BigInteger(modulus, isUnsigned: true, isBigEndian: true), new BigInteger(publicExponent, isUnsigned: true, isBigEndian: true));


    /// <summary>Which necessary RSA condition the parameters break, or <see langword="null"/> when they break none.</summary>
    /// <param name="modulus">The modulus.</param>
    /// <param name="publicExponent">The public exponent.</param>
    /// <returns>The broken condition, or <see langword="null"/>.</returns>
    private static RsaPublicKeyFailureKind? DefectOf(BigInteger modulus, BigInteger publicExponent)
    {
        if(modulus.Sign <= 0)
        {
            return RsaPublicKeyFailureKind.InvalidModulus;
        }

        return publicExponent < 3 || publicExponent.IsEven || publicExponent >= modulus ? RsaPublicKeyFailureKind.InvalidPublicExponent : null;
    }


    /// <summary>
    /// Checks the public exponent's necessary RSA conditions: odd and <c>3 &lt;= e &lt; n</c>.
    /// Modulus-size policies remain with the caller; the prime factors are not available here.
    /// </summary>
    /// <param name="modulus">The modulus.</param>
    /// <param name="publicExponent">The public exponent.</param>
    private static void Validate(BigInteger modulus, BigInteger publicExponent)
    {
        var defect = DefectOf(modulus, publicExponent);

        if(defect == RsaPublicKeyFailureKind.InvalidModulus)
        {
            throw new RsaPublicKeyException(RsaPublicKeyFailureKind.InvalidModulus,
                "The RSA modulus must be positive.");
        }

        if(defect == RsaPublicKeyFailureKind.InvalidPublicExponent)
        {
            throw new RsaPublicKeyException(RsaPublicKeyFailureKind.InvalidPublicExponent,
                "The RSA public exponent must be odd and satisfy 3 <= e < n.");
        }
    }
}
