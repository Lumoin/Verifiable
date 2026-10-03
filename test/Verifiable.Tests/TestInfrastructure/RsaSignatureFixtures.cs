using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using System.Formats.Asn1;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// RSA material no provider member exposes, for the rows that present an RSA verification member of either
/// provider with a public key or a signature of a chosen shape: a key pair whose primes are in hand, a modulus of a
/// chosen bit length, a signature made with a chosen private exponent, and a DER structure of a chosen shape. The
/// key pairs come from BouncyCastle's generator, the signatures from BouncyCastle's signers, and the DER from
/// <c>System.Formats.Asn1</c>; the member under test is always called through its provider's own class.
/// </summary>
internal static class RsaSignatureFixtures
{
    /// <summary>The public exponent 65537 the generated key pairs carry.</summary>
    public static BcBigInteger DefaultPublicExponent { get; } = BcBigInteger.ValueOf(65537);


    /// <summary>
    /// An odd RSA modulus of exactly 2400 bits (300 octets) with no small factor, which with
    /// <see cref="DefaultPublicExponent"/> is a valid RSA public key by
    /// <see cref="Verifiable.Cryptography.RsaUtilities.IsValidPublicKey"/>: the product of the first probable primes
    /// above 1.5 * 2^1199 and above 1.5 * 2^1199 + 1000000, computed once. Its octet length is neither 256 nor 512,
    /// and a signature of 256 octets is not k octets under it.
    /// </summary>
    public static Lazy<BcBigInteger> Modulus2400Bits { get; } = new(() =>
        BcBigInteger.Three.ShiftLeft(1198).NextProbablePrime().Multiply(BcBigInteger.Three.ShiftLeft(1198).Add(BcBigInteger.ValueOf(1_000_000)).NextProbablePrime()));


    /// <summary>
    /// Generates an RSA key pair whose modulus is exactly <paramref name="modulusBitLength"/> bits, with the public
    /// exponent <see cref="DefaultPublicExponent"/>.
    /// </summary>
    /// <param name="modulusBitLength">The bit length of the modulus.</param>
    /// <returns>The private key with its primes and CRT values.</returns>
    public static RsaPrivateCrtKeyParameters GeneratePrivateKey(int modulusBitLength)
    {
        RsaKeyPairGenerator generator = new();
        generator.Init(new RsaKeyGenerationParameters(DefaultPublicExponent, new SecureRandom(), modulusBitLength, 100));

        return (RsaPrivateCrtKeyParameters)generator.GenerateKeyPair().Private;
    }


    /// <summary>
    /// The DER <c>RSAPublicKey</c> of <paramref name="modulus"/> and <paramref name="exponent"/>, a SEQUENCE of the
    /// two INTEGERs.
    /// </summary>
    /// <param name="modulus">The modulus n.</param>
    /// <param name="exponent">The public exponent e.</param>
    /// <returns>The DER octets.</returns>
    public static byte[] EncodeRsaPublicKey(BcBigInteger modulus, BcBigInteger exponent) =>
        EncodeIntegerSequence(ToNumerics(modulus), ToNumerics(exponent));


    /// <summary>Encodes a DER SEQUENCE of the given INTEGERs, the shape of an <c>RSAPublicKey</c> when there are two.</summary>
    /// <param name="integers">The INTEGERs, in order.</param>
    /// <returns>The DER octets.</returns>
    public static byte[] EncodeIntegerSequence(params ReadOnlySpan<System.Numerics.BigInteger> integers)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            foreach(System.Numerics.BigInteger integer in integers)
            {
                writer.WriteInteger(integer);
            }
        }

        return writer.Encode();
    }


    /// <summary>Reads the modulus and the public exponent of a DER <c>RSAPublicKey</c>.</summary>
    /// <param name="der">The DER <c>RSAPublicKey</c>.</param>
    /// <returns>The modulus and the public exponent.</returns>
    public static (System.Numerics.BigInteger Modulus, System.Numerics.BigInteger Exponent) ReadRsaPublicKey(byte[] der)
    {
        AsnReader sequence = new AsnReader(der, AsnEncodingRules.DER).ReadSequence();

        return (sequence.ReadInteger(), sequence.ReadInteger());
    }


    /// <summary>Converts a BouncyCastle integer to the <c>System.Numerics</c> integer of the same non-negative value.</summary>
    /// <param name="value">The non-negative value.</param>
    /// <returns>The same value.</returns>
    public static System.Numerics.BigInteger ToNumerics(BcBigInteger value) =>
        new(value.ToByteArrayUnsigned(), isUnsigned: true, isBigEndian: true);


    /// <summary>
    /// The big-endian octets of <paramref name="value"/> at exactly <paramref name="length"/> octets, zeros first: the
    /// integer-to-octet-string conversion a signature of a modulus of that octet length is.
    /// </summary>
    /// <param name="value">The non-negative value, which fits <paramref name="length"/> octets.</param>
    /// <param name="length">The octet length.</param>
    /// <returns>The octets.</returns>
    public static byte[] ToOctets(BcBigInteger value, int length)
    {
        byte[] magnitude = value.ToByteArrayUnsigned();
        byte[] octets = new byte[length];
        magnitude.CopyTo(octets, length - magnitude.Length);

        return octets;
    }


    /// <summary>
    /// Signs <paramref name="data"/> with BouncyCastle's signer of <paramref name="scheme"/> and
    /// <paramref name="digest"/> under <paramref name="privateKey"/>, whatever its private exponent: RSASSA-PSS with
    /// MGF1 of the same digest and a salt of the digest's length, or RSASSA-PKCS1-v1_5. Under a private exponent of
    /// 1 the signature is the encoded message itself.
    /// </summary>
    /// <param name="scheme"><c>Pss</c> for RSASSA-PSS or <c>Pkcs1</c> for RSASSA-PKCS1-v1_5.</param>
    /// <param name="digest"><c>Sha256</c>, <c>Sha384</c> or <c>Sha512</c>.</param>
    /// <param name="privateKey">The private key, a modulus with a private exponent.</param>
    /// <param name="data">The data to sign.</param>
    /// <returns>The signature at the modulus's octet length.</returns>
    public static byte[] Sign(string scheme, string digest, RsaKeyParameters privateKey, byte[] data)
    {
        ISigner signer = scheme switch
        {
            "Pss" => new PssSigner(new RsaEngine(), CreateDigest(digest), CreateDigest(digest).GetDigestSize()),
            "Pkcs1" => new RsaDigestSigner(CreateDigest(digest)),
            _ => throw new ArgumentOutOfRangeException(nameof(scheme), scheme, "No such RSA signature scheme.")
        };

        ICipherParameters parameters = scheme switch
        {
            "Pss" => new ParametersWithRandom(privateKey, new SecureRandom()),
            _ => privateKey
        };

        signer.Init(forSigning: true, parameters);
        signer.BlockUpdate(data, 0, data.Length);

        return ToOctets(new BcBigInteger(1, signer.GenerateSignature()), (privateKey.Modulus.BitLength + 7) / 8);
    }


    /// <summary>The BouncyCastle digest named <paramref name="digest"/>.</summary>
    /// <param name="digest"><c>Sha256</c>, <c>Sha384</c> or <c>Sha512</c>.</param>
    /// <returns>A fresh digest.</returns>
    private static IDigest CreateDigest(string digest) => digest switch
    {
        "Sha256" => new Sha256Digest(),
        "Sha384" => new Sha384Digest(),
        "Sha512" => new Sha512Digest(),
        _ => throw new ArgumentOutOfRangeException(nameof(digest), digest, "No such digest.")
    };
}
