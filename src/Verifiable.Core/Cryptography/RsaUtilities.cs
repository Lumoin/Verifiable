using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace Verifiable.Core.Cryptography
{
    /// <summary>
    /// These are some helper bit functions to work with RSA key material.
    /// </summary>
    public static class RsaUtilities
    {
        /// <summary>
        /// The exponent used by did:key RSA keys and is a common default value in RSA cryotography.
        /// </summary>
        /// <remarks>
        /// The definitions are at <see href="https://w3c-ccg.github.io/did-method-key/#x2048-bit-modulus-public-exponent-65537">
        /// did:key 2048 bit modulus public exponent</see>. This the same as 0x10001 or 65537 or
        /// ReadOnlySpan<byte> RsaExponent65537 = new byte[] { 0x01, 0x00, 0x01 };
        /// This translates to "AQAB" in Base64.        
        /// </remarks>        
        public static readonly string DefaultExponent = "AQAB";

        /// <summary>
        /// The 2048 byte RSA ASN.1 DER encoded prefix as defined at <see href="https://w3c-ccg.github.io/did-method-key/#x2048-bit-modulus-public-exponent-65537"/>.
        /// </summary>
        public static ReadOnlySpan<byte> Rsa2048Prefix => new byte[] { 0x30, 0x82, 0x01, 0xa, 0x02, 0x82, 0x01, 0x01 };

        /// <summary>        
        /// The 2048 byte RSA ASN.1 DER encoded prefix as defined at <see href="https://w3c-ccg.github.io/did-method-key/#x4096-bit-modulus-public-exponent-65537"/>.
        /// </summary>
        public static ReadOnlySpan<byte> Rsa4096Prefix => new byte[] { 0x30, 0x82, 0x02, 0xa, 0x02, 0x82, 0x02, 0x01 };

        /// <summary>
        /// The suffix for both <see cref="Rsa2048Prefix"/> and <see cref="Rsa4096Prefix"/> ASN.1 DER encoding.
        /// </summary>
        private static ReadOnlySpan<byte> RsaSuffix => new byte[] { 0x02, 0x03, 0x01, 0x00, 0x01 };

        /// <summary>
        /// A constant for ASN.1 DER encoded integers (or bitstrings) to denote the high byte is set
        /// for the following values so the encoders do not misinterpret the values as unsigned.
        /// </summary>
        public static byte IfMsbSetPrefixSuffix => 0x0;

        /// <summary>
        /// The RSA public modulus length for 2048 RSA.
        /// </summary>
        public static int Rsa2048ModulusLength => 256;

        /// <summary>
        /// The RSA public modulus length for 4096 RSA.
        /// </summary>
        public static int Rsa4096ModulusLength => 512;


        /// <summary>
        /// Encodes the RSA public modulus according to ASN.1 DER encoding rules.
        /// </summary>
        /// <param name="rsaModulusBytes"></param>
        /// <returns>RSA modulus bytes encoded in ASN.1 DER format.</returns>
        /// <exception cref="ArgumentOutOfRangeException">The key length mush be either 256 or 512 bytes</exception>.
        public static byte[] Encode(ReadOnlySpan<byte> rsaModulusBytes)
        {
            if(rsaModulusBytes == null)
            {
                throw new ArgumentNullException(nameof(rsaModulusBytes));
            }

            //DID method specifications support only these RSA key lengths at the moment.            
            if(!(rsaModulusBytes.Length == Rsa2048ModulusLength || rsaModulusBytes.Length == Rsa4096ModulusLength))
            {
                throw new ArgumentOutOfRangeException(nameof(rsaModulusBytes), $"Length must be {Rsa2048ModulusLength} (RSA 2048) or {Rsa4096ModulusLength} (RSA 4096).");
            }

            //Only RSA 2048 and 4096 byte lenghts are supported. So it is sufficient to check
            //against either one when pre-condition on entry ensures the incoming buffer is either one.
            //Both of these should be of the same length, but the logic is spelled out here.
            ReadOnlySpan<byte> prefix = rsaModulusBytes.Length == Rsa2048ModulusLength ? Rsa2048Prefix : Rsa4096Prefix;

            //The modulus values are exponents of two, so the MSB should be always set.
            //bool isRsaModuloMsbSet = IsMsbBitSet(rsaModulusBytes);
            //int msbByteLength = isRsaModuloMsbSet ? 1 : 0;
            const int MsbByteLength = 1;
            int arrayLength = prefix.Length + MsbByteLength + rsaModulusBytes.Length + RsaSuffix.Length;

            //TODO: IMemoryOwner<byte> from pool...
            var encodingBuffer = new byte[arrayLength];

            //By specification first is the envelope header according to RSA material            
            prefix.CopyTo(encodingBuffer);

            //And then follows the other bytes. As this is a zero based index, not length,
            //1 is subtracted from the prefix.Length. But then also by ASN.1 DER encoding
            //rules a 0x00 byte is inserted so that DER decoder does not misinterpret
            //an unsigned big endian number (or byte sequence) as signed integer.
            //Here + 1 = msbByteLength.
            int index;
            index = prefix.Length - 1 + MsbByteLength;
            encodingBuffer[index] = IfMsbSetPrefixSuffix;

            //Then the actual content is moved to the result array.
            ++index;
            rsaModulusBytes.CopyTo(((Span<byte>)encodingBuffer)[index..]);

            //And finally the suffix bytes to make the DER encoding complete.
            index += rsaModulusBytes.Length;
            RsaSuffix.CopyTo(((Span<byte>)encodingBuffer)[index..]);

            return encodingBuffer;
        }


        /// <summary>
        /// Decodes ASN.1 DER encoded RSA public modulus bytes.
        /// </summary>
        /// <param name="encodedRsaModulusBytes"></param>
        /// <returns>The plain RSA public modulus bytes.</returns>
        /// <exception cref="ArgumentException">If the encoding fails due to pre- or post-condition violation.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The key length mush be either 270 or 526 bytes</exception>.
        public static byte[] Decode(ReadOnlySpan<byte> encodedRsaModulusBytes)
        {
            //DID method specifications support only these RSA key lengths of 2048 and 4096 bytes.
            //They produce deterministically always the same length ASN.1 DER encoded byte arrays.
            const int Rsa2048DerEncodedBytesLength = 270;
            const int Rsa4096DerEncodedBytesLength = 526;
            if(!(encodedRsaModulusBytes.Length == Rsa2048DerEncodedBytesLength || encodedRsaModulusBytes.Length == Rsa4096DerEncodedBytesLength))
            {
                throw new ArgumentOutOfRangeException(nameof(encodedRsaModulusBytes), $"Length must be {Rsa2048DerEncodedBytesLength} (RSA 2048) or {Rsa4096DerEncodedBytesLength} (RSA 4096).");
            }

            //The ASN.1 DER envelope prolog is not needed, so the index is adjusted to bypass it.
            //The prefix length is the same for both 2048 and 4096 bit RSA keys and they
            //are the only supported ones. So here the Rsa2048.Length is used for both cases.
            //The DER encoded RSA public modulus length is checked on pre-conditions
            //so the list of these two encoding lenghts is exhaustive and the length can be relied on.
            Debug.Assert(Rsa2048Prefix.Length == Rsa4096Prefix.Length, "The RSA 2048 and 4096 bytes encodings ought to be the same here");
            int envelopPrologIndex = Rsa2048Prefix.Length + 1;

            //If the byte following DER prolog is 0x00 (and the one following less than 128 DEC or 0x80),
            //it means it's a padding byte according to DER encoding rules.            
            //Since the modulus values are exponents of two, the MSB should be always set.
            //
            //By the ASN.1 DER encoding rules a 0x00 byte is inserted so that DER decoder does not misinterpret
            //an unsigned big endian number (or byte sequence) as a signed integer. This too can be bypassed.
            //Together these mean += 2 can be added to the index, or += 1 to save a bit of resources.
            //means the index can be added with += 2 to bypass both the
            //Here += 1 to advance to the padding byte and then += 1 to check the high bit really is set.
            //
            //Nevertheless, it is appropriate hygiene to check the 0x00 byte is present and that MSB is set.
            //Since this is a zero based index and not length, -1 is added.
            const string CatastrophicExceptionMessage = "Catastrophic error while decoding RSA modulus bytes.";
            if(encodedRsaModulusBytes[envelopPrologIndex - 1] != 0x00 || !IsRsaModulusMsbBitSet(encodedRsaModulusBytes[envelopPrologIndex..]))
            {
                throw new ArgumentException(CatastrophicExceptionMessage);
            }

            //This would be the previous conditional without the index adjustments done with the given reasoning.
            /*++envelopPrologIndex;
            if(encodedRsaModulusBytes[envelopPrologIndex] == 0x00 && IsMsbBitSet(encodedRsaModulusBytes[(envelopPrologIndex + 1)..]))
            {
                ++envelopPrologIndex;
            }*/

            //The encoding needs to be either for RSA 2048 or RSA 4096 according to DID specifications. Others are not
            //accepted.
            var modulusLength = encodedRsaModulusBytes.Length == Rsa2048DerEncodedBytesLength ? Rsa2048ModulusLength : Rsa4096ModulusLength;
            var decodingBuffer = new byte[modulusLength];
            encodedRsaModulusBytes.Slice(envelopPrologIndex, modulusLength).CopyTo(decodingBuffer);

            //As a post-condition check, the handled bytes should match with the array length.
            //This should not be reached if pre-condition checks are in place and code is not
            //altered in adversory way.
            var decodedModuluslength = envelopPrologIndex + decodingBuffer.Length + RsaSuffix.Length;
            if(decodedModuluslength != encodedRsaModulusBytes.Length)
            {
                throw new ArgumentException(CatastrophicExceptionMessage);
            }

            return decodingBuffer;
        }


        /// <summary>
        /// Checks if the most significant bit of the given RSA modulus is set.
        /// </summary>
        /// <param name="rsaModulusBytes">The modulus bytes to check.</param>
        /// <returns><see langword="true" /> if MSB is set; otherwise, <see langword="false" /></returns>.        
        public static bool IsRsaModulusMsbBitSet(ReadOnlySpan<byte> rsaModulusBytes)
        {
            return (rsaModulusBytes[0] & 0x80) != 0;
        }
    }
}
