using System.Formats.Asn1;

namespace Verifiable.Cryptography
{
    /// <summary>
    /// A collection of well known OIDs. See more at <a href="http://www.oid-info.com/">OID Repository</a>.
    /// </summary>
    public static class WellKnownOids
    {
        /// <summary>
        /// See more at <a href="http://www.oid-info.com/cgi-bin/display?oid=1.3.6.1.4.1.11591.15.1&action=display">Ed25519 curve</a>.
        /// </summary>
        public const string Ed25519 = "1.3.6.1.4.1.11591.15.1";

        /// <summary>
        /// See more at <a href="http://www.oid-info.com/cgi-bin/display?oid=1.3.101.112&action=display">Edwards-curve Digital Signature Algorithm (EdDSA) Ed25519</a>.
        /// </summary>
        public const string EdDSA25519 = "1.3.101.112";

        /// <summary>
        /// OID for the NIST P-256 (secp256r1, prime256v1) elliptic curve per RFC 5480.
        /// </summary>
        public const string EcP256 = "1.2.840.10045.3.1.7";

        /// <summary>
        /// OID for the NIST P-384 (secp384r1) elliptic curve per RFC 5480.
        /// </summary>
        public const string EcP384 = "1.3.132.0.34";

        /// <summary>
        /// OID for the NIST P-521 (secp521r1) elliptic curve per RFC 5480.
        /// </summary>
        public const string EcP521 = "1.3.132.0.35";

        /// <summary>
        /// OID for the secp256k1 elliptic curve per SEC 2.
        /// </summary>
        public const string EcSecp256k1 = "1.3.132.0.10";

        /// <summary>
        /// OID for the Brainpool P-224r1 elliptic curve per RFC 5639 §A.1.
        /// </summary>
        public const string EcBrainpoolP224r1 = "1.3.36.3.3.2.8.1.1.5";

        /// <summary>
        /// OID for the Brainpool P-256r1 elliptic curve per RFC 5639 §A.1.
        /// </summary>
        public const string EcBrainpoolP256r1 = "1.3.36.3.3.2.8.1.1.7";

        /// <summary>
        /// OID for the Brainpool P-320r1 elliptic curve per RFC 5639 §A.1.
        /// </summary>
        public const string EcBrainpoolP320r1 = "1.3.36.3.3.2.8.1.1.9";

        /// <summary>
        /// OID for the Brainpool P-384r1 elliptic curve per RFC 5639 §A.1.
        /// </summary>
        public const string EcBrainpoolP384r1 = "1.3.36.3.3.2.8.1.1.11";

        /// <summary>
        /// OID for the Brainpool P-512r1 elliptic curve per RFC 5639 §A.1.
        /// </summary>
        public const string EcBrainpoolP512r1 = "1.3.36.3.3.2.8.1.1.13";

        /// <summary>
        /// OID for the X9.62 id-ecPublicKey key type per RFC 5480.
        /// </summary>
        public const string EcPublicKey = "1.2.840.10045.2.1";


        //The DER value bytes (the content after the 0x06 OBJECT IDENTIFIER tag and length) of the OIDs
        //above, for callers that compare against an OID parsed from a DER structure (e.g. a
        //SubjectPublicKeyInfo) without re-encoding it. Each is the encoding of the dotted form on the
        //matching string constant.

        /// <summary>DER value bytes of <see cref="EcPublicKey"/>.</summary>
        public static ReadOnlySpan<byte> EcPublicKeyDerValue => [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

        /// <summary>DER value bytes of the PKCS#1 rsaEncryption OID (1.2.840.113549.1.1.1).</summary>
        public static ReadOnlySpan<byte> RsaEncryptionDerValue => [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

        /// <summary>DER value bytes of <see cref="EcP256"/>.</summary>
        public static ReadOnlySpan<byte> EcP256DerValue => [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

        /// <summary>DER value bytes of <see cref="EcP384"/>.</summary>
        public static ReadOnlySpan<byte> EcP384DerValue => [0x2B, 0x81, 0x04, 0x00, 0x22];

        /// <summary>DER value bytes of <see cref="EcP521"/>.</summary>
        public static ReadOnlySpan<byte> EcP521DerValue => [0x2B, 0x81, 0x04, 0x00, 0x23];

        /// <summary>DER value bytes of <see cref="EcSecp256k1"/>.</summary>
        public static ReadOnlySpan<byte> EcSecp256k1DerValue => [0x2B, 0x81, 0x04, 0x00, 0x0A];

        /// <summary>DER value bytes of <see cref="EcBrainpoolP224r1"/>.</summary>
        public static ReadOnlySpan<byte> EcBrainpoolP224r1DerValue => [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x05];

        /// <summary>DER value bytes of <see cref="EcBrainpoolP256r1"/>.</summary>
        public static ReadOnlySpan<byte> EcBrainpoolP256r1DerValue => [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07];

        /// <summary>DER value bytes of <see cref="EcBrainpoolP320r1"/>.</summary>
        public static ReadOnlySpan<byte> EcBrainpoolP320r1DerValue => [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x09];

        /// <summary>DER value bytes of <see cref="EcBrainpoolP384r1"/>.</summary>
        public static ReadOnlySpan<byte> EcBrainpoolP384r1DerValue => [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B];

        /// <summary>DER value bytes of <see cref="EcBrainpoolP512r1"/>.</summary>
        public static ReadOnlySpan<byte> EcBrainpoolP512r1DerValue => [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D];


        /// <summary>
        /// Encodes a dotted OID string (for example <c>1.2.840.10045.3.1.7</c>) to its DER value bytes —
        /// the content after the <c>0x06</c> OBJECT IDENTIFIER tag and length — using the framework DER
        /// encoder. The inverse of <see cref="OidFromDerValue"/>; the round trip is identity.
        /// </summary>
        /// <param name="oid">The dotted OID string.</param>
        /// <returns>The DER value bytes (without the tag and length).</returns>
        public static byte[] OidToDerValue(string oid)
        {
            ArgumentNullException.ThrowIfNull(oid);

            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.WriteObjectIdentifier(oid);
            byte[] element = writer.Encode();

            //Strip the leading 0x06 tag and the definite-length field to leave the value bytes.
            int lengthFieldSize = element[1] < 0x80 ? 1 : 1 + (element[1] & 0x7F);

            return element[(1 + lengthFieldSize)..];
        }


        /// <summary>
        /// Decodes the DER value bytes of an OBJECT IDENTIFIER — the content after the <c>0x06</c> tag and
        /// length, as an ASN.1 parser yields it — to its dotted OID string, using the framework DER
        /// decoder. The inverse of <see cref="OidToDerValue"/>.
        /// </summary>
        /// <param name="derValue">The OID value bytes (without the tag and length).</param>
        /// <returns>The dotted OID string.</returns>
        public static string OidFromDerValue(ReadOnlySpan<byte> derValue)
        {
            //Wrap the value in a minimal DER OBJECT IDENTIFIER element so the framework decoder can read it.
            int lengthFieldSize = derValue.Length <= 0x7F ? 1 : derValue.Length <= 0xFF ? 2 : 3;
            byte[] element = new byte[1 + lengthFieldSize + derValue.Length];
            element[0] = 0x06;
            if(lengthFieldSize == 1)
            {
                element[1] = (byte)derValue.Length;
            }
            else if(lengthFieldSize == 2)
            {
                element[1] = 0x81;
                element[2] = (byte)derValue.Length;
            }
            else
            {
                element[1] = 0x82;
                element[2] = (byte)(derValue.Length >> 8);
                element[3] = (byte)derValue.Length;
            }

            derValue.CopyTo(element.AsSpan(1 + lengthFieldSize));

            return AsnDecoder.ReadObjectIdentifier(element, AsnEncodingRules.DER, out _);
        }
    }
}
