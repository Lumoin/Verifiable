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

        /// <summary>
        /// OID for the X.509 Key Usage certificate extension (id-ce-keyUsage) per RFC 5280 §4.2.1.3.
        /// </summary>
        public const string KeyUsageExtension = "2.5.29.15";

        /// <summary>
        /// OID for the X.509 Certificate Policies certificate extension (id-ce-certificatePolicies)
        /// per RFC 5280 §4.2.1.4.
        /// </summary>
        public const string CertificatePoliciesExtension = "2.5.29.32";

        /// <summary>
        /// OID for the X.509 Extended Key Usage certificate extension (id-ce-extKeyUsage)
        /// per RFC 5280 §4.2.1.12.
        /// </summary>
        public const string ExtendedKeyUsageExtension = "2.5.29.37";

        /// <summary>
        /// OID for the Qualified Certificate Statements certificate extension (id-pe-qcStatements)
        /// per RFC 3739 §3.2.6, the extension carrying the ETSI EN 319 412-5 statements below.
        /// </summary>
        public const string QcStatementsExtension = "1.3.6.1.5.5.7.1.3";

        /// <summary>
        /// OID for the X.520 Organizational Unit Name attribute type (organizationalUnitName) per
        /// RFC 5280 §4.1.2.4, used in a certificate's Subject or Issuer distinguished name.
        /// </summary>
        public const string OrganizationalUnitName = "2.5.4.11";

        /// <summary>
        /// OID for the X.520 Country Name attribute type (countryName) per RFC 5280 §4.1.2.4,
        /// used in a certificate's Subject or Issuer distinguished name.
        /// </summary>
        public const string CountryName = "2.5.4.6";

        /// <summary>
        /// OID for the X.520 Organization Name attribute type (organizationName) per
        /// RFC 5280 §4.1.2.4, used in a certificate's Subject or Issuer distinguished name.
        /// </summary>
        public const string OrganizationName = "2.5.4.10";

        /// <summary>
        /// OID for the X.520 Common Name attribute type (commonName) per RFC 5280 §4.1.2.4,
        /// used in a certificate's Subject or Issuer distinguished name.
        /// </summary>
        public const string CommonName = "2.5.4.3";

        /// <summary>
        /// OID for the ETSI EN 319 412-5 <c>id-etsi-qcs-QcCompliance</c> statement asserting the
        /// certificate is an EU qualified certificate.
        /// </summary>
        public const string QcCompliance = "0.4.0.1862.1.1";

        /// <summary>
        /// OID for the ETSI EN 319 412-5 <c>id-etsi-qcs-QcSSCD</c> statement asserting the private key
        /// resides in a qualified electronic signature/seal creation device.
        /// </summary>
        public const string QcSscd = "0.4.0.1862.1.4";

        /// <summary>
        /// OID for the ETSI EN 319 412-5 <c>id-etsi-qcs-QcType</c> statement carrying the qualified
        /// certificate type identifiers below.
        /// </summary>
        public const string QcType = "0.4.0.1862.1.6";

        /// <summary>
        /// OID for the ETSI EN 319 412-5 <c>id-etsi-qct-esign</c> qualified certificate type (QcType 1,
        /// electronic signatures).
        /// </summary>
        public const string QcTypeElectronicSignature = "0.4.0.1862.1.6.1";

        /// <summary>
        /// OID for the ETSI EN 319 412-5 <c>id-etsi-qct-eseal</c> qualified certificate type (QcType 2,
        /// electronic seals).
        /// </summary>
        public const string QcTypeElectronicSeal = "0.4.0.1862.1.6.2";

        /// <summary>
        /// OID for the ETSI EN 319 412-5 <c>id-etsi-qct-web</c> qualified certificate type (QcType 3,
        /// website authentication).
        /// </summary>
        public const string QcTypeWebsiteAuthentication = "0.4.0.1862.1.6.3";

        /// <summary>
        /// OID for the ETSI TS 101 456 <c>QCP</c> (qcp-public) qualified certificate policy of the
        /// Directive 1999/93/EC era, which ETSI TS 119 615 PRO-4.4.4-33 reads.
        /// </summary>
        public const string QcpPublic = "0.4.0.1456.1.2";

        /// <summary>
        /// OID for the ETSI TS 101 456 <c>QCP+</c> (qcp-public-with-sscd) qualified certificate policy of
        /// the Directive 1999/93/EC era, which ETSI TS 119 615 PRO-4.4.4-33 and PRO-4.5.4-03 read.
        /// </summary>
        public const string QcpPublicWithSscd = "0.4.0.1456.1.1";

        /// <summary>
        /// OID for the X.509 Authority Information Access certificate extension (id-pe-authorityInfoAccess)
        /// per <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.2.1">RFC 5280 §4.2.2.1</see>,
        /// carrying the <see cref="AccessMethodOcsp"/> and <see cref="AccessMethodCaIssuers"/> access
        /// locations a revocation-source or chain-completion seam reads.
        /// </summary>
        public const string AuthorityInfoAccessExtension = "1.3.6.1.5.5.7.1.1";

        /// <summary>
        /// OID for the X.509 CRL Distribution Points certificate extension (id-ce-cRLDistributionPoints)
        /// per <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13">RFC 5280 §4.2.1.13</see>.
        /// </summary>
        public const string CrlDistributionPointsExtension = "2.5.29.31";

        /// <summary>
        /// OID for the <c>id-ad-ocsp</c> Authority Information Access method
        /// (<see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.2.1">RFC 5280 §4.2.2.1</see>; also
        /// RFC 6960 Appendix B), naming an OCSP responder's access location within an
        /// <c>AuthorityInfoAccessSyntax</c> entry.
        /// </summary>
        public const string AccessMethodOcsp = "1.3.6.1.5.5.7.48.1";

        /// <summary>
        /// OID for the <c>id-ad-caIssuers</c> Authority Information Access method
        /// (<see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.2.1">RFC 5280 §4.2.2.1</see>),
        /// naming a certificate-chain-completion access location within an <c>AuthorityInfoAccessSyntax</c>
        /// entry.
        /// </summary>
        public const string AccessMethodCaIssuers = "1.3.6.1.5.5.7.48.2";

        /// <summary>
        /// OID for the <c>id-pkix-ocsp-basic</c> response type
        /// (<see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1">RFC 6960 §4.2.1</see>), the
        /// only <c>ResponseBytes.responseType</c> this library's OCSP client reads. It types a bare
        /// <c>BasicOCSPResponse</c>, and is distinct from <see cref="OcspResponseRevocationInfo"/> — the
        /// two name different structures.
        /// </summary>
        public const string OcspBasicResponseType = "1.3.6.1.5.5.7.48.1.1";

        /// <summary>
        /// OID for the <c>id-ri-ocsp-response</c> revocation-information format
        /// (<see href="https://www.rfc-editor.org/rfc/rfc5940#section-2">RFC 5940 §2</see>), which types a
        /// whole <c>OCSPResponse</c> carried as the <c>other</c> alternative of a CMS <c>RevocationInfoChoice</c>
        /// (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-10.2.1">RFC 5652 §10.2.1</see>) — the
        /// placement ETSI EN 319 122-1 clause 5.4.2.2 gives an embedded OCSP response — and, within an
        /// EN 319 122-1 <c>revocation-values</c> attribute, its <c>otherRevVals</c> field (clause A.1.2.2).
        /// Only this format is defined by RFC 5940; the pre-RFC-5940 <see cref="OcspBasicResponseType"/>
        /// (<c>id-pkix-ocsp-basic</c>) instead types a bare <c>BasicOCSPResponse</c>, so a reader accepting an
        /// embedded OCSP response must recognise both while writing only this one.
        /// </summary>
        public const string OcspResponseRevocationInfo = "1.3.6.1.5.5.7.16.2";

        /// <summary>
        /// OID for the <c>id-pkix-ocsp-nonce</c> request/response extension
        /// (<see href="https://www.rfc-editor.org/rfc/rfc9654#section-2.1">RFC 9654 §2.1</see>, obsoleting
        /// RFC 8954), carrying an anti-replay <c>Nonce ::= OCTET STRING (SIZE(1..128))</c>.
        /// </summary>
        public const string OcspNonce = "1.3.6.1.5.5.7.48.1.2";

        /// <summary>
        /// OID for the <c>id-pkix-ocsp-nocheck</c> extension
        /// (<see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.2.2.2.1">RFC 6960 §4.2.2.2.1</see>),
        /// which a CA places on a delegated OCSP responder certificate to declare that the responder's own
        /// revocation status need not be checked.
        /// </summary>
        public const string OcspNoCheck = "1.3.6.1.5.5.7.48.1.5";

        /// <summary>
        /// OID for the <c>id-kp-OCSPSigning</c> Extended Key Usage key purpose
        /// (<see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.2.2.2">RFC 6960 §4.2.2.2</see>), which
        /// a delegated OCSP responder certificate must assert.
        /// </summary>
        public const string OcspSigningKeyPurpose = "1.3.6.1.5.5.7.3.9";

        /// <summary>
        /// OID for the SHA-1 digest algorithm (RFC 3279). Collision-broken for general integrity use; RFC 6960
        /// §4.3 still requires an OCSP client to support it for <c>CertID</c> hash-algorithm agility, an
        /// identification rather than a collision-sensitive use.
        /// </summary>
        public const string Sha1 = "1.3.14.3.2.26";

        /// <summary>OID for the SHA-256 digest algorithm (RFC 5754 §2, NIST FIPS 180-4).</summary>
        public const string Sha256 = "2.16.840.1.101.3.4.2.1";

        /// <summary>OID for the SHA-384 digest algorithm (RFC 5754 §2, NIST FIPS 180-4).</summary>
        public const string Sha384 = "2.16.840.1.101.3.4.2.2";

        /// <summary>OID for the SHA-512 digest algorithm (RFC 5754 §2, NIST FIPS 180-4).</summary>
        public const string Sha512 = "2.16.840.1.101.3.4.2.3";


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
