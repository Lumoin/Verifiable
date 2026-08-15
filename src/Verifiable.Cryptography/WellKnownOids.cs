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
        /// OID for the X.509 Basic Constraints certificate extension (id-ce-basicConstraints)
        /// per RFC 5280 §4.2.1.9.
        /// </summary>
        public const string BasicConstraintsExtension = "2.5.29.19";

        /// <summary>
        /// OID for the X.509 Subject Key Identifier certificate extension (id-ce-subjectKeyIdentifier)
        /// per RFC 5280 §4.2.1.2.
        /// </summary>
        public const string SubjectKeyIdentifierExtension = "2.5.29.14";

        /// <summary>
        /// OID for the X.509 Authority Key Identifier certificate extension (id-ce-authorityKeyIdentifier)
        /// per RFC 5280 §4.2.1.1.
        /// </summary>
        public const string AuthorityKeyIdentifierExtension = "2.5.29.35";

        /// <summary>
        /// OID for the <c>id-kp-timeStamping</c> Extended Key Usage key purpose per RFC 3161 §2.3, which a
        /// Time-Stamping Authority's certificate must assert alone and critically.
        /// </summary>
        public const string TimeStampingKeyPurpose = "1.3.6.1.5.5.7.3.8";

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
        /// OID for the X.520 Pseudonym attribute type (pseudonym) per RFC 5280 §4.1.2.4, used in a
        /// certificate's Subject distinguished name, whose presence ETSI TS 119 172-4 REQ-4.5-01 c)
        /// requires an applicability rules checking report to clearly indicate.
        /// </summary>
        public const string Pseudonym = "2.5.4.65";

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
        /// OID for the ETSI EN 319 412-5 <c>id-etsi-qcs-QcLimitValue</c> statement of
        /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">
        /// ETSI EN 319 412-5 V2.6.1</see> clause 4.3.2, declaring a limitation on the value of transactions
        /// for which the certificate can be used.
        /// </summary>
        public const string QcLimitValue = "0.4.0.1862.1.2";

        /// <summary>
        /// OID for the ETSI EN 319 412-5 <c>id-etsi-qcs-QcRetentionPeriod</c> statement of
        /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">
        /// ETSI EN 319 412-5 V2.6.1</see> clause 4.3.3, declaring the retention period for material
        /// information relevant to the certificate, expressed as a number of years after the certificate's
        /// expiry date.
        /// </summary>
        public const string QcRetentionPeriod = "0.4.0.1862.1.3";

        /// <summary>
        /// OID for the ETSI EN 319 412-5 <c>id-etsi-qcs-QcPDS</c> statement of
        /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">
        /// ETSI EN 319 412-5 V2.6.1</see> clause 4.3.4, holding URLs to PKI Disclosure Statements in
        /// accordance with ETSI EN 319 411-1 Annex A.
        /// </summary>
        public const string QcPds = "0.4.0.1862.1.5";

        /// <summary>
        /// OID for the ETSI EN 319 412-5 <c>id-etsi-qcs-QcCClegislation</c> statement of
        /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">
        /// ETSI EN 319 412-5 V2.6.1</see> clause 4.2.4, identifying the country or set of countries under the
        /// legislation of which the certificate is issued as a qualified certificate.
        /// </summary>
        public const string QcCcLegislation = "0.4.0.1862.1.7";

        /// <summary>
        /// OID for the ETSI EN 319 412-5 <c>id-etsi-qcs-QcIdentMethod</c> statement of
        /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">
        /// ETSI EN 319 412-5 V2.6.1</see> clause 4.3.5.1, carrying the eIDAS Article 24 identification method
        /// OID below that was used to verify the certificate subject's identity.
        /// </summary>
        public const string QcIdentMethod = "0.4.0.1862.1.8";

        /// <summary>
        /// OID for the ETSI EN 319 412-5 <c>id-etsi-qcs-QcQSCDlegislation</c> statement (the Annex B ASN.1
        /// module's spelling; clause 4.2.5's own body text spells it <c>id-etsi-qcs-QcQCSDlegislation</c>,
        /// but QCS-4.1-04 gives Annex B precedence over the body's ASN.1 in case of discrepancy) of
        /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">
        /// ETSI EN 319 412-5 V2.6.1</see> clause 4.2.5, declaring the country or set of countries, outside
        /// the EU and EEA, under the legislation of which the QSCD was certified.
        /// </summary>
        public const string QcQscdLegislation = "0.4.0.1862.1.9";

        /// <summary>
        /// OID for the ETSI EN 319 412-5 <c>id-etsi-qct-eIDAS1-ab</c> identification method of
        /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">
        /// ETSI EN 319 412-5 V2.6.1</see> Annex B: identification according to eIDAS1 Article 24
        /// paragraph 1 a) or b).
        /// </summary>
        public const string QcIdentMethodEidas1Ab = "0.4.0.1862.1.8.1";

        /// <summary>
        /// OID for the ETSI EN 319 412-5 <c>id-etsi-qct-eIDAS1-cd</c> identification method of
        /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">
        /// ETSI EN 319 412-5 V2.6.1</see> Annex B: identification according to eIDAS1 Article 24
        /// paragraph 1 c) or d).
        /// </summary>
        public const string QcIdentMethodEidas1Cd = "0.4.0.1862.1.8.2";

        /// <summary>
        /// OID for the ETSI EN 319 412-5 <c>id-etsi-qct-eIDAS2-acd</c> identification method of
        /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">
        /// ETSI EN 319 412-5 V2.6.1</see> clause 4.3.5.3: identification according to eIDAS2 Article 24
        /// paragraph 1a a), c) or d).
        /// </summary>
        public const string QcIdentMethodEidas2Acd = "0.4.0.1862.1.8.3";

        /// <summary>
        /// OID for the ETSI EN 319 412-5 <c>id-etsi-qct-eIDAS2-b</c> identification method of
        /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">
        /// ETSI EN 319 412-5 V2.6.1</see> clause 4.3.5.3: identification according to eIDAS2 Article 24
        /// paragraph 1a b).
        /// </summary>
        public const string QcIdentMethodEidas2B = "0.4.0.1862.1.8.4";

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
        /// OID for the ETSI EN 319 411-2 <c>qcp-natural</c> certificate policy of
        /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.06.01_60/en_31941102v020601p.pdf">
        /// ETSI EN 319 411-2 V2.6.1</see> clause 5.3 item a) (QCP-n): EU qualified certificates issued to
        /// natural persons. GEN-6.6.1-05 requires a certificate issued under this policy to carry this
        /// identifier and/or a TSP-allocated policy OID in its <see cref="CertificatePoliciesExtension"/>.
        /// Trusted-list criteria (ETSI TS 119 612 clause 5.5.9.2.2.2 PolicySet) match it against a trusted
        /// list's own policy OIDs rather than through the TS 119 615 determination tables.
        /// </summary>
        public const string QcpNatural = "0.4.0.194112.1.0";

        /// <summary>
        /// OID for the ETSI EN 319 411-2 <c>qcp-legal</c> certificate policy of
        /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.06.01_60/en_31941102v020601p.pdf">
        /// ETSI EN 319 411-2 V2.6.1</see> clause 5.3 item b) (QCP-l): EU qualified certificates issued to
        /// legal persons. GEN-6.6.1-05 requires a certificate issued under this policy to carry this
        /// identifier and/or a TSP-allocated policy OID in its <see cref="CertificatePoliciesExtension"/>.
        /// Trusted-list criteria (ETSI TS 119 612 clause 5.5.9.2.2.2 PolicySet) match it against a trusted
        /// list's own policy OIDs rather than through the TS 119 615 determination tables.
        /// </summary>
        public const string QcpLegal = "0.4.0.194112.1.1";

        /// <summary>
        /// OID for the ETSI EN 319 411-2 <c>qcp-natural-qscd</c> certificate policy of
        /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.06.01_60/en_31941102v020601p.pdf">
        /// ETSI EN 319 411-2 V2.6.1</see> clause 5.3 item c) (QCP-n-qscd): EU qualified certificates issued
        /// to natural persons whose private key and related certificate reside on a QSCD. GEN-6.6.1-05
        /// requires a certificate issued under this policy to carry this identifier and/or a TSP-allocated
        /// policy OID in its <see cref="CertificatePoliciesExtension"/>. Trusted-list criteria
        /// (ETSI TS 119 612 clause 5.5.9.2.2.2 PolicySet) match it against a trusted list's own policy OIDs
        /// rather than through the TS 119 615 determination tables.
        /// </summary>
        public const string QcpNaturalQscd = "0.4.0.194112.1.2";

        /// <summary>
        /// OID for the ETSI EN 319 411-2 <c>qcp-legal-qscd</c> certificate policy of
        /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.06.01_60/en_31941102v020601p.pdf">
        /// ETSI EN 319 411-2 V2.6.1</see> clause 5.3 item d) (QCP-l-qscd): EU qualified certificates issued
        /// to legal persons whose private key and related certificate reside on a QSCD. GEN-6.6.1-05
        /// requires a certificate issued under this policy to carry this identifier and/or a TSP-allocated
        /// policy OID in its <see cref="CertificatePoliciesExtension"/>. Trusted-list criteria
        /// (ETSI TS 119 612 clause 5.5.9.2.2.2 PolicySet) match it against a trusted list's own policy OIDs
        /// rather than through the TS 119 615 determination tables.
        /// </summary>
        public const string QcpLegalQscd = "0.4.0.194112.1.3";

        /// <summary>
        /// OID for the ETSI EN 319 411-2 <c>qcp-web</c> certificate policy of
        /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.06.01_60/en_31941102v020601p.pdf">
        /// ETSI EN 319 411-2 V2.6.1</see> clause 5.3 item e): EU qualified website authentication
        /// certificates issued to a legal person and linking the website to that person, based on EVCP; the
        /// current abbreviation is QEVCP-w (clause 3.3 notes earlier editions of the present document used
        /// the abbreviation QCP-w) while the ASN.1 identifier name stays <c>qcp-web</c>. GEN-6.6.1-05
        /// requires a certificate issued under this policy to carry this identifier and/or a TSP-allocated
        /// policy OID in its <see cref="CertificatePoliciesExtension"/>. Trusted-list criteria
        /// (ETSI TS 119 612 clause 5.5.9.2.2.2 PolicySet) match it against a trusted list's own policy OIDs
        /// rather than through the TS 119 615 determination tables.
        /// </summary>
        public const string QcpWeb = "0.4.0.194112.1.4";

        /// <summary>
        /// OID for the ETSI EN 319 411-2 <c>qncp-web</c> certificate policy of
        /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.06.01_60/en_31941102v020601p.pdf">
        /// ETSI EN 319 411-2 V2.6.1</see> clause 5.3 item f) (QNCP-w): EU qualified website authentication
        /// certificates issued to a natural or legal person and linking the website to that person, based on
        /// NCP and OVCP or IVCP. GEN-6.6.1-05 requires a certificate issued under this policy to carry this
        /// identifier and/or a TSP-allocated policy OID in its <see cref="CertificatePoliciesExtension"/>.
        /// Trusted-list criteria (ETSI TS 119 612 clause 5.5.9.2.2.2 PolicySet) match it against a trusted
        /// list's own policy OIDs rather than through the TS 119 615 determination tables.
        /// </summary>
        public const string QncpWeb = "0.4.0.194112.1.5";

        /// <summary>
        /// OID for the ETSI EN 319 411-2 <c>qncp-web-gen</c> certificate policy of
        /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.06.01_60/en_31941102v020601p.pdf">
        /// ETSI EN 319 411-2 V2.6.1</see> clause 5.3 item g) (QNCP-w-gen): EU qualified website
        /// authentication certificates issued to a natural or legal person and linking the website to that
        /// person, applicable for general purpose qualified website authentication (NCP plus the
        /// requirements tagged [WEB] in EN 319 411-1). GEN-6.6.1-05 requires a certificate issued under this
        /// policy to carry this identifier and/or a TSP-allocated policy OID in its
        /// <see cref="CertificatePoliciesExtension"/>. Trusted-list criteria (ETSI TS 119 612
        /// clause 5.5.9.2.2.2 PolicySet) match it against a trusted list's own policy OIDs rather than
        /// through the TS 119 615 determination tables.
        /// </summary>
        public const string QncpWebGen = "0.4.0.194112.1.6";

        /// <summary>
        /// OID for the ETSI TS 119 172-4 <c>id-etsi-sars</c> arc under which
        /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/01.02.01_60/ts_11917204v010201p.pdf">
        /// ETSI TS 119 172-4 V1.2.1 Annex A</see> allocates the signature applicability rules and digital
        /// signature type identifiers below.
        /// </summary>
        public const string SignatureApplicabilityRules = "0.4.0.191724.1";

        /// <summary>
        /// OID for the ETSI TS 119 172-4 <c>id-etsi-sars-SpCompliance</c> arc of
        /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/01.02.01_60/ts_11917204v010201p.pdf">
        /// ETSI TS 119 172-4 V1.2.1 Annex A</see>, whose children indicate that validation and reporting
        /// comply with one of that document's two sets of signature applicability rules.
        /// </summary>
        public const string SignatureApplicabilityRulesSpCompliance = "0.4.0.191724.1.1";

        /// <summary>
        /// OID for the ETSI TS 119 172-4 <c>id-etsi-sarc-realTimeReq</c> signature applicability rules of
        /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/01.02.01_60/ts_11917204v010201p.pdf">
        /// ETSI TS 119 172-4 V1.2.1 Annex A</see>: the rule set for contexts where a real time validation
        /// response is required and basic signatures are acceptable (clause 4.1 set 1).
        /// </summary>
        public const string SignatureApplicabilityRulesRealTimeRequired = "0.4.0.191724.1.1.1";

        /// <summary>
        /// OID for the ETSI TS 119 172-4 <c>id-etsi-sarc-realTimeNotReq</c> signature applicability rules of
        /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/01.02.01_60/ts_11917204v010201p.pdf">
        /// ETSI TS 119 172-4 V1.2.1 Annex A</see>: the rule set for contexts where a validation response
        /// delay of up to 24 hours is acceptable, or the minimum acceptable class of signature is a
        /// signature with time (clause 4.1 set 2).
        /// </summary>
        public const string SignatureApplicabilityRulesRealTimeNotRequired = "0.4.0.191724.1.1.2";

        /// <summary>
        /// OID for the ETSI TS 119 172-4 <c>id-etsi-sars-SigType</c> arc of
        /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/01.02.01_60/ts_11917204v010201p.pdf">
        /// ETSI TS 119 172-4 V1.2.1 Annex A</see>, whose children identify the type of a digital signature
        /// in an applicability rules checking report (REQ-4.5-02).
        /// </summary>
        public const string SignatureApplicabilityRulesSigType = "0.4.0.191724.1.2";

        /// <summary>
        /// OID for the ETSI TS 119 172-4 <c>id-etsi-dst-euqesig</c> digital signature type of
        /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/01.02.01_60/ts_11917204v010201p.pdf">
        /// ETSI TS 119 172-4 V1.2.1 Annex A</see>: an EU qualified electronic signature.
        /// </summary>
        public const string DigitalSignatureTypeEuQualifiedSignature = "0.4.0.191724.1.2.1";

        /// <summary>
        /// OID for the ETSI TS 119 172-4 <c>id-etsi-dst-adesigqc</c> digital signature type of
        /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/01.02.01_60/ts_11917204v010201p.pdf">
        /// ETSI TS 119 172-4 V1.2.1 Annex A</see>: an advanced electronic signature supported by an EU
        /// qualified certificate for electronic signature.
        /// </summary>
        public const string DigitalSignatureTypeAdvancedSignatureWithQualifiedCertificate = "0.4.0.191724.1.2.2";

        /// <summary>
        /// OID for the ETSI TS 119 172-4 <c>id-etsi-dst-adesig</c> digital signature type of
        /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/01.02.01_60/ts_11917204v010201p.pdf">
        /// ETSI TS 119 172-4 V1.2.1 Annex A</see>: an advanced electronic signature.
        /// </summary>
        public const string DigitalSignatureTypeAdvancedSignature = "0.4.0.191724.1.2.3";

        /// <summary>
        /// OID for the ETSI TS 119 172-4 <c>id-etsi-dst-euqeseal</c> digital signature type of
        /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/01.02.01_60/ts_11917204v010201p.pdf">
        /// ETSI TS 119 172-4 V1.2.1 Annex A</see>: an EU qualified electronic seal.
        /// </summary>
        public const string DigitalSignatureTypeEuQualifiedSeal = "0.4.0.191724.1.2.4";

        /// <summary>
        /// OID for the ETSI TS 119 172-4 <c>id-etsi-dst-adesealqc</c> digital signature type of
        /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/01.02.01_60/ts_11917204v010201p.pdf">
        /// ETSI TS 119 172-4 V1.2.1 Annex A</see>: an advanced electronic seal supported by an EU
        /// qualified certificate for electronic seal.
        /// </summary>
        public const string DigitalSignatureTypeAdvancedSealWithQualifiedCertificate = "0.4.0.191724.1.2.5";

        /// <summary>
        /// OID for the ETSI TS 119 172-4 <c>id-etsi-dst-adeseal</c> digital signature type of
        /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/01.02.01_60/ts_11917204v010201p.pdf">
        /// ETSI TS 119 172-4 V1.2.1 Annex A</see>: an advanced electronic seal.
        /// </summary>
        public const string DigitalSignatureTypeAdvancedSeal = "0.4.0.191724.1.2.6";

        /// <summary>
        /// OID for the ETSI TS 119 172-4 <c>id-etsi-dst-euqtst</c> digital signature type of
        /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/01.02.01_60/ts_11917204v010201p.pdf">
        /// ETSI TS 119 172-4 V1.2.1 Annex A</see>: an EU qualified electronic time stamp.
        /// </summary>
        public const string DigitalSignatureTypeEuQualifiedTimeStamp = "0.4.0.191724.1.2.7";

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

        /// <summary>
        /// OID for the PKCS#1 rsaEncryption algorithm
        /// (<see href="https://www.rfc-editor.org/rfc/rfc8017#appendix-A.1">RFC 8017 Appendix A.1</see>); as a
        /// CMS <c>SignerInfo</c> signature algorithm it carries the hash in the digest algorithm instead of
        /// naming one itself (RFC 3370 §3.2).
        /// </summary>
        public const string RsaEncryption = "1.2.840.113549.1.1.1";

        /// <summary>OID for the sha256WithRSAEncryption signature algorithm (<see href="https://www.rfc-editor.org/rfc/rfc8017#appendix-A.2.4">RFC 8017 Appendix A.2.4</see>).</summary>
        public const string Sha256WithRsaEncryption = "1.2.840.113549.1.1.11";

        /// <summary>OID for the sha384WithRSAEncryption signature algorithm (<see href="https://www.rfc-editor.org/rfc/rfc8017#appendix-A.2.4">RFC 8017 Appendix A.2.4</see>).</summary>
        public const string Sha384WithRsaEncryption = "1.2.840.113549.1.1.12";

        /// <summary>OID for the sha512WithRSAEncryption signature algorithm (<see href="https://www.rfc-editor.org/rfc/rfc8017#appendix-A.2.4">RFC 8017 Appendix A.2.4</see>).</summary>
        public const string Sha512WithRsaEncryption = "1.2.840.113549.1.1.13";

        /// <summary>OID for the ecdsa-with-SHA256 signature algorithm (<see href="https://www.rfc-editor.org/rfc/rfc5758#section-3.2">RFC 5758 §3.2</see>); the AlgorithmIdentifier's parameters field is absent per that clause.</summary>
        public const string EcdsaWithSha256 = "1.2.840.10045.4.3.2";

        /// <summary>OID for the ecdsa-with-SHA384 signature algorithm (<see href="https://www.rfc-editor.org/rfc/rfc5758#section-3.2">RFC 5758 §3.2</see>); the AlgorithmIdentifier's parameters field is absent per that clause.</summary>
        public const string EcdsaWithSha384 = "1.2.840.10045.4.3.3";

        /// <summary>OID for the ecdsa-with-SHA512 signature algorithm (<see href="https://www.rfc-editor.org/rfc/rfc5758#section-3.2">RFC 5758 §3.2</see>); the AlgorithmIdentifier's parameters field is absent per that clause.</summary>
        public const string EcdsaWithSha512 = "1.2.840.10045.4.3.4";

        /// <summary>
        /// OID for the ML-DSA-44 signature algorithm (NIST FIPS 204, security category 2), from the
        /// <see href="https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration">
        /// NIST Computer Security Objects Register</see> <c>sigAlgs</c> arc. In X.509 and CMS the one
        /// identifier names both the <c>SubjectPublicKeyInfo</c> key algorithm and the signature algorithm,
        /// with absent parameters.
        /// </summary>
        public const string MlDsa44 = "2.16.840.1.101.3.4.3.17";

        /// <summary>OID for the ML-DSA-65 signature algorithm (NIST FIPS 204, security category 3); see <see cref="MlDsa44"/> for the registration and its X.509/CMS use.</summary>
        public const string MlDsa65 = "2.16.840.1.101.3.4.3.18";

        /// <summary>OID for the ML-DSA-87 signature algorithm (NIST FIPS 204, security category 5); see <see cref="MlDsa44"/> for the registration and its X.509/CMS use.</summary>
        public const string MlDsa87 = "2.16.840.1.101.3.4.3.19";


        //The DER value bytes (the content after the 0x06 OBJECT IDENTIFIER tag and length) of the OIDs
        //above, for callers that compare against an OID parsed from a DER structure (e.g. a
        //SubjectPublicKeyInfo) without re-encoding it. Each is the encoding of the dotted form on the
        //matching string constant.

        /// <summary>DER value bytes of <see cref="EcPublicKey"/>.</summary>
        public static ReadOnlySpan<byte> EcPublicKeyDerValue => [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

        /// <summary>DER value bytes of the PKCS#1 rsaEncryption OID (1.2.840.113549.1.1.1).</summary>
        public static ReadOnlySpan<byte> RsaEncryptionDerValue => [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

        /// <summary>DER value bytes of <see cref="Sha256WithRsaEncryption"/>.</summary>
        public static ReadOnlySpan<byte> Sha256WithRsaEncryptionDerValue => [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];

        /// <summary>DER value bytes of <see cref="Sha512WithRsaEncryption"/>.</summary>
        public static ReadOnlySpan<byte> Sha512WithRsaEncryptionDerValue => [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D];

        /// <summary>DER value bytes of <see cref="MlDsa44"/>.</summary>
        public static ReadOnlySpan<byte> MlDsa44DerValue => [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11];

        /// <summary>DER value bytes of <see cref="MlDsa65"/>.</summary>
        public static ReadOnlySpan<byte> MlDsa65DerValue => [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];

        /// <summary>DER value bytes of <see cref="MlDsa87"/>.</summary>
        public static ReadOnlySpan<byte> MlDsa87DerValue => [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13];

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
