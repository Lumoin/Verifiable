using System;
using System.Collections.Generic;
using System.Formats.Asn1;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Extracts <see cref="QualifiedCertificateFacts"/> straight off a DER-encoded X.509 certificate with
/// <see cref="System.Formats.Asn1"/> only — the same no-certificate-library approach as
/// <see cref="ManagedCertificate"/>: the issuer and subject name attributes per
/// <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.4">RFC 5280 §4.1.2.4</see>, the
/// <c>notBefore</c> validity instant per
/// <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5">RFC 5280 §4.1.2.5</see>, the
/// qualified-certificate statements per
/// <see href="https://www.rfc-editor.org/rfc/rfc3739#section-3.2.6">RFC 3739 §3.2.6</see> as profiled by
/// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.04.01_60/en_31941205v020401p.pdf">
/// ETSI EN 319 412-5</see>, and the CertificatePolicies, KeyUsage and ExtendedKeyUsage extension contents
/// per <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2">RFC 5280 §4.2</see> that the
/// TS 119 612 clause 5.5.9.2.2 criteria trees assert against.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Attacker-reachable input.</strong> A certificate under qualification arrives from a signature or
/// a network location and its own signature is verified by the separate chain step, not here, so this
/// extractor treats the bytes as hostile: every structure is read with <see cref="AsnEncodingRules.DER"/>
/// through <see cref="AsnReader"/>'s bounds-checked cursors, the walk is straight-line loops with no
/// recursion (a distinguished name and an extension list nest to fixed depth by their ASN.1 definitions),
/// and trailing data is rejected wherever the schema closes a structure this extractor reads: after the
/// outermost <c>Certificate</c> sequence, after the last recognised field of the to-be-signed structure,
/// and inside every extension value read into a fact. The <c>signatureAlgorithm</c> and
/// <c>signatureValue</c> fields are validated structurally (a sequence and a bit string), never
/// cryptographically — verification is the chain step's concern. Malformed content throws
/// <see cref="AsnContentException"/>.
/// </para>
/// <para>
/// <strong>Tolerated real-world deviations</strong>, each chosen so that a deployed certificate's encoding
/// quirk degrades the affected fact instead of aborting extraction of the rest: a <c>SET OF</c> inside a
/// relative distinguished name is read without DER sort-order validation (multi-valued RDNs violating the
/// sort exist in deployed certificates; encoding strictness belongs to the signature verification step); an
/// attribute value in an unsupported string form is skipped while its attribute type is still recorded; an
/// unknown <c>QcType</c> identifier is omitted from <see cref="QualifiedCertificateFacts.QcTypes"/> (the
/// determination tables select rows only by the known types); and of duplicate extensions — an RFC 5280
/// §4.2 profile violation — the first occurrence is read.
/// </para>
/// <para>
/// <see cref="QualifiedCertificateFacts.IssuerDistinguishedName"/> is left unset: rendering a
/// distinguished name to a string is a presentation choice this library does not make, and only the
/// PRO-4.4.4-06 (b) fallback identification strategy reads it. A caller composing that fallback grafts its
/// own rendering onto the returned record with a <c>with</c> expression.
/// </para>
/// </remarks>
public static class QualifiedCertificateFactsExtractor
{
    /// <summary>
    /// Extracts the <see cref="QualifiedCertificateFacts"/> the ETSI TS 119 615 clause 4 procedures read
    /// from a DER-encoded X.509 certificate.
    /// </summary>
    /// <param name="certificate">The certificate to read. The caller retains ownership.</param>
    /// <returns>The extracted facts.</returns>
    /// <exception cref="ArgumentException">When <paramref name="certificate"/> does not carry an X.509 certificate — a composition error, same as a wrong-territory list.</exception>
    /// <exception cref="AsnContentException">When the bytes are not a DER-encoded RFC 5280 certificate.</exception>
    public static QualifiedCertificateFacts Extract(PkiCertificateMemory certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if(!certificate.IsX509Certificate)
        {
            throw new ArgumentException("The carrier must hold an X.509 certificate.", nameof(certificate));
        }

        //Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue } (RFC 5280 §4.1.1);
        //only tbsCertificate is read — the signature is the chain step's concern, not a fact.
        var reader = new AsnReader(certificate.AsReadOnlyMemory(), AsnEncodingRules.DER);
        AsnReader certificateSequence = reader.ReadSequence();
        reader.ThrowIfNotEmpty();
        AsnReader tbsCertificate = certificateSequence.ReadSequence();

        //version [0] EXPLICIT INTEGER DEFAULT v1 (RFC 5280 §4.1.2.1), present in practically every certificate.
        if(tbsCertificate.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            _ = tbsCertificate.ReadEncodedValue();
        }

        _ = tbsCertificate.ReadEncodedValue();                              //serialNumber.
        _ = tbsCertificate.ReadEncodedValue();                              //signature AlgorithmIdentifier.
        DistinguishedNameFacts issuer = ReadName(new AsnReader(tbsCertificate.ReadEncodedValue(), AsnEncodingRules.DER));
        AsnReader validity = tbsCertificate.ReadSequence();
        DateTimeOffset notBefore = ReadTime(validity);
        _ = ReadTime(validity);                                             //notAfter, structurally validated only.
        validity.ThrowIfNotEmpty();
        DistinguishedNameFacts subject = ReadName(new AsnReader(tbsCertificate.ReadEncodedValue(), AsnEncodingRules.DER));
        _ = tbsCertificate.ReadEncodedValue();                              //subjectPublicKeyInfo.

        ExtensionFacts extensions = ReadExtensions(tbsCertificate);

        //signatureAlgorithm and signatureValue close the Certificate sequence (RFC 5280 §4.1.1); their
        //structure is this contract's concern, their content the chain step's.
        _ = certificateSequence.ReadSequence();
        if(!certificateSequence.TryReadPrimitiveBitString(out _, out _))
        {
            throw new AsnContentException("A Certificate must close with its signatureValue BIT STRING (RFC 5280 §4.1.1).");
        }

        certificateSequence.ThrowIfNotEmpty();

        return new QualifiedCertificateFacts
        {
            IssuerCountryCode = issuer.CountryCode,
            IssuerOrganizationNames = issuer.OrganizationNames,
            IssuerCommonNames = issuer.CommonNames,
            SubjectCountryCode = subject.CountryCode,
            SubjectOrganizationNames = subject.OrganizationNames,
            NotBefore = notBefore,
            HasQcCompliance = extensions.HasQcCompliance,
            QcTypes = extensions.QcTypes,
            HasQcSscdStatement = extensions.HasQcSscdStatement,
            HasCertificatePoliciesExtension = extensions.HasCertificatePoliciesExtension,
            CertificatePolicyOids = extensions.CertificatePolicyOids,
            HasKeyUsageExtension = extensions.HasKeyUsageExtension,
            SetKeyUsageBits = extensions.SetKeyUsageBits,
            HasExtendedKeyUsageExtension = extensions.HasExtendedKeyUsageExtension,
            ExtendedKeyUsageOids = extensions.ExtendedKeyUsageOids,
            SubjectAttributeTypeOids = subject.AttributeTypeOids
        };
    }


    /// <summary>
    /// Reads the <c>notBefore</c> instant of a <c>Validity</c> sequence per
    /// <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5">RFC 5280 §4.1.2.5</see>: a
    /// <c>UTCTime</c> for dates through 2049 (two-digit years 00–49 read as 20YY, exactly the
    /// <see cref="AsnReader.ReadUtcTime(int)"/> default pivot) or a <c>GeneralizedTime</c> from 2050 on.
    /// </summary>
    /// <param name="validity">The reader positioned at the <c>Validity</c> sequence's <c>notBefore</c> element.</param>
    /// <returns>The <c>notBefore</c> instant.</returns>
    private static DateTimeOffset ReadTime(AsnReader validity)
    {
        Asn1Tag tag = validity.PeekTag();
        if(tag.TagClass != TagClass.Universal)
        {
            throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5).");
        }

        return (UniversalTagNumber)tag.TagValue switch
        {
            UniversalTagNumber.UtcTime => validity.ReadUtcTime(),
            UniversalTagNumber.GeneralizedTime => validity.ReadGeneralizedTime(),
            _ => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5).")
        };
    }


    /// <summary>
    /// Walks a <c>Name</c> (an <c>RDNSequence</c>) per
    /// <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.4">RFC 5280 §4.1.2.4</see>,
    /// collecting the attribute type identifiers in certificate order and the <c>countryName</c>,
    /// <c>organizationName</c> and <c>commonName</c> values the qualification procedures read.
    /// </summary>
    /// <param name="name">The reader positioned at the <c>Name</c> sequence.</param>
    /// <returns>The collected name facts.</returns>
    private static DistinguishedNameFacts ReadName(AsnReader name)
    {
        string? countryCode = null;
        List<string> organizationNames = [];
        List<string> commonNames = [];
        List<string> attributeTypeOids = [];

        AsnReader relativeNames = name.ReadSequence();
        while(relativeNames.HasData)
        {
            //A deployed multi-valued RDN violating the DER SET OF sort order must not abort fact
            //extraction; encoding strictness is the signature verification step's concern.
            AsnReader relativeName = relativeNames.ReadSetOf(skipSortOrderValidation: true);
            while(relativeName.HasData)
            {
                AsnReader attribute = relativeName.ReadSequence();
                string attributeType = attribute.ReadObjectIdentifier();
                attributeTypeOids.Add(attributeType);

                string? value = TryReadDirectoryStringValue(attribute);
                attribute.ThrowIfNotEmpty();
                if(value is null)
                {
                    continue;
                }

                switch(attributeType)
                {
                    case WellKnownOids.CountryName:
                        countryCode ??= value;
                        break;

                    case WellKnownOids.OrganizationName:
                        organizationNames.Add(value);
                        break;

                    case WellKnownOids.CommonName:
                        commonNames.Add(value);
                        break;

                    default:
                        break;
                }
            }
        }

        name.ThrowIfNotEmpty();

        return new DistinguishedNameFacts(countryCode, organizationNames, commonNames, attributeTypeOids);
    }


    /// <summary>
    /// Reads an <c>AttributeTypeAndValue</c>'s value as text when it is one of the
    /// <c>DirectoryString</c>-style forms this extractor decodes (<c>UTF8String</c>,
    /// <c>PrintableString</c>, <c>IA5String</c>, <c>TeletexString</c>, <c>BMPString</c> — per
    /// <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.4">RFC 5280 §4.1.2.4</see>'s
    /// <c>DirectoryString</c> plus the <c>IA5String</c> forms of the domain-component and email
    /// attributes), consuming and skipping any other form so the walk continues.
    /// </summary>
    /// <param name="attribute">The reader positioned at the attribute value.</param>
    /// <returns>The decoded text, or <see langword="null"/> when the value form is not decoded.</returns>
    private static string? TryReadDirectoryStringValue(AsnReader attribute)
    {
        Asn1Tag tag = attribute.PeekTag();
        bool isDecodableText = tag.TagClass == TagClass.Universal && (UniversalTagNumber)tag.TagValue is
            UniversalTagNumber.UTF8String or
            UniversalTagNumber.PrintableString or
            UniversalTagNumber.IA5String or
            UniversalTagNumber.T61String or
            UniversalTagNumber.BMPString;

        if(!isDecodableText)
        {
            _ = attribute.ReadEncodedValue();

            return null;
        }

        return attribute.ReadCharacterString((UniversalTagNumber)tag.TagValue);
    }


    /// <summary>
    /// Skips the obsolete unique-identifier fields and walks the <c>extensions [3]</c> list per
    /// <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.9">RFC 5280 §4.1.2.9</see>,
    /// reading the first occurrence of each extension the facts record carries.
    /// </summary>
    /// <param name="tbsCertificate">The reader positioned after <c>subjectPublicKeyInfo</c>.</param>
    /// <returns>The collected extension facts.</returns>
    private static ExtensionFacts ReadExtensions(AsnReader tbsCertificate)
    {
        //issuerUniqueID [1] IMPLICIT and subjectUniqueID [2] IMPLICIT are obsolete but allowed before
        //extensions (RFC 5280 §4.1.2.8); IMPLICIT BIT STRING is a primitive tag, so only class and value
        //are compared.
        if(tbsCertificate.HasData && tbsCertificate.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
        {
            _ = tbsCertificate.ReadEncodedValue();
        }

        if(tbsCertificate.HasData && tbsCertificate.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
        {
            _ = tbsCertificate.ReadEncodedValue();
        }

        QcStatementFacts? qcStatements = null;
        List<string>? certificatePolicyOids = null;
        List<KeyUsageBitName>? setKeyUsageBits = null;
        List<string>? extendedKeyUsageOids = null;

        if(tbsCertificate.HasData && tbsCertificate.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 3)))
        {
            AsnReader extensionsWrapper = tbsCertificate.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            AsnReader extensions = extensionsWrapper.ReadSequence();
            while(extensions.HasData)
            {
                //Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }.
                AsnReader extension = extensions.ReadSequence();
                string extensionId = extension.ReadObjectIdentifier();
                if(extension.PeekTag() == Asn1Tag.Boolean)
                {
                    _ = extension.ReadBoolean();
                }

                if(!extension.TryReadPrimitiveOctetString(out ReadOnlyMemory<byte> extensionValue))
                {
                    throw new AsnContentException("An extension value must be a primitive OCTET STRING in DER (RFC 5280 §4.1.2.9).");
                }

                switch(extensionId)
                {
                    case WellKnownOids.QcStatementsExtension:
                        qcStatements ??= ReadQcStatements(new AsnReader(extensionValue, AsnEncodingRules.DER));
                        break;

                    case WellKnownOids.CertificatePoliciesExtension:
                        certificatePolicyOids ??= ReadCertificatePolicyIdentifiers(new AsnReader(extensionValue, AsnEncodingRules.DER));
                        break;

                    case WellKnownOids.KeyUsageExtension:
                        setKeyUsageBits ??= ReadSetKeyUsageBits(new AsnReader(extensionValue, AsnEncodingRules.DER));
                        break;

                    case WellKnownOids.ExtendedKeyUsageExtension:
                        extendedKeyUsageOids ??= ReadKeyPurposeIdentifiers(new AsnReader(extensionValue, AsnEncodingRules.DER));
                        break;

                    default:
                        break;
                }

                extension.ThrowIfNotEmpty();
            }

            extensionsWrapper.ThrowIfNotEmpty();
        }

        //Any to-be-signed content still unread here is not an RFC 5280 §4.1.2 field: malformed input is
        //rejected, never silently read as "no extensions".
        tbsCertificate.ThrowIfNotEmpty();

        return new ExtensionFacts(
            qcStatements?.HasQcCompliance ?? false,
            qcStatements?.HasQcSscdStatement ?? false,
            qcStatements?.QcTypes ?? [],
            certificatePolicyOids is not null,
            certificatePolicyOids ?? [],
            setKeyUsageBits is not null,
            setKeyUsageBits ?? [],
            extendedKeyUsageOids is not null,
            extendedKeyUsageOids ?? []);
    }


    /// <summary>
    /// Reads a <c>QCStatements</c> extension value — <c>SEQUENCE OF QCStatement { statementId OID,
    /// statementInfo ANY OPTIONAL }</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc3739#section-3.2.6">RFC 3739 §3.2.6</see> — for the
    /// ETSI EN 319 412-5 statements the determination reads: <c>id-etsi-qcs-QcCompliance</c>,
    /// <c>id-etsi-qcs-QcSSCD</c>, and the <c>id-etsi-qcs-QcType</c> statement whose info is a
    /// <c>SEQUENCE OF OBJECT IDENTIFIER</c> naming the declared certificate types.
    /// </summary>
    /// <param name="qcStatements">The reader positioned at the extension's inner value.</param>
    /// <returns>The statement facts; unknown statements and unknown type identifiers are ignored.</returns>
    private static QcStatementFacts ReadQcStatements(AsnReader qcStatements)
    {
        bool hasQcCompliance = false;
        bool hasQcSscdStatement = false;
        List<EuQualifiedCertificateType> qcTypes = [];

        AsnReader statements = qcStatements.ReadSequence();
        while(statements.HasData)
        {
            AsnReader statement = statements.ReadSequence();
            string statementId = statement.ReadObjectIdentifier();
            switch(statementId)
            {
                case WellKnownOids.QcCompliance:
                    hasQcCompliance = true;
                    break;

                case WellKnownOids.QcSscd:
                    hasQcSscdStatement = true;
                    break;

                case WellKnownOids.QcType:
                    //A QcType statement without its statementInfo declares no types; a declared
                    //identifier no determination table selects rows by is omitted.
                    if(statement.HasData)
                    {
                        AsnReader declaredTypes = statement.ReadSequence();
                        while(declaredTypes.HasData)
                        {
                            EuQualifiedCertificateType? declaredType = EuQualifiedCertificateTypeMapping.FromOid(declaredTypes.ReadObjectIdentifier());
                            if(declaredType is EuQualifiedCertificateType knownType)
                            {
                                qcTypes.Add(knownType);
                            }
                        }
                    }

                    break;

                default:
                    break;
            }
        }

        qcStatements.ThrowIfNotEmpty();

        return new QcStatementFacts(hasQcCompliance, hasQcSscdStatement, qcTypes);
    }


    /// <summary>
    /// Reads a <c>CertificatePolicies</c> extension value — <c>SEQUENCE OF PolicyInformation</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.4">RFC 5280 §4.2.1.4</see> —
    /// collecting each <c>policyIdentifier</c> in certificate order; policy qualifiers are not facts.
    /// </summary>
    /// <param name="certificatePolicies">The reader positioned at the extension's inner value.</param>
    /// <returns>The policy identifiers in certificate order.</returns>
    private static List<string> ReadCertificatePolicyIdentifiers(AsnReader certificatePolicies)
    {
        List<string> policyOids = [];
        AsnReader policies = certificatePolicies.ReadSequence();
        while(policies.HasData)
        {
            AsnReader policyInformation = policies.ReadSequence();
            policyOids.Add(policyInformation.ReadObjectIdentifier());
        }

        certificatePolicies.ThrowIfNotEmpty();

        return policyOids;
    }


    /// <summary>
    /// Reads a <c>KeyUsage</c> extension value — a named <c>BIT STRING</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.3">RFC 5280 §4.2.1.3</see> —
    /// into the set bits, in ascending bit order. The <see cref="KeyUsageBitName"/> members are numbered
    /// exactly as RFC 5280 numbers the bits, and a named bit string's bit <c>n</c> is bit
    /// <c>7 - (n mod 8)</c> of content octet <c>n / 8</c>.
    /// </summary>
    /// <param name="keyUsage">The reader positioned at the extension's inner value.</param>
    /// <returns>The bits the certificate asserts to one.</returns>
    private static List<KeyUsageBitName> ReadSetKeyUsageBits(AsnReader keyUsage)
    {
        if(!keyUsage.TryReadPrimitiveBitString(out int unusedBitCount, out ReadOnlyMemory<byte> bits))
        {
            throw new AsnContentException("A KeyUsage value must be a primitive BIT STRING in DER (RFC 5280 §4.2.1.3).");
        }

        keyUsage.ThrowIfNotEmpty();

        List<KeyUsageBitName> setBits = [];
        ReadOnlySpan<byte> bitSpan = bits.Span;
        int bitCount = (bitSpan.Length * 8) - unusedBitCount;
        for(int bit = 0; bit <= (int)KeyUsageBitName.DecipherOnly && bit < bitCount; bit++)
        {
            if((bitSpan[bit / 8] & (0x80 >> (bit % 8))) != 0)
            {
                setBits.Add((KeyUsageBitName)bit);
            }
        }

        return setBits;
    }


    /// <summary>
    /// Reads an <c>ExtendedKeyUsage</c> extension value — <c>SEQUENCE OF KeyPurposeId</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.12">RFC 5280 §4.2.1.12</see> —
    /// collecting the key purpose identifiers in certificate order.
    /// </summary>
    /// <param name="extendedKeyUsage">The reader positioned at the extension's inner value.</param>
    /// <returns>The key purpose identifiers in certificate order.</returns>
    private static List<string> ReadKeyPurposeIdentifiers(AsnReader extendedKeyUsage)
    {
        List<string> keyPurposeOids = [];
        AsnReader keyPurposes = extendedKeyUsage.ReadSequence();
        while(keyPurposes.HasData)
        {
            keyPurposeOids.Add(keyPurposes.ReadObjectIdentifier());
        }

        extendedKeyUsage.ThrowIfNotEmpty();

        return keyPurposeOids;
    }


    /// <summary>The name attributes one distinguished name contributes to the facts.</summary>
    /// <param name="CountryCode">The first <c>countryName</c> value, or <see langword="null"/> when the name carries none.</param>
    /// <param name="OrganizationNames">The <c>organizationName</c> values in certificate order.</param>
    /// <param name="CommonNames">The <c>commonName</c> values in certificate order.</param>
    /// <param name="AttributeTypeOids">Every attribute type identifier in certificate order.</param>
    private sealed record DistinguishedNameFacts(
        string? CountryCode,
        IReadOnlyList<string> OrganizationNames,
        IReadOnlyList<string> CommonNames,
        IReadOnlyList<string> AttributeTypeOids);


    /// <summary>The statements one <c>QCStatements</c> extension contributes to the facts.</summary>
    /// <param name="HasQcCompliance">Whether the <c>id-etsi-qcs-QcCompliance</c> statement is present.</param>
    /// <param name="HasQcSscdStatement">Whether the <c>id-etsi-qcs-QcSSCD</c> statement is present.</param>
    /// <param name="QcTypes">The known declared certificate types in certificate order.</param>
    private sealed record QcStatementFacts(
        bool HasQcCompliance,
        bool HasQcSscdStatement,
        IReadOnlyList<EuQualifiedCertificateType> QcTypes);


    /// <summary>The extension contents the facts record carries, with presence tracked per extension.</summary>
    /// <param name="HasQcCompliance">Whether the <c>id-etsi-qcs-QcCompliance</c> statement is present.</param>
    /// <param name="HasQcSscdStatement">Whether the <c>id-etsi-qcs-QcSSCD</c> statement is present.</param>
    /// <param name="QcTypes">The known declared certificate types in certificate order.</param>
    /// <param name="HasCertificatePoliciesExtension">Whether a CertificatePolicies extension is present.</param>
    /// <param name="CertificatePolicyOids">The policy identifiers in certificate order.</param>
    /// <param name="HasKeyUsageExtension">Whether a KeyUsage extension is present.</param>
    /// <param name="SetKeyUsageBits">The Key Usage bits asserted to one, in ascending bit order.</param>
    /// <param name="HasExtendedKeyUsageExtension">Whether an ExtendedKeyUsage extension is present.</param>
    /// <param name="ExtendedKeyUsageOids">The key purpose identifiers in certificate order.</param>
    private sealed record ExtensionFacts(
        bool HasQcCompliance,
        bool HasQcSscdStatement,
        IReadOnlyList<EuQualifiedCertificateType> QcTypes,
        bool HasCertificatePoliciesExtension,
        IReadOnlyList<string> CertificatePolicyOids,
        bool HasKeyUsageExtension,
        IReadOnlyList<KeyUsageBitName> SetKeyUsageBits,
        bool HasExtendedKeyUsageExtension,
        IReadOnlyList<string> ExtendedKeyUsageOids);
}
