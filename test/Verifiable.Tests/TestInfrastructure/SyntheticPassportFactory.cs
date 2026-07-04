using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto.Digests;
using Verifiable.Apdu;
using Verifiable.Apdu.Lds;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Mints firewalled synthetic eMRTD material — a self-signed Country Signing CA, a Document Signer issued
/// under it, an LDS Security Object over the data-group hashes, and an EF.SOD whose CMS SignedData is signed
/// by the Document Signer with an independent base class library signer (the oracle). The verifier-facing
/// outputs are the pooled carriers a real read returns, never naked buffers. Used by Passive Authentication
/// and CSCA Master List tests so the synthetic-authority machinery has a single source of truth.
/// </summary>
internal static class SyntheticPassportFactory
{
    private const string LdsSecurityObjectOid = "2.23.136.1.1.1";
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";
    private const string Sha1Oid = "1.3.14.3.2.26";

    /// <summary>Bytes that are not a well-formed DER CRL, so the CRL parser rejects them.</summary>
    private static ReadOnlySpan<byte> MalformedCrlBytes => [0xDE, 0xAD, 0xBE, 0xEF];

    private const string WriterMrz =
        "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<" +
        "L898902C<3UTO6908061F9406236<<<<<<<8";

    private static readonly byte[] WriterFaceImage = [0xFF, 0xD8, 0x00, 0x11, 0x22, 0xFF, 0xD9];

    /// <summary>The default certificate validity start.</summary>
    public static readonly DateTimeOffset NotBefore = new(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The default certificate validity end.</summary>
    public static readonly DateTimeOffset NotAfter = new(2034, 1, 1, 0, 0, 0, TimeSpan.Zero);


    /// <summary>
    /// Mints a synthetic passport with hand-built data groups (arbitrary bytes wrapped in their DG tag).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the pooled EF.SOD, data-group buffers, CSCA anchor, and Document Signer certificate transfers to the returned SyntheticPassport, which the caller disposes.")]
    public static SyntheticPassport Mint()
    {
        using ECDsa cscaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa documentSignerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 csca = MintCsca(cscaKey);
        using X509Certificate2 documentSigner = MintDocumentSigner(documentSignerKey, csca);

        byte[] dg1 = [0x61, 0x05, 0x5F, 0x1F, 0x02, 0x41, 0x42];
        byte[] dg2 = [0x75, 0x04, 0x7F, 0x61, 0x01, 0x00];

        byte[] ldsSecurityObject = BuildLdsSecurityObject(
            (1, SHA256.HashData(dg1)),
            (2, SHA256.HashData(dg2)));

        ElementaryFile efSod = BuildEfSod(ldsSecurityObject, documentSigner);

        var dataGroups = new Dictionary<int, ElementaryFile>
        {
            [1] = ToElementaryFile(dg1, 0x0101),
            [2] = ToElementaryFile(dg2, 0x0102)
        };

        return new SyntheticPassport(efSod, dataGroups, ToPkiCertificate(csca), ToPkiCertificate(documentSigner));
    }


    /// <summary>
    /// Mints a synthetic passport whose data groups come from <see cref="DataGroup1.Write"/> /
    /// <see cref="DataGroup2.Write"/> and whose EF.SOD comes from <see cref="DocumentSecurityObject.Write"/> —
    /// the owned producer end to end, signed by an independent base class library Document Signer.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the writer-minted data groups, EF.SOD, and certificate carriers transfers to the returned SyntheticPassport, which disposes them.")]
    public static SyntheticPassport MintFromWriters()
    {
        using ECDsa cscaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa documentSignerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 csca = MintCsca(cscaKey);
        using X509Certificate2 documentSigner = MintDocumentSigner(documentSignerKey, csca);

        ElementaryFile dataGroup1 = DataGroup1.Write(WriterMrz, BaseMemoryPool.Shared);
        ElementaryFile dataGroup2 = DataGroup2.Write(WriterFaceImage, FaceImageFormat.Jpeg, BaseMemoryPool.Shared);

        byte[] ldsSecurityObject = BuildLdsSecurityObject(
            (1, SHA256.HashData(dataGroup1.Content)),
            (2, SHA256.HashData(dataGroup2.Content)));
        ElementaryFile efSod = BuildEfSod(ldsSecurityObject, documentSigner);

        var dataGroups = new Dictionary<int, ElementaryFile>
        {
            [1] = dataGroup1,
            [2] = dataGroup2
        };

        return new SyntheticPassport(efSod, dataGroups, ToPkiCertificate(csca), ToPkiCertificate(documentSigner));
    }


    /// <summary>
    /// Mints a synthetic passport whose LDS Security Object declares SHA-1 over SHA-1 data-group hashes — the
    /// collision-forgeable legacy digest — used to exercise the Passive Authentication SHA-1 policy gate.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the pooled EF.SOD, data-group buffers, CSCA anchor, and Document Signer certificate transfers to the returned SyntheticPassport, which the caller disposes.")]
    public static SyntheticPassport MintWithSha1SecurityObject()
    {
        using ECDsa cscaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa documentSignerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 csca = MintCsca(cscaKey);
        using X509Certificate2 documentSigner = MintDocumentSigner(documentSignerKey, csca);

        byte[] dg1 = [0x61, 0x05, 0x5F, 0x1F, 0x02, 0x41, 0x42];
        byte[] dg2 = [0x75, 0x04, 0x7F, 0x61, 0x01, 0x00];

        byte[] ldsSecurityObject = BuildLdsSecurityObject(
            Sha1Oid,
            (1, Sha1(dg1)),
            (2, Sha1(dg2)));

        ElementaryFile efSod = BuildEfSod(ldsSecurityObject, documentSigner);

        var dataGroups = new Dictionary<int, ElementaryFile>
        {
            [1] = ToElementaryFile(dg1, 0x0101),
            [2] = ToElementaryFile(dg2, 0x0102)
        };

        return new SyntheticPassport(efSod, dataGroups, ToPkiCertificate(csca), ToPkiCertificate(documentSigner));
    }


    /// <summary>
    /// Mints a synthetic passport whose Document Signer certificate violates the ICAO Doc 9303 Part 12 §7.1
    /// Document Signer profile — it is marked as a certificate authority (<c>cA=TRUE</c>) and asserts the
    /// <c>keyCertSign</c> key usage — used to exercise the Passive Authentication Document Signer profile gate.
    /// Everything else is well formed, so the certificate still chains to the CSCA and only the profile gate rejects it.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the pooled EF.SOD, data-group buffers, CSCA anchor, and Document Signer certificate transfers to the returned SyntheticPassport, which the caller disposes.")]
    public static SyntheticPassport MintWithNonConformantDocumentSigner()
    {
        using ECDsa cscaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa documentSignerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 csca = MintCsca(cscaKey);
        using X509Certificate2 documentSigner = MintNonConformantDocumentSigner(documentSignerKey, csca);

        byte[] dg1 = [0x61, 0x05, 0x5F, 0x1F, 0x02, 0x41, 0x42];
        byte[] dg2 = [0x75, 0x04, 0x7F, 0x61, 0x01, 0x00];

        byte[] ldsSecurityObject = BuildLdsSecurityObject(
            (1, SHA256.HashData(dg1)),
            (2, SHA256.HashData(dg2)));

        ElementaryFile efSod = BuildEfSod(ldsSecurityObject, documentSigner);

        var dataGroups = new Dictionary<int, ElementaryFile>
        {
            [1] = ToElementaryFile(dg1, 0x0101),
            [2] = ToElementaryFile(dg2, 0x0102)
        };

        return new SyntheticPassport(efSod, dataGroups, ToPkiCertificate(csca), ToPkiCertificate(documentSigner));
    }


    /// <summary>
    /// Returns a copy of <paramref name="certificate"/> as a pooled carrier with a second, critical KeyUsage
    /// extension (asserting <c>keyCertSign</c>) appended to its extensions — the RFC 5280 §4.2-forbidden shape
    /// (a certificate MUST NOT include more than one instance of an extension). A profile reader that returned only
    /// the first (conformant, digitalSignature-only) instance would misread this certificate as conformant; the
    /// reader must instead fail closed. The issuer signature is left unchanged — no longer valid over the modified
    /// TBSCertificate, which is immaterial to the certificate-profile reader this fixture exercises.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned pooled certificate carrier transfers to the caller, which disposes it.")]
    public static PkiCertificateMemory WithDuplicateKeyUsageExtension(PkiCertificateMemory certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        var addedKeyUsage = new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, critical: true);
        var extensionWriter = new AsnWriter(AsnEncodingRules.DER);
        using(extensionWriter.PushSequence())
        {
            extensionWriter.WriteObjectIdentifier(WellKnownOids.KeyUsageExtension);
            extensionWriter.WriteBoolean(true);
            extensionWriter.WriteOctetString(addedKeyUsage.RawData);
        }

        using IMemoryOwner<byte> extraExtension = EncodeToPooled(extensionWriter);

        AsnReader certificateReader = new AsnReader(certificate.AsReadOnlyMemory(), AsnEncodingRules.DER).ReadSequence();
        ReadOnlyMemory<byte> tbsCertificate = certificateReader.ReadEncodedValue();
        ReadOnlyMemory<byte> signatureAlgorithm = certificateReader.ReadEncodedValue();
        ReadOnlyMemory<byte> signatureValue = certificateReader.ReadEncodedValue();

        var extensionsTag = new Asn1Tag(TagClass.ContextSpecific, 3);
        AsnReader tbsReader = new AsnReader(tbsCertificate, AsnEncodingRules.DER).ReadSequence();
        var tbsWriter = new AsnWriter(AsnEncodingRules.DER);
        using(tbsWriter.PushSequence())
        {
            while(tbsReader.HasData)
            {
                Asn1Tag tag = tbsReader.PeekTag();
                if(tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 3)
                {
                    AsnReader extensionsSequence = tbsReader.ReadSequence(extensionsTag).ReadSequence();
                    using(tbsWriter.PushSequence(extensionsTag))
                    using(tbsWriter.PushSequence())
                    {
                        while(extensionsSequence.HasData)
                        {
                            tbsWriter.WriteEncodedValue(extensionsSequence.ReadEncodedValue().Span);
                        }

                        tbsWriter.WriteEncodedValue(extraExtension.Memory.Span);
                    }
                }
                else
                {
                    tbsWriter.WriteEncodedValue(tbsReader.ReadEncodedValue().Span);
                }
            }
        }

        using IMemoryOwner<byte> modifiedTbsCertificate = EncodeToPooled(tbsWriter);

        var certificateWriter = new AsnWriter(AsnEncodingRules.DER);
        using(certificateWriter.PushSequence())
        {
            certificateWriter.WriteEncodedValue(modifiedTbsCertificate.Memory.Span);
            certificateWriter.WriteEncodedValue(signatureAlgorithm.Span);
            certificateWriter.WriteEncodedValue(signatureValue.Span);
        }

        return new PkiCertificateMemory(EncodeToPooled(certificateWriter), PkiCertificateTags.X509Certificate);
    }


    /// <summary>Encodes an <see cref="AsnWriter"/> into an exact-size pooled buffer the caller owns.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned pooled buffer transfers to the caller, which disposes it.")]
    private static IMemoryOwner<byte> EncodeToPooled(AsnWriter writer)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(writer.GetEncodedLength());
        if(!writer.TryEncode(owner.Memory.Span, out _))
        {
            owner.Dispose();

            throw new InvalidOperationException("DER encoding failed.");
        }

        return owner;
    }


    /// <summary>
    /// Mints a DER-encoded CRL signed by <paramref name="issuer"/> with the issuer certificate's own private key,
    /// optionally revoking <paramref name="revokedCertificate"/>, valid across [<paramref name="thisUpdate"/>,
    /// <paramref name="nextUpdate"/>].
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the pooled CRL carrier transfers to the caller, which disposes it.")]
    public static PkiCertificateMemory MintCrl(X509Certificate2 issuer, X509Certificate2? revokedCertificate, DateTimeOffset thisUpdate, DateTimeOffset nextUpdate, long crlNumber)
    {
        ArgumentNullException.ThrowIfNull(issuer);

        var builder = new CertificateRevocationListBuilder();
        if(revokedCertificate is not null)
        {
            builder.AddEntry(revokedCertificate, thisUpdate);
        }

        return new PkiCertificateMemory(
            ToPooled(builder.Build(issuer, new System.Numerics.BigInteger(crlNumber), nextUpdate, HashAlgorithmName.SHA256, thisUpdate: thisUpdate)),
            PkiCertificateTags.X509Crl);
    }


    /// <summary>
    /// Mints a DER-encoded CRL that omits the optional <c>nextUpdate</c> field, signed by <paramref name="issuer"/>.
    /// The .NET CRL builder always emits <c>nextUpdate</c>, so this builds a normal clean CRL, removes the
    /// <c>nextUpdate</c> element from the TBSCertList, and re-signs the result with <paramref name="issuerKey"/>.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the pooled CRL carrier transfers to the caller, which disposes it.")]
    public static PkiCertificateMemory MintCrlWithoutNextUpdate(X509Certificate2 issuer, ECDsa issuerKey, DateTimeOffset thisUpdate)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(issuerKey);

        using IMemoryOwner<byte> baseCrl = ToPooled(new CertificateRevocationListBuilder().Build(
            issuer, System.Numerics.BigInteger.One, thisUpdate.AddDays(30), HashAlgorithmName.SHA256, thisUpdate: thisUpdate));

        AsnReader certificate = new AsnReader(baseCrl.Memory, AsnEncodingRules.DER).ReadSequence();
        ReadOnlyMemory<byte> tbsCertList = certificate.ReadEncodedValue();
        ReadOnlyMemory<byte> signatureAlgorithm = certificate.ReadEncodedValue();
        _ = certificate.ReadEncodedValue();

        AsnReader tbsReader = new AsnReader(tbsCertList, AsnEncodingRules.DER).ReadSequence();
        var tbsWriter = new AsnWriter(AsnEncodingRules.DER);
        int timeElements = 0;
        using(tbsWriter.PushSequence())
        {
            while(tbsReader.HasData)
            {
                Asn1Tag tag = tbsReader.PeekTag();
                bool isTime = tag.TagClass == TagClass.Universal
                    && (tag.TagValue == (int)UniversalTagNumber.UtcTime || tag.TagValue == (int)UniversalTagNumber.GeneralizedTime);
                if(isTime && ++timeElements == 2)
                {
                    //The second Time in a TBSCertList is nextUpdate (thisUpdate is the first); drop it.
                    _ = tbsReader.ReadEncodedValue();

                    continue;
                }

                tbsWriter.WriteEncodedValue(tbsReader.ReadEncodedValue().Span);
            }
        }

        using IMemoryOwner<byte> modifiedTbs = EncodeToPooled(tbsWriter);
        using IMemoryOwner<byte> signatureBuffer = BaseMemoryPool.Shared.Rent(issuerKey.GetMaxSignatureSize(DSASignatureFormat.Rfc3279DerSequence));
        if(!issuerKey.TrySignData(modifiedTbs.Memory.Span, signatureBuffer.Memory.Span, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence, out int signatureLength))
        {
            throw new InvalidOperationException("Signing the modified TBSCertList failed.");
        }

        var crlWriter = new AsnWriter(AsnEncodingRules.DER);
        using(crlWriter.PushSequence())
        {
            crlWriter.WriteEncodedValue(modifiedTbs.Memory.Span);
            crlWriter.WriteEncodedValue(signatureAlgorithm.Span);
            crlWriter.WriteBitString(signatureBuffer.Memory.Span[..signatureLength]);
        }

        return new PkiCertificateMemory(EncodeToPooled(crlWriter), PkiCertificateTags.X509Crl);
    }


    /// <summary>
    /// Mints a self-contained CRL revocation scenario around one CSCA and Document Signer, all relative to
    /// <paramref name="validationTime"/>: the certificates (including a same-name CA whose Key Usage lacks
    /// <c>cRLSign</c>), a clean CRL, a revoking CRL, a stale (expired) CRL, a forged revoking and a forged clean CRL
    /// (the CSCA's issuer name but a different key), a not-yet-valid CRL, a CRL with no <c>nextUpdate</c>, and a
    /// malformed CRL.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the pooled certificate and CRL carriers transfers to the returned RevocationScenario, which the caller disposes.")]
    public static RevocationScenario MintRevocationScenario(DateTimeOffset validationTime)
    {
        using ECDsa cscaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa documentSignerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa impostorCscaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 csca = MintCsca(cscaKey);
        using X509Certificate2 documentSigner = MintDocumentSigner(documentSignerKey, csca);
        //The CSCA's subject name but a different key — the source of the forged CRLs below.
        using X509Certificate2 impostorCsca = MintCsca(impostorCscaKey);
        //The CSCA's subject name and key but a Key Usage lacking cRLSign. Presented as a candidate it can verify a
        //genuine CSCA CRL (same key), but it is not authorised to sign CRLs, so the checker must still reject it.
        using X509Certificate2 nonCrlSigner = MintCscaWithoutCrlSign(cscaKey);

        DateTimeOffset thisUpdate = validationTime.AddDays(-1);
        DateTimeOffset nextUpdate = validationTime.AddDays(30);

        return new RevocationScenario
        {
            DocumentSigner = ToPkiCertificate(documentSigner),
            CscaAnchor = ToPkiCertificate(csca),
            NonCrlSignerAnchor = ToPkiCertificate(nonCrlSigner),
            CleanCrl = MintCrl(csca, revokedCertificate: null, thisUpdate, nextUpdate, crlNumber: 1),
            RevokingCrl = MintCrl(csca, documentSigner, thisUpdate, nextUpdate, crlNumber: 2),
            StaleCrl = MintCrl(csca, revokedCertificate: null, validationTime.AddDays(-30), validationTime.AddDays(-1), crlNumber: 3),
            ForgedRevokingCrl = MintCrl(impostorCsca, documentSigner, thisUpdate, nextUpdate, crlNumber: 4),
            ForgedCleanCrl = MintCrl(impostorCsca, revokedCertificate: null, thisUpdate, nextUpdate, crlNumber: 5),
            NotYetValidCrl = MintCrl(csca, revokedCertificate: null, validationTime.AddDays(1), validationTime.AddDays(30), crlNumber: 6),
            NoNextUpdateCrl = MintCrlWithoutNextUpdate(csca, cscaKey, thisUpdate),
            MalformedCrl = new PkiCertificateMemory(ToPooled(MalformedCrlBytes), PkiCertificateTags.X509Crl)
        };
    }


    /// <summary>Mints a self-signed Country Signing CA certificate.</summary>
    public static X509Certificate2 MintCsca(ECDsa key)
    {
        var request = new CertificateRequest("CN=Verifiable Test CSCA", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: false, 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        return request.CreateSelfSigned(NotBefore, NotAfter);
    }


    /// <summary>
    /// Mints a self-signed CA with the CSCA's subject name but a Key Usage that omits <c>cRLSign</c> (only
    /// <c>keyCertSign</c>) — a CA that is not authorised to sign CRLs per RFC 5280 §6.3.3(f).
    /// </summary>
    public static X509Certificate2 MintCscaWithoutCrlSign(ECDsa key)
    {
        var request = new CertificateRequest("CN=Verifiable Test CSCA", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: false, 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        return request.CreateSelfSigned(NotBefore, NotAfter);
    }


    /// <summary>Mints a Document Signer certificate issued under <paramref name="csca"/> (signed with the CSCA certificate's own private key).</summary>
    public static X509Certificate2 MintDocumentSigner(ECDsa key, X509Certificate2 csca)
    {
        var request = new CertificateRequest("CN=Verifiable Test Document Signer", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        //The Authority Key Identifier ties the Document Signer to its issuing CSCA's key (ICAO Doc 9303 Part 12).
        //Without it, a master list carrying several CSCAs that share a subject name is an ambiguous set of issuers:
        //name-based path builders can select the wrong CSCA and report a signature failure instead of chaining.
        request.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromCertificate(csca, includeKeyIdentifier: true, includeIssuerAndSerial: false));

        byte[] serial = new byte[8];
        serial[0] = 0x01;
        X509Certificate2 issued = request.Create(csca, NotBefore, NotAfter, serial);

        return issued.CopyWithPrivateKey(key);
    }


    /// <summary>
    /// Mints a Document Signer certificate issued under <paramref name="csca"/> that violates the ICAO Doc 9303
    /// Part 12 §7.1 Document Signer profile: it is marked as a certificate authority (<c>cA=TRUE</c>) and asserts
    /// <c>keyCertSign</c>, so it could issue further certificates. It still chains to the CSCA — only the Passive
    /// Authentication profile gate rejects it.
    /// </summary>
    public static X509Certificate2 MintNonConformantDocumentSigner(ECDsa key, X509Certificate2 csca)
    {
        var request = new CertificateRequest("CN=Verifiable Test Non-Conformant Document Signer", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: false, 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        request.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromCertificate(csca, includeKeyIdentifier: true, includeIssuerAndSerial: false));

        byte[] serial = new byte[8];
        serial[0] = 0x02;
        X509Certificate2 issued = request.Create(csca, NotBefore, NotAfter, serial);

        return issued.CopyWithPrivateKey(key);
    }


    /// <summary>Copies a certificate's DER into a pooled <see cref="PkiCertificateMemory"/>.</summary>
    public static PkiCertificateMemory ToPkiCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        return new PkiCertificateMemory(ToPooled(certificate.RawData), PkiCertificateTags.X509Certificate);
    }


    /// <summary>Copies bytes into an exact-size pooled buffer.</summary>
    public static IMemoryOwner<byte> ToPooled(ReadOnlySpan<byte> bytes)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return owner;
    }


    /// <summary>Wraps bytes in a pooled <see cref="ElementaryFile"/> carrier.</summary>
    public static ElementaryFile ToElementaryFile(ReadOnlySpan<byte> bytes, ushort fileIdentifier) =>
        new(ToPooled(bytes), fileIdentifier);


    /// <summary>Builds an LDS Security Object (SHA-256) over the given data-group hashes.</summary>
    public static byte[] BuildLdsSecurityObject(params (int Number, byte[] Hash)[] dataGroupHashes) =>
        BuildLdsSecurityObject(Sha256Oid, dataGroupHashes);


    /// <summary>Builds an LDS Security Object over the given data-group hashes, declaring <paramref name="digestAlgorithmOid"/> as its hash algorithm.</summary>
    public static byte[] BuildLdsSecurityObject(string digestAlgorithmOid, params (int Number, byte[] Hash)[] dataGroupHashes)
    {
        ArgumentNullException.ThrowIfNull(digestAlgorithmOid);
        ArgumentNullException.ThrowIfNull(dataGroupHashes);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteInteger(0);

            using(writer.PushSequence())
            {
                writer.WriteObjectIdentifier(digestAlgorithmOid);
            }

            using(writer.PushSequence())
            {
                foreach((int number, byte[] hash) in dataGroupHashes)
                {
                    using(writer.PushSequence())
                    {
                        writer.WriteInteger(number);
                        writer.WriteOctetString(hash);
                    }
                }
            }
        }

        return writer.Encode();
    }


    /// <summary>
    /// Computes a SHA-1 digest through the independent BouncyCastle oracle — firewalled from the verifier's
    /// registered digest seam, and off the base class library weak-hash surface the analyzer flags.
    /// </summary>
    private static byte[] Sha1(ReadOnlySpan<byte> data)
    {
        var digest = new Sha1Digest();
        digest.BlockUpdate(data);
        byte[] hash = new byte[digest.GetDigestSize()];
        digest.DoFinal(hash);

        return hash;
    }


    /// <summary>Wraps a Document-Signer-signed CMS over the LDS Security Object in EF.SOD via the library writer.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the EF.SOD carrier transfers to the caller; the CMS carrier is disposed once its bytes have been copied into the EF.SOD.")]
    public static ElementaryFile BuildEfSod(byte[] ldsSecurityObject, X509Certificate2 documentSigner)
    {
        using CmsSignedData cms = CmsSignedData.FromBytes(BuildCmsSignedData(ldsSecurityObject, documentSigner), BaseMemoryPool.Shared);

        return DocumentSecurityObject.Write(cms, BaseMemoryPool.Shared);
    }


    /// <summary>Signs the LDS Security Object as CMS SignedData (the independent oracle: base class library, not the stack under test).</summary>
    private static byte[] BuildCmsSignedData(byte[] ldsSecurityObject, X509Certificate2 documentSigner)
    {
        var content = new ContentInfo(new Oid(LdsSecurityObjectOid), ldsSecurityObject);
        var signedCms = new SignedCms(content, detached: false);
        var signer = new CmsSigner(documentSigner) { IncludeOption = X509IncludeOption.EndCertOnly };
        signedCms.ComputeSignature(signer);

        return signedCms.Encode();
    }
}


/// <summary>
/// A firewalled synthetic passport: the EF.SOD and data groups held in pooled memory as a real read returns
/// them, plus the CSCA trust anchor. Owns and disposes all of it.
/// </summary>
internal sealed class SyntheticPassport: IDisposable
{
    /// <summary>
    /// Initialises a new <see cref="SyntheticPassport"/>, taking ownership of every carrier.
    /// </summary>
    public SyntheticPassport(
        ElementaryFile efSod,
        Dictionary<int, ElementaryFile> dataGroups,
        PkiCertificateMemory cscaAnchor,
        PkiCertificateMemory documentSignerCertificate)
    {
        EfSod = efSod;
        DataGroups = dataGroups;
        CscaAnchor = cscaAnchor;
        DocumentSignerCertificate = documentSignerCertificate;
    }


    /// <summary>Gets the EF.SOD file.</summary>
    public ElementaryFile EfSod { get; }

    /// <summary>Gets the data groups keyed by data-group number, as a chip read returns them.</summary>
    public Dictionary<int, ElementaryFile> DataGroups { get; }

    /// <summary>Gets the Country Signing CA trust anchor.</summary>
    public PkiCertificateMemory CscaAnchor { get; }

    /// <summary>Gets the Document Signer certificate (the EF.SOD signer), as embedded in the EF.SOD.</summary>
    public PkiCertificateMemory DocumentSignerCertificate { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        EfSod.Dispose();
        foreach(ElementaryFile dataGroup in DataGroups.Values)
        {
            dataGroup.Dispose();
        }

        CscaAnchor.Dispose();
        DocumentSignerCertificate.Dispose();
    }
}


/// <summary>
/// A firewalled CRL revocation scenario: a Document Signer and its CSCA, plus four CRLs — clean, revoking, stale,
/// and forged (the CSCA's issuer name but a different signing key) — all held as pooled carriers. Owns and disposes
/// all of them.
/// </summary>
internal sealed class RevocationScenario: IDisposable
{
    /// <summary>Gets the Document Signer certificate whose revocation status the CRLs speak to.</summary>
    public required PkiCertificateMemory DocumentSigner { get; init; }

    /// <summary>Gets the Country Signing CA — the CRL issuer and the trust anchor.</summary>
    public required PkiCertificateMemory CscaAnchor { get; init; }

    /// <summary>Gets a CA with the CSCA's subject name but a Key Usage lacking cRLSign (not authorised to sign CRLs).</summary>
    public required PkiCertificateMemory NonCrlSignerAnchor { get; init; }

    /// <summary>Gets a valid CRL that does not revoke the Document Signer.</summary>
    public required PkiCertificateMemory CleanCrl { get; init; }

    /// <summary>Gets a valid CRL that revokes the Document Signer.</summary>
    public required PkiCertificateMemory RevokingCrl { get; init; }

    /// <summary>Gets an expired (stale) CRL that is past its next-update time.</summary>
    public required PkiCertificateMemory StaleCrl { get; init; }

    /// <summary>Gets a revoking CRL whose issuer name matches the CSCA but which is signed by a different key.</summary>
    public required PkiCertificateMemory ForgedRevokingCrl { get; init; }

    /// <summary>Gets a clean CRL whose issuer name matches the CSCA but which is signed by a different key.</summary>
    public required PkiCertificateMemory ForgedCleanCrl { get; init; }

    /// <summary>Gets a CRL whose this-update time is in the future (not yet valid).</summary>
    public required PkiCertificateMemory NotYetValidCrl { get; init; }

    /// <summary>Gets a CRL that omits the optional next-update field.</summary>
    public required PkiCertificateMemory NoNextUpdateCrl { get; init; }

    /// <summary>Gets a carrier whose bytes are not a well-formed CRL.</summary>
    public required PkiCertificateMemory MalformedCrl { get; init; }


    /// <inheritdoc/>
    public void Dispose()
    {
        DocumentSigner.Dispose();
        CscaAnchor.Dispose();
        NonCrlSignerAnchor.Dispose();
        CleanCrl.Dispose();
        RevokingCrl.Dispose();
        StaleCrl.Dispose();
        ForgedRevokingCrl.Dispose();
        ForgedCleanCrl.Dispose();
        NotYetValidCrl.Dispose();
        NoNextUpdateCrl.Dispose();
        MalformedCrl.Dispose();
    }
}
