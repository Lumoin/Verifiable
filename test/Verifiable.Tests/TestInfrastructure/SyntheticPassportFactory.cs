using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
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
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the pooled EF.SOD, data-group buffers, and CSCA anchor transfers to the returned SyntheticPassport, which the caller disposes.")]
    public static SyntheticPassport Mint()
    {
        using ECDsa cscaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa documentSignerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 csca = MintCsca(cscaKey);
        using X509Certificate2 documentSigner = MintDocumentSigner(documentSignerKey, csca, cscaKey);

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

        return new SyntheticPassport(efSod, dataGroups, ToPkiCertificate(csca));
    }


    /// <summary>
    /// Mints a synthetic passport whose data groups come from <see cref="DataGroup1.Write"/> /
    /// <see cref="DataGroup2.Write"/> and whose EF.SOD comes from <see cref="DocumentSecurityObject.Write"/> —
    /// the owned producer end to end, signed by an independent base class library Document Signer.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the writer-minted data groups and EF.SOD transfers to the returned SyntheticPassport, which disposes them.")]
    public static SyntheticPassport MintFromWriters()
    {
        using ECDsa cscaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa documentSignerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 csca = MintCsca(cscaKey);
        using X509Certificate2 documentSigner = MintDocumentSigner(documentSignerKey, csca, cscaKey);

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

        return new SyntheticPassport(efSod, dataGroups, ToPkiCertificate(csca));
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


    /// <summary>Mints a Document Signer certificate issued under <paramref name="csca"/>.</summary>
    public static X509Certificate2 MintDocumentSigner(ECDsa key, X509Certificate2 csca, ECDsa cscaKey)
    {
        var request = new CertificateRequest("CN=Verifiable Test Document Signer", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        byte[] serial = new byte[8];
        serial[0] = 0x01;
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
    public static byte[] BuildLdsSecurityObject(params (int Number, byte[] Hash)[] dataGroupHashes)
    {
        ArgumentNullException.ThrowIfNull(dataGroupHashes);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteInteger(0);

            using(writer.PushSequence())
            {
                writer.WriteObjectIdentifier(Sha256Oid);
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
        PkiCertificateMemory cscaAnchor)
    {
        EfSod = efSod;
        DataGroups = dataGroups;
        CscaAnchor = cscaAnchor;
    }


    /// <summary>Gets the EF.SOD file.</summary>
    public ElementaryFile EfSod { get; }

    /// <summary>Gets the data groups keyed by data-group number, as a chip read returns them.</summary>
    public Dictionary<int, ElementaryFile> DataGroups { get; }

    /// <summary>Gets the Country Signing CA trust anchor.</summary>
    public PkiCertificateMemory CscaAnchor { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        EfSod.Dispose();
        foreach(ElementaryFile dataGroup in DataGroups.Values)
        {
            dataGroup.Dispose();
        }

        CscaAnchor.Dispose();
    }
}
