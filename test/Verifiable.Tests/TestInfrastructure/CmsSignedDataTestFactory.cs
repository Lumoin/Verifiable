using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using BcCmsSignedData = Org.BouncyCastle.Cms.CmsSignedData;
using SignerInformation = Org.BouncyCastle.Cms.SignerInformation;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Mints CAdES (ETSI EN 319 122-1) CMS SignedData with the framework's own CMS signer for the CAdES and
/// CMS-backend tests. It returns a pooled <see cref="CmsSignedData"/> carrier — the wire form the verifier
/// consumes — never a naked buffer; the third-party CMS APIs are byte-oriented, so their returns are consumed
/// inline into the carrier at the boundary. The signer is independent of the library wiring under test.
/// </summary>
internal static class CmsSignedDataTestFactory
{
    /// <summary>The signing-certificate-v2 signed attribute object identifier (ESS, RFC 5035 §3).</summary>
    public const string SigningCertificateV2Oid = "1.2.840.113549.1.9.16.2.47";

    /// <summary>The SHA-256 hash algorithm object identifier.</summary>
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";

    /// <summary>The SHA-256 digest length in bytes.</summary>
    private const int Sha256Length = 32;

    /// <summary>The signature-time-stamp-token unsigned attribute object identifier (CAdES-T).</summary>
    private const string SignatureTimeStampTokenOid = "1.2.840.113549.1.9.16.2.14";

    /// <summary>The id-ct-TSTInfo content type of an RFC 3161 timestamp token.</summary>
    private const string TstInfoContentTypeOid = "1.2.840.113549.1.9.16.1.4";


    /// <summary>
    /// Mints a self-signed certificate for an elliptic-curve signing key.
    /// </summary>
    public static X509Certificate2 MintSelfSignedCertificate(ECDsa key, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        ArgumentNullException.ThrowIfNull(key);

        var request = new CertificateRequest("CN=Verifiable CAdES Test", key, HashAlgorithmName.SHA256);

        return request.CreateSelfSigned(notBefore, notAfter);
    }


    /// <summary>
    /// Mints a self-signed certificate for an RSA signing key (PKCS#1 v1.5, SHA-256).
    /// </summary>
    public static X509Certificate2 MintSelfSignedCertificate(RSA key, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        ArgumentNullException.ThrowIfNull(key);

        var request = new CertificateRequest("CN=Verifiable CAdES Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return request.CreateSelfSigned(notBefore, notAfter);
    }


    /// <summary>
    /// Signs the payload as a plain CMS SignedData (no CAdES attributes) and returns the pooled wire carrier,
    /// optionally with a signing-time signed attribute. Used to exercise the neutral CMS seam.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the carrier transfers to the caller, which disposes it.")]
    public static CmsSignedData SignAsCms(
        ReadOnlySpan<byte> payload,
        X509Certificate2 signerCertificate,
        bool withSigningTime = false,
        DateTimeOffset signingTime = default)
    {
        var content = new ContentInfo(payload.ToArray());
        var signedCms = new SignedCms(content, detached: false);
        var signer = new CmsSigner(signerCertificate) { IncludeOption = X509IncludeOption.EndCertOnly };
        if(withSigningTime)
        {
            signer.SignedAttributes.Add(new Pkcs9SigningTime(signingTime.UtcDateTime));
        }

        signedCms.ComputeSignature(signer);

        return CmsSignedData.FromBytes(signedCms.Encode(), BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Signs the payload as a plain CMS SignedData with an explicit encapsulated content type (for example the
    /// ICAO CSCA Master List content type) and returns the pooled wire carrier. The third-party CMS API is
    /// byte-oriented, so the payload is materialised inline at the boundary.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the carrier transfers to the caller, which disposes it.")]
    public static CmsSignedData SignAsCms(ReadOnlySpan<byte> payload, string contentTypeOid, X509Certificate2 signerCertificate)
    {
        var content = new ContentInfo(new Oid(contentTypeOid), payload.ToArray());
        var signedCms = new SignedCms(content, detached: false);
        var signer = new CmsSigner(signerCertificate) { IncludeOption = X509IncludeOption.EndCertOnly };
        signedCms.ComputeSignature(signer);

        return CmsSignedData.FromBytes(signedCms.Encode(), BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Signs the payload as a CAdES-B-B signature and returns the pooled wire carrier. The CMS signer adds the
    /// content-type and message-digest attributes; this adds a signing-time attribute and, when requested, the
    /// signing-certificate-v2 attribute (ESS) binding the signer certificate (or a deliberately wrong one).
    /// </summary>
    /// <param name="payload">The content to sign.</param>
    /// <param name="signerCertificate">The signer certificate (the test holds its key).</param>
    /// <param name="signingTime">The signing-time attribute value.</param>
    /// <param name="includeSigningCertificate">Whether to add the signing-certificate-v2 attribute (a CAdES-B requirement).</param>
    /// <param name="bindWrongCertificate">When <see langword="true"/>, the signing-certificate-v2 hash binds a different certificate, for the mismatch negative.</param>
    /// <param name="explicitHashAlgorithm">When <see langword="true"/>, the ESSCertIDv2 names SHA-256 explicitly rather than relying on the default.</param>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the carrier transfers to the caller, which disposes it.")]
    public static CmsSignedData SignAsCAdES(
        ReadOnlySpan<byte> payload,
        X509Certificate2 signerCertificate,
        DateTimeOffset signingTime,
        bool includeSigningCertificate = true,
        bool bindWrongCertificate = false,
        bool explicitHashAlgorithm = false)
    {
        SignedCms signedCms = BuildCAdES(payload, signerCertificate, signingTime, includeSigningCertificate, bindWrongCertificate, explicitHashAlgorithm);

        return CmsSignedData.FromBytes(signedCms.Encode(), BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Signs the payload as a CAdES-B-T signature — a CAdES-B-B signature plus a signature timestamp (an RFC
    /// 3161 timestamp token, signed by <paramref name="tsaCertificate"/>) over the signature value, attached as
    /// the signature-time-stamp-token unsigned attribute — and returns the pooled wire carrier.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the carrier transfers to the caller, which disposes it.")]
    public static CmsSignedData SignAsCAdEST(
        ReadOnlySpan<byte> payload,
        X509Certificate2 signerCertificate,
        DateTimeOffset signingTime,
        X509Certificate2 tsaCertificate,
        DateTimeOffset timestampTime)
    {
        SignedCms cades = BuildCAdES(payload, signerCertificate, signingTime, includeSigningCertificate: true, bindWrongCertificate: false, explicitHashAlgorithm: false);

        //The timestamp imprints the CAdES signature value; the Microsoft SignerInfo API does not expose it, so
        //it is read back through BouncyCastle and hashed into a stack span — no owned buffer.
        SignerInformation bcSigner = new BcCmsSignedData(cades.Encode()).GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        Span<byte> imprint = stackalloc byte[Sha256Length];
        SHA256.HashData(bcSigner.GetSignature(), imprint);
        SignedCms token = BuildTimeStampToken(imprint, timestampTime, tsaCertificate);

        //An unsigned attribute is not covered by the signature, so attaching the token leaves it valid.
        cades.SignerInfos[0].AddUnsignedAttribute(new AsnEncodedData(new Oid(SignatureTimeStampTokenOid), token.Encode()));

        return CmsSignedData.FromBytes(cades.Encode(), BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Produces a tampered copy of a signed-data carrier: the first occurrence of <paramref name="marker"/> has
    /// its first byte flipped, so a signature over the affected region no longer verifies.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned carrier, which the caller disposes.")]
    public static CmsSignedData TamperContent(CmsSignedData original, ReadOnlySpan<byte> marker)
    {
        ArgumentNullException.ThrowIfNull(original);

        ReadOnlySpan<byte> span = original.AsReadOnlySpan();
        int index = span.IndexOf(marker);

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(span.Length);
        try
        {
            span.CopyTo(owner.Memory.Span);
            if(index >= 0)
            {
                owner.Memory.Span[index] ^= 0x01;
            }

            return new CmsSignedData(owner, CryptoTags.CmsEncodedSignedData);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Builds the CAdES-B-B <see cref="SignedCms"/> (a Microsoft object, not a buffer), the shared core of the
    /// baseline and timestamped signers.
    /// </summary>
    private static SignedCms BuildCAdES(
        ReadOnlySpan<byte> payload,
        X509Certificate2 signerCertificate,
        DateTimeOffset signingTime,
        bool includeSigningCertificate,
        bool bindWrongCertificate,
        bool explicitHashAlgorithm)
    {
        var content = new ContentInfo(payload.ToArray());
        var signedCms = new SignedCms(content, detached: false);
        var signer = new CmsSigner(signerCertificate) { IncludeOption = X509IncludeOption.EndCertOnly };
        signer.SignedAttributes.Add(new Pkcs9SigningTime(signingTime.UtcDateTime));
        if(includeSigningCertificate)
        {
            //The certificate hash goes into a stack span; the ESS DER is encoded straight into the attribute.
            Span<byte> certificateHash = stackalloc byte[Sha256Length];
            SHA256.HashData(signerCertificate.RawData, certificateHash);
            if(bindWrongCertificate)
            {
                certificateHash[0] ^= 0xFF;
            }

            var writer = new AsnWriter(AsnEncodingRules.DER);
            WriteSigningCertificateV2(writer, certificateHash, explicitHashAlgorithm);
            signer.SignedAttributes.Add(new AsnEncodedData(new Oid(SigningCertificateV2Oid), writer.Encode()));
        }

        signedCms.ComputeSignature(signer);

        return signedCms;
    }


    /// <summary>
    /// Signs a TSTInfo (binding <paramref name="imprint"/> at <paramref name="timestampTime"/>) as a CMS
    /// SignedData with the id-ct-TSTInfo content type — an RFC 3161 timestamp token.
    /// </summary>
    private static SignedCms BuildTimeStampToken(ReadOnlySpan<byte> imprint, DateTimeOffset timestampTime, X509Certificate2 tsaCertificate)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        WriteTstInfo(writer, imprint, timestampTime);
        var content = new ContentInfo(new Oid(TstInfoContentTypeOid), writer.Encode());
        var signedCms = new SignedCms(content, detached: false);
        var signer = new CmsSigner(tsaCertificate) { IncludeOption = X509IncludeOption.EndCertOnly };
        signedCms.ComputeSignature(signer);

        return signedCms;
    }


    /// <summary>
    /// Writes an RFC 3161 TSTInfo binding <paramref name="imprint"/> (a SHA-256 message imprint) at
    /// <paramref name="timestampTime"/> into <paramref name="writer"/>.
    /// </summary>
    private static void WriteTstInfo(AsnWriter writer, ReadOnlySpan<byte> imprint, DateTimeOffset timestampTime)
    {
        using(writer.PushSequence())
        {
            writer.WriteInteger(1);                                    //version
            writer.WriteObjectIdentifier("1.2.3.4.1");                 //policy (any)
            using(writer.PushSequence())                              //messageImprint
            {
                using(writer.PushSequence())                          //hashAlgorithm
                {
                    writer.WriteObjectIdentifier(Sha256Oid);
                    writer.WriteNull();
                }

                writer.WriteOctetString(imprint);
            }

            writer.WriteInteger(1);                                    //serialNumber
            writer.WriteGeneralizedTime(timestampTime);
        }
    }


    /// <summary>
    /// Writes a SigningCertificateV2 attribute value (ESS, RFC 5035) carrying one ESSCertIDv2 with the given
    /// certificate hash and the issuer-serial omitted into <paramref name="writer"/>. The SHA-256 hash
    /// algorithm is either omitted (the default) or named explicitly, exercising both parse branches.
    /// </summary>
    private static void WriteSigningCertificateV2(AsnWriter writer, ReadOnlySpan<byte> certificateHash, bool explicitHashAlgorithm)
    {
        using(writer.PushSequence())
        {
            using(writer.PushSequence())
            {
                using(writer.PushSequence())
                {
                    if(explicitHashAlgorithm)
                    {
                        using(writer.PushSequence())
                        {
                            writer.WriteObjectIdentifier(Sha256Oid);
                        }
                    }

                    writer.WriteOctetString(certificateHash);
                }
            }
        }
    }
}
