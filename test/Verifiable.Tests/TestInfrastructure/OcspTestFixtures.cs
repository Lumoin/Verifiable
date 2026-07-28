using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.X509;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Mints RFC 6960/RFC 5280 fixtures for the OCSP waverev test classes: certificates carrying Authority
/// Information Access and CRL Distribution Points extensions (via <see cref="AsnWriter"/>, the same
/// hostile-input-shaped construction the certificate-facts fixtures elsewhere in this project use), and
/// <c>BasicOCSPResponse</c> vectors produced by the independent BouncyCastle OCSP implementation
/// (<c>Org.BouncyCastle.Ocsp</c>) — an ASN.1 encoder and an ECDSA signer distinct from this library's own
/// <c>OcspResponseVerification</c> reader and <c>OcspRequests</c> writer under test.
/// </summary>
/// <remarks>
/// X.509 cert-factory carve-out (mirroring <see cref="X509ChainTestRing"/> and
/// <c>QualifiedCertificateFactsExtractorTests</c>): <see cref="CertificateRequest"/> needs a live framework
/// ECDsa signing key, so certificates are minted with the platform factory. A minted certificate's private
/// key is then bridged to a BouncyCastle <see cref="AsymmetricKeyParameter"/> via
/// <see cref="DotNetUtilities.GetECDsaKeyPair(ECDsa)"/> exclusively to drive the independent BouncyCastle
/// OCSP response generator — the resulting response bytes are BouncyCastle's own DER encoding and ECDSA
/// signature, not this library's.
/// </remarks>
internal static class OcspTestFixtures
{
    /// <summary>The <c>uniformResourceIdentifier [6] IMPLICIT IA5String</c> GeneralName choice tag (RFC 5280 §4.2.1.6).</summary>
    private static Asn1Tag UniformResourceIdentifierTag { get; } = new(TagClass.ContextSpecific, 6);

    /// <summary>The <c>rfc822Name [1] IMPLICIT IA5String</c> GeneralName choice tag (RFC 5280 §4.2.1.6) — a non-URI form for the skip tests.</summary>
    private static Asn1Tag Rfc822NameTag { get; } = new(TagClass.ContextSpecific, 1);


    /// <summary>
    /// Writes a small (0..127) DER <c>ENUMERATED</c> value's raw TLV bytes directly. <see cref="AsnWriter"/>'s
    /// convenience <c>WriteInteger</c>/<c>WriteEnumeratedValue</c> overloads cannot express this: an explicit
    /// <see cref="TagClass.Universal"/> tag override must name the write operation's own natural tag, so
    /// <c>WriteInteger</c> rejects an <see cref="UniversalTagNumber.Enumerated"/> override, and
    /// <c>WriteEnumeratedValue</c> takes a C# <see cref="Enum"/> value rather than an arbitrary integer.
    /// </summary>
    /// <param name="writer">The writer to append to.</param>
    /// <param name="value">The value, in <c>0..127</c> so it fits a single content octet.</param>
    private static void WriteSmallEnumerated(AsnWriter writer, byte value) => writer.WriteEncodedValue([0x0A, 0x01, value]);


    /// <summary>Maps an <see cref="OcspCertIdDigestAlgorithm"/> to its RFC 6960/5754 hash algorithm OID.</summary>
    /// <param name="algorithm">The digest algorithm to map.</param>
    /// <returns>The dotted OID string.</returns>
    internal static string CertIdHashOid(OcspCertIdDigestAlgorithm algorithm) => algorithm switch
    {
        OcspCertIdDigestAlgorithm.Sha256 => WellKnownOids.Sha256,
        OcspCertIdDigestAlgorithm.Sha1 => WellKnownOids.Sha1,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unsupported OCSP CertID digest algorithm.")
    };


    /// <summary>
    /// Maps an <see cref="OcspCertIdDigestAlgorithm"/> to the <c>AlgorithmIdentifier</c> BouncyCastle's
    /// <see cref="CertificateID"/> constructor takes — SHA-1 with its RFC 3279 explicit NULL parameters
    /// (<see cref="CertificateID.DigestSha1"/>), SHA-256 with RFC 5754 §2's absent parameters, matching
    /// exactly what <c>OcspRequests</c> itself writes.
    /// </summary>
    /// <param name="algorithm">The digest algorithm to map.</param>
    /// <returns>The BouncyCastle algorithm identifier.</returns>
    private static Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier CertIdHashAlgorithmIdentifier(OcspCertIdDigestAlgorithm algorithm) => algorithm switch
    {
        OcspCertIdDigestAlgorithm.Sha256 => new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(new DerObjectIdentifier(WellKnownOids.Sha256)),
        OcspCertIdDigestAlgorithm.Sha1 => CertificateID.DigestSha1,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unsupported OCSP CertID digest algorithm.")
    };


    /// <summary>
    /// Encodes an Authority Information Access extension value
    /// (<see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.2.1">RFC 5280 §4.2.2.1</see>) from
    /// access-method/GeneralName pairs, so a test can compose a URI entry, a non-URI GeneralName to be
    /// skipped, or an arbitrary access method verbatim.
    /// </summary>
    /// <param name="entries">The access-method OID and GeneralName choice tag/value pairs, in extension order.</param>
    /// <returns>The extension, non-critical, ready to add to a <see cref="CertificateRequest"/>.</returns>
    internal static X509Extension CreateAuthorityInfoAccessExtension(params (string AccessMethod, Asn1Tag NameTag, string NameValue)[] entries)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            foreach((string accessMethod, Asn1Tag nameTag, string nameValue) in entries)
            {
                using(writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(accessMethod);
                    writer.WriteCharacterString(UniversalTagNumber.IA5String, nameValue, nameTag);
                }
            }
        }

        return new X509Extension(WellKnownOids.AuthorityInfoAccessExtension, writer.Encode(), critical: false);
    }


    /// <summary>An AIA GeneralName entry using the URI-form <c>uniformResourceIdentifier</c> choice.</summary>
    /// <param name="accessMethod">The access method OID this entry is filed under.</param>
    /// <param name="uri">The URI value.</param>
    /// <returns>The entry tuple, for <see cref="CreateAuthorityInfoAccessExtension(ValueTuple{string, Asn1Tag, string}[])"/>.</returns>
    internal static (string AccessMethod, Asn1Tag NameTag, string NameValue) UriAiaEntry(string accessMethod, string uri) =>
        (accessMethod, UniformResourceIdentifierTag, uri);


    /// <summary>An AIA GeneralName entry using the non-URI <c>rfc822Name</c> choice, for the "must be skipped" fixtures.</summary>
    /// <param name="accessMethod">The access method OID this entry is filed under.</param>
    /// <param name="emailAddress">The rfc822Name value.</param>
    /// <returns>The entry tuple, for <see cref="CreateAuthorityInfoAccessExtension(ValueTuple{string, Asn1Tag, string}[])"/>.</returns>
    internal static (string AccessMethod, Asn1Tag NameTag, string NameValue) NonUriAiaEntry(string accessMethod, string emailAddress) =>
        (accessMethod, Rfc822NameTag, emailAddress);


    /// <summary>The distribution-point shapes <see cref="CreateCrlDistributionPointsExtension"/> can encode.</summary>
    internal enum DistributionPointKind
    {
        /// <summary>A <c>fullName [0] IMPLICIT GeneralNames</c> choice carrying one <c>uniformResourceIdentifier</c> entry.</summary>
        FullNameUri,

        /// <summary>A <c>nameRelativeToCRLIssuer [1] IMPLICIT RDN</c> choice — not a URI form, must be skipped.</summary>
        NameRelativeToCrlIssuer,

        /// <summary>A distribution point carrying only <c>reasons [1]</c>, omitting <c>distributionPoint</c> entirely — contributes no URI.</summary>
        ReasonsOnly
    }


    /// <summary>
    /// Encodes a CRL Distribution Points extension value
    /// (<see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13">RFC 5280 §4.2.1.13</see>) from
    /// distribution-point specifications, so a test can mix a URI-bearing point with the non-URI and
    /// reasons-only shapes the extractor must skip without failing.
    /// </summary>
    /// <param name="points">The distribution points, in extension order.</param>
    /// <returns>The extension, non-critical.</returns>
    internal static X509Extension CreateCrlDistributionPointsExtension(params (DistributionPointKind Kind, string? Uri)[] points)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            foreach((DistributionPointKind kind, string? uri) in points)
            {
                using(writer.PushSequence())
                {
                    switch(kind)
                    {
                        case DistributionPointKind.FullNameUri:
                            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                            {
                                using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                                {
                                    writer.WriteCharacterString(UniversalTagNumber.IA5String, uri!, UniformResourceIdentifierTag);
                                }
                            }

                            break;

                        case DistributionPointKind.NameRelativeToCrlIssuer:
                            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                            {
                                //nameRelativeToCRLIssuer [1] IMPLICIT RDN ::= SET OF AttributeTypeAndValue.
                                using(writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 1)))
                                {
                                    using(writer.PushSequence())
                                    {
                                        writer.WriteObjectIdentifier(WellKnownOids.CommonName);
                                        writer.WriteCharacterString(UniversalTagNumber.UTF8String, "Relative Issuer Name");
                                    }
                                }
                            }

                            break;

                        case DistributionPointKind.ReasonsOnly:
                            //reasons [1] IMPLICIT ReasonFlags ::= BIT STRING; distributionPoint is omitted entirely.
                            writer.WriteBitString([0x80], 0, new Asn1Tag(TagClass.ContextSpecific, 1));
                            break;

                        default:
                            throw new ArgumentOutOfRangeException(nameof(points), kind, "Unsupported distribution point kind.");
                    }
                }
            }
        }

        return new X509Extension(WellKnownOids.CrlDistributionPointsExtension, writer.Encode(), critical: false);
    }


    /// <summary>
    /// Assembles a minimal <c>Certificate</c> directly with <see cref="AsnWriter"/> — structural stand-ins for
    /// <c>serialNumber</c>/<c>signature</c>/<c>subjectPublicKeyInfo</c>/<c>signatureValue</c>, exactly as
    /// <c>QualifiedCertificateFactsExtractorTests</c>' synthetic-certificate helper does — for the one shape
    /// <see cref="CertificateRequest"/> refuses to mint: two extensions filed under the same OID
    /// (<see cref="System.Security.Cryptography.X509Certificates.CertificateRequest"/> rejects a duplicate
    /// extension OID at build time, but RFC 5280 §4.2 nowhere forbids a certificate from carrying one on the
    /// wire).
    /// </summary>
    /// <param name="extensions">The raw extensions, in certificate order, duplicates permitted.</param>
    /// <returns>The pooled certificate carrier; the caller disposes it.</returns>
    internal static PkiCertificateMemory BuildSyntheticCertificateWithRawExtensions(params (string Oid, byte[] Value)[] extensions)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())                                        //Certificate.
        {
            using(writer.PushSequence())                                    //tbsCertificate.
            {
                using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    writer.WriteInteger(2);                                 //version v3.
                }

                writer.WriteInteger(1);                                     //serialNumber stand-in.
                using(writer.PushSequence())                                //signature AlgorithmIdentifier stand-in.
                {
                    writer.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
                }

                WriteSingleCommonNameSequence(writer, "Synthetic Issuer");
                using(writer.PushSequence())                                //validity.
                {
                    writer.WriteUtcTime(new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero));
                    writer.WriteUtcTime(new DateTimeOffset(2034, 1, 1, 0, 0, 0, TimeSpan.Zero));
                }

                WriteSingleCommonNameSequence(writer, "Synthetic Subject");
                using(writer.PushSequence())                                //subjectPublicKeyInfo stand-in, skipped whole by the extractor.
                {
                }

                using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3)))
                {
                    using(writer.PushSequence())                            //Extensions.
                    {
                        foreach((string oid, byte[] value) in extensions)
                        {
                            using(writer.PushSequence())                    //Extension.
                            {
                                writer.WriteObjectIdentifier(oid);
                                writer.WriteOctetString(value);
                            }
                        }
                    }
                }
            }

            using(writer.PushSequence())                                    //signatureAlgorithm stand-in.
            {
                writer.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
            }

            writer.WriteBitString([]);                                      //signatureValue stand-in.
        }

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(writer.GetEncodedLength());
        _ = writer.Encode(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    /// <summary>Writes a <c>Name</c> (RFC 5280 §4.1.2.4) carrying a single <c>commonName</c> relative distinguished name.</summary>
    /// <param name="writer">The writer to append to.</param>
    /// <param name="commonName">The common name value.</param>
    private static void WriteSingleCommonNameSequence(AsnWriter writer, string commonName)
    {
        using(writer.PushSequence())
        {
            using(writer.PushSetOf())
            {
                using(writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(WellKnownOids.CommonName);
                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, commonName);
                }
            }
        }
    }


    /// <summary>Mints a self-signed Root CA carrying a Subject Key Identifier, for issuing certificates in these fixtures.</summary>
    /// <param name="subjectCn">The CA's common name.</param>
    /// <param name="notBefore">The validity start.</param>
    /// <param name="notAfter">The validity end.</param>
    /// <returns>The minted certificate and its signing key; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the signing key transfers to the returned MintedCertificate, which the caller disposes.")]
    internal static MintedCertificate MintRootCa(string subjectCn, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        try
        {
            var request = new CertificateRequest($"CN={subjectCn}", key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 2, critical: true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature, critical: true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, X509SubjectKeyIdentifierHashAlgorithm.Sha256, critical: false));

            using X509Certificate2 selfSignedWithKey = request.CreateSelfSigned(notBefore.UtcDateTime, notAfter.UtcDateTime);
            X509Certificate2 publicOnly = X509CertificateLoader.LoadCertificate(selfSignedWithKey.RawData);

            return new MintedCertificate(publicOnly, key);
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Mints a certificate issued by <paramref name="issuerCertificate"/>/<paramref name="issuerKey"/>, carrying
    /// the supplied extensions plus a Subject Key Identifier and an Authority Key Identifier chained to the
    /// issuer's own Subject Key Identifier (so chain building never sees an ambiguous same-subject issuer).
    /// </summary>
    /// <param name="issuerCertificate">The issuer.</param>
    /// <param name="issuerKey">The issuer's private key.</param>
    /// <param name="subjectCn">The subject's common name.</param>
    /// <param name="notBefore">The validity start.</param>
    /// <param name="notAfter">The validity end.</param>
    /// <param name="extensions">Extensions beyond Basic Constraints/Key Usage/Subject Key Identifier/Authority Key Identifier, in certificate order.</param>
    /// <param name="isCa">Whether this certificate's Basic Constraints assert <c>cA</c>.</param>
    /// <returns>The minted certificate and its signing key; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the signing key transfers to the returned MintedCertificate, which the caller disposes.")]
    internal static MintedCertificate MintCertificate(
        X509Certificate2 issuerCertificate,
        ECDsa issuerKey,
        string subjectCn,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        IReadOnlyList<X509Extension> extensions,
        bool isCa = false)
    {
        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        try
        {
            var request = new CertificateRequest($"CN={subjectCn}", key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: isCa, hasPathLengthConstraint: isCa, pathLengthConstraint: isCa ? 0 : 0, critical: true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                isCa ? X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign : X509KeyUsageFlags.DigitalSignature, critical: true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, X509SubjectKeyIdentifierHashAlgorithm.Sha256, critical: false));

            X509SubjectKeyIdentifierExtension? issuerSubjectKeyId = X509ChainTestRing.FindSubjectKeyIdentifier(issuerCertificate);
            if(issuerSubjectKeyId is not null)
            {
                request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(issuerSubjectKeyId));
            }

            foreach(X509Extension extension in extensions)
            {
                request.CertificateExtensions.Add(extension);
            }

            using Salt serial = X509ChainTestRing.CreateSerialNumber();
            using X509Certificate2 issuerWithKey = issuerCertificate.HasPrivateKey ? issuerCertificate : issuerCertificate.CopyWithPrivateKey(issuerKey);
            using X509Certificate2 signed = request.Create(issuerWithKey, notBefore.UtcDateTime, notAfter.UtcDateTime, serial.AsReadOnlySpan());
            X509Certificate2 publicOnly = X509CertificateLoader.LoadCertificate(signed.RawData);

            return new MintedCertificate(publicOnly, key);
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }


    /// <summary>Copies a certificate's DER bytes into a pooled <see cref="PkiCertificateMemory"/> tagged as an X.509 certificate.</summary>
    /// <param name="certificate">The certificate to copy.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    internal static PkiCertificateMemory ToCertificateCarrier(X509Certificate2 certificate)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(certificate.RawDataMemory.Length);
        certificate.RawDataMemory.Span.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    /// <summary>Wraps arbitrary DER bytes into a pooled <see cref="PkiCertificateMemory"/> tagged as an OCSP response.</summary>
    /// <param name="responseBytes">The DER-encoded <c>OCSPResponse</c> bytes.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    internal static PkiCertificateMemory ToResponseCarrier(byte[] responseBytes)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(responseBytes.Length);
        responseBytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.OcspResponse);
    }


    /// <summary>Parses a certificate's DER bytes with the independent BouncyCastle certificate parser.</summary>
    /// <param name="certificate">The certificate to parse.</param>
    /// <returns>The BouncyCastle certificate.</returns>
    internal static BcX509Certificate ToBouncyCastleCertificate(X509Certificate2 certificate) =>
        new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(certificate.RawData);


    /// <summary>Bridges a platform ECDsa private key to a BouncyCastle signing key, exclusively to drive the independent BouncyCastle OCSP response generator (see class remarks).</summary>
    /// <param name="key">The platform key.</param>
    /// <returns>The BouncyCastle private key parameter.</returns>
    internal static AsymmetricKeyParameter ToBouncyCastlePrivateKey(ECDsa key) => DotNetUtilities.GetECDsaKeyPair(key).Private;


    /// <summary>
    /// Mints a <c>BasicOCSPResponse</c>-carrying <c>OCSPResponse</c> (RFC 6960 §4.2.1) with the independent
    /// BouncyCastle OCSP implementation, signed by <paramref name="signerCertificate"/>/<paramref name="signerKey"/>.
    /// </summary>
    /// <param name="targetCertificate">The certificate the single response answers for.</param>
    /// <param name="issuerCertificate">The target's issuer — the <c>CertID</c> hash input.</param>
    /// <param name="certIdDigestAlgorithm">The <c>CertID</c> hash algorithm.</param>
    /// <param name="signerCertificate">The certificate whose key signs the response — the CA itself for a direct response, or a delegated responder certificate.</param>
    /// <param name="signerKey">The signer's private key.</param>
    /// <param name="responderIdByKey">Whether the <c>responderID</c> is <c>byKey</c> (a SHA-1 key hash) rather than <c>byName</c> (the signer's subject).</param>
    /// <param name="embeddedCertificates">Certificates to embed in the response's <c>certs [0]</c> block, or <see langword="null"/> for none.</param>
    /// <param name="status">The <c>CertStatus</c> to report.</param>
    /// <param name="thisUpdate">The <c>thisUpdate</c> instant.</param>
    /// <param name="nextUpdate">The optional <c>nextUpdate</c> instant.</param>
    /// <param name="revocationTime">The revocation time, required when <paramref name="status"/> is <see cref="OcspCertificateStatus.Revoked"/>.</param>
    /// <param name="revocationReason">The optional revocation reason.</param>
    /// <param name="echoNonce">The nonce to echo in a <c>responseExtensions</c> <c>id-pkix-ocsp-nonce</c> entry, or <see langword="null"/> for none.</param>
    /// <param name="serialOverride">A serial number to write into the <c>CertID</c> instead of the target certificate's own — for the <c>UnmatchedCertificateId</c> fixture.</param>
    /// <param name="certIdHashAlgorithmOverride">
    /// A <c>hashAlgorithm AlgorithmIdentifier</c> to use for the <c>SingleResponse</c>'s <c>CertID</c> instead
    /// of the one <paramref name="certIdDigestAlgorithm"/> maps to — for a fixture proving the reader tolerates
    /// a re-encoded, rather than echoed, <c>CertID</c> (e.g. explicit NULL parameters where the request wrote
    /// them absent). The digest itself is still whatever this identifier's OID names; only the parameters
    /// encoding differs from the default mapping.
    /// </param>
    /// <param name="extraCertIdSerialNumbers">
    /// Additional serial numbers, under <paramref name="issuerCertificate"/>, to add as extra <c>Good</c>
    /// <c>SingleResponse</c> entries alongside the one answering for <paramref name="targetCertificate"/> — for
    /// a fixture proving the reader tolerates a response carrying more than one <c>SingleResponse</c>.
    /// </param>
    /// <returns>The pooled response carrier; the caller disposes it.</returns>
    internal static PkiCertificateMemory MintOcspResponse(
        X509Certificate2 targetCertificate,
        X509Certificate2 issuerCertificate,
        OcspCertIdDigestAlgorithm certIdDigestAlgorithm,
        X509Certificate2 signerCertificate,
        ECDsa signerKey,
        bool responderIdByKey,
        IReadOnlyList<X509Certificate2>? embeddedCertificates,
        OcspCertificateStatus status,
        DateTimeOffset thisUpdate,
        DateTimeOffset? nextUpdate,
        DateTimeOffset? revocationTime = null,
        int? revocationReason = null,
        Nonce? echoNonce = null,
        BcBigInteger? serialOverride = null,
        Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier? certIdHashAlgorithmOverride = null,
        IReadOnlyList<BcBigInteger>? extraCertIdSerialNumbers = null)
    {
        BcX509Certificate bcTarget = ToBouncyCastleCertificate(targetCertificate);
        BcX509Certificate bcIssuer = ToBouncyCastleCertificate(issuerCertificate);
        BcX509Certificate bcSigner = ToBouncyCastleCertificate(signerCertificate);
        AsymmetricKeyParameter signerPrivateKey = ToBouncyCastlePrivateKey(signerKey);

        Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier certIdHashAlgorithm = certIdHashAlgorithmOverride ?? CertIdHashAlgorithmIdentifier(certIdDigestAlgorithm);
        var certId = new CertificateID(certIdHashAlgorithm, bcIssuer, serialOverride ?? bcTarget.SerialNumber);

        RespID responderId = responderIdByKey ? new RespID(bcSigner.GetPublicKey()) : new RespID(bcSigner.SubjectDN);
        var generator = new BasicOcspRespGenerator(responderId);

        CertificateStatus certStatus = status switch
        {
            OcspCertificateStatus.Good => CertificateStatus.Good,
            OcspCertificateStatus.Revoked when revocationReason is int reason => new RevokedStatus(revocationTime!.Value.UtcDateTime, reason),
            OcspCertificateStatus.Revoked => new RevokedStatus(revocationTime!.Value.UtcDateTime),
            OcspCertificateStatus.Unknown => new UnknownStatus(),
            _ => throw new ArgumentOutOfRangeException(nameof(status), status, "Unsupported OCSP certificate status.")
        };

        generator.AddResponse(certId, certStatus, thisUpdate.UtcDateTime, nextUpdate?.UtcDateTime, singleExtensions: null);

        if(extraCertIdSerialNumbers is { Count: > 0 })
        {
            foreach(BcBigInteger extraSerial in extraCertIdSerialNumbers)
            {
                var extraCertId = new CertificateID(certIdHashAlgorithm, bcIssuer, extraSerial);
                generator.AddResponse(extraCertId, CertificateStatus.Good, thisUpdate.UtcDateTime, nextUpdate?.UtcDateTime, singleExtensions: null);
            }
        }

        if(echoNonce is not null)
        {
            var extensionsGenerator = new Org.BouncyCastle.Asn1.X509.X509ExtensionsGenerator();
            extensionsGenerator.AddExtension(OcspObjectIdentifiers.PkixOcspNonce, critical: false, new DerOctetString(echoNonce.AsReadOnlySpan().ToArray()));
            generator.SetResponseExtensions(extensionsGenerator.Generate());
        }

        BcX509Certificate[]? chain = embeddedCertificates is { Count: > 0 }
            ? [.. embeddedCertificates.Select(ToBouncyCastleCertificate)]
            : null;

        BasicOcspResp basicResponse = generator.Generate("SHA256withECDSA", signerPrivateKey, chain, thisUpdate.UtcDateTime);

        var responseGenerator = new OCSPRespGenerator();
        OcspResp response = responseGenerator.Generate(OcspRespStatus.Successful, basicResponse);

        return ToResponseCarrier(response.GetEncoded());
    }


    /// <summary>Mints an <c>OCSPResponse</c> whose <c>responseStatus</c> is not <c>successful</c> and which therefore carries no <c>responseBytes</c>.</summary>
    /// <param name="status">The non-successful <c>OCSPResponseStatus</c> ENUMERATED value.</param>
    /// <returns>The pooled response carrier; the caller disposes it.</returns>
    internal static PkiCertificateMemory MintNonSuccessfulOcspResponse(int status)
    {
        var responseGenerator = new OCSPRespGenerator();
        OcspResp response = responseGenerator.Generate(status, null);

        return ToResponseCarrier(response.GetEncoded());
    }


    /// <summary>
    /// Flips the last byte of a minted response's bytes — for a response with no embedded <c>certs</c> block
    /// this lands inside the outer <c>signature</c> BIT STRING content, corrupting the signature while leaving
    /// every other structural field, including the envelope and <c>tbsResponseData</c>, untouched.
    /// </summary>
    /// <param name="response">The response carrier to corrupt; disposed by this call.</param>
    /// <returns>A new carrier with the corrupted bytes; the caller disposes it.</returns>
    internal static PkiCertificateMemory FlipLastByte(PkiCertificateMemory response)
    {
        using(response)
        {
            byte[] bytes = response.AsReadOnlySpan().ToArray();
            bytes[^1] ^= 0xFF;

            return ToResponseCarrier(bytes);
        }
    }


    /// <summary>
    /// Builds an <c>OCSPResponse</c> whose <c>responseType</c> is not <c>id-pkix-ocsp-basic</c> — a well-formed
    /// envelope the reader must recognise it cannot interpret, per RFC 6960 §4.2.1.
    /// </summary>
    /// <returns>The pooled response carrier; the caller disposes it.</returns>
    internal static PkiCertificateMemory BuildResponseWithUnrecognisedResponseType()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            WriteSmallEnumerated(writer, 0);
            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                using(writer.PushSequence())
                {
                    writer.WriteObjectIdentifier("1.2.3.4.5");  //An arbitrary, unrecognised responseType.
                    writer.WriteOctetString([0x01, 0x02, 0x03]);
                }
            }
        }

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(writer.GetEncodedLength());
        _ = writer.Encode(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.OcspResponse);
    }


    /// <summary>
    /// Builds a minimal, hand-assembled <c>OCSPResponse</c> whose <c>BasicOCSPResponse</c> carries either
    /// trailing content inside <c>tbsResponseData</c> or a mis-tagged <c>certs</c> block — both malformations
    /// this fixture's <see cref="MintOcspResponse"/> cannot produce because BouncyCastle only ever emits
    /// conformant structures.
    /// </summary>
    /// <param name="trailingDataInTbsResponseData">Whether an extra INTEGER trails the legitimate <c>tbsResponseData</c> fields, inside its SEQUENCE.</param>
    /// <param name="misTaggedCertsBlock">Whether a <c>[1]</c>-tagged element, rather than the conformant <c>[0]</c>, follows the signature.</param>
    /// <returns>The pooled response carrier; the caller disposes it.</returns>
    internal static PkiCertificateMemory BuildStructurallyMalformedBasicResponse(bool trailingDataInTbsResponseData, bool misTaggedCertsBlock)
    {
        var basicWriter = new AsnWriter(AsnEncodingRules.DER);
        using(basicWriter.PushSequence())                                              //BasicOCSPResponse.
        {
            using(basicWriter.PushSequence())                                          //tbsResponseData.
            {
                using(basicWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2)))
                {
                    //responderID byKey [2], a 20-byte stand-in SHA-1 KeyHash.
                    basicWriter.WriteOctetString(new byte[20]);
                }

                basicWriter.WriteGeneralizedTime(TimeProvider.System.GetUtcNow());     //producedAt.
                using(basicWriter.PushSequence())                                      //responses SEQUENCE OF SingleResponse — empty.
                {
                }

                if(trailingDataInTbsResponseData)
                {
                    basicWriter.WriteInteger(1);                                       //Not an RFC 6960 ResponseData field.
                }
            }

            using(basicWriter.PushSequence())                                          //signatureAlgorithm stand-in.
            {
                basicWriter.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
            }

            basicWriter.WriteBitString([]);                                            //signature stand-in.

            using(basicWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, misTaggedCertsBlock ? 1 : 0)))
            {
                using(basicWriter.PushSequence())
                {
                }
            }
        }

        byte[] basicResponseBytes = basicWriter.Encode();

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())                                                    //OCSPResponse.
        {
            WriteSmallEnumerated(writer, 0);         //responseStatus successful.
            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                using(writer.PushSequence())                                            //ResponseBytes.
                {
                    writer.WriteObjectIdentifier(WellKnownOids.OcspBasicResponseType);
                    writer.WriteOctetString(basicResponseBytes);
                }
            }
        }

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(writer.GetEncodedLength());
        _ = writer.Encode(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.OcspResponse);
    }


    /// <summary>
    /// Builds an <c>OCSPResponse</c> whose <c>certs [0]</c> block embeds one certificate carrying trailing
    /// content inside its own outer <c>Certificate</c> SEQUENCE, past the legitimate <c>tbsCertificate</c>/
    /// <c>signatureAlgorithm</c>/<c>signatureValue</c> fields (RFC 5280 §4.1.1) — a malformation
    /// <see cref="MintOcspResponse"/> cannot produce because BouncyCastle only ever emits conformant
    /// structures. <c>certs</c> is read, and so must reject this, before any signature is checked (RFC 6960
    /// §4.2.1: <c>certs</c> is outside <c>tbsResponseData</c>), so the rest of the envelope is a minimal
    /// structural stand-in — its content is never reached once the malformed certificate throws.
    /// </summary>
    /// <returns>The pooled response carrier; the caller disposes it.</returns>
    internal static PkiCertificateMemory BuildResponseWithMalformedEmbeddedCertificate()
    {
        byte[] certificateBytes = BuildOversizedCertificateBytes();

        var basicWriter = new AsnWriter(AsnEncodingRules.DER);
        using(basicWriter.PushSequence())                                              //BasicOCSPResponse.
        {
            using(basicWriter.PushSequence())                                          //tbsResponseData.
            {
                using(basicWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2)))
                {
                    //responderID byKey [2], a 20-byte stand-in SHA-1 KeyHash — never reached.
                    basicWriter.WriteOctetString(new byte[20]);
                }

                basicWriter.WriteGeneralizedTime(TimeProvider.System.GetUtcNow());     //producedAt.
                using(basicWriter.PushSequence())                                      //responses — empty.
                {
                }
            }

            using(basicWriter.PushSequence())                                          //signatureAlgorithm stand-in.
            {
                basicWriter.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
            }

            basicWriter.WriteBitString([]);                                            //signature stand-in.

            using(basicWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                using(basicWriter.PushSequence())
                {
                    basicWriter.WriteEncodedValue(certificateBytes);
                }
            }
        }

        byte[] basicResponseBytes = basicWriter.Encode();

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())                                                    //OCSPResponse.
        {
            WriteSmallEnumerated(writer, 0);         //responseStatus successful.
            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                using(writer.PushSequence())                                            //ResponseBytes.
                {
                    writer.WriteObjectIdentifier(WellKnownOids.OcspBasicResponseType);
                    writer.WriteOctetString(basicResponseBytes);
                }
            }
        }

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(writer.GetEncodedLength());
        _ = writer.Encode(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.OcspResponse);


        //Builds a structurally minimal Certificate (RFC 5280 §4.1.1) whose outer SEQUENCE carries one extra
        //INTEGER after signatureValue — legal at the DER length-prefix level, illegal at the schema level. A
        //one-off helper kept local to the call it serves.
        static byte[] BuildOversizedCertificateBytes()
        {
            var certificateWriter = new AsnWriter(AsnEncodingRules.DER);
            using(certificateWriter.PushSequence())                                    //Certificate.
            {
                using(certificateWriter.PushSequence())                                //tbsCertificate.
                {
                    using(certificateWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                    {
                        certificateWriter.WriteInteger(2);                             //version v3.
                    }

                    certificateWriter.WriteInteger(1);                                 //serialNumber stand-in.
                    using(certificateWriter.PushSequence())                            //signature AlgorithmIdentifier stand-in.
                    {
                        certificateWriter.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
                    }

                    WriteSingleCommonNameSequence(certificateWriter, "Trailing Data Issuer");
                    using(certificateWriter.PushSequence())                            //validity.
                    {
                        certificateWriter.WriteUtcTime(new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero));
                        certificateWriter.WriteUtcTime(new DateTimeOffset(2034, 1, 1, 0, 0, 0, TimeSpan.Zero));
                    }

                    WriteSingleCommonNameSequence(certificateWriter, "Trailing Data Subject");
                    using(certificateWriter.PushSequence())                            //subjectPublicKeyInfo stand-in.
                    {
                    }
                }

                using(certificateWriter.PushSequence())                                //signatureAlgorithm stand-in.
                {
                    certificateWriter.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
                }

                certificateWriter.WriteBitString([]);                                  //signatureValue stand-in.
                certificateWriter.WriteInteger(1);                                     //Not an RFC 5280 §4.1.1 field.
            }

            return certificateWriter.Encode();
        }
    }


    /// <summary>
    /// Mints a self-signed RSA Root CA with the platform's default public exponent (65537), for the RSA
    /// exponent-confusion fixture. Kept separate from <see cref="MintRootCa"/> (elliptic-curve) rather than
    /// widening that method's key type, so every existing caller is untouched.
    /// </summary>
    /// <param name="subjectCn">The CA's common name.</param>
    /// <param name="notBefore">The validity start.</param>
    /// <param name="notAfter">The validity end.</param>
    /// <returns>The minted certificate and its signing key; the caller disposes both.</returns>
    internal static (X509Certificate2 Certificate, RSA Key) MintRsaRootCa(string subjectCn, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        RSA key = RSA.Create(2048);
        try
        {
            var request = new CertificateRequest($"CN={subjectCn}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 2, critical: true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature, critical: true));

            using X509Certificate2 selfSignedWithKey = request.CreateSelfSigned(notBefore.UtcDateTime, notAfter.UtcDateTime);
            X509Certificate2 publicOnly = X509CertificateLoader.LoadCertificate(selfSignedWithKey.RawData);

            return (publicOnly, key);
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Copies <paramref name="certificate"/>'s DER bytes, replacing its <c>subjectPublicKeyInfo</c>'s
    /// <c>RSAPublicKey.publicExponent</c> content — encoded as 65537 (<c>02 03 01 00 01</c>, the value
    /// <see cref="MintRsaRootCa"/>'s key always carries) — with <paramref name="forgedExponent"/>, a
    /// same-length substitute that needs no cascading DER length re-encoding. The certificate's own
    /// self-signature is left over the ORIGINAL bytes and so no longer verifies, which is immaterial: nothing
    /// in <see cref="Verifiable.Cryptography.Pki.OcspResponseVerification.VerifyAsync"/>'s direct-signer path
    /// checks an issuer certificate's own signature.
    /// </summary>
    /// <param name="certificate">The certificate to patch; not disposed by this call.</param>
    /// <param name="forgedExponent">The exponent value to substitute, encoded big-endian with one leading zero octet (mirroring 65537's own encoding) so the substitution is exact-length.</param>
    /// <returns>A new certificate carrying the same key material but the forged declared exponent; the caller disposes it.</returns>
    internal static X509Certificate2 PatchRsaPublicExponent(X509Certificate2 certificate, ushort forgedExponent)
    {
        ReadOnlySpan<byte> exponent65537Encoding = [0x02, 0x03, 0x01, 0x00, 0x01];
        byte[] original = certificate.RawData;

        int matchIndex = -1;
        int matchCount = 0;
        for(int i = 0; i <= original.Length - exponent65537Encoding.Length; i++)
        {
            if(original.AsSpan(i, exponent65537Encoding.Length).SequenceEqual(exponent65537Encoding))
            {
                matchIndex = i;
                matchCount++;
            }
        }

        if(matchCount != 1)
        {
            throw new InvalidOperationException(
                $"Expected exactly one 65537 exponent encoding in the certificate DER to patch unambiguously; found {matchCount}.");
        }

        byte[] patched = (byte[])original.Clone();
        patched[matchIndex + 2] = 0x00;
        patched[matchIndex + 3] = (byte)(forgedExponent >> 8);
        patched[matchIndex + 4] = (byte)forgedExponent;

        return X509CertificateLoader.LoadCertificate(patched);
    }


    /// <summary>
    /// Mints a <c>BasicOCSPResponse</c>-carrying <c>OCSPResponse</c> signed with an RSA key (RSASSA-PKCS1-v1_5
    /// SHA-256), directly by the issuer (no delegated responder), for the RSA exponent-confusion fixture. A
    /// dedicated sibling of <see cref="MintOcspResponse"/> rather than a widened overload, so ECDSA callers are
    /// untouched; carries only what that fixture needs — a <c>Good</c> status, no nonce, no embedded certs.
    /// </summary>
    /// <param name="targetCertificate">The certificate the single response answers for.</param>
    /// <param name="issuerCertificate">The target's issuer — the <c>CertID</c> hash input; also the direct signer.</param>
    /// <param name="signerCertificate">The certificate whose key signs the response.</param>
    /// <param name="signerKey">The signer's RSA private key.</param>
    /// <param name="status">The <c>CertStatus</c> to report.</param>
    /// <param name="thisUpdate">The <c>thisUpdate</c> instant.</param>
    /// <param name="nextUpdate">The optional <c>nextUpdate</c> instant.</param>
    /// <returns>The pooled response carrier; the caller disposes it.</returns>
    internal static PkiCertificateMemory MintOcspResponseRsaSigned(
        X509Certificate2 targetCertificate,
        X509Certificate2 issuerCertificate,
        X509Certificate2 signerCertificate,
        RSA signerKey,
        OcspCertificateStatus status,
        DateTimeOffset thisUpdate,
        DateTimeOffset? nextUpdate)
    {
        BcX509Certificate bcTarget = ToBouncyCastleCertificate(targetCertificate);
        BcX509Certificate bcIssuer = ToBouncyCastleCertificate(issuerCertificate);
        BcX509Certificate bcSigner = ToBouncyCastleCertificate(signerCertificate);
        AsymmetricKeyParameter signerPrivateKey = DotNetUtilities.GetRsaKeyPair(signerKey).Private;

        var certId = new CertificateID(CertIdHashAlgorithmIdentifier(OcspCertIdDigestAlgorithm.Sha256), bcIssuer, bcTarget.SerialNumber);
        var responderId = new RespID(bcSigner.SubjectDN);
        var generator = new BasicOcspRespGenerator(responderId);

        CertificateStatus certStatus = status switch
        {
            OcspCertificateStatus.Good => CertificateStatus.Good,
            _ => throw new ArgumentOutOfRangeException(nameof(status), status, "This RSA fixture supports only the Good status.")
        };

        generator.AddResponse(certId, certStatus, thisUpdate.UtcDateTime, nextUpdate?.UtcDateTime, singleExtensions: null);

        BasicOcspResp basicResponse = generator.Generate("SHA256withRSA", signerPrivateKey, null, thisUpdate.UtcDateTime);

        var responseGenerator = new OCSPRespGenerator();
        OcspResp response = responseGenerator.Generate(OcspRespStatus.Successful, basicResponse);

        return ToResponseCarrier(response.GetEncoded());
    }


    /// <summary>
    /// Takes a well-formed, genuinely signed response and appends one byte to the content of
    /// <c>BasicOCSPResponse.signature</c>'s BIT STRING, past the <c>ECDSA-Sig-Value</c> SEQUENCE it wraps — a
    /// malformation <see cref="MintOcspResponse"/> cannot itself produce (BouncyCastle only ever emits
    /// conformant structures). Every other field, including the genuine <c>r</c>/<c>s</c> the enclosing
    /// SEQUENCE still opens with, round-trips unchanged: this re-encodes the envelope with
    /// <see cref="AsnWriter"/>, copying every sibling field through as an opaque encoded value and only ever
    /// touching the signature BIT STRING's content.
    /// </summary>
    /// <param name="response">The response to extend; disposed by this call.</param>
    /// <returns>A new carrier with the extended signature; the caller disposes it.</returns>
    internal static PkiCertificateMemory AppendByteToBasicResponseSignature(PkiCertificateMemory response)
    {
        using(response)
        {
            var outerReader = new AsnReader(response.AsReadOnlyMemory(), AsnEncodingRules.DER);
            AsnReader ocspResponse = outerReader.ReadSequence();
            ReadOnlyMemory<byte> responseStatusDer = ocspResponse.ReadEncodedValue();
            AsnReader responseBytesWrapper = ocspResponse.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            AsnReader responseBytes = responseBytesWrapper.ReadSequence();
            string responseType = responseBytes.ReadObjectIdentifier();
            ReadOnlyMemory<byte> basicResponseBytes = responseBytes.ReadOctetString();

            AsnReader basic = new AsnReader(basicResponseBytes, AsnEncodingRules.DER).ReadSequence();
            ReadOnlyMemory<byte> tbsResponseDataDer = basic.ReadEncodedValue();
            ReadOnlyMemory<byte> signatureAlgorithmDer = basic.ReadEncodedValue();
            if(!basic.TryReadPrimitiveBitString(out int unusedBitCount, out ReadOnlyMemory<byte> signatureContent))
            {
                throw new InvalidOperationException("Expected a primitive signature BIT STRING to extend.");
            }

            byte[] extendedSignatureContent = [.. signatureContent.Span, 0x00];

            //Deliberately not a `basic.HasData ? basic.ReadEncodedValue() : null` conditional expression:
            //ReadOnlyMemory<byte> has an implicit conversion from byte[], so the compiler resolves that
            //ternary's type as the non-nullable ReadOnlyMemory<byte> (converting the null literal through
            //that operator to an EMPTY memory, not "no value"), and boxing the result into this nullable
            //local then reports HasValue=true with Length 0 rather than genuinely absent.
            ReadOnlyMemory<byte>? certsDer = null;
            if(basic.HasData)
            {
                certsDer = basic.ReadEncodedValue();
            }

            var basicWriter = new AsnWriter(AsnEncodingRules.DER);
            using(basicWriter.PushSequence())
            {
                basicWriter.WriteEncodedValue(tbsResponseDataDer.Span);
                basicWriter.WriteEncodedValue(signatureAlgorithmDer.Span);
                basicWriter.WriteBitString(extendedSignatureContent, unusedBitCount);
                if(certsDer is { } certs)
                {
                    basicWriter.WriteEncodedValue(certs.Span);
                }
            }

            byte[] newBasicResponseBytes = basicWriter.Encode();

            var writer = new AsnWriter(AsnEncodingRules.DER);
            using(writer.PushSequence())
            {
                writer.WriteEncodedValue(responseStatusDer.Span);
                using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    using(writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier(responseType);
                        writer.WriteOctetString(newBasicResponseBytes);
                    }
                }
            }

            IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(writer.GetEncodedLength());
            _ = writer.Encode(owner.Memory.Span);

            return new PkiCertificateMemory(owner, PkiCertificateTags.OcspResponse);
        }
    }


    /// <summary>
    /// Builds an <c>OCSPResponse</c> whose <c>responseExtensions</c> carries an <c>id-pkix-ocsp-nonce</c> entry
    /// whose <c>extnValue</c> holds a well-formed <c>Nonce ::= OCTET STRING</c> encoding followed by one
    /// trailing byte — a malformation reachable purely by hand-assembly, since this fixture's own writer
    /// (<see cref="Verifiable.Cryptography.Pki.OcspRequests"/>/the reader under test) never produces it. The
    /// malformed nonce sits inside <c>tbsResponseData</c>, read before <c>signatureAlgorithm</c>/<c>signature</c>
    /// are even reached, so — mirroring <see cref="BuildStructurallyMalformedBasicResponse"/> — those trailing
    /// fields are unreachable structural stand-ins.
    /// </summary>
    /// <returns>The pooled response carrier; the caller disposes it.</returns>
    internal static PkiCertificateMemory BuildResponseWithMalformedNonceExtension()
    {
        var basicWriter = new AsnWriter(AsnEncodingRules.DER);
        using(basicWriter.PushSequence())                                              //BasicOCSPResponse.
        {
            using(basicWriter.PushSequence())                                          //tbsResponseData.
            {
                using(basicWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2)))
                {
                    //responderID byKey [2], a 20-byte stand-in SHA-1 KeyHash — never reached.
                    basicWriter.WriteOctetString(new byte[20]);
                }

                basicWriter.WriteGeneralizedTime(TimeProvider.System.GetUtcNow());     //producedAt.
                using(basicWriter.PushSequence())                                      //responses — empty.
                {
                }

                using(basicWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1))) //responseExtensions [1] EXPLICIT.
                {
                    using(basicWriter.PushSequence())                                  //Extensions.
                    {
                        using(basicWriter.PushSequence())                              //Extension.
                        {
                            basicWriter.WriteObjectIdentifier(WellKnownOids.OcspNonce);

                            var nonceValueWriter = new AsnWriter(AsnEncodingRules.DER);
                            nonceValueWriter.WriteOctetString([0x01, 0x02, 0x03, 0x04]);
                            byte[] extnValue = [.. nonceValueWriter.Encode(), 0x00];    //Trailing byte past the Nonce OCTET STRING.
                            basicWriter.WriteOctetString(extnValue);
                        }
                    }
                }
            }

            using(basicWriter.PushSequence())                                          //signatureAlgorithm stand-in — never reached.
            {
                basicWriter.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
            }

            basicWriter.WriteBitString([]);                                            //signature stand-in — never reached.
        }

        byte[] basicResponseBytes = basicWriter.Encode();

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())                                                    //OCSPResponse.
        {
            WriteSmallEnumerated(writer, 0);         //responseStatus successful.
            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                using(writer.PushSequence())                                            //ResponseBytes.
                {
                    writer.WriteObjectIdentifier(WellKnownOids.OcspBasicResponseType);
                    writer.WriteOctetString(basicResponseBytes);
                }
            }
        }

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(writer.GetEncodedLength());
        _ = writer.Encode(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.OcspResponse);
    }
}


/// <summary>
/// A certificate minted by <see cref="OcspTestFixtures.MintRootCa"/>/<see cref="OcspTestFixtures.MintCertificate"/>
/// paired with its signing key, disposed together.
/// </summary>
/// <param name="Certificate">The minted certificate (public-only).</param>
/// <param name="Key">The certificate's signing key.</param>
internal sealed record MintedCertificate(X509Certificate2 Certificate, ECDsa Key): IDisposable
{
    /// <inheritdoc/>
    public void Dispose()
    {
        Certificate.Dispose();
        Key.Dispose();
    }
}
