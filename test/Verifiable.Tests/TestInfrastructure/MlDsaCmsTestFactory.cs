using System;
using System.Buffers;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.X509;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;
using BcCmsSignedData = Org.BouncyCastle.Cms.CmsSignedData;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;
using CmsSignedData = Verifiable.Cryptography.Pki.CmsSignedData;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Mints ML-DSA (NIST FIPS 204) authorities and CMS SignedData structures for the managed verifiers' tests,
/// through the independent BouncyCastle X.509 and CMS generators — a certificate writer and a CMS writer that
/// share no code with the library's own ASN.1 readers under test. The keys come from
/// <see cref="BouncyCastleKeyMaterialCreator"/>, the library's registered ML-DSA key-creation backend, so a
/// minted authority carries the same provenance as production material.
/// </summary>
/// <remarks>
/// The independence this factory provides is at the FORMAT layer: the certificate and CMS encodings the managed
/// readers parse were written by a generator sharing none of their code. The FIPS 204 primitive itself is NOT
/// independently checked by structures minted here — the registered verification delegate the readers resolve
/// is BouncyCastle-backed, the same implementation these generators sign with, so a self-consistent defect in
/// that implementation's sign/verify pairing would go unseen. Cross-checking the primitive against the
/// platform's own ML-DSA where the platform provides one, and against authentic FIPS 204 known-answer vectors,
/// is the recorded follow-up that closes this.
/// </remarks>
internal static class MlDsaCmsTestFactory
{
    /// <summary>
    /// An ML-DSA authority: the pooled key carriers, the parameter-set identifier, and the BouncyCastle-native
    /// certificate and signing key the independent generators consume.
    /// </summary>
    internal sealed class MlDsaSigningAuthority: IDisposable
    {
        /// <summary>The authority's public key carrier (raw FIPS 204 encoding).</summary>
        public PublicKeyMemory PublicKey { get; }

        /// <summary>The authority's private key carrier (raw FIPS 204 encoding).</summary>
        public PrivateKeyMemory PrivateKey { get; }

        /// <summary>The authority's self-signed certificate as a pooled DER carrier.</summary>
        public PkiCertificateMemory Certificate { get; }

        /// <summary>The ML-DSA parameter-set object identifier the authority's key pins.</summary>
        public string ParameterSetOid { get; }

        /// <summary>The BouncyCastle signature-algorithm name the independent generators sign under.</summary>
        public string AlgorithmName { get; }

        /// <summary>The BouncyCastle-native certificate, for the independent CMS and OCSP generators.</summary>
        public BcX509Certificate BouncyCastleCertificate { get; }

        /// <summary>The BouncyCastle-native private key parameter, for the independent generators' signature factories.</summary>
        public AsymmetricKeyParameter SigningKey { get; }


        /// <summary>
        /// Initializes the authority. Ownership of the carriers transfers to this instance, which the caller
        /// disposes.
        /// </summary>
        /// <param name="publicKey">The public key carrier.</param>
        /// <param name="privateKey">The private key carrier.</param>
        /// <param name="certificate">The certificate carrier.</param>
        /// <param name="parameterSetOid">The parameter-set object identifier.</param>
        /// <param name="algorithmName">The BouncyCastle signature-algorithm name.</param>
        /// <param name="bouncyCastleCertificate">The BouncyCastle-native certificate.</param>
        /// <param name="signingKey">The BouncyCastle-native private key parameter.</param>
        public MlDsaSigningAuthority(
            PublicKeyMemory publicKey,
            PrivateKeyMemory privateKey,
            PkiCertificateMemory certificate,
            string parameterSetOid,
            string algorithmName,
            BcX509Certificate bouncyCastleCertificate,
            AsymmetricKeyParameter signingKey)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
            Certificate = certificate;
            ParameterSetOid = parameterSetOid;
            AlgorithmName = algorithmName;
            BouncyCastleCertificate = bouncyCastleCertificate;
            SigningKey = signingKey;
        }


        /// <inheritdoc/>
        public void Dispose()
        {
            PublicKey.Dispose();
            PrivateKey.Dispose();
            Certificate.Dispose();
        }
    }


    /// <summary>
    /// Mints a self-signed ML-DSA authority: keys through the registered BouncyCastle key-creation backend,
    /// the certificate through the independent BouncyCastle X.509 generator, signed under the key's own
    /// parameter set so the <c>SubjectPublicKeyInfo</c> identifier, the certificate signature algorithm, and
    /// the key agree.
    /// </summary>
    /// <param name="parameterSetOid">The ML-DSA parameter set (<see cref="WellKnownOids.MlDsa44"/>, <see cref="WellKnownOids.MlDsa65"/> or <see cref="WellKnownOids.MlDsa87"/>).</param>
    /// <param name="notBefore">The certificate validity start.</param>
    /// <param name="notAfter">The certificate validity end.</param>
    /// <returns>The authority; the caller disposes it.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="parameterSetOid"/> names no ML-DSA parameter set.</exception>
    internal static MlDsaSigningAuthority MintSelfSignedAuthority(string parameterSetOid, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        (PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> material, MLDsaParameters parameters, string algorithmName) = parameterSetOid switch
        {
            WellKnownOids.MlDsa44 => (BouncyCastleKeyMaterialCreator.CreateMlDsa44Keys(BaseMemoryPool.Shared), MLDsaParameters.ml_dsa_44, "ML-DSA-44"),
            WellKnownOids.MlDsa65 => (BouncyCastleKeyMaterialCreator.CreateMlDsa65Keys(BaseMemoryPool.Shared), MLDsaParameters.ml_dsa_65, "ML-DSA-65"),
            WellKnownOids.MlDsa87 => (BouncyCastleKeyMaterialCreator.CreateMlDsa87Keys(BaseMemoryPool.Shared), MLDsaParameters.ml_dsa_87, "ML-DSA-87"),
            _ => throw new ArgumentOutOfRangeException(nameof(parameterSetOid), parameterSetOid, "The identifier names no ML-DSA parameter set.")
        };

        try
        {
            var publicParameters = MLDsaPublicKeyParameters.FromEncoding(parameters, material.PublicKey.AsReadOnlySpan().ToArray());
            var privateParameters = MLDsaPrivateKeyParameters.FromEncoding(parameters, material.PrivateKey.AsReadOnlySpan().ToArray());

            var generator = new X509V3CertificateGenerator();
            using(Salt serialNumber = X509ChainTestRing.CreateSerialNumber())
            {
                generator.SetSerialNumber(new BcBigInteger(1, serialNumber.AsReadOnlySpan().ToArray()));
            }

            var name = new X509Name($"CN=Verifiable ML-DSA Test Authority, O=Verifiable Test Infrastructure");
            generator.SetIssuerDN(name);
            generator.SetSubjectDN(name);
            generator.SetNotBefore(notBefore.UtcDateTime);
            generator.SetNotAfter(notAfter.UtcDateTime);
            generator.SetPublicKey(publicParameters);

            BcX509Certificate certificate = generator.Generate(new Asn1SignatureFactory(algorithmName, privateParameters));
            PkiCertificateMemory certificateCarrier = ToCertificateCarrier(certificate.GetEncoded());

            return new MlDsaSigningAuthority(
                material.PublicKey, material.PrivateKey, certificateCarrier, parameterSetOid, algorithmName, certificate, privateParameters);
        }
        catch
        {
            material.PublicKey.Dispose();
            material.PrivateKey.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Signs the payload as an encapsulating CMS SignedData under the authority's ML-DSA key through the
    /// independent BouncyCastle CMS generator: the signed attributes (content-type and message-digest) are the
    /// generator's defaults, the <c>SignerInfo</c> signature algorithm states the key's own parameter-set
    /// identifier, and the authority's certificate is embedded.
    /// </summary>
    /// <param name="payload">The content the signature encapsulates and covers.</param>
    /// <param name="authority">The signing authority.</param>
    /// <returns>The pooled wire carrier. The caller disposes it.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="authority"/> is <see langword="null"/>.</exception>
    internal static CmsSignedData SignAsCms(ReadOnlySpan<byte> payload, MlDsaSigningAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);

        var generator = new CmsSignedDataGenerator();
        generator.AddSignerInfoGenerator(new SignerInfoGeneratorBuilder()
            .Build(new Asn1SignatureFactory(authority.AlgorithmName, authority.SigningKey), authority.BouncyCastleCertificate));
        generator.AddCertificates(CollectionUtilities.CreateStore(new List<BcX509Certificate> { authority.BouncyCastleCertificate }));

        //The generator's default encoding is BER (indefinite lengths); the managed verifier reads strict DER,
        //which CMS structures on the wire carry, so the definite-length form is requested explicitly.
        BcCmsSignedData signed = generator.Generate(new CmsProcessableByteArray(payload.ToArray()), encapsulate: true);

        return CmsSignedData.FromBytes(signed.GetEncoded("DER"), BaseMemoryPool.Shared);
    }


    /// <summary>Copies DER certificate bytes into a pooled carrier tagged as an X.509 certificate.</summary>
    /// <param name="der">The DER-encoded certificate.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory ToCertificateCarrier(byte[] der)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(der.Length);
        der.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }
}
