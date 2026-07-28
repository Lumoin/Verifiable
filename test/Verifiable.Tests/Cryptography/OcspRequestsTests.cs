using System;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="OcspRequests"/>: the unsigned, single-certificate <c>OCSPRequest</c>
/// writer (<see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.1.1">RFC 6960 §4.1.1</see>) and its
/// optional <c>id-pkix-ocsp-nonce</c> extension (<see href="https://www.rfc-editor.org/rfc/rfc9654#section-2.1">
/// RFC 9654 §2.1</see>). Every request is parsed back by the independent BouncyCastle <c>OcspReq</c> reader
/// (<c>Org.BouncyCastle.Ocsp</c>), never by re-reading with this library's own parser, so the assertions are
/// cross-implementation checks of the bytes this writer actually produced.
/// </summary>
[TestClass]
internal sealed class OcspRequestsTests
{
    /// <summary>The default minted validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = new(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The default minted validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = new(2034, 1, 1, 0, 0, 0, TimeSpan.Zero);


    /// <summary>
    /// A SHA-256 <c>CertID</c> request: the independent oracle confirms the issuer/serial match and that
    /// the <c>hashAlgorithm</c> parameters are absent, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc5754#section-2">RFC 5754 §2</see>.
    /// </summary>
    [TestMethod]
    public void BuildsASha256CertIdRequestTheOracleMatchesAndDecodesExactly()
    {
        using MintedCertificate root = OcspTestFixtures.MintRootCa("OCSP Requests Sha256 Root", NotBefore, NotAfter);
        using MintedCertificate leaf = OcspTestFixtures.MintCertificate(root.Certificate, root.Key, "OCSP Requests Sha256 Leaf", NotBefore, NotAfter, []);
        using PkiCertificateMemory certificate = OcspTestFixtures.ToCertificateCarrier(leaf.Certificate);
        using PkiCertificateMemory issuer = OcspTestFixtures.ToCertificateCarrier(root.Certificate);

        using OcspRequestContent request = OcspRequests.Create(certificate, issuer, OcspCertIdDigestAlgorithm.Sha256, BaseMemoryPool.Shared);

        Assert.IsTrue(request.Request.IsOcspRequest, "The built request must carry the OcspRequest tag.");

        var oracleRequest = new OcspReq(request.Request.AsReadOnlySpan().ToArray());
        Req[] oracleRequestList = oracleRequest.GetRequestList();
        Assert.HasCount(1, oracleRequestList, "RFC 6960 §4.1.1: exactly one Request for a single-certificate request.");

        CertificateID certId = oracleRequestList[0].GetCertID();
        Assert.IsTrue(certId.MatchesIssuer(OcspTestFixtures.ToBouncyCastleCertificate(root.Certificate)), "The CertID must match the issuer via the oracle's own matching API.");
        Assert.AreEqual(OcspTestFixtures.ToBouncyCastleCertificate(leaf.Certificate).SerialNumber, certId.SerialNumber, "The CertID serial number must be the target certificate's own.");
        Assert.AreEqual(WellKnownOids.Sha256, certId.HashAlgOid, "The CertID hash algorithm OID must be SHA-256.");

        CertID rawCertId = certId.ToAsn1Object();
        Assert.IsNull(rawCertId.HashAlgorithm.Parameters, "RFC 5754 §2: SHA-256's AlgorithmIdentifier parameters must be absent.");
        Assert.AreEqual(1, oracleRequest.Version, "RFC 6960 §4.1.1: version DEFAULT v1 must be omitted; the oracle reports the default (its 1-based v1) when no explicit version field was written.");
    }


    /// <summary>A SHA-1 <c>CertID</c> request carries explicit NULL <c>hashAlgorithm</c> parameters, per RFC 3279.</summary>
    [TestMethod]
    public void BuildsASha1CertIdRequestWithExplicitNullParameters()
    {
        using MintedCertificate root = OcspTestFixtures.MintRootCa("OCSP Requests Sha1 Root", NotBefore, NotAfter);
        using MintedCertificate leaf = OcspTestFixtures.MintCertificate(root.Certificate, root.Key, "OCSP Requests Sha1 Leaf", NotBefore, NotAfter, []);
        using PkiCertificateMemory certificate = OcspTestFixtures.ToCertificateCarrier(leaf.Certificate);
        using PkiCertificateMemory issuer = OcspTestFixtures.ToCertificateCarrier(root.Certificate);

        using OcspRequestContent request = OcspRequests.Create(certificate, issuer, OcspCertIdDigestAlgorithm.Sha1, BaseMemoryPool.Shared);

        var oracleRequest = new OcspReq(request.Request.AsReadOnlySpan().ToArray());
        CertificateID certId = oracleRequest.GetRequestList()[0].GetCertID();

        Assert.AreEqual(WellKnownOids.Sha1, certId.HashAlgOid, "The CertID hash algorithm OID must be SHA-1.");
        Assert.IsInstanceOfType<Org.BouncyCastle.Asn1.DerNull>(certId.ToAsn1Object().HashAlgorithm.Parameters, "RFC 3279: SHA-1's AlgorithmIdentifier parameters must be an explicit NULL.");
    }


    /// <summary>A requested nonce round-trips through the independent oracle's own extension reader.</summary>
    [TestMethod]
    public void RequestsWithANonceRoundTripThroughTheOracle()
    {
        using MintedCertificate root = OcspTestFixtures.MintRootCa("OCSP Requests Nonce Root", NotBefore, NotAfter);
        using MintedCertificate leaf = OcspTestFixtures.MintCertificate(root.Certificate, root.Key, "OCSP Requests Nonce Leaf", NotBefore, NotAfter, []);
        using PkiCertificateMemory certificate = OcspTestFixtures.ToCertificateCarrier(leaf.Certificate);
        using PkiCertificateMemory issuer = OcspTestFixtures.ToCertificateCarrier(root.Certificate);

        using OcspRequestContent request = OcspRequests.Create(certificate, issuer, OcspCertIdDigestAlgorithm.Sha256, BaseMemoryPool.Shared, nonceByteLength: 24, includeNonce: true);

        Assert.IsNotNull(request.RequestNonce, "A nonce must be present when requested.");
        Assert.AreEqual(24, request.RequestNonce.Length, "The nonce must be exactly the requested length.");

        var oracleRequest = new OcspReq(request.Request.AsReadOnlySpan().ToArray());
        X509Extensions extensions = oracleRequest.RequestExtensions;
        Assert.IsNotNull(extensions, "The requestExtensions block must be present when a nonce is requested.");

        var nonceOid = new Org.BouncyCastle.Asn1.DerObjectIdentifier(WellKnownOids.OcspNonce);
        byte[] extensionValueOctets = extensions.GetExtensionValue(nonceOid).GetOctets();
        byte[] oracleNonceBytes = Org.BouncyCastle.Asn1.Asn1OctetString.GetInstance(extensionValueOctets).GetOctets();

        Assert.AreSequenceEqual(request.RequestNonce.AsReadOnlySpan().ToArray(), oracleNonceBytes, "The oracle-decoded nonce must match the bytes the library embedded.");
    }


    /// <summary>The RFC 9654 §2.1 <c>SIZE(1..128)</c> nonce-length bound is enforced regardless of whether a nonce is actually requested.</summary>
    [TestMethod]
    public void EnforcesTheNonceLengthBoundUnconditionally()
    {
        using MintedCertificate root = OcspTestFixtures.MintRootCa("OCSP Requests Bounds Root", NotBefore, NotAfter);
        using MintedCertificate leaf = OcspTestFixtures.MintCertificate(root.Certificate, root.Key, "OCSP Requests Bounds Leaf", NotBefore, NotAfter, []);
        using PkiCertificateMemory certificate = OcspTestFixtures.ToCertificateCarrier(leaf.Certificate);
        using PkiCertificateMemory issuer = OcspTestFixtures.ToCertificateCarrier(root.Certificate);

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => OcspRequests.Create(certificate, issuer, OcspCertIdDigestAlgorithm.Sha256, BaseMemoryPool.Shared, nonceByteLength: 0),
            "A zero-length nonce is below the RFC 9654 §2.1 SIZE(1..128) lower bound.");
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => OcspRequests.Create(certificate, issuer, OcspCertIdDigestAlgorithm.Sha256, BaseMemoryPool.Shared, nonceByteLength: 129),
            "A 129-byte nonce is above the RFC 9654 §2.1 SIZE(1..128) upper bound.");
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => OcspRequests.Create(certificate, issuer, OcspCertIdDigestAlgorithm.Sha256, BaseMemoryPool.Shared, nonceByteLength: 0, includeNonce: false),
            "The nonce length is validated unconditionally, even when includeNonce is false.");
    }


    /// <summary>With <c>includeNonce: false</c> the request carries no <c>requestExtensions</c> block at all.</summary>
    [TestMethod]
    public void OmittingTheNonceOmitsRequestExtensionsEntirely()
    {
        using MintedCertificate root = OcspTestFixtures.MintRootCa("OCSP Requests No Nonce Root", NotBefore, NotAfter);
        using MintedCertificate leaf = OcspTestFixtures.MintCertificate(root.Certificate, root.Key, "OCSP Requests No Nonce Leaf", NotBefore, NotAfter, []);
        using PkiCertificateMemory certificate = OcspTestFixtures.ToCertificateCarrier(leaf.Certificate);
        using PkiCertificateMemory issuer = OcspTestFixtures.ToCertificateCarrier(root.Certificate);

        using OcspRequestContent request = OcspRequests.Create(certificate, issuer, OcspCertIdDigestAlgorithm.Sha256, BaseMemoryPool.Shared, includeNonce: false);

        Assert.IsNull(request.RequestNonce, "No nonce carrier is produced when includeNonce is false.");

        var oracleRequest = new OcspReq(request.Request.AsReadOnlySpan().ToArray());
        Assert.IsNull(oracleRequest.RequestExtensions, "The requestExtensions [2] block must be entirely absent, not merely empty.");
    }
}
