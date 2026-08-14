using System;
using System.Buffers;
using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="RevocationSourceFactsExtractor"/>: the Authority Information Access
/// (<see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.2.1">RFC 5280 §4.2.2.1</see>) and CRL
/// Distribution Points (<see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13">RFC 5280
/// §4.2.1.13</see>) extraction the OCSP and CRL revocation sources both read. Certificates are minted with
/// <see cref="CertificateRequest"/> carrying extension bytes assembled with <see cref="AsnWriter"/>
/// (<see cref="OcspTestFixtures"/>), so the expected URIs and skip decisions are fixed by construction; the
/// malformed vectors inject raw <c>extnValue</c> bytes the platform factory itself would never produce.
/// </summary>
[TestClass]
internal sealed class RevocationSourceFactsExtractorTests
{
    /// <summary>The default minted validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = new(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The default minted validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = new(2034, 1, 1, 0, 0, 0, TimeSpan.Zero);


    /// <summary>
    /// A certificate carrying both extensions extracts every URI-form entry in certificate order, skips the
    /// non-URI GeneralName and CRLDP shapes without failing, and ignores an AIA access method that is neither
    /// <c>id-ad-ocsp</c> nor <c>id-ad-caIssuers</c>.
    /// </summary>
    [TestMethod]
    public void ExtractsEveryUriAndSkipsNonUriFormsFromAMintedCertificate()
    {
        using MintedCertificate root = OcspTestFixtures.MintRootCa("Revocation Facts Root", NotBefore, NotAfter);

        X509Extension aia = OcspTestFixtures.CreateAuthorityInfoAccessExtension(
            OcspTestFixtures.UriAiaEntry(WellKnownOids.AccessMethodOcsp, "http://ocsp.example.test/one"),
            OcspTestFixtures.UriAiaEntry(WellKnownOids.AccessMethodOcsp, "http://ocsp.example.test/two"),
            OcspTestFixtures.UriAiaEntry(WellKnownOids.AccessMethodCaIssuers, "http://ca-issuers.example.test/issuer.cer"),
            OcspTestFixtures.NonUriAiaEntry(WellKnownOids.AccessMethodOcsp, "skip-me@example.test"),
            OcspTestFixtures.UriAiaEntry("1.2.3.4.5", "http://unrecognised-method.example.test/ignored"));
        X509Extension crldp = OcspTestFixtures.CreateCrlDistributionPointsExtension(
            (OcspTestFixtures.DistributionPointKind.FullNameUri, "http://crl.example.test/a.crl"),
            (OcspTestFixtures.DistributionPointKind.NameRelativeToCrlIssuer, null),
            (OcspTestFixtures.DistributionPointKind.ReasonsOnly, null),
            (OcspTestFixtures.DistributionPointKind.FullNameUri, "http://crl.example.test/b.crl"));

        using MintedCertificate leaf = OcspTestFixtures.MintCertificate(
            root.Certificate, root.Key, "Revocation Facts Leaf", NotBefore, NotAfter, [aia, crldp]);
        using PkiCertificateMemory certificate = OcspTestFixtures.ToCertificateCarrier(leaf.Certificate);

        RevocationSourceFacts facts = RevocationSourceFactsExtractor.Extract(certificate);

        Assert.IsTrue(facts.HasAuthorityInfoAccessExtension, "The AIA extension must be seen.");
        Assert.AreSequenceEqual(
            ["http://ocsp.example.test/one", "http://ocsp.example.test/two"],
            facts.OcspResponderUris,
            "Only the URI-form id-ad-ocsp entries are extracted, in certificate order; the rfc822Name entry is skipped.");
        Assert.AreSequenceEqual(
            ["http://ca-issuers.example.test/issuer.cer"],
            facts.CaIssuerUris,
            "Only the URI-form id-ad-caIssuers entry is extracted.");
        Assert.DoesNotContain("http://unrecognised-method.example.test/ignored", facts.OcspResponderUris, "An unrecognised access method must not contribute to the OCSP list.");
        Assert.DoesNotContain("http://unrecognised-method.example.test/ignored", facts.CaIssuerUris, "An unrecognised access method must not contribute to the CA-issuers list.");

        Assert.IsTrue(facts.HasCrlDistributionPointsExtension, "The CRLDP extension must be seen.");
        Assert.AreSequenceEqual(
            ["http://crl.example.test/a.crl", "http://crl.example.test/b.crl"],
            facts.CrlDistributionPointUris,
            "Only the fullName URI entries are extracted, in certificate order; the nameRelativeToCRLIssuer and reasons-only points contribute nothing.");
    }


    /// <summary>A certificate with neither extension reports both presence flags <see langword="false"/> and both URI lists empty.</summary>
    [TestMethod]
    public void ReportsAbsenceWhenNeitherExtensionIsPresent()
    {
        using MintedCertificate root = OcspTestFixtures.MintRootCa("Revocation Facts Absent Root", NotBefore, NotAfter);
        using MintedCertificate leaf = OcspTestFixtures.MintCertificate(root.Certificate, root.Key, "Revocation Facts Absent Leaf", NotBefore, NotAfter, []);
        using PkiCertificateMemory certificate = OcspTestFixtures.ToCertificateCarrier(leaf.Certificate);

        RevocationSourceFacts facts = RevocationSourceFactsExtractor.Extract(certificate);

        Assert.IsFalse(facts.HasAuthorityInfoAccessExtension, "No AIA extension is present.");
        Assert.IsEmpty(facts.OcspResponderUris, "An absent AIA extension contributes no OCSP URIs.");
        Assert.IsEmpty(facts.CaIssuerUris, "An absent AIA extension contributes no CA-issuer URIs.");
        Assert.IsFalse(facts.HasCrlDistributionPointsExtension, "No CRLDP extension is present.");
        Assert.IsEmpty(facts.CrlDistributionPointUris, "An absent CRLDP extension contributes no URIs.");
    }


    /// <summary>
    /// Of a duplicated AIA extension — an RFC 5280 §4.2 profile violation <see cref="CertificateRequest"/>
    /// itself refuses to mint, so the certificate is assembled directly — the first occurrence is read; the
    /// second is ignored.
    /// </summary>
    [TestMethod]
    public void ReadsTheFirstOccurrenceWhenTheAiaExtensionIsDuplicated()
    {
        X509Extension firstAia = OcspTestFixtures.CreateAuthorityInfoAccessExtension(OcspTestFixtures.UriAiaEntry(WellKnownOids.AccessMethodOcsp, "http://first.example.test/ocsp"));
        X509Extension secondAia = OcspTestFixtures.CreateAuthorityInfoAccessExtension(OcspTestFixtures.UriAiaEntry(WellKnownOids.AccessMethodOcsp, "http://second.example.test/ocsp"));

        using PkiCertificateMemory certificate = OcspTestFixtures.BuildSyntheticCertificateWithRawExtensions(
            (WellKnownOids.AuthorityInfoAccessExtension, firstAia.RawData),
            (WellKnownOids.AuthorityInfoAccessExtension, secondAia.RawData));

        RevocationSourceFacts facts = RevocationSourceFactsExtractor.Extract(certificate);

        Assert.AreSequenceEqual(["http://first.example.test/ocsp"], facts.OcspResponderUris, "The first AIA occurrence must win; the duplicate is ignored.");
    }


    /// <summary>Trailing bytes after the well-formed <c>AuthorityInfoAccessSyntax</c> content, inside the extension's <c>extnValue</c>, must throw.</summary>
    [TestMethod]
    public void ThrowsOnTrailingDataInsideTheAiaExtensionValue()
    {
        using MintedCertificate root = OcspTestFixtures.MintRootCa("Revocation Facts Trailing Root", NotBefore, NotAfter);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            using(writer.PushSequence())
            {
                writer.WriteObjectIdentifier(WellKnownOids.AccessMethodOcsp);
                writer.WriteCharacterString(UniversalTagNumber.IA5String, "http://trailing.example.test/ocsp", new Asn1Tag(TagClass.ContextSpecific, 6));
            }
        }

        byte[] wellFormedAia = writer.Encode();
        byte[] withTrailingJunk = [.. wellFormedAia, 0x05, 0x00];  //A trailing NULL TLV after the AuthorityInfoAccessSyntax SEQUENCE closes.
        var extension = new X509Extension(WellKnownOids.AuthorityInfoAccessExtension, withTrailingJunk, critical: false);

        using MintedCertificate leaf = OcspTestFixtures.MintCertificate(
            root.Certificate, root.Key, "Revocation Facts Trailing Leaf", NotBefore, NotAfter, [extension]);
        using PkiCertificateMemory certificate = OcspTestFixtures.ToCertificateCarrier(leaf.Certificate);

        Assert.ThrowsExactly<AsnContentException>(() => RevocationSourceFactsExtractor.Extract(certificate), "Trailing content after the AIA sequence, inside extnValue, must throw.");
    }


    /// <summary>An <c>extnValue</c> that is not even a <c>SEQUENCE</c> where <c>AuthorityInfoAccessSyntax</c> belongs must throw, not be read as absent.</summary>
    [TestMethod]
    public void ThrowsOnAMisTaggedAiaExtensionValue()
    {
        using MintedCertificate root = OcspTestFixtures.MintRootCa("Revocation Facts MisTagged Root", NotBefore, NotAfter);

        //An INTEGER where the AuthorityInfoAccessSyntax SEQUENCE belongs.
        var extension = new X509Extension(WellKnownOids.AuthorityInfoAccessExtension, [0x02, 0x01, 0x05], critical: false);

        using MintedCertificate leaf = OcspTestFixtures.MintCertificate(
            root.Certificate, root.Key, "Revocation Facts MisTagged Leaf", NotBefore, NotAfter, [extension]);
        using PkiCertificateMemory certificate = OcspTestFixtures.ToCertificateCarrier(leaf.Certificate);

        Assert.ThrowsExactly<AsnContentException>(() => RevocationSourceFactsExtractor.Extract(certificate), "A mis-tagged AIA extension value must throw.");
    }


    /// <summary>A carrier holding something other than an X.509 certificate is a composition error, rejected before any parsing.</summary>
    [TestMethod]
    public void RejectsANonCertificateCarrier()
    {
        using MintedCertificate root = OcspTestFixtures.MintRootCa("Revocation Facts Mistagged Carrier Root", NotBefore, NotAfter);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(root.Certificate.RawDataMemory.Length);
        root.Certificate.RawDataMemory.Span.CopyTo(owner.Memory.Span);
        using var mistagged = new PkiCertificateMemory(owner, PkiCertificateTags.X509Crl);

        Assert.ThrowsExactly<ArgumentException>(() => RevocationSourceFactsExtractor.Extract(mistagged), "A CRL-tagged carrier must be rejected before any parsing.");
    }


    /// <summary>Garbage bytes, and a well-formed certificate followed by trailing data, both throw <see cref="AsnContentException"/>.</summary>
    [TestMethod]
    public void ThrowsOnMalformedDer()
    {
        IMemoryOwner<byte> garbageOwner = BaseMemoryPool.Shared.Rent(3);
        ReadOnlySpan<byte> garbageBytes = [0x01, 0x02, 0x03];
        garbageBytes.CopyTo(garbageOwner.Memory.Span);
        using var garbage = new PkiCertificateMemory(garbageOwner, PkiCertificateTags.X509Certificate);
        Assert.ThrowsExactly<AsnContentException>(() => RevocationSourceFactsExtractor.Extract(garbage), "Garbage bytes must throw.");

        using MintedCertificate root = OcspTestFixtures.MintRootCa("Revocation Facts Trailing DER Root", NotBefore, NotAfter);
        IMemoryOwner<byte> trailingOwner = BaseMemoryPool.Shared.Rent(root.Certificate.RawDataMemory.Length + 1);
        root.Certificate.RawDataMemory.Span.CopyTo(trailingOwner.Memory.Span);
        trailingOwner.Memory.Span[root.Certificate.RawDataMemory.Length] = 0x00;
        using var trailing = new PkiCertificateMemory(trailingOwner, PkiCertificateTags.X509Certificate);
        Assert.ThrowsExactly<AsnContentException>(() => RevocationSourceFactsExtractor.Extract(trailing), "Trailing data after the Certificate sequence must throw.");
    }
}
