using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;
using PkiAlgorithmIdentifier = Verifiable.Cryptography.Pki.AlgorithmIdentifier;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="AsicContainerReading"/> and <see cref="AsicContainerValidation"/>: the
/// obligations clause 4.4.4.2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> places on a validation application, and the Annex A.7 chain walk.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Every container these tests validate was built by the shipped creation surface</strong>
/// (<see cref="AsicContainerCreation"/>, <see cref="AsicContainerAugmentation"/>), and every conclusion is
/// checked against material an independent reader recomputes: the raw-octet
/// <see cref="AsicZipStructureOracle"/> for the archive, an independent <see cref="XDocument"/> walk for the
/// Annex A.7 chain, and <see cref="EvidenceRecordOracle"/> for the Evidence Record digests.
/// </para>
/// <para>
/// The CAdES objects are validated through the shipped EN 319 102-1 clause 5 engine against a
/// <see cref="X509ChainTestRing"/> root, with the platform path validation seam and a certificate revocation
/// list minted by the independent revocation oracle — not a stand-in.
/// </para>
/// </remarks>
[TestClass]
internal sealed class AsicContainerValidationTests
{
    /// <summary>The address handed to the transport delegate; no socket is opened for it.</summary>
    private const string TsaUri = "http://tsa.asic-validation.example.test/";

    /// <summary>The DNS name the signer's leaf certificate carries.</summary>
    private const string SignerDnsName = "asic-validation-signer.example.test";

    /// <summary>The DNS name the RSA signer's leaf certificate carries.</summary>
    private const string RsaSignerDnsName = "asic-validation-rsa-signer.example.test";

    /// <summary>The registration qualifier the independent BouncyCastle CMS backends are registered under.</summary>
    private const string BouncyCastleQualifier = "BouncyCastle";


    /// <summary>
    /// The <c>id-RSASSA-PSS</c> signature algorithm object identifier
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8017#appendix-A.2.3">RFC 8017 Appendix A.2.3</see>), the
    /// signature algorithm the container of the detached-backend test is signed with.
    /// </summary>
    private static string RsaSsaPssSignatureOid { get; } = "1.2.840.113549.1.1.10";


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    /// <summary>The signing time every signed container states.</summary>
    private static DateTimeOffset SigningTime { get; } = TestClock.CanonicalEpoch;

    /// <summary>The instant every container entry records.</summary>
    private static DateTimeOffset ContainerInstant { get; } = TestClock.CanonicalEpoch;

    /// <summary>The <c>genTime</c> every minted token states.</summary>
    private static DateTimeOffset TimeAssertionInstant { get; } = TestClock.CanonicalEpoch.AddHours(1);

    /// <summary>The instant every container is validated at.</summary>
    private static DateTimeOffset ValidationTime { get; } = TestClock.CanonicalEpoch.AddDays(1);

    /// <summary>The certificate revocation list's <c>thisUpdate</c>.</summary>
    private static DateTimeOffset ThisUpdate { get; } = TestClock.CanonicalEpoch.AddMinutes(-5);

    /// <summary>The certificate revocation list's <c>nextUpdate</c>.</summary>
    private static DateTimeOffset NextUpdate { get; } = TestClock.CanonicalEpoch.AddDays(7);

    /// <summary>The first data object every ASiC-E container carries.</summary>
    private static byte[] FirstDataObject { get; } = [.. "the first archived data object"u8];

    /// <summary>The second data object every ASiC-E container carries.</summary>
    private static byte[] SecondDataObject { get; } = [.. "the second archived data object"u8];

    /// <summary>The entry names the two data objects of every ASiC-E container of this class are carried under.</summary>
    private static string[] ExtendedDataObjectNames { get; } = ["first.txt", "folder/second.bin"];

    /// <summary>The single data file the XML-form Evidence Record container of this class carries and protects.</summary>
    private static string[] XmlEvidenceRecordTargetNames { get; } = ["first.txt"];


    /// <summary>
    /// The whole of clause 4.4.4.2's validation intro and items a) and d) on a container the shipped creation
    /// surface built: every manifest parses, every <c>DataObjectReference</c> digest is recomputed and matches
    /// the entry the reference names, and the CAdES object the <c>SigReference</c> names reaches
    /// <c>TOTAL-PASSED</c> through the validation process of EN 319 102-1 clause 5 over the manifest's own octets
    /// as the detached signed content.
    /// </summary>
    [TestMethod]
    public async Task AnExtendedCAdESContainerValidatesWithEveryReferenceRecomputedAndTheSignatureTotalPassed()
    {
        using var world = ValidationWorld.Create();
        using AsicContainerCreationResult created = await CreateExtendedCAdESAsync(world).ConfigureAwait(false);

        using AsicContainerValidationResult result = await AsicContainerValidation.ValidateAsync(
            ValidationContext(world, created.Container.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AsicContainerValidationStatus.Valid, result.Status,
            $"A container this library wrote validates against the clauses it was written from ({result.FailureReason}).");
        Assert.AreEqual(AsicContainerShape.Extended, result.Facts!.Shape, "Clause 4.4.4.1 item 2: the media type states the shape.");
        Assert.AreEqual(AsicContainerProfile.ExtendedCAdES, result.Facts.Profile,
            "EN 319 162-2 clause 4.3.1: every manifest is protected by a CAdES object and the container carries no time assertion of its own.");
        Assert.IsTrue(result.Facts.MediaTypeReadableAtOffset38, "Annex A.1 NOTE: the media type is where an operating system sniffs for it.");

        AsicManifestValidation manifest = result.Manifests.Single();
        Assert.AreEqual(AsicManifestRole.Signature, manifest.Role, "Clause 4.4.4.2 item 2: the name states the role.");
        Assert.AreEqual(created.SignatureEntryName, manifest.ProtectiveObjectEntryName, "The SigReference names the CAdES object.");
        Assert.HasCount(2, manifest.DataObjectReferences, "Annex A.4.1 item 2: the manifest references every data file.");
        foreach(AsicDataObjectReferenceValidation reference in manifest.DataObjectReferences)
        {
            Assert.AreEqual(AsicDataObjectReferenceStatus.Matched, reference.Status,
                $"Clause 4.4.4.2 item d): the digest stated for '{reference.EntryName}' equals the digest over the entry.");
        }

        AsicSignatureValidation signature = result.Signatures.Single();
        Assert.AreEqual(AsicContainerValidationStatus.Valid, signature.Status, $"The CAdES object validates ({signature.FailureReason}).");
        Assert.AreEqual(created.ManifestEntryName, signature.DetachedContentEntryName,
            "Annex A.4.1: an ASiC-E CAdES object is detached over the manifest file naming it.");
        Assert.AreEqual(SignatureValidationIndication.TotalPassed, signature.Outcome!.Conclusion.Indication,
            "Clause 4.4.4.2 item a): the referenced CAdES signature is validated against the ASiCManifest file content.");

        //Every digest the manifest states is independently recomputed over the octets the raw-ZIP oracle
        //extracted, so the conclusion above is not the library agreeing with itself.
        Dictionary<string, byte[]> payloads = EntryPayloads(created.Container.AsReadOnlySpan().ToArray());
        foreach(ManifestReference reference in ReadReferences(payloads[created.ManifestEntryName!]))
        {
            Assert.AreSequenceEqual(
                EvidenceRecordOracle.Hash(payloads[reference.EntryName], reference.Algorithm),
                reference.Digest,
                $"The manifest states the digest of '{reference.EntryName}' as the container stores it.");
        }

        List<AsicProtectedObject> protectedObjects = [.. result.ProtectedObjects];
        Assert.Contains(created.ManifestEntryName!, protectedObjects.Select(o => o.EntryName).ToList(),
            "Annex A.4.1: the manifest file is itself covered by the CAdES object its SigReference names.");
        foreach(string dataObject in new[] { "first.txt", "folder/second.bin" })
        {
            AsicProtectedObject entry = protectedObjects.Single(o => o.EntryName == dataObject);
            Assert.AreEqual(AsicProtectionKind.CAdESSignature, entry.ProtectedBy);
            Assert.AreEqual(created.ManifestEntryName, entry.ThroughManifestEntryName,
                "A data file is protected through the manifest whose DataObjectReference states its digest.");
        }
    }


    /// <summary>
    /// Clause 4.4.4.2 item d) is unconditional: one changed octet of a referenced data file fails the container
    /// closed, and the fact that the CAdES object over the manifest still verifies changes nothing.
    /// </summary>
    [TestMethod]
    public async Task AChangedDataObjectOctetFailsTheContainerClosedWhateverTheSignatureSays()
    {
        using var world = ValidationWorld.Create();
        using AsicContainerCreationResult created = await CreateExtendedCAdESAsync(world).ConfigureAwait(false);
        using PooledMemory tampered = RewriteWithChangedEntry(created.Container.AsReadOnlyMemory(), "first.txt");

        using AsicContainerValidationResult result = await AsicContainerValidation.ValidateAsync(
            ValidationContext(world, tampered.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AsicContainerValidationStatus.DigestMismatch, result.Status,
            "Clause 4.4.4.2 item d): a validation application shall raise an error whenever a digest value mismatch is detected.");

        AsicManifestValidation manifest = result.Manifests.Single();
        Assert.AreEqual(AsicContainerValidationStatus.DigestMismatch, manifest.Status, "The manifest carrying the mismatching reference states it.");
        Assert.AreEqual(
            AsicDataObjectReferenceStatus.DigestMismatch,
            manifest.DataObjectReferences.Single(r => r.EntryName == "first.txt").Status,
            "The reference whose entry changed is the one that does not match.");
        Assert.AreEqual(
            AsicDataObjectReferenceStatus.Matched,
            manifest.DataObjectReferences.Single(r => r.EntryName == "folder/second.bin").Status,
            "Every other reference is still recomputed and still matches — the report names all of them, and the conclusion is still terminal.");

        Assert.AreEqual(SignatureValidationIndication.TotalPassed, result.Signatures.Single().Outcome!.Conclusion.Indication,
            "The manifest's own octets did not change, so the detached CAdES object still validates — which is exactly why item d) has to be unconditional.");
        Assert.IsEmpty(result.ProtectedObjects,
            "Nothing is reported as protected by a manifest whose references do not all hold.");
    }


    /// <summary>
    /// The Evidence Record branch of the clause 4.4.4.2 item 4 dispatch: a <c>*evidencerecord*.ers</c> entry is
    /// verified per <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see> against the
    /// <c>DataObjectReference</c> targets of the manifest naming it, and NOTE 2 holds — the manifest file itself
    /// is not among the objects the record protects.
    /// </summary>
    [TestMethod]
    public async Task AnEvidenceRecordProvesTheManifestTargetsAndNotTheManifestFile()
    {
        using var world = ValidationWorld.Create();
        using AsicContainerCreationResult created = await CreateExtendedEvidenceRecordAsync(world).ConfigureAwait(false);

        using AsicContainerValidationResult result = await AsicContainerValidation.ValidateAsync(
            ValidationContext(world, created.Container.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AsicContainerValidationStatus.Valid, result.Status, $"The container validates ({result.FailureReason}).");
        Assert.AreEqual(AsicManifestRole.EvidenceRecord, result.Manifests.Single().Role,
            "Clause 4.4.3.2 item 4: an ASiCEvidenceRecordManifest is recognised by its name.");

        AsicEvidenceRecordValidation record = result.EvidenceRecords.Single();
        Assert.AreEqual(AsicEvidenceRecordForm.Binary, record.Form, "Clause 4.4.4.2 item 4 a): a '.ers' entry is the RFC 4998 form.");
        Assert.AreEqual(AsicContainerValidationStatus.Valid, record.Status, $"The record proves what the manifest says it protects ({record.FailureReason}).");
        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, record.VerificationStatus, "RFC 4998 clause 5.3 held for every target.");
        Assert.AreEqual(created.EvidenceRecordArchiveTime, record.InitialArchiveTime,
            "The instant the record proves its objects existed at is its initial Archive Timestamp's genTime.");
        Assert.AreSequenceEqual(ExtendedDataObjectNames, record.ProtectedEntryNames.ToArray(),
            "The record proves the manifest's DataObjectReference targets.");
        Assert.DoesNotContain(created.ManifestEntryName!, record.ProtectedEntryNames.ToList(),
            "Clause 4.4.4.2 NOTE 2: the ASiCManifest file referencing an ER is not itself covered by that ER.");

        List<AsicProtectedObject> byRecord = [.. result.ProtectedObjects.Where(o => o.ProtectedBy == AsicProtectionKind.EvidenceRecord)];
        Assert.AreSequenceEqual(ExtendedDataObjectNames, byRecord.Select(o => o.EntryName).ToArray(),
            "The protected-objects report names the targets and nothing else.");
        Assert.DoesNotContain(created.ManifestEntryName!, result.ProtectedObjects.Select(o => o.EntryName).ToList(),
            "Clause 4.4.4.2 NOTE 2 again, at the report level: nothing states the manifest file is protected.");
        foreach(AsicProtectedObject entry in byRecord)
        {
            Assert.AreEqual(created.EvidenceRecordArchiveTime, entry.ProvenAt, "The record's archive time is the instant the protection asserts.");
        }
    }


    /// <summary>
    /// The other branch of the same dispatch: clause 4.4.4.2 item 4 b) names the XML Evidence Record Syntax of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6283">IETF RFC 6283</see>. A run that supplies no parsing or
    /// canonicalization seam cannot read one, and refuses it with its own status rather than passing over it, so
    /// a container relying on it is never reported as valid.
    /// </summary>
    [TestMethod]
    public async Task AnXmlFormEvidenceRecordIsRefusedWhenNoSeamCanReadIt()
    {
        using var world = ValidationWorld.Create();
        using PooledMemory container = await BuildXmlEvidenceRecordContainerAsync().ConfigureAwait(false);

        using AsicContainerValidationResult result = await AsicContainerValidation.ValidateAsync(
            ValidationContext(world, container.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AsicContainerValidationStatus.XmlEvidenceRecordNotSupported, result.Status,
            "Clause 4.4.4.2 item 4 b): the XML form is recognised, and refused rather than skipped.");

        AsicEvidenceRecordValidation record = result.EvidenceRecords.Single();
        Assert.AreEqual(AsicEvidenceRecordForm.Xml, record.Form, "The form is read from the entry's name.");
        Assert.AreEqual("META-INF/ASiCEvidenceRecordManifest1.xml", record.ManifestEntryName,
            "The manifest naming the record is found through its SigReference, which is what the dispatch rule reads.");
        Assert.AreEqual(AsicContainerValidationStatus.Valid, result.Manifests.Single().Status,
            "The manifest itself is well-formed and its digests match; what is missing is a seam to read the record with.");
    }


    /// <summary>
    /// The same branch with the seams supplied: an XML-form Evidence Record is verified per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6283#appendix-A">IETF RFC 6283 Appendix A</see> over the
    /// <c>DataObjectReference</c> targets of the manifest naming it, and clause 4.4.4.2 NOTE 2 holds for it
    /// exactly as it does for the ASN.1 form.
    /// </summary>
    [TestMethod]
    public async Task AnXmlFormEvidenceRecordIsVerifiedThroughTheSuppliedSeams()
    {
        using var world = ValidationWorld.Create();
        byte[] evidenceRecord = XmlEvidenceRecordTestFactory.MintInitial(
            [[EvidenceRecordOracle.Hash(FirstDataObject, PkiDigestAlgorithm.Sha256)]],
            PkiDigestAlgorithm.Sha256,
            XmlSignatureWellKnown.ExclusiveCanonicalXml10Uri,
            world.Authority,
            world.AuthorityChain,
            TimeAssertionInstant);
        using PooledMemory container = await BuildXmlEvidenceRecordContainerAsync(evidenceRecord).ConfigureAwait(false);

        AsicContainerValidationContext context = ValidationContext(world, container.AsReadOnlyMemory()) with
        {
            ParseXmlEvidenceRecord = XmlEvidenceRecordXmlBinding.ParseAsync,
            CanonicalizeXml = XmlEvidenceRecordXmlBinding.CanonicalizeAsync
        };
        using AsicContainerValidationResult result = await AsicContainerValidation.ValidateAsync(
            context, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AsicContainerValidationStatus.Valid, result.Status, $"The container validates ({result.FailureReason}).");

        AsicEvidenceRecordValidation record = result.EvidenceRecords.Single();
        Assert.AreEqual(AsicEvidenceRecordForm.Xml, record.Form, "Clause 4.4.4.2 item 4 b): a '*evidencerecord*.xml' entry is the RFC 6283 form.");
        Assert.AreEqual(AsicContainerValidationStatus.Valid, record.Status, $"The record proves what the manifest says it protects ({record.FailureReason}).");
        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, record.XmlVerificationStatus,
            "The XML form concludes in its own enumeration, because the two forms fail in ways the other one cannot.");
        Assert.AreEqual(EvidenceRecordVerificationStatus.NotVerified, record.VerificationStatus,
            "The ASN.1 form's status stays unset for an XML-form record rather than being borrowed for it.");
        Assert.AreEqual(TimeAssertionInstant, record.InitialArchiveTime, "The instant proved is the initial Archive Time-Stamp's genTime.");
        Assert.AreSequenceEqual(XmlEvidenceRecordTargetNames,record.ProtectedEntryNames.ToArray(), "The record proves the manifest's DataObjectReference targets.");
        Assert.DoesNotContain("META-INF/ASiCEvidenceRecordManifest1.xml", record.ProtectedEntryNames.ToList(),
            "Clause 4.4.4.2 NOTE 2: the manifest file referencing an Evidence Record is not itself covered by it.");

        List<AsicProtectedObject> byRecord = [.. result.ProtectedObjects.Where(o => o.ProtectedBy == AsicProtectionKind.EvidenceRecord)];
        Assert.AreSequenceEqual(XmlEvidenceRecordTargetNames,byRecord.Select(o => o.EntryName).ToArray(),
            "The protected-objects report names the targets and nothing else.");
    }


    /// <summary>
    /// The seams are supplied but the record does not prove what the manifest says it protects: the container
    /// fails closed with the Evidence Record's own status, and nothing is reported as protected by it.
    /// </summary>
    [TestMethod]
    public async Task AnXmlFormEvidenceRecordOverOtherOctetsProvesNothing()
    {
        using var world = ValidationWorld.Create();
        byte[] evidenceRecord = XmlEvidenceRecordTestFactory.MintInitial(
            [[EvidenceRecordOracle.Hash([.. "octets no entry of the container carries"u8], PkiDigestAlgorithm.Sha256)]],
            PkiDigestAlgorithm.Sha256,
            XmlSignatureWellKnown.ExclusiveCanonicalXml10Uri,
            world.Authority,
            world.AuthorityChain,
            TimeAssertionInstant);
        using PooledMemory container = await BuildXmlEvidenceRecordContainerAsync(evidenceRecord).ConfigureAwait(false);

        AsicContainerValidationContext context = ValidationContext(world, container.AsReadOnlyMemory()) with
        {
            ParseXmlEvidenceRecord = XmlEvidenceRecordXmlBinding.ParseAsync,
            CanonicalizeXml = XmlEvidenceRecordXmlBinding.CanonicalizeAsync
        };
        using AsicContainerValidationResult result = await AsicContainerValidation.ValidateAsync(
            context, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AsicContainerValidationStatus.EvidenceRecordNotVerified, result.Status,
            "A record that proves nothing the container carries fails the container closed.");
        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.DataObjectNotCovered, result.EvidenceRecords.Single().XmlVerificationStatus,
            "Appendix A step 5.b: the data object's digest value is not in the first sequence.");
        Assert.IsEmpty(result.EvidenceRecords.Single().ProtectedEntryNames, "Nothing is reported as proved.");
        Assert.IsEmpty(result.ProtectedObjects.Where(o => o.ProtectedBy == AsicProtectionKind.EvidenceRecord).ToList(),
            "And nothing is reported as protected by it.");
    }


    /// <summary>
    /// The Annex A.7 chain walk over a container renewed twice: the walk starts at the fixed name, follows each
    /// link's single <c>Rootfile="true"</c> reference backwards, and reaches exactly the chain an independent
    /// <see cref="XDocument"/> walk over the stored manifest octets reconstructs.
    /// </summary>
    [TestMethod]
    public async Task TheArchiveManifestChainWalksBackwardThroughEveryRenewal()
    {
        using var world = ValidationWorld.Create();
        using AsicContainerCreationResult created = await CreateExtendedCAdESAsync(world).ConfigureAwait(false);
        using AsicContainerAugmentationResult first = await AsicContainerAugmentation.AddContainerArchiveTimestampAsync(
            ArchiveTimestampContext(world, created.Container.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using AsicContainerAugmentationResult second = await AsicContainerAugmentation.AddContainerArchiveTimestampAsync(
            ArchiveTimestampContext(world, first.Container.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] octets = second.Container.AsReadOnlySpan().ToArray();
        using AsicContainerValidationResult result = await AsicContainerValidation.ValidateAsync(
            ValidationContext(world, second.Container.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AsicContainerValidationStatus.Valid, result.Status, $"The renewed container validates ({result.FailureReason}).");

        List<string> independent = WalkArchiveManifestChain(EntryPayloads(octets));
        Assert.AreSequenceEqual(independent.ToArray(), result.ArchiveManifestChain.Select(link => link.EntryName).ToArray(),
            "The shipped walk reaches exactly the chain an independent XML walk over the stored octets reconstructs.");
        Assert.HasCount(2, result.ArchiveManifestChain, "Two renewals leave two links.");
        Assert.AreEqual(AsicManifestNaming.FixedArchiveManifestEntryName, result.ArchiveManifestChain[0].EntryName,
            "Annex A.7 item 2 a): the newest link always carries the fixed name.");
        Assert.AreEqual(result.ArchiveManifestChain[1].EntryName, result.ArchiveManifestChain[0].PreviousEntryName,
            "Annex A.7 item 2 b) iv): the Rootfile reference of a link names the manifest renamed out of the fixed name.");
        Assert.IsNull(result.ArchiveManifestChain[1].PreviousEntryName, "The first link ever added points back at nothing.");
        Assert.IsNotNull(result.ArchiveManifestChain[0].TimestampEntryName, "Annex A.7 item 1 c c): every link names the token applied to it.");

        foreach(AsicArchiveManifestChainLink link in result.ArchiveManifestChain)
        {
            AsicTimeAssertionValidation token = result.TimeAssertions.Single(t => t.EntryName == link.TimestampEntryName);
            Assert.AreEqual(AsicContainerValidationStatus.Valid, token.Status, $"The token of '{link.EntryName}' binds it ({token.FailureReason}).");
            Assert.AreEqual(link.EntryName, token.ProtectedEntryName, "A chain link's token is applied to that link's own octets.");
            Assert.AreEqual(TimeAssertionInstant, token.GenerationTime, "The token asserts the instant the authority minted it at.");
        }
    }


    /// <summary>
    /// A time assertion is reported as NOT EVALUATED, and the container with it, when the run supplied no
    /// signature validation inputs or seams. Clause 4.4.4.2 item b) says the token "SHALL BE VALIDATED against
    /// the ASiCManifest file content", and validating a token is the building block of EN 319 102-1 clause 5.4 —
    /// a signer certificate, a chain to a trust anchor, revocation material — not the message-imprint
    /// recomputation alone. The imprint check is necessary and not sufficient: it establishes WHICH octets the
    /// token binds and nothing about who minted it or whether that authority was trusted, so a run with nothing
    /// to check the token against reports what it did not check rather than a proof-of-existence instant it has
    /// no basis for. This is the rule the same class already applies to a CAdES object with no inputs.
    /// </summary>
    [TestMethod]
    public async Task ATimeAssertionIsNotEvaluatedRatherThanValidWhenTheRunSuppliesNoSeams()
    {
        using var world = ValidationWorld.Create();
        using AsicContainerCreationResult created = await CreateExtendedTimeAssertionAsync(world).ConfigureAwait(false);

        using(AsicContainerValidationResult evaluated = await AsicContainerValidation.ValidateAsync(
            ValidationContext(world, created.Container.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.AreEqual(AsicContainerValidationStatus.Valid, evaluated.Status, $"With inputs and seams the container validates ({evaluated.FailureReason}).");

            AsicTimeAssertionValidation token = evaluated.TimeAssertions.Single();
            Assert.AreEqual(AsicContainerValidationStatus.Valid, token.Status, token.FailureReason);
            Assert.IsNotNull(token.TokenValidation, "The token went through the time-stamp validation building block of clause 5.4.");
            Assert.AreEqual(BuildingBlockIndication.Passed, token.TokenValidation.Conclusion.Indication);
            Assert.AreEqual(TimeAssertionInstant, token.GenerationTime);
            Assert.IsNotEmpty(
                evaluated.ProtectedObjects.Where(o => o.ProtectedBy == AsicProtectionKind.TimeAssertion && o.ProvenAt == TimeAssertionInstant).ToList(),
                "A validated token proves the objects its manifest names, at the instant it asserts.");
        }

        using AsicContainerValidationResult unevaluated = await AsicContainerValidation.ValidateAsync(
            ValidationContext(world, created.Container.AsReadOnlyMemory()) with { SignatureInputs = null, SignatureSeams = null },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        AsicTimeAssertionValidation withoutSeams = unevaluated.TimeAssertions.Single();
        Assert.AreEqual(AsicContainerValidationStatus.NotEvaluated, withoutSeams.Status, "The same status the same class gives a CAdES object it was given nothing to validate with.");
        Assert.IsNull(withoutSeams.TokenValidation, "Nothing ran clause 5.4, which is what the missing result says.");
        Assert.IsNotNull(withoutSeams.FailureReason, "And the report says why rather than leaving an operator to infer it from a null.");
        Assert.AreEqual(created.TimestampEntryName, withoutSeams.EntryName);

        Assert.AreNotEqual(AsicContainerValidationStatus.Valid, unevaluated.Status, "A container whose only protective object was never evaluated is not valid.");
        Assert.AreEqual(AsicContainerValidationStatus.NotEvaluated, unevaluated.Status);
        Assert.IsEmpty(
            unevaluated.ProtectedObjects.Where(o => o.ProtectedBy == AsicProtectionKind.TimeAssertion).ToList(),
            "And nothing is reported as protected at an instant read out of a token nothing authenticated.");

        //The manifest itself was still parsed and every DataObjectReference digest recomputed — the structural
        //half of the validation is exactly what it was, which is what makes the difference attributable to the
        //token's own evaluation alone.
        Assert.AreEqual(AsicContainerValidationStatus.Valid, unevaluated.Manifests.Single().Status);
        foreach(AsicDataObjectReferenceValidation reference in unevaluated.Manifests.Single().DataObjectReferences)
        {
            Assert.AreEqual(AsicDataObjectReferenceStatus.Matched, reference.Status, reference.Uri);
        }

        //And the half that IS checkable without trust material stays fail-closed and is still checked first: the
        //same container with one XML-insignificant octet added to the manifest the token is applied to — every
        //DataObjectReference digest still matching, the document still parsing — refuses the token for its
        //message imprint rather than reporting it as merely unevaluated.
        Dictionary<string, byte[]> payloads = EntryPayloads(created.Container.AsReadOnlySpan().ToArray());
        byte[] loosened = [.. payloads[created.ManifestEntryName!], (byte)'\n'];
        using PooledMemory retouched = RewriteWithEntryContent(created.Container.AsReadOnlySpan().ToArray(), created.ManifestEntryName!, loosened);
        using AsicContainerValidationResult unbound = await AsicContainerValidation.ValidateAsync(
            ValidationContext(world, retouched.AsReadOnlyMemory()) with { SignatureInputs = null, SignatureSeams = null },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AsicContainerValidationStatus.Valid, unbound.Manifests.Single().Status, "The manifest still parses and every reference still matches.");
        Assert.AreEqual(
            AsicContainerValidationStatus.TimeAssertionNotValid,
            unbound.TimeAssertions.Single().Status,
            "The imprint recomputation is the necessary half and it runs whether or not the run can validate the token.");
    }


    /// <summary>
    /// An ASiC-S container carries no manifest at all: clause 4.3.3.2 item 4 b) makes
    /// <c>META-INF/signature.p7s</c> a detached signature over the single data file at the container root, and
    /// the validation resolves that without a manifest parsing seam.
    /// </summary>
    [TestMethod]
    public async Task ASimpleCAdESContainerValidatesOverItsSingleRootDataFile()
    {
        using var world = ValidationWorld.Create();
        using AsicContainerCreationResult created = await CreateSimpleCAdESAsync(world).ConfigureAwait(false);

        using AsicContainerValidationResult result = await AsicContainerValidation.ValidateAsync(
            ValidationContext(world, created.Container.AsReadOnlyMemory()) with { ParseManifest = null },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AsicContainerValidationStatus.Valid, result.Status, $"The container validates ({result.FailureReason}).");
        Assert.AreEqual(AsicContainerShape.Simple, result.Facts!.Shape, "Clause 4.3.3.1 item 1: the media type states the shape.");
        Assert.AreEqual(AsicContainerProfile.SimpleBaselineCAdES, result.Facts.Profile, "Clause 5.3.2.2 Table 3: one data file and one signature.");
        Assert.IsEmpty(result.Manifests, "An ASiC-S container carries no manifest.");

        AsicSignatureValidation signature = result.Signatures.Single();
        Assert.AreEqual(AsicManifestNaming.SimpleSignatureEntryName, signature.EntryName, "Clause 4.3.3.2 item 4 b) fixes the name.");
        Assert.AreEqual("data.txt", signature.DetachedContentEntryName, "The single data file at the root is what the signature covers.");
        Assert.AreEqual(SignatureValidationIndication.TotalPassed, signature.Outcome!.Conclusion.Indication, "The signature validates.");

        AsicProtectedObject entry = result.ProtectedObjects.Single();
        Assert.AreEqual("data.txt", entry.EntryName);
        Assert.AreEqual(AsicProtectionKind.CAdESSignature, entry.ProtectedBy);
        Assert.IsNull(entry.ThroughManifestEntryName, "An ASiC-S signature applies to the data file directly, through no manifest.");
    }


    /// <summary>
    /// Fail-closed: a container carrying a manifest cannot be validated without the seam that reads it, and the
    /// refusal names that rather than reporting a container nothing was checked about as valid.
    /// </summary>
    [TestMethod]
    public async Task AContainerWhoseManifestCannotBeReadIsRefusedRatherThanAssumedValid()
    {
        using var world = ValidationWorld.Create();
        using AsicContainerCreationResult created = await CreateExtendedCAdESAsync(world).ConfigureAwait(false);

        using AsicContainerValidationResult result = await AsicContainerValidation.ValidateAsync(
            ValidationContext(world, created.Container.AsReadOnlyMemory()) with { ParseManifest = null },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AsicContainerValidationStatus.ManifestParserMissing, result.Status,
            "Clause 4.4.4.2's validation intro requires the manifest's content to be verified; with no seam it cannot be read at all.");
        Assert.AreEqual(AsicContainerValidationStatus.ManifestParserMissing, result.Manifests.Single().Status);
        Assert.IsEmpty(result.ProtectedObjects, "Nothing is reported as protected when nothing could be checked.");
    }


    /// <summary>
    /// Every CAdES object inside a container is DETACHED (clause 4.4.4.2 item 3 a) for ASiC-E, clause 4.3.3.2
    /// item 4 b) for ASiC-S), so the backend detached verification runs on decides which containers can be
    /// validated at all. A container whose CAdES object states <c>id-RSASSA-PSS</c> — an algorithm this
    /// library's own managed backend does not implement — reaches <c>TOTAL-PASSED</c>, because the CAdES
    /// binding resolves the registered <see cref="VerifyDetachedCmsSignedDataDelegate"/> rather than reaching
    /// past the registry for one fixed backend.
    /// </summary>
    /// <remarks>
    /// The three assertions are one argument: an independent backend verifies the signature (so it is valid),
    /// the managed backend refuses it (so the outcome cannot come from that backend), and the container
    /// validates (so the registered seam is what the container path reached).
    /// </remarks>
    [TestMethod]
    public async Task AContainerSignedWithRsaPssValidatesThroughTheRegisteredDetachedCmsBackend()
    {
        using var world = ValidationWorld.Create(withRsaSigner: true);
        using AuthoredContainer authored = await BuildExtendedContainerSignedByAsync(world.RsaSigner!, RSASignaturePadding.Pss).ConfigureAwait(false);

        //The signature is genuinely valid: an independently registered backend, sharing no code with the one
        //the binding resolves, verifies it over the very octets the container carries as the manifest.
        VerifyDetachedCmsSignedDataDelegate independent = CryptographicKeyFactory.GetFunction<VerifyDetachedCmsSignedDataDelegate>(
            typeof(VerifyDetachedCmsSignedDataDelegate), BouncyCastleQualifier)
            ?? throw new InvalidOperationException("No BouncyCastle VerifyDetachedCmsSignedDataDelegate has been registered.");
        using(CmsVerifiedContent verified = await independent(
            authored.Signature, authored.ManifestContent, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.AreSequenceEqual(
                authored.ManifestContent.AsReadOnlySpan().ToArray(),
                verified.Content.ToArray(),
                "The independent backend verified the signature over the manifest octets the container carries.");
        }

        //...and the library's own managed backend, which is what the seam falls back to when a host registers
        //nothing, does not implement the algorithm: its RSA profile is PKCS#1 v1.5 with SHA-256 alone.
        await Assert.ThrowsExactlyAsync<CryptographicException>(
            async () => (await ManagedCmsVerification.VerifyDetachedCmsSignedDataAsync(
                authored.Signature, authored.ManifestContent, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).Dispose(),
            "The managed backend states what it does not implement rather than reporting a valid signature as broken.");

        using AsicContainerValidationResult result = await AsicContainerValidation.ValidateAsync(
            ValidationContext(world, authored.Container.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AsicContainerValidationStatus.Valid, result.Status,
            $"A container whose signature verifies is valid whichever backend the host registered ({result.FailureReason}).");

        AsicSignatureValidation signature = result.Signatures.Single();
        Assert.AreEqual(SignatureValidationIndication.TotalPassed, signature.Outcome!.Conclusion.Indication,
            $"Clause 4.4.4.2 item a): the CAdES signature validates against the ASiCManifest file content ({signature.FailureReason}).");
        Assert.AreEqual(authored.ManifestEntryName, signature.DetachedContentEntryName,
            "Annex A.4.1: the CAdES object is detached over the manifest file naming it.");
    }


    /// <summary>
    /// The other half of the same rule: a host that registers nothing for the detached seam keeps the library's
    /// own managed backend, and the elliptic-curve container this library writes validates through it exactly as
    /// it did before the seam existed — the backend verifies the container's own CAdES object over the
    /// container's own manifest octets, and the container reaches <c>TOTAL-PASSED</c>.
    /// </summary>
    [TestMethod]
    public async Task TheManagedBackendStillVerifiesTheDetachedObjectOfAnEllipticCurveContainer()
    {
        using var world = ValidationWorld.Create();
        using AsicContainerCreationResult created = await CreateExtendedCAdESAsync(world).ConfigureAwait(false);

        //The two objects are taken out of the container by the independent raw-ZIP oracle, so what the managed
        //backend is handed is what a validation application reading the container would hand it.
        Dictionary<string, byte[]> payloads = EntryPayloads(created.Container.AsReadOnlySpan().ToArray());
        using CmsSignedData signature = CmsSignedData.FromBytes(payloads[created.SignatureEntryName!], BaseMemoryPool.Shared);
        using SignedContentMemory manifestContent = SignedContentMemory.FromBytes(payloads[created.ManifestEntryName!], BaseMemoryPool.Shared);

        using(CmsVerifiedContent verified = await ManagedCmsVerification.VerifyDetachedCmsSignedDataAsync(
            signature, manifestContent, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.AreSequenceEqual(
                payloads[created.ManifestEntryName!],
                verified.Content.ToArray(),
                "The fallback backend verifies the container's CAdES object over the container's manifest octets.");
        }

        using AsicContainerValidationResult result = await AsicContainerValidation.ValidateAsync(
            ValidationContext(world, created.Container.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AsicContainerValidationStatus.Valid, result.Status, $"The container validates ({result.FailureReason}).");
        Assert.AreEqual(SignatureValidationIndication.TotalPassed, result.Signatures.Single().Outcome!.Conclusion.Indication,
            "An algorithm the managed backend accepts reaches the same conclusion it always did.");
    }


    /// <summary>
    /// Octets that are not a container are refused with the reader's own status, and nothing escapes as an
    /// exception — the discipline contract R-10 states for attacker-reachable input.
    /// </summary>
    [TestMethod]
    public async Task OctetsThatAreNotAContainerAreRefusedWithTheReaderStatus()
    {
        using var world = ValidationWorld.Create();
        byte[] notAnArchive = [.. "this is not a ZIP archive at all"u8];

        using AsicContainerValidationResult result = await AsicContainerValidation.ValidateAsync(
            ValidationContext(world, notAnArchive), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AsicContainerValidationStatus.ContainerNotRead, result.Status, "The octets are refused as a status.");
        Assert.AreNotEqual(AsicZipReadStatus.Read, result.ReadStatus, "The reader's own reason is carried through.");
        Assert.IsNull(result.Facts, "Nothing was read, so there are no facts.");
    }


    /// <summary>
    /// Builds an ASiC-E container carrying one CAdES object over an <c>ASiCManifest</c> file naming two data
    /// files, signed by the ring leaf through the three-phase split.
    /// </summary>
    /// <param name="world">The minted world.</param>
    /// <returns>The container. The caller owns and disposes it.</returns>
    private async Task<AsicContainerCreationResult> CreateExtendedCAdESAsync(ValidationWorld world)
    {
        using AsicContainerSignaturePreparation preparation = await AsicContainerCreation.PrepareSignatureAsync(
            new AsicContainerSignatureContext
            {
                Shape = AsicContainerShape.Extended,
                DataObjects =
                [
                    new AsicDataObject { Name = "first.txt", Content = FirstDataObject, MediaType = "text/plain" },
                    new AsicDataObject { Name = "folder/second.bin", Content = SecondDataObject }
                ],
                SignerCertificate = world.SignerCertificate,
                SigningTime = SigningTime,
                LastModified = ContainerInstant,
                EncodeManifest = AsicManifestXmlBinding.EncodeAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        return CompleteWithRingLeaf(world, preparation);
    }


    /// <summary>
    /// Builds an ASiC-S container carrying one CAdES object detached over the single data file.
    /// </summary>
    /// <param name="world">The minted world.</param>
    /// <returns>The container. The caller owns and disposes it.</returns>
    private async Task<AsicContainerCreationResult> CreateSimpleCAdESAsync(ValidationWorld world)
    {
        using AsicContainerSignaturePreparation preparation = await AsicContainerCreation.PrepareSignatureAsync(
            new AsicContainerSignatureContext
            {
                Shape = AsicContainerShape.Simple,
                DataObjects = [new AsicDataObject { Name = "data.txt", Content = FirstDataObject }],
                SignerCertificate = world.SignerCertificate,
                SigningTime = SigningTime,
                LastModified = ContainerInstant
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        return CompleteWithRingLeaf(world, preparation);
    }


    /// <summary>
    /// Builds an ASiC-E container carrying a time assertion over the <c>ASiCManifest</c> file naming the two
    /// data files (clause 4.4.4.2 item 3 b) with Annex A.4.1) and no CAdES object at all, so what validating it
    /// concludes is a statement about the token alone.
    /// </summary>
    /// <param name="world">The minted world, whose responder mints the token.</param>
    /// <returns>The container. The caller owns and disposes it.</returns>
    private async Task<AsicContainerCreationResult> CreateExtendedTimeAssertionAsync(ValidationWorld world) =>
        await AsicContainerCreation.CreateTimeAssertionAsync(
            new AsicContainerTimeAssertionContext
            {
                Shape = AsicContainerShape.Extended,
                DataObjects =
                [
                    new AsicDataObject { Name = "first.txt", Content = FirstDataObject, MediaType = "text/plain" },
                    new AsicDataObject { Name = "folder/second.bin", Content = SecondDataObject }
                ],
                LastModified = ContainerInstant,
                TsaUri = TsaUri,
                FetchTimestampResponse = world.Responder.FetchAsync,
                EncodeManifest = AsicManifestXmlBinding.EncodeAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>
    /// Builds an ASiC-E container carrying an RFC 4998 Evidence Record over two data files and the
    /// <c>ASiCEvidenceRecordManifest</c> naming it.
    /// </summary>
    /// <param name="world">The minted world.</param>
    /// <returns>The container. The caller owns and disposes it.</returns>
    private async Task<AsicContainerCreationResult> CreateExtendedEvidenceRecordAsync(ValidationWorld world) =>
        await AsicContainerCreation.CreateEvidenceRecordAsync(
            new AsicContainerEvidenceRecordContext
            {
                Shape = AsicContainerShape.Extended,
                DataObjects =
                [
                    new AsicDataObject { Name = "first.txt", Content = FirstDataObject, MediaType = "text/plain" },
                    new AsicDataObject { Name = "folder/second.bin", Content = SecondDataObject }
                ],
                LastModified = ContainerInstant,
                TsaUri = TsaUri,
                FetchTimestampResponse = world.Responder.FetchAsync,
                EncodeManifest = AsicManifestXmlBinding.EncodeAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>
    /// Completes a prepared container by signing phase one's output with the ring leaf's own key — the shape a
    /// remote signer uses, and the only way a container's signer can carry a certificate chaining to the ring's
    /// root.
    /// </summary>
    /// <param name="world">The minted world.</param>
    /// <param name="preparation">The phase-one result.</param>
    /// <returns>The container. The caller owns and disposes it.</returns>
    private static AsicContainerCreationResult CompleteWithRingLeaf(ValidationWorld world, AsicContainerSignaturePreparation preparation)
    {
        byte[] signatureValueP1363 = world.Signer.SigningKey.SignData(
            preparation.SignaturePreparation.SigningInput.AsReadOnlySpan().ToArray(), HashAlgorithmName.SHA256);
        using IMemoryOwner<byte> signatureValueDer = EcdsaSignatureEncoding.ConvertP1363ToDer(
            signatureValueP1363, BaseMemoryPool.Shared, out int derLength);

        return AsicContainerCreation.CompleteSignature(
            preparation, world.SignerCertificate, CryptoAlgorithm.P256, signatureValueDer.Memory[..derLength],
            additionalCertificates: null, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Builds, entry by entry, a container carrying an Evidence Record in the XML form — a container this
    /// library's creation surface does not produce, because it emits the RFC 4998 form only.
    /// </summary>
    /// <returns>The container's octets. The caller owns and disposes them.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the digest transfers to the AsicDataObjectReference and the reference's to the manifest, which the using declaration disposes; the analyzer's data flow does not follow ownership into a collection expression.")]
    private async Task<PooledMemory> BuildXmlEvidenceRecordContainerAsync(byte[]? evidenceRecordDocument = null)
    {
        byte[] evidenceRecord = evidenceRecordDocument
            ?? Encoding.UTF8.GetBytes("<EvidenceRecord xmlns=\"urn:ietf:params:xml:ns:ers\" Version=\"1.0\"/>");

        //The digest's ownership transfers to the reference, and the reference's to the manifest, which the using
        //below disposes — the same ownership chain the creation surface builds a manifest through.
        DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlyMemory<byte>(FirstDataObject), PkiDigestAlgorithm.Sha256.OutputByteLength, PkiDigestAlgorithm.Sha256.DigestTag,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using var manifest = new AsicManifest
        {
            SignatureReference = new AsicSignatureReference { Uri = AsicContainerUri.ToReference("META-INF/evidencerecord1.xml") },
            DataObjectReferences =
            [
                new AsicDataObjectReference
                {
                    Uri = AsicContainerUri.ToReference("first.txt"),
                    DigestAlgorithm = PkiDigestAlgorithm.Sha256,
                    Digest = digest
                }
            ]
        };
        using AsicManifestEncodeResult encoded = await AsicManifestXmlBinding.EncodeAsync(
            new AsicManifestEncodeContext { Manifest = manifest }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(encoded.IsEncoded, "The manifest has to be written before a container can carry it.");

        return AsicZipAuthoring.Write(
            new AsicZipAuthoringContext
            {
                MediaType = AsicWellKnown.AsicExtendedMediaType,
                LastModified = ContainerInstant,
                Entries =
                [
                    new AsicZipEntrySource { Name = "first.txt", Content = FirstDataObject },
                    new AsicZipEntrySource { Name = "META-INF/ASiCEvidenceRecordManifest1.xml", Content = encoded.Document!.AsReadOnlyMemory() },
                    new AsicZipEntrySource { Name = "META-INF/evidencerecord1.xml", Content = evidenceRecord }
                ]
            },
            BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Builds, entry by entry, an ASiC-E container whose <c>ASiCManifest</c> file is protected by a detached
    /// CAdES object signed with the given RSA padding — the shape clause 4.4.4.2 item 3 a) states, authored
    /// outside this library's creation surface because that surface emits the signature algorithms of its own
    /// baseline profiles only, and a third-party container is exactly what a validation application meets.
    /// </summary>
    /// <param name="signerCertificate">The signer's certificate, carrying its private key.</param>
    /// <param name="rsaSignaturePadding">The padding the CAdES object is signed with.</param>
    /// <returns>The container and the objects a test checks it against. The caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the digest transfers to the AsicDataObjectReference and the reference's to the manifest, which the using declaration disposes; the analyzer's data flow does not follow ownership into a collection expression.")]
    private async Task<AuthoredContainer> BuildExtendedContainerSignedByAsync(
        X509Certificate2 signerCertificate,
        RSASignaturePadding rsaSignaturePadding)
    {
        string manifestEntryName = AsicManifestNaming.CreateEntryName(AsicContainerFileKind.SignatureManifest, []);
        string signatureEntryName = AsicManifestNaming.CreateEntryName(AsicContainerFileKind.Signature, []);

        //The digest's ownership transfers to the reference, and the reference's to the manifest, which the using
        //below disposes — the same ownership chain the creation surface builds a manifest through.
        DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlyMemory<byte>(FirstDataObject), PkiDigestAlgorithm.Sha256.OutputByteLength, PkiDigestAlgorithm.Sha256.DigestTag,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using var manifest = new AsicManifest
        {
            SignatureReference = new AsicSignatureReference { Uri = AsicContainerUri.ToReference(signatureEntryName) },
            DataObjectReferences =
            [
                new AsicDataObjectReference
                {
                    Uri = AsicContainerUri.ToReference("first.txt"),
                    DigestAlgorithm = PkiDigestAlgorithm.Sha256,
                    Digest = digest
                }
            ]
        };
        using AsicManifestEncodeResult encoded = await AsicManifestXmlBinding.EncodeAsync(
            new AsicManifestEncodeContext { Manifest = manifest }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(encoded.IsEncoded, "The manifest has to be written before a container can carry it.");

        SignedContentMemory? manifestContent = null;
        CmsSignedData? signature = null;
        try
        {
            manifestContent = SignedContentMemory.FromBytes(encoded.Document!.AsReadOnlySpan(), BaseMemoryPool.Shared);
            signature = CmsSignedDataTestFactory.SignAsCAdESDetached(
                manifestContent.AsReadOnlySpan(), signerCertificate, SigningTime, rsaSignaturePadding);

            PooledMemory container = AsicZipAuthoring.Write(
                new AsicZipAuthoringContext
                {
                    MediaType = AsicWellKnown.AsicExtendedMediaType,
                    LastModified = ContainerInstant,
                    Entries =
                    [
                        new AsicZipEntrySource { Name = "first.txt", Content = FirstDataObject },
                        new AsicZipEntrySource { Name = manifestEntryName, Content = manifestContent.AsReadOnlyMemory() },
                        new AsicZipEntrySource { Name = signatureEntryName, Content = signature.AsReadOnlyMemory() }
                    ]
                },
                BaseMemoryPool.Shared);

            return new AuthoredContainer(container, manifestContent, signature, manifestEntryName, signatureEntryName);
        }
        catch
        {
            signature?.Dispose();
            manifestContent?.Dispose();

            throw;
        }
    }


    /// <summary>
    /// States the validation context every test of this class shares: the container, the instant, the manifest
    /// seam and the inputs and seams the embedded objects are validated under.
    /// </summary>
    /// <param name="world">The minted world.</param>
    /// <param name="container">The container's octets.</param>
    /// <returns>The context.</returns>
    private static AsicContainerValidationContext ValidationContext(ValidationWorld world, ReadOnlyMemory<byte> container) =>
        new()
        {
            Container = container,
            CurrentTime = ValidationTime,
            ParseManifest = AsicManifestXmlBinding.ParseAsync,
            SignatureInputs = world.Inputs,
            SignatureSeams = world.Seams
        };


    /// <summary>
    /// States the Annex A.7 augmentation context this class's chain test shares.
    /// </summary>
    /// <param name="world">The minted world.</param>
    /// <param name="container">The container to augment.</param>
    /// <returns>The context.</returns>
    private static AsicContainerArchiveTimestampContext ArchiveTimestampContext(ValidationWorld world, ReadOnlyMemory<byte> container) =>
        new()
        {
            Container = container,
            LastModified = ContainerInstant,
            TsaUri = TsaUri,
            FetchTimestampResponse = world.Responder.FetchAsync,
            EncodeManifest = AsicManifestXmlBinding.EncodeAsync,
            ParseManifest = AsicManifestXmlBinding.ParseAsync
        };


    /// <summary>
    /// Rewrites a container with one entry's octets replaced and every other entry carried across as the
    /// independent raw-ZIP oracle recovered it.
    /// </summary>
    /// <param name="container">The container's octets.</param>
    /// <param name="entryName">The entry whose octets are replaced.</param>
    /// <param name="content">The octets to store under that name.</param>
    /// <returns>The rewritten container. The caller owns and disposes it.</returns>
    private static PooledMemory RewriteWithEntryContent(byte[] container, string entryName, byte[] content)
    {
        Dictionary<string, byte[]> payloads = EntryPayloads(container);
        string mediaType = Encoding.UTF8.GetString(payloads[AsicWellKnown.MimetypeEntryName]);
        var entries = new List<AsicZipEntrySource>(payloads.Count);
        foreach((string name, byte[] payload) in payloads)
        {
            if(AsicWellKnown.IsMimetypeEntryName(name) || name.EndsWith('/'))
            {
                continue;
            }

            entries.Add(new AsicZipEntrySource
            {
                Name = name,
                Content = string.Equals(name, entryName, StringComparison.Ordinal) ? content : payload
            });
        }

        return AsicZipAuthoring.Write(
            new AsicZipAuthoringContext { MediaType = mediaType, Entries = entries, LastModified = ContainerInstant },
            BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Reads every entry's octets out of a container through the independent raw-ZIP oracle.
    /// </summary>
    /// <param name="container">The container's octets.</param>
    /// <returns>The payloads, keyed by entry name.</returns>
    private static Dictionary<string, byte[]> EntryPayloads(byte[] container)
    {
        OracleZipArchive archive = AsicZipStructureOracle.Parse(container);
        var payloads = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach(OracleZipEntry header in archive.LocalHeaders)
        {
            payloads.Add(header.Name, AsicZipStructureOracle.ReadEntryContent(container, header));
        }

        return payloads;
    }


    /// <summary>
    /// Reads the <c>DataObjectReference</c> elements of a manifest document with an independent XML reader.
    /// </summary>
    /// <param name="manifest">The manifest document's octets, as the container stores them.</param>
    /// <returns>The references, in document order.</returns>
    private static List<ManifestReference> ReadReferences(byte[] manifest)
    {
        XDocument document = XDocument.Parse(Encoding.UTF8.GetString(manifest));
        XNamespace asic = AsicManifestXmlBinding.AsicNamespace;
        XNamespace ds = XmlSignatureWellKnown.XmlSignatureNamespace;

        var references = new List<ManifestReference>();
        foreach(XElement element in document.Root!.Elements(asic + "DataObjectReference"))
        {
            string algorithmUri = element.Element(ds + XmlSignatureWellKnown.DigestMethodElementName)!
                .Attribute(XmlSignatureWellKnown.AlgorithmAttributeName)!.Value;
            PkiDigestAlgorithm algorithm = XmlSignatureWellKnown.DigestAlgorithmFromUri(algorithmUri)
                ?? throw new InvalidOperationException($"'{algorithmUri}' does not name a digest algorithm this library computes.");

            references.Add(new ManifestReference(
                element.Attribute("URI")!.Value,
                algorithm,
                Convert.FromBase64String(element.Element(ds + XmlSignatureWellKnown.DigestValueElementName)!.Value),
                element.Attribute("Rootfile") is { } rootFile ? bool.Parse(rootFile.Value) : null));
        }

        return references;
    }


    /// <summary>
    /// Walks the Annex A.7 chain backward from the file carrying the fixed name, following the one reference of
    /// each manifest whose <c>Rootfile</c> attribute states true.
    /// </summary>
    /// <param name="payloads">Every entry of the container, keyed by name.</param>
    /// <returns>The chain, newest first.</returns>
    /// <remarks>
    /// Written from Annex A.7 items 2 a) and 2 b) iv) rather than from the library, and iteratively rather than
    /// recursively, bounded by the number of entries the container carries so that a manifest pointing at itself
    /// cannot spin. This is the algorithm the shipped walk has to agree with.
    /// </remarks>
    private static List<string> WalkArchiveManifestChain(Dictionary<string, byte[]> payloads)
    {
        var chain = new List<string>();
        string? current = AsicManifestNaming.FixedArchiveManifestEntryName;
        while(current is not null && chain.Count <= payloads.Count)
        {
            chain.Add(current);
            List<ManifestReference> rootFiles = [.. ReadReferences(payloads[current]).Where(reference => reference.RootFile == true)];
            Assert.IsLessThanOrEqualTo(1, rootFiles.Count, $"'{current}' states at most one backward pointer.");
            current = rootFiles.Count == 0 ? null : rootFiles[0].EntryName;
        }

        return chain;
    }


    /// <summary>
    /// Rewrites a container with one entry's first octet changed, recomputing the archive's own checksums so
    /// that what fails is the manifest's digest rather than the ZIP structure.
    /// </summary>
    /// <param name="container">The container's octets.</param>
    /// <param name="entryName">The entry to change.</param>
    /// <returns>The rewritten container. The caller owns and disposes it.</returns>
    private static PooledMemory RewriteWithChangedEntry(ReadOnlyMemory<byte> container, string entryName)
    {
        using AsicZipReadResult read = AsicZipReading.Read(container, AsicZipReadLimits.Conformant, BaseMemoryPool.Shared);
        Assert.IsTrue(read.IsRead, $"The container must read before it can be changed ({read.Status}).");

        var entries = new List<AsicZipEntrySource>(read.Container!.Entries.Count);
        var changed = new List<byte[]>(1);
        foreach(AsicZipEntry entry in read.Container.Entries)
        {
            if(AsicWellKnown.IsMimetypeEntryName(entry.Name))
            {
                continue;
            }

            byte[] octets = entry.Content.AsReadOnlySpan().ToArray();
            if(string.Equals(entry.Name, entryName, StringComparison.Ordinal))
            {
                octets[0] ^= 0x01;
                changed.Add(octets);
            }

            entries.Add(new AsicZipEntrySource
            {
                Name = entry.Name,
                Content = octets,
                CompressionMethod = entry.CompressionMethod,
                LastModified = entry.LastModified
            });
        }

        Assert.HasCount(1, changed, $"'{entryName}' must be an entry of the container.");

        return AsicZipAuthoring.Write(
            new AsicZipAuthoringContext
            {
                MediaType = read.Container.MediaType,
                Entries = entries,
                LastModified = ContainerInstant,
                ArchiveComment = read.Container.ArchiveComment
            },
            BaseMemoryPool.Shared);
    }


    /// <summary>
    /// A container this class authored entry by entry, together with the two objects a test checks it against:
    /// the octets the CAdES object is detached over, and the CAdES object itself.
    /// </summary>
    private sealed class AuthoredContainer: IDisposable
    {
        /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
        private bool disposed;


        /// <summary>Initialises the holder, taking ownership of every carrier.</summary>
        /// <param name="container">The container's octets.</param>
        /// <param name="manifestContent">The manifest octets the CAdES object is detached over.</param>
        /// <param name="signature">The CAdES object.</param>
        /// <param name="manifestEntryName">The entry name the manifest is carried under.</param>
        /// <param name="signatureEntryName">The entry name the CAdES object is carried under.</param>
        public AuthoredContainer(
            PooledMemory container,
            SignedContentMemory manifestContent,
            CmsSignedData signature,
            string manifestEntryName,
            string signatureEntryName)
        {
            Container = container;
            ManifestContent = manifestContent;
            Signature = signature;
            ManifestEntryName = manifestEntryName;
            SignatureEntryName = signatureEntryName;
        }


        /// <summary>The container's octets. Owned by this instance.</summary>
        public PooledMemory Container { get; }

        /// <summary>The manifest octets the CAdES object is detached over. Owned by this instance.</summary>
        public SignedContentMemory ManifestContent { get; }

        /// <summary>The CAdES object the container carries. Owned by this instance.</summary>
        public CmsSignedData Signature { get; }

        /// <summary>The entry name the manifest is carried under.</summary>
        public string ManifestEntryName { get; }

        /// <summary>The entry name the CAdES object is carried under.</summary>
        public string SignatureEntryName { get; }


        /// <inheritdoc/>
        public void Dispose()
        {
            if(disposed)
            {
                return;
            }

            disposed = true;
            Signature.Dispose();
            ManifestContent.Dispose();
            Container.Dispose();
        }
    }


    /// <summary>One <c>DataObjectReference</c> an independent XML reader recovered from a manifest.</summary>
    /// <param name="EntryName">The <c>URI</c> attribute, which for every container this class builds is already an entry name.</param>
    /// <param name="Algorithm">The algorithm the <c>ds:DigestMethod</c> names.</param>
    /// <param name="Digest">The <c>ds:DigestValue</c>, decoded.</param>
    /// <param name="RootFile">The <c>Rootfile</c> attribute's value, or <see langword="null"/> when the element states none.</param>
    private sealed record ManifestReference(string EntryName, PkiDigestAlgorithm Algorithm, byte[] Digest, bool? RootFile);


    /// <summary>
    /// The world every container of this class is built and validated in: the ring, the responder, the signer
    /// whose certificate chains to the ring's root, and the validation inputs and seams.
    /// </summary>
    private sealed class ValidationWorld: IDisposable
    {
        /// <summary>The carriers this world rented, released in reverse order.</summary>
        private readonly List<IDisposable> owned = [];

        /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
        private bool disposed;


        /// <summary>The signer, whose own key completes every prepared signature.</summary>
        public X509ChainTestRingNode Signer { get; private set; } = null!;

        /// <summary>The transport that mints a genuine token over whatever imprint a request states.</summary>
        public MintingTimestampResponder Responder { get; private set; } = null!;

        /// <summary>The Time-Stamping Authority node, exposed so an Evidence Record can be minted directly against it.</summary>
        public X509ChainTestRingNode Authority { get; private set; } = null!;

        /// <summary>The certificates a token minted against <see cref="Authority"/> carries.</summary>
        public IReadOnlyList<X509ChainTestRingNode> AuthorityChain { get; private set; } = null!;

        /// <summary>The signer's certificate.</summary>
        public PkiCertificateMemory SignerCertificate { get; private set; } = null!;

        /// <summary>
        /// The RSA end-entity certificate, carrying its private key, for a container whose CAdES object is
        /// signed with an RSA signature algorithm; <see langword="null"/> unless the world was asked for one.
        /// </summary>
        public X509Certificate2? RsaSigner { get; private set; }

        /// <summary>The inputs every embedded object is validated under.</summary>
        public SignatureValidationInputs Inputs { get; private set; } = null!;

        /// <summary>The seams every embedded object's validation composes.</summary>
        public SignatureValidationSeams Seams { get; private set; } = null!;


        /// <summary>
        /// Mints the world.
        /// </summary>
        /// <param name="withRsaSigner">
        /// Whether to mint the RSA end-entity certificate <see cref="RsaSigner"/> as well — the key material a
        /// container signed with an RSA signature algorithm needs, minted only when a test asks for it because
        /// an RSA key generation costs more than every other part of a world put together.
        /// </param>
        /// <returns>The world, which the caller disposes.</returns>
        public static ValidationWorld Create(bool withRsaSigner = false)
        {
            var world = new ValidationWorld();
            try
            {
                world.Build(withRsaSigner);

                return world;
            }
            catch
            {
                world.Dispose();

                throw;
            }
        }


        /// <inheritdoc/>
        public void Dispose()
        {
            if(disposed)
            {
                return;
            }

            disposed = true;
            for(int i = owned.Count - 1; i >= 0; --i)
            {
                owned[i].Dispose();
            }

            owned.Clear();
        }


        /// <summary>Mints the ring, the responder and the validation inputs and seams.</summary>
        /// <param name="withRsaSigner">Whether to mint <see cref="RsaSigner"/> as well.</param>
        private void Build(bool withRsaSigner)
        {
            var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
            X509ChainTestRingNode root = Own(X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter));
            X509ChainTestRingNode authority = Own(X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter));
            Signer = Own(X509ChainTestRing.CreateLeaf(root, SignerDnsName, timeProvider, notBefore: NotBefore, notAfter: NotAfter));
            if(withRsaSigner)
            {
                RsaSigner = Own(X509ChainTestRing.CreateRsaLeafCertificate(root, RsaSignerDnsName, timeProvider, notBefore: NotBefore, notAfter: NotAfter));
            }

            Responder = new MintingTimestampResponder(authority, [authority, root], TimeAssertionInstant);
            Authority = authority;
            AuthorityChain = [authority, root];

            SignerCertificate = Own(OcspTestFixtures.ToCertificateCarrier(Signer.Certificate));
            PkiCertificateMemory rootCertificate = Own(OcspTestFixtures.ToCertificateCarrier(root.Certificate));
            PkiCertificateMemory authorityCertificate = Own(OcspTestFixtures.ToCertificateCarrier(authority.Certificate));
            PkiCertificateMemory revocationList = Own(X509ChainTestRingRevocation.MintCertificateRevocationList(root, ThisUpdate, NextUpdate, []));

            var x509Constraints = new X509ValidationConstraints
            {
                TrustAnchors = [new TrustAnchorConstraint(rootCertificate, SunsetDate: null)],
                MaximumAcceptedRevocationFreshness = TimeSpan.FromDays(365)
            };
            var cryptographicConstraints = new CryptographicConstraints
            {
                Entries =
                [
                    new AlgorithmReliabilityEntry(
                        new PkiAlgorithmIdentifier(X509ChainTestRing.EcdsaWithSha256SignatureOid),
                        MinimumKeySizeBits: X509ChainTestRing.SigningKeySizeBits,
                        TrustedUntil: null),
                    new AlgorithmReliabilityEntry(PkiAlgorithmIdentifier.Sha256, MinimumKeySizeBits: null, TrustedUntil: null),

                    //Stated in every world of this class, whether or not that world minted an RSA signer: the
                    //table is a lookup, and a container whose CAdES object states id-RSASSA-PSS is validated
                    //against the same constraints as every other one.
                    new AlgorithmReliabilityEntry(
                        new PkiAlgorithmIdentifier(RsaSsaPssSignatureOid),
                        MinimumKeySizeBits: X509ChainTestRing.RsaSigningKeySizeBits,
                        TrustedUntil: null)
                ]
            };
            var constraints = new SignatureValidationConstraints
            {
                Identifier = SignatureValidationPolicyIdentifier.CallerSuppliedConstraints,
                X509 = x509Constraints,
                Cryptographic = cryptographicConstraints,
                SignatureElements = SignatureElementsConstraints.None
            };

            var completer = new CertificateChainCompleter([rootCertificate]);
            var revocationChecker = new CrlRevocationChecker([revocationList]);
            Seams = new SignatureValidationSeams
            {
                Format = CAdESSignatureFacts.Seam,
                CompleteCertificateChain = completer.CompleteAsync,
                ValidateCertificateChain = MicrosoftX509Functions.ValidateChainAsync,
                CheckRevocation = revocationChecker.CheckAsync
            };

            //Every container this class validates carries its own Signed Data Objects, so the SignedDataObject
            //here is a placeholder the container layer replaces per embedded object; what the inputs carry that
            //matters is the constraints, the trust anchor and the validation data.
            Inputs = new SignatureValidationInputs
            {
                SignedDataObject = SignerCertificate,
                Constraints = constraints,
                TimestampConstraints = constraints,
                CertificateValidationData = [rootCertificate, authorityCertificate, revocationList]
            };
        }


        /// <summary>Takes ownership of one carrier.</summary>
        /// <typeparam name="T">The carrier's type.</typeparam>
        /// <param name="carrier">The carrier.</param>
        /// <returns>The same carrier.</returns>
        private T Own<T>(T carrier) where T: IDisposable
        {
            owned.Add(carrier);

            return carrier;
        }
    }
}
