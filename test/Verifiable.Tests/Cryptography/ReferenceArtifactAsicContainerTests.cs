using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;
using Verifiable.Tests.TestInfrastructure;
using BcCmsSignedData = Org.BouncyCastle.Cms.CmsSignedData;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The reference-artifact leg of the Associated Signature Container surfaces of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> and
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916202/01.01.01_60/en_31916202v010101p.pdf">
/// ETSI EN 319 162-2 V1.1.1</see>: containers this library never produced are read by
/// <see cref="AsicContainerReading"/> and concluded on by <see cref="AsicContainerValidation"/>, and every
/// conclusion is a precise recorded outcome rather than a "does not throw".
/// </summary>
/// <remarks>
/// <para>
/// <strong>Where the artifacts come from.</strong> The same optional local reference-artifact clone under
/// <c>tempdocs/etsi-ades-reference/</c> the other reference-artifact classes read, discovered by LAYOUT and by
/// CONTENT rather than by any directory name: a <c>src/test/resources/validation</c> tree whose container files
/// carry a <c>META-INF/*signature*.p7s</c> entry is the CAdES-flavoured container corpus, and the tree carrying
/// the most such containers is the one used. Nothing is copied into this repository, and when the clone is
/// absent every test here reports <see cref="Assert.Inconclusive(string)"/> instead of failing.
/// </para>
/// <para>
/// <strong>What is checked independently.</strong> Every archive is taken apart by
/// <see cref="AsicZipStructureOracle"/> — a second implementation of the ZIP structures written from the
/// format's own field layout — before anything is asserted about it; every CAdES object is verified detached by
/// the BouncyCastle CMS reader over the octets the container reader resolved; every time-stamp token by the
/// BouncyCastle Time-Stamp Protocol validator; every digest by an independent recomputation.
/// </para>
/// <para>
/// <strong>Why some artifacts are validated after a re-encoding.</strong> Two thirds of this corpus places the
/// <c>mimetype</c> entry somewhere other than the archive's first octet, which Annex A.1 forbids and this
/// library refuses at the archive layer. Refusing there says nothing about whether the ASiC CONTENT of those
/// artifacts is conformant, and the content is what the manifests, signatures, time assertions and Evidence
/// Records live in. <see cref="MovingTheMimetypeEntryFirstChangesNothingElseAndTheContentThenValidates"/>
/// therefore rewrites those archives with the entry moved to the front and nothing else altered — asserting
/// first, against the independent oracle's reading of the ORIGINAL octets, that every entry name and every
/// entry payload survived byte for byte — and then states the conclusion the content reaches. Every digest,
/// signature, token and Evidence Record in a container is computed over entry PAYLOADS, which is exactly what
/// the rewrite preserves and why the exercise means something.
/// </para>
/// </remarks>
[TestClass]
internal sealed class ReferenceArtifactAsicContainerTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The instant every container of this class is validated at; later than every artifact's own instants.</summary>
    private static DateTimeOffset ValidationTime { get; } = new(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The instant a re-encoded archive records for its entries; no obligation of either text rests on it.</summary>
    private static DateTimeOffset RewriteInstant { get; } = new(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);


    /// <summary>
    /// The census: every container artifact of the corpus is either read in full or refused by one of five
    /// named rules, and the counts are the recorded ones. A read status outside that set would be a rule this
    /// leg has never looked at.
    /// </summary>
    /// <remarks>
    /// The dominant refusal is Annex A.1's first rule — "'mimetype' shall be the first file in the ASiC
    /// container" — which 57 of the 85 artifacts break, every one of them by placing the entry last. That is a
    /// statement about this corpus's producers rather than about this library, and it is recorded here as a
    /// number so a later change to the rule cannot pass unnoticed.
    /// <see cref="MovingTheMimetypeEntryFirstChangesNothingElseAndTheContentThenValidates"/> then shows that
    /// the placement is all that is wrong with them.
    /// </remarks>
    [TestMethod]
    public void TheContainerCorpusIsReadOrRefusedExactlyAsRecorded()
    {
        string? directory = TryFindContainerCorpusDirectory();
        if(directory is null)
        {
            Assert.Inconclusive(MissingCloneMessage);

            return;
        }

        var census = new Dictionary<AsicZipReadStatus, int>();
        int total = 0;
        foreach(string file in EnumerateContainers(directory))
        {
            ++total;
            using AsicContainerReadResult read = AsicContainerReading.Read(File.ReadAllBytes(file), AsicZipReadLimits.Conformant, BaseMemoryPool.Shared);
            census[read.Status] = census.TryGetValue(read.Status, out int count) ? count + 1 : 1;
        }

        Assert.AreEqual(85, total, "The corpus carries 85 container artifacts under the five accepted extensions.");
        Assert.AreEqual(17, census.GetValueOrDefault(AsicZipReadStatus.Read), "17 artifacts are read in full.");
        Assert.AreEqual(57, census.GetValueOrDefault(AsicZipReadStatus.MimetypeNotFirstEntry), "57 place the 'mimetype' entry somewhere other than the archive's first octet (Annex A.1).");
        Assert.AreEqual(5, census.GetValueOrDefault(AsicZipReadStatus.ArchiveMalformed), "5 carry local file headers their central directory contradicts.");
        Assert.AreEqual(4, census.GetValueOrDefault(AsicZipReadStatus.Zip64Required), "4 declare the ZIP64 size sentinels in both headers.");
        Assert.AreEqual(1, census.GetValueOrDefault(AsicZipReadStatus.EntryNameRejected), "1 carries an entry name that is not UTF-8.");
        Assert.AreEqual(1, census.GetValueOrDefault(AsicZipReadStatus.NotZipArchive), "1 is not an archive at all.");
        Assert.HasCount(6, census, "No artifact reaches a status outside the six this leg has looked at.");
    }


    /// <summary>
    /// Every artifact the archive layer reads in full reaches the recorded conclusion: the container type of
    /// clause 4.1.2, the EN 319 162-2 profile, how many manifests, CAdES objects, time assertions and Evidence
    /// Records it carries, and what validating it concludes.
    /// </summary>
    /// <param name="artifact">The artifact's file name within the corpus.</param>
    /// <param name="shape">The container type clause 4.1.2 gives it.</param>
    /// <param name="profile">The EN 319 162-2 profile its protective objects state.</param>
    /// <param name="manifests">How many manifest files it carries.</param>
    /// <param name="signatures">How many CAdES objects it carries.</param>
    /// <param name="timeAssertions">How many time assertions it carries.</param>
    /// <param name="evidenceRecords">How many Evidence Records it carries.</param>
    /// <param name="conclusion">What <see cref="AsicContainerValidation.ValidateAsync"/> concludes when no signature validation inputs are supplied.</param>
    /// <remarks>
    /// No run of this class supplies <see cref="AsicContainerValidationContext.SignatureInputs"/>: these
    /// signatures and tokens chain to certification authorities no test world can carry, so their EN 319 102-1
    /// clause 5 conclusion would be a statement about the trust anchors rather than about the container. A
    /// container whose structure holds and whose CAdES objects or time assertions were therefore not evaluated
    /// concludes <see cref="AsicContainerValidationStatus.NotEvaluated"/>; one whose every protective object IS
    /// checkable without trust material — an Evidence Record, whose hash tree is a self-contained recomputation —
    /// concludes <see cref="AsicContainerValidationStatus.Valid"/>. A time assertion is NOT such an object: its
    /// message imprint binds the octets, and the token itself is validated by clause 5.4, which needs the inputs.
    /// The CAdES objects are verified cryptographically by
    /// <see cref="AThirdPartyDetachedCAdESObjectVerifiesOverTheOctetsTheContainerReaderResolved"/> and the tokens
    /// by <see cref="AContainerCarryingNoMimetypeEntryIsReadAndItsTimeAssertionBindsTheManifest"/>, both through
    /// the independent readers instead.
    /// </remarks>
    [TestMethod]
    [DataRow("dss1984.asics", AsicContainerShape.Simple, AsicContainerProfile.SimpleBaselineCAdES, 0, 1, 0, 0, AsicContainerValidationStatus.NotEvaluated)]
    [DataRow("removed-doc.asics", AsicContainerShape.Simple, AsicContainerProfile.SimpleBaselineCAdES, 0, 1, 0, 0, AsicContainerValidationStatus.NotEvaluated)]
    [DataRow("dss1984.asice", AsicContainerShape.Extended, AsicContainerProfile.ExtendedCAdES, 2, 1, 1, 0, AsicContainerValidationStatus.NotEvaluated)]
    [DataRow("emptyCertStore.asice", AsicContainerShape.Extended, AsicContainerProfile.ExtendedCAdES, 1, 1, 0, 0, AsicContainerValidationStatus.NotEvaluated)]
    [DataRow("cades-duplicate-orphan-revocation.asice", AsicContainerShape.Extended, AsicContainerProfile.ExtendedCAdES, 2, 1, 1, 0, AsicContainerValidationStatus.NotEvaluated)]
    [DataRow("cades-lta.sce", AsicContainerShape.Extended, AsicContainerProfile.ExtendedCAdES, 2, 1, 1, 0, AsicContainerValidationStatus.NotEvaluated)]
    [DataRow("cades-lta-alternative-naming.sce", AsicContainerShape.Extended, AsicContainerProfile.ExtendedCAdES, 2, 1, 1, 0, AsicContainerValidationStatus.NotEvaluated)]
    [DataRow("asice-level-lta-with-custom-manifest-namespace.sce", AsicContainerShape.Extended, AsicContainerProfile.ExtendedCAdES, 2, 1, 1, 0, AsicContainerValidationStatus.NotEvaluated)]
    [DataRow("cades-lt-two-sigs.sce", AsicContainerShape.Extended, AsicContainerProfile.ExtendedCAdES, 2, 2, 0, 0, AsicContainerValidationStatus.NotEvaluated)]
    [DataRow("tstNoMimeType.asice", AsicContainerShape.Extended, AsicContainerProfile.ExtendedTimeAssertion, 1, 0, 1, 0, AsicContainerValidationStatus.NotEvaluated)]
    [DataRow("er-asn1-full-renewal.asics", AsicContainerShape.Simple, AsicContainerProfile.SimpleTimeAssertion, 0, 0, 0, 1, AsicContainerValidationStatus.Valid)]
    [DataRow("er-asn1-tst-renewal.asics", AsicContainerShape.Simple, AsicContainerProfile.SimpleTimeAssertion, 0, 0, 0, 1, AsicContainerValidationStatus.Valid)]
    [DataRow("er-asn1-full-renewal-with-manifest.asics", AsicContainerShape.Extended, AsicContainerProfile.ExtendedTimeAssertion, 1, 0, 0, 1, AsicContainerValidationStatus.Valid)]
    public async Task AContainerOfTheCorpusReachesTheRecordedConclusion(
        string artifact,
        AsicContainerShape shape,
        AsicContainerProfile profile,
        int manifests,
        int signatures,
        int timeAssertions,
        int evidenceRecords,
        AsicContainerValidationStatus conclusion)
    {
        byte[]? octets = TryReadArtifact(artifact);
        if(octets is null)
        {
            return;
        }

        using(AsicContainerReadResult read = AsicContainerReading.Read(octets, AsicZipReadLimits.Conformant, BaseMemoryPool.Shared))
        {
            Assert.IsTrue(read.IsRead, $"'{artifact}' is one of the artifacts the archive layer reads ({read.Status}).");
            AsicContainerFacts facts = read.Facts!;
            Assert.AreEqual(shape, facts.Shape);
            Assert.AreEqual(profile, facts.Profile);
            Assert.HasCount(manifests, facts.Manifests);
            Assert.HasCount(signatures, facts.Signatures);
            Assert.HasCount(timeAssertions, facts.TimeAssertions);
            Assert.HasCount(evidenceRecords, facts.EvidenceRecords);
        }

        using AsicContainerValidationResult validation = await ValidateAsync(octets).ConfigureAwait(false);
        Assert.AreEqual(conclusion, validation.Status, StateReasons(validation));
        foreach(AsicManifestValidation manifest in validation.Manifests)
        {
            Assert.AreEqual(AsicContainerValidationStatus.Valid, manifest.Status, $"'{manifest.EntryName}': {manifest.FailureReason}");
            foreach(AsicDataObjectReferenceValidation reference in manifest.DataObjectReferences)
            {
                Assert.AreEqual(AsicDataObjectReferenceStatus.Matched, reference.Status, $"'{manifest.EntryName}' -> '{reference.Uri}'.");
            }
        }
    }


    /// <summary>
    /// The interop statement this whole leg exists for: a detached CAdES object another implementation produced
    /// verifies, under the independent CMS reader, over exactly the octets this library's container reader
    /// resolved as its detached content — and not over any other entry of the same container.
    /// </summary>
    /// <param name="artifact">The artifact's file name within the corpus.</param>
    /// <remarks>
    /// Clause 4.4.4.2 item 3 a) with Annex A.4.1 makes an ASiC-E CAdES object detached over the
    /// <c>ASiCManifest</c> file whose <c>SigReference</c> names it; clause 4.3.3.2 item 4 b) makes an ASiC-S one
    /// detached over the single root data file. Resolving the wrong one is the defect that a "sign the data"
    /// reading introduces, and it is invisible to any test that only asks the library what it thinks.
    /// <para>
    /// One read artifact of the corpus is deliberately NOT a row here: the one whose own name says its
    /// certificate store is empty. Its CMS object embeds no certificate at all, so the independent reader has
    /// nothing to verify the signer with — that is a statement about the artifact rather than about the
    /// detached content this library resolved, and asserting it here would say nothing about the resolution.
    /// </para>
    /// </remarks>
    [TestMethod]
    [DataRow("dss1984.asice")]
    [DataRow("cades-lta-alternative-naming.sce")]
    [DataRow("cades-duplicate-orphan-revocation.asice")]
    [DataRow("dss1984.asics")]
    public async Task AThirdPartyDetachedCAdESObjectVerifiesOverTheOctetsTheContainerReaderResolved(string artifact)
    {
        byte[]? octets = TryReadArtifact(artifact);
        if(octets is null)
        {
            return;
        }

        Dictionary<string, byte[]> payloads = EntryPayloads(octets);
        using AsicContainerValidationResult validation = await ValidateAsync(octets).ConfigureAwait(false);
        Assert.IsNotEmpty(validation.Signatures, "The artifact carries a CAdES object.");

        foreach(AsicSignatureValidation signature in validation.Signatures)
        {
            Assert.IsNotNull(signature.DetachedContentEntryName, $"'{signature.EntryName}' has its detached content resolved.");
            byte[] signatureOctets = payloads[signature.EntryName];
            byte[] detached = payloads[signature.DetachedContentEntryName!];

            Assert.IsTrue(
                VerifiesDetached(signatureOctets, detached),
                $"The independent CMS reader verifies '{signature.EntryName}' over '{signature.DetachedContentEntryName}'.");

            foreach((string name, byte[] other) in payloads)
            {
                if(string.Equals(name, signature.DetachedContentEntryName, StringComparison.Ordinal) || other.Length == 0)
                {
                    continue;
                }

                Assert.IsFalse(
                    VerifiesDetached(signatureOctets, other),
                    $"'{signature.EntryName}' does not verify over '{name}', so the resolution is a fact rather than a coincidence.");
            }
        }
    }


    /// <summary>
    /// The manifest binding reads by namespace and local name, not by the spelling a producer chose: an
    /// artifact whose <c>ASiCManifest</c> declares the Annex A.3 namespace under an unconventional prefix and
    /// declares the XML Signature namespace on the grandchild elements rather than on the root parses, and
    /// every digest it states matches.
    /// </summary>
    [TestMethod]
    public async Task AManifestWhoseNamespacePrefixIsNotTheConventionalOneIsRead()
    {
        const string Artifact = "asice-level-lta-with-custom-manifest-namespace.sce";
        byte[]? octets = TryReadArtifact(Artifact);
        if(octets is null)
        {
            return;
        }

        Dictionary<string, byte[]> payloads = EntryPayloads(octets);
        XDocument document = XDocument.Parse(Encoding.UTF8.GetString(payloads["META-INF/ASiCManifest.xml"]));
        Assert.AreEqual(AsicManifestXmlBinding.AsicNamespace, document.Root!.Name.NamespaceName, "The document is in the namespace Annex A.3 declares.");
        Assert.IsNotEmpty(document.Root.GetPrefixOfNamespace(document.Root.Name.Namespace) ?? string.Empty, "The namespace is bound to a prefix rather than being the default one.");
        Assert.AreNotEqual("asic", document.Root.GetPrefixOfNamespace(document.Root.Name.Namespace), "The prefix is not the one the specification's own examples print.");
        Assert.IsNull(
            document.Root.GetPrefixOfNamespace(XmlSignatureWellKnown.XmlSignatureNamespace),
            "The XML Signature namespace is not declared on the root at all — it is declared on the elements that use it.");

        using AsicContainerValidationResult validation = await ValidateAsync(octets).ConfigureAwait(false);
        Assert.AreEqual(AsicContainerValidationStatus.NotEvaluated, validation.Status, StateReasons(validation));
        Assert.HasCount(2, validation.Manifests);
        foreach(AsicManifestValidation manifest in validation.Manifests)
        {
            Assert.AreEqual(AsicContainerValidationStatus.Valid, manifest.Status, manifest.FailureReason);
            Assert.IsNotEmpty(manifest.DataObjectReferences);
        }
    }


    /// <summary>
    /// The three file-name patterns of clause 4.4.4.2 are patterns, not fixed names: an artifact naming its
    /// manifest, its CAdES object and its time assertion with a suffix no example of either text prints is
    /// classified by the pattern alone, and its Annex A.7 chain still walks.
    /// </summary>
    [TestMethod]
    public async Task TheWildcardNamingOfTheManifestAndItsProtectiveObjectIsRecognisedFromThePatternAlone()
    {
        const string Artifact = "cades-lta-alternative-naming.sce";
        byte[]? octets = TryReadArtifact(Artifact);
        if(octets is null)
        {
            return;
        }

        using AsicContainerReadResult read = AsicContainerReading.Read(octets, AsicZipReadLimits.Conformant, BaseMemoryPool.Shared);
        Assert.IsTrue(read.IsRead, read.Status.ToString());

        AsicContainerFacts facts = read.Facts!;
        AsicManifestFile signatureManifest = facts.Manifests.Single(manifest => manifest.Role == AsicManifestRole.Signature);
        AsicManifestFile archiveManifest = facts.Manifests.Single(manifest => manifest.Role == AsicManifestRole.Archive);

        Assert.AreNotEqual("META-INF/ASiCManifest.xml", signatureManifest.Entry.Name, "The signature manifest's name carries a suffix of the producer's own choosing.");
        Assert.EndsWith(".p7s", facts.Signatures.Single().Name, StringComparison.Ordinal);
        Assert.AreNotEqual("META-INF/signature.p7s", facts.Signatures.Single().Name);
        Assert.AreNotEqual("META-INF/timestamp.tst", facts.TimeAssertions.Single().Name);
        Assert.AreEqual(AsicManifestNaming.FixedArchiveManifestEntryName, archiveManifest.Entry.Name, "Annex A.7 item 1 c a) fixes the archive manifest's own name, and this producer used it.");

        using AsicContainerValidationResult validation = await ValidateAsync(octets).ConfigureAwait(false);
        Assert.HasCount(1, validation.ArchiveManifestChain);
        Assert.AreEqual(AsicManifestNaming.FixedArchiveManifestEntryName, validation.ArchiveManifestChain[0].EntryName);
        Assert.AreEqual(facts.TimeAssertions.Single().Name, validation.ArchiveManifestChain[0].TimestampEntryName);
        Assert.IsNull(validation.ArchiveManifestChain[0].PreviousEntryName, "A chain of one link points back at nothing.");
    }


    /// <summary>
    /// Clause 4.4.4.2 item 1 makes the <c>mimetype</c> entry a "may": an artifact carrying none is read, reports
    /// no media type and no Annex A.1 magic at offset 38, and its time assertion is resolved to the manifest it
    /// applies to and its message imprint recomputed against it — checked here against an independent
    /// recomputation, with the token itself accepted by the independent Time-Stamp Protocol validator.
    /// </summary>
    /// <remarks>
    /// This run supplies no signature validation inputs (see the class remark), so the shipped validation reports
    /// the token as <see cref="AsicContainerValidationStatus.NotEvaluated"/>: the imprint recomputation states
    /// which octets the token binds, and the clause 5.4 building block that would state whether the authority is
    /// trusted did not run. The interop statement this test carries is therefore made by the independent
    /// validator, and the shipped conclusion asserted here is that the imprint bound and nothing further was
    /// claimed.
    /// </remarks>
    [TestMethod]
    public async Task AContainerCarryingNoMimetypeEntryIsReadAndItsTimeAssertionBindsTheManifest()
    {
        const string Artifact = "tstNoMimeType.asice";
        byte[]? octets = TryReadArtifact(Artifact);
        if(octets is null)
        {
            return;
        }

        using(AsicContainerReadResult read = AsicContainerReading.Read(octets, AsicZipReadLimits.Conformant, BaseMemoryPool.Shared))
        {
            Assert.IsTrue(read.IsRead, read.Status.ToString());
            Assert.IsNull(read.Facts!.MediaType, "The container states no media type because it carries no 'mimetype' entry.");
            Assert.IsFalse(read.Facts.MediaTypeReadableAtOffset38, "Annex A.1's NOTE cannot recognise a media type that is not there.");
            Assert.IsNull(AsicZipStructureOracle.MediaTypeAtOffset38(octets), "The independent reader agrees, reading the octets itself.");
        }

        using AsicContainerValidationResult validation = await ValidateAsync(octets).ConfigureAwait(false);
        Assert.AreEqual(AsicContainerValidationStatus.NotEvaluated, validation.Status, StateReasons(validation));

        AsicTimeAssertionValidation assertion = validation.TimeAssertions.Single();
        Assert.AreEqual(AsicContainerValidationStatus.NotEvaluated, assertion.Status, assertion.FailureReason);
        Assert.IsNull(assertion.TokenValidation, "No clause 5.4 run took place, because this run supplied nothing to validate a token against.");
        Assert.IsEmpty(validation.ProtectedObjects, "An unevaluated token proves nothing, so nothing is reported as protected at the instant it asserts.");
        Assert.IsNotNull(assertion.ProtectedEntryName);

        Dictionary<string, byte[]> payloads = EntryPayloads(octets);
        Assert.IsTrue(VerifiesUnderAnyEmbeddedCertificate(payloads[assertion.EntryName]), "The independent validator accepts the token.");
        byte[] imprint = ImprintOf(payloads[assertion.EntryName]);
        byte[] recomputed = EvidenceRecordOracle.Hash(payloads[assertion.ProtectedEntryName!], PkiDigestAlgorithm.Sha256);
        Assert.IsTrue(imprint.AsSpan().SequenceEqual(recomputed), "The token binds the digest of the manifest as the container stores it.");
    }


    /// <summary>
    /// Each non-conformant artifact of the corpus is refused, and the reason reported is the one that rule
    /// carries rather than a generic failure. An artifact refused at the archive layer never reaches the
    /// content rules at all, which is what <paramref name="readStatus"/> and <paramref name="conclusion"/>
    /// state jointly.
    /// </summary>
    /// <param name="artifact">The artifact's file name within the corpus.</param>
    /// <param name="readStatus">What the archive layer concluded.</param>
    /// <param name="conclusion">What validating the container concluded.</param>
    /// <param name="reason">A fragment the reported reason has to carry, or the empty string when the refusal is at the archive layer and states no per-object reason.</param>
    [TestMethod]
    [DataRow("onefile-ok.asice", AsicZipReadStatus.MimetypeNotFirstEntry, AsicContainerValidationStatus.ContainerNotRead, "")]
    [DataRow("cades-lt-with-er.sce", AsicZipReadStatus.MimetypeNotFirstEntry, AsicContainerValidationStatus.ContainerNotRead, "")]
    [DataRow("cp852encoded_signature.asice", AsicZipReadStatus.EntryNameRejected, AsicContainerValidationStatus.ContainerNotRead, "")]
    [DataRow("malformed-container.asics", AsicZipReadStatus.NotZipArchive, AsicContainerValidationStatus.ContainerNotRead, "")]
    [DataRow("er-asn1-chain-renewal.asice", AsicZipReadStatus.Zip64Required, AsicContainerValidationStatus.ContainerNotRead, "")]
    [DataRow("er-asn1-tst-renewal.asice", AsicZipReadStatus.ArchiveMalformed, AsicContainerValidationStatus.ContainerNotRead, "")]
    [DataRow("removed-doc.asice", AsicZipReadStatus.Read, AsicContainerValidationStatus.ReferencedObjectMissing, "which the container does not carry")]
    [DataRow("nonConformantManifest.asice", AsicZipReadStatus.Read, AsicContainerValidationStatus.ManifestParseFailed, "DataObjectReference")]
    [DataRow("er-asn1-full-renewal-with-invalid-manifest.asics", AsicZipReadStatus.Read, AsicContainerValidationStatus.DigestMismatch, "clause 4.4.4.2 item d")]
    [DataRow("tstWithEmptyCertSource.asice", AsicZipReadStatus.Read, AsicContainerValidationStatus.TimeAssertionNotValid, "TSTInfo")]
    public async Task ANonConformantContainerIsRefusedWithItsOwnReason(
        string artifact,
        AsicZipReadStatus readStatus,
        AsicContainerValidationStatus conclusion,
        string reason)
    {
        byte[]? octets = TryReadArtifact(artifact);
        if(octets is null)
        {
            return;
        }

        using(AsicContainerReadResult read = AsicContainerReading.Read(octets, AsicZipReadLimits.Conformant, BaseMemoryPool.Shared))
        {
            Assert.AreEqual(readStatus, read.Status);
        }

        using AsicContainerValidationResult validation = await ValidateAsync(octets).ConfigureAwait(false);
        Assert.AreEqual(conclusion, validation.Status, StateReasons(validation));
        if(conclusion == AsicContainerValidationStatus.ContainerNotRead)
        {
            Assert.AreEqual(readStatus, validation.ReadStatus, "The container's conclusion carries the archive layer's own status.");
            Assert.IsEmpty(validation.Manifests, "Nothing of the content was looked at.");

            return;
        }

        Assert.IsTrue(
            StateReasons(validation).Contains(reason, StringComparison.Ordinal),
            $"The reported reason states why: {StateReasons(validation)}");
    }


    /// <summary>
    /// The 62 artifacts Annex A.1 refuses are refused for the PLACEMENT of one entry and for nothing else:
    /// rewritten with the <c>mimetype</c> entry moved to the archive's first octet and every other entry
    /// carried across byte for byte, their content reaches the conclusion recorded here.
    /// </summary>
    /// <param name="artifact">The artifact's file name within the corpus.</param>
    /// <param name="conclusion">What validating the rewritten container concludes.</param>
    /// <param name="reason">A fragment the reported reason has to carry, or the empty string when there is no failure.</param>
    /// <remarks>
    /// The rewrite is performed through <see cref="AsicZipStructureOracle"/> — the independent reader — and the
    /// entry names and payloads it recovered are asserted to be exactly what the rewritten archive carries, so
    /// nothing but the ZIP-level ordering can have changed. This is what separates "the archive's encoding is
    /// wrong" from "the ASiC content is wrong", and the answer for these artifacts is the first.
    /// </remarks>
    [TestMethod]
    [DataRow("onefile-ok.asice", AsicContainerValidationStatus.NotEvaluated, "")]
    [DataRow("multifiles-ok.asice", AsicContainerValidationStatus.NotEvaluated, "")]
    [DataRow("tst-with-asn1-er.sce", AsicContainerValidationStatus.NotEvaluated, "")]
    [DataRow("tst-with-two-diff-ers.sce", AsicContainerValidationStatus.NotEvaluated, "")]
    [DataRow("er-asn1-no-hashtree.scs", AsicContainerValidationStatus.Valid, "")]
    [DataRow("er-multi-files.asice", AsicContainerValidationStatus.Valid, "")]
    [DataRow("cades-lt-with-er.sce", AsicContainerValidationStatus.NotEvaluated, "")]
    [DataRow("cades-lt-with-er-multi-files.sce", AsicContainerValidationStatus.NotEvaluated, "")]
    [DataRow("cades-lt-with-er-renewed.sce", AsicContainerValidationStatus.NotEvaluated, "")]
    [DataRow("cades-lt-with-er-chain-renewed.sce", AsicContainerValidationStatus.NotEvaluated, "")]
    [DataRow("cades-lt-with-er-chain-renewed-invalid-ref.sce", AsicContainerValidationStatus.EvidenceRecordNotVerified, "DataObjectNotCovered")]
    [DataRow("cades-lt-with-er-covers-more-files.sce", AsicContainerValidationStatus.EvidenceRecordNotVerified, "DataObjectGroupNotCoveredExclusively")]
    [DataRow("er-asn1-incorrect-hash.asice", AsicContainerValidationStatus.EvidenceRecordNotVerified, "ChainAlgorithmInconsistent")]
    [DataRow("er-one-file.asics", AsicContainerValidationStatus.EvidenceRecordNotVerified, "DataObjectGroupNotCoveredExclusively")]
    [DataRow("er-asn1-no-hashtree-multiple-files-invalid.scs", AsicContainerValidationStatus.EvidenceRecordNotVerified, "is not stated")]
    [DataRow("er-no-hashtree-xml-with-wrong-manifest-sig-ref.scs", AsicContainerValidationStatus.ReferencedObjectMissing, "which the container does not carry")]
    [DataRow("er-no-hashtree-xml-manifest-canonicalized.sce", AsicContainerValidationStatus.DigestMismatch, "clause 4.4.4.2 item d")]
    public async Task MovingTheMimetypeEntryFirstChangesNothingElseAndTheContentThenValidates(
        string artifact,
        AsicContainerValidationStatus conclusion,
        string reason)
    {
        byte[]? octets = TryReadArtifact(artifact);
        if(octets is null)
        {
            return;
        }

        using(AsicContainerReadResult refused = AsicContainerReading.Read(octets, AsicZipReadLimits.Conformant, BaseMemoryPool.Shared))
        {
            Assert.AreEqual(AsicZipReadStatus.MimetypeNotFirstEntry, refused.Status, "The artifact is one Annex A.1's first rule refuses.");
        }

        Dictionary<string, byte[]> original = EntryPayloads(octets);
        using PooledMemory rewritten = RewriteWithMimetypeFirst(octets);

        using(AsicZipReadResult reread = AsicZipReading.Read(rewritten.AsReadOnlyMemory(), AsicZipReadLimits.Conformant, BaseMemoryPool.Shared))
        {
            Assert.IsTrue(reread.IsRead, $"The rewritten archive reads ({reread.Status}).");
            foreach(AsicZipEntry entry in reread.Container!.Entries)
            {
                if(AsicWellKnown.IsMimetypeEntryName(entry.Name))
                {
                    continue;
                }

                Assert.IsTrue(original.TryGetValue(entry.Name, out byte[]? before), $"'{entry.Name}' is an entry the original archive carried.");
                Assert.IsTrue(entry.Content.AsReadOnlySpan().SequenceEqual(before), $"'{entry.Name}' survived the rewrite octet for octet.");
            }
        }

        using AsicContainerValidationResult validation = await ValidateAsync(rewritten.AsReadOnlyMemory()).ConfigureAwait(false);
        Assert.AreEqual(conclusion, validation.Status, StateReasons(validation));
        if(reason.Length != 0)
        {
            Assert.IsTrue(
                StateReasons(validation).Contains(reason, StringComparison.Ordinal),
                $"The reported reason states why: {StateReasons(validation)}");
        }
    }


    /// <summary>
    /// The dispatch rule of clause 4.4.4.2 item 4 on a third party's own container: one archive carries an
    /// Evidence Record in each of the two forms, each named by its own <c>ASiCEvidenceRecordManifest</c>, and
    /// each is verified through the surface its file name dispatches to — the binary one through the RFC 4998
    /// path, the XML one through the RFC 6283 path and its canonicalization seam.
    /// </summary>
    [TestMethod]
    public async Task BothFormsOfEvidenceRecordInOneThirdPartyContainerAreVerifiedThroughTheirOwnSurface()
    {
        const string Artifact = "tst-with-two-diff-ers.sce";
        byte[]? octets = TryReadArtifact(Artifact);
        if(octets is null)
        {
            return;
        }

        using PooledMemory rewritten = RewriteWithMimetypeFirst(octets);
        using AsicContainerValidationResult validation = await ValidateAsync(rewritten.AsReadOnlyMemory()).ConfigureAwait(false);
        Assert.AreEqual(
            AsicContainerValidationStatus.NotEvaluated,
            validation.Status,
            $"The container also carries a time assertion this run supplied nothing to validate: {StateReasons(validation)}");
        Assert.AreEqual(
            AsicContainerValidationStatus.NotEvaluated,
            validation.TimeAssertions.Single().Status,
            "Which is the only thing the container-level conclusion is withheld for — both Evidence Records below are Valid.");
        Assert.HasCount(2, validation.EvidenceRecords);

        AsicEvidenceRecordValidation binary = validation.EvidenceRecords.Single(record => record.Form == AsicEvidenceRecordForm.Binary);
        AsicEvidenceRecordValidation xml = validation.EvidenceRecords.Single(record => record.Form == AsicEvidenceRecordForm.Xml);

        Assert.AreEqual(AsicContainerValidationStatus.Valid, binary.Status, binary.FailureReason);
        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, binary.VerificationStatus, "The binary form goes through the RFC 4998 verification.");
        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.NotVerified, binary.XmlVerificationStatus, "The RFC 6283 surface was never asked about it.");

        Assert.AreEqual(AsicContainerValidationStatus.Valid, xml.Status, xml.FailureReason);
        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, xml.XmlVerificationStatus, "The XML form goes through the RFC 6283 verification.");
        Assert.AreEqual(EvidenceRecordVerificationStatus.NotVerified, xml.VerificationStatus, "The RFC 4998 surface was never asked about it.");

        Assert.AreNotEqual(binary.ManifestEntryName, xml.ManifestEntryName, "Each record is named by its own manifest.");
        Assert.IsTrue(binary.ProtectedEntryNames.SequenceEqual(xml.ProtectedEntryNames), "Both records protect the same file object — the time assertion.");
        Assert.IsNotEmpty(binary.ProtectedEntryNames);
    }


    /// <summary>
    /// Appendix A step 5.b of IETF RFC 6283 states the membership check in BOTH directions, and contract R-3
    /// ships the strict reading. A third party's own artifact — one this corpus names for covering more files
    /// than its manifest states — is refused by exactly that second direction, which is the evidence the
    /// strict reading is the interoperable one rather than merely the cautious one.
    /// </summary>
    [TestMethod]
    public async Task AThirdPartyRecordCoveringMoreThanItsManifestNamesIsRefusedByTheSecondMembershipDirection()
    {
        const string Artifact = "cades-lt-with-er-covers-more-files.sce";
        byte[]? octets = TryReadArtifact(Artifact);
        if(octets is null)
        {
            return;
        }

        using PooledMemory rewritten = RewriteWithMimetypeFirst(octets);
        using AsicContainerValidationResult strict = await ValidateAsync(rewritten.AsReadOnlyMemory()).ConfigureAwait(false);

        Assert.AreEqual(AsicContainerValidationStatus.EvidenceRecordNotVerified, strict.Status, StateReasons(strict));
        AsicEvidenceRecordValidation record = strict.EvidenceRecords.Single();
        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.DataObjectGroupNotCoveredExclusively, record.XmlVerificationStatus);
        Assert.IsEmpty(record.ProtectedEntryNames, "A record that proves nothing the container states protects nothing in the report.");

        using AsicContainerValidationResult loose = await ValidateAsync(rewritten.AsReadOnlyMemory(), requireGroupExclusivity: false).ConfigureAwait(false);
        Assert.AreEqual(AsicContainerValidationStatus.NotEvaluated, loose.Status, StateReasons(loose));
        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, loose.EvidenceRecords.Single().XmlVerificationStatus,
            "Under the clause 3.3 reading the caller has to state, the same record verifies — which is what makes the default a choice and not an accident.");
    }


    /// <summary>
    /// The corpus settles a reading this wave had to choose: whether the digest of an XML file object inside a
    /// container is taken over the octets the container stores or over that document's canonical form. It
    /// carries the SAME data object under both readings, in two artifacts whose manifests differ in nothing but
    /// that digest, and the wave takes the octets as stored (EN 319 162-1 clause 4.4.4.2 item d).
    /// </summary>
    /// <remarks>
    /// The Evidence Record beside them takes the canonical reading, which is clause 4.1.2 of IETF RFC 6283
    /// applied to a container entry — a reading this wave declines for container entries, so those records are
    /// refused. Both halves are asserted here so the divergence is a recorded fact rather than a surprise.
    /// </remarks>
    [TestMethod]
    public async Task TheCorpusCarriesBothReadingsOfAnXmlFileObjectsDigestAndTheWaveTakesTheOctetsAsStored()
    {
        byte[]? stored = TryReadArtifact("er-no-hashtree-xml-with-manifest.scs");
        byte[]? canonical = TryReadArtifact("er-no-hashtree-xml-manifest-canonicalized.sce");
        if(stored is null || canonical is null)
        {
            return;
        }

        Dictionary<string, byte[]> storedEntries = EntryPayloads(stored);
        Dictionary<string, byte[]> canonicalEntries = EntryPayloads(canonical);

        string dataObjectName = storedEntries.Keys.Single(name => name.EndsWith(".xml", StringComparison.Ordinal) && !AsicWellKnown.IsMetaInfEntryName(name));
        Assert.IsTrue(
            storedEntries[dataObjectName].AsSpan().SequenceEqual(canonicalEntries[dataObjectName]),
            "The two artifacts carry the very same data object, so only the stated digest can differ.");

        byte[] digestOfStoredOctets = EvidenceRecordOracle.Hash(storedEntries[dataObjectName], PkiDigestAlgorithm.Sha256);
        string storedManifestName = storedEntries.Keys.Single(name => AsicManifestNaming.RoleFromEntryName(name) == AsicManifestRole.EvidenceRecord);
        string canonicalManifestName = canonicalEntries.Keys.Single(name => AsicManifestNaming.RoleFromEntryName(name) == AsicManifestRole.EvidenceRecord);

        Assert.IsTrue(
            StatedDigest(storedEntries[storedManifestName], dataObjectName).AsSpan().SequenceEqual(digestOfStoredOctets),
            "One artifact's manifest states the digest of the entry as the container stores it.");
        Assert.IsFalse(
            StatedDigest(canonicalEntries[canonicalManifestName], dataObjectName).AsSpan().SequenceEqual(digestOfStoredOctets),
            "The other artifact's manifest — whose own name says so — states a different digest of the same octets.");

        using PooledMemory rewrittenStored = RewriteWithMimetypeFirst(stored);
        using AsicContainerValidationResult storedConclusion = await ValidateAsync(rewrittenStored.AsReadOnlyMemory()).ConfigureAwait(false);
        Assert.AreEqual(
            AsicDataObjectReferenceStatus.Matched,
            storedConclusion.Manifests.Single().DataObjectReferences.Single().Status,
            "The reading this wave takes is the one clause 4.4.4.2 item d states: the content of the file object.");

        using PooledMemory rewrittenCanonical = RewriteWithMimetypeFirst(canonical);
        using AsicContainerValidationResult canonicalConclusion = await ValidateAsync(rewrittenCanonical.AsReadOnlyMemory()).ConfigureAwait(false);
        Assert.AreEqual(
            AsicDataObjectReferenceStatus.DigestMismatch,
            canonicalConclusion.Manifests.Single().DataObjectReferences.Single().Status,
            "The other reading is refused unconditionally, whatever else the container says.");

        Assert.AreEqual(
            XmlEvidenceRecordVerificationStatus.RootMismatch,
            storedConclusion.EvidenceRecords.Single().XmlVerificationStatus,
            "The Evidence Record beside them takes the canonical reading of the same object, which this wave declines for container entries — recorded, not silently skipped.");
    }


    /// <summary>
    /// States the validation context every test of this class shares: the manifest seam, both Evidence Record
    /// seams, and no signature validation inputs.
    /// </summary>
    /// <param name="container">The container's octets.</param>
    /// <param name="requireGroupExclusivity">Whether Appendix A step 5.b's second direction is performed for XML-form records.</param>
    /// <returns>The conclusion. The caller disposes it.</returns>
    private async Task<AsicContainerValidationResult> ValidateAsync(ReadOnlyMemory<byte> container, bool requireGroupExclusivity = true)
    {
        return await AsicContainerValidation.ValidateAsync(
            new AsicContainerValidationContext
            {
                Container = container,
                CurrentTime = ValidationTime,
                ParseManifest = AsicManifestXmlBinding.ParseAsync,
                ParseXmlEvidenceRecord = XmlEvidenceRecordXmlBinding.ParseAsync,
                CanonicalizeXml = XmlEvidenceRecordXmlBinding.CanonicalizeAsync,
                RequireXmlEvidenceRecordGroupExclusivity = requireGroupExclusivity
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Rewrites an archive with the <c>mimetype</c> entry as its first entry and every other entry carried
    /// across unchanged, reading the original through the independent oracle rather than through the reader
    /// that refused it.
    /// </summary>
    /// <param name="container">The original archive's octets.</param>
    /// <returns>The rewritten archive. The caller owns and disposes it.</returns>
    private static PooledMemory RewriteWithMimetypeFirst(byte[] container)
    {
        OracleZipArchive archive = AsicZipStructureOracle.Parse(container);
        string? mediaType = null;
        var entries = new List<AsicZipEntrySource>(archive.LocalHeaders.Count);
        foreach(OracleZipEntry header in archive.LocalHeaders)
        {
            OracleZipEntry record = archive.CentralDirectory.Single(candidate => string.Equals(candidate.Name, header.Name, StringComparison.Ordinal));
            byte[] content = AsicZipStructureOracle.ReadEntryContent(container, header, record);
            if(AsicWellKnown.IsMimetypeEntryName(header.Name))
            {
                mediaType = Encoding.UTF8.GetString(content);

                continue;
            }

            if(header.Name.EndsWith('/'))
            {
                //A folder entry carries no octets and no obligation of either text rests on it; the container
                //layer surfaces one when it meets one and this rewrite has nothing to preserve about it.
                continue;
            }

            entries.Add(new AsicZipEntrySource { Name = header.Name, Content = content });
        }

        Assert.IsNotNull(mediaType, "The rewrite exists to move a 'mimetype' entry, so there has to be one.");

        return AsicZipAuthoring.Write(
            new AsicZipAuthoringContext { MediaType = mediaType, Entries = entries, LastModified = RewriteInstant },
            BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Reads every entry's octets out of an archive through the independent oracle, taking the sizes from the
    /// central directory for the entries this corpus streams with a data descriptor.
    /// </summary>
    /// <param name="container">The archive's octets.</param>
    /// <returns>The payloads, keyed by entry name.</returns>
    private static Dictionary<string, byte[]> EntryPayloads(byte[] container)
    {
        OracleZipArchive archive = AsicZipStructureOracle.Parse(container);
        var payloads = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach(OracleZipEntry header in archive.LocalHeaders)
        {
            OracleZipEntry record = archive.CentralDirectory.Single(candidate => string.Equals(candidate.Name, header.Name, StringComparison.Ordinal));
            payloads.Add(header.Name, AsicZipStructureOracle.ReadEntryContent(container, header, record));
        }

        return payloads;
    }


    /// <summary>
    /// Reads the <c>ds:DigestValue</c> a manifest states for one referenced entry, with an independent XML
    /// reader rather than through the seam under test.
    /// </summary>
    /// <param name="manifest">The manifest document's octets.</param>
    /// <param name="uri">The <c>URI</c> attribute to look for.</param>
    /// <returns>The digest octets the manifest states.</returns>
    private static byte[] StatedDigest(byte[] manifest, string uri)
    {
        XDocument document = XDocument.Parse(Encoding.UTF8.GetString(manifest));
        XNamespace asic = AsicManifestXmlBinding.AsicNamespace;
        XNamespace ds = XmlSignatureWellKnown.XmlSignatureNamespace;
        XElement reference = document.Root!.Elements(asic + "DataObjectReference")
            .Single(element => string.Equals(element.Attribute("URI")!.Value, uri, StringComparison.Ordinal));

        return Convert.FromBase64String(reference.Element(ds + XmlSignatureWellKnown.DigestValueElementName)!.Value);
    }


    /// <summary>
    /// Collects every reason a validation reported into one line, so an assertion that fails says which object
    /// disagreed rather than only that something did.
    /// </summary>
    /// <param name="validation">The conclusion.</param>
    /// <returns>The reasons, one after another.</returns>
    private static string StateReasons(AsicContainerValidationResult validation)
    {
        var reasons = new StringBuilder();
        reasons.Append(CultureInfo.InvariantCulture, $"status={validation.Status} readStatus={validation.ReadStatus}");
        foreach(AsicManifestValidation manifest in validation.Manifests)
        {
            reasons.Append(CultureInfo.InvariantCulture, $"; manifest '{manifest.EntryName}' {manifest.Status} {manifest.FailureReason}");
        }

        foreach(AsicSignatureValidation signature in validation.Signatures)
        {
            reasons.Append(CultureInfo.InvariantCulture, $"; signature '{signature.EntryName}' {signature.Status} {signature.FailureReason}");
        }

        foreach(AsicTimeAssertionValidation assertion in validation.TimeAssertions)
        {
            reasons.Append(CultureInfo.InvariantCulture, $"; time assertion '{assertion.EntryName}' {assertion.Status} {assertion.FailureReason}");
        }

        foreach(AsicEvidenceRecordValidation record in validation.EvidenceRecords)
        {
            reasons.Append(CultureInfo.InvariantCulture, $"; evidence record '{record.EntryName}' {record.Status} {record.VerificationStatus}/{record.XmlVerificationStatus} {record.FailureReason}");
        }

        return reasons.ToString();
    }


    /// <summary>
    /// Verifies a detached CMS signature over the supplied content with the independent BouncyCastle reader,
    /// which never sees this library's objects.
    /// </summary>
    /// <param name="signature">The DER-encoded CMS <c>SignedData</c>.</param>
    /// <param name="content">The detached content the signature is claimed to cover.</param>
    /// <returns><see langword="true"/> when a signer of the object verifies over that content under a certificate the object itself embeds.</returns>
    private static bool VerifiesDetached(byte[] signature, byte[] content)
    {
        BcCmsSignedData signedData;
        try
        {
            signedData = new BcCmsSignedData(new CmsProcessableByteArray(content), signature);
        }
        catch(CmsException)
        {
            return false;
        }

        foreach(SignerInformation signer in signedData.GetSignerInfos().GetSigners())
        {
            foreach(BcX509Certificate candidate in signedData.GetCertificates().EnumerateMatches(signer.SignerID))
            {
                try
                {
                    if(signer.Verify(candidate))
                    {
                        return true;
                    }
                }
                catch(CmsException)
                {
                    //This embedded certificate is not the signer's; try the next one the object carries.
                }
            }
        }

        return false;
    }


    /// <summary>
    /// Checks a time-stamp token against the independent BouncyCastle Time-Stamp Protocol validator, trying
    /// each certificate the token itself embeds.
    /// </summary>
    /// <param name="token">The DER-encoded RFC 3161 <c>TimeStampToken</c>.</param>
    /// <returns><see langword="true"/> when the independent validator accepts the token.</returns>
    private static bool VerifiesUnderAnyEmbeddedCertificate(byte[] token)
    {
        var parsed = new TimeStampToken(new BcCmsSignedData(token));
        foreach(BcX509Certificate candidate in parsed.GetCertificates().EnumerateMatches(null))
        {
            try
            {
                parsed.Validate(candidate);

                return true;
            }
            catch(TspException)
            {
                //This embedded certificate is not the authority's own; try the next.
            }
        }

        return false;
    }


    /// <summary>
    /// Reads the <c>messageImprint</c> a time-stamp token binds, through the independent BouncyCastle reader.
    /// </summary>
    /// <param name="token">The DER-encoded RFC 3161 <c>TimeStampToken</c>.</param>
    /// <returns>The imprint octets.</returns>
    private static byte[] ImprintOf(byte[] token) =>
        new TimeStampToken(new BcCmsSignedData(token)).TimeStampInfo.TstInfo.MessageImprint.GetHashedMessage();


    /// <summary>
    /// Reads one container artifact, or reports <see cref="Assert.Inconclusive(string)"/> and returns
    /// <see langword="null"/> when the local reference-artifact clone, or the file within it, is not present.
    /// </summary>
    /// <param name="artifact">The artifact's file name.</param>
    /// <returns>The artifact's octets, or <see langword="null"/>.</returns>
    private static byte[]? TryReadArtifact(string artifact)
    {
        string? directory = TryFindContainerCorpusDirectory();
        if(directory is null)
        {
            Assert.Inconclusive(MissingCloneMessage);

            return null;
        }

        string? path = Directory.EnumerateFiles(directory, artifact, SearchOption.AllDirectories)
            .OrderBy(candidate => candidate, StringComparer.Ordinal)
            .FirstOrDefault();
        if(path is null)
        {
            Assert.Inconclusive($"The artifact '{artifact}' is not present in the local reference-artifact container corpus.");

            return null;
        }

        return File.ReadAllBytes(path);
    }


    /// <summary>
    /// Enumerates every container artifact of a corpus directory, under the five extensions clause 4.3.3.1 and
    /// clause 4.4.4.1 admit.
    /// </summary>
    /// <param name="directory">The corpus directory.</param>
    /// <returns>The artifacts' full paths, in ordinal order.</returns>
    private static IEnumerable<string> EnumerateContainers(string directory) =>
        Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
            .Where(file => AsicWellKnown.IsAcceptedContainerExtension(Path.GetExtension(file)))
            .OrderBy(file => file, StringComparer.Ordinal);


    /// <summary>
    /// Resolves the CAdES-flavoured container corpus by LAYOUT and by CONTENT: a
    /// <c>src/test/resources/validation</c> tree whose container artifacts carry a CAdES object under
    /// <c>META-INF</c>, and of those the tree carrying the most.
    /// </summary>
    /// <returns>The directory's full path, or <see langword="null"/> when it is not present.</returns>
    /// <remarks>
    /// No directory name of the clone is spelled here. The XAdES-flavoured trees of the same clone have the
    /// same layout and are told apart by what their containers hold — clause 4.4.4.2 item 3 a) names the CAdES
    /// container's protective object <c>META-INF/*signature*.p7s</c>, and the XAdES one's is an XML document —
    /// so the discriminator is the specification's own, not a path.
    /// </remarks>
    private static string? TryFindContainerCorpusDirectory()
    {
        string? referenceMaterial = TryFindReferenceMaterialDirectory();
        if(referenceMaterial is null)
        {
            return null;
        }

        string tail = Path.Combine("src", "test", "resources", "validation");
        string? best = null;
        int bestCount = 0;
        foreach(string candidate in Directory.EnumerateDirectories(referenceMaterial, "validation", SearchOption.AllDirectories)
            .Where(directory => directory.EndsWith(tail, StringComparison.OrdinalIgnoreCase))
            .OrderBy(directory => directory, StringComparer.Ordinal))
        {
            int count = 0;
            foreach(string file in EnumerateContainers(candidate))
            {
                if(CarriesCAdESObject(file))
                {
                    ++count;
                }
            }

            if(count > bestCount)
            {
                best = candidate;
                bestCount = count;
            }
        }

        return best;
    }


    /// <summary>
    /// States whether an archive's central directory names a CAdES object where clause 4.4.4.2 item 3 a) and
    /// clause 4.3.3.2 item 4 b) put one.
    /// </summary>
    /// <param name="file">The archive's full path.</param>
    /// <returns><see langword="true"/> when it does.</returns>
    private static bool CarriesCAdESObject(string file)
    {
        OracleZipArchive archive;
        try
        {
            archive = AsicZipStructureOracle.Parse(File.ReadAllBytes(file));
        }
        catch(InvalidOperationException)
        {
            //Octets that are not an archive cannot state which flavour of container they are.
            return false;
        }

        foreach(OracleZipEntry record in archive.CentralDirectory)
        {
            if(AsicManifestNaming.IsSignatureEntryName(record.Name))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Walks up from the test assembly's output directory to the repository root and resolves the local
    /// reference-artifact clone's own root relative to it.
    /// </summary>
    /// <returns>The directory's full path, or <see langword="null"/> when it is not present.</returns>
    private static string? TryFindReferenceMaterialDirectory()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while(current is not null && !File.Exists(Path.Combine(current.FullName, "Verifiable.slnx")))
        {
            current = current.Parent;
        }

        if(current is null)
        {
            return null;
        }

        string referenceMaterial = Path.Combine(current.FullName, "tempdocs", "etsi-ades-reference");

        return Directory.Exists(referenceMaterial) ? referenceMaterial : null;
    }


    /// <summary>What every test reports when the optional local reference-artifact clone is not present.</summary>
    private static string MissingCloneMessage =>
        "The local reference-artifact clone (tempdocs/etsi-ades-reference) was not found; the container corpus is optional local reference material, not a repository asset.";
}
