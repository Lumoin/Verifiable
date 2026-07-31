using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.Extensions.Time.Testing;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;
using BcCmsSignedData = Org.BouncyCastle.Cms.CmsSignedData;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="AsicContainerAugmentation"/>: raising the CAdES baseline level of every
/// signature a container incorporates (clause 5.1 item 2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see>) and adding links to the container-level long-term-availability chain of that
/// document's Annex A.7.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Every container is taken apart by the independent raw-octet oracle before anything is asserted about
/// it.</strong> <see cref="AsicZipStructureOracle"/> walks the end record, the central directory and every local
/// file header itself and shares no code with <see cref="AsicZipAuthoring"/>; the CAdES objects are verified
/// detached by the BouncyCastle CMS reader, the time-stamp tokens by the BouncyCastle TSP validator, and every
/// manifest digest by an independent recomputation through the BouncyCastle digest backend. The Annex A.7 chain
/// walk is performed here with <see cref="XDocument"/> against the raw manifest octets, so it is a statement
/// about the container the library wrote rather than about the library's reading of it.
/// </para>
/// <para>
/// The signing key under test is minted through <see cref="BouncyCastleKeyMaterialCreator"/>; the time-stamp
/// tokens come from a <see cref="MintingTimestampResponder"/>, which mints a genuine token over whatever imprint
/// the request octets state.
/// </para>
/// </remarks>
[TestClass]
internal sealed class AsicContainerAugmentationTests
{
    /// <summary>The address handed to the transport delegate; no socket is opened for it.</summary>
    private const string TsaUri = "http://tsa.asic.example.test/";


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

    /// <summary>The certificate revocation list's <c>thisUpdate</c>.</summary>
    private static DateTimeOffset ThisUpdate { get; } = TestClock.CanonicalEpoch.AddMinutes(-5);

    /// <summary>The certificate revocation list's <c>nextUpdate</c>.</summary>
    private static DateTimeOffset NextUpdate { get; } = TestClock.CanonicalEpoch.AddDays(7);

    /// <summary>The first data object every ASiC-E container carries.</summary>
    private static byte[] FirstDataObject { get; } = [.. "the first archived data object"u8];

    /// <summary>The second data object every ASiC-E container carries.</summary>
    private static byte[] SecondDataObject { get; } = [.. "the second archived data object"u8];


    /// <summary>
    /// Raising a container to B-T adds a <c>signature-time-stamp</c> to the CAdES object it carries, leaves that
    /// object verifying detached over the manifest it was detached over, and leaves every other entry's octets
    /// exactly as they were — the byte-preservation property every later chain link rests on.
    /// </summary>
    [TestMethod]
    public async Task RaisingToBaselineTTimestampsTheSignatureAndPreservesEveryOtherEntry()
    {
        using var world = AugmentationWorld.Create();
        using AsicContainerCreationResult created = await CreateExtendedCAdESAsync(world).ConfigureAwait(false);
        byte[] before = created.Container.AsReadOnlySpan().ToArray();

        Assert.AreEqual(AsicContainerLevel.BaselineB, LevelOf(before), "A freshly created container incorporates B-B signatures.");

        using AsicContainerAugmentationResult raised = await AsicContainerAugmentation.AddSignatureTimestampsAsync(
            SignatureTimestampContext(world, before), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] after = raised.Container.AsReadOnlySpan().ToArray();
        Assert.AreEqual(AsicContainerLevel.BaselineT, LevelOf(after), "Clause 5.1 item 2: every incorporated signature now carries a proof of existence.");
        Assert.AreSequenceEqual(new[] { created.SignatureEntryName! }, raised.RaisedSignatureEntryNames.ToArray());

        Dictionary<string, byte[]> payloadsBefore = EntryPayloads(before);
        Dictionary<string, byte[]> payloadsAfter = EntryPayloads(after);
        AssertOnlyTheseEntriesChanged(payloadsBefore, payloadsAfter, [created.SignatureEntryName!]);

        byte[] manifest = payloadsAfter[created.ManifestEntryName!];
        Assert.IsTrue(VerifiesDetached(payloadsAfter[created.SignatureEntryName!], manifest),
            "Adding an unsigned attribute leaves the signature verifying over exactly what it signed.");
        Assert.IsTrue(VerifiesUnderAnyEmbeddedCertificate(SignatureTimestampTokenOf(payloadsAfter[created.SignatureEntryName!])),
            "The independent TSP validator must accept the token the augmentation attached.");
    }


    /// <summary>
    /// Raising a container to B-LT places the stated validation material into the CAdES object's own
    /// <c>SignedData</c> — Annex A.7 item 1 b)'s first route, which the independent CMS reader finds among the
    /// object's certificates and revocation information.
    /// </summary>
    [TestMethod]
    public async Task RaisingToBaselineLTPlacesTheMaterialInSignedDataWhereTheIndependentReaderFindsIt()
    {
        using var world = AugmentationWorld.Create();
        using AsicContainerCreationResult created = await CreateExtendedCAdESAsync(world).ConfigureAwait(false);

        using AsicContainerAugmentationResult raised = await AsicContainerAugmentation.AddSignatureTimestampsAsync(
            SignatureTimestampContext(world, created.Container.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory rootCertificate = ToCertificateCarrier(world.Root.Certificate.RawData);
        using PkiCertificateMemory revocationList = X509ChainTestRingRevocation.MintCertificateRevocationList(world.Root, ThisUpdate, NextUpdate, []);

        using AsicContainerAugmentationResult longTerm = AsicContainerAugmentation.AddSignatureValidationData(
            new AsicContainerValidationDataContext
            {
                Container = raised.Container.AsReadOnlyMemory(),
                LastModified = ContainerInstant,
                ValidationMaterial = new CAdESValidationMaterial { Certificates = [rootCertificate], CertificateRevocationLists = [revocationList] }
            },
            BaseMemoryPool.Shared);

        byte[] after = longTerm.Container.AsReadOnlySpan().ToArray();
        Assert.AreEqual(AsicContainerLevel.BaselineLT, LevelOf(after), "Revocation information is what a reader can see B-LT by; certificates alone every baseline signature carries.");

        var independent = new BcCmsSignedData(EntryPayloads(after)[created.SignatureEntryName!]);
        Assert.IsGreaterThan(1, independent.GetCertificates().EnumerateMatches(null).Count(),
            "The signer's certificate was already there and the root's was added beside it.");
        Assert.HasCount(1, independent.GetCrls().EnumerateMatches(null).ToList(),
            "Requirement q) places a certificate revocation list in SignedData.crls, where the independent reader finds it.");
    }


    /// <summary>
    /// Raising a container to B-LTA attaches an <c>archive-time-stamp-v3</c> to the CAdES object, over the
    /// manifest that object is detached across — which the augmentation learns from the manifest's own
    /// <c>SigReference</c> (Annex A.4.1) rather than from the caller.
    /// </summary>
    [TestMethod]
    public async Task RaisingToBaselineLTAArchiveTimestampsTheSignatureOverTheManifestItIsDetachedAcross()
    {
        using var world = AugmentationWorld.Create();
        using AsicContainerAugmentationResult longTerm = await CreateExtendedCAdESAtBaselineLTAsync(world).ConfigureAwait(false);
        string signatureEntryName = longTerm.RaisedSignatureEntryNames[0];

        using AsicContainerAugmentationResult archived = await AsicContainerAugmentation.AddSignatureArchiveTimestampsAsync(
            new AsicContainerSignatureArchiveTimestampContext
            {
                Container = longTerm.Container.AsReadOnlyMemory(),
                LastModified = ContainerInstant,
                TsaUri = TsaUri,
                FetchTimestampResponse = world.Responder.FetchAsync,
                ParseManifest = AsicManifestXmlBinding.ParseAsync,
                SigningCertificate = world.SignerCertificate
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        byte[] after = archived.Container.AsReadOnlySpan().ToArray();
        Assert.AreEqual(AsicContainerLevel.BaselineLTA, LevelOf(after), "An archive time-stamp is what names B-LTA.");

        Dictionary<string, byte[]> payloads = EntryPayloads(after);
        AssertOnlyTheseEntriesChanged(EntryPayloads(longTerm.Container.AsReadOnlySpan().ToArray()), payloads, [signatureEntryName]);

        string manifestEntryName = payloads.Keys.Single(AsicManifestNaming.IsSignatureManifestEntryName);
        Assert.IsTrue(VerifiesDetached(payloads[signatureEntryName], payloads[manifestEntryName]),
            "The archive time-stamp is an unsigned attribute, so the signature still verifies over the manifest.");
    }


    /// <summary>
    /// An ASiC-S container carries no manifest, so the file object its CAdES signature is detached across is the
    /// single data file at the container root (clause 4.3.3.2 item 4 b) — resolved without a manifest parsing
    /// seam, which such a container has nothing for.
    /// </summary>
    [TestMethod]
    public async Task ASimpleContainerResolvesItsDetachedContentFromTheSingleDataFile()
    {
        using var world = AugmentationWorld.Create();
        using AsicContainerCreationResult created = await CreateSimpleCAdESAsync(world).ConfigureAwait(false);

        using AsicContainerAugmentationResult archived = await AsicContainerAugmentation.AddSignatureArchiveTimestampsAsync(
            new AsicContainerSignatureArchiveTimestampContext
            {
                Container = created.Container.AsReadOnlyMemory(),
                LastModified = ContainerInstant,
                TsaUri = TsaUri,
                FetchTimestampResponse = world.Responder.FetchAsync,
                SigningCertificate = world.SignerCertificate
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        byte[] after = archived.Container.AsReadOnlySpan().ToArray();
        Assert.AreEqual(AsicContainerLevel.BaselineLTA, LevelOf(after));

        Dictionary<string, byte[]> payloads = EntryPayloads(after);
        Assert.IsTrue(VerifiesDetached(payloads[AsicManifestNaming.SimpleSignatureEntryName], payloads["data.txt"]),
            "The ASiC-S signature still verifies detached over the data file it was created over.");
    }


    /// <summary>
    /// The first addition of Annex A.7 writes <c>META-INF/ASiCArchiveManifest.xml</c> referencing every file
    /// object the container carries, with no <c>Rootfile</c> anywhere because there is no predecessor to point
    /// back at, and a time-stamp token applied to that manifest as it is stored.
    /// </summary>
    [TestMethod]
    public async Task TheFirstArchiveManifestReferencesEveryFileObjectAndCarriesNoBackwardPointer()
    {
        using var world = AugmentationWorld.Create();
        using AsicContainerCreationResult created = await CreateExtendedCAdESAsync(world).ConfigureAwait(false);
        byte[] before = created.Container.AsReadOnlySpan().ToArray();

        using AsicContainerAugmentationResult archived = await AsicContainerAugmentation.AddContainerArchiveTimestampAsync(
            ArchiveTimestampContext(world, before), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AsicManifestNaming.FixedArchiveManifestEntryName, archived.ArchiveManifestEntryName,
            "Annex A.7 item 1 c a): the ASiCArchiveManifest file shall be named \"ASiCArchiveManifest.xml\".");
        Assert.IsNull(archived.RenamedArchiveManifestEntryName, "A first addition has nothing to rename.");
        Assert.AreEqual(1, archived.ArchiveManifestChainLength);
        Assert.AreEqual(TimeAssertionInstant, archived.ArchiveTimestampTime);
        Assert.IsTrue(AsicManifestNaming.IsTimestampEntryName(archived.ArchiveTimestampEntryName),
            "Annex A.7 item 1 c c): the token is named with a valid \"META-INF/*timestamp*.tst\" name.");

        byte[] after = archived.Container.AsReadOnlySpan().ToArray();
        Dictionary<string, byte[]> payloads = EntryPayloads(after);
        AssertOnlyTheseEntriesChanged(EntryPayloads(before), payloads, []);

        List<ArchiveManifestReference> references = ReadReferences(payloads[archived.ArchiveManifestEntryName!]);
        Assert.AreSequenceEqual(
            new[] { "first.txt", "folder/second.bin", created.ManifestEntryName!, created.SignatureEntryName! },
            references.Select(reference => reference.EntryName).ToArray(),
            "Annex A.7 item 1 c b): every data, signature and manifest file object of the container is referenced, and the media type entry is not a file object.");

        foreach(ArchiveManifestReference reference in references)
        {
            Assert.IsNull(reference.RootFile, "A first addition points back at nothing, so no reference states Rootfile.");
            Assert.AreSequenceEqual(
                EvidenceRecordOracle.Hash(payloads[reference.EntryName], reference.Algorithm),
                reference.Digest,
                $"The digest stated for '{reference.EntryName}' must be the digest of that entry.");
        }

        byte[] token = payloads[archived.ArchiveTimestampEntryName!];
        Assert.IsTrue(VerifiesUnderAnyEmbeddedCertificate(token), "The independent TSP validator must accept the archive time-stamp token.");
        Assert.AreSequenceEqual(
            EvidenceRecordOracle.Hash(payloads[archived.ArchiveManifestEntryName!], PkiDigestAlgorithm.Sha256),
            ImprintOf(token),
            "Annex A.7 item 1 c c): the token is applied to the ASiCArchiveManifest file as it is stored.");
    }


    /// <summary>
    /// A renewal renames the archive manifest already present, preserving its octets exactly, reclaims the fixed
    /// name for the new one, and points the new one back at the renamed predecessor with <c>Rootfile</c> set to
    /// true and at nothing else.
    /// </summary>
    [TestMethod]
    public async Task ARenewalRenamesThePredecessorByteForByteAndPointsBackAtItAlone()
    {
        using var world = AugmentationWorld.Create();
        using AsicContainerCreationResult created = await CreateExtendedCAdESAsync(world).ConfigureAwait(false);

        using AsicContainerAugmentationResult first = await AsicContainerAugmentation.AddContainerArchiveTimestampAsync(
            ArchiveTimestampContext(world, created.Container.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] afterFirst = first.Container.AsReadOnlySpan().ToArray();

        using AsicContainerAugmentationResult second = await AsicContainerAugmentation.AddContainerArchiveTimestampAsync(
            ArchiveTimestampContext(world, afterFirst), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] afterSecond = second.Container.AsReadOnlySpan().ToArray();

        Assert.AreEqual("META-INF/ASiCArchiveManifest1.xml", second.RenamedArchiveManifestEntryName,
            "Annex A.7 item 2 a): the manifest already present is renamed to a valid \"META-INF/*ASiCArchiveManifest*.xml\" name.");
        Assert.AreEqual(AsicManifestNaming.FixedArchiveManifestEntryName, second.ArchiveManifestEntryName,
            "Annex A.7 item 2 b) i): the new manifest reclaims the fixed name.");
        Assert.AreEqual(2, second.ArchiveManifestChainLength);

        Dictionary<string, byte[]> before = EntryPayloads(afterFirst);
        Dictionary<string, byte[]> after = EntryPayloads(afterSecond);

        Assert.AreSequenceEqual(
            before[AsicManifestNaming.FixedArchiveManifestEntryName],
            after[second.RenamedArchiveManifestEntryName!],
            "The rename changes an entry name and nothing else: a token has already committed to those octets.");

        foreach(KeyValuePair<string, byte[]> entry in before)
        {
            if(string.Equals(entry.Key, AsicManifestNaming.FixedArchiveManifestEntryName, StringComparison.Ordinal))
            {
                continue;
            }

            Assert.AreSequenceEqual(entry.Value, after[entry.Key], $"'{entry.Key}' was carried forward unchanged.");
        }

        List<ArchiveManifestReference> references = ReadReferences(after[second.ArchiveManifestEntryName!]);
        List<ArchiveManifestReference> rootFiles = [.. references.Where(reference => reference.RootFile == true)];
        Assert.HasCount(1, rootFiles, "Annex A.7 item 2 b) iv): exactly one reference is the backward pointer.");
        Assert.AreEqual(second.RenamedArchiveManifestEntryName, rootFiles[0].EntryName,
            "The backward pointer names the manifest renamed according to item 2 a).");

        Assert.Contains(first.ArchiveTimestampEntryName!, references.Select(reference => reference.EntryName).ToList(),
            "Annex A.7 item 2 b) iii): the time-stamp tokens applying to the archive manifests already present are referenced too.");
        foreach(ArchiveManifestReference reference in references)
        {
            Assert.AreSequenceEqual(
                EvidenceRecordOracle.Hash(after[reference.EntryName], reference.Algorithm),
                reference.Digest,
                $"The digest stated for '{reference.EntryName}' must be the digest of that entry as the container now stores it.");
        }
    }


    /// <summary>
    /// Walking the <c>Rootfile</c> pointers backward from the file named <c>ASiCArchiveManifest.xml</c>
    /// reconstructs the whole chain over several renewals, in order, ending at the first link ever added — and
    /// every link's own token still binds the manifest it was taken over.
    /// </summary>
    /// <remarks>
    /// The walk is performed here against the raw manifest octets, so what it establishes is a property of the
    /// containers the library wrote. Annex A.7 states no verification algorithm; the walk is the only reading of
    /// the <c>Rootfile</c>-linked list its items 2 a) and 2 b) iv) describe.
    /// </remarks>
    [TestMethod]
    public async Task TheRenameChainWalksBackwardThroughEveryRenewal()
    {
        using var world = AugmentationWorld.Create();
        using AsicContainerCreationResult created = await CreateExtendedCAdESAsync(world).ConfigureAwait(false);

        using AsicContainerAugmentationResult first = await AsicContainerAugmentation.AddContainerArchiveTimestampAsync(
            ArchiveTimestampContext(world, created.Container.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using AsicContainerAugmentationResult second = await AsicContainerAugmentation.AddContainerArchiveTimestampAsync(
            ArchiveTimestampContext(world, first.Container.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using AsicContainerAugmentationResult third = await AsicContainerAugmentation.AddContainerArchiveTimestampAsync(
            ArchiveTimestampContext(world, second.Container.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(3, third.ArchiveManifestChainLength);

        Dictionary<string, byte[]> payloads = EntryPayloads(third.Container.AsReadOnlySpan().ToArray());
        List<string> walked = WalkArchiveManifestChain(payloads);

        Assert.AreSequenceEqual(
            new[] { AsicManifestNaming.FixedArchiveManifestEntryName, "META-INF/ASiCArchiveManifest2.xml", "META-INF/ASiCArchiveManifest1.xml" },
            walked.ToArray(),
            "The walk starts at the fixed name and follows one backward pointer per renewal to the first link ever added.");

        foreach(string link in walked)
        {
            string tokenEntryName = SignatureReferenceOf(payloads[link]);
            Assert.IsTrue(AsicManifestNaming.IsTimestampEntryName(tokenEntryName), $"'{link}' names a time-stamp token in its SigReference.");
            Assert.AreSequenceEqual(
                EvidenceRecordOracle.Hash(payloads[link], PkiDigestAlgorithm.Sha256),
                ImprintOf(payloads[tokenEntryName]),
                $"The token of '{link}' still binds that manifest's octets after every later renewal.");
        }
    }


    /// <summary>
    /// Changing one octet of a file object an archive manifest references leaves the digest that manifest states
    /// for it unmatched, while every other reference still matches — the unconditional comparison of clause
    /// 4.4.4.2 item d, shown to be the thing that catches the change.
    /// </summary>
    [TestMethod]
    public async Task TamperingWithACoveredFileObjectBreaksExactlyItsOwnStatedDigest()
    {
        using var world = AugmentationWorld.Create();
        using AsicContainerCreationResult created = await CreateExtendedCAdESAsync(world).ConfigureAwait(false);

        using AsicContainerAugmentationResult archived = await AsicContainerAugmentation.AddContainerArchiveTimestampAsync(
            ArchiveTimestampContext(world, created.Container.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        using PooledMemory tampered = RewriteWithChangedEntry(archived.Container.AsReadOnlyMemory(), "first.txt");
        Dictionary<string, byte[]> payloads = EntryPayloads(tampered.AsReadOnlySpan().ToArray());

        int matched = 0;
        foreach(ArchiveManifestReference reference in ReadReferences(payloads[archived.ArchiveManifestEntryName!]))
        {
            byte[] recomputed = EvidenceRecordOracle.Hash(payloads[reference.EntryName], reference.Algorithm);
            bool matches = recomputed.AsSpan().SequenceEqual(reference.Digest);
            if(string.Equals(reference.EntryName, "first.txt", StringComparison.Ordinal))
            {
                Assert.IsFalse(matches, "Clause 4.4.4.2 item d: a changed file object no longer matches the digest the manifest states for it.");

                continue;
            }

            Assert.IsTrue(matches, $"'{reference.EntryName}' was not touched, so its stated digest still matches.");
            ++matched;
        }

        Assert.IsGreaterThan(0, matched, "The other references were checked as well, so the failure is about the changed entry alone.");
    }


    /// <summary>
    /// Re-encoding an archive manifest during the rename — even by one whitespace octet — breaks the token
    /// already applied to it, which is why Annex A.7 item 2 a)'s rename changes an entry name and nothing else.
    /// </summary>
    [TestMethod]
    public async Task ReEncodingTheRenamedArchiveManifestWouldBreakTheTokenAlreadyOverIt()
    {
        using var world = AugmentationWorld.Create();
        using AsicContainerCreationResult created = await CreateExtendedCAdESAsync(world).ConfigureAwait(false);

        using AsicContainerAugmentationResult first = await AsicContainerAugmentation.AddContainerArchiveTimestampAsync(
            ArchiveTimestampContext(world, created.Container.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using AsicContainerAugmentationResult second = await AsicContainerAugmentation.AddContainerArchiveTimestampAsync(
            ArchiveTimestampContext(world, first.Container.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, byte[]> payloads = EntryPayloads(second.Container.AsReadOnlySpan().ToArray());
        byte[] renamed = payloads[second.RenamedArchiveManifestEntryName!];
        byte[] token = payloads[first.ArchiveTimestampEntryName!];

        Assert.AreSequenceEqual(EvidenceRecordOracle.Hash(renamed, PkiDigestAlgorithm.Sha256), ImprintOf(token),
            "As stored, the renamed manifest is still what its own token binds.");

        byte[] reEncoded = [.. renamed, (byte)'\n'];
        Assert.AreNotEqual(
            Convert.ToBase64String(EvidenceRecordOracle.Hash(reEncoded, PkiDigestAlgorithm.Sha256)),
            Convert.ToBase64String(ImprintOf(token)),
            "One whitespace octet is a different signed object; a rename that re-serialised the manifest would break the chain silently.");
    }


    /// <summary>
    /// A container whose Annex A.7 chain has already begun refuses an augmentation that would change the octets
    /// of the file objects that chain committed a token to. Annex A.7 item 1 a) states the order this enforces:
    /// the signatures reach the level they are to be preserved at, and the chain is started over them.
    /// </summary>
    [TestMethod]
    public async Task RaisingASignatureAfterTheArchiveChainHasBegunIsRefused()
    {
        using var world = AugmentationWorld.Create();
        using AsicContainerCreationResult created = await CreateExtendedCAdESAsync(world).ConfigureAwait(false);

        using AsicContainerAugmentationResult archived = await AsicContainerAugmentation.AddContainerArchiveTimestampAsync(
            ArchiveTimestampContext(world, created.Container.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        AsicContainerAugmentationException refusal = await Assert.ThrowsExactlyAsync<AsicContainerAugmentationException>(async () =>
        {
            using AsicContainerAugmentationResult _ = await AsicContainerAugmentation.AddSignatureTimestampsAsync(
                SignatureTimestampContext(world, archived.Container.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);

        Assert.AreEqual(AsicContainerAugmentationFailureKind.WouldBreakArchiveManifestChain, refusal.FailureKind, refusal.Message);
    }


    /// <summary>
    /// The ASiC-S time assertion container refuses the <c>certificate-values</c>/<c>revocation-values</c> route
    /// outright: ETSI EN 319 162-2 clause 4.2.1 d) narrows Annex A.7 for that profile to "the additional
    /// restriction that only <c>SignedData</c> shall be used to include certificate and revocation information".
    /// </summary>
    [TestMethod]
    public async Task TheSimpleTimeAssertionProfileRefusesTheCertificateValuesRoute()
    {
        using var world = AugmentationWorld.Create();
        using AsicContainerCreationResult created = await CreateSimpleTimeAssertionAsync(world).ConfigureAwait(false);
        using PkiCertificateMemory rootCertificate = ToCertificateCarrier(world.Root.Certificate.RawData);

        AsicContainerAugmentationException refusal = await Assert.ThrowsExactlyAsync<AsicContainerAugmentationException>(async () =>
        {
            using AsicContainerAugmentationResult _ = await AsicContainerAugmentation.AddContainerArchiveTimestampAsync(
                ArchiveTimestampContext(world, created.Container.AsReadOnlyMemory()) with
                {
                    ValidationMaterial = new CAdESValidationMaterial { Certificates = [rootCertificate] },
                    Placement = AsicValidationMaterialPlacement.CertificateAndRevocationValues
                },
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);

        Assert.AreEqual(AsicContainerAugmentationFailureKind.ValidationMaterialPlacementRefused, refusal.FailureKind, refusal.Message);
    }


    /// <summary>
    /// The same route is refused on an ASiC-E container too when the object's own state contradicts it: Annex
    /// A.7 item 1 b)'s "as specified in CAdES" defers the choice to ETSI EN 319 122-1 clause 5.5.3, which places
    /// material in the root <c>SignedData</c> of an object carrying no legacy long-term-availability attribute.
    /// </summary>
    [TestMethod]
    public async Task TheCertificateValuesRouteIsRefusedForAnObjectClause553PlacesInSignedData()
    {
        using var world = AugmentationWorld.Create();
        using AsicContainerCreationResult created = await CreateExtendedCAdESAsync(world).ConfigureAwait(false);
        using PkiCertificateMemory rootCertificate = ToCertificateCarrier(world.Root.Certificate.RawData);

        AsicContainerAugmentationException refusal = Assert.ThrowsExactly<AsicContainerAugmentationException>(() =>
        {
            using AsicContainerAugmentationResult _ = AsicContainerAugmentation.AddSignatureValidationData(
                new AsicContainerValidationDataContext
                {
                    Container = created.Container.AsReadOnlyMemory(),
                    LastModified = ContainerInstant,
                    ValidationMaterial = new CAdESValidationMaterial { Certificates = [rootCertificate] },
                    Placement = AsicValidationMaterialPlacement.CertificateAndRevocationValues
                },
                BaseMemoryPool.Shared);
        });

        Assert.AreEqual(AsicContainerAugmentationFailureKind.ValidationMaterialPlacementRefused, refusal.FailureKind, refusal.Message);
    }


    /// <summary>
    /// A container's level is the LOWEST level of the signatures it incorporates (clause 5.1 item 2): a
    /// container carrying one B-T object and one B-B object is a B-B container, and the report names which
    /// object caps it.
    /// </summary>
    [TestMethod]
    public async Task TheContainerLevelIsTheLowestLevelOfTheSignaturesItIncorporates()
    {
        using var world = AugmentationWorld.Create();
        using AsicContainerCreationResult created = await CreateExtendedCAdESAsync(world).ConfigureAwait(false);
        byte[] baseline = created.Container.AsReadOnlySpan().ToArray();

        using AsicContainerAugmentationResult raised = await AsicContainerAugmentation.AddSignatureTimestampsAsync(
            SignatureTimestampContext(world, baseline), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] withTimestamp = raised.Container.AsReadOnlySpan().ToArray();

        Assert.AreEqual(AsicContainerLevel.BaselineT, LevelOf(withTimestamp), "One signature, one level.");

        //A second CAdES object that stayed at B-B: the B-B octets of the same signature, stored under a second
        //name the clause 4.4.4.2 item 3 a pattern also dispatches as a signature file.
        using PooledMemory twoSignatures = AddEntry(
            withTimestamp, "META-INF/signature2.p7s", EntryPayloads(baseline)[created.SignatureEntryName!]);

        AsicContainerLevelReport report = AsicContainerAugmentation.StateContainerLevel(
            twoSignatures.AsReadOnlyMemory(), AsicZipReadLimits.Conformant, BaseMemoryPool.Shared);

        Assert.HasCount(2, report.Signatures);
        Assert.AreEqual(AsicContainerLevel.BaselineB, report.Level,
            "Clause 5.1 item 2: the container's level is the lowest of the incorporated signatures'.");
        Assert.AreEqual(AsicContainerLevel.BaselineT, report.Signatures.Single(signature => string.Equals(signature.EntryName, created.SignatureEntryName, StringComparison.Ordinal)).Level);
        Assert.AreEqual(AsicContainerLevel.BaselineB, report.Signatures.Single(signature => string.Equals(signature.EntryName, "META-INF/signature2.p7s", StringComparison.Ordinal)).Level);
    }


    /// <summary>
    /// The four refusals a caller can reach without an authority: octets that are not a container, a container
    /// carrying no CAdES object, a renewal with no manifest parsing seam, and a digest algorithm clause 5.2.1 or
    /// this library's creation-side line refuses.
    /// </summary>
    [TestMethod]
    public async Task RefusesWhatItCannotAugment()
    {
        using var world = AugmentationWorld.Create();
        using AsicContainerCreationResult created = await CreateExtendedCAdESAsync(world).ConfigureAwait(false);
        using AsicContainerCreationResult timeAssertion = await CreateSimpleTimeAssertionAsync(world).ConfigureAwait(false);

        AsicContainerAugmentationException notAContainer = Assert.ThrowsExactly<AsicContainerAugmentationException>(() =>
            AsicContainerAugmentation.StateContainerLevel(new byte[] { 1, 2, 3, 4 }, AsicZipReadLimits.Conformant, BaseMemoryPool.Shared));
        Assert.AreEqual(AsicContainerAugmentationFailureKind.ContainerNotRead, notAContainer.FailureKind, notAContainer.Message);

        AsicContainerAugmentationException noSignature = await Assert.ThrowsExactlyAsync<AsicContainerAugmentationException>(async () =>
        {
            using AsicContainerAugmentationResult _ = await AsicContainerAugmentation.AddSignatureTimestampsAsync(
                SignatureTimestampContext(world, timeAssertion.Container.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
        Assert.AreEqual(AsicContainerAugmentationFailureKind.NoSignatureToRaise, noSignature.FailureKind, noSignature.Message);

        using AsicContainerAugmentationResult archived = await AsicContainerAugmentation.AddContainerArchiveTimestampAsync(
            ArchiveTimestampContext(world, created.Container.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        AsicContainerAugmentationException noParser = await Assert.ThrowsExactlyAsync<AsicContainerAugmentationException>(async () =>
        {
            using AsicContainerAugmentationResult _ = await AsicContainerAugmentation.AddContainerArchiveTimestampAsync(
                ArchiveTimestampContext(world, archived.Container.AsReadOnlyMemory()) with { ParseManifest = null },
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
        Assert.AreEqual(AsicContainerAugmentationFailureKind.ManifestParserMissing, noParser.FailureKind, noParser.Message);

        var sha1 = new PkiDigestAlgorithm(new AlgorithmIdentifier("1.3.14.3.2.26"), PkiDigestAlgorithm.Sha256.DigestTag, 20);
        AsicContainerAugmentationException weakDigest = await Assert.ThrowsExactlyAsync<AsicContainerAugmentationException>(async () =>
        {
            using AsicContainerAugmentationResult _ = await AsicContainerAugmentation.AddContainerArchiveTimestampAsync(
                ArchiveTimestampContext(world, created.Container.AsReadOnlyMemory()) with { DigestAlgorithm = sha1 },
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
        Assert.AreEqual(AsicContainerAugmentationFailureKind.DigestAlgorithmRefused, weakDigest.FailureKind, weakDigest.Message);
    }


    /// <summary>
    /// A renewal completes the validation material of the token applied to the last archive manifest, and of
    /// nothing else — the boundary Annex A.7 item 2's own wording draws, and the only one that leaves every
    /// digest an earlier link stated still matching.
    /// </summary>
    [TestMethod]
    public async Task ARenewalPlacesMaterialOnlyInTheTokenTheLastArchiveManifestApplies()
    {
        using var world = AugmentationWorld.Create();
        using AsicContainerCreationResult created = await CreateExtendedCAdESAsync(world).ConfigureAwait(false);

        //A certificate revocation list rather than a certificate: the minted tokens already carry the whole
        //certification path, and requirement e)'s "duplication of certificate values should be avoided" means
        //placing one of those would correctly change nothing at all.
        using PkiCertificateMemory revocationList = X509ChainTestRingRevocation.MintCertificateRevocationList(world.Root, ThisUpdate, NextUpdate, []);

        using AsicContainerAugmentationResult first = await AsicContainerAugmentation.AddContainerArchiveTimestampAsync(
            ArchiveTimestampContext(world, created.Container.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] afterFirst = first.Container.AsReadOnlySpan().ToArray();

        using AsicContainerAugmentationResult second = await AsicContainerAugmentation.AddContainerArchiveTimestampAsync(
            ArchiveTimestampContext(world, afterFirst) with
            {
                ValidationMaterial = new CAdESValidationMaterial { CertificateRevocationLists = [revocationList] }
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreSequenceEqual(new[] { first.ArchiveTimestampEntryName! }, second.RaisedSignatureEntryNames.ToArray(),
            "Annex A.7 item 2 names the token applied to the last ASiCArchiveManifest file, and every other object is already covered by a digest that link stated.");

        Dictionary<string, byte[]> before = EntryPayloads(afterFirst);
        Dictionary<string, byte[]> after = EntryPayloads(second.Container.AsReadOnlySpan().ToArray());

        Assert.IsFalse(before[first.ArchiveTimestampEntryName!].AsSpan().SequenceEqual(after[first.ArchiveTimestampEntryName!]),
            "The token that carried the material is the one entry whose octets changed.");
        Assert.AreSequenceEqual(before[created.SignatureEntryName!], after[created.SignatureEntryName!],
            "The CAdES object an earlier link already stated a digest for is untouched.");
        Assert.HasCount(1, new BcCmsSignedData(after[first.ArchiveTimestampEntryName!]).GetCrls().EnumerateMatches(null).ToList(),
            "Annex A.7 item 1 b)'s SignedData route places the revocation information where the independent reader finds it.");

        List<ArchiveManifestReference> references = ReadReferences(after[second.ArchiveManifestEntryName!]);
        foreach(ArchiveManifestReference reference in references)
        {
            Assert.AreSequenceEqual(
                EvidenceRecordOracle.Hash(after[reference.EntryName], reference.Algorithm),
                reference.Digest,
                $"The new manifest states the digest of '{reference.EntryName}' as the container now stores it.");
        }
    }


    /// <summary>
    /// Builds an ASiC-E container carrying one CAdES object over an <c>ASiCManifest</c> file naming two data
    /// files.
    /// </summary>
    /// <param name="world">The minted signer and Time-Stamping Authority.</param>
    /// <returns>The container. The caller owns and disposes it.</returns>
    private async Task<AsicContainerCreationResult> CreateExtendedCAdESAsync(AugmentationWorld world) =>
        await AsicContainerCreation.SignAsync(
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
            world.SignerPrivateKey,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>
    /// Builds an ASiC-S container carrying one CAdES object detached over the single data file.
    /// </summary>
    /// <param name="world">The minted signer and Time-Stamping Authority.</param>
    /// <returns>The container. The caller owns and disposes it.</returns>
    private async Task<AsicContainerCreationResult> CreateSimpleCAdESAsync(AugmentationWorld world) =>
        await AsicContainerCreation.SignAsync(
            new AsicContainerSignatureContext
            {
                Shape = AsicContainerShape.Simple,
                DataObjects = [new AsicDataObject { Name = "data.txt", Content = FirstDataObject }],
                SignerCertificate = world.SignerCertificate,
                SigningTime = SigningTime,
                LastModified = ContainerInstant,
                EncodeManifest = AsicManifestXmlBinding.EncodeAsync
            },
            world.SignerPrivateKey,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>
    /// Builds an ASiC-S time assertion container — the profile EN 319 162-2 clause 4.2.1 d) restricts.
    /// </summary>
    /// <param name="world">The minted signer and Time-Stamping Authority.</param>
    /// <returns>The container. The caller owns and disposes it.</returns>
    private async Task<AsicContainerCreationResult> CreateSimpleTimeAssertionAsync(AugmentationWorld world) =>
        await AsicContainerCreation.CreateTimeAssertionAsync(
            new AsicContainerTimeAssertionContext
            {
                Shape = AsicContainerShape.Simple,
                DataObjects = [new AsicDataObject { Name = "data.txt", Content = FirstDataObject }],
                LastModified = ContainerInstant,
                TsaUri = TsaUri,
                FetchTimestampResponse = world.Responder.FetchAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>
    /// Builds an ASiC-E container whose CAdES object has been raised to B-LT, which is the precondition
    /// requirement s) of ETSI EN 319 122-1 Table 1 states for an archive time-stamp.
    /// </summary>
    /// <param name="world">The minted signer and Time-Stamping Authority.</param>
    /// <returns>The augmented container. The caller owns and disposes it.</returns>
    private async Task<AsicContainerAugmentationResult> CreateExtendedCAdESAtBaselineLTAsync(AugmentationWorld world)
    {
        using AsicContainerCreationResult created = await CreateExtendedCAdESAsync(world).ConfigureAwait(false);
        using AsicContainerAugmentationResult raised = await AsicContainerAugmentation.AddSignatureTimestampsAsync(
            SignatureTimestampContext(world, created.Container.AsReadOnlyMemory()), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory rootCertificate = ToCertificateCarrier(world.Root.Certificate.RawData);
        using PkiCertificateMemory revocationList = X509ChainTestRingRevocation.MintCertificateRevocationList(world.Root, ThisUpdate, NextUpdate, []);

        return AsicContainerAugmentation.AddSignatureValidationData(
            new AsicContainerValidationDataContext
            {
                Container = raised.Container.AsReadOnlyMemory(),
                LastModified = ContainerInstant,
                ValidationMaterial = new CAdESValidationMaterial { Certificates = [rootCertificate], CertificateRevocationLists = [revocationList] }
            },
            BaseMemoryPool.Shared);
    }


    /// <summary>
    /// States the context every signature-time-stamp augmentation in this class shares.
    /// </summary>
    /// <param name="world">The minted signer and Time-Stamping Authority.</param>
    /// <param name="container">The container to augment.</param>
    /// <returns>The context.</returns>
    private static AsicContainerSignatureTimestampContext SignatureTimestampContext(AugmentationWorld world, ReadOnlyMemory<byte> container) =>
        new()
        {
            Container = container,
            LastModified = ContainerInstant,
            TsaUri = TsaUri,
            FetchTimestampResponse = world.Responder.FetchAsync,
            SigningCertificate = world.SignerCertificate
        };


    /// <summary>
    /// States the context every Annex A.7 augmentation in this class shares.
    /// </summary>
    /// <param name="world">The minted signer and Time-Stamping Authority.</param>
    /// <param name="container">The container to augment.</param>
    /// <returns>The context.</returns>
    private static AsicContainerArchiveTimestampContext ArchiveTimestampContext(AugmentationWorld world, ReadOnlyMemory<byte> container) =>
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
    /// States a container's level through the shipped reading surface.
    /// </summary>
    /// <param name="container">The container's octets.</param>
    /// <returns>The level.</returns>
    private static AsicContainerLevel LevelOf(ReadOnlyMemory<byte> container) =>
        AsicContainerAugmentation.StateContainerLevel(container, AsicZipReadLimits.Conformant, BaseMemoryPool.Shared).Level;


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
    /// Asserts that exactly the named entries changed and every other entry carries the octets it carried
    /// before, entries added by the augmentation excepted.
    /// </summary>
    /// <param name="before">The payloads before the augmentation.</param>
    /// <param name="after">The payloads afterwards.</param>
    /// <param name="changed">The entries the augmentation was to replace.</param>
    private static void AssertOnlyTheseEntriesChanged(
        Dictionary<string, byte[]> before, Dictionary<string, byte[]> after, IReadOnlyList<string> changed)
    {
        foreach(KeyValuePair<string, byte[]> entry in before)
        {
            Assert.IsTrue(after.ContainsKey(entry.Key), $"'{entry.Key}' is still in the container.");
            bool wasToChange = changed.Contains(entry.Key, StringComparer.Ordinal);
            bool isIdentical = entry.Value.AsSpan().SequenceEqual(after[entry.Key]);

            if(wasToChange)
            {
                Assert.IsFalse(isIdentical, $"'{entry.Key}' was augmented, so its octets differ.");

                continue;
            }

            Assert.IsTrue(isIdentical, $"'{entry.Key}' was not augmented, so its octets are bit-identical across the augmentation.");
        }
    }


    /// <summary>
    /// Reads the <c>DataObjectReference</c> elements of a manifest document with an independent XML reader.
    /// </summary>
    /// <param name="manifest">The manifest document's octets, as the container stores them.</param>
    /// <returns>The references, in document order.</returns>
    private static List<ArchiveManifestReference> ReadReferences(byte[] manifest)
    {
        XDocument document = XDocument.Parse(Encoding.UTF8.GetString(manifest));
        XNamespace asic = AsicManifestXmlBinding.AsicNamespace;
        XNamespace ds = XmlSignatureWellKnown.XmlSignatureNamespace;

        var references = new List<ArchiveManifestReference>();
        foreach(XElement element in document.Root!.Elements(asic + "DataObjectReference"))
        {
            string algorithmUri = element.Element(ds + XmlSignatureWellKnown.DigestMethodElementName)!
                .Attribute(XmlSignatureWellKnown.AlgorithmAttributeName)!.Value;
            PkiDigestAlgorithm algorithm = XmlSignatureWellKnown.DigestAlgorithmFromUri(algorithmUri)
                ?? throw new InvalidOperationException($"'{algorithmUri}' does not name a digest algorithm this library computes.");

            references.Add(new ArchiveManifestReference(
                element.Attribute("URI")!.Value,
                algorithm,
                Convert.FromBase64String(element.Element(ds + XmlSignatureWellKnown.DigestValueElementName)!.Value),
                element.Attribute("Rootfile") is { } rootFile ? bool.Parse(rootFile.Value) : null));
        }

        return references;
    }


    /// <summary>
    /// Reads the entry name a manifest's <c>SigReference</c> names, with an independent XML reader.
    /// </summary>
    /// <param name="manifest">The manifest document's octets.</param>
    /// <returns>The referenced entry name.</returns>
    private static string SignatureReferenceOf(byte[] manifest)
    {
        XDocument document = XDocument.Parse(Encoding.UTF8.GetString(manifest));

        return document.Root!.Element(AsicManifestXmlBinding.AsicNamespace + "SigReference")!.Attribute("URI")!.Value;
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
    /// cannot spin.
    /// </remarks>
    private static List<string> WalkArchiveManifestChain(Dictionary<string, byte[]> payloads)
    {
        var chain = new List<string>();
        string? current = AsicManifestNaming.FixedArchiveManifestEntryName;
        while(current is not null && chain.Count <= payloads.Count)
        {
            chain.Add(current);
            List<ArchiveManifestReference> rootFiles = [.. ReadReferences(payloads[current]).Where(reference => reference.RootFile == true)];
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
    /// Rewrites a container with one entry added, for the two-signature container the lowest-level rule is
    /// stated over.
    /// </summary>
    /// <param name="container">The container's octets.</param>
    /// <param name="entryName">The name the added entry carries.</param>
    /// <param name="content">The added entry's octets.</param>
    /// <returns>The rewritten container. The caller owns and disposes it.</returns>
    private static PooledMemory AddEntry(ReadOnlyMemory<byte> container, string entryName, byte[] content)
    {
        using AsicZipReadResult read = AsicZipReading.Read(container, AsicZipReadLimits.Conformant, BaseMemoryPool.Shared);
        Assert.IsTrue(read.IsRead, $"The container must read before an entry can be added to it ({read.Status}).");

        var entries = new List<AsicZipEntrySource>(read.Container!.Entries.Count + 1);
        foreach(AsicZipEntry entry in read.Container.Entries)
        {
            if(AsicWellKnown.IsMimetypeEntryName(entry.Name))
            {
                continue;
            }

            entries.Add(new AsicZipEntrySource
            {
                Name = entry.Name,
                Content = entry.Content.AsReadOnlySpan().ToArray(),
                CompressionMethod = entry.CompressionMethod,
                LastModified = entry.LastModified
            });
        }

        entries.Add(new AsicZipEntrySource { Name = entryName, Content = content, LastModified = ContainerInstant });

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
    /// Reads the <c>signature-time-stamp</c> token a CAdES object carries, through the independent CMS reader.
    /// </summary>
    /// <param name="signature">The CAdES object's octets.</param>
    /// <returns>The token's octets.</returns>
    private static byte[] SignatureTimestampTokenOf(byte[] signature)
    {
        var signedData = new BcCmsSignedData(signature);
        foreach(SignerInformation signer in signedData.GetSignerInfos().GetSigners())
        {
            Org.BouncyCastle.Asn1.Cms.Attribute? attribute = signer.UnsignedAttributes?[
                new Org.BouncyCastle.Asn1.DerObjectIdentifier(CAdESSignatureFacts.SignatureTimestampAttributeOid)];
            if(attribute is not null)
            {
                return attribute.AttrValues[0].ToAsn1Object().GetEncoded();
            }
        }

        throw new InvalidOperationException("The CAdES object carries no signature-time-stamp attribute.");
    }


    /// <summary>
    /// Verifies a detached CMS signature over the supplied content with the independent BouncyCastle reader.
    /// </summary>
    /// <param name="signature">The DER-encoded CMS <c>SignedData</c>.</param>
    /// <param name="content">The detached content the signature is claimed to cover.</param>
    /// <returns><see langword="true"/> when a signer verifies over that content under a certificate the object embeds.</returns>
    private static bool VerifiesDetached(byte[] signature, byte[] content)
    {
        var signedData = new BcCmsSignedData(new CmsProcessableByteArray(content), signature);
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
    /// Checks a time-stamp token against the independent BouncyCastle TSP validator.
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
    /// Reads the <c>messageImprint</c> a time-stamp token binds, through the independent BouncyCastle TSP reader.
    /// </summary>
    /// <param name="token">The DER-encoded RFC 3161 <c>TimeStampToken</c>.</param>
    /// <returns>The imprint octets.</returns>
    private static byte[] ImprintOf(byte[] token) =>
        new TimeStampToken(new BcCmsSignedData(token)).TimeStampInfo.TstInfo.MessageImprint.GetHashedMessage();


    /// <summary>Copies DER octets into a pooled carrier tagged as an X.509 certificate.</summary>
    /// <param name="certificate">The DER-encoded certificate.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory ToCertificateCarrier(byte[] certificate)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(certificate.Length);
        certificate.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    /// <summary>
    /// One <c>DataObjectReference</c> as an independent XML reader found it.
    /// </summary>
    /// <param name="EntryName">The container entry the reference names.</param>
    /// <param name="Algorithm">The algorithm the <c>ds:DigestMethod</c> named.</param>
    /// <param name="Digest">The <c>ds:DigestValue</c> octets.</param>
    /// <param name="RootFile">The <c>Rootfile</c> attribute, or <see langword="null"/> when the document stated none.</param>
    private sealed record ArchiveManifestReference(string EntryName, PkiDigestAlgorithm Algorithm, byte[] Digest, bool? RootFile);


    /// <summary>
    /// The minted world every test of this class runs against: a root certification authority, a Time-Stamping
    /// Authority under it answering through a <see cref="MintingTimestampResponder"/>, and a signer.
    /// </summary>
    private sealed class AugmentationWorld: IDisposable
    {
        /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
        private bool disposed;


        /// <summary>Initialises a new world.</summary>
        /// <param name="root">The root certification authority.</param>
        /// <param name="authority">The Time-Stamping Authority.</param>
        /// <param name="responder">The transport that mints tokens.</param>
        /// <param name="signerCertificate">The signer's certificate.</param>
        /// <param name="signerPrivateKey">The signer's private key.</param>
        private AugmentationWorld(
            X509ChainTestRingNode root,
            X509ChainTestRingNode authority,
            MintingTimestampResponder responder,
            PkiCertificateMemory signerCertificate,
            PrivateKeyMemory signerPrivateKey)
        {
            Root = root;
            Authority = authority;
            Responder = responder;
            SignerCertificate = signerCertificate;
            SignerPrivateKey = signerPrivateKey;
        }


        /// <summary>Gets the root certification authority, which issues the certificate revocation lists.</summary>
        public X509ChainTestRingNode Root { get; }

        /// <summary>Gets the Time-Stamping Authority whose key signs every minted token.</summary>
        public X509ChainTestRingNode Authority { get; }

        /// <summary>Gets the transport delegate's owner, which mints a genuine token over whatever imprint a request states.</summary>
        public MintingTimestampResponder Responder { get; }

        /// <summary>Gets the signer's certificate.</summary>
        public PkiCertificateMemory SignerCertificate { get; }

        /// <summary>Gets the signer's private key.</summary>
        public PrivateKeyMemory SignerPrivateKey { get; }


        /// <summary>
        /// Mints a world: the two-node ring, the responder, and a P-256 signer whose key material comes from
        /// <see cref="BouncyCastleKeyMaterialCreator"/> and whose self-signed certificate carries the same
        /// public point.
        /// </summary>
        /// <returns>The world. The caller disposes it.</returns>
        public static AugmentationWorld Create()
        {
            var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
            X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
            X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
            var responder = new MintingTimestampResponder(authority, [authority, root], TimeAssertionInstant);

            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
            using(keys.PublicKey)
            {
                byte[] uncompressedPoint = EllipticCurveUtilities.NormalizeToUncompressed(keys.PublicKey.AsReadOnlySpan(), EllipticCurveTypes.P256);
                var ecParameters = new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    D = keys.PrivateKey.AsReadOnlySpan().ToArray(),
                    Q = new ECPoint
                    {
                        X = EllipticCurveUtilities.SliceXCoordinate(uncompressedPoint).ToArray(),
                        Y = EllipticCurveUtilities.SliceYCoordinate(uncompressedPoint).ToArray()
                    }
                };

                using ECDsa platformKey = ECDsa.Create(ecParameters);
                using X509Certificate2 platformCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(platformKey, NotBefore, NotAfter);

                return new AugmentationWorld(root, authority, responder, ToCertificateCarrier(platformCertificate.RawData), keys.PrivateKey);
            }
        }


        /// <summary>Disposes the minted certificates and key material.</summary>
        public void Dispose()
        {
            if(!disposed)
            {
                SignerPrivateKey.Dispose();
                SignerCertificate.Dispose();
                Authority.Dispose();
                Root.Dispose();
                disposed = true;
            }
        }
    }
}
