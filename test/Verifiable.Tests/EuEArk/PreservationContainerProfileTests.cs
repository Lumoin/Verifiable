using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for the preservation object container profile "ASiC with Evidence Records" of Annex A.3.1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> — its six numbered requirements, and its one tightening of the container
/// specification enforced on both the creating and the judging side.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Every container judged here was minted, not written by hand.</strong> The container comes from the
/// shipped creation surface and carries a real Evidence Record over a real hash tree, time-stamped by an
/// authority that signs what it is asked to sign, and its manifest is read back out of the archive and parsed
/// through the worked binding — so the profile is exercised against exactly the octets a caller would produce.
/// </para>
/// <para>
/// <strong>The tightening is exercised in both directions.</strong> Creation refuses a caller that asks for the
/// media type requirement 6 forbids, and a container built through the shipped surface <em>with</em> that media
/// type is judged and reported. A profile that could only refuse, or only report, would leave half of the
/// requirement untested.
/// </para>
/// </remarks>
[TestClass]
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "A manifest built by a record copy shares the carriers of the manifest it was copied from; exactly one instance of each carrier set is disposed — the parsed manifest held in its own result — and disposing the copy as well would return the same rented memory twice.")]
internal sealed class PreservationContainerProfileTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = default!;


    /// <summary>The profile's own format identifier is the one clause A.3.1.1 registers.</summary>
    [TestMethod]
    public void TheProfileIsIdentifiedByTheUrlItsClauseRegisters()
    {
        Assert.AreEqual("http://uri.etsi.org/ades/ASiC/type/ASiC-ERS", PreservationContainerProfile.FormatIdentifier);
        Assert.IsTrue(PreservationFormatWellKnown.IsContainerFormat(PreservationContainerProfile.FormatIdentifier));
        Assert.AreEqual(nameof(PreservationContainerProfileStatus.NotEvaluated), Enum.GetName(default(PreservationContainerProfileStatus)));

        var uncomputed = new PreservationContainerProfileReport { Status = default };
        Assert.IsFalse(uncomputed.IsConformant);
    }


    /// <summary>A container the profile created satisfies every requirement the profile states of one.</summary>
    [TestMethod]
    public async Task AContainerTheProfileCreatedSatisfiesTheProfile()
    {
        using PreservationTimestampAuthority authority = PreservationProfileSource.MintAuthority(PreservationProfileSource.InitialArchiveTime);
        List<AsicDataObject> dataObjects = PreservationProfileSource.DataObjects("first", "second");

        using AsicContainerCreationResult created = await PreservationContainerProfile.CreateAsync(
            PreservationProfileSource.CreationContext(dataObjects, authority),
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        (AsicContainerReadResult read, List<AsicManifestParseResult> manifests) =
            await PreservationProfileSource.ReadContainerAsync(created.Container.AsReadOnlyMemory(), TestContext.CancellationToken);

        try
        {
            Assert.IsTrue(read.IsRead);
            Assert.HasCount(1, manifests);
            Assert.IsTrue(manifests[0].IsValid);

            PreservationContainerProfileReport report = PreservationContainerProfile.StateProfile(
                new PreservationContainerProfileContext
                {
                    Facts = read.Facts!,
                    Manifests = [Manifest(created.ManifestEntryName!, manifests[0].Manifest!)]
                });

            Assert.AreEqual(PreservationContainerProfileStatus.Conformant, report.Status);
            Assert.HasCount(1, report.Manifests);

            PreservationContainerManifestReport manifestReport = report.Manifests[0];
            Assert.IsTrue(manifestReport.IsConformant);
            Assert.AreEqual(created.EvidenceRecordEntryName, manifestReport.EvidenceRecordEntryName);
            Assert.AreEqual(AsicEvidenceRecordForm.Binary, manifestReport.EvidenceRecordForm);
            Assert.AreEqual(dataObjects.Count, manifestReport.DataObjectReferenceCount);
            Assert.AreEqual(AsicManifestExtensionStatus.Accepted, manifestReport.ExtensionEvaluation.Status);
            Assert.IsEmpty(manifestReport.CriticalityDepartures);

            //Requirement 6 as the container really carries it: nothing states a media type on the reference.
            Assert.IsNull(manifests[0].Manifest!.SignatureReference.MimeType);

            //The evaluation is pure over its inputs, so judging the same container twice answers the same.
            PreservationContainerProfileReport again = PreservationContainerProfile.StateProfile(
                new PreservationContainerProfileContext
                {
                    Facts = read.Facts!,
                    Manifests = [Manifest(created.ManifestEntryName!, manifests[0].Manifest!)]
                });

            Assert.AreEqual(report.Status, again.Status);
            Assert.AreEqual(manifestReport.EvidenceRecordEntryName, again.Manifests[0].EvidenceRecordEntryName);
        }
        finally
        {
            DisposeAll(read, manifests);
        }
    }


    /// <summary>Creation refuses the media type requirement 6 forbids rather than dropping it silently.</summary>
    [TestMethod]
    public async Task CreationRefusesAMediaTypeOnTheSignatureReference()
    {
        using PreservationTimestampAuthority authority = PreservationProfileSource.MintAuthority(PreservationProfileSource.InitialArchiveTime);
        List<AsicDataObject> dataObjects = PreservationProfileSource.DataObjects("first");

        AsicContainerEvidenceRecordContext context = PreservationProfileSource.CreationContext(
            dataObjects, authority, evidenceRecordReferenceMediaType: "application/octet-stream");

        PreservationContainerProfileException refused = await Assert.ThrowsExactlyAsync<PreservationContainerProfileException>(
            async () => await PreservationContainerProfile.CreateAsync(context, BaseMemoryPool.Shared, TestContext.CancellationToken));

        Assert.AreEqual(PreservationContainerProfileStatus.SignatureReferenceMediaTypeStated, refused.Status);

        //The context the profile admits is the caller's own, unchanged — the value is refused, never removed.
        AsicContainerEvidenceRecordContext admitted = PreservationContainerProfile.StateCreationContext(
            PreservationProfileSource.CreationContext(dataObjects, authority));

        Assert.IsNull(admitted.EvidenceRecordReferenceMediaType);
        Assert.AreEqual(AsicContainerShape.Extended, admitted.Shape);
    }


    /// <summary>Creation refuses the simple container shape, which requirement 1 does not admit.</summary>
    [TestMethod]
    public async Task CreationRefusesTheSimpleContainerShape()
    {
        using PreservationTimestampAuthority authority = PreservationProfileSource.MintAuthority(PreservationProfileSource.InitialArchiveTime);
        List<AsicDataObject> dataObjects = PreservationProfileSource.DataObjects("only");

        AsicContainerEvidenceRecordContext context = PreservationProfileSource.CreationContext(
            dataObjects, authority, shape: AsicContainerShape.Simple);

        PreservationContainerProfileException refused = await Assert.ThrowsExactlyAsync<PreservationContainerProfileException>(
            async () => await PreservationContainerProfile.CreateAsync(context, BaseMemoryPool.Shared, TestContext.CancellationToken));

        Assert.AreEqual(PreservationContainerProfileStatus.NotExtendedContainer, refused.Status);
    }


    /// <summary>
    /// A container really built with the media type requirement 6 forbids is judged and reported — the other half
    /// of the tightening.
    /// </summary>
    [TestMethod]
    public async Task AContainerStatingAMediaTypeOnItsSignatureReferenceIsReported()
    {
        using PreservationTimestampAuthority authority = PreservationProfileSource.MintAuthority(PreservationProfileSource.InitialArchiveTime);
        List<AsicDataObject> dataObjects = PreservationProfileSource.DataObjects("first");

        //Built through the shipped surface rather than the profile's own creation, which is exactly how a
        //container the profile refuses to write comes to exist.
        using AsicContainerCreationResult created = await AsicContainerCreation.CreateEvidenceRecordAsync(
            PreservationProfileSource.CreationContext(dataObjects, authority, evidenceRecordReferenceMediaType: "application/octet-stream"),
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        (AsicContainerReadResult read, List<AsicManifestParseResult> manifests) =
            await PreservationProfileSource.ReadContainerAsync(created.Container.AsReadOnlyMemory(), TestContext.CancellationToken);

        try
        {
            Assert.AreEqual("application/octet-stream", manifests[0].Manifest!.SignatureReference.MimeType);

            PreservationContainerProfileReport report = PreservationContainerProfile.StateProfile(
                new PreservationContainerProfileContext
                {
                    Facts = read.Facts!,
                    Manifests = [Manifest(created.ManifestEntryName!, manifests[0].Manifest!)]
                });

            Assert.AreEqual(PreservationContainerProfileStatus.SignatureReferenceMediaTypeStated, report.Status);
            Assert.AreEqual(PreservationContainerProfileStatus.SignatureReferenceMediaTypeStated, report.Manifests[0].Status);

            //The container is still a conformant container of the specification the profile profiles; it is the
            //profile alone that refuses it.
            Assert.AreEqual(AsicContainerShape.Extended, read.Facts!.Shape);
            Assert.HasCount(1, read.Facts.EvidenceRecords);
        }
        finally
        {
            DisposeAll(read, manifests);
        }
    }


    /// <summary>A manifest whose reference names something that is not an evidence record file is refused.</summary>
    [TestMethod]
    public async Task AReferenceThatDoesNotNameAnEvidenceRecordFileIsRefused()
    {
        using PreservationTimestampAuthority authority = PreservationProfileSource.MintAuthority(PreservationProfileSource.InitialArchiveTime);
        List<AsicDataObject> dataObjects = PreservationProfileSource.DataObjects("first");

        using AsicContainerCreationResult created = await PreservationContainerProfile.CreateAsync(
            PreservationProfileSource.CreationContext(dataObjects, authority),
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        (AsicContainerReadResult read, List<AsicManifestParseResult> manifests) =
            await PreservationProfileSource.ReadContainerAsync(created.Container.AsReadOnlyMemory(), TestContext.CancellationToken);

        try
        {
            AsicManifest parsed = manifests[0].Manifest!;

            AsicManifest namesADataFile = parsed with
            {
                SignatureReference = parsed.SignatureReference with { Uri = "data-1.txt" }
            };

            Assert.AreEqual(
                PreservationContainerProfileStatus.SignatureReferenceNotAnEvidenceRecord,
                StatusOf(read.Facts!, created.ManifestEntryName!, namesADataFile));

            AsicManifest namesAMissingRecord = parsed with
            {
                SignatureReference = parsed.SignatureReference with { Uri = "META-INF/evidencerecord9.ers" }
            };

            Assert.AreEqual(
                PreservationContainerProfileStatus.EvidenceRecordFileMissing,
                StatusOf(read.Facts!, created.ManifestEntryName!, namesAMissingRecord));

            AsicManifest namesNothingResolvable = parsed with
            {
                SignatureReference = parsed.SignatureReference with { Uri = "https://example.invalid/evidencerecord1.ers" }
            };

            Assert.AreEqual(
                PreservationContainerProfileStatus.SignatureReferenceNotResolvable,
                StatusOf(read.Facts!, created.ManifestEntryName!, namesNothingResolvable));

            AsicManifest referencesNoDataObject = parsed with { DataObjectReferences = [] };

            Assert.AreEqual(
                PreservationContainerProfileStatus.NoDataObjectReference,
                StatusOf(read.Facts!, created.ManifestEntryName!, referencesNoDataObject));

            //A manifest read from an entry whose name gives it another role is not judged by this profile's
            //manifest rules at all.
            Assert.AreEqual(
                PreservationContainerProfileStatus.NotAnEvidenceRecordManifest,
                StatusOf(read.Facts!, "META-INF/ASiCManifest1.xml", parsed));
        }
        finally
        {
            DisposeAll(read, manifests);
        }
    }


    /// <summary>An extension marked critical that the policy does not recognise stops the profile too.</summary>
    [TestMethod]
    public async Task ACriticalExtensionThePolicyDoesNotRecogniseStopsTheProfile()
    {
        using PreservationTimestampAuthority authority = PreservationProfileSource.MintAuthority(PreservationProfileSource.InitialArchiveTime);
        List<AsicDataObject> dataObjects = PreservationProfileSource.DataObjects("first");

        using AsicContainerCreationResult created = await PreservationContainerProfile.CreateAsync(
            PreservationProfileSource.CreationContext(dataObjects, authority),
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        (AsicContainerReadResult read, List<AsicManifestParseResult> manifests) =
            await PreservationProfileSource.ReadContainerAsync(created.Container.AsReadOnlyMemory(), TestContext.CancellationToken);

        using var unrecognized = new PreservationCanonicalizationMethodExtension { Algorithm = "urn:example:canonicalization/1" };
        using PreservationAsicExtensionEncodeResult encoded = await PreservationAsicExtensionXmlBinding.EncodeAsync(
            new PreservationAsicExtensionEncodeContext
            {
                Payload = unrecognized,
                CanonicalizationMethodNamespace = "urn:example:canonicalization-schema"
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        try
        {
            AsicManifest extended = manifests[0].Manifest! with { Extensions = [encoded.Extension!] };

            Assert.AreEqual(
                PreservationContainerProfileStatus.UnrecognizedCriticalExtension,
                StatusOf(read.Facts!, created.ManifestEntryName!, extended));

            //Once the caller states the namespace the external schema declares the element in, the same container
            //satisfies the profile — the refusal was about what the consumer could read, not about the container.
            PreservationContainerProfileReport recognised = PreservationContainerProfile.StateProfile(
                new PreservationContainerProfileContext
                {
                    Facts = read.Facts!,
                    Manifests = [Manifest(created.ManifestEntryName!, extended)],
                    ExtensionPolicy = PreservationAsicExtensionWellKnown.RecommendedPolicyRecognizing("urn:example:canonicalization-schema"),
                    CanonicalizationMethodNamespace = "urn:example:canonicalization-schema"
                });

            Assert.AreEqual(PreservationContainerProfileStatus.Conformant, recognised.Status);
            Assert.IsEmpty(recognised.Manifests[0].CriticalityDepartures);
        }
        finally
        {
            DisposeAll(read, manifests);
        }
    }


    /// <summary>
    /// A criticality departing from the recommendation of clause 5.5 is reported beside the outcome and does not
    /// refuse the container, because both halves of that guidance are recommendations.
    /// </summary>
    [TestMethod]
    public async Task ACriticalityDepartureIsReportedWithoutRefusingTheContainer()
    {
        using PreservationTimestampAuthority authority = PreservationProfileSource.MintAuthority(PreservationProfileSource.InitialArchiveTime);
        List<AsicDataObject> dataObjects = PreservationProfileSource.DataObjects("first");

        using AsicContainerCreationResult created = await PreservationContainerProfile.CreateAsync(
            PreservationProfileSource.CreationContext(dataObjects, authority),
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        (AsicContainerReadResult read, List<AsicManifestParseResult> manifests) =
            await PreservationProfileSource.ReadContainerAsync(created.Container.AsReadOnlyMemory(), TestContext.CancellationToken);

        using var submitter = new PreservationSubmitterExtension { Submitter = "urn:example:submitter:1" };
        using PreservationAsicExtensionEncodeResult encoded = await PreservationAsicExtensionXmlBinding.EncodeAsync(
            new PreservationAsicExtensionEncodeContext { Payload = submitter, Critical = true },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        try
        {
            AsicManifest extended = manifests[0].Manifest! with { Extensions = [encoded.Extension!] };

            PreservationContainerProfileReport report = PreservationContainerProfile.StateProfile(
                new PreservationContainerProfileContext
                {
                    Facts = read.Facts!,
                    Manifests = [Manifest(created.ManifestEntryName!, extended)]
                });

            Assert.AreEqual(PreservationContainerProfileStatus.Conformant, report.Status);
            Assert.HasCount(1, report.Manifests[0].CriticalityDepartures);

            PreservationAsicExtensionCriticality departure = report.Manifests[0].CriticalityDepartures[0];
            Assert.AreEqual(PreservationAsicExtensionKind.PreservationSubmitter, departure.Kind);
            Assert.IsTrue(departure.Critical);
            Assert.IsFalse(departure.RecommendedCritical);
            Assert.IsFalse(departure.FollowsRecommendation);
        }
        finally
        {
            DisposeAll(read, manifests);
        }
    }


    /// <summary>
    /// An extended container whose only manifest protects a time assertion carries no evidence record manifest,
    /// which requirement 2 asks for.
    /// </summary>
    [TestMethod]
    public async Task AContainerCarryingNoEvidenceRecordManifestIsRefused()
    {
        using PreservationTimestampAuthority authority = PreservationProfileSource.MintAuthority(PreservationProfileSource.InitialArchiveTime);
        List<AsicDataObject> dataObjects = PreservationProfileSource.DataObjects("first");

        using AsicContainerCreationResult created = await AsicContainerCreation.CreateTimeAssertionAsync(
            new AsicContainerTimeAssertionContext
            {
                Shape = AsicContainerShape.Extended,
                DataObjects = dataObjects,
                LastModified = TestClock.CanonicalEpoch,
                TsaUri = authority.Address,
                FetchTimestampResponse = authority.Responder.FetchAsync,
                EncodeManifest = AsicManifestXmlBinding.EncodeAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        (AsicContainerReadResult read, List<AsicManifestParseResult> manifests) =
            await PreservationProfileSource.ReadContainerAsync(created.Container.AsReadOnlyMemory(), TestContext.CancellationToken);

        try
        {
            //The source parses only evidence-record manifests, and this container carries none.
            Assert.IsEmpty(manifests);

            PreservationContainerProfileReport report = PreservationContainerProfile.StateProfile(
                new PreservationContainerProfileContext { Facts = read.Facts!, Manifests = [] });

            Assert.AreEqual(PreservationContainerProfileStatus.NoEvidenceRecordManifest, report.Status);
            Assert.IsEmpty(report.Manifests);
        }
        finally
        {
            DisposeAll(read, manifests);
        }
    }


    /// <summary>A simple container is not the extended container requirement 1 states, whichever manifests it names.</summary>
    [TestMethod]
    public async Task ASimpleContainerIsNotTheProfilesContainer()
    {
        using PreservationTimestampAuthority authority = PreservationProfileSource.MintAuthority(PreservationProfileSource.InitialArchiveTime);
        List<AsicDataObject> dataObjects = PreservationProfileSource.DataObjects("only");

        using AsicContainerCreationResult created = await AsicContainerCreation.CreateEvidenceRecordAsync(
            PreservationProfileSource.CreationContext(dataObjects, authority, shape: AsicContainerShape.Simple),
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        (AsicContainerReadResult read, List<AsicManifestParseResult> manifests) =
            await PreservationProfileSource.ReadContainerAsync(created.Container.AsReadOnlyMemory(), TestContext.CancellationToken);

        try
        {
            Assert.AreEqual(AsicContainerShape.Simple, read.Facts!.Shape);

            PreservationContainerProfileReport report = PreservationContainerProfile.StateProfile(
                new PreservationContainerProfileContext { Facts = read.Facts, Manifests = [] });

            Assert.AreEqual(PreservationContainerProfileStatus.NotExtendedContainer, report.Status);
        }
        finally
        {
            DisposeAll(read, manifests);
        }
    }


    /// <summary>The evaluation refuses to be called with nothing.</summary>
    [TestMethod]
    public void TheEvaluationRefusesNothing()
    {
        _ = Assert.ThrowsExactly<ArgumentNullException>(() => PreservationContainerProfile.StateProfile(null!));
        _ = Assert.ThrowsExactly<ArgumentNullException>(() => PreservationContainerProfile.StateCreationContext(null!));
    }


    /// <summary>
    /// States one manifest of a container as the profile evaluation takes it.
    /// </summary>
    /// <param name="entryName">The container entry the manifest was read from.</param>
    /// <param name="manifest">The parsed manifest.</param>
    /// <returns>The manifest, ready to be judged.</returns>
    private static PreservationContainerManifest Manifest(string entryName, AsicManifest manifest) =>
        new() { EntryName = entryName, Manifest = manifest };


    /// <summary>
    /// States the profile status of one manifest of a container.
    /// </summary>
    /// <param name="facts">The container's facts.</param>
    /// <param name="entryName">The entry the manifest was read from.</param>
    /// <param name="manifest">The manifest to judge.</param>
    /// <returns>The status the profile evaluation answers.</returns>
    private static PreservationContainerProfileStatus StatusOf(AsicContainerFacts facts, string entryName, AsicManifest manifest) =>
        PreservationContainerProfile.StateProfile(
            new PreservationContainerProfileContext
            {
                Facts = facts,
                Manifests = [new PreservationContainerManifest { EntryName = entryName, Manifest = manifest }]
            }).Status;


    /// <summary>
    /// Disposes what one container read produced.
    /// </summary>
    /// <param name="read">The read result, which owns the archive.</param>
    /// <param name="manifests">The parse results, each owning its manifest.</param>
    private static void DisposeAll(AsicContainerReadResult read, List<AsicManifestParseResult> manifests)
    {
        for(int i = 0; i < manifests.Count; ++i)
        {
            manifests[i].Dispose();
        }

        read.Dispose();
    }
}
