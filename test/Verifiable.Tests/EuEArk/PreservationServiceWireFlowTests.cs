using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Assessment;
using Verifiable.Core.Assessment.EArchiving;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// The multi-server Kestrel wire end-to-end leg for the preservation protocol of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> (contract R-9.5): a preservation service, a Time-Stamping Authority and an OCSP
/// responder each run on their own loopback Kestrel host, and every message of the flow — a submission, a
/// discovery, two retrievals, an update whose evidence renewal reaches the authority over a real socket, a
/// validation and a trace — crosses those sockets as the document one of the two normative syntaxes of clause 5
/// states.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Host A (the preservation service)</strong> speaks the clause-5.3 vocabulary through the staged
/// <see cref="PreservationMessageXmlJsonBinding"/> in BOTH syntaxes — the flow deliberately alternates, so that
/// the operations exercised in XML and the operations exercised in JSON together cover the whole leg.
/// <strong>Host B (the Time-Stamping Authority)</strong> answers every <c>TimeStampReq</c> of
/// <see href="https://www.rfc-editor.org/rfc/rfc3161#section-3.4">IETF RFC 3161 §3.4</see> with a genuine token
/// and is reconfigured between the phases so the renewal's token can advance past the one it renews, which
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.1">IETF RFC 4998 clause 5.1</see> requires.
/// <strong>Host C (the OCSP responder)</strong> answers every <c>OCSPRequest</c> of
/// <see href="https://www.rfc-editor.org/rfc/rfc6960#appendix-A">IETF RFC 6960 Appendix A</see>.
/// </para>
/// <para>
/// <strong>The renewal really crosses the wire from inside the service.</strong> The service's <c>UpdatePOC</c>
/// handler composes the shipped <see cref="PreservationDigestListRenewal"/> bridge — the clause-5.6.1 hash-only
/// submission wrapper — with the wire transport, so the time-stamp request of the Hash-Tree Renewal leaves Host A
/// and arrives at Host B over a real socket.
/// </para>
/// <para>
/// <strong>The firewall is what the verifying code path reads.</strong> The verifier is handed the octets the
/// <c>RetrievePO</c> response carried and the trust anchor's octets and nothing else, and rebuilds the package,
/// its manifest, its provenance document and its preservation container from them. As in the W5 wire leg the
/// archiving party's certificates cannot be released first, because Host C must keep answering through the
/// verifier's own live revocation round trips.
/// </para>
/// </remarks>
[TestClass]
internal sealed class PreservationServiceWireFlowTests
{
    /// <summary>The <c>Content-Type</c> RFC 3161 §3.4 gives a <c>TimeStampReq</c>.</summary>
    private const string TimestampQueryContentType = "application/timestamp-query";

    /// <summary>The <c>Content-Type</c> RFC 3161 §3.4 gives a <c>TimeStampResp</c>.</summary>
    private const string TimestampReplyContentType = "application/timestamp-reply";

    /// <summary>The <c>Content-Type</c> RFC 6960 Appendix A gives an <c>OCSPRequest</c>.</summary>
    private const string OcspRequestContentType = "application/ocsp-request";

    /// <summary>The <c>Content-Type</c> RFC 6960 Appendix A gives an <c>OCSPResponse</c>.</summary>
    private const string OcspResponseContentType = "application/ocsp-response";

    /// <summary>The media type the service's XML messages are carried under.</summary>
    private const string XmlMessageContentType = "application/xml";

    /// <summary>The media type the service's JSON messages are carried under.</summary>
    private const string JsonMessageContentType = "application/json";

    /// <summary>The media type a client states for an Information Package it submits, having no format identifier for one.</summary>
    private const string PackageMediaType = "application/zip";

    /// <summary>
    /// The major code a successful call carries. The <c>Result</c> component is defined by reference to an
    /// external base specification whose text this repository does not hold, so
    /// <see cref="PreservationResultWellKnown"/> deliberately enumerates the seventeen MINOR codes and no major
    /// one; a peer's major code is carried verbatim, and these three are the values this test's service sends.
    /// </summary>
    private static string SuccessResultMajor { get; } = "urn:oasis:names:tc:dss:1.0:resultmajor:Success";

    /// <summary>The major code a call refused because of what the client asked carries.</summary>
    private static string RequesterErrorResultMajor { get; } = "urn:oasis:names:tc:dss:1.0:resultmajor:RequesterError";

    /// <summary>The major code a call refused because of the service's own state carries.</summary>
    private static string ResponderErrorResultMajor { get; } = "urn:oasis:names:tc:dss:1.0:resultmajor:ResponderError";


    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// The whole preservation flow over three Kestrel hosts, in both syntaxes, ending in a verifying party that
    /// reconstructs the Archival Information Package from the octets one response carried.
    /// </summary>
    /// <returns>A task that completes when the received package and the renewed evidence have been judged.</returns>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "authorityMinted.Certificate/.Key ownership transfers immediately into the X509ChainTestRingNode wrapping them; MintedCertificate itself holds no resource beyond those two properties.")]
    public async Task PreserveDiscoverRetrieveRenewValidateAndTraceAcrossThreeKestrelHosts()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        DateTimeOffset signingTime = timeProvider.GetUtcNow();
        DateTimeOffset timestampTime = signingTime.AddHours(1);
        DateTimeOffset renewalTime = signingTime.AddHours(2);
        DateTimeOffset validationTime = signingTime.AddDays(30);
        DateTimeOffset notBefore = signingTime.AddYears(-1);
        DateTimeOffset notAfter = signingTime.AddYears(9);
        DateTimeOffset revocationThisUpdate = signingTime.AddMinutes(-30);
        DateTimeOffset revocationNextUpdate = signingTime.AddYears(1);

        //Host C (OCSP) starts first: every certificate below needs its real address baked into an Authority
        //Information Access entry before it can be minted.
        var ocspAdapter = new BinaryOcspHostAdapter();
        await using BinaryHttpHost ocspHost = await BinaryHttpHost.StartAsync(
            ocspAdapter.HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        string ocspResponderUri = new Uri(ocspHost.BaseAddress, "/ocsp").AbsoluteUri;
        X509Extension aia = OcspTestFixtures.CreateAuthorityInfoAccessExtension(
            OcspTestFixtures.UriAiaEntry(WellKnownOids.AccessMethodOcsp, ocspResponderUri));

        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: notBefore, notAfter: notAfter);

        var timeStampingEku = new X509EnhancedKeyUsageExtension(
            [new System.Security.Cryptography.Oid(X509ChainTestRing.TimeStampingKeyPurposeOid)], critical: true);
        MintedCertificate authorityMinted = OcspTestFixtures.MintCertificate(
            root.Certificate, root.SigningKey, "eark-wire-tsa.example.test", notBefore, notAfter, [timeStampingEku, aia]);
        using X509ChainTestRingNode authority = new(X509ChainNodeRole.Leaf, authorityMinted.Certificate, authorityMinted.Key);

        using MintedCertificate signerMinted = OcspTestFixtures.MintCertificate(
            root.Certificate, root.SigningKey, "eark-wire-signer.example.test", notBefore, notAfter, [aia]);
        using X509ChainTestRingNode signer = new(X509ChainNodeRole.Leaf, signerMinted.Certificate, signerMinted.Key);

        ocspAdapter.Configure(new MintingOcspResponder(
            [signerMinted.Certificate, authority.Certificate], root.Certificate, root.Certificate, root.SigningKey,
            OcspCertificateStatus.Good, revocationThisUpdate, revocationNextUpdate).FetchAsync);

        //Host B (TSA), reconfigured between the phases so that the renewal's token advances past the one it renews.
        var tsaAdapter = new BinaryTsaHostAdapter();
        await using BinaryHttpHost tsaHost = await BinaryHttpHost.StartAsync(
            tsaAdapter.HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        string tsaUri = new Uri(tsaHost.BaseAddress, "/tsa").AbsoluteUri;

        using HttpClient tsaHttpClient = LoopbackTls.CreatePinnedHttpClient(tsaHost.Certificate);
        using HttpClient ocspHttpClient = LoopbackTls.CreatePinnedHttpClient(ocspHost.Certificate);
        var wireTsa = new WireTimestampTransport(tsaHttpClient);
        var wireOcsp = new WireOcspTransport(ocspHttpClient);

        tsaAdapter.Configure(new MintingTimestampResponder(authority, [authority, root], timestampTime).FetchAsync);

        //=== The archiving party builds the package, taking the signer's revocation status over Host C and every
        //time-stamp over Host B. ===
        using PkiCertificateMemory signerCertificate = OcspTestFixtures.ToCertificateCarrier(signerMinted.Certificate);
        using PkiCertificateMemory rootCertificate = OcspTestFixtures.ToCertificateCarrier(root.Certificate);

        var mintTimeRevocationChecker = new OcspRevocationChecker(wireOcsp.FetchAsync);
        using RetainedOcspResponse retained = await mintTimeRevocationChecker.CheckRetainingResponseAsync(
            signerCertificate, [rootCertificate], revocationThisUpdate.AddMinutes(5), BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Good, retained.Status,
            "The signer's certificate is Good, decided through a real OCSPRequest/OCSPResponse round trip against Host C.");

        using EArkCapstonePackage package = await EArkCapstoneSource.MintAsync(
            new EArkCapstoneMintContext
            {
                Signer = signer,
                SignerCertificate = signerCertificate,
                ValidationMaterial = new CAdESValidationMaterial
                {
                    Certificates = [rootCertificate],
                    OcspResponses = [retained.Response!]
                },
                TsaUri = tsaUri,
                FetchTimestampResponse = wireTsa.FetchAsync,
                SigningTime = signingTime,
                PackageInstant = signingTime,
                MetadataInstant = signingTime,
                TimestampGenerationTime = timestampTime,
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        byte[] submitted = package.ArchiveBytes();

        //=== Host A: the preservation service, speaking the clause-5.3 vocabulary over both syntaxes. ===
        var service = new PreservationServiceHost(tsaUri, wireTsa.FetchAsync, timeProvider);
        await using BinaryHttpHost serviceHost = await BinaryHttpHost.StartAsync(
            service.HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient serviceHttpClient = LoopbackTls.CreatePinnedHttpClient(serviceHost.Certificate);
        var client = new PreservationServiceClient(serviceHttpClient, serviceHost.BaseAddress);

        //--- PreservePO, in the XML syntax. ---
        using PreservePreservationObjectRequest submission = new()
        {
            RequestId = "request-preserve",
            ProfileIdentifier = PreservationServiceHost.ProfileIdentifier,
            PreservationObjects =
            [
                new PreservationObject
                {
                    Content = PooledMemory.FromBytes(submitted, BaseMemoryPool.Shared, PreservationTags.PreservationObject),
                    ContentForm = PreservationContentForm.BinaryData,
                    MimeType = PackageMediaType
                }
            ]
        };

        using PreservePreservationObjectResponse preserved = await client.CallAsync<PreservePreservationObjectRequest, PreservePreservationObjectResponse>(
            submission, PreservationMessageKind.PreservePreservationObjectResponse, PreservationSyntax.Xml, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SuccessResultMajor, preserved.Result.ResultMajor,
            "Clause 5.3.3.2.1: a submission a service stores answers with the success major code.");
        Assert.AreEqual("request-preserve", preserved.RequestId, "Clause 5.3.1.1: a service that received a request identifier returns it.");
        Assert.IsNotNull(preserved.PreservationObjectId, "Clause 5.3.3.2.1: a service that stores states the identifier later calls address the submission by.");

        string preservationObjectId = preserved.PreservationObjectId!;

        //--- RetrieveInfo, in the JSON syntax. ---
        using RetrieveInfoRequest discovery = new() { RequestId = "request-info", Status = PreservationWellKnown.ActiveStatus };
        using RetrieveInfoResponse discovered = await client.CallAsync<RetrieveInfoRequest, RetrieveInfoResponse>(
            discovery, PreservationMessageKind.RetrieveInfoResponse, PreservationSyntax.Json, TestContext.CancellationToken).ConfigureAwait(false);

        PreservationProfile published = discovered.Profiles.Single();
        Assert.AreEqual(PreservationServiceHost.ProfileIdentifier, published.ProfileIdentifier,
            "The profile the submission named is the profile the service publishes.");
        Assert.AreEqual(PreservationWellKnown.WithStorageModel, published.StorageModel,
            "Clause 5.3.4.1.1 permits the retrieval this flow performs only in a scheme with storage, and the profile announces one.");
        Assert.Contains(PreservationFormatWellKnown.EvidenceRecordEvidenceFormat,
            published.EvidenceFormats.Select(static format => format.FormatId).ToList(),
            "The evidence format the service produces is one it announces.");

        //--- RetrievePO for the package itself, in the XML syntax. ---
        using RetrievePreservationObjectRequest retrieval = new()
        {
            RequestId = "request-retrieve",
            PreservationObjectId = preservationObjectId,
            SubjectOfRetrieval = PreservationWellKnown.PreservationObjectSubject
        };

        using RetrievePreservationObjectResponse retrieved = await client.CallAsync<RetrievePreservationObjectRequest, RetrievePreservationObjectResponse>(
            retrieval, PreservationMessageKind.RetrievePreservationObjectResponse, PreservationSyntax.Xml, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] received = retrieved.PreservationObjects.Single().Content.AsReadOnlySpan().ToArray();
        Assert.AreSequenceEqual(submitted, received, "What came back over the wire is the package that went out over it.");

        //--- UpdatePOC, in the JSON syntax: the service renews the evidence, and its time-stamp request crosses
        //the wire to Host B at an instant later than the one the initial record asserts. ---
        tsaAdapter.Configure(new MintingTimestampResponder(authority, [authority, root], renewalTime).FetchAsync);

        using UpdatePreservationObjectContainerRequest update = new()
        {
            RequestId = "request-update",
            PreservationObjectId = preservationObjectId,
            DeltaContainers =
            [
                new PreservationObject
                {
                    Content = PooledMemory.FromBytes("the delta this update states"u8, BaseMemoryPool.Shared, PreservationTags.PreservationObject),
                    ContentForm = PreservationContentForm.BinaryData,
                    MimeType = "application/octet-stream"
                }
            ]
        };

        using UpdatePreservationObjectContainerResponse updated = await client.CallAsync<UpdatePreservationObjectContainerRequest, UpdatePreservationObjectContainerResponse>(
            update, PreservationMessageKind.UpdatePreservationObjectContainerResponse, PreservationSyntax.Json, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SuccessResultMajor, updated.Result.ResultMajor,
            $"The update, and the evidence renewal it performed over the wire, succeeded ({updated.Result.ResultMessage}).");
        Assert.IsNotNull(updated.VersionId, "Clause 5.3.6.2.1: the update states the version it produced.");

        //--- RetrievePO for the renewed evidence, in the XML syntax. ---
        using RetrievePreservationObjectRequest evidenceRetrieval = new()
        {
            RequestId = "request-evidence",
            PreservationObjectId = preservationObjectId,
            SubjectOfRetrieval = PreservationWellKnown.EvidenceSubject,
            EvidenceFormat = PreservationFormatWellKnown.EvidenceRecordEvidenceFormat
        };

        using RetrievePreservationObjectResponse evidenceRetrieved = await client.CallAsync<RetrievePreservationObjectRequest, RetrievePreservationObjectResponse>(
            evidenceRetrieval, PreservationMessageKind.RetrievePreservationObjectResponse, PreservationSyntax.Xml, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] renewedEvidence = evidenceRetrieved.PreservationObjects.Single().Content.AsReadOnlySpan().ToArray();

        using EvidenceRecord renewedRecord = EvidenceRecord.Read(renewedEvidence, BaseMemoryPool.Shared);
        Assert.HasCount(2, renewedRecord.ArchiveTimeStampSequence.Chains,
            "RFC 4998 clause 5.2 step 6: the Hash-Tree Renewal the service performed over the wire started a second chain.");

        //--- ValidateEvidence, in the XML syntax, over the evidence and the object it protects. ---
        byte[] provenance = ProvenanceOf(received, package.RootFolderName, package.ProvenanceEntryName);

        using ValidateEvidenceRequest validation = new()
        {
            RequestId = "request-validate",
            Evidence = new PreservationEvidence
            {
                Content = PooledMemory.FromBytes(renewedEvidence, BaseMemoryPool.Shared, PreservationTags.PreservationEvidence),
                ContentForm = PreservationContentForm.BinaryData,
                FormatId = PreservationFormatWellKnown.EvidenceRecordEvidenceFormat,
                PreservationObjectId = preservationObjectId
            },
            PreservationObjects =
            [
                new PreservationObject
                {
                    Content = PooledMemory.FromBytes(provenance, BaseMemoryPool.Shared, PreservationTags.PreservationObject),
                    ContentForm = PreservationContentForm.BinaryData,
                    MimeType = "text/xml"
                }
            ]
        };

        using ValidateEvidenceResponse validated = await client.CallAsync<ValidateEvidenceRequest, ValidateEvidenceResponse>(
            validation, PreservationMessageKind.ValidateEvidenceResponse, PreservationSyntax.Xml, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SuccessResultMajor, validated.Result.ResultMajor,
            $"The renewed evidence proves the object it was submitted with ({validated.Result.ResultMessage}).");
        Assert.AreEqual(timestampTime, validated.ProofOfExistence,
            "Clause 5.3.8.2.1: the proof of existence is the instant the record's INITIAL archive time-stamp asserts, not the renewal's.");

        //--- RetrieveTrace, in the JSON syntax. ---
        using RetrieveTraceRequest traceRequest = new() { RequestId = "request-trace", PreservationObjectId = preservationObjectId };
        using RetrieveTraceResponse trace = await client.CallAsync<RetrieveTraceRequest, RetrieveTraceResponse>(
            traceRequest, PreservationMessageKind.RetrieveTraceResponse, PreservationSyntax.Json, TestContext.CancellationToken).ConfigureAwait(false);

        List<string> operations = [.. trace.Trace.Events.Select(static recorded => recorded.Operation)];
        Assert.AreSequenceEqual(
            new[]
            {
                PreservationWellKnown.PreservePreservationObjectOperation,
                PreservationWellKnown.RetrievePreservationObjectOperation,
                PreservationWellKnown.UpdatePreservationObjectContainerOperation,
                PreservationWellKnown.RetrievePreservationObjectOperation,
                PreservationWellKnown.ValidateEvidenceOperation
            },
            operations,
            "The trace records what the service did to this preservation object, in the order it did it.");

        //=== The verifying party: it reads the octets one response carried and the trust anchor's octets, and
        //decides revocation through its own live round trips to Host C. ===
        var verifyTimeRevocationChecker = new OcspRevocationChecker(wireOcsp.FetchAsync);
        using ReconstructedEArkVerifyingParty verifier = await ReconstructedEArkVerifyingParty.CreateAsync(
            received,
            root.Certificate.RawData,
            package.ContainerEntryName,
            package.ProvenanceEntryName,
            validationTime,
            verifyTimeRevocationChecker.CheckAsync,
            TestContext.CancellationToken).ConfigureAwait(false);

        PreservationContainerProfileReport profile = PreservationContainerProfile.StateProfile(verifier.ProfileContext());
        Assert.AreEqual(PreservationContainerProfileStatus.Conformant, profile.Status,
            "Annex A.3.1.3: what the wire delivered is still the preservation object container profile's container.");

        using AsicContainerValidationResult container = await AsicContainerValidation.ValidateAsync(
            verifier.ContainerValidationContext(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AsicContainerValidationStatus.Valid, container.Status,
            $"The container validates from the octets the retrieval carried ({container.FailureReason}).");
        Assert.AreEqual(SignatureValidationIndication.TotalPassed, container.Signatures.Single().Outcome!.Conclusion.Indication,
            "The embedded CAdES object reaches TOTAL-PASSED with revocation decided by a live OCSP round trip over a real socket.");
        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, container.EvidenceRecords.Single().VerificationStatus,
            "RFC 4998 clause 4.3 still holds over the octets that crossed the wire.");

        verifier.StateArtifactFacts(package.ContainerEntryName, [.. container.EvidenceRecords.Single().ProtectedEntryNames]);
        ClaimIssueResult claims = await RunAsync(verifier.ValidationContext()).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(claims, EArkClaimIds.PackageFixityRecomputed, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(claims, EArkClaimIds.PackageEvidencePlacement, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(claims, PreservationClaimIds.Ovr92Item04, ClaimOutcome.Success, EArkClaimReason.RequirementMet);

        //The renewed evidence, verified by the verifying party itself over the provenance document it rebuilt
        //from the archive — and its self-description is now protected, which is what a Hash-Tree Renewal does to
        //an attribute of the chain it renews (OVR-9.2-05).
        using EvidenceRecordVerification renewedVerification = await EvidenceRecords.VerifyAsync(
            new EvidenceRecordVerificationContext
            {
                EvidenceRecord = renewedRecord,
                DataObject = verifier.Snapshot.FindEntry(package.ProvenanceEntryName)!.Content.AsReadOnlyMemory()
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, renewedVerification.Status,
            "The evidence the service renewed over the wire still proves the provenance document the package holds.");
        Assert.AreEqual(timestampTime, renewedVerification.InitialArchiveTime);
        Assert.AreEqual(renewalTime, renewedVerification.LatestArchiveTime,
            "The renewal's own token is the one Host B minted at the later instant it was reconfigured to.");

        EArkEvidenceSelfDescription? selfDescription = PreservationEvidenceAttributes.ReadSelfDescription(renewedRecord);
        Assert.IsNotNull(selfDescription, "The Annex H attributes the initial record carried were carried forward by the renewal.");
        Assert.AreEqual(EArkCapstoneSource.SelfDescription.EvidencePolicyIdentifier, selfDescription!.EvidencePolicyIdentifier);

        EArkValidationContext renewedContext = verifier.ValidationContext() with
        {
            EvidenceArtifacts =
            [
                verifier.Artifact with { SelfDescriptionIsProtected = renewedRecord.ArchiveTimeStampSequence.Chains.Count > 1 }
            ]
        };

        ClaimIssueResult renewedClaims = await RunAsync(renewedContext).ConfigureAwait(false);
        EArkStructuralRuleTests.AssertOutcome(renewedClaims, PreservationClaimIds.Ovr92Item05, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
    }


    /// <summary>
    /// Negative leg over the same socket: a document that is a conformant message of one operation, submitted to
    /// the endpoint of another, is refused rather than reinterpreted — which is the whole reason
    /// <see cref="PreservationMessageParseStatus.UnexpectedMessage"/> exists, the wire carrying no discriminator
    /// a reader may trust before parsing.
    /// </summary>
    /// <returns>A task that completes when the refusal has been observed.</returns>
    [TestMethod]
    public async Task AMessageOfOneOperationSubmittedToAnotherIsRefusedOverTheWire()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        var service = new PreservationServiceHost("https://unused.example.test/tsa", NoTimestampAuthority, timeProvider);
        await using BinaryHttpHost serviceHost = await BinaryHttpHost.StartAsync(
            service.HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient serviceHttpClient = LoopbackTls.CreatePinnedHttpClient(serviceHost.Certificate);

        using RetrieveTraceRequest trace = new() { PreservationObjectId = "po-1" };
        using PreservationMessageEncodeResult encoded = await PreservationMessageXmlJsonBinding.EncodeAsync(
            new PreservationMessageEncodeContext { Message = trace, Syntax = PreservationSyntax.Xml },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(encoded.IsEncoded, encoded.FailureReason);

        using var content = new ByteArrayContent(encoded.Document!.AsReadOnlySpan().ToArray());
        content.Headers.ContentType = new MediaTypeHeaderValue(XmlMessageContentType);
        using HttpResponseMessage response = await serviceHttpClient.PostAsync(
            new Uri(serviceHost.BaseAddress, "/xml/" + PreservationWellKnown.ValidateEvidenceOperation),
            content,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode,
            "A trace request submitted to the validation endpoint is a refusal, not a validation of whatever could be read out of it.");
    }


    /// <summary>Runs the whole archival rule list over one context.</summary>
    /// <param name="context">The package validation is given.</param>
    /// <returns>What the issuer concluded.</returns>
    private async Task<ClaimIssueResult> RunAsync(EArkValidationContext context)
    {
        var issuer = new ClaimIssuer<EArkValidationContext>(
            "eark-wire-validator",
            [.. EArkValidationProfiles.ArchivalPackageRules()],
            new FakeTimeProvider(TestClock.CanonicalEpoch));

        return await issuer.GenerateClaimsAsync(context, "eark-wire-validation", TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Reads the digital-provenance document out of a package archive that crossed the wire.</summary>
    /// <param name="archive">The archive's octets.</param>
    /// <param name="rootFolderName">The root folder the archive unpacks to.</param>
    /// <param name="provenanceEntryName">The entry name the document sits under.</param>
    /// <returns>The document's octets.</returns>
    private static byte[] ProvenanceOf(byte[] archive, string rootFolderName, string provenanceEntryName)
    {
        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.ReadArchive(
            archive, EArkPackageLimits.Conformant, BaseMemoryPool.Shared);
        if(read.Snapshot is null)
        {
            throw new InvalidOperationException($"The received archive has to read as an Information Package ({read.Status}).");
        }

        _ = rootFolderName;

        return read.Snapshot.FindEntry(provenanceEntryName)!.Content.AsReadOnlySpan().ToArray();
    }


    /// <summary>
    /// The transport a service with no authority is given: it answers nothing, because the negative leg never
    /// reaches a renewal.
    /// </summary>
    /// <param name="context">The authority address and the request bytes.</param>
    /// <param name="pool">The memory pool the response would be rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>Always <see langword="null"/>.</returns>
    private static ValueTask<PkiCertificateMemory?> NoTimestampAuthority(
        TimestampFetchContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken) => ValueTask.FromResult<PkiCertificateMemory?>(null);


    /// <summary>
    /// The preservation service: a store, a trace and the six operation seams this flow exercises, bridged to a
    /// <see cref="BinaryHttpHost"/> that routes by the syntax and the operation the path names.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A configured object holding its own state and its own transport, never a closure over test state — the
    /// discipline every seam of this namespace states. Which syntax a call uses is the path's first segment and
    /// which operation it is the second, because clause 5.1 asserts a binding to two transports and gives neither
    /// in its body: a routing scheme is the caller's, and this one is stated rather than assumed.
    /// </para>
    /// <para>
    /// <strong>The renewal is the shipped bridge.</strong> <c>UpdatePOC</c> composes
    /// <see cref="PreservationDigestListRenewal.RenewAsync"/> — the clause-5.6.1 <c>DigestList</c> wrapper over
    /// the shipped Hash-Tree Renewal — with the wire transport, so this service adds no Evidence Record logic of
    /// its own.
    /// </para>
    /// </remarks>
    private sealed class PreservationServiceHost
    {
        /// <summary>The identifier of the one profile this service publishes.</summary>
        internal static string ProfileIdentifier { get; } = "https://preservation.example.test/profile/eark-ers";

        /// <summary>The packages this service stores, by preservation object identifier.</summary>
        private readonly Dictionary<string, byte[]> packages = new(StringComparer.Ordinal);

        /// <summary>The evidence this service holds, by preservation object identifier.</summary>
        private readonly Dictionary<string, byte[]> evidences = new(StringComparer.Ordinal);

        /// <summary>The versions this service has produced, by preservation object identifier.</summary>
        private readonly Dictionary<string, int> versions = new(StringComparer.Ordinal);

        /// <summary>The events this service has recorded, by preservation object identifier.</summary>
        private readonly Dictionary<string, List<PreservationEvent>> traces = new(StringComparer.Ordinal);

        /// <summary>The Time-Stamping Authority address this service renews against.</summary>
        private readonly string tsaUri;

        /// <summary>The transport this service reaches that authority over.</summary>
        private readonly FetchTimestampResponseAsyncDelegate fetchTimestampResponse;

        /// <summary>The clock this service stamps its trace events with.</summary>
        private readonly TimeProvider timeProvider;

        /// <summary>How many submissions this service has stored, which is what its identifiers count.</summary>
        private int stored;


        /// <summary>Initializes a service reaching one authority over one transport.</summary>
        /// <param name="tsaUri">The authority's address.</param>
        /// <param name="fetchTimestampResponse">The transport the authority is reached over.</param>
        /// <param name="timeProvider">The clock the trace's events are stamped with.</param>
        internal PreservationServiceHost(
            string tsaUri,
            FetchTimestampResponseAsyncDelegate fetchTimestampResponse,
            TimeProvider timeProvider)
        {
            this.tsaUri = tsaUri;
            this.fetchTimestampResponse = fetchTimestampResponse;
            this.timeProvider = timeProvider;
        }


        /// <summary>Implements <see cref="BinaryHttpHandlerDelegate"/>.</summary>
        /// <param name="request">The buffered request.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The response.</returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "Every message and every encode result this handler builds is released by its using declaration before the octets are copied into the response.")]
        internal async Task<BinaryHttpResponse> HandleAsync(BinaryHttpRequest request, CancellationToken cancellationToken)
        {
            string[] segments = request.Path.Split('/', StringSplitOptions.RemoveEmptyEntries);
            if(segments.Length != 2)
            {
                return new BinaryHttpResponse { StatusCode = 404 };
            }

            PreservationSyntax syntax = string.Equals(segments[0], "xml", StringComparison.Ordinal)
                ? PreservationSyntax.Xml
                : string.Equals(segments[0], "json", StringComparison.Ordinal) ? PreservationSyntax.Json : PreservationSyntax.NotEvaluated;

            if(syntax == PreservationSyntax.NotEvaluated || !TryStateKinds(segments[1], out PreservationMessageKind requestKind))
            {
                return new BinaryHttpResponse { StatusCode = 404 };
            }

            using PooledMemory document = PooledMemory.FromBytes(request.Body, BaseMemoryPool.Shared, PreservationTags.OpaqueElement);
            using PreservationMessageParseResult parsed = await PreservationMessageXmlJsonBinding.ParseAsync(
                new PreservationMessageParseContext { Document = document, ExpectedKind = requestKind, Syntax = syntax },
                BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false);

            if(!parsed.IsValid)
            {
                return new BinaryHttpResponse { StatusCode = 400 };
            }

            using PreservationMessage response = await AnswerAsync(parsed.Message!, cancellationToken).ConfigureAwait(false);
            using PreservationMessageEncodeResult encoded = await PreservationMessageXmlJsonBinding.EncodeAsync(
                new PreservationMessageEncodeContext { Message = response, Syntax = syntax },
                BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false);

            return encoded.IsEncoded
                ? new BinaryHttpResponse
                {
                    StatusCode = 200,
                    ContentType = syntax == PreservationSyntax.Xml ? XmlMessageContentType : JsonMessageContentType,
                    Body = encoded.Document!.AsReadOnlySpan().ToArray()
                }
                : new BinaryHttpResponse { StatusCode = 500 };
        }


        /// <summary>States which request message an operation's endpoint accepts.</summary>
        /// <param name="operationName">The operation the path names.</param>
        /// <param name="requestKind">The request message that endpoint accepts.</param>
        /// <returns><see langword="true"/> when this service exposes that operation.</returns>
        private static bool TryStateKinds(string operationName, out PreservationMessageKind requestKind)
        {
            requestKind = operationName switch
            {
                var name when string.Equals(name, PreservationWellKnown.RetrieveInfoOperation, StringComparison.Ordinal) =>
                    PreservationMessageKind.RetrieveInfoRequest,
                var name when string.Equals(name, PreservationWellKnown.PreservePreservationObjectOperation, StringComparison.Ordinal) =>
                    PreservationMessageKind.PreservePreservationObjectRequest,
                var name when string.Equals(name, PreservationWellKnown.RetrievePreservationObjectOperation, StringComparison.Ordinal) =>
                    PreservationMessageKind.RetrievePreservationObjectRequest,
                var name when string.Equals(name, PreservationWellKnown.UpdatePreservationObjectContainerOperation, StringComparison.Ordinal) =>
                    PreservationMessageKind.UpdatePreservationObjectContainerRequest,
                var name when string.Equals(name, PreservationWellKnown.ValidateEvidenceOperation, StringComparison.Ordinal) =>
                    PreservationMessageKind.ValidateEvidenceRequest,
                var name when string.Equals(name, PreservationWellKnown.RetrieveTraceOperation, StringComparison.Ordinal) =>
                    PreservationMessageKind.RetrieveTraceRequest,
                _ => PreservationMessageKind.NotEvaluated
            };

            return requestKind != PreservationMessageKind.NotEvaluated;
        }


        /// <summary>Answers one parsed request.</summary>
        /// <param name="request">The request as the binding produced it.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The response. The caller disposes it.</returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "Ownership of the response transfers to the handler that called this, which disposes it with a using declaration once its octets have been written.")]
        private async ValueTask<PreservationMessage> AnswerAsync(PreservationMessage request, CancellationToken cancellationToken) => request switch
        {
            RetrieveInfoRequest discovery => Answer(discovery),
            PreservePreservationObjectRequest submission => Answer(submission),
            RetrievePreservationObjectRequest retrieval => Answer(retrieval),
            UpdatePreservationObjectContainerRequest update => await AnswerAsync(update, cancellationToken).ConfigureAwait(false),
            ValidateEvidenceRequest validation => await AnswerAsync(validation, cancellationToken).ConfigureAwait(false),
            RetrieveTraceRequest trace => Answer(trace),
            _ => throw new InvalidOperationException($"This service exposes no operation for {request.Kind}.")
        };


        /// <summary>Answers the discovery operation of clause 5.3.2 with the one profile this service publishes.</summary>
        /// <param name="request">The request.</param>
        /// <returns>The response.</returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "Ownership of the profile transfers to the response that carries it, whose own Dispose releases it.")]
        private static RetrieveInfoResponse Answer(RetrieveInfoRequest request) =>
            new()
            {
                RequestId = request.RequestId,
                Result = new PreservationResult { ResultMajor = SuccessResultMajor },
                Profiles =
                [
                    new PreservationProfile
                    {
                        ProfileIdentifier = ProfileIdentifier,
                        Operations =
                        [
                            new PreservationOperationDescriptor { Name = PreservationWellKnown.RetrieveInfoOperation },
                            new PreservationOperationDescriptor { Name = PreservationWellKnown.PreservePreservationObjectOperation },
                            new PreservationOperationDescriptor { Name = PreservationWellKnown.RetrievePreservationObjectOperation },
                            new PreservationOperationDescriptor { Name = PreservationWellKnown.UpdatePreservationObjectContainerOperation },
                            new PreservationOperationDescriptor { Name = PreservationWellKnown.ValidateEvidenceOperation },
                            new PreservationOperationDescriptor { Name = PreservationWellKnown.RetrieveTraceOperation }
                        ],
                        Policies = [new PreservationPolicyReference { PolicyType = PreservationWellKnown.PreservationEvidencePolicyType }],
                        ValidityPeriod = new PreservationValidityPeriod { ValidFrom = TestClock.CanonicalEpoch.AddYears(-1) },
                        StorageModel = PreservationWellKnown.WithStorageModel,
                        PreservationGoals = [PreservationWellKnown.GeneralDataGoal],
                        EvidenceFormats = [new PreservationFormatDescriptor { FormatId = PreservationFormatWellKnown.EvidenceRecordEvidenceFormat }],
                        SchemeIdentifier = PreservationWellKnown.StorageWithEvidenceRecordsScheme
                    }
                ]
            };


        /// <summary>Answers the submission operation of clause 5.3.3 by storing the package and its evidence.</summary>
        /// <param name="request">The request.</param>
        /// <returns>The response.</returns>
        private PreservePreservationObjectResponse Answer(PreservePreservationObjectRequest request)
        {
            byte[] submitted = request.PreservationObjects[0].Content.AsReadOnlySpan().ToArray();
            string identifier = string.Create(CultureInfo.InvariantCulture, $"po-{++stored}");

            packages[identifier] = submitted;
            evidences[identifier] = EvidenceOf(submitted);
            versions[identifier] = 1;
            traces[identifier] = [];
            Record(identifier, PreservationWellKnown.PreservePreservationObjectOperation, "the submitted Information Package was stored");

            return new PreservePreservationObjectResponse
            {
                RequestId = request.RequestId,
                Result = new PreservationResult { ResultMajor = SuccessResultMajor },
                PreservationObjectId = identifier
            };
        }


        /// <summary>Answers the retrieval operation of clause 5.3.4, by the subject the request states.</summary>
        /// <param name="request">The request.</param>
        /// <returns>The response.</returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "Ownership of the returned preservation object transfers to the response that carries it, whose own Dispose releases it.")]
        private RetrievePreservationObjectResponse Answer(RetrievePreservationObjectRequest request)
        {
            if(!packages.TryGetValue(request.PreservationObjectId, out byte[]? stored))
            {
                return new RetrievePreservationObjectResponse
                {
                    RequestId = request.RequestId,
                    Result = new PreservationResult
                    {
                        ResultMajor = RequesterErrorResultMajor,
                        ResultMinor = PreservationResultWellKnown.UnknownPreservationObjectIdentifier
                    }
                };
            }

            bool wantsEvidence = string.Equals(request.SubjectOfRetrieval, PreservationWellKnown.EvidenceSubject, StringComparison.Ordinal);
            byte[] payload = wantsEvidence ? evidences[request.PreservationObjectId] : stored;
            Record(
                request.PreservationObjectId,
                PreservationWellKnown.RetrievePreservationObjectOperation,
                wantsEvidence ? "the evidence was retrieved" : "the Information Package was retrieved");

            return new RetrievePreservationObjectResponse
            {
                RequestId = request.RequestId,
                Result = new PreservationResult { ResultMajor = SuccessResultMajor },
                PreservationObjects =
                [
                    new PreservationObject
                    {
                        Content = PooledMemory.FromBytes(payload, BaseMemoryPool.Shared, PreservationTags.PreservationObject),
                        ContentForm = PreservationContentForm.BinaryData,
                        FormatId = wantsEvidence ? PreservationFormatWellKnown.EvidenceRecordEvidenceFormat : null,
                        MimeType = wantsEvidence ? null : PackageMediaType,
                        Id = request.PreservationObjectId
                    }
                ]
            };
        }


        /// <summary>
        /// Answers the update operation of clause 5.3.6 by renewing the evidence — which is what a new version of
        /// a preserved container needs — through the shipped <c>DigestList</c> bridge and the wire transport.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The response.</returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "Every carrier the renewal builds is released by its using declaration; the renewed record's octets are copied into the store before the result is disposed.")]
        private async ValueTask<UpdatePreservationObjectContainerResponse> AnswerAsync(
            UpdatePreservationObjectContainerRequest request,
            CancellationToken cancellationToken)
        {
            if(!packages.TryGetValue(request.PreservationObjectId, out byte[]? stored))
            {
                return new UpdatePreservationObjectContainerResponse
                {
                    RequestId = request.RequestId,
                    Result = new PreservationResult
                    {
                        ResultMajor = RequesterErrorResultMajor,
                        ResultMinor = PreservationResultWellKnown.UnknownPreservationObjectIdentifier
                    }
                };
            }

            byte[] provenance = ProvenanceOf(stored, rootFolderName: string.Empty, EArkCapstoneSource.ProvenanceEntryName);

            using EvidenceRecord current = EvidenceRecord.Read(evidences[request.PreservationObjectId], BaseMemoryPool.Shared);
            using PreservationDigestList digestList = await PreservationProfileSource.DigestListAsync(
                [provenance],
                PkiDigestAlgorithm.Sha512,
                PreservationProfileSource.Evidence(current),
                cancellationToken).ConfigureAwait(false);

            using PreservationDigestListRenewalResult renewal = await PreservationDigestListRenewal.RenewAsync(
                new PreservationDigestListRenewalContext
                {
                    DigestList = digestList,
                    DataObjects = [provenance],
                    TsaUri = tsaUri,
                    FetchTimestampResponse = fetchTimestampResponse
                },
                BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false);

            if(!renewal.IsRenewed)
            {
                return new UpdatePreservationObjectContainerResponse
                {
                    RequestId = request.RequestId,
                    Result = new PreservationResult
                    {
                        ResultMajor = ResponderErrorResultMajor,
                        ResultMinor = PreservationResultWellKnown.InternalError,
                        ResultMessage = renewal.Status.ToString()
                    }
                };
            }

            evidences[request.PreservationObjectId] = renewal.EvidenceRecord!.AsReadOnlySpan().ToArray();
            string versionId = string.Create(CultureInfo.InvariantCulture, $"v{++versions[request.PreservationObjectId]}");
            Record(
                request.PreservationObjectId,
                PreservationWellKnown.UpdatePreservationObjectContainerOperation,
                string.Create(CultureInfo.InvariantCulture, $"{request.DeltaContainers.Count} delta(s) applied and the evidence renewed"));

            return new UpdatePreservationObjectContainerResponse
            {
                RequestId = request.RequestId,
                Result = new PreservationResult { ResultMajor = SuccessResultMajor },
                VersionId = versionId
            };
        }


        /// <summary>
        /// Answers the validation operation of clause 5.3.8 through the shipped Evidence Record verification —
        /// the one seam of the eight whose behaviour this library really has.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The response.</returns>
        private async ValueTask<ValidateEvidenceResponse> AnswerAsync(ValidateEvidenceRequest request, CancellationToken cancellationToken)
        {
            if(!string.Equals(request.Evidence.FormatId, PreservationFormatWellKnown.EvidenceRecordEvidenceFormat, StringComparison.Ordinal))
            {
                return new ValidateEvidenceResponse
                {
                    RequestId = request.RequestId,
                    Result = new PreservationResult
                    {
                        ResultMajor = RequesterErrorResultMajor,
                        ResultMinor = PreservationResultWellKnown.UnknownEvidenceFormat
                    }
                };
            }

            using EvidenceRecord record = EvidenceRecord.Read(request.Evidence.Content.AsReadOnlySpan(), BaseMemoryPool.Shared);
            using EvidenceRecordVerification verification = await EvidenceRecords.VerifyAsync(
                new EvidenceRecordVerificationContext
                {
                    EvidenceRecord = record,
                    DataObject = request.PreservationObjects[0].Content.AsReadOnlyMemory()
                },
                BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false);

            if(request.Evidence.PreservationObjectId is string identifier && traces.ContainsKey(identifier))
            {
                Record(identifier, PreservationWellKnown.ValidateEvidenceOperation, verification.Status.ToString());
            }

            return verification.Status == EvidenceRecordVerificationStatus.Verified
                ? new ValidateEvidenceResponse
                {
                    RequestId = request.RequestId,
                    Result = new PreservationResult { ResultMajor = SuccessResultMajor },
                    ProofOfExistence = verification.InitialArchiveTime
                }
                : new ValidateEvidenceResponse
                {
                    RequestId = request.RequestId,
                    Result = new PreservationResult
                    {
                        ResultMajor = RequesterErrorResultMajor,
                        ResultMinor = PreservationResultWellKnown.ParameterError,
                        ResultMessage = verification.Status.ToString()
                    }
                };
        }


        /// <summary>Answers the trace operation of clause 5.3.7 with the events this service recorded.</summary>
        /// <param name="request">The request.</param>
        /// <returns>The response.</returns>
        private RetrieveTraceResponse Answer(RetrieveTraceRequest request) =>
            traces.TryGetValue(request.PreservationObjectId, out List<PreservationEvent>? recorded)
                ? new RetrieveTraceResponse
                {
                    RequestId = request.RequestId,
                    Result = new PreservationResult { ResultMajor = SuccessResultMajor },
                    Trace = new PreservationTrace { Events = recorded }
                }
                : new RetrieveTraceResponse
                {
                    RequestId = request.RequestId,
                    Result = new PreservationResult
                    {
                        ResultMajor = RequesterErrorResultMajor,
                        ResultMinor = PreservationResultWellKnown.UnknownPreservationObjectIdentifier
                    },
                    Trace = new PreservationTrace()
                };


        /// <summary>Records one event of this service's own audit trail.</summary>
        /// <param name="identifier">The preservation object the event is about.</param>
        /// <param name="operation">The operation that was performed.</param>
        /// <param name="detail">What the service did.</param>
        private void Record(string identifier, string operation, string detail) =>
            traces[identifier].Add(new PreservationEvent
            {
                Time = timeProvider.GetUtcNow(),
                Subject = ProfileIdentifier,
                Operation = operation,
                Object = identifier,
                Detail = detail
            });


        /// <summary>Reads the Evidence Record a submitted Information Package's preservation container carries.</summary>
        /// <param name="archive">The package archive.</param>
        /// <returns>The record's octets.</returns>
        private static byte[] EvidenceOf(byte[] archive)
        {
            using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.ReadArchive(
                archive, EArkPackageLimits.Conformant, BaseMemoryPool.Shared);
            if(read.Snapshot is null)
            {
                throw new InvalidOperationException($"A submitted package has to read as an Information Package ({read.Status}).");
            }

            EArkPackageEntry containerEntry = read.Snapshot.FindEntry(EArkCapstoneSource.ContainerEntryName)
                ?? throw new InvalidOperationException("A submitted package carries no preservation container.");

            using AsicContainerReadResult container = AsicContainerReading.Read(
                containerEntry.Content.AsReadOnlyMemory(), AsicZipReadLimits.Conformant, BaseMemoryPool.Shared);
            if(!container.IsRead)
            {
                throw new InvalidOperationException($"A submitted package's container has to read ({container.Status}).");
            }

            return container.Facts!.EvidenceRecords[0].Entry.Content.AsReadOnlySpan().ToArray();
        }
    }


    /// <summary>
    /// The client side of the preservation protocol: it writes a request in the stated syntax, posts it to the
    /// endpoint the operation names, and reads the response back through the same binding.
    /// </summary>
    /// <remarks>A configured object holding the client and the address, not a closure over test state.</remarks>
    private sealed class PreservationServiceClient
    {
        /// <summary>The client, already pinned to the preservation service host's certificate.</summary>
        private readonly HttpClient httpClient;

        /// <summary>The service's base address.</summary>
        private readonly Uri baseAddress;


        /// <summary>Initializes a client over a pinned HTTP client.</summary>
        /// <param name="httpClient">The client, already pinned to the service host's certificate.</param>
        /// <param name="baseAddress">The service's base address.</param>
        internal PreservationServiceClient(HttpClient httpClient, Uri baseAddress)
        {
            this.httpClient = httpClient;
            this.baseAddress = baseAddress;
        }


        /// <summary>
        /// Performs one operation over the wire.
        /// </summary>
        /// <typeparam name="TRequest">The request message.</typeparam>
        /// <typeparam name="TResponse">The response message.</typeparam>
        /// <param name="request">The request to send. The caller retains ownership.</param>
        /// <param name="responseKind">Which message the response octets are expected to be.</param>
        /// <param name="syntax">Which of the two normative syntaxes to speak.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The response. The caller owns and disposes it.</returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "Ownership of the parsed response transfers to the caller; the parse result itself is a value the message was taken out of, and the encode result is released by its using declaration.")]
        internal async Task<TResponse> CallAsync<TRequest, TResponse>(
            TRequest request,
            PreservationMessageKind responseKind,
            PreservationSyntax syntax,
            CancellationToken cancellationToken)
            where TRequest: PreservationRequest
            where TResponse: PreservationResponse
        {
            using PreservationMessageEncodeResult encoded = await PreservationMessageXmlJsonBinding.EncodeAsync(
                new PreservationMessageEncodeContext { Message = request, Syntax = syntax },
                BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false);

            if(!encoded.IsEncoded)
            {
                throw new InvalidOperationException($"The request has to be writable ({encoded.Status}: {encoded.FailureReason}).");
            }

            string path = string.Concat(syntax == PreservationSyntax.Xml ? "/xml/" : "/json/", request.OperationName);
            using var content = new ByteArrayContent(encoded.Document!.AsReadOnlySpan().ToArray());
            content.Headers.ContentType = new MediaTypeHeaderValue(
                syntax == PreservationSyntax.Xml ? XmlMessageContentType : JsonMessageContentType);

            using HttpResponseMessage httpResponse = await httpClient.PostAsync(
                new Uri(baseAddress, path), content, cancellationToken).ConfigureAwait(false);

            if(!httpResponse.IsSuccessStatusCode)
            {
                throw new InvalidOperationException($"The service answered {(int)httpResponse.StatusCode} for '{path}'.");
            }

            byte[] body = await httpResponse.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
            using PooledMemory document = PooledMemory.FromBytes(body, BaseMemoryPool.Shared, PreservationTags.OpaqueElement);
            PreservationMessageParseResult parsed = await PreservationMessageXmlJsonBinding.ParseAsync(
                new PreservationMessageParseContext { Document = document, ExpectedKind = responseKind, Syntax = syntax },
                BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false);

            if(!parsed.IsValid)
            {
                parsed.Dispose();

                throw new InvalidOperationException($"The response has to be readable ({parsed.Status}: {parsed.FailureReason}).");
            }

            return (TResponse)parsed.Message!;
        }
    }


    /// <summary>
    /// Bridges a <see cref="BinaryHttpHost"/> to a <see cref="FetchTimestampResponseAsyncDelegate"/>-shaped
    /// responder the flow RECONFIGURES between phases, so one authority host can state a different generation
    /// time for each token the flow asks it for.
    /// </summary>
    private sealed class BinaryTsaHostAdapter
    {
        /// <summary>The responder every request is currently answered through, or <see langword="null"/> before the first configuration.</summary>
        private FetchTimestampResponseAsyncDelegate? responder;


        /// <summary>Sets the responder every subsequent request is answered through.</summary>
        /// <param name="value">The RFC 3161 responder.</param>
        internal void Configure(FetchTimestampResponseAsyncDelegate value)
        {
            responder = value;
        }


        /// <summary>Implements <see cref="BinaryHttpHandlerDelegate"/>.</summary>
        /// <param name="request">The buffered request.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The response.</returns>
        internal async Task<BinaryHttpResponse> HandleAsync(BinaryHttpRequest request, CancellationToken cancellationToken)
        {
            if(responder is not { } configured)
            {
                return new BinaryHttpResponse { StatusCode = 503 };
            }

            using PkiCertificateMemory requestCarrier = ToCarrier(request.Body, PkiCertificateTags.TimestampRequest);
            PkiCertificateMemory? response = await configured(
                new TimestampFetchContext { TsaUri = request.Path, Request = requestCarrier },
                BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            if(response is null)
            {
                return new BinaryHttpResponse { StatusCode = 502 };
            }

            using(response)
            {
                return new BinaryHttpResponse
                {
                    StatusCode = 200,
                    ContentType = TimestampReplyContentType,
                    Body = response.AsReadOnlySpan().ToArray()
                };
            }
        }
    }


    /// <summary>
    /// Bridges a <see cref="BinaryHttpHost"/> to a <see cref="FetchOcspResponseAsyncDelegate"/>-shaped responder,
    /// configured AFTER the host starts because the certificates' Authority Information Access entries need the
    /// host's real, only-known-once-bound address.
    /// </summary>
    private sealed class BinaryOcspHostAdapter
    {
        /// <summary>The responder every request is currently answered through, or <see langword="null"/> before the first configuration.</summary>
        private FetchOcspResponseAsyncDelegate? responder;


        /// <summary>Sets the responder every subsequent request is answered through.</summary>
        /// <param name="value">The RFC 6960 responder.</param>
        internal void Configure(FetchOcspResponseAsyncDelegate value)
        {
            responder = value;
        }


        /// <summary>Implements <see cref="BinaryHttpHandlerDelegate"/>.</summary>
        /// <param name="request">The buffered request.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The response.</returns>
        internal async Task<BinaryHttpResponse> HandleAsync(BinaryHttpRequest request, CancellationToken cancellationToken)
        {
            if(responder is not { } configured)
            {
                return new BinaryHttpResponse { StatusCode = 503 };
            }

            using PkiCertificateMemory requestCarrier = ToCarrier(request.Body, PkiCertificateTags.OcspRequest);
            PkiCertificateMemory? response = await configured(
                new OcspFetchContext { ResponderUri = request.Path, Request = requestCarrier },
                BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            if(response is null)
            {
                return new BinaryHttpResponse { StatusCode = 502 };
            }

            using(response)
            {
                return new BinaryHttpResponse
                {
                    StatusCode = 200,
                    ContentType = OcspResponseContentType,
                    Body = response.AsReadOnlySpan().ToArray()
                };
            }
        }
    }


    /// <summary>
    /// The client-side RFC 3161 §3.4 HTTP binding: implements <see cref="FetchTimestampResponseAsyncDelegate"/>
    /// over a real <see cref="HttpClient"/> POST.
    /// </summary>
    private sealed class WireTimestampTransport
    {
        /// <summary>The client, already pinned to the Time-Stamping Authority host's certificate.</summary>
        private readonly HttpClient httpClient;


        /// <summary>Initializes a transport over a pinned client.</summary>
        /// <param name="httpClient">The client, already pinned to the authority host's certificate.</param>
        internal WireTimestampTransport(HttpClient httpClient)
        {
            this.httpClient = httpClient;
        }


        /// <summary>Implements <see cref="FetchTimestampResponseAsyncDelegate"/>.</summary>
        /// <param name="context">The authority address and the request bytes.</param>
        /// <param name="pool">The memory pool the returned response is rented from.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The response, or <see langword="null"/> on a transport failure.</returns>
        internal async ValueTask<PkiCertificateMemory?> FetchAsync(TimestampFetchContext context, BaseMemoryPool pool, CancellationToken cancellationToken)
        {
            using var content = new ByteArrayContent(context.Request.AsReadOnlySpan().ToArray());
            content.Headers.ContentType = new MediaTypeHeaderValue(TimestampQueryContentType);

            HttpResponseMessage httpResponse;
            try
            {
                httpResponse = await httpClient.PostAsync(new Uri(context.TsaUri), content, cancellationToken).ConfigureAwait(false);
            }
            catch(HttpRequestException)
            {
                return null;
            }

            using(httpResponse)
            {
                if(!httpResponse.IsSuccessStatusCode)
                {
                    return null;
                }

                byte[] bytes = await httpResponse.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
                IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
                bytes.CopyTo(owner.Memory.Span);

                return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampResponse);
            }
        }
    }


    /// <summary>
    /// The client-side RFC 6960 Appendix A HTTP binding: implements <see cref="FetchOcspResponseAsyncDelegate"/>
    /// over a real <see cref="HttpClient"/> POST.
    /// </summary>
    private sealed class WireOcspTransport
    {
        /// <summary>The client, already pinned to the OCSP responder host's certificate.</summary>
        private readonly HttpClient httpClient;


        /// <summary>Initializes a transport over a pinned client.</summary>
        /// <param name="httpClient">The client, already pinned to the responder host's certificate.</param>
        internal WireOcspTransport(HttpClient httpClient)
        {
            this.httpClient = httpClient;
        }


        /// <summary>Implements <see cref="FetchOcspResponseAsyncDelegate"/>.</summary>
        /// <param name="context">The responder address and the request bytes.</param>
        /// <param name="pool">The memory pool the returned response is rented from.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The response, or <see langword="null"/> on a transport failure.</returns>
        internal async ValueTask<PkiCertificateMemory?> FetchAsync(OcspFetchContext context, BaseMemoryPool pool, CancellationToken cancellationToken)
        {
            using var content = new ByteArrayContent(context.Request.AsReadOnlySpan().ToArray());
            content.Headers.ContentType = new MediaTypeHeaderValue(OcspRequestContentType);

            HttpResponseMessage httpResponse;
            try
            {
                httpResponse = await httpClient.PostAsync(new Uri(context.ResponderUri), content, cancellationToken).ConfigureAwait(false);
            }
            catch(HttpRequestException)
            {
                return null;
            }

            using(httpResponse)
            {
                if(!httpResponse.IsSuccessStatusCode)
                {
                    return null;
                }

                byte[] bytes = await httpResponse.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
                IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
                bytes.CopyTo(owner.Memory.Span);

                return new PkiCertificateMemory(owner, PkiCertificateTags.OcspResponse);
            }
        }
    }


    /// <summary>Copies received DER octets into a pooled carrier of the stated kind.</summary>
    /// <param name="derBytes">The octets to copy.</param>
    /// <param name="tag">The kind discriminator the carrier states.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory ToCarrier(byte[] derBytes, Tag tag)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(derBytes.Length);
        derBytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, tag);
    }
}
