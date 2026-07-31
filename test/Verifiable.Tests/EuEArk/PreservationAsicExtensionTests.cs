using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for the seven container-extension payloads of clause 5.5 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>: their names, the criticality each of their clauses recommends, the policy a
/// consumer applies them through, and one round trip per payload through the shipped
/// <see cref="AsicManifestExtension"/> model.
/// </summary>
/// <remarks>
/// <para>
/// Every round trip goes through the seam the library declares and the worked binding staged beside these tests
/// implements, so what is exercised is the shape a caller really uses rather than a value handed straight back.
/// Each round trip asserts the criticality the payload's own clause recommends alongside the value, because the
/// criticality is the half of clause 5.5 that is new — the container specification declares the attribute and
/// states no obligation for it.
/// </para>
/// <para>
/// The canonicalization method is the odd one out on purpose: its element belongs to an external schema whose
/// namespace this repository does not hold, so it is not recognised until a caller states one, and a critical
/// extension nobody recognises stops a consumer under the shipped policy's own rule.
/// </para>
/// </remarks>
[TestClass]
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "A payload built here is either disposed by the using that holds it or handed to the encode context whose result owns the extension; a report's preservation object is owned by the payload that carries it and is disposed with it.")]
internal sealed class PreservationAsicExtensionTests
{
    /// <summary>The namespace a canonicalization method is stated under in these tests — a value a caller supplies, never one this library states.</summary>
    private static string CanonicalizationNamespace { get; } = "urn:example:canonicalization-schema";

    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = default!;


    /// <summary>Every payload the vocabulary names is classified by the element name it is written under.</summary>
    [TestMethod]
    public void EveryPayloadIsClassifiedByItsOwnElementName()
    {
        Assert.AreEqual(
            PreservationAsicExtensionKind.ContainerId,
            PreservationAsicExtensionWellKnown.KindOf(PreservationAsicExtensionWellKnown.ContainerIdExtensionName));

        Assert.AreEqual(
            PreservationAsicExtensionKind.PreservationPeriod,
            PreservationAsicExtensionWellKnown.KindOf(PreservationAsicExtensionWellKnown.PreservationPeriodExtensionName));

        Assert.AreEqual(
            PreservationAsicExtensionKind.PreservationSubmitter,
            PreservationAsicExtensionWellKnown.KindOf(PreservationAsicExtensionWellKnown.PreservationSubmitterExtensionName));

        Assert.AreEqual(
            PreservationAsicExtensionKind.IsUpdatedVersionOf,
            PreservationAsicExtensionWellKnown.KindOf(PreservationAsicExtensionWellKnown.IsUpdatedVersionOfExtensionName));

        Assert.AreEqual(
            PreservationAsicExtensionKind.ValidationReport,
            PreservationAsicExtensionWellKnown.KindOf(PreservationAsicExtensionWellKnown.ValidationReportExtensionName));

        Assert.AreEqual(
            PreservationAsicExtensionKind.IsMetaDataOf,
            PreservationAsicExtensionWellKnown.KindOf(PreservationAsicExtensionWellKnown.IsMetaDataOfExtensionName));

        //The seventh is recognised only under the namespace a caller states, because this document declares none
        //for it.
        var canonicalization = new AsicManifestExtensionName(
            CanonicalizationNamespace, PreservationAsicExtensionWellKnown.CanonicalizationMethodElementName);

        Assert.AreEqual(PreservationAsicExtensionKind.None, PreservationAsicExtensionWellKnown.KindOf(canonicalization));
        Assert.AreEqual(
            PreservationAsicExtensionKind.CanonicalizationMethod,
            PreservationAsicExtensionWellKnown.KindOf(canonicalization, CanonicalizationNamespace));
    }


    /// <summary>A name of another namespace, of another case, or absent altogether is no payload of this vocabulary.</summary>
    [TestMethod]
    public void ANameThisVocabularyDoesNotStateIsNoPayload()
    {
        Assert.AreEqual(PreservationAsicExtensionKind.None, PreservationAsicExtensionWellKnown.KindOf(null));

        Assert.AreEqual(
            PreservationAsicExtensionKind.None,
            PreservationAsicExtensionWellKnown.KindOf(new AsicManifestExtensionName("urn:example:other", "ContainerID")));

        Assert.AreEqual(
            PreservationAsicExtensionKind.None,
            PreservationAsicExtensionWellKnown.KindOf(new AsicManifestExtensionName(PreservationWellKnown.PreservationNamespace, "containerid")));

        Assert.AreEqual(
            PreservationAsicExtensionKind.None,
            PreservationAsicExtensionWellKnown.KindOf(new AsicManifestExtensionName(PreservationWellKnown.PreservationNamespace, "ContainerID ")));

        Assert.AreEqual(PreservationAsicExtensionKind.None, PreservationAsicExtensionWellKnown.KindOf(default(AsicManifestExtensionName?)));
    }


    /// <summary>Exactly one of the seven is recommended to be critical, and its clause says why.</summary>
    [TestMethod]
    [DataRow(PreservationAsicExtensionKind.ContainerId, false)]
    [DataRow(PreservationAsicExtensionKind.PreservationPeriod, false)]
    [DataRow(PreservationAsicExtensionKind.PreservationSubmitter, false)]
    [DataRow(PreservationAsicExtensionKind.IsUpdatedVersionOf, false)]
    [DataRow(PreservationAsicExtensionKind.CanonicalizationMethod, true)]
    [DataRow(PreservationAsicExtensionKind.ValidationReport, false)]
    [DataRow(PreservationAsicExtensionKind.IsMetaDataOf, false)]
    public void EachPayloadCarriesTheCriticalityItsOwnClauseRecommends(PreservationAsicExtensionKind kind, bool recommended)
    {
        Assert.AreEqual(recommended, PreservationAsicExtensionWellKnown.IsCriticalRecommended(kind));

        PreservationAsicExtensionCriticality following = PreservationAsicExtensionWellKnown.StateCriticality(kind, recommended);
        Assert.IsTrue(following.FollowsRecommendation);
        Assert.AreEqual(kind, following.Kind);

        PreservationAsicExtensionCriticality departing = PreservationAsicExtensionWellKnown.StateCriticality(kind, !recommended);
        Assert.IsFalse(departing.FollowsRecommendation);
        Assert.AreEqual(recommended, departing.RecommendedCritical);
    }


    /// <summary>A value that is not one of the seven payloads has no criticality recommendation to state.</summary>
    [TestMethod]
    public void AValueThatIsNoPayloadHasNoCriticalityRecommendation()
    {
        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => PreservationAsicExtensionWellKnown.IsCriticalRecommended(PreservationAsicExtensionKind.None));

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => PreservationAsicExtensionWellKnown.StateCriticality((PreservationAsicExtensionKind)99, critical: false));
    }


    /// <summary>Six payloads extend the manifest and the seventh extends a data object reference.</summary>
    [TestMethod]
    public void ThePlacementOfEachPayloadIsTheOneItsClauseGivesIt()
    {
        PreservationAsicExtensionKind[] manifestExtensions =
        [
            PreservationAsicExtensionKind.ContainerId,
            PreservationAsicExtensionKind.PreservationPeriod,
            PreservationAsicExtensionKind.PreservationSubmitter,
            PreservationAsicExtensionKind.IsUpdatedVersionOf,
            PreservationAsicExtensionKind.CanonicalizationMethod,
            PreservationAsicExtensionKind.ValidationReport
        ];

        foreach(PreservationAsicExtensionKind kind in manifestExtensions)
        {
            Assert.IsTrue(PreservationAsicExtensionWellKnown.IsManifestExtension(kind));
            Assert.IsFalse(PreservationAsicExtensionWellKnown.IsDataObjectReferenceExtension(kind));
        }

        Assert.IsTrue(PreservationAsicExtensionWellKnown.IsDataObjectReferenceExtension(PreservationAsicExtensionKind.IsMetaDataOf));
        Assert.IsFalse(PreservationAsicExtensionWellKnown.IsManifestExtension(PreservationAsicExtensionKind.IsMetaDataOf));
        Assert.IsFalse(PreservationAsicExtensionWellKnown.IsManifestExtension(PreservationAsicExtensionKind.None));
        Assert.IsFalse(PreservationAsicExtensionWellKnown.IsDataObjectReferenceExtension(PreservationAsicExtensionKind.None));
    }


    /// <summary>The recommended policy recognises the six this document declares and nothing else.</summary>
    [TestMethod]
    public void TheRecommendedPolicyRecognisesTheSixThisDocumentDeclares()
    {
        Assert.HasCount(6, PreservationAsicExtensionWellKnown.RecommendedPolicy.RecognizedExtensions);
        Assert.IsFalse(PreservationAsicExtensionWellKnown.RecommendedPolicy.AcceptUnrecognizedCriticalExtensions);

        Assert.Contains(
            PreservationAsicExtensionWellKnown.ContainerIdExtensionName,
            PreservationAsicExtensionWellKnown.RecommendedPolicy.RecognizedExtensions);

        AsicManifestExtensionPolicy widened =
            PreservationAsicExtensionWellKnown.RecommendedPolicyRecognizing(CanonicalizationNamespace);

        Assert.HasCount(7, widened.RecognizedExtensions);
        Assert.Contains(
            new AsicManifestExtensionName(CanonicalizationNamespace, PreservationAsicExtensionWellKnown.CanonicalizationMethodElementName),
            widened.RecognizedExtensions);

        _ = Assert.ThrowsExactly<ArgumentException>(() => PreservationAsicExtensionWellKnown.RecommendedPolicyRecognizing(string.Empty));
    }


    /// <summary>
    /// The one payload recommended to be critical is the one the recommended policy does not recognise, so an
    /// extension following that recommendation stops a consumer that never learned the external namespace.
    /// </summary>
    [TestMethod]
    public async Task ACriticalCanonicalizationMethodFromAnUnknownNamespaceFailsClosed()
    {
        using var payload = new PreservationCanonicalizationMethodExtension { Algorithm = "urn:example:canonicalization/1" };
        using PreservationAsicExtensionEncodeResult encoded = await PreservationAsicExtensionXmlBinding.EncodeAsync(
            new PreservationAsicExtensionEncodeContext
            {
                Payload = payload,
                CanonicalizationMethodNamespace = CanonicalizationNamespace
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.IsTrue(encoded.IsEncoded);
        Assert.IsTrue(encoded.Extension!.Critical, "Clause 5.5.2.5.3 recommends this extension be critical, which is what the default writes.");

        AsicManifestExtensionEvaluation refused =
            PreservationAsicExtensionWellKnown.RecommendedPolicy.Evaluate([encoded.Extension]);

        Assert.AreEqual(AsicManifestExtensionStatus.UnrecognizedCriticalExtension, refused.Status);
        Assert.AreEqual(encoded.Extension.Name, refused.RejectedExtension);

        AsicManifestExtensionEvaluation accepted =
            PreservationAsicExtensionWellKnown.RecommendedPolicyRecognizing(CanonicalizationNamespace).Evaluate([encoded.Extension]);

        Assert.AreEqual(AsicManifestExtensionStatus.Accepted, accepted.Status);
    }


    /// <summary>A canonicalization method cannot be written at all without the namespace its schema declares it in.</summary>
    [TestMethod]
    public async Task ACanonicalizationMethodIsNotWrittenUnderANamespaceThisDocumentDoesNotState()
    {
        using var payload = new PreservationCanonicalizationMethodExtension { Algorithm = "urn:example:canonicalization/1" };
        using PreservationAsicExtensionEncodeResult refused = await PreservationAsicExtensionXmlBinding.EncodeAsync(
            new PreservationAsicExtensionEncodeContext { Payload = payload },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.AreEqual(PreservationAsicExtensionEncodeStatus.CanonicalizationMethodNamespaceNotStated, refused.Status);
        Assert.IsNull(refused.Extension);
        Assert.IsNotNull(refused.FailureReason);
    }


    /// <summary>The container identifier round-trips with both of its sub-components, and with only the mandatory one.</summary>
    [TestMethod]
    public async Task TheContainerIdentifierRoundTripsThroughTheExtensionModel()
    {
        using var stated = new PreservationContainerIdExtension { PreservationObjectId = "poid-1", VersionId = "version-2" };
        using PreservationAsicExtensionParseResult read = await RoundTripAsync(stated);

        Assert.IsTrue(read.IsValid);
        var payload = (PreservationContainerIdExtension)read.Payload!;
        Assert.AreEqual("poid-1", payload.PreservationObjectId);
        Assert.AreEqual("version-2", payload.VersionId);
        Assert.IsTrue(read.Criticality.FollowsRecommendation);
        Assert.IsFalse(read.Criticality.Critical, "Clause 5.5.2.1.3 recommends the ContainerID extension not be critical.");

        using var unversioned = new PreservationContainerIdExtension { PreservationObjectId = "poid-2" };
        using PreservationAsicExtensionParseResult readUnversioned = await RoundTripAsync(unversioned);

        Assert.IsTrue(readUnversioned.IsValid);
        Assert.IsNull(((PreservationContainerIdExtension)readUnversioned.Payload!).VersionId);
    }


    /// <summary>The preservation period round-trips as a calendar date, and a value that is no date is refused.</summary>
    [TestMethod]
    public async Task ThePreservationPeriodRoundTripsAsACalendarDate()
    {
        using var stated = new PreservationPeriodExtension { Period = new DateOnly(2038, 1, 19) };
        using PreservationAsicExtensionParseResult read = await RoundTripAsync(stated);

        Assert.IsTrue(read.IsValid);
        Assert.AreEqual(new DateOnly(2038, 1, 19), ((PreservationPeriodExtension)read.Payload!).Period);
        Assert.IsFalse(read.Criticality.Critical);

        using AsicManifestExtension malformed = HandBuiltExtension(
            PreservationAsicExtensionWellKnown.PreservationPeriodElementName, "the nineteenth of January", critical: false);

        using PreservationAsicExtensionParseResult refused = await PreservationAsicExtensionXmlBinding.ParseAsync(
            new PreservationAsicExtensionParseContext { Extension = malformed },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.AreEqual(PreservationAsicExtensionParseStatus.MalformedValue, refused.Status);
        Assert.IsNull(refused.Payload);
    }


    /// <summary>The three single-value payloads round-trip verbatim.</summary>
    [TestMethod]
    public async Task TheSingleValuePayloadsRoundTripVerbatim()
    {
        using var submitter = new PreservationSubmitterExtension { Submitter = "urn:example:submitter:1" };
        using PreservationAsicExtensionParseResult readSubmitter = await RoundTripAsync(submitter);
        Assert.AreEqual("urn:example:submitter:1", ((PreservationSubmitterExtension)readSubmitter.Payload!).Submitter);
        Assert.IsFalse(readSubmitter.Criticality.Critical);

        using var updated = new PreservationIsUpdatedVersionOfExtension { Reference = "urn:example:container:1" };
        using PreservationAsicExtensionParseResult readUpdated = await RoundTripAsync(updated);
        Assert.AreEqual("urn:example:container:1", ((PreservationIsUpdatedVersionOfExtension)readUpdated.Payload!).Reference);
        Assert.IsFalse(readUpdated.Criticality.Critical);

        using var metadata = new PreservationIsMetaDataOfExtension { Reference = "data-1.txt" };
        using PreservationAsicExtensionParseResult readMetadata = await RoundTripAsync(metadata);
        Assert.AreEqual("data-1.txt", ((PreservationIsMetaDataOfExtension)readMetadata.Payload!).Reference);
        Assert.IsFalse(readMetadata.Criticality.Critical);
    }


    /// <summary>The canonicalization method round-trips under the namespace the caller states.</summary>
    [TestMethod]
    public async Task TheCanonicalizationMethodRoundTripsUnderTheStatedNamespace()
    {
        using var stated = new PreservationCanonicalizationMethodExtension { Algorithm = "urn:example:canonicalization/1" };
        using PreservationAsicExtensionEncodeResult encoded = await PreservationAsicExtensionXmlBinding.EncodeAsync(
            new PreservationAsicExtensionEncodeContext
            {
                Payload = stated,
                CanonicalizationMethodNamespace = CanonicalizationNamespace
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        using PreservationAsicExtensionParseResult read = await PreservationAsicExtensionXmlBinding.ParseAsync(
            new PreservationAsicExtensionParseContext
            {
                Extension = encoded.Extension!,
                CanonicalizationMethodNamespace = CanonicalizationNamespace
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.IsTrue(read.IsValid);
        Assert.AreEqual("urn:example:canonicalization/1", ((PreservationCanonicalizationMethodExtension)read.Payload!).Algorithm);
        Assert.IsTrue(read.Criticality.Critical);
        Assert.IsTrue(read.Criticality.FollowsRecommendation);

        //Without the namespace the reader has no way to know what the element is, and says so rather than
        //guessing from the local name.
        using PreservationAsicExtensionParseResult unrecognised = await PreservationAsicExtensionXmlBinding.ParseAsync(
            new PreservationAsicExtensionParseContext { Extension = encoded.Extension! },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.AreEqual(PreservationAsicExtensionParseStatus.PayloadNotRecognized, unrecognised.Status);
    }


    /// <summary>The validation report round-trips as the preservation object clause 5.4.5 makes it, octet for octet.</summary>
    [TestMethod]
    public async Task TheValidationReportRoundTripsAsAPreservationObject()
    {
        byte[] reportOctets = Encoding.UTF8.GetBytes("<ValidationReport>total-passed</ValidationReport>");
        using var stated = new PreservationValidationReportExtension
        {
            Report = new PreservationObject
            {
                Content = PooledMemory.FromBytes(reportOctets, BaseMemoryPool.Shared, PreservationTags.PreservationObject),
                ContentForm = PreservationContentForm.BinaryData,
                MimeType = "application/xml"
            }
        };

        using PreservationAsicExtensionParseResult read = await RoundTripAsync(stated);

        Assert.IsTrue(read.IsValid);
        var payload = (PreservationValidationReportExtension)read.Payload!;
        Assert.AreEqual("application/xml", payload.Report.MimeType);
        Assert.AreEqual(PreservationContentForm.BinaryData, payload.Report.ContentForm);
        Assert.IsTrue(reportOctets.AsSpan().SequenceEqual(payload.Report.Content.AsReadOnlySpan()));
        Assert.IsFalse(read.Criticality.Critical);
    }


    /// <summary>A report stating neither a format identifier nor a media type is one no conformant document can carry.</summary>
    [TestMethod]
    public async Task AValidationReportStatingNeitherFormatNorMediaTypeIsRefused()
    {
        using var stated = new PreservationValidationReportExtension
        {
            Report = new PreservationObject
            {
                Content = PooledMemory.FromBytes("report"u8, BaseMemoryPool.Shared, PreservationTags.PreservationObject),
                ContentForm = PreservationContentForm.BinaryData
            }
        };

        using PreservationAsicExtensionEncodeResult refused = await PreservationAsicExtensionXmlBinding.EncodeAsync(
            new PreservationAsicExtensionEncodeContext { Payload = stated },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.AreEqual(PreservationAsicExtensionEncodeStatus.MissingRequiredElement, refused.Status);
        Assert.IsNull(refused.Extension);
    }


    /// <summary>A caller may depart from the recommendation, and the departure is what the parse reports.</summary>
    [TestMethod]
    public async Task ADepartureFromTheRecommendedCriticalityIsCarriedAndReported()
    {
        using var stated = new PreservationSubmitterExtension { Submitter = "urn:example:submitter:2" };
        using PreservationAsicExtensionEncodeResult encoded = await PreservationAsicExtensionXmlBinding.EncodeAsync(
            new PreservationAsicExtensionEncodeContext { Payload = stated, Critical = true },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.IsTrue(encoded.Extension!.Critical);

        using PreservationAsicExtensionParseResult read = await PreservationAsicExtensionXmlBinding.ParseAsync(
            new PreservationAsicExtensionParseContext { Extension = encoded.Extension },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.IsTrue(read.IsValid);
        Assert.IsTrue(read.Criticality.Critical);
        Assert.IsFalse(read.Criticality.RecommendedCritical);
        Assert.IsFalse(read.Criticality.FollowsRecommendation);
    }


    /// <summary>An extension the vocabulary does not name is reported as unrecognised rather than as malformed.</summary>
    [TestMethod]
    public async Task AnExtensionThisVocabularyDoesNotNameIsUnrecognisedRatherThanMalformed()
    {
        using AsicManifestExtension foreign = HandBuiltExtension("SomethingElse", "value", critical: false, "urn:example:other");

        using PreservationAsicExtensionParseResult read = await PreservationAsicExtensionXmlBinding.ParseAsync(
            new PreservationAsicExtensionParseContext { Extension = foreign },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.AreEqual(PreservationAsicExtensionParseStatus.PayloadNotRecognized, read.Status);
        Assert.IsNull(read.Payload);
    }


    /// <summary>Hostile octets are refused by status, and neither a document type definition nor an external entity is processed.</summary>
    [TestMethod]
    [DataRow("not markup at all", PreservationAsicExtensionParseStatus.Malformed, DisplayName = "not markup")]
    [DataRow("<Extension Critical=\"false\">", PreservationAsicExtensionParseStatus.Malformed, DisplayName = "truncated")]
    [DataRow("<Other xmlns=\"http://uri.etsi.org/02918/v1.2.1#\" Critical=\"false\"/>", PreservationAsicExtensionParseStatus.Malformed, DisplayName = "wrong root element")]
    [DataRow("<Extension xmlns=\"urn:example:other\" Critical=\"false\"/>", PreservationAsicExtensionParseStatus.Malformed, DisplayName = "wrong namespace")]
    [DataRow("<!DOCTYPE Extension [<!ENTITY x \"y\">]><Extension xmlns=\"http://uri.etsi.org/02918/v1.2.1#\" Critical=\"false\"/>", PreservationAsicExtensionParseStatus.Malformed, DisplayName = "document type definition")]
    [DataRow("<!DOCTYPE Extension [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><Extension xmlns=\"http://uri.etsi.org/02918/v1.2.1#\" Critical=\"false\">&x;</Extension>", PreservationAsicExtensionParseStatus.Malformed, DisplayName = "external entity")]
    [DataRow("<Extension xmlns=\"http://uri.etsi.org/02918/v1.2.1#\" Critical=\"false\"/>", PreservationAsicExtensionParseStatus.PayloadNotRecognized, DisplayName = "no content element")]
    public async Task HostileOctetsAreRefusedByStatus(string document, PreservationAsicExtensionParseStatus expected)
    {
        using PooledMemory octets = PooledMemory.FromBytes(
            Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, PreservationTags.AsicExtension);

        using var extension = new AsicManifestExtension
        {
            Critical = false,
            Content = PooledMemory.FromBytes(octets.AsReadOnlySpan(), BaseMemoryPool.Shared, PreservationTags.AsicExtension)
        };

        using PreservationAsicExtensionParseResult read = await PreservationAsicExtensionXmlBinding.ParseAsync(
            new PreservationAsicExtensionParseContext { Extension = extension },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.AreEqual(expected, read.Status);
        Assert.IsNull(read.Payload);
        Assert.IsNotNull(read.FailureReason);
    }


    /// <summary>Each of the three bounds refuses what lies beyond it.</summary>
    [TestMethod]
    public async Task EachBoundRefusesWhatLiesBeyondIt()
    {
        Assert.AreEqual(1_048_576, PreservationAsicExtensionLimits.Conformant.MaximumExtensionByteLength);
        Assert.AreEqual(4_096, PreservationAsicExtensionLimits.Conformant.MaximumValueLength);
        Assert.AreEqual(16, PreservationAsicExtensionLimits.Conformant.MaximumDepth);

        using var payload = new PreservationSubmitterExtension { Submitter = new string('s', 64) };
        using PreservationAsicExtensionEncodeResult tooLarge = await PreservationAsicExtensionXmlBinding.EncodeAsync(
            new PreservationAsicExtensionEncodeContext
            {
                Payload = payload,
                Limits = new PreservationAsicExtensionLimits { MaximumExtensionByteLength = 16 }
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.AreEqual(PreservationAsicExtensionEncodeStatus.LimitExceeded, tooLarge.Status);

        using PreservationAsicExtensionEncodeResult encoded = await PreservationAsicExtensionXmlBinding.EncodeAsync(
            new PreservationAsicExtensionEncodeContext { Payload = payload },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        using PreservationAsicExtensionParseResult overOctets = await PreservationAsicExtensionXmlBinding.ParseAsync(
            new PreservationAsicExtensionParseContext
            {
                Extension = encoded.Extension!,
                Limits = new PreservationAsicExtensionLimits { MaximumExtensionByteLength = 8 }
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.AreEqual(PreservationAsicExtensionParseStatus.LimitExceeded, overOctets.Status);

        using PreservationAsicExtensionParseResult overValue = await PreservationAsicExtensionXmlBinding.ParseAsync(
            new PreservationAsicExtensionParseContext
            {
                Extension = encoded.Extension!,
                Limits = new PreservationAsicExtensionLimits { MaximumValueLength = 4 }
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.AreEqual(PreservationAsicExtensionParseStatus.LimitExceeded, overValue.Status);

        using PreservationAsicExtensionParseResult overDepth = await PreservationAsicExtensionXmlBinding.ParseAsync(
            new PreservationAsicExtensionParseContext
            {
                Extension = encoded.Extension!,
                Limits = new PreservationAsicExtensionLimits { MaximumDepth = 1 }
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.AreEqual(PreservationAsicExtensionParseStatus.LimitExceeded, overDepth.Status);
    }


    /// <summary>No status this stage declares reads as a success when it has not been computed.</summary>
    [TestMethod]
    public void NoUncomputedStatusReadsAsSuccess()
    {
        Assert.AreEqual(nameof(PreservationAsicExtensionKind.None), Enum.GetName(default(PreservationAsicExtensionKind)));
        Assert.AreEqual(nameof(PreservationAsicExtensionEncodeStatus.NotEvaluated), Enum.GetName(default(PreservationAsicExtensionEncodeStatus)));
        Assert.AreEqual(nameof(PreservationAsicExtensionParseStatus.NotEvaluated), Enum.GetName(default(PreservationAsicExtensionParseStatus)));

        using var encodeResult = new PreservationAsicExtensionEncodeResult { Status = default };
        Assert.IsFalse(encodeResult.IsEncoded);

        using var parseResult = new PreservationAsicExtensionParseResult { Status = default };
        Assert.IsFalse(parseResult.IsValid);
        Assert.AreEqual(PreservationAsicExtensionKind.None, parseResult.Criticality.Kind);
    }


    /// <summary>
    /// Writes one payload as an extension and reads it back, which is the round trip every payload test performs.
    /// </summary>
    /// <param name="payload">The payload to write.</param>
    /// <returns>The parse result. The caller owns and disposes it.</returns>
    private async ValueTask<PreservationAsicExtensionParseResult> RoundTripAsync(PreservationAsicExtensionPayload payload)
    {
        using PreservationAsicExtensionEncodeResult encoded = await PreservationAsicExtensionXmlBinding.EncodeAsync(
            new PreservationAsicExtensionEncodeContext { Payload = payload },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.IsTrue(encoded.IsEncoded, $"The payload '{payload.Kind}' was not written: {encoded.FailureReason}");
        Assert.AreEqual(
            PreservationAsicExtensionWellKnown.IsCriticalRecommended(payload.Kind),
            encoded.Extension!.Critical,
            "An extension written with no criticality stated carries the one its own clause recommends.");

        return await PreservationAsicExtensionXmlBinding.ParseAsync(
            new PreservationAsicExtensionParseContext { Extension = encoded.Extension },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);
    }


    /// <summary>
    /// Builds an extension by hand, for the cases a conformant encoder cannot produce.
    /// </summary>
    /// <param name="elementName">The local name of the content element.</param>
    /// <param name="value">The text the content element carries.</param>
    /// <param name="critical">The value of the <c>Critical</c> attribute.</param>
    /// <param name="elementNamespace">The namespace of the content element, or <see langword="null"/> for the protocol's own.</param>
    /// <returns>The extension. The caller owns and disposes it.</returns>
    private static AsicManifestExtension HandBuiltExtension(
        string elementName,
        string value,
        bool critical,
        string? elementNamespace = null)
    {
        string contentNamespace = elementNamespace ?? PreservationWellKnown.PreservationNamespace;
        string document = string.Concat(
            "<Extension xmlns=\"http://uri.etsi.org/02918/v1.2.1#\" Critical=\"",
            critical ? "true" : "false",
            "\"><",
            elementName,
            " xmlns=\"",
            contentNamespace,
            "\">",
            value,
            "</",
            elementName,
            "></Extension>");

        return new AsicManifestExtension
        {
            Critical = critical,
            ElementNamespace = contentNamespace,
            ElementName = elementName,
            Content = PooledMemory.FromBytes(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, PreservationTags.AsicExtension)
        };
    }
}
