using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for the <c>DigestList</c> component of clause 5.6.1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> — the hash-only submission payload, the object-identifier uniform resource name
/// its digest method is stated as, and the composition its own NOTE describes: a submission carrying an evidence
/// record is a hash-tree renewal request.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The renewal is the shipped one and the check is independent.</strong> The evidence a submission
/// carries is a record minted by the shipped creation surface against an authority that signs real tokens; the
/// renewal is <see cref="EvidenceRecords.RenewHashTreeAsync"/>'s; and what the renewed record proves is
/// recomputed from the clause text by the independent oracle, which decodes the structures itself and hashes
/// through a different implementation than the one the surface under test uses.
/// </para>
/// <para>
/// <strong>The refusals are exercised one by one.</strong> Every way a submission can be one this library must
/// not act on — an algorithm it cannot compute, a value of the wrong length, an evidence of a format it does not
/// renew, data objects that disagree with the digest values, and the hash-only case the shipped renewal cannot
/// serve at all — has a test, because a wrapper that only ever saw agreeing input has not been shown to refuse
/// anything.
/// </para>
/// </remarks>
[TestClass]
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "A digest value and an evidence built here are handed to the digest list that owns them and are disposed with it; a record read out of a renewal is owned by the result held in a using.")]
internal sealed class PreservationDigestListTests
{
    /// <summary>The algorithm a submission of these tests states in its digest method.</summary>
    private static PkiDigestAlgorithm RenewalAlgorithm { get; } = PkiDigestAlgorithm.Sha512;

    /// <summary>The algorithm the records these tests renew were created under.</summary>
    private static PkiDigestAlgorithm InitialAlgorithm { get; } = PkiDigestAlgorithm.Sha256;

    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = default!;


    /// <summary>Table 24's three names are the ones the component's own table states.</summary>
    [TestMethod]
    public void TheComponentsNamesAreTheOnesItsTableStates()
    {
        Assert.AreEqual("DigestMethod", PreservationDigestListParameterNames.DigestMethod.XmlElementName);
        Assert.AreEqual("digAlg", PreservationDigestListParameterNames.DigestMethod.JsonMemberName);
        Assert.AreEqual("DigestValue", PreservationDigestListParameterNames.DigestValue.XmlElementName);
        Assert.AreEqual("digVal", PreservationDigestListParameterNames.DigestValue.JsonMemberName);
        Assert.AreEqual("Evidence", PreservationDigestListParameterNames.Evidence.XmlElementName);
        Assert.AreEqual("ev", PreservationDigestListParameterNames.Evidence.JsonMemberName);

        Assert.IsTrue(PreservationDigestListParameterNames.DigestMethod.IsXmlElementName("DigestMethod"));
        Assert.IsFalse(PreservationDigestListParameterNames.DigestMethod.IsXmlElementName("digestMethod"));
        Assert.IsTrue(PreservationDigestListParameterNames.DigestValue.IsJsonMemberName("digVal"));
        Assert.IsFalse(PreservationDigestListParameterNames.DigestValue.IsJsonMemberName("digval"));
    }


    /// <summary>The submission format identifier is the one clause A.1.6 registers for this payload.</summary>
    [TestMethod]
    public void TheSubmissionFormatIdentifierIsTheOneItsClauseRegisters()
    {
        Assert.AreEqual("http://uri.etsi.org/19512/format/DigestList", PreservationFormatWellKnown.DigestListFormat);
        Assert.IsTrue(PreservationFormatWellKnown.IsSubmissionFormat(PreservationFormatWellKnown.DigestListFormat));
        Assert.IsFalse(PreservationFormatWellKnown.IsEvidenceFormat(PreservationFormatWellKnown.DigestListFormat));
    }


    /// <summary>Every algorithm this library computes round-trips through the object-identifier uniform resource name.</summary>
    [TestMethod]
    public void EveryAlgorithmRoundTripsThroughItsObjectIdentifierName()
    {
        PkiDigestAlgorithm[] algorithms = [PkiDigestAlgorithm.Sha256, PkiDigestAlgorithm.Sha384, PkiDigestAlgorithm.Sha512];
        foreach(PkiDigestAlgorithm algorithm in algorithms)
        {
            string urn = PreservationDigestMethod.ToUrn(algorithm);
            Assert.StartsWith("urn:oid:", urn);
            Assert.EndsWith(algorithm.Identifier.Oid, urn);

            Assert.IsTrue(PreservationDigestMethod.TryResolve(urn, out PkiDigestAlgorithm resolved));
            Assert.AreEqual(algorithm.Identifier.Oid, resolved.Identifier.Oid);
            Assert.AreEqual(algorithm.OutputByteLength, resolved.OutputByteLength);
        }

        //The specification's own example, spelled out.
        Assert.AreEqual("urn:oid:2.16.840.1.101.3.4.2.1", PreservationDigestMethod.ToUrn(PkiDigestAlgorithm.Sha256));
    }


    /// <summary>The namespace identifier folds case; everything else about the value does not.</summary>
    [TestMethod]
    [DataRow("URN:OID:2.16.840.1.101.3.4.2.1", true, DisplayName = "the namespace identifier is case-insensitive")]
    [DataRow("urn:oid:2.16.840.1.101.3.4.2.1", true, DisplayName = "the form the library writes")]
    [DataRow("2.16.840.1.101.3.4.2.1", false, DisplayName = "a bare object identifier is not the required form")]
    [DataRow("urn:oid:", false, DisplayName = "no object identifier at all")]
    [DataRow("urn:oid:1.3.14.3.2.26", false, DisplayName = "an algorithm this library does not compute")]
    [DataRow("http://www.w3.org/2001/04/xmlenc#sha256", false, DisplayName = "another identification scheme")]
    [DataRow("", false, DisplayName = "empty")]
    [DataRow(null, false, DisplayName = "absent")]
    public void OnlyAWellFormedNameOfAComputableAlgorithmResolves(string? digestMethod, bool resolves)
    {
        Assert.AreEqual(resolves, PreservationDigestMethod.TryResolve(digestMethod, out PkiDigestAlgorithm algorithm));
        if(!resolves)
        {
            Assert.AreEqual(default, algorithm);
        }
    }


    /// <summary>A value longer than the bound is refused before it is split.</summary>
    [TestMethod]
    public void ADigestMethodBeyondTheBoundIsRefused()
    {
        Assert.AreEqual(128, PreservationDigestMethod.MaximumLength);

        string overLong = string.Concat("urn:oid:", new string('1', PreservationDigestMethod.MaximumLength));
        Assert.IsFalse(PreservationDigestMethod.TryResolve(overLong, out _));
    }


    /// <summary>A digest list owns its digest values and the evidence riding with them.</summary>
    [TestMethod]
    public async Task ADigestListOwnsWhatItCarries()
    {
        using PreservationTimestampAuthority authority = PreservationProfileSource.MintAuthority(PreservationProfileSource.InitialArchiveTime);
        List<ReadOnlyMemory<byte>> dataObjects = DataObjects("first", "second");

        using EvidenceRecord record = await MintRecordAsync(dataObjects, authority);
        using MeteredHousePool pool = new();

        var digestValues = new List<DigestValue>(dataObjects.Count);
        for(int i = 0; i < dataObjects.Count; ++i)
        {
            digestValues.Add(await CryptographicKeyEvents.ComputeDigestAsync(
                dataObjects[i],
                RenewalAlgorithm.OutputByteLength,
                RenewalAlgorithm.DigestTag,
                pool.Pool,
                cancellationToken: TestContext.CancellationToken));
        }

        var digestList = new PreservationDigestList
        {
            DigestMethod = PreservationDigestMethod.ToUrn(RenewalAlgorithm),
            DigestValues = digestValues,
            Evidence = new PreservationEvidence
            {
                Content = PooledMemory.FromBytes(record.AsReadOnlySpan(), pool.Pool, PreservationTags.PreservationEvidence),
                ContentForm = PreservationContentForm.BinaryData,
                FormatId = PreservationFormatWellKnown.EvidenceRecordEvidenceFormat
            }
        };

        Assert.HasCount(2, digestList.DigestValues);
        Assert.IsNotNull(digestList.Evidence);
        Assert.AreEqual(PreservationFormatWellKnown.EvidenceRecordEvidenceFormat, digestList.Evidence.FormatId);
        //Two digest values and the evidence's octets are the three carriers the list goes on to own; whatever the
        //digest seam rented for its own working has already come back, which is why outstanding is the count to
        //read rather than what was handed out.
        Assert.AreEqual(3, pool.OutstandingCount);

        digestList.Dispose();

        //A digest list owns its digest values and the evidence riding with them, which the counting pool is what
        //makes visible from outside: everything the list was built with came back.
        Assert.AreEqual(0, pool.OutstandingCount, "Disposing the digest list returns every carrier it owns.");
    }


    /// <summary>
    /// A submission carrying an evidence record and the data objects its digest values were computed over is
    /// renewed by the shipped procedure, and the renewed record proves what the independent oracle recomputes.
    /// </summary>
    [TestMethod]
    public async Task ASubmissionCarryingAnEvidenceRecordIsRenewedAndTheRenewalVerifies()
    {
        using PreservationTimestampAuthority initialAuthority = PreservationProfileSource.MintAuthority(PreservationProfileSource.InitialArchiveTime);
        List<ReadOnlyMemory<byte>> dataObjects = DataObjects("first", "second");

        using EvidenceRecord submitted = await MintRecordAsync(dataObjects, initialAuthority);
        using PreservationDigestList digestList = await PreservationProfileSource.DigestListAsync(
            dataObjects, RenewalAlgorithm, PreservationProfileSource.Evidence(submitted), TestContext.CancellationToken);

        using PreservationTimestampAuthority renewalAuthority = PreservationProfileSource.MintAuthority(PreservationProfileSource.RenewalArchiveTime);
        using PreservationDigestListRenewalResult renewal = await PreservationDigestListRenewal.RenewAsync(
            new PreservationDigestListRenewalContext
            {
                DigestList = digestList,
                DataObjects = dataObjects,
                TsaUri = renewalAuthority.Address,
                FetchTimestampResponse = renewalAuthority.Responder.FetchAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.AreEqual(PreservationDigestListRenewalStatus.Renewed, renewal.Status);
        Assert.IsNotNull(renewal.EvidenceRecord);
        Assert.AreEqual(PreservationProfileSource.RenewalArchiveTime, renewal.ArchiveTime);

        //The shipped verifier, over the same data objects: a renewed record still proves what it always proved.
        using EvidenceRecordVerification verified = await EvidenceRecords.VerifyAsync(
            new EvidenceRecordVerificationContext
            {
                EvidenceRecord = renewal.EvidenceRecord,
                DataObject = dataObjects[0],
                DataObjectGroup = dataObjects
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, verified.Status);

        //And the independent oracle, from the clause text: the renewed chain's own tree walks to the root its own
        //token binds, for every data object the submission stated a digest value for.
        OracleEvidenceRecord parsed = EvidenceRecordOracle.ParseEvidenceRecord(renewal.EvidenceRecord.AsReadOnlySpan().ToArray());
        Assert.HasCount(2, parsed.Chains, "A Hash-Tree Renewal appends a new chain to the sequence (RFC 4998 clause 5.2).");

        OracleArchiveTimeStamp renewed = parsed.Chains[1][0];
        for(int i = 0; i < dataObjects.Count; ++i)
        {
            byte[] dataObject = dataObjects[i].ToArray();
            byte[] positional = EvidenceRecordOracle.HashTreeRenewalValue(dataObject, [parsed.ChainEncodings[0]], RenewalAlgorithm);
            byte[]? root = EvidenceRecordOracle.RecomputeRoot(positional, renewed.ReducedHashtree, RenewalAlgorithm);

            Assert.IsNotNull(root, "The independent walk reaches a root for every data object the submission named.");
            Assert.IsTrue(root.AsSpan().SequenceEqual(renewed.MessageImprint),
                "Clause 5.2 step 4: the value the submission's own digest method produced is what the renewed chain's tree is built over.");
        }

        //The submitted record is untouched: a renewal produces a new record and leaves what it renewed alone.
        Assert.HasCount(1, EvidenceRecordOracle.ParseEvidenceRecord(submitted.AsReadOnlySpan().ToArray()).Chains);
    }


    /// <summary>
    /// A submission carrying only hashes — the privacy-preserving mode of clause A.3.1.4.7 — is refused with the
    /// reason, because the shipped renewal computes the data object hashes itself.
    /// </summary>
    [TestMethod]
    public async Task AHashOnlySubmissionIsRefusedWithTheReasonRatherThanServedWrongly()
    {
        using PreservationTimestampAuthority authority = PreservationProfileSource.MintAuthority(PreservationProfileSource.InitialArchiveTime);
        List<ReadOnlyMemory<byte>> dataObjects = DataObjects("first");

        using EvidenceRecord submitted = await MintRecordAsync(dataObjects, authority);
        using PreservationDigestList digestList = await PreservationProfileSource.DigestListAsync(
            dataObjects, RenewalAlgorithm, PreservationProfileSource.Evidence(submitted), TestContext.CancellationToken);

        using PreservationDigestListRenewalResult refused = await PreservationDigestListRenewal.RenewAsync(
            new PreservationDigestListRenewalContext
            {
                DigestList = digestList,
                TsaUri = authority.Address,
                FetchTimestampResponse = authority.Responder.FetchAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.AreEqual(PreservationDigestListRenewalStatus.DataObjectsNotSupplied, refused.Status);
        Assert.IsNull(refused.EvidenceRecord);
        Assert.IsNull(refused.ArchiveTime);
        Assert.IsNotNull(refused.FailureReason);
    }


    /// <summary>The submitted digest values bind: data objects that disagree with them are refused.</summary>
    [TestMethod]
    public async Task DataObjectsThatDisagreeWithTheSubmittedDigestValuesAreRefused()
    {
        using PreservationTimestampAuthority authority = PreservationProfileSource.MintAuthority(PreservationProfileSource.InitialArchiveTime);
        List<ReadOnlyMemory<byte>> dataObjects = DataObjects("first", "second");

        using EvidenceRecord submitted = await MintRecordAsync(dataObjects, authority);
        using PreservationDigestList digestList = await PreservationProfileSource.DigestListAsync(
            dataObjects, RenewalAlgorithm, PreservationProfileSource.Evidence(submitted), TestContext.CancellationToken);

        List<ReadOnlyMemory<byte>> otherObjects = DataObjects("first", "something else");
        using PreservationDigestListRenewalResult mismatched = await PreservationDigestListRenewal.RenewAsync(
            new PreservationDigestListRenewalContext
            {
                DigestList = digestList,
                DataObjects = otherObjects,
                TsaUri = authority.Address,
                FetchTimestampResponse = authority.Responder.FetchAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.AreEqual(PreservationDigestListRenewalStatus.DigestValueNotMatched, mismatched.Status);

        using PreservationDigestListRenewalResult tooFew = await PreservationDigestListRenewal.RenewAsync(
            new PreservationDigestListRenewalContext
            {
                DigestList = digestList,
                DataObjects = [dataObjects[0]],
                TsaUri = authority.Address,
                FetchTimestampResponse = authority.Responder.FetchAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.AreEqual(PreservationDigestListRenewalStatus.DataObjectCountMismatch, tooFew.Status);
    }


    /// <summary>A submission stating no evidence is a submission rather than a renewal request.</summary>
    [TestMethod]
    public async Task ASubmissionCarryingNoEvidenceIsNotARenewalRequest()
    {
        using PreservationTimestampAuthority authority = PreservationProfileSource.MintAuthority(PreservationProfileSource.InitialArchiveTime);
        List<ReadOnlyMemory<byte>> dataObjects = DataObjects("first");

        using PreservationDigestList digestList = await PreservationProfileSource.DigestListAsync(
            dataObjects, RenewalAlgorithm, evidence: null, TestContext.CancellationToken);

        using PreservationDigestListRenewalResult refused = await PreservationDigestListRenewal.RenewAsync(
            new PreservationDigestListRenewalContext
            {
                DigestList = digestList,
                DataObjects = dataObjects,
                TsaUri = authority.Address,
                FetchTimestampResponse = authority.Responder.FetchAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.AreEqual(PreservationDigestListRenewalStatus.NoEvidence, refused.Status);
    }


    /// <summary>An evidence of a format this library does not renew, and octets that are no record at all, are refused apart.</summary>
    [TestMethod]
    public async Task AnEvidenceThisLibraryDoesNotRenewIsRefusedByFormatAndByContent()
    {
        using PreservationTimestampAuthority authority = PreservationProfileSource.MintAuthority(PreservationProfileSource.InitialArchiveTime);
        List<ReadOnlyMemory<byte>> dataObjects = DataObjects("first");

        using EvidenceRecord submitted = await MintRecordAsync(dataObjects, authority);
        using PreservationDigestList otherFormat = await PreservationProfileSource.DigestListAsync(
            dataObjects,
            RenewalAlgorithm,
            PreservationProfileSource.Evidence(submitted, PreservationFormatWellKnown.XmlEvidenceRecordEvidenceFormat),
            TestContext.CancellationToken);

        using PreservationDigestListRenewalResult byFormat = await PreservationDigestListRenewal.RenewAsync(
            new PreservationDigestListRenewalContext
            {
                DigestList = otherFormat,
                DataObjects = dataObjects,
                TsaUri = authority.Address,
                FetchTimestampResponse = authority.Responder.FetchAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.AreEqual(PreservationDigestListRenewalStatus.EvidenceFormatNotRenewable, byFormat.Status);

        using var notARecord = new PreservationDigestList
        {
            DigestMethod = PreservationDigestMethod.ToUrn(RenewalAlgorithm),
            DigestValues = [.. otherFormat.DigestValues],
            Evidence = new PreservationEvidence
            {
                Content = PooledMemory.FromBytes("not a record"u8, BaseMemoryPool.Shared, PreservationTags.PreservationEvidence),
                ContentForm = PreservationContentForm.BinaryData,
                FormatId = PreservationFormatWellKnown.EvidenceRecordEvidenceFormat
            }
        };

        using PreservationDigestListRenewalResult byContent = await PreservationDigestListRenewal.RenewAsync(
            new PreservationDigestListRenewalContext
            {
                DigestList = notARecord,
                DataObjects = dataObjects,
                TsaUri = authority.Address,
                FetchTimestampResponse = authority.Responder.FetchAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.AreEqual(PreservationDigestListRenewalStatus.EvidenceNotReadable, byContent.Status);

        //The digest values were moved into the second list and are disposed with it, so the first must not
        //dispose them again; the assertion states that the two lists really share them.
        Assert.HasCount(otherFormat.DigestValues.Count, notARecord.DigestValues);
    }


    /// <summary>A digest method the library cannot compute, and a value of the wrong length, are refused apart.</summary>
    [TestMethod]
    public async Task AnUnusableDigestMethodAndAMisSizedValueAreRefusedApart()
    {
        using PreservationTimestampAuthority authority = PreservationProfileSource.MintAuthority(PreservationProfileSource.InitialArchiveTime);
        List<ReadOnlyMemory<byte>> dataObjects = DataObjects("first");

        using PreservationDigestList underOtherMethod = await PreservationProfileSource.DigestListAsync(
            dataObjects, InitialAlgorithm, evidence: null, TestContext.CancellationToken);

        using var unusable = new PreservationDigestList
        {
            DigestMethod = "urn:oid:1.3.14.3.2.26",
            DigestValues = [.. underOtherMethod.DigestValues]
        };

        using PreservationDigestListRenewalResult byMethod = await PreservationDigestListRenewal.RenewAsync(
            Context(unusable, dataObjects, authority),
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.AreEqual(PreservationDigestListRenewalStatus.DigestMethodNotResolvable, byMethod.Status);

        //The values are the shorter algorithm's while the method names the longer one, which is a value that is
        //not a digest under the method it is stated with.
        using var misSized = new PreservationDigestList
        {
            DigestMethod = PreservationDigestMethod.ToUrn(RenewalAlgorithm),
            DigestValues = [.. underOtherMethod.DigestValues]
        };

        using PreservationDigestListRenewalResult byLength = await PreservationDigestListRenewal.RenewAsync(
            Context(misSized, dataObjects, authority),
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.AreEqual(PreservationDigestListRenewalStatus.DigestValueLengthMismatch, byLength.Status);

        using var empty = new PreservationDigestList
        {
            DigestMethod = PreservationDigestMethod.ToUrn(RenewalAlgorithm),
            DigestValues = []
        };

        using PreservationDigestListRenewalResult byCount = await PreservationDigestListRenewal.RenewAsync(
            Context(empty, dataObjects, authority),
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.AreEqual(PreservationDigestListRenewalStatus.NoDigestValue, byCount.Status);
    }


    /// <summary>Nothing that has not been computed reads as a renewal, and the wrapper refuses to be called with nothing.</summary>
    [TestMethod]
    public async Task NoUncomputedStatusReadsAsARenewal()
    {
        Assert.AreEqual(nameof(PreservationDigestListRenewalStatus.NotEvaluated), Enum.GetName(default(PreservationDigestListRenewalStatus)));

        using var uncomputed = new PreservationDigestListRenewalResult { Status = default };
        Assert.IsFalse(uncomputed.IsRenewed);
        Assert.IsNull(uncomputed.EvidenceRecord);

        _ = await Assert.ThrowsExactlyAsync<ArgumentNullException>(
            async () => await PreservationDigestListRenewal.RenewAsync(null!, BaseMemoryPool.Shared, TestContext.CancellationToken));
    }


    /// <summary>
    /// States the renewal context of a submission, which every refusal test builds the same way.
    /// </summary>
    /// <param name="digestList">The submission.</param>
    /// <param name="dataObjects">The data objects the caller holds.</param>
    /// <param name="authority">The authority a renewal would take its time-stamp from.</param>
    /// <returns>The context.</returns>
    private static PreservationDigestListRenewalContext Context(
        PreservationDigestList digestList,
        IReadOnlyList<ReadOnlyMemory<byte>> dataObjects,
        PreservationTimestampAuthority authority) =>
        new()
        {
            DigestList = digestList,
            DataObjects = dataObjects,
            TsaUri = authority.Address,
            FetchTimestampResponse = authority.Responder.FetchAsync
        };


    /// <summary>
    /// States data objects from their content.
    /// </summary>
    /// <param name="contents">The content of each object, in order.</param>
    /// <returns>The objects as the shipped surfaces take them.</returns>
    private static List<ReadOnlyMemory<byte>> DataObjects(params string[] contents)
    {
        var dataObjects = new List<ReadOnlyMemory<byte>>(contents.Length);
        for(int i = 0; i < contents.Length; ++i)
        {
            dataObjects.Add(Encoding.UTF8.GetBytes(contents[i]));
        }

        return dataObjects;
    }


    /// <summary>
    /// Mints an Evidence Record over one data object group through the shipped creation surface.
    /// </summary>
    /// <param name="dataObjects">The octets the record is to prove, as one group.</param>
    /// <param name="authority">The authority the record's initial archive time-stamp is taken from.</param>
    /// <returns>The record. The caller owns and disposes it.</returns>
    private async ValueTask<EvidenceRecord> MintRecordAsync(
        IReadOnlyList<ReadOnlyMemory<byte>> dataObjects,
        PreservationTimestampAuthority authority)
    {
        using EvidenceRecordCreation creation = await EvidenceRecords.CreateInitialAsync(
            new EvidenceRecordCreationContext
            {
                DataObjectGroups = [new EvidenceRecordDataObjectGroup { DataObjects = dataObjects }],
                DigestAlgorithm = InitialAlgorithm,
                TsaUri = authority.Address,
                FetchTimestampResponse = authority.Responder.FetchAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        return EvidenceRecord.Read(creation.EvidenceRecords[0].AsReadOnlySpan(), BaseMemoryPool.Shared);
    }
}
