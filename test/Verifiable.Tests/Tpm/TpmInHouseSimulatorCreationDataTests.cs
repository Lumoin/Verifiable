using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Seal;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Proves the <c>TPMS_CREATION_DATA</c> conformance builder (TPM 2.0 Library Part 2, clause 15.1, Table
/// 261) against the in-house behavioural <see cref="TpmSimulator"/> — entirely in-process, with no external
/// assets — through the same production command path the production code uses (<see cref="TpmCommandExecutor"/>
/// with the real <see cref="CreatePrimaryInput"/>/<see cref="CreateInput"/> and response codecs): the parent
/// identity's handle form (permanent hierarchy) versus a loaded storage parent's own Name and Qualified
/// Name; the <c>pcrSelect</c>/<c>pcrDigest</c> filter-then-gather-then-hash pipeline, including the
/// empty-list and unallocated-bank rows; <c>outsideInfo</c> echoed verbatim; and <c>creationHash</c> under
/// the created object's OWN nameAlg, never the fixed context-integrity width the creation ticket keeps.
/// </summary>
/// <remarks>
/// <para>
/// Every oracle here is independent of the production helper under test: hashes run through the registered
/// <see cref="CryptographicKeyEvents"/> digest seam under a hand-selected <see cref="HashAlgorithmName"/>, PCR
/// values are read back over the real wire with <c>TPM2_PCR_Read()</c> rather than peeked out of simulator
/// state, and a parent's Qualified Name is hand-computed per Part 1, clause 23.5, mirroring the sibling
/// <c>TpmInHouseSimulatorCertifyCreationTests</c>' firewalled oracle style. <c>Tpm2bName.Handle</c> is asserted
/// only after <c>IsHandleName</c>/<c>IsDigestName</c> — it returns 0 silently on a digest-form Name, a hazard this
/// file's own <see cref="TpmObjectName"/> analogue documents.
/// </para>
/// <para>
/// A 17-bank <c>creationPCR</c> refused with <c>TPM_RC_SIZE</c>, and an over-bound <c>outsideInfo</c>/the
/// host <c>TpmsCreationData.Parse</c> carrier proofs, are proven in
/// <c>TpmInHouseSimulatorCreationParameterTests</c> and <c>TpmCreationDataCarrierTests</c> respectively
/// and are not repeated here.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorCreationDataTests
{
    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A <c>TPM2_Create()</c> child under a loaded ECC storage parent carries the PARENT's own Name
    /// and Qualified Name — never the permanent-handle form — because the parent is a loaded object, not a
    /// hierarchy. The whole <c>TPMS_CREATION_DATA</c> is pinned field by field alongside the parent identity: an
    /// empty <c>creationPCR</c> gives <c>pcrSelect</c> count 0 and a size-0 <c>pcrDigest</c>, <c>locality</c> is
    /// the model's fixed <c>TPM_LOC_ZERO</c>, and an empty <c>outsideInfo</c> stays size 0
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 15.1, Table 261; Part 1: Architecture, clause 23.5;
    /// Part 2: Structures, clause 8.5, Table 39).
    /// </summary>
    [TestMethod]
    public async Task CreateChildUnderOwnerEccStorageParentCarriesTheParentsOwnNameAndQualifiedName()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateEccStorageParentAsync(
            tpm, registry, pool, TpmRh.TPM_RH_OWNER, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic childTemplate = Tpm2bPublic.CreateSealedDataTemplate(TpmAlgIdConstants.TPM_ALG_SHA256, pool, noDa: true);
        using CreateInput input = new(parent.ObjectHandle.Value, inSensitive, childTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, input, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"Create failed: '{result.ResponseCode}'.");

        using CreateResponse sealedObject = result.Value;
        TpmsCreationData creationData = sealedObject.CreationData.CreationData;

        Assert.AreEqual(
            TpmAlgIdConstants.TPM_ALG_SHA256, creationData.ParentNameAlg,
            "The loaded parent's own nameAlg names parentNameAlg — never TPM_ALG_NULL, which only the permanent-handle form uses.");

        //IsDigestName is checked BEFORE .Handle: a digest-form Name returns 0 from .Handle silently.
        Assert.IsTrue(creationData.ParentName.IsDigestName, "The parent's Name is a digest form (nameAlg || H(TPMT_PUBLIC)), not a handle.");
        Assert.IsTrue(
            creationData.ParentName.Span.SequenceEqual(parent.Name.Span),
            "parentName must be the parent's own Name octets verbatim (Part 4 FillInCreationData copies parentObject->name).");

        byte[] expectedQn = await ComputeQualifiedNameAsync(
            (uint)TpmRh.TPM_RH_OWNER, parent.Name.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            creationData.ParentQualifiedName.Span.SequenceEqual(expectedQn),
            "parentQualifiedName must be the parent's own Qualified Name: nameAlg || H_nameAlg(OWNER handle || parentName) (Part 1, clause 23.5) — every parent this model holds is a primary.");

        //The remaining Table 261 rows, pinned field by field alongside the parent identity above: an empty
        //creationPCR (this test's own request) gives pcrSelect count 0 and a size-0 pcrDigest, locality
        //is the model's fixed platform value, and an empty outsideInfo stays size 0.
        Assert.AreEqual(0, creationData.PcrSelect.Count, "This request's empty creationPCR echoes pcrSelect count 0.");
        Assert.AreEqual(0, creationData.PcrDigest.Size, "Table 261: pcrDigest.size shall be zero if the pcrSelect list is empty.");
        Assert.AreEqual(TpmaLocality.TPM_LOC_ZERO, creationData.Locality, "locality is this model's fixed platform locality (Part 2, clause 8.5).");
        Assert.AreEqual(0, creationData.OutsideInfo.Length, "This request's empty outsideInfo stays size 0.");
    }

    /// <summary>
    /// A SHA-384-nameAlg storage parent's Name is 50 octets (2-octet algorithm prefix + 48-octet digest)
    /// and is written verbatim as <c>parentName</c>, while the SEALED CHILD's own <c>creationHash</c> stays sized
    /// to the CHILD's own (SHA-256) nameAlg — the two algorithms never conflate
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 15.1, Table 261).
    /// </summary>
    [TestMethod]
    public async Task CreateChildUnderASha384NamedParentKeepsTheParentAndChildAlgorithmsDistinct()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateEccStorageParentAsync(
            tpm, registry, pool, TpmRh.TPM_RH_OWNER, TpmAlgIdConstants.TPM_ALG_SHA384).ConfigureAwait(false);
        Assert.HasCount(50, parent.Name.Span.ToArray(), "Test setup: a SHA-384 Name is 2 + 48 = 50 octets.");

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic childTemplate = Tpm2bPublic.CreateSealedDataTemplate(TpmAlgIdConstants.TPM_ALG_SHA256, pool, noDa: true);
        using CreateInput input = new(parent.ObjectHandle.Value, inSensitive, childTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, input, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"Create failed: '{result.ResponseCode}'.");

        using CreateResponse sealedObject = result.Value;
        TpmsCreationData creationData = sealedObject.CreationData.CreationData;

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA384, creationData.ParentNameAlg, "parentNameAlg must be the PARENT's own nameAlg (SHA-384).");
        Assert.HasCount(50, creationData.ParentName.Span.ToArray(), "parentName is 50 octets — the SHA-384 Name width, not the child's SHA-256 width.");
        Assert.IsTrue(creationData.ParentName.Span.SequenceEqual(parent.Name.Span), "parentName must equal the parent's own Name octets.");

        Assert.AreEqual(32, sealedObject.CreationHash.Size, "The CHILD's creationHash stays sized to the child's OWN nameAlg (SHA-256), never the parent's (SHA-384).");
        byte[] expectedCreationHash = await ComputeDigestAsync(
            sealedObject.CreationData.GetRawMemory(), TpmAlgIdConstants.TPM_ALG_SHA256, 32, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            expectedCreationHash.AsSpan().SequenceEqual(sealedObject.CreationHash.AsReadOnlySpan()),
            "creationHash must equal H_childNameAlg(creationData), independent of the parent's own nameAlg.");
    }

    /// <summary>
    /// The permanent-handle form holds for every hierarchy <c>TPM2_CreatePrimary()</c>
    /// admits, not only <c>TPM_RH_OWNER</c>: <c>parentNameAlg</c> is <c>TPM_ALG_NULL</c> and both
    /// <c>parentName</c>/<c>parentQualifiedName</c> are the 4-octet hierarchy handle. This is the CreatePrimary leg
    /// of the same field-by-field octet pin
    /// <see cref="CreateChildUnderOwnerEccStorageParentCarriesTheParentsOwnNameAndQualifiedName"/> runs for the
    /// Create leg: an empty <c>creationPCR</c> gives
    /// <c>pcrSelect</c> count 0 and a size-0 <c>pcrDigest</c>, <c>locality</c> is the model's fixed
    /// <c>TPM_LOC_ZERO</c>, and an empty <c>outsideInfo</c> stays size 0
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 15.1, Table 261, "If the parent is a permanent handle";
    /// Part 2: Structures, clause 8.5, Table 39).
    /// </summary>
    [TestMethod]
    [DataRow(TpmRh.TPM_RH_OWNER)]
    [DataRow(TpmRh.TPM_RH_ENDORSEMENT)]
    [DataRow(TpmRh.TPM_RH_PLATFORM)]
    public async Task CreatePrimaryUnderEveryPermanentHierarchyUsesTheHandleFormForNameAndQualifiedName(TpmRh hierarchy)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic template = BuildEccSigningTemplate(TpmAlgIdConstants.TPM_ALG_SHA256);
        using CreatePrimaryInput input = new(hierarchy, inSensitive, template, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary ({hierarchy}) failed: '{result.ResponseCode}'.");

        using CreatePrimaryResponse primary = result.Value;
        TpmsCreationData creationData = primary.CreationData.CreationData;

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_NULL, creationData.ParentNameAlg, $"A primary under {hierarchy} carries parentNameAlg TPM_ALG_NULL.");
        Assert.IsTrue(creationData.ParentName.IsHandleName, "The permanent-handle form is the bare 4-octet handle, not a digest.");
        Assert.AreEqual((uint)hierarchy, creationData.ParentName.Handle, "parentName is the hierarchy handle itself.");
        Assert.AreEqual((uint)hierarchy, creationData.ParentQualifiedName.Handle, "parentQualifiedName is the same hierarchy handle.");

        //The remaining Table 261 rows, pinned field by field alongside the parent identity above — the
        //CreatePrimary leg of the same octet-layout pin the Create leg above runs.
        Assert.AreEqual(0, creationData.PcrSelect.Count, "This request's empty creationPCR echoes pcrSelect count 0.");
        Assert.AreEqual(0, creationData.PcrDigest.Size, "Table 261: pcrDigest.size shall be zero if the pcrSelect list is empty.");
        Assert.AreEqual(TpmaLocality.TPM_LOC_ZERO, creationData.Locality, "locality is this model's fixed platform locality (Part 2, clause 8.5).");
        Assert.AreEqual(0, creationData.OutsideInfo.Length, "This request's empty outsideInfo stays size 0.");
    }

    /// <summary>
    /// An empty <c>creationPCR</c> writes <c>pcrSelect</c> count 0 and a size-0 <c>pcrDigest</c> —
    /// the normative Table 261 row, on both creation commands
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 15.1, Table 261, "pcrDigest.size shall be zero if the
    /// pcrSelect list is empty").
    /// </summary>
    [TestMethod]
    public async Task EmptyCreationPcrYieldsSizeZeroPcrDigestOnBothCommands()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using(Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool))
        using(Tpm2bPublic template = BuildEccSigningTemplate(TpmAlgIdConstants.TPM_ALG_SHA256))
        using(CreatePrimaryInput input = new(TpmRh.TPM_RH_OWNER, inSensitive, template, Tpm2bData.Empty, TpmlPcrSelection.Empty))
        using(TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool))
        {
            TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
                tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"CreatePrimary failed: '{result.ResponseCode}'.");

            using CreatePrimaryResponse primary = result.Value;
            TpmsCreationData creationData = primary.CreationData.CreationData;
            Assert.AreEqual(0, creationData.PcrSelect.Count, "An empty creationPCR echoes count 0.");
            Assert.AreEqual(0, creationData.PcrDigest.Size, "Table 261: pcrDigest.size shall be zero if the pcrSelect list is empty.");
        }

        using CreatePrimaryResponse parent = await CreateEccStorageParentAsync(
            tpm, registry, pool, TpmRh.TPM_RH_OWNER, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        using Tpm2bSensitiveCreate childInSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic childTemplate = Tpm2bPublic.CreateSealedDataTemplate(TpmAlgIdConstants.TPM_ALG_SHA256, pool, noDa: true);
        using CreateInput createInput = new(parent.ObjectHandle.Value, childInSensitive, childTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create failed: '{createResult.ResponseCode}'.");

        using CreateResponse sealedObject = createResult.Value;
        TpmsCreationData childCreationData = sealedObject.CreationData.CreationData;
        Assert.AreEqual(0, childCreationData.PcrSelect.Count, "An empty creationPCR echoes count 0 on TPM2_Create() too.");
        Assert.AreEqual(0, childCreationData.PcrDigest.Size, "Table 261: pcrDigest.size shall be zero on TPM2_Create() too.");
    }

    /// <summary>
    /// A <c>creationPCR</c> naming PCR 0, 13, and 30 over the modelled SHA-256 bank is filtered to
    /// the 24 registers this model holds — bit 30 is cleared, bits 0 and 13 survive — and <c>pcrDigest</c> covers
    /// exactly the SURVIVING values, read back independently over the wire with <c>TPM2_PCR_Read()</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 14.5; Part 2: Structures, clause 15.1, Table 261).
    /// </summary>
    [TestMethod]
    public async Task CreationPcrNamingAnUnimplementedRegisterIsFilteredAndPcrDigestCoversOnlyTheSurvivors()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic template = BuildEccSigningTemplate(TpmAlgIdConstants.TPM_ALG_SHA256);
        using TpmlPcrSelection creationPcr = BuildSelection(pool, (TpmAlgIdConstants.TPM_ALG_SHA256, 4, [0, 13, 30]));
        using CreatePrimaryInput input = new(TpmRh.TPM_RH_OWNER, inSensitive, template, Tpm2bData.Empty, creationPcr);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary failed: '{result.ResponseCode}'.");

        using CreatePrimaryResponse primary = result.Value;
        TpmsCreationData creationData = primary.CreationData.CreationData;

        Assert.AreEqual(1, creationData.PcrSelect.Count);
        ReadOnlySpan<byte> bitmap = creationData.PcrSelect[0].PcrSelect.Span;
        Assert.IsTrue(IsBitSet(bitmap, 0), "PCR 0 must survive the filter.");
        Assert.IsTrue(IsBitSet(bitmap, 13), "PCR 13 must survive the filter.");
        Assert.IsFalse(IsBitSet(bitmap, 30), "PCR 30 is beyond the 24-register model and must be cleared.");

        byte[] concatenated = await ReadPcrValuesConcatenatedAsync(
            tpm, registry, pool, TpmAlgIdConstants.TPM_ALG_SHA256, [0, 13], TestContext.CancellationToken).ConfigureAwait(false);
        byte[] expectedPcrDigest = await ComputeDigestAsync(concatenated, TpmAlgIdConstants.TPM_ALG_SHA256, 32, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            creationData.PcrDigest.AsReadOnlySpan().SequenceEqual(expectedPcrDigest),
            "pcrDigest must equal H_nameAlg(PCR[0] || PCR[13]) — the object's own nameAlg, over the SURVIVING values only.");
    }

    /// <summary>
    /// A <c>creationPCR</c> naming a bank this model has not allocated (SHA-384) is retained with
    /// every bit CLEARED rather than dropped, and <c>pcrDigest</c> is the FULL-WIDTH hash of the empty
    /// concatenation — "empty" means the filtered list's <c>Count</c> is zero, never that its gathered values are
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 14.5, "No value is included in the concatenation of PCR
    /// for an unimplemented PCR").
    /// </summary>
    [TestMethod]
    public async Task CreationPcrNamingAnUnallocatedBankIsRetainedWithClearedBitsAndAFullWidthPcrDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic template = BuildEccSigningTemplate(TpmAlgIdConstants.TPM_ALG_SHA256);
        using TpmlPcrSelection creationPcr = BuildSelection(pool, (TpmAlgIdConstants.TPM_ALG_SHA384, 3, [7]));
        using CreatePrimaryInput input = new(TpmRh.TPM_RH_OWNER, inSensitive, template, Tpm2bData.Empty, creationPcr);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary failed: '{result.ResponseCode}'.");

        using CreatePrimaryResponse primary = result.Value;
        TpmsCreationData creationData = primary.CreationData.CreationData;

        Assert.AreEqual(1, creationData.PcrSelect.Count, "An unallocated bank's entry is RETAINED, not dropped.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA384, creationData.PcrSelect[0].HashAlgorithm);
        foreach(byte octet in creationData.PcrSelect[0].PcrSelect.Span)
        {
            Assert.AreEqual(0, octet, "Every bit of an unallocated bank's entry must be cleared.");
        }

        Assert.AreEqual(32, creationData.PcrDigest.Size, "pcrDigest is full-width (the object's own SHA-256 nameAlg), never size 0: Count==1, not 0.");
        byte[] expectedPcrDigest = await ComputeDigestAsync(
            ReadOnlyMemory<byte>.Empty, TpmAlgIdConstants.TPM_ALG_SHA256, 32, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            creationData.PcrDigest.AsReadOnlySpan().SequenceEqual(expectedPcrDigest),
            "pcrDigest must equal H_nameAlg(empty concatenation) — the full-width hash of zero gathered values.");
    }

    /// <summary>
    /// Two <c>creationPCR</c> selectors over the implemented bank are BOTH echoed, byte-exactly, in
    /// SELECTOR order (never re-sorted), and <c>pcrDigest</c> covers the values in that same selector order
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 14.5, "selectors processed in order").
    /// </summary>
    [TestMethod]
    public async Task CreationPcrWithTwoSelectorsIsEchoedInSelectorOrderAndPcrDigestCoversBoth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] inputWire = BuildPcrSelectionWireBytes(
            (TpmAlgIdConstants.TPM_ALG_SHA256, 3, [1]),
            (TpmAlgIdConstants.TPM_ALG_SHA256, 3, [0]));
        using TpmlPcrSelection creationPcr = ParseSelectionWire(inputWire, pool);
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic template = BuildEccSigningTemplate(TpmAlgIdConstants.TPM_ALG_SHA256);
        using CreatePrimaryInput input = new(TpmRh.TPM_RH_OWNER, inSensitive, template, Tpm2bData.Empty, creationPcr);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary failed: '{result.ResponseCode}'.");

        using CreatePrimaryResponse primary = result.Value;
        TpmsCreationData creationData = primary.CreationData.CreationData;

        byte[] echoed = new byte[creationData.PcrSelect.GetSerializedSize()];
        var echoWriter = new TpmWriter(echoed);
        creationData.PcrSelect.WriteTo(ref echoWriter);
        Assert.IsTrue(
            echoed.AsSpan().SequenceEqual(inputWire),
            "Both selectors name the implemented bank and registers, so neither is bit-cleared, and both are echoed byte-exactly in the ORIGINAL selector order.");

        //Every modelled register resets to all-zero, so the digest EQUATION is proven here even though the
        //concatenation ORDER is not value-discriminable until TPM2_PCR_Extend lands (a recorded candidate).
        byte[] concatenated = await ReadPcrValuesConcatenatedAsync(
            tpm, registry, pool, TpmAlgIdConstants.TPM_ALG_SHA256, [1, 0], TestContext.CancellationToken).ConfigureAwait(false);
        byte[] expectedPcrDigest = await ComputeDigestAsync(concatenated, TpmAlgIdConstants.TPM_ALG_SHA256, 32, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            creationData.PcrDigest.AsReadOnlySpan().SequenceEqual(expectedPcrDigest),
            "pcrDigest must equal H_nameAlg(PCR[1] || PCR[0]), the selector-order concatenation.");
    }

    /// <summary>
    /// A <c>TPM2_Create()</c> child's <c>pcrDigest</c> is likewise hashed under the CHILD's own nameAlg —
    /// proven here with a non-empty <c>creationPCR</c> and a SHA-384 child under a SHA-256 parent, so the
    /// child-vs-parent algorithm choice this file already pins for <c>creationHash</c>
    /// (<see cref="CreateChildCreationHashEqualsHashOfCreationDataUnderTheChildsOwnNameAlg"/>) is pinned for
    /// <c>pcrDigest</c> too, not only over an empty selection
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 15.1, Table 261, "digest of the selected PCR using
    /// nameAlg of the object for which this structure is being created").
    /// </summary>
    [TestMethod]
    public async Task CreateChildPcrDigestIsHashedUnderTheChildsOwnNameAlgDistinctFromTheParents()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateEccStorageParentAsync(
            tpm, registry, pool, TpmRh.TPM_RH_OWNER, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic childTemplate = Tpm2bPublic.CreateSealedDataTemplate(TpmAlgIdConstants.TPM_ALG_SHA384, pool, noDa: true);
        using TpmlPcrSelection creationPcr = BuildSelection(pool, (TpmAlgIdConstants.TPM_ALG_SHA256, 3, [5]));
        using CreateInput input = new(parent.ObjectHandle.Value, inSensitive, childTemplate, Tpm2bData.Empty, creationPcr);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, input, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"Create failed: '{result.ResponseCode}'.");

        using CreateResponse sealedObject = result.Value;
        TpmsCreationData creationData = sealedObject.CreationData.CreationData;

        Assert.AreEqual(1, creationData.PcrSelect.Count, "The single SHA-256 selector must survive the filter and be echoed.");
        Assert.IsTrue(IsBitSet(creationData.PcrSelect[0].PcrSelect.Span, 5), "PCR 5 must survive the filter.");
        Assert.AreEqual(48, creationData.PcrDigest.Size, "pcrDigest is sized to the CHILD's own SHA-384 nameAlg, never the parent's SHA-256 nameAlg.");

        byte[] concatenated = await ReadPcrValuesConcatenatedAsync(
            tpm, registry, pool, TpmAlgIdConstants.TPM_ALG_SHA256, [5], TestContext.CancellationToken).ConfigureAwait(false);
        byte[] expectedPcrDigest = await ComputeDigestAsync(
            concatenated, TpmAlgIdConstants.TPM_ALG_SHA384, 48, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            creationData.PcrDigest.AsReadOnlySpan().SequenceEqual(expectedPcrDigest),
            "pcrDigest must equal H_childNameAlg(PCR[5]) — the CHILD's own (SHA-384) nameAlg, independent of the parent's (SHA-256).");
    }

    /// <summary>
    /// A 66-octet <c>outsideInfo</c> (<c>sizeof(TPMT_HA)</c>, the <c>TPM2B_DATA</c> bound) is echoed
    /// VERBATIM into the creation data on <c>TPM2_CreatePrimary()</c>, the plain-password <c>TPM2_Create()</c>,
    /// and the over-sessions <c>TPM2_Create()</c> tail decode alike — the real-wire rule applies to the
    /// session-authorized leg too
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 15.1, Table 261, "the contents of the outsideInfo
    /// parameter").
    /// </summary>
    [TestMethod]
    public async Task OutsideInfoIsEchoedVerbatimOnCreatePrimaryCreateAndTheOverSessionsCreate()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] outsideInfoBytes = BuildFilledBytes(Tpm2bData.MaxSize, 0x5A);

        using(Tpm2bData outsideInfo = Tpm2bData.Create(outsideInfoBytes, pool))
        using(Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool))
        using(Tpm2bPublic template = BuildEccSigningTemplate(TpmAlgIdConstants.TPM_ALG_SHA256))
        using(CreatePrimaryInput primaryInput = new(TpmRh.TPM_RH_OWNER, inSensitive, template, outsideInfo, TpmlPcrSelection.Empty))
        using(TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool))
        {
            TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
                tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"CreatePrimary failed: '{result.ResponseCode}'.");

            using CreatePrimaryResponse primary = result.Value;
            Assert.IsTrue(
                primary.CreationData.CreationData.OutsideInfo.Span.SequenceEqual(outsideInfoBytes),
                "CreatePrimary must echo outsideInfo verbatim into the creation data.");
        }

        using CreatePrimaryResponse parent = await CreateEccStorageParentAsync(
            tpm, registry, pool, TpmRh.TPM_RH_OWNER, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);

        using(Tpm2bData outsideInfo = Tpm2bData.Create(outsideInfoBytes, pool))
        using(Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool))
        using(Tpm2bPublic childTemplate = Tpm2bPublic.CreateSealedDataTemplate(TpmAlgIdConstants.TPM_ALG_SHA256, pool, noDa: true))
        using(CreateInput createInput = new(parent.ObjectHandle.Value, inSensitive, childTemplate, outsideInfo, TpmlPcrSelection.Empty))
        using(TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool))
        {
            TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, createInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"Create failed: '{result.ResponseCode}'.");

            using CreateResponse sealedObject = result.Value;
            Assert.IsTrue(
                sealedObject.CreationData.CreationData.OutsideInfo.Span.SequenceEqual(outsideInfoBytes),
                "Create must echo outsideInfo verbatim into the creation data.");
        }

        byte[] outsideInfoWire = BuildOutsideInfoWireBytes(outsideInfoBytes);
        TpmInHouseSimulatorParameterDecryptionTests.HandCraftedCreateResult overSessionsResult =
            await TpmInHouseSimulatorParameterDecryptionTests.SendHandCraftedCreateAsync(
                simulator, pool, parent.ObjectHandle.Value, parent.Name.Span.ToArray(), corruptDeclaredInSensitiveSize: false,
                TestContext.CancellationToken, outsideInfoWire: outsideInfoWire).ConfigureAwait(false);
        try
        {
            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, overSessionsResult.ResponseCode, "The over-sessions Create must succeed.");
            using Tpm2bCreationData creationData = ParseCreationDataFromResponseParameters(overSessionsResult.ResponseParameters!, pool);
            Assert.IsTrue(
                creationData.CreationData.OutsideInfo.Span.SequenceEqual(outsideInfoBytes),
                "The over-sessions Create must echo outsideInfo verbatim, exactly as the plain-password path does.");
        }
        finally
        {
            overSessionsResult.OutPublic?.Dispose();
            await FlushIfPresentAsync(tpm, registry, overSessionsResult.DecryptSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, overSessionsResult.AuthorizingSessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A non-empty <c>creationPCR</c> is echoed on the over-sessions <c>TPM2_Create()</c> tail decode too —
    /// the filter-then-echo pipeline is not specific to the plain-password parse site
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 15.1, Table 261; Part 3: Commands, clause 12.1).
    /// </summary>
    [TestMethod]
    public async Task CreationPcrIsEchoedOnTheOverSessionsCreate()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateEccStorageParentAsync(
            tpm, registry, pool, TpmRh.TPM_RH_OWNER, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);

        byte[] creationPcrWire = BuildPcrSelectionWireBytes((TpmAlgIdConstants.TPM_ALG_SHA256, 3, [2]));

        TpmInHouseSimulatorParameterDecryptionTests.HandCraftedCreateResult result =
            await TpmInHouseSimulatorParameterDecryptionTests.SendHandCraftedCreateAsync(
                simulator, pool, parent.ObjectHandle.Value, parent.Name.Span.ToArray(), corruptDeclaredInSensitiveSize: false,
                TestContext.CancellationToken, creationPcrWire: creationPcrWire).ConfigureAwait(false);
        try
        {
            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, result.ResponseCode, "The over-sessions Create must succeed.");
            using Tpm2bCreationData creationData = ParseCreationDataFromResponseParameters(result.ResponseParameters!, pool);

            Assert.AreEqual(1, creationData.CreationData.PcrSelect.Count, "The single SHA-256 selector must be echoed.");
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, creationData.CreationData.PcrSelect[0].HashAlgorithm);
            Assert.IsTrue(IsBitSet(creationData.CreationData.PcrSelect[0].PcrSelect.Span, 2), "PCR 2 must survive the filter and be echoed.");
        }
        finally
        {
            result.OutPublic?.Dispose();
            await FlushIfPresentAsync(tpm, registry, result.DecryptSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, result.AuthorizingSessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_CreatePrimary()</c>'s <c>creationHash</c> width and value follow the DECLARED nameAlg —
    /// 20/32/48/64 octets for SHA-1/256/384/512 — while the creation TICKET's own digest stays the fixed
    /// context-integrity width (32 octets, SHA-256) in every row
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 24.1, Table 192, "digest of creationData.creationData using
    /// nameAlg of outPublic"; Part 2: Structures, clause 10.6.3).
    /// </summary>
    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA1, 20)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA256, 32)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA384, 48)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA512, 64)]
    public async Task CreatePrimaryCreationHashWidthAndValueFollowTheDeclaredNameAlg(TpmAlgIdConstants nameAlg, int digestSize)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic template = BuildEccSigningTemplate(nameAlg);
        using CreatePrimaryInput input = new(TpmRh.TPM_RH_OWNER, inSensitive, template, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (nameAlg={nameAlg}) failed: '{result.ResponseCode}'.");

        using CreatePrimaryResponse primary = result.Value;
        Assert.AreEqual(digestSize, primary.CreationHash.Size, "creationHash width must follow the declared nameAlg, never a fixed SHA-256 width.");

        byte[] expectedCreationHash = await ComputeDigestAsync(
            primary.CreationData.GetRawMemory(), nameAlg, digestSize, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            expectedCreationHash.AsSpan().SequenceEqual(primary.CreationHash.AsReadOnlySpan()),
            "creationHash must equal H_declared-nameAlg(creationData raw octets).");

        Assert.HasCount(
            32, primary.CreationTicket.Digest.ToArray(),
            "The creation ticket's own digest stays the fixed context-integrity width (SHA-256) regardless of the object's nameAlg.");
    }

    /// <summary>
    /// <c>TPM2_Create()</c>'s <c>creationHash</c> is likewise <c>H_childNameAlg(creationData)</c> — the
    /// same relation <c>TPM2_CreatePrimary()</c> proves above, over the sealed-child path
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 12.1, Table 19).
    /// </summary>
    [TestMethod]
    public async Task CreateChildCreationHashEqualsHashOfCreationDataUnderTheChildsOwnNameAlg()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateEccStorageParentAsync(
            tpm, registry, pool, TpmRh.TPM_RH_OWNER, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic childTemplate = Tpm2bPublic.CreateSealedDataTemplate(TpmAlgIdConstants.TPM_ALG_SHA384, pool, noDa: true);
        using CreateInput input = new(parent.ObjectHandle.Value, inSensitive, childTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, input, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"Create failed: '{result.ResponseCode}'.");

        using CreateResponse sealedObject = result.Value;
        Assert.AreEqual(48, sealedObject.CreationHash.Size, "The child's own SHA-384 nameAlg sizes creationHash, independent of the parent's SHA-256 nameAlg.");

        byte[] expectedCreationHash = await ComputeDigestAsync(
            sealedObject.CreationData.GetRawMemory(), TpmAlgIdConstants.TPM_ALG_SHA384, 48, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            expectedCreationHash.AsSpan().SequenceEqual(sealedObject.CreationHash.AsReadOnlySpan()),
            "creationHash must equal H_childNameAlg(creationData raw octets) for TPM2_Create() too.");
    }

    /// <summary>
    /// <c>TPM2_CertifyCreation()</c> re-verifies the creation ticket end to end over a SHA-384-nameAlg
    /// subject — the 48-octet <c>creationHash</c> round-trips into the attestation unchanged, proving the HMAC
    /// path (Part 2, clause 10.6.3) is width-agnostic
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 18.3).
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationRoundTripsA48OctetCreationHashOverASha384NamedPrimary()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using Tpm2bSensitiveCreate subjectInSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic subjectTemplate = BuildEccSigningTemplate(TpmAlgIdConstants.TPM_ALG_SHA384);
        using CreatePrimaryInput subjectInput = new(TpmRh.TPM_RH_OWNER, subjectInSensitive, subjectTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession subjectOwnerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> subjectResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, subjectInput, [subjectOwnerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(subjectResult.IsSuccess, $"CreatePrimary (SHA-384 subject) failed: '{subjectResult.ResponseCode}'.");

        using CreatePrimaryResponse subject = subjectResult.Value;
        Assert.AreEqual(48, subject.CreationHash.Size, "Test setup: the subject's creationHash must be 48 octets (SHA-384).");

        using CreatePrimaryInput akInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_ENDORSEMENT, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession akAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> akResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, akInput, [akAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(akResult.IsSuccess, $"CreatePrimary (AK) failed: '{akResult.ResponseCode}'.");
        using CreatePrimaryResponse ak = akResult.Value;

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyCreationInput certifyCreationInput = CertifyCreationInput.ForEcdsa(
            ak.ObjectHandle, subject.ObjectHandle, "creation-data SHA-384 creationHash round trip"u8.ToArray(),
            subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
            tpm, certifyCreationInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_CertifyCreation failed: '{result.ResponseCode}'.");

        using CertifyCreationResponse certifyCreation = result.Value;
        TpmsAttest attest = certifyCreation.CertifyInfo.AttestationData;
        Assert.IsNotNull(attest.Attested.Creation);
        Assert.AreEqual(48, attest.Attested.Creation!.CreationHash.Size, "The attested creationHash preserves the subject's 48-octet SHA-384 width.");
        Assert.IsTrue(
            attest.Attested.Creation!.CreationHash.AsReadOnlySpan().SequenceEqual(subject.CreationHash.AsReadOnlySpan()),
            "The attested creationHash must equal the SHA-384 creationHash CreatePrimary reported — the ticket verified against exactly these bytes.");
    }

    /// <summary>
    /// A <see cref="MeteredHousePool"/> balance check across a successful <c>TPM2_CreatePrimary()</c> and a
    /// successful <c>TPM2_Create()</c>, each with a NON-EMPTY <c>creationPCR</c>/<c>outsideInfo</c> pair that the
    /// builder now genuinely CONSUMES (a hash and a Qualified-Name computation, not just a literal): every rental
    /// still returns to the pool once the response is disposed (and, for CreatePrimary, the durable key state is
    /// flushed) — an empty pair proves nothing about these newly-added consumers
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 15.1, Table 261).
    /// </summary>
    [TestMethod]
    public async Task MeteredPoolBalancesAfterCreatePrimaryAndCreateSuccessWithNonEmptyCreationPcrAndOutsideInfo()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        using(Tpm2bData outsideInfo = Tpm2bData.Create(BuildFilledBytes(32, 0x11), pool))
        using(TpmlPcrSelection creationPcr = BuildSelection(pool, (TpmAlgIdConstants.TPM_ALG_SHA256, 3, [3])))
        using(Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool))
        using(Tpm2bPublic template = BuildEccSigningTemplate(TpmAlgIdConstants.TPM_ALG_SHA256))
        using(CreatePrimaryInput input = new(TpmRh.TPM_RH_OWNER, inSensitive, template, outsideInfo, creationPcr))
        using(TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool))
        {
            TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
                tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"CreatePrimary failed: '{result.ResponseCode}'.");

            using CreatePrimaryResponse primary = result.Value;
            await FlushPrimaryAsync(tpm, registry, primary.ObjectHandle.Value).ConfigureAwait(false);
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "CreatePrimary with a NON-EMPTY, now-CONSUMED creationPCR/outsideInfo pair must still return every carrier once the response is disposed and the primary is flushed.");

        using CreatePrimaryResponse parent = await CreateEccStorageParentAsync(
            tpm, registry, pool, TpmRh.TPM_RH_OWNER, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        long baselineAfterParent = trackingPool.OutstandingCount;

        using(Tpm2bData outsideInfo = Tpm2bData.Create(BuildFilledBytes(32, 0x22), pool))
        using(TpmlPcrSelection creationPcr = BuildSelection(pool, (TpmAlgIdConstants.TPM_ALG_SHA256, 3, [4])))
        using(Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool))
        using(Tpm2bPublic childTemplate = Tpm2bPublic.CreateSealedDataTemplate(TpmAlgIdConstants.TPM_ALG_SHA256, pool, noDa: true))
        using(CreateInput input = new(parent.ObjectHandle.Value, inSensitive, childTemplate, outsideInfo, creationPcr))
        using(TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool))
        {
            TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, input, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"Create failed: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }

        Assert.AreEqual(
            baselineAfterParent, trackingPool.OutstandingCount,
            "Create with a NON-EMPTY, now-CONSUMED creationPCR/outsideInfo pair must likewise return every carrier once the response is disposed.");
    }

    /// <summary>
    /// A regression check: <c>Extensions/Seal</c>'s <see cref="TpmDeviceExtensions.SealAsync"/> drops the creation
    /// by-products entirely, so its persisted <see cref="TpmSealedBlob"/> is exactly
    /// <c>outPrivate ‖ outPublic</c> and still round-trips the sealed secret byte for byte — the creationData
    /// conformance changes above must not perturb the Extensions surface at all
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 12.1).
    /// </summary>
    [TestMethod]
    public async Task SealAsyncsSealedBlobIsUnaffectedByTheCreationDataByProducts()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateEccStorageParentAsync(
            tpm, registry, pool, TpmRh.TPM_RH_OWNER, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        byte[] secret = "seal-extension red-check secret."u8.ToArray();

        TpmResult<TpmSealedBlob> sealResult = await tpm.SealAsync(
            parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, secret, ReadOnlyMemory<byte>.Empty, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(sealResult.IsSuccess, $"SealAsync failed: '{sealResult.ResponseCode}'.");

        using TpmSealedBlob sealedBlob = sealResult.Value;
        Assert.AreEqual(
            sealedBlob.OutPrivate.SerializedSize + sealedBlob.OutPublic.GetSerializedSize(), sealedBlob.GetSerializedSize(),
            "The persisted sealed blob carries only outPrivate and outPublic — the Extensions path drops the creation by-products entirely.");

        TpmResult<UnsealResponse> unsealResult = await tpm.UnsealAsync(
            parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, sealedBlob, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(unsealResult.IsSuccess, $"UnsealAsync failed: '{unsealResult.ResponseCode}'.");

        using UnsealResponse unsealed = unsealResult.Value;
        Assert.IsTrue(
            unsealed.OutData.AsReadOnlySpan().SequenceEqual(secret),
            "The sealed blob must still round-trip the exact secret byte for byte, proving the Extensions path is untouched by the creationData conformance changes above.");
    }

    /// <summary>
    /// Builds the ECC signing template every CreatePrimary fixture in this file uses, mirroring
    /// <see cref="CreatePrimaryInput.ForEccSigningKey"/> but exposing the nameAlg so a caller-chosen creationPCR/
    /// outsideInfo pair can still be threaded through the raw <see cref="CreatePrimaryInput"/> constructor.
    /// </summary>
    /// <param name="nameAlg">The Name algorithm to carry in the template.</param>
    /// <returns>The public template; the caller disposes it.</returns>
    private static Tpm2bPublic BuildEccSigningTemplate(TpmAlgIdConstants nameAlg)
    {
        TpmaObject attributes =
            TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.USER_WITH_AUTH | TpmaObject.SIGN_ENCRYPT | TpmaObject.NO_DA;

        return Tpm2bPublic.CreateEccSigningTemplate(nameAlg, attributes, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256));
    }

    /// <summary>
    /// Creates an ECC restricted storage parent (suitable as a <c>TPM2_Create()</c> parent) under
    /// <paramref name="hierarchy"/> with the requested nameAlg and an empty authValue.
    /// </summary>
    private async Task<CreatePrimaryResponse> CreateEccStorageParentAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy, TpmAlgIdConstants nameAlg)
    {
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic template = Tpm2bPublic.CreateEccStorageParentTemplate(nameAlg, TpmEccCurveConstants.TPM_ECC_NIST_P256, noDa: true);
        using CreatePrimaryInput input = new(hierarchy, inSensitive, template, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC storage parent, {hierarchy}, nameAlg={nameAlg}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Issues <c>TPM2_FlushContext()</c> against a created primary's handle, releasing its durable retained carriers.</summary>
    private async Task FlushPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, uint handle)
    {
        var flush = FlushContextInput.ForHandle(handle);
        TpmResult<FlushContextResponse> result = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flush, [], null, BaseMemoryPool.Shared, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"FlushContext of the created primary failed: '{result.ResponseCode}'.");
    }

    /// <summary>Issues <c>TPM2_FlushContext()</c> against a session handle the hand-crafted harness started, unless it is the sentinel zero (never allocated).</summary>
    private async Task FlushIfPresentAsync(TpmDevice tpm, TpmResponseRegistry registry, uint handle)
    {
        if(handle == 0)
        {
            return;
        }

        var flush = FlushContextInput.ForHandle(handle);
        TpmResult<FlushContextResponse> result = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flush, [], null, BaseMemoryPool.Shared, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"FlushContext failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Reads the given PCR indices over the real wire with <c>TPM2_PCR_Read()</c> (no authorization required)
    /// and returns their values concatenated in the order the response returns them — the independent oracle
    /// input for every pcrDigest assertion in this file.
    /// </summary>
    private static async Task<byte[]> ReadPcrValuesConcatenatedAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmAlgIdConstants bank, int[] indices, CancellationToken cancellationToken)
    {
        using PcrReadInput input = PcrReadInput.ForPcrs(bank, indices, pool);
        TpmResult<PcrReadResponse> result = await TpmCommandExecutor.ExecuteAsync<PcrReadResponse>(
            tpm, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_PCR_Read failed: '{result.ResponseCode}'.");

        using PcrReadResponse response = result.Value;
        int total = 0;
        for(int i = 0; i < response.PcrValues.Count; i++)
        {
            total += response.PcrValues[i].Size;
        }

        byte[] concatenated = new byte[total];
        int offset = 0;
        for(int i = 0; i < response.PcrValues.Count; i++)
        {
            ReadOnlySpan<byte> value = response.PcrValues[i].AsReadOnlySpan();
            value.CopyTo(concatenated.AsSpan(offset));
            offset += value.Length;
        }

        return concatenated;
    }

    /// <summary>
    /// Computes a digest through the registered digest seam (never a direct framework hash) under the framework
    /// <see cref="HashAlgorithmName"/> matching a declared TPM nameAlg — the shared independent oracle every
    /// creationHash/pcrDigest/Qualified-Name assertion in this file goes through.
    /// </summary>
    private static async Task<byte[]> ComputeDigestAsync(
        ReadOnlyMemory<byte> message, TpmAlgIdConstants nameAlg, int digestSize, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        HashAlgorithmName frameworkAlg = nameAlg switch
        {
            TpmAlgIdConstants.TPM_ALG_SHA1 => HashAlgorithmName.SHA1,
            TpmAlgIdConstants.TPM_ALG_SHA256 => HashAlgorithmName.SHA256,
            TpmAlgIdConstants.TPM_ALG_SHA384 => HashAlgorithmName.SHA384,
            TpmAlgIdConstants.TPM_ALG_SHA512 => HashAlgorithmName.SHA512,
            _ => throw new NotSupportedException($"Test oracle does not support nameAlg '{nameAlg}'.")
        };

        Tag tag = Tag.Create(frameworkAlg).With(Purpose.Digest).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlySequence<byte>(message), digestSize, tag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>Gets the digest width, in octets, for one of the nameAlg values this test file's oracle supports.</summary>
    private static int DigestSizeFor(TpmAlgIdConstants nameAlg) => nameAlg switch
    {
        TpmAlgIdConstants.TPM_ALG_SHA1 => 20,
        TpmAlgIdConstants.TPM_ALG_SHA256 => 32,
        TpmAlgIdConstants.TPM_ALG_SHA384 => 48,
        TpmAlgIdConstants.TPM_ALG_SHA512 => 64,
        _ => throw new NotSupportedException($"Test oracle does not support nameAlg '{nameAlg}'.")
    };

    /// <summary>
    /// Independently recomputes a primary object's Qualified Name — <c>nameAlg || H_nameAlg(hierarchy handle ||
    /// Name)</c> (TPM 2.0 Library Part 1, clause 23.5) — reading the nameAlg back out of <paramref name="name"/>'s
    /// own two-octet prefix rather than assuming SHA-256, so this oracle serves every nameAlg the matrix tests
    /// exercise. Never calls the production <see cref="TpmObjectName"/> helper.
    /// </summary>
    private static async Task<byte[]> ComputeQualifiedNameAsync(uint hierarchy, ReadOnlyMemory<byte> name, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        ushort nameAlgValue = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(name.Span[..sizeof(ushort)]);
        var nameAlg = (TpmAlgIdConstants)nameAlgValue;
        int digestSize = DigestSizeFor(nameAlg);

        byte[] message = new byte[sizeof(uint) + name.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(message, hierarchy);
        name.Span.CopyTo(message.AsSpan(sizeof(uint)));

        byte[] digest = await ComputeDigestAsync(message, nameAlg, digestSize, pool, cancellationToken).ConfigureAwait(false);

        byte[] qualifiedName = new byte[sizeof(ushort) + digest.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(qualifiedName, nameAlgValue);
        digest.CopyTo(qualifiedName.AsSpan(sizeof(ushort)));

        return qualifiedName;
    }

    /// <summary>Reports whether bit <paramref name="bit"/> is set in <paramref name="bitmap"/> (TPM 2.0 Library Part 2, clause 10.5.2's bitmap encoding).</summary>
    private static bool IsBitSet(ReadOnlySpan<byte> bitmap, int bit) => (bitmap[bit / 8] & (1 << (bit % 8))) != 0;

    /// <summary>
    /// Builds a hand-crafted <c>TPML_PCR_SELECTION</c> wire image naming one selector per supplied tuple, in
    /// order — the raw bytes <see cref="TpmInHouseSimulatorParameterDecryptionTests.SendHandCraftedCreateAsync"/>'s
    /// <c>creationPcrWire</c> parameter wants, and the input <see cref="ParseSelectionWire"/>/<see cref="BuildSelection"/>
    /// parse into a real, owned <see cref="TpmlPcrSelection"/> for the plain-password commands.
    /// </summary>
    /// <param name="selections">Each selector's bank, its <c>sizeofSelect</c> width, and the bit indices to set within it.</param>
    /// <returns>The marshaled selection octets.</returns>
    private static byte[] BuildPcrSelectionWireBytes(params (TpmAlgIdConstants Bank, int SizeofSelect, int[] Bits)[] selections)
    {
        int totalSize = sizeof(uint);
        foreach((TpmAlgIdConstants _, int sizeofSelect, int[] _) in selections)
        {
            totalSize += sizeof(ushort) + sizeof(byte) + sizeofSelect;
        }

        byte[] octets = new byte[totalSize];
        var writer = new TpmWriter(octets);
        writer.WriteUInt32((uint)selections.Length);
        foreach((TpmAlgIdConstants bank, int sizeofSelect, int[] bits) in selections)
        {
            writer.WriteUInt16((ushort)bank);
            writer.WriteByte((byte)sizeofSelect);

            byte[] bitmap = new byte[sizeofSelect];
            foreach(int bit in bits)
            {
                bitmap[bit / 8] |= (byte)(1 << (bit % 8));
            }

            writer.WriteBytes(bitmap);
        }

        return octets;
    }

    /// <summary>Parses a hand-built <c>TPML_PCR_SELECTION</c> wire image (from <see cref="BuildPcrSelectionWireBytes"/>) into a real, owned selection.</summary>
    private static TpmlPcrSelection ParseSelectionWire(byte[] wire, BaseMemoryPool pool)
    {
        var reader = new TpmReader(wire);
        TpmlPcrSelection selection = TpmlPcrSelection.Parse(ref reader, pool);
        Assert.AreEqual(0, reader.Remaining, "The hand-built selection wire must be fully consumed by Parse.");

        return selection;
    }

    /// <summary>Builds and parses a <c>TPML_PCR_SELECTION</c> directly from selector tuples — the composition of <see cref="BuildPcrSelectionWireBytes"/> and <see cref="ParseSelectionWire"/>.</summary>
    private static TpmlPcrSelection BuildSelection(BaseMemoryPool pool, params (TpmAlgIdConstants Bank, int SizeofSelect, int[] Bits)[] selections) =>
        ParseSelectionWire(BuildPcrSelectionWireBytes(selections), pool);

    /// <summary>Marshals <paramref name="content"/> as a raw <c>TPM2B_DATA</c> wire image (a 2-octet size prefix then the octets themselves).</summary>
    private static byte[] BuildOutsideInfoWireBytes(ReadOnlySpan<byte> content)
    {
        byte[] octets = new byte[sizeof(ushort) + content.Length];
        var writer = new TpmWriter(octets);
        writer.WriteTpm2b(content);

        return octets;
    }

    /// <summary>Builds a byte array of <paramref name="length"/> octets, every one <paramref name="fill"/> — a deliberately non-zero, non-empty payload for a pool-balance or content-echo fixture.</summary>
    private static byte[] BuildFilledBytes(int length, byte fill)
    {
        byte[] bytes = new byte[length];
        Array.Fill(bytes, fill);

        return bytes;
    }

    /// <summary>
    /// Parses the creation data out of an over-sessions <c>TPM2_Create()</c> response's raw parameter bytes
    /// (<c>outPrivate ‖ outPublic ‖ creationData ‖ creationHash ‖ creationTicket</c>), skipping the two leading
    /// fields this file does not need — <see cref="TpmInHouseSimulatorParameterDecryptionTests.SendHandCraftedCreateAsync"/>
    /// itself parses no further than <c>outPublic</c>.
    /// </summary>
    private static Tpm2bCreationData ParseCreationDataFromResponseParameters(byte[] responseParameters, BaseMemoryPool pool)
    {
        var reader = new TpmReader(responseParameters);
        using(Tpm2bPrivate.Parse(ref reader, pool))
        {
        }

        using(Tpm2bPublic.Parse(ref reader, pool))
        {
        }

        return Tpm2bCreationData.Parse(ref reader, pool);
    }

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-creation-data", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an
    /// unauthorized command on the wire, to move it into <see cref="TpmLifecyclePhase.Operational"/>.
    /// </summary>
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var input = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_CertifyCreation, TpmResponseCodec.CertifyCreation);
        _ = registry.Register(TpmCcConstants.TPM_CC_PCR_Read, TpmResponseCodec.PcrRead);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }
}
