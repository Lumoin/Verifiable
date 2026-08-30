using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Proves the capture of <c>TPM2_CreatePrimary()</c>'s and <c>TPM2_Create()</c>'s <c>outsideInfo</c>
/// (<c>TPM2B_DATA</c>) and <c>creationPCR</c> (<c>TPML_PCR_SELECTION</c>) trailing parameters against the
/// in-house behavioural <see cref="TpmSimulator"/>: the two refusals these parameters raise (a
/// <c>creationPCR</c> naming more banks than the list admits; an <c>outsideInfo</c> wider than
/// <c>TPM2B_DATA</c>'s declared bound), the truncation refusal beneath them, the precedence between an
/// over-bound declared size and a truncated frame when both apply at once, that a spec-legal pair at
/// the exact bound still succeeds, and that the parse-rented carriers the effect owns are returned to the
/// pool on every path.
/// </summary>
/// <remarks>
/// <para>
/// <c>BuildCreationByProductsAsync</c> writes the same faithful literals for every command's <c>creationData</c>
/// regardless of the captured <c>outsideInfo</c>/<c>creationPCR</c> — a successful response's <c>creationData</c>
/// is identical whether the two parameters are empty or genuinely rented. Every carrier driven through a
/// refusal or success case here is deliberately NON-EMPTY, because an empty one parses to the type's shared
/// dispose-immune sentinel and would make a pool-balance assertion vacuous.
/// </para>
/// <para>
/// A <c>creationPCR</c> naming 17 banks and an <c>outsideInfo</c> one octet past its bound cannot be expressed
/// through <see cref="CreateInput"/>/<see cref="CreatePrimaryInput"/> at all — <see cref="TpmlPcrSelection.Parse"/>
/// and <see cref="Tpm2bData.Create(ReadOnlySpan{byte}, BaseMemoryPool)"/> refuse exactly those shapes themselves —
/// so those two commands are framed octet by octet, mirroring
/// <c>TpmInHouseSimulatorQuoteCarrierTests.FrameQuoteCommand</c>'s identical technique for
/// <c>TPM2_Quote()</c>'s own <c>PCRselect</c> bound. A one-selection-count-too-many and a one-octet-too-wide
/// pair are both otherwise ordinary, spec-legal frames.
/// </para>
/// <para>
/// The over-sessions <c>TPM2_Create()</c> tail decode (<c>DecryptCreateSensitiveAsync</c>) applies the identical
/// probe-then-parse capture behind a real HMAC session; its own over-bound-<c>creationPCR</c> refusal (a
/// rented, non-empty <c>outsideInfo</c> released when the trailing <c>creationPCR</c> then refuses) is proven in
/// <see cref="TpmInHouseSimulatorParameterDecryptionTests.CreateOverSessionsWithCreationPcrCountAboveTheListBoundIsRefusedWithSize"/>,
/// which reuses that file's existing hand-crafted independent-HMAC harness rather than duplicating it here.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorCreationParameterTests
{
    /// <summary>The PCR bank every hand-built <c>creationPCR</c> selection here names.</summary>
    private const TpmAlgIdConstants PcrBank = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The real, non-empty secret the <c>TPM2_Create()</c> baseline seals and recovers.</summary>
    private static byte[] SealedSecretBytes { get; } = "creation-parameter carrier proof secret"u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A <c>creationPCR</c> naming 17 banks — one more than <see cref="TpmlPcrSelection.MaxSelections"/> — is
    /// refused with <c>TPM_RC_SIZE</c> on <c>TPM2_CreatePrimary()</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.8.7, Table 128, "response code when count is greater
    /// than the possible number of banks").
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryWithCreationPcrCountAboveTheListBoundReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic inPublic = BuildEccSigningInPublic();
        byte[] outsideInfoWire = BuildTpm2bDataWireOctets(BuildContentBytes(32, 0x11));
        byte[] pcrSelectionWire = BuildPcrSelectionOctets(TpmlPcrSelection.MaxSelections + 1);

        TpmRcConstants code = await SubmitCreateFamilyCommandAsync(
            simulator, pool, TpmCcConstants.TPM_CC_CreatePrimary, (uint)TpmRh.TPM_RH_OWNER,
            inSensitive, inPublic, outsideInfoWire, pcrSelectionWire).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "A creationPCR naming more than MaxSelections banks is TPM_RC_SIZE (Table 128).");
    }

    /// <summary>
    /// The <c>TPM2_Create()</c> counterpart of
    /// <see cref="CreatePrimaryWithCreationPcrCountAboveTheListBoundReturnsSize"/> — the same over-bound
    /// <c>creationPCR</c> refusal applies identically to the sealed-data path's own <c>creationPCR</c> capture
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.8.7, Table 128).
    /// </summary>
    [TestMethod]
    public async Task CreateWithCreationPcrCountAboveTheListBoundReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic inPublic = BuildSealedDataInPublic(pool);
        byte[] outsideInfoWire = BuildTpm2bDataWireOctets(BuildContentBytes(32, 0x22));
        byte[] pcrSelectionWire = BuildPcrSelectionOctets(TpmlPcrSelection.MaxSelections + 1);

        TpmRcConstants code = await SubmitCreateFamilyCommandAsync(
            simulator, pool, TpmCcConstants.TPM_CC_Create, parent.ObjectHandle.Value,
            inSensitive, inPublic, outsideInfoWire, pcrSelectionWire).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "A creationPCR naming more than MaxSelections banks is TPM_RC_SIZE (Table 128).");
    }

    /// <summary>
    /// An <c>outsideInfo</c> one octet past <see cref="Tpm2bData.MaxSize"/> (<c>sizeof(TPMT_HA)</c>, 66 octets:
    /// the 2-octet algorithm identifier plus the largest supported digest) is refused with <c>TPM_RC_SIZE</c> on
    /// <c>TPM2_CreatePrimary()</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.3, Table 91).
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryWithOutsideInfoAboveTheDataBoundReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic inPublic = BuildEccSigningInPublic();
        byte[] outsideInfoWire = BuildTpm2bDataWireOctets(BuildContentBytes(Tpm2bData.MaxSize + 1, 0x33));
        byte[] pcrSelectionWire = EmptyPcrSelectionWire;

        TpmRcConstants code = await SubmitCreateFamilyCommandAsync(
            simulator, pool, TpmCcConstants.TPM_CC_CreatePrimary, (uint)TpmRh.TPM_RH_OWNER,
            inSensitive, inPublic, outsideInfoWire, pcrSelectionWire).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "An outsideInfo wider than Tpm2bData.MaxSize is TPM_RC_SIZE (Table 91).");
    }

    /// <summary>
    /// The <c>TPM2_Create()</c> counterpart of
    /// <see cref="CreatePrimaryWithOutsideInfoAboveTheDataBoundReturnsSize"/> — the same over-bound
    /// <c>outsideInfo</c> refusal applies identically to the sealed-data path's own <c>outsideInfo</c> capture
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.3, Table 91).
    /// </summary>
    [TestMethod]
    public async Task CreateWithOutsideInfoAboveTheDataBoundReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic inPublic = BuildSealedDataInPublic(pool);
        byte[] outsideInfoWire = BuildTpm2bDataWireOctets(BuildContentBytes(Tpm2bData.MaxSize + 1, 0x44));
        byte[] pcrSelectionWire = EmptyPcrSelectionWire;

        TpmRcConstants code = await SubmitCreateFamilyCommandAsync(
            simulator, pool, TpmCcConstants.TPM_CC_Create, parent.ObjectHandle.Value,
            inSensitive, inPublic, outsideInfoWire, pcrSelectionWire).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "An outsideInfo wider than Tpm2bData.MaxSize is TPM_RC_SIZE (Table 91).");
    }

    /// <summary>
    /// A non-empty <c>outsideInfo</c> at EXACTLY <see cref="Tpm2bData.MaxSize"/> (66 octets, the <c>TPM2B_DATA</c>
    /// spec bound) paired with a <c>creationPCR</c> naming EXACTLY <see cref="TpmlPcrSelection.MaxSelections"/>
    /// (16 banks, this library's widened <c>HASH_COUNT</c> bound — see that member's own doc comment) must still
    /// succeed on <c>TPM2_CreatePrimary()</c> — the response parses and the created key signs, proving neither
    /// bound is an off-by-one refusal
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.3, Table 91 and clause 10.8.7, Table 128).
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryWithOutsideInfoAndCreationPcrAtTheirRespectiveBoundsSucceedsAndKeyIsUsable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic inPublic = BuildEccSigningInPublic();
        using Tpm2bData outsideInfo = Tpm2bData.Create(BuildContentBytes(Tpm2bData.MaxSize, 0x55), pool);
        using TpmlPcrSelection creationPcr = ParseSelectionOctets(BuildPcrSelectionOctets(TpmlPcrSelection.MaxSelections), pool);
        using CreatePrimaryInput input = new(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, outsideInfo, creationPcr);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary at the outsideInfo/creationPCR spec bound must succeed: '{result.ResponseCode}'.");

        using CreatePrimaryResponse primary = result.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECC, primary.OutPublic.PublicArea.Type);

        using SignInput signInput = SignInput.ForEcdsa(primary.ObjectHandle, FixedDigestBytes, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"The primary created at the spec bound must still be usable to sign: '{signResult.ResponseCode}'.");
        signResult.Value.Dispose();
    }

    /// <summary>
    /// The <c>TPM2_Create()</c> counterpart of
    /// <see cref="CreatePrimaryWithOutsideInfoAndCreationPcrAtTheirRespectiveBoundsSucceedsAndKeyIsUsable"/>: the
    /// same at-bound pair succeeds on the sealed-data path, and the sealed object loads and unseals back to the
    /// original secret
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.3, Table 91 and clause 10.8.7, Table 128).
    /// </summary>
    [TestMethod]
    public async Task CreateWithOutsideInfoAndCreationPcrAtTheirRespectiveBoundsSucceedsAndKeyIsUsable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecretBytes, pool);
        using Tpm2bPublic inPublic = BuildSealedDataInPublic(pool);
        using Tpm2bData outsideInfo = Tpm2bData.Create(BuildContentBytes(Tpm2bData.MaxSize, 0x66), pool);
        using TpmlPcrSelection creationPcr = ParseSelectionOctets(BuildPcrSelectionOctets(TpmlPcrSelection.MaxSelections), pool);
        using CreateInput input = new(parentHandle, inSensitive, inPublic, outsideInfo, creationPcr);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, input, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create at the outsideInfo/creationPCR spec bound must succeed: '{createResult.ResponseCode}'.");

        using CreateResponse sealedObject = createResult.Value;
        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
        using Tpm2bPublic loadPublic = ClonePublic(sealedObject.OutPublic, pool);
        using LoadInput loadInput = new(parentHandle, inPrivate, loadPublic);
        using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load of the sealed object created at the spec bound must succeed: '{loadResult.ResponseCode}'.");

        using LoadResponse loaded = loadResult.Value;
        using TpmPasswordSession itemAuth = TpmPasswordSession.CreateEmpty(pool);
        UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);

        TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
            tpm, unsealInput, [itemAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(unsealResult.IsSuccess, $"Unseal of the object created at the spec bound must succeed: '{unsealResult.ResponseCode}'.");

        using UnsealResponse unsealed = unsealResult.Value;
        Assert.IsTrue(
            unsealed.OutData.AsReadOnlySpan().SequenceEqual(SealedSecretBytes),
            "The sealed object created at the outsideInfo/creationPCR spec bound must still recover its secret byte for byte.");
    }

    /// <summary>
    /// An <c>outsideInfo</c> whose declared size (10, within <see cref="Tpm2bData.MaxSize"/>) exceeds what the
    /// command frame actually carries is refused with <c>TPM_RC_INSUFFICIENT</c> on <c>TPM2_CreatePrimary()</c> —
    /// the declared size passes the over-bound peek, so the truncation probe beneath it is what answers
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 5.2).
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryWithTruncatedOutsideInfoReturnsInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic inPublic = BuildEccSigningInPublic();

        TpmRcConstants code = await SubmitTruncatedOutsideInfoCommandAsync(
            simulator, pool, TpmCcConstants.TPM_CC_CreatePrimary, (uint)TpmRh.TPM_RH_OWNER,
            inSensitive, inPublic, declaredOutsideInfoSize: 10, actualOutsideInfoBytesProvided: 2).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_INSUFFICIENT, code, "A declared outsideInfo size past the frame's own end is TPM_RC_INSUFFICIENT.");
    }

    /// <summary>
    /// The <c>TPM2_Create()</c> counterpart of <see cref="CreatePrimaryWithTruncatedOutsideInfoReturnsInsufficient"/>
    /// — the sealed-data path's truncation behaviour is the same
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 5.2).
    /// </summary>
    [TestMethod]
    public async Task CreateWithTruncatedOutsideInfoReturnsInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic inPublic = BuildSealedDataInPublic(pool);

        TpmRcConstants code = await SubmitTruncatedOutsideInfoCommandAsync(
            simulator, pool, TpmCcConstants.TPM_CC_Create, parent.ObjectHandle.Value,
            inSensitive, inPublic, declaredOutsideInfoSize: 10, actualOutsideInfoBytesProvided: 2).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_INSUFFICIENT, code, "A declared outsideInfo size past the frame's own end is TPM_RC_INSUFFICIENT.");
    }

    /// <summary>
    /// A <c>creationPCR</c> naming one bank whose <c>sizeofSelect</c> (3, a spec-legal width) declares more
    /// bitmap octets than the frame actually carries is refused with <c>TPM_RC_INSUFFICIENT</c> on
    /// <c>TPM2_CreatePrimary()</c> — the count itself (1) passes the over-bound peek, so the per-selection
    /// truncation probe beneath it is what answers, and the already-rented, non-empty <c>outsideInfo</c> is
    /// released by the same refusing arm
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.5.2, Table 107).
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryWithTruncatedCreationPcrBitmapReturnsInsufficient()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(trackingPool.Pool);
        using Tpm2bPublic inPublic = BuildEccSigningInPublic();
        byte[] outsideInfoWire = BuildTpm2bDataWireOctets(BuildContentBytes(32, 0xC1));
        byte[] pcrSelectionWire = BuildTruncatedSingleSelectionBitmapOctets(presentBitmapOctets: 1);

        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants code = await SubmitCreateFamilyCommandAsync(
            simulator, trackingPool.Pool, TpmCcConstants.TPM_CC_CreatePrimary, (uint)TpmRh.TPM_RH_OWNER,
            inSensitive, inPublic, outsideInfoWire, pcrSelectionWire).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_INSUFFICIENT, code, "A creationPCR selection truncated mid-bitmap is TPM_RC_INSUFFICIENT (Table 107).");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The already-rented, non-empty outsideInfo must be released when the trailing creationPCR then refuses.");
    }

    /// <summary>
    /// The <c>TPM2_Create()</c> counterpart of
    /// <see cref="CreatePrimaryWithTruncatedCreationPcrBitmapReturnsInsufficient"/> — the sealed-data path's
    /// truncation behaviour for a spec-legal but incomplete <c>creationPCR</c> selection is the same
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.5.2, Table 107).
    /// </summary>
    [TestMethod]
    public async Task CreateWithTruncatedCreationPcrBitmapReturnsInsufficient()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(trackingPool.Pool);
        using Tpm2bPublic inPublic = BuildSealedDataInPublic(trackingPool.Pool);
        byte[] outsideInfoWire = BuildTpm2bDataWireOctets(BuildContentBytes(32, 0xC2));
        byte[] pcrSelectionWire = BuildTruncatedSingleSelectionBitmapOctets(presentBitmapOctets: 1);

        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants code = await SubmitCreateFamilyCommandAsync(
            simulator, trackingPool.Pool, TpmCcConstants.TPM_CC_Create, parent.ObjectHandle.Value,
            inSensitive, inPublic, outsideInfoWire, pcrSelectionWire).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_INSUFFICIENT, code, "A creationPCR selection truncated mid-bitmap is TPM_RC_INSUFFICIENT (Table 107).");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The already-rented, non-empty outsideInfo must be released when the trailing creationPCR then refuses.");
    }

    /// <summary>
    /// An <c>outsideInfo</c> that is BOTH over <see cref="Tpm2bData.MaxSize"/> (declaring 67 octets) AND
    /// truncated (the frame carries only 10) is refused with <c>TPM_RC_SIZE</c>, not <c>TPM_RC_INSUFFICIENT</c>,
    /// on <c>TPM2_CreatePrimary()</c> — the declared size is peeked and checked against
    /// <see cref="Tpm2bData.MaxSize"/> on a by-value reader copy before the truncation probe ever runs, so the
    /// over-bound declaration wins even though the frame could never have supplied all 67 octets either way
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.3, Table 91; Part 4, Marshal.c,
    /// <c>TPM2B_DATA_Unmarshal</c>, which checks the size bound ahead of the array read).
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryWithOverBoundAndTruncatedOutsideInfoReturnsSize()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(trackingPool.Pool);
        using Tpm2bPublic inPublic = BuildEccSigningInPublic();

        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants code = await SubmitTruncatedOutsideInfoCommandAsync(
            simulator, trackingPool.Pool, TpmCcConstants.TPM_CC_CreatePrimary, (uint)TpmRh.TPM_RH_OWNER,
            inSensitive, inPublic, declaredOutsideInfoSize: Tpm2bData.MaxSize + 1, actualOutsideInfoBytesProvided: 10).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "An outsideInfo declaring a size past Tpm2bData.MaxSize is TPM_RC_SIZE even when the frame is also too short to supply it (Table 91).");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The refusal must rent nothing for the malformed outsideInfo and release everything parsed ahead of it (inSensitive and inPublic, including the ECC template's own key-material carriers).");
    }

    /// <summary>
    /// A <c>creationPCR</c> naming 17 banks — one more than <see cref="TpmlPcrSelection.MaxSelections"/> — while
    /// the frame supplies only ONE full selection entry is refused with <c>TPM_RC_SIZE</c>, not
    /// <c>TPM_RC_INSUFFICIENT</c>, on <c>TPM2_CreatePrimary()</c>: the declared count is peeked and checked
    /// against <see cref="TpmlPcrSelection.MaxSelections"/> on a by-value reader copy before the per-selection
    /// truncation probe ever looks past the first entry, so the over-bound declaration wins even though the
    /// frame could never have supplied all 17 entries either way — and the already-rented, non-empty
    /// <c>outsideInfo</c> is released by the same refusing arm
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.8.7, Table 128; Part 4, Marshal.c,
    /// <c>TPML_PCR_SELECTION_Unmarshal</c>, which checks the count bound ahead of the per-selection loop).
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryWithOverBoundAndTruncatedCreationPcrReturnsSize()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(trackingPool.Pool);
        using Tpm2bPublic inPublic = BuildEccSigningInPublic();
        byte[] outsideInfoWire = BuildTpm2bDataWireOctets(BuildContentBytes(32, 0xC3));
        byte[] pcrSelectionWire = BuildOverBoundCreationPcrWireWithOneEntryPresent(TpmlPcrSelection.MaxSelections + 1);

        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants code = await SubmitCreateFamilyCommandAsync(
            simulator, trackingPool.Pool, TpmCcConstants.TPM_CC_CreatePrimary, (uint)TpmRh.TPM_RH_OWNER,
            inSensitive, inPublic, outsideInfoWire, pcrSelectionWire).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "A creationPCR count past MaxSelections is TPM_RC_SIZE even when the frame is also too short to supply every entry (Table 128).");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The already-rented, non-empty outsideInfo must be released when the trailing creationPCR then refuses.");
    }

    /// <summary>
    /// Proves the pooled-carrier ownership of <c>TPM2_CreatePrimary()</c>'s new <c>outsideInfo</c>/<c>creationPCR</c>
    /// capture against an ABSOLUTE pool baseline: the over-bound <c>creationPCR</c> refusal and the over-bound
    /// <c>outsideInfo</c> refusal each leave the metered pool exactly where they found it (the parser rents
    /// nothing for a frame it refuses), and a successful round
    /// trip — with either an empty or a genuinely non-empty <c>outsideInfo</c>/<c>creationPCR</c> pair — returns
    /// every carrier once the response is disposed and the created primary is flushed.
    /// </summary>
    /// <remarks>
    /// A loaded primary retains its private key and Name in a durable <see cref="TransientKeyState"/> until
    /// <c>TPM2_FlushContext()</c> evicts it, so the created primary is flushed here before the balance is read —
    /// otherwise the retained state's own carriers, not <c>outsideInfo</c>/<c>creationPCR</c>, would be the
    /// carriers still outstanding.
    /// </remarks>
    [TestMethod]
    public async Task CreatePrimaryCarrierPoolBalanceAcrossRefusalsAndSuccess()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        {
            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(trackingPool.Pool);
            using Tpm2bPublic inPublic = BuildEccSigningInPublic();
            byte[] outsideInfoWire = BuildTpm2bDataWireOctets(BuildContentBytes(32, 0x77));
            byte[] pcrSelectionWire = BuildPcrSelectionOctets(TpmlPcrSelection.MaxSelections + 1);

            TpmRcConstants code = await SubmitCreateFamilyCommandAsync(
                simulator, trackingPool.Pool, TpmCcConstants.TPM_CC_CreatePrimary, (uint)TpmRh.TPM_RH_OWNER,
                inSensitive, inPublic, outsideInfoWire, pcrSelectionWire).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "An over-bound creationPCR must still answer TPM_RC_SIZE under the metered pool.");
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The over-bound creationPCR refusal must not move the pool balance.");

        {
            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(trackingPool.Pool);
            using Tpm2bPublic inPublic = BuildEccSigningInPublic();
            byte[] outsideInfoWire = BuildTpm2bDataWireOctets(BuildContentBytes(Tpm2bData.MaxSize + 1, 0x88));
            byte[] pcrSelectionWire = EmptyPcrSelectionWire;

            TpmRcConstants code = await SubmitCreateFamilyCommandAsync(
                simulator, trackingPool.Pool, TpmCcConstants.TPM_CC_CreatePrimary, (uint)TpmRh.TPM_RH_OWNER,
                inSensitive, inPublic, outsideInfoWire, pcrSelectionWire).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "An over-bound outsideInfo must still answer TPM_RC_SIZE under the metered pool.");
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The over-bound outsideInfo refusal must not move the pool balance.");

        await ExecuteCreatePrimarySuccessAsync(
            tpm, trackingPool.Pool, registry, Tpm2bData.Empty, TpmlPcrSelection.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A successful CreatePrimary with an EMPTY outsideInfo/creationPCR pair must return every carrier once the response is disposed and the primary is flushed.");

        using(Tpm2bData outsideInfo = Tpm2bData.Create(BuildContentBytes(48, 0x99), trackingPool.Pool))
        using(TpmlPcrSelection creationPcr = ParseSelectionOctets(BuildPcrSelectionOctets(3), trackingPool.Pool))
        {
            await ExecuteCreatePrimarySuccessAsync(tpm, trackingPool.Pool, registry, outsideInfo, creationPcr).ConfigureAwait(false);
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A successful CreatePrimary with a NON-EMPTY outsideInfo/creationPCR pair must likewise return every carrier once the response is disposed and the primary is flushed, proving CreateEccKeyAsync is the genuine terminal owner of both.");
    }

    /// <summary>
    /// Runs one successful <c>TPM2_CreatePrimary()</c> ECC signing-key round trip with the supplied
    /// <c>outsideInfo</c>/<c>creationPCR</c> pair, disposes the response, and flushes the created primary — so
    /// <see cref="CreatePrimaryCarrierPoolBalanceAcrossRefusalsAndSuccess"/> can read an ABSOLUTE pool balance
    /// rather than one still carrying the durable key state's own retained rentals.
    /// </summary>
    private async Task ExecuteCreatePrimarySuccessAsync(
        TpmDevice tpm, BaseMemoryPool pool, TpmResponseRegistry registry, Tpm2bData outsideInfo, TpmlPcrSelection creationPcr)
    {
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic inPublic = BuildEccSigningInPublic();
        using CreatePrimaryInput input = new(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, outsideInfo, creationPcr);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary must succeed: '{result.ResponseCode}'.");

        using CreatePrimaryResponse primary = result.Value;
        await FlushPrimaryAsync(tpm, registry, primary.ObjectHandle.Value).ConfigureAwait(false);
    }

    /// <summary>Issues <c>TPM2_FlushContext()</c> against a created primary's handle, evicting its durable <see cref="TransientKeyState"/> and releasing the carriers it retains.</summary>
    private async Task FlushPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, uint handle)
    {
        var flush = FlushContextInput.ForHandle(handle);
        TpmResult<FlushContextResponse> result = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flush, [], null, BaseMemoryPool.Shared, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"FlushContext of the created primary failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// The <c>TPM2_Create()</c> counterpart of <see cref="CreatePrimaryCarrierPoolBalanceAcrossRefusalsAndSuccess"/>
    /// — the sealed-data path's <c>TpmCreateKeyedHashAction</c> is likewise the terminal owner of the new carriers on
    /// its own success path.
    /// </summary>
    [TestMethod]
    public async Task CreateCarrierPoolBalanceAcrossRefusalsAndSuccess()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        long baseline = trackingPool.OutstandingCount;

        {
            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(trackingPool.Pool);
            using Tpm2bPublic inPublic = BuildSealedDataInPublic(trackingPool.Pool);
            byte[] outsideInfoWire = BuildTpm2bDataWireOctets(BuildContentBytes(32, 0xAA));
            byte[] pcrSelectionWire = BuildPcrSelectionOctets(TpmlPcrSelection.MaxSelections + 1);

            TpmRcConstants code = await SubmitCreateFamilyCommandAsync(
                simulator, trackingPool.Pool, TpmCcConstants.TPM_CC_Create, parentHandle,
                inSensitive, inPublic, outsideInfoWire, pcrSelectionWire).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "An over-bound creationPCR must still answer TPM_RC_SIZE under the metered pool.");
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The over-bound creationPCR refusal must not move the pool balance.");

        {
            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(trackingPool.Pool);
            using Tpm2bPublic inPublic = BuildSealedDataInPublic(trackingPool.Pool);
            byte[] outsideInfoWire = BuildTpm2bDataWireOctets(BuildContentBytes(Tpm2bData.MaxSize + 1, 0xBB));
            byte[] pcrSelectionWire = EmptyPcrSelectionWire;

            TpmRcConstants code = await SubmitCreateFamilyCommandAsync(
                simulator, trackingPool.Pool, TpmCcConstants.TPM_CC_Create, parentHandle,
                inSensitive, inPublic, outsideInfoWire, pcrSelectionWire).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "An over-bound outsideInfo must still answer TPM_RC_SIZE under the metered pool.");
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The over-bound outsideInfo refusal must not move the pool balance.");

        {
            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecretBytes, trackingPool.Pool);
            using Tpm2bPublic inPublic = BuildSealedDataInPublic(trackingPool.Pool);
            using Tpm2bData outsideInfo = Tpm2bData.Create(BuildContentBytes(48, 0xCC), trackingPool.Pool);
            using TpmlPcrSelection creationPcr = ParseSelectionOctets(BuildPcrSelectionOctets(3), trackingPool.Pool);
            using CreateInput input = new(parentHandle, inSensitive, inPublic, outsideInfo, creationPcr);
            using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);

            TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, input, [parentAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"A non-empty, in-bound outsideInfo/creationPCR pair must succeed: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A successful Create must return the new outsideInfo/creationPCR carriers to the pool once the response is disposed.");
    }

    /// <summary>
    /// Builds the ECC signing template <c>TPM2_CreatePrimary()</c> uses throughout this file, composed directly
    /// from the same public pieces <see cref="CreatePrimaryInput.ForEccSigningKey"/> assembles internally, so a
    /// caller-chosen <c>outsideInfo</c>/<c>creationPCR</c> pair can still be threaded into the surrounding
    /// <see cref="CreatePrimaryInput"/> — the factory itself always hardcodes both to empty.
    /// </summary>
    /// <returns>The public template; the caller disposes it.</returns>
    private static Tpm2bPublic BuildEccSigningInPublic()
    {
        TpmaObject attributes = TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.SENSITIVE_DATA_ORIGIN
            | TpmaObject.USER_WITH_AUTH | TpmaObject.SIGN_ENCRYPT | TpmaObject.NO_DA;

        return Tpm2bPublic.CreateEccSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256, attributes, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256));
    }

    /// <summary>
    /// Builds the sealed-data template <c>TPM2_Create()</c> uses throughout this file, for the same reason
    /// <see cref="BuildEccSigningInPublic"/> composes its ECC counterpart directly rather than through a factory
    /// that hardcodes an empty <c>outsideInfo</c>/<c>creationPCR</c>.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The public template; the caller disposes it.</returns>
    private static Tpm2bPublic BuildSealedDataInPublic(BaseMemoryPool pool) =>
        Tpm2bPublic.CreateSealedDataTemplate(TpmAlgIdConstants.TPM_ALG_SHA256, pool, noDa: true);

    /// <summary>
    /// Builds a byte array of <paramref name="length"/> octets, every one <paramref name="fill"/> — a
    /// deliberately non-zero, non-empty payload so a carrier rented over it is never the shared empty sentinel a
    /// pool-balance assertion would find vacuous.
    /// </summary>
    private static byte[] BuildContentBytes(int length, byte fill)
    {
        byte[] bytes = new byte[length];
        Array.Fill(bytes, fill);

        return bytes;
    }

    /// <summary>
    /// Marshals <paramref name="content"/> as a raw <c>TPM2B_DATA</c> wire image (a 2-octet size prefix then the
    /// octets themselves), for the two commands' hand-framed refusal fixtures — never through
    /// <see cref="Tpm2bData.Create(ReadOnlySpan{byte}, BaseMemoryPool)"/>, which refuses a content wider than
    /// <see cref="Tpm2bData.MaxSize"/> itself and so cannot express the very over-bound shape these fixtures need
    /// to reach the wire.
    /// </summary>
    private static byte[] BuildTpm2bDataWireOctets(ReadOnlySpan<byte> content)
    {
        byte[] octets = new byte[sizeof(ushort) + content.Length];
        var writer = new TpmWriter(octets);
        writer.WriteTpm2b(content);

        return octets;
    }

    /// <summary>
    /// The empty <c>TPML_PCR_SELECTION</c> wire image (a zero <c>count</c>, no entries) — the pcr-selection half
    /// of a hand-framed command whose fixture is exercising <c>outsideInfo</c> instead.
    /// </summary>
    private static byte[] EmptyPcrSelectionWire { get; } = new byte[sizeof(uint)];

    /// <summary>
    /// A fixed, non-computed 32-octet stand-in digest for <c>TPM2_Sign()</c>'s externally-supplied
    /// <c>digest</c> parameter: the validation ticket is NULL, so the TPM never checks it against anything, and
    /// nothing here needs it to be a genuine hash of any particular message.
    /// </summary>
    private static byte[] FixedDigestBytes { get; } =
    [
        0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
        0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
        0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
        0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5
    ];

    /// <summary>
    /// Builds a <c>TPML_PCR_SELECTION</c> octet sequence naming <paramref name="selectionCount"/> banks, each
    /// selecting PCR 0 over the three octets that cover PCRs 0 to 23 — the shape needed to drive the list's
    /// count bound past <see cref="TpmlPcrSelection.MaxSelections"/>, which
    /// <see cref="TpmlPcrSelection.Parse"/> itself refuses to build in-process (mirroring
    /// <c>TpmInHouseSimulatorQuoteCarrierTests.BuildSelectionOctets</c>).
    /// </summary>
    /// <param name="selectionCount">How many bank selections to name.</param>
    /// <returns>The marshaled selection octets.</returns>
    private static byte[] BuildPcrSelectionOctets(int selectionCount)
    {
        const int SelectionSize = sizeof(ushort) + sizeof(byte) + 3;
        byte[] octets = new byte[sizeof(uint) + (selectionCount * SelectionSize)];
        var writer = new TpmWriter(octets);
        writer.WriteUInt32((uint)selectionCount);
        for(int i = 0; i < selectionCount; i++)
        {
            writer.WriteUInt16((ushort)PcrBank);
            writer.WriteByte(3);
            writer.WriteByte(0x01);
            writer.WriteByte(0x00);
            writer.WriteByte(0x00);
        }

        return octets;
    }

    /// <summary>
    /// Builds a <c>TPML_PCR_SELECTION</c> octet sequence declaring ONE selection over <see cref="PcrBank"/> with
    /// a spec-legal <c>sizeofSelect</c> of 3 (within <see cref="TpmlPcrSelection.PcrSelectMin"/>..
    /// <see cref="TpmlPcrSelection.PcrSelectMax"/>), but supplying only <paramref name="presentBitmapOctets"/> of
    /// that bitmap before the buffer ends — a frame truncated strictly WITHIN a single, otherwise well-formed
    /// selection entry, never at its <c>count</c> or at a whole missing entry.
    /// </summary>
    /// <param name="presentBitmapOctets">How many of the declared 3 bitmap octets are actually present.</param>
    /// <returns>The marshaled, truncated selection octets.</returns>
    private static byte[] BuildTruncatedSingleSelectionBitmapOctets(int presentBitmapOctets)
    {
        byte[] octets = new byte[sizeof(uint) + sizeof(ushort) + sizeof(byte) + presentBitmapOctets];
        var writer = new TpmWriter(octets);
        writer.WriteUInt32(1);
        writer.WriteUInt16((ushort)PcrBank);
        writer.WriteByte(3);
        if(presentBitmapOctets > 0)
        {
            writer.WriteBytes(new byte[presentBitmapOctets]);
        }

        return octets;
    }

    /// <summary>
    /// Builds a <c>TPML_PCR_SELECTION</c> octet sequence declaring <paramref name="declaredCount"/> selections —
    /// over <see cref="TpmlPcrSelection.MaxSelections"/> — while the buffer itself carries only ONE full,
    /// otherwise well-formed selection entry: a frame that is simultaneously over its count bound AND too short
    /// to hold every entry the declared count promises.
    /// </summary>
    /// <param name="declaredCount">The declared selection count.</param>
    /// <returns>The marshaled, over-bound-and-truncated selection octets.</returns>
    private static byte[] BuildOverBoundCreationPcrWireWithOneEntryPresent(int declaredCount)
    {
        const int EntrySize = sizeof(ushort) + sizeof(byte) + 3;
        byte[] octets = new byte[sizeof(uint) + EntrySize];
        var writer = new TpmWriter(octets);
        writer.WriteUInt32((uint)declaredCount);
        writer.WriteUInt16((ushort)PcrBank);
        writer.WriteByte(3);
        writer.WriteBytes([0x01, 0x00, 0x00]);

        return octets;
    }

    /// <summary>
    /// Parses hand-built <c>TPML_PCR_SELECTION</c> octets (from <see cref="BuildPcrSelectionOctets"/>) into a
    /// real, owned <see cref="TpmlPcrSelection"/> for a caller that needs one at or under
    /// <see cref="TpmlPcrSelection.MaxSelections"/> — the only way to get a MULTI-selection list at all, since
    /// <see cref="TpmlPcrSelection.Create"/> builds a single bank only.
    /// </summary>
    private static TpmlPcrSelection ParseSelectionOctets(byte[] octets, BaseMemoryPool pool)
    {
        var reader = new TpmReader(octets);
        TpmlPcrSelection selection = TpmlPcrSelection.Parse(ref reader, pool);
        Assert.AreEqual(0, reader.Remaining, "The hand-built selection octets must be fully consumed by Parse.");

        return selection;
    }

    /// <summary>
    /// Frames a <c>TPM2_CreatePrimary()</c> or <c>TPM2_Create()</c> command over a single empty-auth
    /// <c>TPM_RS_PW</c> slot, carrying <paramref name="outsideInfoWire"/> and <paramref name="pcrSelectionWire"/>
    /// verbatim as the trailing two parameters — for shapes <see cref="CreatePrimaryInput"/>/
    /// <see cref="CreateInput"/> cannot themselves express (an over-bound <c>outsideInfo</c> or a
    /// too-long <c>creationPCR</c>).
    /// </summary>
    /// <param name="pool">The memory pool the command buffer is rented from.</param>
    /// <param name="commandCode">Either <c>TPM_CC_CreatePrimary</c> or <c>TPM_CC_Create</c>.</param>
    /// <param name="handleValue">The hierarchy (CreatePrimary) or loaded parent (Create) handle.</param>
    /// <param name="inSensitive">The sensitive-create parameter.</param>
    /// <param name="inPublic">The public template.</param>
    /// <param name="outsideInfoWire">The raw, already-marshaled <c>outsideInfo</c> (<c>TPM2B_DATA</c>) octets.</param>
    /// <param name="pcrSelectionWire">The raw, already-marshaled <c>creationPCR</c> (<c>TPML_PCR_SELECTION</c>) octets.</param>
    /// <param name="length">The number of valid octets in the returned buffer.</param>
    /// <returns>The command buffer; the caller disposes it.</returns>
    private static IMemoryOwner<byte> FrameCreateFamilyCommand(
        BaseMemoryPool pool, TpmCcConstants commandCode, uint handleValue,
        Tpm2bSensitiveCreate inSensitive, Tpm2bPublic inPublic,
        ReadOnlySpan<byte> outsideInfoWire, ReadOnlySpan<byte> pcrSelectionWire, out int length)
    {
        const int PasswordSlotSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);
        length =
            TpmHeader.HeaderSize
            + sizeof(uint)                                //Handle area: @primaryHandle / @parentHandle.
            + sizeof(uint) + PasswordSlotSize             //authorizationSize + the TPM_RS_PW slot.
            + inSensitive.SerializedSize
            + inPublic.GetSerializedSize()
            + outsideInfoWire.Length
            + pcrSelectionWire.Length;

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..length]);
            var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)commandCode);
            header.WriteTo(ref writer);
            writer.WriteUInt32(handleValue);
            writer.WriteUInt32(PasswordSlotSize);
            writer.WriteUInt32((uint)TpmRh.TPM_RH_PW);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            inSensitive.WriteTo(ref writer);
            inPublic.WriteTo(ref writer);
            writer.WriteBytes(outsideInfoWire);
            writer.WriteBytes(pcrSelectionWire);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Frames the same command shape as <see cref="FrameCreateFamilyCommand"/>, but with <c>outsideInfo</c>
    /// declaring <paramref name="declaredOutsideInfoSize"/> octets while the frame itself supplies only
    /// <paramref name="actualOutsideInfoBytesProvided"/> and ends there — no <c>creationPCR</c> follows at all —
    /// so <c>TrySkipTpm2b</c>'s bound-against-<c>Remaining</c> probe answers <c>TPM_RC_INSUFFICIENT</c>.
    /// </summary>
    private static IMemoryOwner<byte> FrameCreateFamilyCommandWithTruncatedOutsideInfo(
        BaseMemoryPool pool, TpmCcConstants commandCode, uint handleValue,
        Tpm2bSensitiveCreate inSensitive, Tpm2bPublic inPublic,
        ushort declaredOutsideInfoSize, int actualOutsideInfoBytesProvided, out int length)
    {
        const int PasswordSlotSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);
        length =
            TpmHeader.HeaderSize
            + sizeof(uint)
            + sizeof(uint) + PasswordSlotSize
            + inSensitive.SerializedSize
            + inPublic.GetSerializedSize()
            + sizeof(ushort) + actualOutsideInfoBytesProvided;

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..length]);
            var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)commandCode);
            header.WriteTo(ref writer);
            writer.WriteUInt32(handleValue);
            writer.WriteUInt32(PasswordSlotSize);
            writer.WriteUInt32((uint)TpmRh.TPM_RH_PW);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            inSensitive.WriteTo(ref writer);
            inPublic.WriteTo(ref writer);
            writer.WriteUInt16(declaredOutsideInfoSize);
            if(actualOutsideInfoBytesProvided > 0)
            {
                writer.WriteBytes(new byte[actualOutsideInfoBytesProvided]);
            }

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Submits a hand-framed <c>TPM2_CreatePrimary()</c>/<c>TPM2_Create()</c> straight to the simulator (bypassing
    /// <see cref="TpmCommandExecutor"/>, whose typed inputs cannot express the shape under test) and yields the
    /// response code.
    /// </summary>
    private async Task<TpmRcConstants> SubmitCreateFamilyCommandAsync(
        TpmSimulator simulator, BaseMemoryPool pool, TpmCcConstants commandCode, uint handleValue,
        Tpm2bSensitiveCreate inSensitive, Tpm2bPublic inPublic, byte[] outsideInfoWire, byte[] pcrSelectionWire)
    {
        using IMemoryOwner<byte> commandOwner = FrameCreateFamilyCommand(
            pool, commandCode, handleValue, inSensitive, inPublic, outsideInfoWire, pcrSelectionWire, out int length);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>
    /// Submits a hand-framed command built by <see cref="FrameCreateFamilyCommandWithTruncatedOutsideInfo"/> and
    /// yields the response code, the truncated-frame counterpart of <see cref="SubmitCreateFamilyCommandAsync"/>.
    /// </summary>
    private async Task<TpmRcConstants> SubmitTruncatedOutsideInfoCommandAsync(
        TpmSimulator simulator, BaseMemoryPool pool, TpmCcConstants commandCode, uint handleValue,
        Tpm2bSensitiveCreate inSensitive, Tpm2bPublic inPublic, ushort declaredOutsideInfoSize, int actualOutsideInfoBytesProvided)
    {
        using IMemoryOwner<byte> commandOwner = FrameCreateFamilyCommandWithTruncatedOutsideInfo(
            pool, commandCode, handleValue, inSensitive, inPublic, declaredOutsideInfoSize, actualOutsideInfoBytesProvided, out int length);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>
    /// Creates an ECC storage parent under the owner hierarchy with an empty authValue, the loaded parent every
    /// <c>TPM2_Create()</c> fixture in this file seals under.
    /// </summary>
    private async Task<CreatePrimaryResponse> CreateStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary storage parent failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Reserializes a public area into a fresh <see cref="Tpm2bPublic"/>, the disk round-trip a real deployment
    /// performs between <c>TPM2_Create()</c> and <c>TPM2_Load()</c> — mirrors
    /// <c>TpmInHouseSimulatorSealTests.ClonePublic</c>.
    /// </summary>
    private static Tpm2bPublic ClonePublic(Tpm2bPublic source, BaseMemoryPool pool)
    {
        int size = source.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span);
        source.WriteTo(ref writer);

        var reader = new TpmReader(owner.Memory.Span[..size]);

        return Tpm2bPublic.Parse(ref reader, pool);
    }

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-creation-parameters", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
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
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_Unseal, TpmResponseCodec.Unseal);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }
}
