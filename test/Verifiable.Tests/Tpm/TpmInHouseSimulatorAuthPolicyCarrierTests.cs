using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Proves the pooled-carrier ownership of the authorization policy digest (<c>TPM2B_DIGEST</c>, TPM 2.0 Library
/// Part 2, clause 10.4.2, Table 92) wherever the simulator retains one: an object's
/// <c>TPMT_PUBLIC.authPolicy</c>, an NV Index's <c>TPMS_NV_PUBLIC.authPolicy</c>, and a permanent entity's
/// policy slot installed by <c>TPM2_SetPrimaryPolicy()</c> (Part 3, clause 24.3). Each digest is rented once,
/// transferred into durable state, deep-copied when <c>TPM2_EvictControl()</c> persists an object (clause 28.5),
/// and returned to the pool when the entity leaves its dictionary or its policy is replaced.
/// </summary>
/// <remarks>
/// <para>
/// The instrument is <see cref="MeteredHousePool"/>: a genuine <see cref="BaseMemoryPool"/> whose own rent and
/// return telemetry is observed, so nothing here depends on a seam in production code.
/// </para>
/// <para>
/// A balance assertion over a policy digest is only meaningful when the digest is genuinely non-empty — an empty
/// one resolves to <see cref="Tpm2bDigest.Empty"/>, the shared dispose-immune sentinel that rents nothing. Every
/// case here therefore drives an A/B pair through the SAME command: once with a policy-bearing template or public
/// area and once with a policy-free one, asserting the with-policy form holds EXACTLY one carrier more. The two
/// arms are not byte-identical frames, so what makes that difference the digest's OWN rental is an assumption the
/// assertions rest on: both arms route to the same action and the same artifact builder, and retain the same set
/// of non-policy carriers. A change that made one arm rent something the other does not would move the difference
/// away from the digest, and these balance assertions are what would fail.
/// </para>
/// <para>
/// The commands are issued through <see cref="TpmCommandExecutor"/> with the metered pool rather than through the
/// <c>Extensions</c> verbs, because those compose their own <c>BaseMemoryPool.Shared</c> internally and the
/// simulator would then rent from a pool this instrument does not observe.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorAuthPolicyCarrierTests
{
    /// <summary>The NV Index handle every case here defines.</summary>
    private const uint NvIndexHandle = 0x0100_0041;

    /// <summary>The persistent handle the deep-copy proof persists an object to.</summary>
    private const uint PersistentHandle = 0x8100_0041;

    /// <summary>The declared data area size of every Index these tests define.</summary>
    private const ushort NvDataSize = 8;

    /// <summary>
    /// The parent handle the over-bound-policy refusal cases name. It resolves to nothing, and needs not to:
    /// the wire parse refuses the frame before any handle is looked up (TPM 2.0 Library Part 3, clause 5.8.2).
    /// </summary>
    private const uint PolicyRefusalParentHandle = 0x8000_0000;

    /// <summary>An ordinary caller-authorized, DA-exempt Index attribute set.</summary>
    private const TpmaNv IndexAttributes = TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>A SHA-256-width access policy digest: the exact width <c>TPMS_NV_PUBLIC.nameAlg</c> demands.</summary>
    private static byte[] IndexPolicy { get; } =
        [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
         0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50];

    /// <summary>A second, distinct SHA-256-width policy digest, so a replacement is observably a different value.</summary>
    private static byte[] ReplacementPolicy { get; } =
        [0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
         0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A loaded object created from a policy-bearing template holds exactly one pooled carrier more than the
    /// otherwise identical policy-free template does — the retained <c>TPMT_PUBLIC.authPolicy</c> digest — and
    /// <c>TPM2_FlushContext()</c> returns it. The policy-bearing template is the standard endorsement key's
    /// (TCG EK Credential Profile, Annex B.3.4, Template L-2), whose "PolicyA" is a real SHA-256 digest rather
    /// than the Empty Buffer, so the difference cannot be the dispose-immune empty sentinel.
    /// </summary>
    [TestMethod]
    public async Task LoadedPolicyBearingObjectHoldsOneCarrierMoreThanAPolicyFreeObject()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        uint policyFreeHandle = await CreatePolicyFreeParentAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        long policyFreeCost = trackingPool.OutstandingCount - baseline;
        await FlushAsync(tpm, registry, trackingPool.Pool, policyFreeHandle).ConfigureAwait(false);
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Flushing the policy-free object must return every carrier it held.");

        uint policyBearingHandle = await CreatePolicyBearingKeyAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        long policyBearingCost = trackingPool.OutstandingCount - baseline;

        Assert.AreEqual(
            policyFreeCost + 1, policyBearingCost,
            "A retained non-empty authPolicy is exactly one more pooled carrier than the policy-free object holds.");

        await FlushAsync(tpm, registry, trackingPool.Pool, policyBearingHandle).ConfigureAwait(false);

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Flushing the object must return its retained authPolicy carrier to the pool.");
    }

    /// <summary>
    /// <c>TPM2_EvictControl()</c>'s persist arm deep-copies the object into its persistent instance (TPM 2.0
    /// Library Part 3, clause 28.5), so persisting a policy-bearing object rents exactly one carrier more than
    /// persisting a policy-free one: the persistent entry's OWN authPolicy digest, never an alias of the
    /// transient entry's. Evicting the persistent copy afterwards returns everything, which a shared buffer
    /// could not do without one entry's disposal reaching the other's octets.
    /// </summary>
    [TestMethod]
    public async Task PersistingAPolicyBearingObjectDeepCopiesItsAuthPolicyCarrier()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        uint policyFreeHandle = await CreatePolicyFreeParentAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        long beforePolicyFreePersist = trackingPool.OutstandingCount;
        await PersistAsync(tpm, registry, trackingPool.Pool, policyFreeHandle).ConfigureAwait(false);
        long policyFreeCopyCost = trackingPool.OutstandingCount - beforePolicyFreePersist;

        await FlushAsync(tpm, registry, trackingPool.Pool, policyFreeHandle).ConfigureAwait(false);
        await EvictAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Flushing the transient original and evicting the persistent copy must return every carrier both held.");

        uint policyBearingHandle = await CreatePolicyBearingKeyAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        long beforePolicyBearingPersist = trackingPool.OutstandingCount;
        await PersistAsync(tpm, registry, trackingPool.Pool, policyBearingHandle).ConfigureAwait(false);
        long policyBearingCopyCost = trackingPool.OutstandingCount - beforePolicyBearingPersist;

        Assert.AreEqual(
            policyFreeCopyCost + 1, policyBearingCopyCost,
            "The persistent instance must rent its OWN authPolicy digest, so the deep copy costs one carrier more than a policy-free object's.");

        await FlushAsync(tpm, registry, trackingPool.Pool, policyBearingHandle).ConfigureAwait(false);
        await EvictAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Both instances own separate authPolicy carriers, so releasing both must return the pool to its baseline.");
    }

    /// <summary>
    /// An NV Index defined with a non-empty <c>TPMS_NV_PUBLIC.authPolicy</c> (TPM 2.0 Library Part 3, clause
    /// 31.3) holds exactly one pooled carrier more than an otherwise identical Index defined without one, and
    /// <c>TPM2_NV_UndefineSpace()</c> returns it — the Index's policy digest is owned durable state on the same
    /// lifecycle as its authValue.
    /// </summary>
    [TestMethod]
    public async Task DefinedNvIndexWithAnAccessPolicyHoldsOneCarrierMoreThanAPolicyFreeIndex()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        TpmResult<NvDefineSpaceResponse> policyFreeDefine = await DefineIndexAsync(
            tpm, registry, trackingPool.Pool, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(policyFreeDefine.IsSuccess, $"NV_DefineSpace (no policy) failed: '{policyFreeDefine.ResponseCode}'.");
        long policyFreeCost = trackingPool.OutstandingCount - baseline;

        await UndefineIndexAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Undefining the policy-free Index must return every carrier it held.");

        TpmResult<NvDefineSpaceResponse> policyDefine = await DefineIndexAsync(
            tpm, registry, trackingPool.Pool, IndexPolicy).ConfigureAwait(false);
        Assert.IsTrue(policyDefine.IsSuccess, $"NV_DefineSpace (with policy) failed: '{policyDefine.ResponseCode}'.");

        Assert.AreEqual(
            policyFreeCost + 1, trackingPool.OutstandingCount - baseline,
            "A retained non-empty access policy is exactly one more pooled carrier than the policy-free Index holds.");

        await UndefineIndexAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Undefining the Index must return its retained access policy carrier to the pool.");
    }

    /// <summary>
    /// A <c>TPM2_NV_DefineSpace()</c> refused because the handle is already defined (<c>TPM_RC_NV_DEFINED</c>,
    /// TPM 2.0 Library Part 3, clause 31.3) returns the access policy digest the parser rented: the refusing arm
    /// releases it through the request record's own disposal, exactly as it releases the Index authValue beside
    /// it, so no refusal orphans a parse-time rental.
    /// </summary>
    [TestMethod]
    public async Task RefusedNvDefineSpaceReturnsTheAccessPolicyCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<NvDefineSpaceResponse> firstDefine = await DefineIndexAsync(
            tpm, registry, trackingPool.Pool, IndexPolicy).ConfigureAwait(false);
        Assert.IsTrue(firstDefine.IsSuccess, $"NV_DefineSpace (first) failed: '{firstDefine.ResponseCode}'.");

        long baseline = trackingPool.OutstandingCount;

        TpmResult<NvDefineSpaceResponse> secondDefine = await DefineIndexAsync(
            tpm, registry, trackingPool.Pool, IndexPolicy).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_DEFINED, secondDefine.ResponseCode,
            "Redefining a handle that is already defined is TPM_RC_NV_DEFINED (TPM 2.0 Library Part 3, clause 31.3).");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusing arm must return the parse-rented access policy carrier to the pool.");

        await UndefineIndexAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
    }

    /// <summary>
    /// The permanent-entity policy slot <c>TPM2_SetPrimaryPolicy()</c> writes (TPM 2.0 Library Part 3, clause
    /// 24.3) holds exactly one live carrier however many times it is written: installing a policy costs one,
    /// replacing it with a different policy of the same width costs nothing further (the superseded digest is
    /// disposed as the replacement is installed), and installing the Empty Buffer — which disables policy
    /// authorization of that entity outright (Part 1, clause 11.2, Table 5) — returns the slot to the
    /// dispose-immune empty sentinel and the pool to its baseline.
    /// </summary>
    [TestMethod]
    public async Task HierarchyPolicyInstallationHoldsExactlyOneCarrier()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        await SetOwnerPolicyAsync(tpm, registry, trackingPool.Pool, IndexPolicy, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.AreEqual(
            baseline + 1, trackingPool.OutstandingCount,
            "Installing a non-empty hierarchy policy must hold exactly one pooled carrier.");

        await SetOwnerPolicyAsync(tpm, registry, trackingPool.Pool, ReplacementPolicy, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.AreEqual(
            baseline + 1, trackingPool.OutstandingCount,
            "Replacing the policy must dispose the superseded digest as the replacement is installed, so the balance may not grow.");

        await SetOwnerPolicyAsync(tpm, registry, trackingPool.Pool, ReadOnlyMemory<byte>.Empty, TpmAlgIdConstants.TPM_ALG_NULL).ConfigureAwait(false);

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Installing the Empty Buffer must return the last installed policy carrier to the pool.");
    }

    /// <summary>
    /// <c>TPM2_Load()</c>'s <c>inPublic</c> carries a <c>TPMT_PUBLIC.authPolicy</c>, and a <c>TPM2B_DIGEST</c>'s
    /// buffer is bounded by <c>sizeof(TPMU_HA)</c> — the widest member of the hash union (TPM 2.0 Library Part 2,
    /// clause 10.4.2, Table 92). A hand-framed public area declaring one octet more is answered
    /// <c>TPM_RC_SIZE</c> as a response code: the structure parser's only refusal channel is a throw, and an
    /// unmarshaling error means no command processing occurs (Part 3, clause 5.8.2), so the wire parse answers
    /// it rather than letting an exception escape the command surface. The frame is built by hand because
    /// <see cref="Tpm2bDigest.Create"/> refuses the over-bound width outright, so no shipped input type can
    /// express it.
    /// </summary>
    [TestMethod]
    public async Task LoadWithAnOversizeInPublicAuthPolicyIsRefusedWithSize()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);

        byte[] inPublic = FrameOversizePolicyPublicArea();
        byte[] parameters = new byte[sizeof(ushort) + sizeof(uint) + inPublic.Length];

        //inPrivate (TPM2B_PRIVATE): four opaque octets, so the parse reaches inPublic with a well-formed
        //parameter behind it and the refusal can only be the policy digest's own declared width.
        BinaryPrimitives.WriteUInt16BigEndian(parameters, sizeof(uint));
        inPublic.CopyTo(parameters.AsSpan(sizeof(ushort) + sizeof(uint)));

        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants responseCode = await SubmitRawAsync(
            simulator,
            trackingPool.Pool,
            FramePasswordAuthorizedCommand(TpmCcConstants.TPM_CC_Load, PolicyRefusalParentHandle, parameters)).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIZE, responseCode,
            "An inPublic authPolicy wider than sizeof(TPMU_HA) is TPM_RC_SIZE (TPM 2.0 Library Part 2, clause 10.4.2, Table 92).");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A frame refused while the public area is being unmarshaled rents none of the parse's owned carriers.");
    }

    /// <summary>
    /// The <c>TPM2_Create()</c> sibling of <see cref="LoadWithAnOversizeInPublicAuthPolicyIsRefusedWithSize"/>:
    /// the sealed object's template carries the same <c>TPMT_PUBLIC.authPolicy</c>, so the same over-bound
    /// <c>TPM2B_DIGEST</c> (Part 2, clause 10.4.2, Table 92) is answered <c>TPM_RC_SIZE</c> on the plain
    /// password-authorized seal path too, and the sealed-data carriers the parse would otherwise rent behind it
    /// are never rented.
    /// </summary>
    [TestMethod]
    public async Task CreateWithAnOversizeInPublicAuthPolicyIsRefusedWithSize()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);

        byte[] inPublic = FrameOversizePolicyPublicArea();

        //inSensitive (TPM2B_SENSITIVE_CREATE): a four-octet TPMS_SENSITIVE_CREATE holding an empty userAuth
        //(TPM2B_AUTH) and empty data (TPM2B_SENSITIVE_DATA), so the parse reaches inPublic well-formed.
        byte[] parameters = new byte[sizeof(ushort) + 4 + inPublic.Length];
        BinaryPrimitives.WriteUInt16BigEndian(parameters, 4);
        inPublic.CopyTo(parameters.AsSpan(sizeof(ushort) + 4));

        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants responseCode = await SubmitRawAsync(
            simulator,
            trackingPool.Pool,
            FramePasswordAuthorizedCommand(TpmCcConstants.TPM_CC_Create, PolicyRefusalParentHandle, parameters)).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIZE, responseCode,
            "An inPublic authPolicy wider than sizeof(TPMU_HA) is TPM_RC_SIZE on the seal path too (TPM 2.0 Library Part 2, clause 10.4.2, Table 92).");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A frame refused while the template is being unmarshaled rents none of the parse's owned carriers.");
    }

    /// <summary>
    /// Frames a <c>TPM2B_PUBLIC</c> whose <c>TPMT_PUBLIC.authPolicy</c> declares one octet more than
    /// <see cref="Tpm2bDigest.MaxSize"/>. The parameters and unique fields are absent because the authPolicy's
    /// own declared size is refused as it is read, before either is reached.
    /// </summary>
    /// <returns>The marshaled sized public area.</returns>
    private static byte[] FrameOversizePolicyPublicArea()
    {
        const int OversizeAuthPolicySize = Tpm2bDigest.MaxSize + 1;

        int publicAreaSize = sizeof(ushort) + sizeof(ushort) + sizeof(uint) + sizeof(ushort) + OversizeAuthPolicySize;
        byte[] framed = new byte[sizeof(ushort) + publicAreaSize];
        Span<byte> span = framed;
        int offset = 0;

        BinaryPrimitives.WriteUInt16BigEndian(span[offset..], (ushort)publicAreaSize);
        offset += sizeof(ushort);
        BinaryPrimitives.WriteUInt16BigEndian(span[offset..], (ushort)TpmAlgIdConstants.TPM_ALG_KEYEDHASH);
        offset += sizeof(ushort);
        BinaryPrimitives.WriteUInt16BigEndian(span[offset..], (ushort)TpmAlgIdConstants.TPM_ALG_SHA256);
        offset += sizeof(ushort);
        BinaryPrimitives.WriteUInt32BigEndian(span[offset..], (uint)(TpmaObject.USER_WITH_AUTH | TpmaObject.NO_DA));
        offset += sizeof(uint);
        BinaryPrimitives.WriteUInt16BigEndian(span[offset..], (ushort)OversizeAuthPolicySize);
        offset += sizeof(ushort);
        span.Slice(offset, OversizeAuthPolicySize).Fill(0x5A);

        return framed;
    }

    /// <summary>
    /// Frames a complete command: the header, one handle, an authorization area carrying a single empty
    /// <c>TPM_RH_PW</c> password session, and the supplied parameter octets.
    /// </summary>
    /// <param name="commandCode">The command code to frame.</param>
    /// <param name="handle">The single handle-area value.</param>
    /// <param name="parameters">The already-marshaled parameter octets.</param>
    /// <returns>The complete command frame.</returns>
    private static byte[] FramePasswordAuthorizedCommand(TpmCcConstants commandCode, uint handle, ReadOnlySpan<byte> parameters)
    {
        //sessionHandle + nonceCaller (empty TPM2B) + sessionAttributes + hmac (empty TPM2B).
        const int PasswordAuthAreaSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);

        int length = TpmHeader.HeaderSize + sizeof(uint) + sizeof(uint) + PasswordAuthAreaSize + parameters.Length;
        byte[] framed = new byte[length];

        var writer = new TpmWriter(framed);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)commandCode);
        header.WriteTo(ref writer);

        Span<byte> span = framed.AsSpan(TpmHeader.HeaderSize);
        int offset = 0;

        BinaryPrimitives.WriteUInt32BigEndian(span[offset..], handle);
        offset += sizeof(uint);
        BinaryPrimitives.WriteUInt32BigEndian(span[offset..], PasswordAuthAreaSize);
        offset += sizeof(uint);
        BinaryPrimitives.WriteUInt32BigEndian(span[offset..], (uint)TpmRh.TPM_RH_PW);
        offset += sizeof(uint);
        BinaryPrimitives.WriteUInt16BigEndian(span[offset..], 0);
        offset += sizeof(ushort);
        span[offset] = 0;
        offset += sizeof(byte);
        BinaryPrimitives.WriteUInt16BigEndian(span[offset..], 0);
        offset += sizeof(ushort);
        parameters.CopyTo(span[offset..]);

        return framed;
    }

    /// <summary>
    /// Submits a hand-framed command straight to the simulator and returns the response code its header carries
    /// — the channel a refused frame is answered on, since a parse refusal is a header-only response rather
    /// than a transport failure.
    /// </summary>
    /// <param name="simulator">The simulator to submit to.</param>
    /// <param name="pool">The memory pool the response is framed from.</param>
    /// <param name="command">The complete command frame.</param>
    /// <returns>The response code the simulator answered with.</returns>
    private async Task<TpmRcConstants> SubmitRawAsync(TpmSimulator simulator, BaseMemoryPool pool, ReadOnlyMemory<byte> command)
    {
        TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "A refused frame must still be answered with a framed response.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>Creates a policy-free ECC storage parent under the owner hierarchy and returns its transient handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The transient handle of the created object.</returns>
    private async Task<uint> CreatePolicyFreeParentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, authPassword: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (policy-free storage parent) failed: '{result.ResponseCode}'.");

        using CreatePrimaryResponse response = result.Value;

        return response.ObjectHandle.Value;
    }

    /// <summary>
    /// Creates the standard ECC endorsement key, whose template carries a real SHA-256 "PolicyA" digest, and
    /// returns its transient handle.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The transient handle of the created object.</returns>
    private async Task<uint> CreatePolicyBearingKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEndorsementKey(TpmRh.TPM_RH_ENDORSEMENT, pool);
        using TpmPasswordSession endorsementAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [endorsementAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (endorsement key) failed: '{result.ResponseCode}'.");

        using CreatePrimaryResponse response = result.Value;

        return response.ObjectHandle.Value;
    }

    /// <summary>Persists a transient object to <see cref="PersistentHandle"/> under owner authorization.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="objectHandle">The transient handle to persist.</param>
    private async Task PersistAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint objectHandle)
    {
        var input = new EvictControlInput(TpmRh.TPM_RH_OWNER, objectHandle, PersistentHandle);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<EvictControlResponse> result = await TpmCommandExecutor.ExecuteAsync<EvictControlResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"EvictControl (persist) failed: '{result.ResponseCode}'.");
    }

    /// <summary>Evicts the persistent instance at <see cref="PersistentHandle"/> under owner authorization.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task EvictAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        var input = new EvictControlInput(TpmRh.TPM_RH_OWNER, PersistentHandle, PersistentHandle);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<EvictControlResponse> result = await TpmCommandExecutor.ExecuteAsync<EvictControlResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"EvictControl (evict) failed: '{result.ResponseCode}'.");
    }

    /// <summary>Defines <see cref="NvIndexHandle"/> under owner authorization with the supplied access policy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="authPolicy">The access policy digest to define with; empty for no policy.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> DefineIndexAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, ReadOnlyMemory<byte> authPolicy)
    {
        using Tpm2bAuth indexAuth = Tpm2bAuth.CreateEmpty(pool);
        using Tpm2bDigest policyDigest = Tpm2bDigest.Create(authPolicy.Span, pool);
        using var publicInfo = new TpmsNvPublic(NvIndexHandle, TpmAlgIdConstants.TPM_ALG_SHA256, IndexAttributes, policyDigest, NvDataSize);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, indexAuth, publicInfo);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Undefines <see cref="NvIndexHandle"/> under owner authorization, asserting the command succeeded.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task UndefineIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        var input = new NvUndefineSpaceInput(TpmRh.TPM_RH_OWNER, NvIndexHandle);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<NvUndefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"NV_UndefineSpace failed: '{result.ResponseCode}'.");
    }

    /// <summary>Installs an owner-hierarchy authorization policy, asserting the command succeeded.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="authPolicy">The policy digest to install, or empty to disable policy authorization.</param>
    /// <param name="hashAlg">The hash algorithm the digest is expressed under, <c>TPM_ALG_NULL</c> for the Empty Buffer.</param>
    private async Task SetOwnerPolicyAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, ReadOnlyMemory<byte> authPolicy, TpmAlgIdConstants hashAlg)
    {
        using Tpm2bDigest policyDigest = Tpm2bDigest.Create(authPolicy.Span, pool);
        using var input = new SetPrimaryPolicyInput(TpmRh.TPM_RH_OWNER, policyDigest, hashAlg);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<SetPrimaryPolicyResponse> result = await TpmCommandExecutor.ExecuteAsync<SetPrimaryPolicyResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"SetPrimaryPolicy failed: '{result.ResponseCode}'.");
    }

    /// <summary>Flushes a transient handle, asserting the command succeeded.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle to flush.</param>
    private async Task FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        TpmResult<FlushContextResponse> result = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(handle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"FlushContext failed: '{result.ResponseCode}'.");
    }

    /// <summary>Creates a response codec registry covering every command this file drives directly.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_EvictControl, TpmResponseCodec.EvictControl)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext)
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace)
            .Register(TpmCcConstants.TPM_CC_SetPrimaryPolicy, TpmResponseCodec.SetPrimaryPolicy);

    /// <summary>Creates a simulator with the ECC signing backend wired, powers it on, and brings it operational.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-auth-policy-carriers", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator to move it into the operational phase.</summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
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
    }
}
