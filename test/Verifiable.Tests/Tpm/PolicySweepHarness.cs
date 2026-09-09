using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Verifiable.Tests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Shared plumbing for the policy-sweep simulator acceptance tests (<c>TPM2_PolicyPassword()</c>,
/// <c>TPM2_PolicyCpHash()</c>, <c>TPM2_PolicyNameHash()</c>, <c>TPM2_PolicyTemplate()</c>,
/// <c>TPM2_PolicyLocality()</c>, <c>TPM2_PolicyNvWritten()</c>, <c>TPM2_PolicyAuthorizeNV()</c>): an operational
/// in-house <see cref="TpmSimulator"/>, a deterministic ECC storage parent, a seal-under-policy-then-unseal round
/// trip, and NV Index provisioning — all in-process against the production wire path (<see cref="TpmCommandExecutor"/>,
/// the real device verbs, and the real codecs), reused so each command's own class carries only its normative
/// assertions rather than a copy of this scaffolding.
/// </summary>
internal static class PolicySweepHarness
{
    /// <summary>The policy session and Name hash algorithm used throughout the sweep.</summary>
    public const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The reserved data size for the NV Indexes the sweep defines (large enough for a SHA-256 TPMT_HA plus metadata).</summary>
    public const ushort NvDataSize = 64;

    /// <summary>
    /// Creates an ECC-capable simulator, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the
    /// operational phase.
    /// </summary>
    /// <param name="name">A per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The operational simulator.</returns>
    public static async Task<TpmSimulator> CreateOperationalAsync(string name, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        var simulator = new TpmSimulator(name, signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(cancellationToken).ConfigureAwait(false);

        var startup = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + startup.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)startup.CommandCode);
        header.WriteTo(ref writer);
        startup.WriteHandles(ref writer);
        startup.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed at the transport level.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }

    /// <summary>Builds the response codec registry covering every executor-driven command the sweep issues directly.</summary>
    /// <returns>The registry.</returns>
    public static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_Unseal, TpmResponseCodec.Unseal);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);

        return registry;
    }

    /// <summary>Creates the deterministic ECC storage parent under the owner hierarchy; the caller owns and flushes the response.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The CreatePrimary response for the storage parent.</returns>
    public static async Task<CreatePrimaryResponse> CreateStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [ownerAuth], null, pool, registry, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary storage parent failed: '{parentResult.ResponseCode}'.");

        return parentResult.Value;
    }

    /// <summary>
    /// Seals <paramref name="secret"/> under <paramref name="authPolicy"/> as the sealed object's access policy,
    /// then loads it under <paramref name="parentHandle"/>, returning the loaded handle and its Name.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent handle.</param>
    /// <param name="secret">The secret to seal.</param>
    /// <param name="authPolicy">The access policy digest the object is sealed under.</param>
    /// <param name="userAuth">The object's authorization value (empty unless the policy presents it).</param>
    /// <param name="userWithAuth">Whether the object admits USER-role authValue authorization.</param>
    /// <param name="isDuplicable">Whether the object is exportable by <c>TPM2_Duplicate()</c>.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The loaded object's handle and its Name octets.</returns>
    public static async Task<(uint Handle, byte[] Name)> SealAndLoadAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, ReadOnlyMemory<byte> secret, ReadOnlyMemory<byte> authPolicy,
        ReadOnlyMemory<byte> userAuth = default, bool userWithAuth = true, bool isDuplicable = false, CancellationToken cancellationToken = default)
    {
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(secret.Span, userAuth.Span, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy.Span, noDa: true, userWithAuth: userWithAuth, isDuplicable: isDuplicable);
        using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [createParentAuth], null, pool, registry, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (seal under policy) failed: '{createResult.ResponseCode}'.");
        using CreateResponse sealedObject = createResult.Value;

        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
        using Tpm2bPublic inPublic = ClonePublic(sealedObject.OutPublic, pool);
        using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
        using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadParentAuth], null, pool, registry, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (sealed object) failed: '{loadResult.ResponseCode}'.");
        using LoadResponse loaded = loadResult.Value;

        return (loaded.ObjectHandle.Value, loaded.Name.Span.ToArray());
    }

    /// <summary>Reserializes a public area into a fresh carrier, the round trip a disk-persisted public blob makes.</summary>
    /// <param name="source">The public area to clone.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>An independent copy of the public area.</returns>
    public static Tpm2bPublic ClonePublic(Tpm2bPublic source, BaseMemoryPool pool)
    {
        int size = source.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span);
        source.WriteTo(ref writer);
        var reader = new TpmReader(owner.Memory.Span[..size]);

        return Tpm2bPublic.Parse(ref reader, pool);
    }

    /// <summary>Defines an ordinary, dictionary-attack-exempt NV Index authorized by the empty owner authValue.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A task that completes once the Index is defined.</returns>
    public static async Task DefineOwnerReadableIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex, CancellationToken cancellationToken)
    {
        TpmaNv attributes =
            TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_OWNERREAD
            | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_NO_DA;

        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bAuth auth = Tpm2bAuth.CreateEmpty(pool);
        using Tpm2bDigest policyDigest = Tpm2bDigest.Empty;
        using TpmsNvPublic publicInfo = new(nvIndex, SessionAlg, attributes, policyDigest, NvDataSize);
        using NvDefineSpaceInput input = new(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        TpmResult<NvDefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, input, [ownerSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"NV_DefineSpace (owner-readable) failed: '{result.ResponseCode}'.");
    }

    /// <summary>Writes <paramref name="data"/> to an owner-writable NV Index over the owner-authorized path, setting TPMA_NV_WRITTEN.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index handle to write.</param>
    /// <param name="data">The octets to store at offset zero.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A task that completes once the write lands.</returns>
    public static async Task WriteOwnerIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(data.Span, pool);
        var input = new NvWriteInput((uint)TpmRh.TPM_RH_OWNER, nvIndex, buffer, Offset: 0);

        TpmResult<NvWriteResponse> result = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            tpm, input, [ownerSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"NV_Write (owner) failed: '{result.ResponseCode}'.");
    }

    /// <summary>Flushes a transient object or session handle when one is present (non-zero), ignoring the result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="handle">The handle to flush, or 0 when none was acquired.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A task that completes once the flush is issued.</returns>
    public static async Task FlushIfPresentAsync(TpmDevice tpm, uint handle, CancellationToken cancellationToken)
    {
        if(handle == 0)
        {
            return;
        }

        _ = await tpm.FlushContextAsync(handle, cancellationToken).ConfigureAwait(false);
    }
}
