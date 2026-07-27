using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Extensions.Counter;

/// <summary>
/// Monotonic-counter ("rollback-proof event count") business-capability extensions for <see cref="TpmDevice"/>.
/// </summary>
/// <remarks>
/// <para>
/// These verbs compose the shipped <c>TPM2_NV_DefineSpace</c>/<c>TPM2_NV_Increment</c>/<c>TPM2_NV_Read</c>/
/// <c>TPM2_NV_UndefineSpace</c> surface (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 3, Sections 31.3, 31.8, 31.13, 31.4) into a single business capability:
/// a rollback-proof monotonic counter suitable for signature counters, revocation epochs, or anti-rollback version
/// stamps. Every session (the owner hierarchy's for the administrative arms, the Index's own for the counter arms)
/// is built and disposed internally; a caller never hands in a pre-built session, matching the existing
/// <c>Extensions/DictionaryAttack</c> and <c>Extensions/Seal</c> verb groups.
/// </para>
/// <para>
/// <b>Rollback protection.</b> A Counter Index's value cannot be rolled back by deleting and redefining the same
/// handle: the in-house simulator retains the highest value any written Counter Index held at the moment it was
/// deleted (the "phantom counter" mechanism, TPM 2.0 Library Part 1, Section 37.2.6.3 NOTE 2/NOTE 6), so a
/// redefined counter's first <see cref="TpmDeviceExtensions.IncrementCounterAsync"/> always seeds strictly above
/// the deleted counter's last value. This is the capability the group exists for.
/// </para>
/// <para>
/// <b>Counted value is public state.</b> Every verb here returns or accepts a plain <see cref="ulong"/> for the
/// counter's value - a count is public state, not a secret buffer, so the no-naked-bytes carrier discipline that
/// binds authorization values (which ride <see cref="ReadOnlyMemory{T}"/>) does not bind scalar counts.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer does not recognize C# 13 extension type syntax.")]
public static class TpmDeviceExtensions
{
    /// <summary>The declared data area size (octets) of every Counter Index this group defines - the whole 8-octet counter value (TPM 2.0 Library Part 2, Section 13.2).</summary>
    private const ushort CounterDataSize = 8;

    /// <summary>The Name hash algorithm fixed for every Counter Index this group defines.</summary>
    private const TpmAlgIdConstants CounterNameAlgorithm = TpmAlgIdConstants.TPM_ALG_SHA256;

    extension(TpmDevice device)
    {
        /// <summary>
        /// Defines a new <c>TPM_NT_COUNTER</c> NV Index under the owner hierarchy, composing <c>TPM2_NV_DefineSpace</c>
        /// internally.
        /// </summary>
        /// <remarks>
        /// The Index is defined with <c>TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE | TPMA_NV_OWNERWRITE</c> (both the Index
        /// authValue and the owner hierarchy may increment it) and a fixed 8-octet data area, the spec-mandated width
        /// of a Counter Index (TPM 2.0 Library Part 2, Section 13.2). See Part 3, Section 31.3.1.
        /// </remarks>
        /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
        /// <param name="nvIndex">The NV Index handle to define.</param>
        /// <param name="counterAuth">The authorization value assigned to the new Counter Index.</param>
        /// <param name="noDa">
        /// When <see langword="true"/>, authorization failures against the Counter Index never advance the
        /// dictionary-attack lockout counter. Defaults to <see langword="false"/> (dictionary-attack PROTECTED) - the
        /// secure default: a real <paramref name="counterAuth"/> is a brute-forceable secret and should count toward
        /// the shared lockout counter unless the caller has a specific reason to exempt it.
        /// </param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<NvDefineSpaceResponse>> DefineCounterAsync(
            ReadOnlyMemory<byte> ownerAuth,
            uint nvIndex,
            ReadOnlyMemory<byte> counterAuth,
            bool noDa = false,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return DefineCounterCoreAsync(device, ownerAuth, nvIndex, counterAuth, noDa, cancellationToken);
        }

        /// <summary>
        /// Advances <paramref name="nvIndex"/> by one and returns the fresh count, composing <c>TPM2_NV_Increment</c>
        /// (Part 3, Section 31.8) then <c>TPM2_NV_Read</c> internally, both authorized by the Index's own authValue.
        /// </summary>
        /// <remarks>
        /// The first increment of an unwritten Counter Index always succeeds (Part 3, Section 31.8.1's explicit
        /// non-error) and never answers <c>TPM_RC_NV_UNINITIALIZED</c> - the contrast <see cref="ReadCounterAsync"/>
        /// does exhibit before any increment has run.
        /// </remarks>
        /// <param name="nvIndex">The Counter Index to increment.</param>
        /// <param name="counterAuth">The Index's authorization value.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the fresh count, or the increment's or the read-back's error.</returns>
        public ValueTask<TpmResult<ulong>> IncrementCounterAsync(
            uint nvIndex,
            ReadOnlyMemory<byte> counterAuth,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return IncrementCounterCoreAsync(device, nvIndex, counterAuth, cancellationToken);
        }

        /// <summary>
        /// Reads the current count of <paramref name="nvIndex"/>, composing <c>TPM2_NV_Read</c> internally,
        /// authorized by the Index's own authValue.
        /// </summary>
        /// <remarks>
        /// Rejects with <c>TPM_RC_NV_UNINITIALIZED</c> (Part 3, Section 31.13.1) when no increment has ever run
        /// against the Index - the contrast <see cref="IncrementCounterAsync"/> never exhibits.
        /// </remarks>
        /// <param name="nvIndex">The Counter Index to read.</param>
        /// <param name="counterAuth">The Index's authorization value.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the current count, or an error.</returns>
        public ValueTask<TpmResult<ulong>> ReadCounterAsync(
            uint nvIndex,
            ReadOnlyMemory<byte> counterAuth,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return ReadCounterCoreAsync(device, nvIndex, counterAuth, cancellationToken);
        }

        /// <summary>
        /// Removes <paramref name="nvIndex"/>'s definition, composing <c>TPM2_NV_UndefineSpace</c> internally,
        /// authorized by the owner hierarchy.
        /// </summary>
        /// <remarks>
        /// The deleted counter's last value is retained as the simulator's phantom high-water mark (TPM 2.0 Library
        /// Part 1, Section 37.2.6.3 NOTE 2/NOTE 6): a subsequent <see cref="DefineCounterAsync"/> of the same handle
        /// seeds its first <see cref="IncrementCounterAsync"/> strictly above the deleted value, so delete-then-redefine
        /// can never roll a counter with this Name back.
        /// </remarks>
        /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
        /// <param name="nvIndex">The Counter Index to undefine.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<NvUndefineSpaceResponse>> UndefineCounterAsync(
            ReadOnlyMemory<byte> ownerAuth,
            uint nvIndex,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return UndefineCounterCoreAsync(device, ownerAuth, nvIndex, cancellationToken);
        }
    }

    /// <summary>
    /// Composes <c>TPM2_NV_DefineSpace</c> for a new <c>TPM_NT_COUNTER</c> Index under the owner hierarchy.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value.</param>
    /// <param name="nvIndex">The NV Index handle to define.</param>
    /// <param name="counterAuth">The authorization value assigned to the new Counter Index.</param>
    /// <param name="noDa">Whether the Counter Index opts out of dictionary-attack protection.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The define-space result.</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the auth value and public area transfers to NvDefineSpaceInput, which disposes both; the redundant using locals satisfy CA2000 and are safe because all three types have idempotent disposal.")]
    private static async ValueTask<TpmResult<NvDefineSpaceResponse>> DefineCounterCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> ownerAuth,
        uint nvIndex,
        ReadOnlyMemory<byte> counterAuth,
        bool noDa,
        CancellationToken cancellationToken)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);

        const TpmaNv baseAttributes =
            TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE
            | (TpmaNv)((uint)TpmNt.TPM_NT_COUNTER << TpmaNvFields.TPM_NT_SHIFT);
        TpmaNv attributes = noDa ? baseAttributes | TpmaNv.TPMA_NV_NO_DA : baseAttributes;

        using Tpm2bAuth auth = Tpm2bAuth.Create(counterAuth.Span, pool);
        using TpmsNvPublic publicInfo = new(nvIndex, CounterNameAlgorithm, attributes, Tpm2bDigest.Empty, CounterDataSize);
        using NvDefineSpaceInput input = new(TpmRh.TPM_RH_OWNER, auth, publicInfo);
        using TpmPasswordSession ownerSession = TpmPasswordSession.Create(ownerAuth.Span, pool);

        return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Composes <c>TPM2_NV_Increment</c> then <c>TPM2_NV_Read</c> against <paramref name="nvIndex"/>, both
    /// authorized by the Index's own authValue, and returns the fresh count read back big-endian.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The Counter Index to increment.</param>
    /// <param name="counterAuth">The Index's authorization value.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A result containing the fresh count, or the increment's or the read-back's error.</returns>
    private static async ValueTask<TpmResult<ulong>> IncrementCounterCoreAsync(
        TpmDevice device,
        uint nvIndex,
        ReadOnlyMemory<byte> counterAuth,
        CancellationToken cancellationToken)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Increment, TpmResponseCodec.NvIncrement);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);

        using TpmPasswordSession incrementSession = TpmPasswordSession.Create(counterAuth.Span, pool);
        var incrementInput = new NvIncrementInput(nvIndex, nvIndex);

        TpmResult<NvIncrementResponse> incrementResult = await TpmCommandExecutor.ExecuteAsync<NvIncrementResponse>(
            device, incrementInput, [incrementSession], null, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!incrementResult.IsSuccess)
        {
            return incrementResult.Map<ulong>(_ => default);
        }

        using TpmPasswordSession readSession = TpmPasswordSession.Create(counterAuth.Span, pool);
        var readInput = new NvReadInput(AuthHandle: nvIndex, NvIndex: nvIndex, Size: CounterDataSize, Offset: 0);

        TpmResult<NvReadResponse> readResult = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, readInput, [readSession], null, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!readResult.IsSuccess)
        {
            return readResult.Map<ulong>(_ => default);
        }

        using NvReadResponse response = readResult.Value;

        return TpmResult<ulong>.Success(BinaryPrimitives.ReadUInt64BigEndian(response.Data));
    }

    /// <summary>
    /// Composes <c>TPM2_NV_Read</c> against <paramref name="nvIndex"/>'s full 8-octet counter window, authorized by
    /// the Index's own authValue.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The Counter Index to read.</param>
    /// <param name="counterAuth">The Index's authorization value.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A result containing the current count, or an error.</returns>
    private static async ValueTask<TpmResult<ulong>> ReadCounterCoreAsync(
        TpmDevice device,
        uint nvIndex,
        ReadOnlyMemory<byte> counterAuth,
        CancellationToken cancellationToken)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);

        using TpmPasswordSession session = TpmPasswordSession.Create(counterAuth.Span, pool);
        var readInput = new NvReadInput(AuthHandle: nvIndex, NvIndex: nvIndex, Size: CounterDataSize, Offset: 0);

        TpmResult<NvReadResponse> readResult = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, readInput, [session], null, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!readResult.IsSuccess)
        {
            return readResult.Map<ulong>(_ => default);
        }

        using NvReadResponse response = readResult.Value;

        return TpmResult<ulong>.Success(BinaryPrimitives.ReadUInt64BigEndian(response.Data));
    }

    /// <summary>
    /// Composes <c>TPM2_NV_UndefineSpace</c> against <paramref name="nvIndex"/>, authorized by the owner hierarchy.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value.</param>
    /// <param name="nvIndex">The Counter Index to undefine.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The undefine-space result.</returns>
    private static async ValueTask<TpmResult<NvUndefineSpaceResponse>> UndefineCounterCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> ownerAuth,
        uint nvIndex,
        CancellationToken cancellationToken)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);

        using TpmPasswordSession ownerSession = TpmPasswordSession.Create(ownerAuth.Span, pool);
        var input = new NvUndefineSpaceInput(TpmRh.TPM_RH_OWNER, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }
}
