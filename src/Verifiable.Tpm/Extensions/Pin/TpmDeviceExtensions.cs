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

namespace Verifiable.Tpm.Extensions.Pin;

/// <summary>
/// The <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> structure retained by a PIN Index's data area (TPM 2.0 Library
/// Part 2, Section 13.3): the current attempt count and the attempt threshold it is compared against.
/// </summary>
/// <param name="PinCount">The current attempt count.</param>
/// <param name="PinLimit">The attempt threshold; the Index's own authValue stops being usable once <see cref="PinCount"/> reaches this.</param>
public readonly record struct TpmPinCounterParameters(uint PinCount, uint PinLimit);

/// <summary>
/// Persistent PIN-retry-budget ("throttle") business-capability extensions for <see cref="TpmDevice"/>, composed
/// over a <c>TPM_NT_PIN_FAIL</c> NV Index (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 1, Section 37.2.6.6).
/// </summary>
/// <remarks>
/// <para>
/// These verbs compose the shipped <c>TPM2_NV_DefineSpace</c>/<c>TPM2_NV_Read</c>/<c>TPM2_NV_Write</c>/
/// <c>TPM2_NV_UndefineSpace</c> surface (Part 3, Sections 31.3, 31.13, 31.7, 31.4) into a single business
/// capability: a PIN-retry counter whose own compare-and-move is one atomic TPM command, so there is no
/// window between "check the PIN" and "record the attempt" for a caller to exploit. Every session (the owner
/// hierarchy's for the administrative arms, the Index's own for the verify arm) is built and disposed
/// internally; a caller never hands in a pre-built session, matching <c>Extensions/Counter</c>.
/// </para>
/// <para>
/// <b>PIN_FAIL only.</b> This group defines and drives only <c>TPM_NT_PIN_FAIL</c> Indexes: a wrong candidate
/// increments <c>pinCount</c>, a correct one below <c>pinLimit</c> resets it to zero, and at <c>pinLimit</c>
/// even the correct value is refused (Part 1, Section 37.2.6.6). <c>TPM_NT_PIN_PASS</c> composes the opposite
/// semantics (increment on success) and is out of this group's scope.
/// </para>
/// <para>
/// <b>Attributes are hard-coded.</b> Every Index this group defines carries exactly <c>TPM_NT_PIN_FAIL |
/// TPMA_NV_NO_DA | TPMA_NV_AUTHREAD | TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD</c>: <c>NO_DA</c> is
/// spec-mandated for a PIN Fail Index (Part 2, Section 13.4) so its own localized throttle never doubles up
/// with the TPM-wide dictionary-attack counter; <c>AUTHWRITE</c> is deliberately absent, so the Index's own
/// authValue can never write it (the PIN oracle the automaton's <c>TPM2_NV_DefineSpace()</c> gate refuses to
/// define in the first place); <c>OWNERWRITE</c>/<c>OWNERREAD</c> make the owner hierarchy the sole
/// administrative path for provisioning, reset, and no-oracle retry-count reporting.
/// </para>
/// <para>
/// <b>PIN is the authorization value.</b> Every candidate/authorization parameter here is
/// <see cref="ReadOnlyMemory{T}"/> carrying the already-hashed, fixed-width stored PIN form - this group
/// never sees or derives a raw PIN, matching the no-naked-bytes carrier discipline that binds every other
/// authorization value in this library.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer does not recognize C# 13 extension type syntax.")]
public static class TpmDeviceExtensions
{
    /// <summary>The declared data area size (octets) of every PIN Fail Index this group defines - the whole 8-octet <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> (TPM 2.0 Library Part 2, Section 13.3).</summary>
    private const ushort PinCounterParametersSize = 8;

    /// <summary>The Name hash algorithm fixed for every PIN Fail Index this group defines.</summary>
    private const TpmAlgIdConstants PinNameAlgorithm = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>
    /// The hard-coded <c>TPMA_NV</c> attribute set for every PIN Fail Index this group defines (TPM 2.0 Library
    /// Part 1, Section 37.2.6.1 and 37.2.6.6; Part 2, Section 13.4): <c>TPM_NT_PIN_FAIL</c>, spec-mandated
    /// <c>TPMA_NV_NO_DA</c>, Index-authValue reads via <c>TPMA_NV_AUTHREAD</c>, and owner-hierarchy
    /// provisioning/reporting via <c>TPMA_NV_OWNERWRITE</c>/<c>TPMA_NV_OWNERREAD</c>. <c>TPMA_NV_AUTHWRITE</c>
    /// is deliberately absent - the Index's own authValue may never write it.
    /// </summary>
    private const TpmaNv PinFailAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_OWNERREAD | TpmaNv.TPMA_NV_NO_DA
        | (TpmaNv)((uint)TpmNt.TPM_NT_PIN_FAIL << TpmaNvFields.TPM_NT_SHIFT);

    extension(TpmDevice device)
    {
        /// <summary>
        /// Defines a new <c>TPM_NT_PIN_FAIL</c> NV Index under the owner hierarchy and provisions it with
        /// <paramref name="pinHash"/> as its authValue and a fresh <c>{pinCount: 0, pinLimit}</c> counter,
        /// composing <c>TPM2_NV_DefineSpace</c> then an owner-authorized <c>TPM2_NV_Write</c> internally.
        /// </summary>
        /// <remarks>
        /// A PIN Fail Index forbids <c>TPMA_NV_AUTHWRITE</c> (Part 1, Section 37.2.6.1), so the counter
        /// parameters can only ever be established by the owner-authorized write this verb composes -
        /// provisioning and the later <see cref="ResetPinCountAsync"/> recovery share the identical write
        /// shape. Rotating the PIN (a fresh definition under the same handle after
        /// <see cref="UndefinePinIndexAsync"/>) rotates the Index authValue itself, so a stale snapshot of the
        /// old authValue can never again resolve authorization against the rotated Index.
        /// </remarks>
        /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
        /// <param name="pinIndexHandle">The NV Index handle to define.</param>
        /// <param name="pinHash">The stored PIN form (already hashed) to install as the Index authValue.</param>
        /// <param name="pinLimit">The attempt threshold to provision.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success, or the definition's or the provisioning write's error.</returns>
        public ValueTask<TpmResult<NvWriteResponse>> DefinePinFailIndexAsync(
            ReadOnlyMemory<byte> ownerAuth,
            uint pinIndexHandle,
            ReadOnlyMemory<byte> pinHash,
            uint pinLimit,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return DefinePinFailIndexCoreAsync(device, ownerAuth, pinIndexHandle, pinHash, pinLimit, cancellationToken);
        }

        /// <summary>
        /// Verifies <paramref name="candidatePinHash"/> against <paramref name="pinIndexHandle"/>'s own
        /// authValue, composing an Index-authorized <c>TPM2_NV_Read</c> of the full counter window internally.
        /// </summary>
        /// <remarks>
        /// The compare and the <c>pinCount</c> move are resolved as ONE atomic TPM command (Part 1, Section
        /// 37.2.6.6): a correct candidate below <c>pinLimit</c> resets <c>pinCount</c> to zero and returns the
        /// reset parameters; a wrong one increments <c>pinCount</c> and answers <c>TPM_RC_BAD_AUTH</c> (a PIN
        /// Fail Index is spec-mandated <c>TPMA_NV_NO_DA</c>, so a wrong PIN is never <c>TPM_RC_AUTH_FAIL</c>);
        /// at <c>pinLimit</c> even the correct candidate is refused with <c>TPM_RC_AUTH_UNAVAILABLE</c>,
        /// without moving <c>pinCount</c> further. There is no TOCTOU window between comparing and recording.
        /// </remarks>
        /// <param name="pinIndexHandle">The PIN Fail Index to verify against.</param>
        /// <param name="candidatePinHash">The candidate stored PIN form to verify.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the post-attempt counter parameters, or an error.</returns>
        public ValueTask<TpmResult<TpmPinCounterParameters>> VerifyPinAsync(
            uint pinIndexHandle,
            ReadOnlyMemory<byte> candidatePinHash,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return VerifyPinCoreAsync(device, pinIndexHandle, candidatePinHash, cancellationToken);
        }

        /// <summary>
        /// Reads <paramref name="pinIndexHandle"/>'s current counter parameters under owner authorization,
        /// composing the owner-authorized arm of <c>TPM2_NV_Read</c> internally, without ever supplying or
        /// guessing the PIN.
        /// </summary>
        /// <remarks>
        /// The owner-read arm never moves <c>pinCount</c>: authorization is resolved entirely against the
        /// OWNER's own authValue, so this is a genuine no-oracle "how many tries remain" query - unlike a
        /// PIN-consuming <see cref="VerifyPinAsync"/> guess, a caller may poll this as often as needed. An
        /// unwritten Index answers <c>TPM_RC_NV_UNINITIALIZED</c> on this arm specifically (the Index-arm's
        /// <c>TPM_RC_AUTH_UNAVAILABLE</c> pre-gate does not apply here, TPM 2.0 Library Part 1, Section
        /// 37.2.6.6).
        /// </remarks>
        /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
        /// <param name="pinIndexHandle">The PIN Fail Index to read.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the current counter parameters, or an error.</returns>
        public ValueTask<TpmResult<TpmPinCounterParameters>> ReadPinCountersAsync(
            ReadOnlyMemory<byte> ownerAuth,
            uint pinIndexHandle,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return ReadPinCountersCoreAsync(device, ownerAuth, pinIndexHandle, cancellationToken);
        }

        /// <summary>
        /// Resets <paramref name="pinIndexHandle"/>'s <c>pinCount</c> to zero and (re)establishes
        /// <paramref name="pinLimit"/>, composing an owner-authorized <c>TPM2_NV_Write</c> of the full 8-octet
        /// counter window internally - the sole recovery path once <c>pinCount</c> has reached <c>pinLimit</c>
        /// (Part 1, Section 37.2.8.1's "no automatic self-heal" note).
        /// </summary>
        /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
        /// <param name="pinIndexHandle">The PIN Fail Index to reset.</param>
        /// <param name="pinLimit">The attempt threshold to (re)establish.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<NvWriteResponse>> ResetPinCountAsync(
            ReadOnlyMemory<byte> ownerAuth,
            uint pinIndexHandle,
            uint pinLimit,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return ResetPinCountCoreAsync(device, ownerAuth, pinIndexHandle, pinLimit, cancellationToken);
        }

        /// <summary>
        /// Removes <paramref name="pinIndexHandle"/>'s definition, composing <c>TPM2_NV_UndefineSpace</c>
        /// internally, authorized by the owner hierarchy's OWN authValue - never by the PIN.
        /// </summary>
        /// <remarks>
        /// The owner authValue actually supplied is now compared (TPM 2.0 Library Part 3, Section 31.4): a
        /// wrong <paramref name="ownerAuth"/> is refused with <c>TPM_RC_BAD_AUTH</c> rather than silently
        /// undefining the Index, so an undefine-then-<see cref="DefinePinFailIndexAsync"/> can no longer serve
        /// as an unauthenticated PIN-throttle reset.
        /// </remarks>
        /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
        /// <param name="pinIndexHandle">The PIN Fail Index to undefine.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<NvUndefineSpaceResponse>> UndefinePinIndexAsync(
            ReadOnlyMemory<byte> ownerAuth,
            uint pinIndexHandle,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return UndefinePinIndexCoreAsync(device, ownerAuth, pinIndexHandle, cancellationToken);
        }
    }

    /// <summary>
    /// Composes <c>TPM2_NV_DefineSpace</c> for a new <c>TPM_NT_PIN_FAIL</c> Index under the owner hierarchy,
    /// then an owner-authorized <c>TPM2_NV_Write</c> of the fresh <c>{pinCount: 0, pinLimit}</c> counter.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value.</param>
    /// <param name="pinIndexHandle">The NV Index handle to define.</param>
    /// <param name="pinHash">The stored PIN form to install as the Index authValue.</param>
    /// <param name="pinLimit">The attempt threshold to provision.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The provisioning write's result, or the definition's error.</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the auth value and public area transfers to NvDefineSpaceInput, which disposes both; the redundant using locals satisfy CA2000 and are safe because all three types have idempotent disposal.")]
    private static async ValueTask<TpmResult<NvWriteResponse>> DefinePinFailIndexCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> ownerAuth,
        uint pinIndexHandle,
        ReadOnlyMemory<byte> pinHash,
        uint pinLimit,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);

        using Tpm2bAuth auth = Tpm2bAuth.Create(pinHash.Span, pool);
        using TpmsNvPublic publicInfo = new(pinIndexHandle, PinNameAlgorithm, PinFailAttributes, Tpm2bDigest.Empty, PinCounterParametersSize);
        using NvDefineSpaceInput defineInput = new(TpmRh.TPM_RH_OWNER, auth, publicInfo);
        using TpmPasswordSession defineSession = TpmPasswordSession.Create(ownerAuth.Span, pool);

        TpmResult<NvDefineSpaceResponse> defineResult = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, defineInput, [defineSession], null, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!defineResult.IsSuccess)
        {
            return defineResult.Map<NvWriteResponse>(_ => default!);
        }

        return await WritePinCounterParametersAsync(device, pool, registry, ownerAuth, pinIndexHandle, pinCount: 0, pinLimit, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Composes an Index-authorized <c>TPM2_NV_Read</c> of the full <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c>
    /// window, whose compare-and-move is one atomic TPM command (Part 1, Section 37.2.6.6).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pinIndexHandle">The PIN Fail Index to verify against.</param>
    /// <param name="candidatePinHash">The candidate stored PIN form to verify.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A result containing the post-attempt counter parameters, or an error.</returns>
    private static async ValueTask<TpmResult<TpmPinCounterParameters>> VerifyPinCoreAsync(
        TpmDevice device,
        uint pinIndexHandle,
        ReadOnlyMemory<byte> candidatePinHash,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);

        using TpmPasswordSession session = TpmPasswordSession.Create(candidatePinHash.Span, pool);
        var readInput = new NvReadInput(AuthHandle: pinIndexHandle, NvIndex: pinIndexHandle, Size: PinCounterParametersSize, Offset: 0);

        TpmResult<NvReadResponse> readResult = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, readInput, [session], null, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!readResult.IsSuccess)
        {
            return readResult.Map<TpmPinCounterParameters>(_ => default);
        }

        using NvReadResponse response = readResult.Value;

        return TpmResult<TpmPinCounterParameters>.Success(ParsePinCounterParameters(response.Data));
    }

    /// <summary>
    /// Composes the owner-authorized arm of <c>TPM2_NV_Read</c> against the full counter window - a no-oracle
    /// retry-count query that never moves <c>pinCount</c> (TPM 2.0 Library Part 3, Section 31.13).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value.</param>
    /// <param name="pinIndexHandle">The PIN Fail Index to read.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A result containing the current counter parameters, or an error.</returns>
    private static async ValueTask<TpmResult<TpmPinCounterParameters>> ReadPinCountersCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> ownerAuth,
        uint pinIndexHandle,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);

        using TpmPasswordSession ownerSession = TpmPasswordSession.Create(ownerAuth.Span, pool);
        var readInput = new NvReadInput(AuthHandle: (uint)TpmRh.TPM_RH_OWNER, NvIndex: pinIndexHandle, Size: PinCounterParametersSize, Offset: 0);

        TpmResult<NvReadResponse> readResult = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, readInput, [ownerSession], null, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!readResult.IsSuccess)
        {
            return readResult.Map<TpmPinCounterParameters>(_ => default);
        }

        using NvReadResponse response = readResult.Value;

        return TpmResult<TpmPinCounterParameters>.Success(ParsePinCounterParameters(response.Data));
    }

    /// <summary>
    /// Composes an owner-authorized <c>TPM2_NV_Write</c> of the full 8-octet counter window, resetting
    /// <c>pinCount</c> to zero and (re)establishing <paramref name="pinLimit"/>.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value.</param>
    /// <param name="pinIndexHandle">The PIN Fail Index to reset.</param>
    /// <param name="pinLimit">The attempt threshold to (re)establish.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The write result.</returns>
    private static async ValueTask<TpmResult<NvWriteResponse>> ResetPinCountCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> ownerAuth,
        uint pinIndexHandle,
        uint pinLimit,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);

        return await WritePinCounterParametersAsync(device, pool, registry, ownerAuth, pinIndexHandle, pinCount: 0, pinLimit, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Composes <c>TPM2_NV_UndefineSpace</c> against <paramref name="pinIndexHandle"/>, authorized by the
    /// owner hierarchy's own authValue.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value.</param>
    /// <param name="pinIndexHandle">The PIN Fail Index to undefine.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The undefine-space result.</returns>
    private static async ValueTask<TpmResult<NvUndefineSpaceResponse>> UndefinePinIndexCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> ownerAuth,
        uint pinIndexHandle,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);

        using TpmPasswordSession ownerSession = TpmPasswordSession.Create(ownerAuth.Span, pool);
        var input = new NvUndefineSpaceInput(TpmRh.TPM_RH_OWNER, pinIndexHandle);

        return await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues an owner-authorized <c>TPM2_NV_Write</c> of the full 8-octet <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c>
    /// blob - the single shape shared by initial provisioning (<see cref="DefinePinFailIndexCoreAsync"/>) and
    /// later reset (<see cref="ResetPinCountCoreAsync"/>).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry, already carrying the <c>NV_Write</c> codec.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value.</param>
    /// <param name="pinIndexHandle">The PIN Fail Index to write.</param>
    /// <param name="pinCount">The pinCount value to store.</param>
    /// <param name="pinLimit">The pinLimit value to store.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The write result.</returns>
    private static async ValueTask<TpmResult<NvWriteResponse>> WritePinCounterParametersAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        ReadOnlyMemory<byte> ownerAuth,
        uint pinIndexHandle,
        uint pinCount,
        uint pinLimit,
        CancellationToken cancellationToken)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.Create(ownerAuth.Span, pool);
        using IMemoryOwner<byte> blobOwner = pool.Rent(PinCounterParametersSize);
        Memory<byte> blob = blobOwner.Memory[..PinCounterParametersSize];
        BinaryPrimitives.WriteUInt32BigEndian(blob.Span, pinCount);
        BinaryPrimitives.WriteUInt32BigEndian(blob.Span[sizeof(uint)..], pinLimit);

        var writeInput = new NvWriteInput((uint)TpmRh.TPM_RH_OWNER, pinIndexHandle, new Tpm2bMaxBuffer(blob), Offset: 0);

        return await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            device, writeInput, [ownerSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Parses the 8-octet <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> window into its two big-endian <see cref="uint"/> fields.</summary>
    /// <param name="data">The octets a successful <c>TPM2_NV_Read</c> returned.</param>
    /// <returns>The parsed counter parameters.</returns>
    private static TpmPinCounterParameters ParsePinCounterParameters(ReadOnlySpan<byte> data) =>
        new(BinaryPrimitives.ReadUInt32BigEndian(data), BinaryPrimitives.ReadUInt32BigEndian(data[sizeof(uint)..]));
}
