using System;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tpm;
using Verifiable.Tpm.Extensions.Counter;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// Composes a <see cref="CtapSignatureCounterCustody"/> bundle whose per-credential signature counters are
/// each backed by their OWN NV Counter Index on an in-house simulated TPM (contract R-9, wavenv) — a thin
/// adapter over the <see cref="TpmDeviceExtensions"/> business-capability verbs package B shipped
/// (<c>DefineCounterAsync</c>/<c>IncrementCounterAsync</c>/<c>UndefineCounterAsync</c>), never a raw
/// <c>TPM2_NV_Increment</c> input — the same dogfood posture <see cref="TpmSealedStateCustody"/> established
/// over the <c>Extensions/Seal</c> verb group.
/// </summary>
/// <remarks>
/// <para>
/// <b>NV index derivation.</b> A credential's counter lives at NV Index <c>baseNvIndexHandle +
/// creationSequence</c> — a per-credential, not global, counter (a device-global counter would be a
/// cross-relying-party correlation channel; per-credential preserves WebAuthn's existing privacy posture).
/// <see cref="Create"/>'s caller owns choosing <c>baseNvIndexHandle</c> from an NV Index range this
/// authenticator does not otherwise use.
/// </para>
/// <para>
/// <b>Ensure semantics.</b> <see cref="CtapSignatureCounterCustody.EnsureCounterAsync"/> defines the Index
/// if absent, then performs its FIRST increment — the first legal way to read any value back at all, since
/// <c>TPM2_NV_Read</c> against a never-incremented Counter Index answers <c>TPM_RC_NV_UNINITIALIZED</c>
/// (Part 3, Section 31.13.1). A define answering <c>TPM_RC_NV_DEFINED</c> (the Index already exists — for
/// example a retry, or a caller that skipped retirement) is NOT surfaced as an error: this adapter proceeds
/// straight to the increment either way, so the ONLY externally visible difference between "freshly defined"
/// and "already defined" is which value the increment returns. A credential's mint-time signature counter
/// is therefore never <c>0</c> once this adapter is composed (contract R-9(3)(c)) — an accepted, opt-in
/// behavioral difference from the whole-snapshot-only default.
/// </para>
/// <para>
/// <b>Retire semantics.</b> <see cref="CtapSignatureCounterCustody.RetireCounterAsync"/> undefines the
/// Index; the in-house simulator's phantom high-water mark (TPM 2.0 Library Part 1, Section 37.2.6.3 NOTE
/// 2/NOTE 6) then guarantees that a LATER credential whose <c>creationSequence</c> collides with a retired
/// one (an <c>authenticatorReset</c> restarts the mint-order sequence at zero) seeds its own first
/// <see cref="CtapSignatureCounterCustody.EnsureCounterAsync"/> strictly above every value the retired Index
/// ever held — the R-9(b) closure this wave delivers. An undefine answering <c>TPM_RC_HANDLE</c> (nothing
/// was ever minted for this identity, or it was already retired) is treated as the ordinary idempotent
/// no-op <see cref="RetireCounterAsyncDelegate"/>'s own contract recommends, never an error.
/// </para>
/// <para>
/// Every other TPM-side rejection surfaces as a <see cref="TpmNvSignatureCounterCustodyException"/> rather
/// than a silently unminted or non-advanced counter (fail closed), mirroring
/// <see cref="TpmSealedStateCustody"/>'s own posture.
/// </para>
/// </remarks>
public static class TpmNvSignatureCounterCustody
{
    /// <summary>
    /// Builds a <see cref="CtapSignatureCounterCustody"/> bundle backed by an in-house simulated TPM's
    /// NV Counter Indexes.
    /// </summary>
    /// <param name="tpm">The TPM device every counter operation is composed against.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set — used to define and undefine every counter Index.</param>
    /// <param name="counterAuth">The authorization value every counter Index is defined with and incremented under.</param>
    /// <param name="baseNvIndexHandle">The NV Index handle credential 0's counter lives at; credential N's counter lives at <c>baseNvIndexHandle + N</c>.</param>
    /// <returns>The composed seam-bundle record.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="tpm"/> is <see langword="null"/>.</exception>
    public static CtapSignatureCounterCustody Create(
        TpmDevice tpm,
        ReadOnlyMemory<byte> ownerAuth,
        ReadOnlyMemory<byte> counterAuth,
        uint baseNvIndexHandle)
    {
        ArgumentNullException.ThrowIfNull(tpm);

        var binding = new TpmNvSignatureCounterCustodyBinding(tpm, ownerAuth, counterAuth, baseNvIndexHandle);

        return new CtapSignatureCounterCustody(binding.EnsureCounterAsync, binding.IncrementCounterAsync, binding.RetireCounterAsync);
    }
}


/// <summary>
/// The bound configuration <see cref="TpmNvSignatureCounterCustody.Create"/> composes into a
/// <see cref="CtapSignatureCounterCustody"/> bundle: every delegate <see cref="TpmNvSignatureCounterCustody.Create"/>
/// returns is a bound instance method on one of these, so the only "context" any of them closes over is the
/// explicit receiver (<see langword="this"/>), never a captured local (house rule: no closure capture) —
/// mirroring <c>TpmSealedStateCustodyBinding</c>'s identical shape.
/// </summary>
internal sealed class TpmNvSignatureCounterCustodyBinding
{
    /// <summary>The TPM device every counter operation is composed against.</summary>
    private TpmDevice Tpm { get; }

    /// <summary>The owner hierarchy's own authorization value.</summary>
    private ReadOnlyMemory<byte> OwnerAuth { get; }

    /// <summary>The authorization value every counter Index is defined with and incremented under.</summary>
    private ReadOnlyMemory<byte> CounterAuth { get; }

    /// <summary>The NV Index handle credential 0's counter lives at.</summary>
    private uint BaseNvIndexHandle { get; }


    /// <summary>
    /// Initializes a new binding. Use <see cref="TpmNvSignatureCounterCustody.Create"/>.
    /// </summary>
    /// <param name="tpm">The TPM device every counter operation is composed against.</param>
    /// <param name="ownerAuth">The owner hierarchy's own authorization value.</param>
    /// <param name="counterAuth">The authorization value every counter Index is defined with and incremented under.</param>
    /// <param name="baseNvIndexHandle">The NV Index handle credential 0's counter lives at.</param>
    internal TpmNvSignatureCounterCustodyBinding(TpmDevice tpm, ReadOnlyMemory<byte> ownerAuth, ReadOnlyMemory<byte> counterAuth, uint baseNvIndexHandle)
    {
        Tpm = tpm;
        OwnerAuth = ownerAuth;
        CounterAuth = counterAuth;
        BaseNvIndexHandle = baseNvIndexHandle;
    }


    /// <summary>
    /// Defines the credential's NV Counter Index if absent, then performs its first increment. Has the
    /// <see cref="EnsureCounterAsyncDelegate"/> shape.
    /// </summary>
    /// <param name="creationSequence">The minting credential's own creation-sequence identity.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The counter's initial count.</returns>
    /// <exception cref="TpmNvSignatureCounterCustodyException">The define (other than "already defined") or the first increment was rejected.</exception>
    internal async ValueTask<ulong> EnsureCounterAsync(ulong creationSequence, CancellationToken cancellationToken)
    {
        uint nvIndex = ResolveNvIndex(BaseNvIndexHandle, creationSequence);

        TpmResult<NvDefineSpaceResponse> defineResult = await Tpm.DefineCounterAsync(
            OwnerAuth, nvIndex, CounterAuth, cancellationToken: cancellationToken).ConfigureAwait(false);
        if(!defineResult.IsSuccess && !(defineResult.IsTpmError && defineResult.ResponseCode == TpmRcConstants.TPM_RC_NV_DEFINED))
        {
            throw new TpmNvSignatureCounterCustodyException(
                $"Defining the signature counter NV index for creation sequence '{creationSequence}' failed: {DescribeFailure(defineResult)}.");
        }

        return await IncrementCounterCoreAsync(nvIndex, creationSequence, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Atomically advances the credential's NV Counter Index by one. Has the
    /// <see cref="IncrementCounterAsyncDelegate"/> shape.
    /// </summary>
    /// <param name="creationSequence">The asserting credential's own creation-sequence identity.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The counter's fresh count.</returns>
    /// <exception cref="TpmNvSignatureCounterCustodyException">The increment was rejected.</exception>
    internal ValueTask<ulong> IncrementCounterAsync(ulong creationSequence, CancellationToken cancellationToken)
    {
        uint nvIndex = ResolveNvIndex(BaseNvIndexHandle, creationSequence);

        return IncrementCounterCoreAsync(nvIndex, creationSequence, cancellationToken);
    }


    /// <summary>
    /// Undefines the credential's NV Counter Index, tolerating an already-retired or never-minted identity
    /// as a no-op. Has the <see cref="RetireCounterAsyncDelegate"/> shape.
    /// </summary>
    /// <param name="creationSequence">The removed credential's own creation-sequence identity.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <exception cref="TpmNvSignatureCounterCustodyException">The undefine was rejected for a reason other than the Index never having existed.</exception>
    internal async ValueTask RetireCounterAsync(ulong creationSequence, CancellationToken cancellationToken)
    {
        uint nvIndex = ResolveNvIndex(BaseNvIndexHandle, creationSequence);

        TpmResult<NvUndefineSpaceResponse> undefineResult = await Tpm.UndefineCounterAsync(OwnerAuth, nvIndex, cancellationToken).ConfigureAwait(false);
        if(undefineResult.IsSuccess || (undefineResult.IsTpmError && undefineResult.ResponseCode == TpmRcConstants.TPM_RC_HANDLE))
        {
            return;
        }

        throw new TpmNvSignatureCounterCustodyException(
            $"Undefining the signature counter NV index for creation sequence '{creationSequence}' failed: {DescribeFailure(undefineResult)}.");
    }


    /// <summary>Increments <paramref name="nvIndex"/> and returns the fresh count, wrapped fail-closed.</summary>
    /// <param name="nvIndex">The already-resolved NV Index to increment.</param>
    /// <param name="creationSequence">The owning credential's creation-sequence identity, named in a failure message.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The counter's fresh count.</returns>
    /// <exception cref="TpmNvSignatureCounterCustodyException">The increment was rejected.</exception>
    private async ValueTask<ulong> IncrementCounterCoreAsync(uint nvIndex, ulong creationSequence, CancellationToken cancellationToken)
    {
        TpmResult<ulong> incrementResult = await Tpm.IncrementCounterAsync(nvIndex, CounterAuth, cancellationToken).ConfigureAwait(false);
        if(!incrementResult.IsSuccess)
        {
            throw new TpmNvSignatureCounterCustodyException(
                $"Incrementing the signature counter NV index for creation sequence '{creationSequence}' failed: {DescribeFailure(incrementResult)}.");
        }

        return incrementResult.Value;
    }


    /// <summary>Resolves the NV Index a credential's counter lives at: <paramref name="baseNvIndexHandle"/> plus its creation sequence.</summary>
    /// <param name="baseNvIndexHandle">The NV Index handle credential 0's counter lives at.</param>
    /// <param name="creationSequence">The credential's own creation-sequence identity.</param>
    /// <returns>The resolved NV Index handle.</returns>
    /// <exception cref="OverflowException">The resolved handle would not fit in a <see cref="uint"/> — fails closed rather than silently wrapping into a different credential's own Index.</exception>
    private static uint ResolveNvIndex(uint baseNvIndexHandle, ulong creationSequence) =>
        checked(baseNvIndexHandle + (uint)creationSequence);


    /// <summary>Describes a non-success <see cref="TpmResult{T}"/> for a fail-closed exception message.</summary>
    /// <typeparam name="T">The result's success-value type.</typeparam>
    /// <param name="result">The non-success result to describe.</param>
    /// <returns>A short, human-readable description of the TPM or transport failure.</returns>
    private static string DescribeFailure<T>(TpmResult<T> result) =>
        result.IsTpmError ? result.ResponseCode.GetDescription() : $"transport error 0x{result.TransportErrorCode:X8}";
}
