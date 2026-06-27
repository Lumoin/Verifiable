using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Extensions.Policy;

/// <summary>
/// A declarative TPM policy: an ordered list of <see cref="TpmPolicyAssertion"/> with the two operations a policy
/// always needs from one description — <see cref="ComputeDigest"/> predicts the policyDigest host-side (to set as
/// an object's authPolicy at create time), and <see cref="ExecuteAsync"/> replays the assertions on a live policy
/// session to satisfy it. Build one with <see cref="TpmPolicyBuilder"/>.
/// </summary>
/// <remarks>
/// The two operations mirror the library's two policy primitives: <see cref="TpmPolicyDigest"/> (host-side
/// prediction) and the <see cref="TpmDeviceExtensions"/> policy commands (on-device execution). Keeping both
/// behind one description means a caller writes the policy once and cannot drift the predicted digest from the
/// executed one.
/// </remarks>
/// <param name="Assertions">The ordered policy assertions.</param>
public sealed record TpmPolicy(IReadOnlyList<TpmPolicyAssertion> Assertions)
{
    /// <summary>
    /// Folds the assertions into the policyDigest they produce on a fresh session, mirroring the TPM.
    /// </summary>
    /// <param name="policyHash">The session's policy hash algorithm.</param>
    /// <param name="destination">Receives the policyDigest; must be at least <see cref="TpmPolicyDigest.Size"/> bytes.</param>
    /// <returns>The number of digest bytes written.</returns>
    public int ComputeDigest(TpmAlgIdConstants policyHash, Span<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(Assertions);

        int size = TpmPolicyDigest.Size(policyHash);
        Span<byte> running = destination[..size];
        running.Clear();

        //The Extend* helpers copy the running digest out before hashing into the destination, so aliasing the
        //running buffer as both source and destination is safe.
        Span<byte> permanentName = stackalloc byte[sizeof(uint)];

        for(int i = 0; i < Assertions.Count; i++)
        {
            switch(Assertions[i])
            {
                case CommandCodePolicyAssertion a:
                    _ = TpmPolicyDigest.ExtendForCommandCode(running, a.CommandCode, policyHash, running);
                    break;
                case AuthValuePolicyAssertion:
                    _ = TpmPolicyDigest.ExtendForAuthValue(running, policyHash, running);
                    break;
                case SecretPolicyAssertion a:
                    BinaryPrimitives.WriteUInt32BigEndian(permanentName, a.AuthHandle);
                    _ = TpmPolicyDigest.ExtendForSecret(running, permanentName, ReadOnlySpan<byte>.Empty, policyHash, running);
                    break;
                case NvPolicyAssertion a:
                    _ = TpmPolicyDigest.ExtendForNv(running, a.OperandB.Span, a.Offset, (ushort)a.Operation, a.NvName.Span, policyHash, running);
                    break;
                case OrPolicyAssertion a:
                    _ = TpmPolicyDigest.ExtendForOr(a.BranchDigests, policyHash, running);
                    break;
                case PcrPolicyAssertion a:
                    ExtendPcr(running, a, policyHash);
                    break;
                default:
                    throw new NotSupportedException($"Unsupported policy assertion '{Assertions[i].GetType().Name}'.");
            }
        }

        return size;
    }

    /// <summary>
    /// Replays the assertions on a live policy session, stopping at the first failure.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="policySession">The policy session handle to drive.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The policy session handle on success, or the first failing command's error.</returns>
    public async ValueTask<TpmResult<uint>> ExecuteAsync(TpmDevice device, uint policySession, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(Assertions);

        for(int i = 0; i < Assertions.Count; i++)
        {
            switch(Assertions[i])
            {
                case CommandCodePolicyAssertion a:
                {
                    TpmResult<PolicyCommandCodeResponse> r = await device.PolicyCommandCodeAsync(policySession, a.CommandCode, cancellationToken).ConfigureAwait(false);
                    if(!r.IsSuccess)
                    {
                        return ToFailure(r);
                    }

                    break;
                }
                case AuthValuePolicyAssertion:
                {
                    TpmResult<PolicyAuthValueResponse> r = await device.PolicyAuthValueAsync(policySession, cancellationToken).ConfigureAwait(false);
                    if(!r.IsSuccess)
                    {
                        return ToFailure(r);
                    }

                    break;
                }
                case SecretPolicyAssertion a:
                {
                    TpmResult<PolicySecretResponse> r = await device.PolicySecretAsync(a.AuthHandle, policySession, cancellationToken).ConfigureAwait(false);
                    if(!r.IsSuccess)
                    {
                        return ToFailure(r);
                    }

                    break;
                }
                case NvPolicyAssertion a:
                {
                    TpmResult<PolicyNvResponse> r = await device.PolicyNvAsync(a.AuthHandle, a.NvIndex, policySession, a.OperandB, a.Offset, a.Operation, cancellationToken).ConfigureAwait(false);
                    if(!r.IsSuccess)
                    {
                        return ToFailure(r);
                    }

                    break;
                }
                case OrPolicyAssertion a:
                {
                    TpmResult<PolicyOrResponse> r = await device.PolicyOrAsync(policySession, a.BranchDigests, cancellationToken).ConfigureAwait(false);
                    if(!r.IsSuccess)
                    {
                        return ToFailure(r);
                    }

                    break;
                }
                case PcrPolicyAssertion a:
                {
                    TpmResult<PolicyPcrResponse> r = await device.PolicyPcrAsync(policySession, a.PcrBank, a.PcrIndices, a.PcrDigest, cancellationToken).ConfigureAwait(false);
                    if(!r.IsSuccess)
                    {
                        return ToFailure(r);
                    }

                    break;
                }
                default:
                    throw new NotSupportedException($"Unsupported policy assertion '{Assertions[i].GetType().Name}'.");
            }
        }

        return TpmResult<uint>.Success(policySession);
    }

    /// <summary>
    /// Folds a PolicyPCR assertion into the running digest, marshaling its PCR selection.
    /// </summary>
    /// <param name="running">The running policyDigest (source and destination).</param>
    /// <param name="assertion">The PCR assertion.</param>
    /// <param name="policyHash">The session's policy hash algorithm.</param>
    private static void ExtendPcr(Span<byte> running, PcrPolicyAssertion assertion, TpmAlgIdConstants policyHash)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using TpmlPcrSelection selection = TpmlPcrSelection.Create(assertion.PcrBank, assertion.PcrIndices, pool);
        int selectionSize = selection.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(selectionSize);
        Span<byte> marshaled = owner.Memory.Span[..selectionSize];
        var writer = new TpmWriter(marshaled);
        selection.WriteTo(ref writer);
        _ = TpmPolicyDigest.ExtendForPcr(running, marshaled, assertion.PcrDigest.Span, policyHash, running);
    }

    /// <summary>
    /// Re-wraps a failed step result as a <see cref="TpmResult{T}"/> of session handle, preserving the error kind.
    /// </summary>
    /// <typeparam name="TResponse">The step response type.</typeparam>
    /// <param name="result">The failed step result.</param>
    /// <returns>The equivalent failure.</returns>
    private static TpmResult<uint> ToFailure<TResponse>(TpmResult<TResponse> result) =>
        result.Match(
            onSuccess: static _ => TpmResult<uint>.Success(0u),
            onTpmError: static code => TpmResult<uint>.TpmError(code),
            onTransportError: static tcode => TpmResult<uint>.TransportError(tcode));
}
