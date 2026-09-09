using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

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
    /// <param name="pool">The memory pool every fold's hash-input scratch buffer is rented from.</param>
    /// <returns>The number of digest bytes written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public int ComputeDigest(TpmAlgIdConstants policyHash, Span<byte> destination, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(Assertions);
        ArgumentNullException.ThrowIfNull(pool);

        int size = TpmPolicyDigest.Size(policyHash);
        Span<byte> running = destination[..size];
        running.Clear();

        //The Extend* helpers copy the running digest out before hashing into the destination, so aliasing the
        //running buffer as both source and destination is safe.
        for(int i = 0; i < Assertions.Count; i++)
        {
            _ = Assertions[i] switch
            {
                CommandCodePolicyAssertion a => TpmPolicyDigest.ExtendForCommandCode(running, a.CommandCode, policyHash, running, pool),
                AuthValuePolicyAssertion => TpmPolicyDigest.ExtendForAuthValue(running, policyHash, running, pool),
                SecretPolicyAssertion a => ExtendSecret(running, a.AuthHandle, policyHash, pool),
                NvPolicyAssertion a => TpmPolicyDigest.ExtendForNv(running, a.OperandB.Span, a.Offset, (ushort)a.Operation, a.NvName.Span, policyHash, running, pool),
                CounterTimerPolicyAssertion a => TpmPolicyDigest.ExtendForCounterTimer(running, a.OperandB.Span, a.Offset, (ushort)a.Operation, policyHash, running, pool),
                OrPolicyAssertion a => TpmPolicyDigest.ExtendForOr(a.BranchDigests, policyHash, running, pool),
                PcrPolicyAssertion a => ExtendPcr(running, a, policyHash, pool),
                SignedPolicyAssertion a => TpmPolicyDigest.ExtendForSigned(running, a.AuthName.Span, a.PolicyRef.Span, policyHash, running, pool),
                AuthorizePolicyAssertion a => TpmPolicyDigest.ExtendForAuthorize(a.KeySign.Span, a.PolicyRef.Span, policyHash, running, pool),
                PasswordPolicyAssertion => TpmPolicyDigest.ExtendForPassword(running, policyHash, running, pool),
                CpHashPolicyAssertion a => TpmPolicyDigest.ExtendForCpHash(running, a.CpHashA.Span, policyHash, running, pool),
                NameHashPolicyAssertion a => TpmPolicyDigest.ExtendForNameHash(running, a.NameHash.Span, policyHash, running, pool),
                DuplicationSelectPolicyAssertion a => TpmPolicyDigest.ExtendForDuplicationSelect(running, a.ObjectName.Span, a.NewParentName.Span, a.IsObjectIncluded, policyHash, running, pool),
                ParametersPolicyAssertion a => TpmPolicyDigest.ExtendForParameters(running, a.ParametersHash.Span, policyHash, running, pool),
                TemplatePolicyAssertion a => TpmPolicyDigest.ExtendForTemplate(running, a.TemplateHash.Span, policyHash, running, pool),
                LocalityPolicyAssertion a => TpmPolicyDigest.ExtendForLocality(running, a.Locality, policyHash, running, pool),
                NvWrittenPolicyAssertion a => TpmPolicyDigest.ExtendForNvWritten(running, a.IsWrittenSet, policyHash, running, pool),
                AuthorizeNvPolicyAssertion a => TpmPolicyDigest.ExtendForAuthorizeNv(a.NvName.Span, policyHash, running, pool),
                _ => throw new NotSupportedException($"Unsupported policy assertion '{Assertions[i].GetType().Name}'.")
            };
        }

        return size;

        /// <summary>
        /// Folds a PolicySecret assertion: a permanent handle's Name is its 4-octet big-endian handle value
        /// (TPM 2.0 Library Part 1, clause 13, Table 9), folded with an empty policyRef.
        /// </summary>
        static int ExtendSecret(Span<byte> running, uint authHandle, TpmAlgIdConstants policyHash, BaseMemoryPool pool)
        {
            //A permanent handle value is public, non-secret data, so the tiny fixed-size stack buffer is safe.
            Span<byte> permanentName = stackalloc byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32BigEndian(permanentName, authHandle);

            return TpmPolicyDigest.ExtendForSecret(running, permanentName, ReadOnlySpan<byte>.Empty, policyHash, running, pool);
        }
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
            TpmResult<uint>? failure = Assertions[i] switch
            {
                CommandCodePolicyAssertion a => await StepCommandCodeAsync(device, policySession, a, cancellationToken).ConfigureAwait(false),
                AuthValuePolicyAssertion => await StepAuthValueAsync(device, policySession, cancellationToken).ConfigureAwait(false),
                SecretPolicyAssertion a => await StepSecretAsync(device, policySession, a, cancellationToken).ConfigureAwait(false),
                NvPolicyAssertion a => await StepNvAsync(device, policySession, a, cancellationToken).ConfigureAwait(false),
                CounterTimerPolicyAssertion a => await StepCounterTimerAsync(device, policySession, a, cancellationToken).ConfigureAwait(false),
                OrPolicyAssertion a => await StepOrAsync(device, policySession, a, cancellationToken).ConfigureAwait(false),
                PcrPolicyAssertion a => await StepPcrAsync(device, policySession, a, cancellationToken).ConfigureAwait(false),
                SignedPolicyAssertion a => await StepSignedAsync(device, policySession, a, cancellationToken).ConfigureAwait(false),
                AuthorizePolicyAssertion a => await StepAuthorizeAsync(device, policySession, a, cancellationToken).ConfigureAwait(false),
                PasswordPolicyAssertion => await StepPasswordAsync(device, policySession, cancellationToken).ConfigureAwait(false),
                CpHashPolicyAssertion a => await StepCpHashAsync(device, policySession, a, cancellationToken).ConfigureAwait(false),
                NameHashPolicyAssertion a => await StepNameHashAsync(device, policySession, a, cancellationToken).ConfigureAwait(false),
                DuplicationSelectPolicyAssertion a => await StepDuplicationSelectAsync(device, policySession, a, cancellationToken).ConfigureAwait(false),
                ParametersPolicyAssertion a => await StepParametersAsync(device, policySession, a, cancellationToken).ConfigureAwait(false),
                TemplatePolicyAssertion a => await StepTemplateAsync(device, policySession, a, cancellationToken).ConfigureAwait(false),
                LocalityPolicyAssertion a => await StepLocalityAsync(device, policySession, a, cancellationToken).ConfigureAwait(false),
                NvWrittenPolicyAssertion a => await StepNvWrittenAsync(device, policySession, a, cancellationToken).ConfigureAwait(false),
                AuthorizeNvPolicyAssertion a => await StepAuthorizeNvAsync(device, policySession, a, cancellationToken).ConfigureAwait(false),
                _ => throw new NotSupportedException($"Unsupported policy assertion '{Assertions[i].GetType().Name}'.")
            };

            if(failure is { } failed)
            {
                return failed;
            }
        }

        return TpmResult<uint>.Success(policySession);

        /// <summary>Replays a TPM2_PolicyCommandCode assertion; <see langword="null"/> on success.</summary>
        static async ValueTask<TpmResult<uint>?> StepCommandCodeAsync(TpmDevice device, uint policySession, CommandCodePolicyAssertion assertion, CancellationToken cancellationToken)
        {
            TpmResult<PolicyCommandCodeResponse> result = await device.PolicyCommandCodeAsync(policySession, assertion.CommandCode, cancellationToken).ConfigureAwait(false);

            return result.IsSuccess ? null : ToFailure(result);
        }

        /// <summary>Replays a TPM2_PolicyAuthValue assertion; <see langword="null"/> on success.</summary>
        static async ValueTask<TpmResult<uint>?> StepAuthValueAsync(TpmDevice device, uint policySession, CancellationToken cancellationToken)
        {
            TpmResult<PolicyAuthValueResponse> result = await device.PolicyAuthValueAsync(policySession, cancellationToken).ConfigureAwait(false);

            return result.IsSuccess ? null : ToFailure(result);
        }

        /// <summary>Replays a TPM2_PolicySecret assertion, disposing the pooled response; <see langword="null"/> on success.</summary>
        static async ValueTask<TpmResult<uint>?> StepSecretAsync(TpmDevice device, uint policySession, SecretPolicyAssertion assertion, CancellationToken cancellationToken)
        {
            TpmResult<PolicySecretResponse> result = await device.PolicySecretAsync(assertion.AuthHandle, policySession, cancellationToken).ConfigureAwait(false);
            if(!result.IsSuccess)
            {
                return ToFailure(result);
            }

            result.Value.Dispose();

            return null;
        }

        /// <summary>Replays a TPM2_PolicyNV assertion; <see langword="null"/> on success.</summary>
        static async ValueTask<TpmResult<uint>?> StepNvAsync(TpmDevice device, uint policySession, NvPolicyAssertion assertion, CancellationToken cancellationToken)
        {
            TpmResult<PolicyNvResponse> result = await device.PolicyNvAsync(assertion.AuthHandle, assertion.NvIndex, policySession, assertion.OperandB, assertion.Offset, assertion.Operation, cancellationToken).ConfigureAwait(false);

            return result.IsSuccess ? null : ToFailure(result);
        }

        /// <summary>Replays a TPM2_PolicyCounterTimer assertion; <see langword="null"/> on success.</summary>
        static async ValueTask<TpmResult<uint>?> StepCounterTimerAsync(TpmDevice device, uint policySession, CounterTimerPolicyAssertion assertion, CancellationToken cancellationToken)
        {
            TpmResult<PolicyCounterTimerResponse> result = await device.PolicyCounterTimerAsync(
                policySession, assertion.OperandB, assertion.Offset, assertion.Operation, cancellationToken).ConfigureAwait(false);

            return result.IsSuccess ? null : ToFailure(result);
        }

        /// <summary>Replays a TPM2_PolicyOR assertion; <see langword="null"/> on success.</summary>
        static async ValueTask<TpmResult<uint>?> StepOrAsync(TpmDevice device, uint policySession, OrPolicyAssertion assertion, CancellationToken cancellationToken)
        {
            TpmResult<PolicyOrResponse> result = await device.PolicyOrAsync(policySession, assertion.BranchDigests, cancellationToken).ConfigureAwait(false);

            return result.IsSuccess ? null : ToFailure(result);
        }

        /// <summary>Replays a TPM2_PolicyPCR assertion; <see langword="null"/> on success.</summary>
        static async ValueTask<TpmResult<uint>?> StepPcrAsync(TpmDevice device, uint policySession, PcrPolicyAssertion assertion, CancellationToken cancellationToken)
        {
            TpmResult<PolicyPcrResponse> result = await device.PolicyPcrAsync(policySession, assertion.PcrBank, assertion.PcrIndices, assertion.PcrDigest, cancellationToken).ConfigureAwait(false);

            return result.IsSuccess ? null : ToFailure(result);
        }

        /// <summary>
        /// Replays a TPM2_PolicySigned assertion: builds <c>aHash</c> in a pooled buffer, obtains the signature
        /// through the assertion's delegate as a pooled <see cref="Signature"/> carrier (disposed here), and
        /// submits the command; <see langword="null"/> on success.
        /// </summary>
        static async ValueTask<TpmResult<uint>?> StepSignedAsync(TpmDevice device, uint policySession, SignedPolicyAssertion assertion, CancellationToken cancellationToken)
        {
            BaseMemoryPool pool = device.Pool;
            int aHashLength = TpmPolicyDigest.Size(assertion.SchemeHashAlg);
            IMemoryOwner<byte> aHashOwner = pool.Rent(aHashLength);
            _ = BuildPolicySignedAHash(assertion.Expiration, assertion.PolicyRef.Span, assertion.SchemeHashAlg, aHashOwner.Memory.Span[..aHashLength], pool);

            //The carrier takes ownership of the pooled buffer; disposing it releases (and zeroes) the rental.
            using var aHash = new DigestValue(aHashOwner, DigestTagFor(assertion.SchemeHashAlg));
            using Signature signature = await assertion.Sign(aHash, assertion.SigningContext, pool, cancellationToken).ConfigureAwait(false);

            TpmResult<PolicySignedResponse> result = await device.PolicySignedAsync(
                assertion.AuthObject, policySession, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, assertion.PolicyRef, assertion.Expiration,
                signature.AsReadOnlyMemory(), assertion.SignatureScheme, assertion.SchemeHashAlg, cancellationToken).ConfigureAwait(false);
            if(!result.IsSuccess)
            {
                return ToFailure(result);
            }

            result.Value.Dispose();

            return null;
        }

        /// <summary>Replays a TPM2_PolicyAuthorize assertion; <see langword="null"/> on success.</summary>
        static async ValueTask<TpmResult<uint>?> StepAuthorizeAsync(TpmDevice device, uint policySession, AuthorizePolicyAssertion assertion, CancellationToken cancellationToken)
        {
            TpmResult<PolicyAuthorizeResponse> result = await device.PolicyAuthorizeAsync(
                policySession, assertion.ApprovedPolicy, assertion.PolicyRef, assertion.KeySign, assertion.CheckTicket, cancellationToken).ConfigureAwait(false);

            return result.IsSuccess ? null : ToFailure(result);
        }

        /// <summary>Replays a TPM2_PolicyPassword assertion; <see langword="null"/> on success.</summary>
        static async ValueTask<TpmResult<uint>?> StepPasswordAsync(TpmDevice device, uint policySession, CancellationToken cancellationToken)
        {
            TpmResult<PolicyPasswordResponse> result = await device.PolicyPasswordAsync(policySession, cancellationToken).ConfigureAwait(false);

            return result.IsSuccess ? null : ToFailure(result);
        }

        /// <summary>Replays a TPM2_PolicyCpHash assertion; <see langword="null"/> on success.</summary>
        static async ValueTask<TpmResult<uint>?> StepCpHashAsync(TpmDevice device, uint policySession, CpHashPolicyAssertion assertion, CancellationToken cancellationToken)
        {
            TpmResult<PolicyCpHashResponse> result = await device.PolicyCpHashAsync(policySession, assertion.CpHashA, cancellationToken).ConfigureAwait(false);

            return result.IsSuccess ? null : ToFailure(result);
        }

        /// <summary>Replays a TPM2_PolicyNameHash assertion; <see langword="null"/> on success.</summary>
        static async ValueTask<TpmResult<uint>?> StepNameHashAsync(TpmDevice device, uint policySession, NameHashPolicyAssertion assertion, CancellationToken cancellationToken)
        {
            TpmResult<PolicyNameHashResponse> result = await device.PolicyNameHashAsync(policySession, assertion.NameHash, cancellationToken).ConfigureAwait(false);

            return result.IsSuccess ? null : ToFailure(result);
        }

        /// <summary>Replays a TPM2_PolicyDuplicationSelect assertion; <see langword="null"/> on success.</summary>
        static async ValueTask<TpmResult<uint>?> StepDuplicationSelectAsync(TpmDevice device, uint policySession, DuplicationSelectPolicyAssertion assertion, CancellationToken cancellationToken)
        {
            TpmResult<PolicyDuplicationSelectResponse> result = await device.PolicyDuplicationSelectAsync(
                policySession, assertion.ObjectName, assertion.NewParentName, assertion.IsObjectIncluded, cancellationToken).ConfigureAwait(false);

            return result.IsSuccess ? null : ToFailure(result);
        }

        /// <summary>Replays a TPM2_PolicyParameters assertion; <see langword="null"/> on success.</summary>
        static async ValueTask<TpmResult<uint>?> StepParametersAsync(TpmDevice device, uint policySession, ParametersPolicyAssertion assertion, CancellationToken cancellationToken)
        {
            TpmResult<PolicyParametersResponse> result = await device.PolicyParametersAsync(policySession, assertion.ParametersHash, cancellationToken).ConfigureAwait(false);

            return result.IsSuccess ? null : ToFailure(result);
        }

        /// <summary>Replays a TPM2_PolicyTemplate assertion; <see langword="null"/> on success.</summary>
        static async ValueTask<TpmResult<uint>?> StepTemplateAsync(TpmDevice device, uint policySession, TemplatePolicyAssertion assertion, CancellationToken cancellationToken)
        {
            TpmResult<PolicyTemplateResponse> result = await device.PolicyTemplateAsync(policySession, assertion.TemplateHash, cancellationToken).ConfigureAwait(false);

            return result.IsSuccess ? null : ToFailure(result);
        }

        /// <summary>Replays a TPM2_PolicyLocality assertion; <see langword="null"/> on success.</summary>
        static async ValueTask<TpmResult<uint>?> StepLocalityAsync(TpmDevice device, uint policySession, LocalityPolicyAssertion assertion, CancellationToken cancellationToken)
        {
            TpmResult<PolicyLocalityResponse> result = await device.PolicyLocalityAsync(policySession, assertion.Locality, cancellationToken).ConfigureAwait(false);

            return result.IsSuccess ? null : ToFailure(result);
        }

        /// <summary>Replays a TPM2_PolicyNvWritten assertion; <see langword="null"/> on success.</summary>
        static async ValueTask<TpmResult<uint>?> StepNvWrittenAsync(TpmDevice device, uint policySession, NvWrittenPolicyAssertion assertion, CancellationToken cancellationToken)
        {
            TpmResult<PolicyNvWrittenResponse> result = await device.PolicyNvWrittenAsync(policySession, assertion.IsWrittenSet, cancellationToken).ConfigureAwait(false);

            return result.IsSuccess ? null : ToFailure(result);
        }

        /// <summary>Replays a TPM2_PolicyAuthorizeNV assertion; <see langword="null"/> on success.</summary>
        static async ValueTask<TpmResult<uint>?> StepAuthorizeNvAsync(TpmDevice device, uint policySession, AuthorizeNvPolicyAssertion assertion, CancellationToken cancellationToken)
        {
            TpmResult<PolicyAuthorizeNvResponse> result = await device.PolicyAuthorizeNvAsync(assertion.AuthHandle, assertion.NvIndex, policySession, cancellationToken).ConfigureAwait(false);

            return result.IsSuccess ? null : ToFailure(result);
        }

        /// <summary>Maps a scheme hash algorithm to the digest tag its <see cref="DigestValue"/> carries.</summary>
        static Tag DigestTagFor(TpmAlgIdConstants schemeHashAlg) => schemeHashAlg switch
        {
            TpmAlgIdConstants.TPM_ALG_SHA256 => CryptoTags.Sha256Digest,
            TpmAlgIdConstants.TPM_ALG_SHA384 => CryptoTags.Sha384Digest,
            TpmAlgIdConstants.TPM_ALG_SHA512 => CryptoTags.Sha512Digest,
            _ => throw new NotSupportedException($"Scheme hash algorithm '{schemeHashAlg}' is not supported.")
        };
    }

    /// <summary>
    /// Folds a PolicyPCR assertion into the running digest, marshaling its PCR selection.
    /// </summary>
    /// <param name="running">The running policyDigest (source and destination).</param>
    /// <param name="assertion">The PCR assertion.</param>
    /// <param name="policyHash">The session's policy hash algorithm.</param>
    /// <param name="pool">The memory pool the marshaled selection scratch and the fold's hash-input scratch buffer are rented from.</param>
    /// <returns>The number of digest bytes written.</returns>
    private static int ExtendPcr(Span<byte> running, PcrPolicyAssertion assertion, TpmAlgIdConstants policyHash, BaseMemoryPool pool)
    {
        using TpmlPcrSelection selection = TpmlPcrSelection.Create(assertion.PcrBank, assertion.PcrIndices, pool);
        int selectionSize = selection.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(selectionSize);
        Span<byte> marshaled = owner.Memory.Span[..selectionSize];
        var writer = new TpmWriter(marshaled);
        selection.WriteTo(ref writer);

        return TpmPolicyDigest.ExtendForPcr(running, marshaled, assertion.PcrDigest.Span, policyHash, running, pool);
    }

    /// <summary>
    /// Builds TPM2_PolicySigned's <c>aHash = H_schemeHashAlg(nonceTPM || expiration || cpHashA || policyRef)</c>
    /// for a <see cref="SignedPolicyAssertion"/>'s replay into a caller-provided (pooled) destination. This
    /// builder always replays with an empty caller nonceTPM and an empty cpHashA (a session-unbound,
    /// command-unbound authorization), so the formula collapses to <c>H(expiration || policyRef)</c> — the
    /// nonceTPM and cpHashA terms contribute no bytes. A pure, synchronous computation with no TPM I/O, so it
    /// hashes directly rather than through the async digest seam (mirrors <see cref="TpmPolicyDigest"/>'s own
    /// host-side prediction).
    /// </summary>
    /// <param name="expiration">The signed expiration.</param>
    /// <param name="policyRef">The policy qualifier.</param>
    /// <param name="schemeHashAlg">H_authAlg: the hash algorithm carried inside the signature.</param>
    /// <param name="destination">Receives the <c>aHash</c>; must be at least <see cref="TpmPolicyDigest.Size"/> bytes for the algorithm.</param>
    /// <param name="pool">The memory pool for the message scratch buffer.</param>
    /// <returns>The number of digest bytes written.</returns>
    private static int BuildPolicySignedAHash(int expiration, ReadOnlySpan<byte> policyRef, TpmAlgIdConstants schemeHashAlg, Span<byte> destination, BaseMemoryPool pool)
    {
        int length = sizeof(int) + policyRef.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Span<byte> message = owner.Memory.Span[..length];
        var writer = new TpmWriter(message);
        writer.WriteInt32(expiration);
        writer.WriteBytes(policyRef);

        return schemeHashAlg switch
        {
            TpmAlgIdConstants.TPM_ALG_SHA256 => SHA256.HashData(message, destination),
            TpmAlgIdConstants.TPM_ALG_SHA384 => SHA384.HashData(message, destination),
            TpmAlgIdConstants.TPM_ALG_SHA512 => SHA512.HashData(message, destination),
            _ => throw new NotSupportedException($"Scheme hash algorithm '{schemeHashAlg}' is not supported.")
        };
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
