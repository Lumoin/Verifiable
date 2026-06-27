using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Host-side computation of TPM policy digests, so an application can predict the policyDigest a sequence of
/// policy assertions produces — for example to bind it to an object's authPolicy at create time — and compare
/// it against the value a trial session reports via TPM2_PolicyGetDigest.
/// </summary>
/// <remarks>
/// <para>
/// A policy session starts with a policyDigest of <see cref="Size"/> zero bytes; each policy assertion extends
/// it. See TPM 2.0 Part 3, Section 23. The hash inputs are assembled in <see cref="BaseMemoryPool"/> buffers
/// that are cleared before release, so the library keeps a uniform containment story for transient material.
/// </para>
/// <para>
/// <b>Debugging a predictor against the TPM.</b> Each <c>Extend*</c> method here mirrors the TPM's
/// <c>PolicyContextUpdate</c> exactly, so a fresh session driven by the matching <c>TpmDevice</c> policy call
/// must report (via TPM2_PolicyGetDigest) the same value this computes. The TPM's value is authoritative; when a
/// prediction disagrees, verify the formula one hash stage at a time against the documented inputs — for example
/// <c>SHA256(zeros || TPM_CC_PolicySecret || authName)</c> then <c>SHA256(that || policyRef)</c> — comparing each
/// intermediate digest (a one-liner: <c>[Convert]::ToHexString([SHA256]::HashData([Convert]::FromHexString(...)))</c>
/// in PowerShell) until the stage that diverges is found. This is how the PolicySecret two-hash behaviour below
/// was pinned down.
/// </para>
/// </remarks>
public static class TpmPolicyDigest
{
    /// <summary>
    /// Gets the policyDigest size in bytes for a policy hash algorithm.
    /// </summary>
    /// <param name="policyHashAlgorithm">The session's policy hash algorithm.</param>
    /// <returns>The digest size in bytes.</returns>
    /// <exception cref="NotSupportedException">Thrown when the hash algorithm is not supported.</exception>
    public static int Size(TpmAlgIdConstants policyHashAlgorithm) => policyHashAlgorithm switch
    {
        TpmAlgIdConstants.TPM_ALG_SHA1 => 20,
        TpmAlgIdConstants.TPM_ALG_SHA256 => 32,
        TpmAlgIdConstants.TPM_ALG_SHA384 => 48,
        TpmAlgIdConstants.TPM_ALG_SHA512 => 64,
        _ => throw new NotSupportedException($"Policy hash algorithm '{policyHashAlgorithm}' is not supported.")
    };

    /// <summary>
    /// Extends a policyDigest for TPM2_PolicyCommandCode:
    /// <c>policyDigestnew = H(policyDigestold || TPM_CC_PolicyCommandCode || code)</c>.
    /// </summary>
    /// <param name="current">The current policyDigest (<see cref="Size"/> bytes; all zero for a fresh session).</param>
    /// <param name="restrictedCommand">The command code the policy is restricted to.</param>
    /// <param name="policyHashAlgorithm">The session's policy hash algorithm.</param>
    /// <param name="destination">Receives the new policyDigest; must be at least <see cref="Size"/> bytes.</param>
    /// <returns>The number of digest bytes written.</returns>
    public static int ExtendForCommandCode(
        ReadOnlySpan<byte> current,
        TpmCcConstants restrictedCommand,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination)
    {
        //H( current || TPM_CC_PolicyCommandCode || code ).
        int length = current.Length + sizeof(uint) + sizeof(uint);
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Span<byte> buffer = owner.Memory.Span;
        current.CopyTo(buffer);
        BinaryPrimitives.WriteUInt32BigEndian(buffer[current.Length..], (uint)TpmCcConstants.TPM_CC_PolicyCommandCode);
        BinaryPrimitives.WriteUInt32BigEndian(buffer[(current.Length + sizeof(uint))..], (uint)restrictedCommand);

        int written = Hash(buffer, policyHashAlgorithm, destination);
        buffer.Clear();

        return written;
    }

    /// <summary>
    /// Extends a policyDigest for TPM2_PolicyAuthValue:
    /// <c>policyDigestnew = H(policyDigestold || TPM_CC_PolicyAuthValue)</c>.
    /// </summary>
    /// <remarks>
    /// TPM2_PolicyPassword extends the digest with the same command code (TPM_CC_PolicyAuthValue), so a single
    /// policy works whether the object is later authorized with an HMAC over its authValue or with a password.
    /// </remarks>
    /// <param name="current">The current policyDigest (<see cref="Size"/> bytes; all zero for a fresh session).</param>
    /// <param name="policyHashAlgorithm">The session's policy hash algorithm.</param>
    /// <param name="destination">Receives the new policyDigest; must be at least <see cref="Size"/> bytes.</param>
    /// <returns>The number of digest bytes written.</returns>
    public static int ExtendForAuthValue(
        ReadOnlySpan<byte> current,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination)
    {
        //H( current || TPM_CC_PolicyAuthValue ).
        int length = current.Length + sizeof(uint);
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Span<byte> buffer = owner.Memory.Span;
        current.CopyTo(buffer);
        BinaryPrimitives.WriteUInt32BigEndian(buffer[current.Length..], (uint)TpmCcConstants.TPM_CC_PolicyAuthValue);

        int written = Hash(buffer, policyHashAlgorithm, destination);
        buffer.Clear();

        return written;
    }

    /// <summary>
    /// Extends a policyDigest for TPM2_PolicyPCR:
    /// <c>policyDigestnew = H(policyDigestold || TPM_CC_PolicyPCR || pcrs || pcrDigest)</c>.
    /// </summary>
    /// <param name="current">The current policyDigest (<see cref="Size"/> bytes; all zero for a fresh session).</param>
    /// <param name="marshaledPcrs">The marshaled TPML_PCR_SELECTION, exactly as sent in the command.</param>
    /// <param name="pcrDigest">The digest of the selected PCR values that the policy binds to.</param>
    /// <param name="policyHashAlgorithm">The session's policy hash algorithm.</param>
    /// <param name="destination">Receives the new policyDigest; must be at least <see cref="Size"/> bytes.</param>
    /// <returns>The number of digest bytes written.</returns>
    public static int ExtendForPcr(
        ReadOnlySpan<byte> current,
        ReadOnlySpan<byte> marshaledPcrs,
        ReadOnlySpan<byte> pcrDigest,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination)
    {
        //H( current || TPM_CC_PolicyPCR || pcrs || pcrDigest ).
        int length = current.Length + sizeof(uint) + marshaledPcrs.Length + pcrDigest.Length;
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Span<byte> buffer = owner.Memory.Span;
        int offset = 0;
        current.CopyTo(buffer);
        offset += current.Length;
        BinaryPrimitives.WriteUInt32BigEndian(buffer[offset..], (uint)TpmCcConstants.TPM_CC_PolicyPCR);
        offset += sizeof(uint);
        marshaledPcrs.CopyTo(buffer[offset..]);
        offset += marshaledPcrs.Length;
        pcrDigest.CopyTo(buffer[offset..]);

        int written = Hash(buffer, policyHashAlgorithm, destination);
        buffer.Clear();

        return written;
    }

    /// <summary>
    /// Extends a policyDigest for TPM2_PolicySecret:
    /// <c>policyDigestnew = H(policyDigestold || TPM_CC_PolicySecret || authName)</c> followed by
    /// <c>policyDigest = H(policyDigestnew || policyRef)</c> (TPM 2.0 Part 4, <c>PolicyContextUpdate</c>).
    /// </summary>
    /// <remarks>
    /// Unlike TPM2_PolicyCommandCode, PolicySecret (like PolicySigned) <b>always</b> applies the second
    /// <c>policyRef</c> hash, even when <paramref name="policyRef"/> is empty — the policyRef is part of the
    /// command's policy update. For <c>authName</c> = the 4-byte Name of TPM_RH_ENDORSEMENT and an empty
    /// <paramref name="policyRef"/>, this produces the well-known TCG endorsement-key authorization policy.
    /// </remarks>
    /// <param name="current">The current policyDigest (<see cref="Size"/> bytes; all zero for a fresh session).</param>
    /// <param name="authName">The Name of the authorizing entity (for a permanent handle, its 4-byte handle value).</param>
    /// <param name="policyRef">The policy qualifier; pass empty for none (the second hash still runs).</param>
    /// <param name="policyHashAlgorithm">The session's policy hash algorithm.</param>
    /// <param name="destination">Receives the new policyDigest; must be at least <see cref="Size"/> bytes.</param>
    /// <returns>The number of digest bytes written.</returns>
    public static int ExtendForSecret(
        ReadOnlySpan<byte> current,
        ReadOnlySpan<byte> authName,
        ReadOnlySpan<byte> policyRef,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination)
    {
        //Step 1: H( current || TPM_CC_PolicySecret || authName ).
        int length = current.Length + sizeof(uint) + authName.Length;
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Span<byte> buffer = owner.Memory.Span[..length];
        int offset = 0;
        current.CopyTo(buffer);
        offset += current.Length;
        BinaryPrimitives.WriteUInt32BigEndian(buffer[offset..], (uint)TpmCcConstants.TPM_CC_PolicySecret);
        offset += sizeof(uint);
        authName.CopyTo(buffer[offset..]);

        int written = Hash(buffer, policyHashAlgorithm, destination);
        buffer.Clear();

        //Step 2: H( policyDigest || policyRef ). This second hash ALWAYS runs for PolicySecret, even when
        //policyRef is empty, because PolicySecret (like PolicySigned) supplies a policyRef to PolicyContextUpdate
        //and the TPM hashes it unconditionally — unlike PolicyCommandCode, which has no policyRef and so stops at
        //one hash. Skipping it on an empty policyRef yields the wrong digest (it omits the EK policy's outer hash).
        int length2 = written + policyRef.Length;
        using IMemoryOwner<byte> owner2 = BaseMemoryPool.Shared.Rent(length2);
        Span<byte> buffer2 = owner2.Memory.Span[..length2];
        destination[..written].CopyTo(buffer2);
        policyRef.CopyTo(buffer2[written..]);

        int written2 = Hash(buffer2, policyHashAlgorithm, destination);
        buffer2.Clear();

        return written2;
    }

    /// <summary>
    /// Computes the policyDigest for TPM2_PolicyOR:
    /// <c>policyDigest = H(0...0 || TPM_CC_PolicyOR || branchDigest0 || branchDigest1 || ...)</c>.
    /// </summary>
    /// <remarks>
    /// PolicyOR resets the policyDigest to zeros before hashing, so the result depends only on the branch set,
    /// not on the session's prior digest (which only has to match one branch for the assertion to be authorized).
    /// The branch digests are concatenated as their raw bytes, with no length prefixes.
    /// </remarks>
    /// <param name="branchDigests">The OR branch policy digests, each <see cref="Size"/> bytes.</param>
    /// <param name="policyHashAlgorithm">The session's policy hash algorithm.</param>
    /// <param name="destination">Receives the new policyDigest; must be at least <see cref="Size"/> bytes.</param>
    /// <returns>The number of digest bytes written.</returns>
    public static int ExtendForOr(
        System.Collections.Generic.IReadOnlyList<ReadOnlyMemory<byte>> branchDigests,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(branchDigests);
        int size = Size(policyHashAlgorithm);

        int branchesLength = 0;
        for(int i = 0; i < branchDigests.Count; i++)
        {
            branchesLength += branchDigests[i].Length;
        }

        //H( zeros(size) || TPM_CC_PolicyOR || branch0 || branch1 || ... ).
        int length = size + sizeof(uint) + branchesLength;
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Span<byte> buffer = owner.Memory.Span[..length];
        buffer[..size].Clear();
        BinaryPrimitives.WriteUInt32BigEndian(buffer[size..], (uint)TpmCcConstants.TPM_CC_PolicyOR);

        int offset = size + sizeof(uint);
        for(int i = 0; i < branchDigests.Count; i++)
        {
            branchDigests[i].Span.CopyTo(buffer[offset..]);
            offset += branchDigests[i].Length;
        }

        int written = Hash(buffer, policyHashAlgorithm, destination);
        buffer.Clear();

        return written;
    }

    /// <summary>
    /// Extends a policyDigest for TPM2_PolicyNV:
    /// <c>argHash = H(operandB || offset || operation)</c>, then
    /// <c>policyDigest = H(policyDigestold || TPM_CC_PolicyNV || argHash || nvName)</c> (TPM 2.0 Part 4,
    /// <c>PolicyNV</c>).
    /// </summary>
    /// <remarks>
    /// <paramref name="nvName"/> is the NV Index's Name (<c>nameAlg || H(TPMS_NV_PUBLIC)</c>); because the public
    /// area includes the attributes, the Name reflects TPMA_NV_WRITTEN once the Index has been written.
    /// </remarks>
    /// <param name="current">The current policyDigest (<see cref="Size"/> bytes; all zero for a fresh session).</param>
    /// <param name="operandB">The comparison operand.</param>
    /// <param name="offset">The octet offset into the NV data.</param>
    /// <param name="operation">The TPM_EO comparison operation value.</param>
    /// <param name="nvName">The NV Index's Name.</param>
    /// <param name="policyHashAlgorithm">The session's policy hash algorithm.</param>
    /// <param name="destination">Receives the new policyDigest; must be at least <see cref="Size"/> bytes.</param>
    /// <returns>The number of digest bytes written.</returns>
    public static int ExtendForNv(
        ReadOnlySpan<byte> current,
        ReadOnlySpan<byte> operandB,
        ushort offset,
        ushort operation,
        ReadOnlySpan<byte> nvName,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination)
    {
        int size = Size(policyHashAlgorithm);

        //argHash = H( operandB || offset || operation ).
        int argLength = operandB.Length + sizeof(ushort) + sizeof(ushort);
        using IMemoryOwner<byte> argOwner = BaseMemoryPool.Shared.Rent(argLength);
        Span<byte> argBuffer = argOwner.Memory.Span[..argLength];
        operandB.CopyTo(argBuffer);
        BinaryPrimitives.WriteUInt16BigEndian(argBuffer[operandB.Length..], offset);
        BinaryPrimitives.WriteUInt16BigEndian(argBuffer[(operandB.Length + sizeof(ushort))..], operation);

        Span<byte> argHash = stackalloc byte[size];
        _ = Hash(argBuffer, policyHashAlgorithm, argHash);
        argBuffer.Clear();

        //policyDigest = H( current || TPM_CC_PolicyNV || argHash || nvName ).
        int length = current.Length + sizeof(uint) + size + nvName.Length;
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Span<byte> buffer = owner.Memory.Span[..length];
        int bufferOffset = 0;
        current.CopyTo(buffer);
        bufferOffset += current.Length;
        BinaryPrimitives.WriteUInt32BigEndian(buffer[bufferOffset..], (uint)TpmCcConstants.TPM_CC_PolicyNV);
        bufferOffset += sizeof(uint);
        argHash.CopyTo(buffer[bufferOffset..]);
        bufferOffset += size;
        nvName.CopyTo(buffer[bufferOffset..]);

        int written = Hash(buffer, policyHashAlgorithm, destination);
        buffer.Clear();

        return written;
    }

    /// <summary>
    /// Hashes <paramref name="data"/> into <paramref name="destination"/> with the policy hash algorithm.
    /// </summary>
    /// <param name="data">The bytes to hash.</param>
    /// <param name="policyHashAlgorithm">The policy hash algorithm.</param>
    /// <param name="destination">The buffer that receives the digest.</param>
    /// <returns>The number of digest bytes written.</returns>
    private static int Hash(ReadOnlySpan<byte> data, TpmAlgIdConstants policyHashAlgorithm, Span<byte> destination) => policyHashAlgorithm switch
    {
        TpmAlgIdConstants.TPM_ALG_SHA256 => SHA256.HashData(data, destination),
        TpmAlgIdConstants.TPM_ALG_SHA384 => SHA384.HashData(data, destination),
        TpmAlgIdConstants.TPM_ALG_SHA512 => SHA512.HashData(data, destination),
        _ => throw new NotSupportedException($"Policy hash algorithm '{policyHashAlgorithm}' is not supported.")
    };
}
