using System;
using System.Buffers;
using System.Buffers.Binary;
using Verifiable.Cryptography;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Host-side computation of TPM policy digests, so an application can predict the policyDigest a sequence of
/// policy assertions produces — for example to bind it to an object's authPolicy at create time — and compare
/// it against the value a trial session reports via TPM2_PolicyGetDigest.
/// </summary>
/// <remarks>
/// <para>
/// A policy session starts with a policyDigest of <see cref="Size"/> zero bytes; each policy assertion extends
/// it. See TPM 2.0 Library Part 3, clause 23. The hash inputs are assembled in <see cref="BaseMemoryPool"/> buffers
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
    /// <param name="pool">The memory pool the fold's hash-input scratch buffer is rented from.</param>
    /// <returns>The number of digest bytes written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public static int ExtendForCommandCode(
        ReadOnlySpan<byte> current,
        TpmCcConstants restrictedCommand,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //H( current || TPM_CC_PolicyCommandCode || code ).
        int length = current.Length + sizeof(uint) + sizeof(uint);
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Span<byte> buffer = owner.Memory.Span;
        current.CopyTo(buffer);
        BinaryPrimitives.WriteUInt32BigEndian(buffer[current.Length..], (uint)TpmCcConstants.TPM_CC_PolicyCommandCode);
        BinaryPrimitives.WriteUInt32BigEndian(buffer[(current.Length + sizeof(uint))..], (uint)restrictedCommand);

        int written = Hash(buffer, policyHashAlgorithm, destination, pool);
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
    /// <param name="pool">The memory pool the fold's hash-input scratch buffer is rented from.</param>
    /// <returns>The number of digest bytes written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public static int ExtendForAuthValue(
        ReadOnlySpan<byte> current,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //H( current || TPM_CC_PolicyAuthValue ).
        int length = current.Length + sizeof(uint);
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Span<byte> buffer = owner.Memory.Span;
        current.CopyTo(buffer);
        BinaryPrimitives.WriteUInt32BigEndian(buffer[current.Length..], (uint)TpmCcConstants.TPM_CC_PolicyAuthValue);

        int written = Hash(buffer, policyHashAlgorithm, destination, pool);
        buffer.Clear();

        return written;
    }

    /// <summary>
    /// Extends a policyDigest for TPM2_PolicyPCR:
    /// <c>policyDigestnew = H(policyDigestold || TPM_CC_PolicyPCR || pcrs || pcrDigest)</c>.
    /// </summary>
    /// <param name="current">The current policyDigest (<see cref="Size"/> bytes; all zero for a fresh session).</param>
    /// <param name="marshaledPcrs">The marshaled TPML_PCR_SELECTION as the TPM folds it (Part 3, clause 23.7): predicting a trial-session digest, the selection exactly as sent; predicting a real-session digest, the target TPM's modified value, with bits corresponding to PCR that TPM does not implement cleared.</param>
    /// <param name="pcrDigest">The digest of the selected PCR values that the policy binds to.</param>
    /// <param name="policyHashAlgorithm">The session's policy hash algorithm.</param>
    /// <param name="destination">Receives the new policyDigest; must be at least <see cref="Size"/> bytes.</param>
    /// <param name="pool">The memory pool the fold's hash-input scratch buffer is rented from.</param>
    /// <returns>The number of digest bytes written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public static int ExtendForPcr(
        ReadOnlySpan<byte> current,
        ReadOnlySpan<byte> marshaledPcrs,
        ReadOnlySpan<byte> pcrDigest,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //H( current || TPM_CC_PolicyPCR || pcrs || pcrDigest ).
        int length = current.Length + sizeof(uint) + marshaledPcrs.Length + pcrDigest.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Span<byte> buffer = owner.Memory.Span;
        int offset = 0;
        current.CopyTo(buffer);
        offset += current.Length;
        BinaryPrimitives.WriteUInt32BigEndian(buffer[offset..], (uint)TpmCcConstants.TPM_CC_PolicyPCR);
        offset += sizeof(uint);
        marshaledPcrs.CopyTo(buffer[offset..]);
        offset += marshaledPcrs.Length;
        pcrDigest.CopyTo(buffer[offset..]);

        int written = Hash(buffer, policyHashAlgorithm, destination, pool);
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
    /// <param name="pool">The memory pool the Step 1 and Step 2 hash-input scratch buffers are rented from.</param>
    /// <returns>The number of digest bytes written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public static int ExtendForSecret(
        ReadOnlySpan<byte> current,
        ReadOnlySpan<byte> authName,
        ReadOnlySpan<byte> policyRef,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //Step 1: H( current || TPM_CC_PolicySecret || authName ).
        int length = current.Length + sizeof(uint) + authName.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Span<byte> buffer = owner.Memory.Span[..length];
        int offset = 0;
        current.CopyTo(buffer);
        offset += current.Length;
        BinaryPrimitives.WriteUInt32BigEndian(buffer[offset..], (uint)TpmCcConstants.TPM_CC_PolicySecret);
        offset += sizeof(uint);
        authName.CopyTo(buffer[offset..]);

        int written = Hash(buffer, policyHashAlgorithm, destination, pool);
        buffer.Clear();

        //Step 2: H( policyDigest || policyRef ). This second hash ALWAYS runs for PolicySecret, even when
        //policyRef is empty, because PolicySecret (like PolicySigned) supplies a policyRef to PolicyContextUpdate
        //and the TPM hashes it unconditionally — unlike PolicyCommandCode, which has no policyRef and so stops at
        //one hash. Skipping it on an empty policyRef yields the wrong digest (it omits the EK policy's outer hash).
        int length2 = written + policyRef.Length;
        using IMemoryOwner<byte> owner2 = pool.Rent(length2);
        Span<byte> buffer2 = owner2.Memory.Span[..length2];
        destination[..written].CopyTo(buffer2);
        policyRef.CopyTo(buffer2[written..]);

        int written2 = Hash(buffer2, policyHashAlgorithm, destination, pool);
        buffer2.Clear();

        return written2;
    }

    /// <summary>
    /// Extends a policyDigest for TPM2_PolicySigned:
    /// <c>policyDigestnew = H(policyDigestold || TPM_CC_PolicySigned || authObjectName)</c> followed by
    /// <c>policyDigest = H(policyDigestnew || policyRef)</c> (TPM 2.0 Library Part 3, clause 23.3, equation 14;
    /// <c>PolicyContextUpdate</c>).
    /// </summary>
    /// <remarks>
    /// Mirrors <see cref="ExtendForSecret"/> exactly, folding <see cref="TpmCcConstants.TPM_CC_PolicySigned"/>
    /// instead of <see cref="TpmCcConstants.TPM_CC_PolicySecret"/>: the second <paramref name="policyRef"/> hash
    /// <b>always</b> runs, even when <paramref name="policyRef"/> is empty, and this fold happens identically for
    /// trial and real (non-trial) sessions — a trial session predicts the same digest a real, signature-verified
    /// authorization would produce, without ever checking the signature itself.
    /// </remarks>
    /// <param name="current">The current policyDigest (<see cref="Size"/> bytes; all zero for a fresh session).</param>
    /// <param name="authName">The Name of the key that will validate (or, for a trial session, is merely claimed to validate) the signature.</param>
    /// <param name="policyRef">The policy qualifier; pass empty for none (the second hash still runs).</param>
    /// <param name="policyHashAlgorithm">The session's policy hash algorithm.</param>
    /// <param name="destination">Receives the new policyDigest; must be at least <see cref="Size"/> bytes.</param>
    /// <param name="pool">The memory pool the Step 1 and Step 2 hash-input scratch buffers are rented from.</param>
    /// <returns>The number of digest bytes written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public static int ExtendForSigned(
        ReadOnlySpan<byte> current,
        ReadOnlySpan<byte> authName,
        ReadOnlySpan<byte> policyRef,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //Step 1: H( current || TPM_CC_PolicySigned || authName ).
        int length = current.Length + sizeof(uint) + authName.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Span<byte> buffer = owner.Memory.Span[..length];
        int offset = 0;
        current.CopyTo(buffer);
        offset += current.Length;
        BinaryPrimitives.WriteUInt32BigEndian(buffer[offset..], (uint)TpmCcConstants.TPM_CC_PolicySigned);
        offset += sizeof(uint);
        authName.CopyTo(buffer[offset..]);

        int written = Hash(buffer, policyHashAlgorithm, destination, pool);
        buffer.Clear();

        //Step 2: H( policyDigest || policyRef ). Always runs, exactly like ExtendForSecret's second fold.
        int length2 = written + policyRef.Length;
        using IMemoryOwner<byte> owner2 = pool.Rent(length2);
        Span<byte> buffer2 = owner2.Memory.Span[..length2];
        destination[..written].CopyTo(buffer2);
        policyRef.CopyTo(buffer2[written..]);

        int written2 = Hash(buffer2, policyHashAlgorithm, destination, pool);
        buffer2.Clear();

        return written2;
    }

    /// <summary>
    /// Computes the policyDigest for TPM2_PolicyAuthorize:
    /// <c>policyDigestnew = H(0...0 || TPM_CC_PolicyAuthorize || keySignName)</c> followed by
    /// <c>policyDigest = H(policyDigestnew || policyRef)</c> (TPM 2.0 Library Part 3, clause 23.16, equation 35;
    /// <c>PolicyContextUpdate</c> composed with a <c>PolicyDigestClear</c> reset that precedes it).
    /// </summary>
    /// <remarks>
    /// Combines <see cref="ExtendForOr"/>'s reset shape (the accumulated digest is <b>discarded</b>, never folded
    /// in — <paramref name="destination"/> starts from an all-zero digest of the session-hash width, exactly like
    /// <see cref="ExtendForOr"/> ignoring its own prior digest) with <see cref="ExtendForSecret"/>'s "always run a
    /// second <paramref name="policyRef"/> hash" shape. This reset is the mechanism that lets an object's fixed
    /// authPolicy accept a policy an authority can revise at will: the result depends only on
    /// <paramref name="keySignName"/> and <paramref name="policyRef"/>, never on whatever policy actually produced
    /// the approved digest TPM2_PolicyAuthorize checked before this fold runs.
    /// </remarks>
    /// <param name="keySignName">The Name of the key that signed the approval.</param>
    /// <param name="policyRef">The policy qualifier; pass empty for none (the second hash still runs).</param>
    /// <param name="policyHashAlgorithm">The session's policy hash algorithm.</param>
    /// <param name="destination">Receives the new policyDigest; must be at least <see cref="Size"/> bytes.</param>
    /// <param name="pool">The memory pool the Step 1 and Step 2 hash-input scratch buffers are rented from.</param>
    /// <returns>The number of digest bytes written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public static int ExtendForAuthorize(
        ReadOnlySpan<byte> keySignName,
        ReadOnlySpan<byte> policyRef,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        int size = Size(policyHashAlgorithm);

        //Step 1: H( zeros(size) || TPM_CC_PolicyAuthorize || keySignName ). The digest is RESET to zero first
        //(PolicyDigestClear) — the accumulated policyDigest is never folded in, unlike ExtendForSigned/ExtendForSecret.
        int length = size + sizeof(uint) + keySignName.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Span<byte> buffer = owner.Memory.Span[..length];
        buffer[..size].Clear();
        BinaryPrimitives.WriteUInt32BigEndian(buffer[size..], (uint)TpmCcConstants.TPM_CC_PolicyAuthorize);
        keySignName.CopyTo(buffer[(size + sizeof(uint))..]);

        int written = Hash(buffer, policyHashAlgorithm, destination, pool);
        buffer.Clear();

        //Step 2: H( policyDigest || policyRef ). Always runs, exactly like ExtendForSecret/ExtendForSigned's second fold.
        int length2 = written + policyRef.Length;
        using IMemoryOwner<byte> owner2 = pool.Rent(length2);
        Span<byte> buffer2 = owner2.Memory.Span[..length2];
        destination[..written].CopyTo(buffer2);
        policyRef.CopyTo(buffer2[written..]);

        int written2 = Hash(buffer2, policyHashAlgorithm, destination, pool);
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
    /// <param name="pool">The memory pool the branch-concatenation scratch buffer is rented from.</param>
    /// <returns>The number of digest bytes written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="branchDigests"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static int ExtendForOr(
        System.Collections.Generic.IReadOnlyList<ReadOnlyMemory<byte>> branchDigests,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(branchDigests);
        ArgumentNullException.ThrowIfNull(pool);
        int size = Size(policyHashAlgorithm);

        int branchesLength = 0;
        for(int i = 0; i < branchDigests.Count; i++)
        {
            branchesLength += branchDigests[i].Length;
        }

        //H( zeros(size) || TPM_CC_PolicyOR || branch0 || branch1 || ... ).
        int length = size + sizeof(uint) + branchesLength;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Span<byte> buffer = owner.Memory.Span[..length];
        buffer[..size].Clear();
        BinaryPrimitives.WriteUInt32BigEndian(buffer[size..], (uint)TpmCcConstants.TPM_CC_PolicyOR);

        int offset = size + sizeof(uint);
        for(int i = 0; i < branchDigests.Count; i++)
        {
            branchDigests[i].Span.CopyTo(buffer[offset..]);
            offset += branchDigests[i].Length;
        }

        int written = Hash(buffer, policyHashAlgorithm, destination, pool);
        buffer.Clear();

        return written;
    }

    /// <summary>
    /// Computes the policyDigest for TPM2_PolicyOR over the branch list in the <c>TPML_DIGEST</c> the command
    /// carries on the wire (TPM 2.0 Library Part 2, clause 10.8.5, Table 126):
    /// <c>policyDigest = H(0...0 || TPM_CC_PolicyOR || branchDigest0 || branchDigest1 || ...)</c>.
    /// </summary>
    /// <remarks>
    /// The formula is <see cref="ExtendForOr(System.Collections.Generic.IReadOnlyList{ReadOnlyMemory{byte}}, TpmAlgIdConstants, Span{byte}, BaseMemoryPool)"/>'s
    /// exactly; only the carrier of the branch set differs, so a caller holding the parsed structure folds it
    /// without projecting it onto a list first. The concatenation scratch comes from the caller's own pool, so
    /// the whole fold is observable on the pool the command was dispatched under.
    /// </remarks>
    /// <param name="branchDigests">The OR branch policy digests, each <see cref="Size"/> bytes.</param>
    /// <param name="policyHashAlgorithm">The session's policy hash algorithm.</param>
    /// <param name="destination">Receives the new policyDigest; must be at least <see cref="Size"/> bytes.</param>
    /// <param name="pool">The memory pool the concatenation scratch is rented from.</param>
    /// <returns>The number of digest bytes written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="branchDigests"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static int ExtendForOr(
        TpmlDigest branchDigests,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(branchDigests);
        ArgumentNullException.ThrowIfNull(pool);
        int size = Size(policyHashAlgorithm);

        int branchesLength = 0;
        for(int i = 0; i < branchDigests.Count; i++)
        {
            branchesLength += branchDigests[i].Size;
        }

        //H( zeros(size) || TPM_CC_PolicyOR || branch0 || branch1 || ... ).
        int length = size + sizeof(uint) + branchesLength;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Span<byte> buffer = owner.Memory.Span[..length];
        buffer[..size].Clear();
        BinaryPrimitives.WriteUInt32BigEndian(buffer[size..], (uint)TpmCcConstants.TPM_CC_PolicyOR);

        int offset = size + sizeof(uint);
        for(int i = 0; i < branchDigests.Count; i++)
        {
            branchDigests[i].AsReadOnlySpan().CopyTo(buffer[offset..]);
            offset += branchDigests[i].Size;
        }

        int written = Hash(buffer, policyHashAlgorithm, destination, pool);
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
    /// <param name="pool">The memory pool the argHash and outer-fold scratch buffers are rented from.</param>
    /// <returns>The number of digest bytes written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public static int ExtendForNv(
        ReadOnlySpan<byte> current,
        ReadOnlySpan<byte> operandB,
        ushort offset,
        ushort operation,
        ReadOnlySpan<byte> nvName,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        int size = Size(policyHashAlgorithm);

        //argHash = H( operandB || offset || operation ).
        int argLength = operandB.Length + sizeof(ushort) + sizeof(ushort);
        using IMemoryOwner<byte> argOwner = pool.Rent(argLength);
        Span<byte> argBuffer = argOwner.Memory.Span[..argLength];
        operandB.CopyTo(argBuffer);
        BinaryPrimitives.WriteUInt16BigEndian(argBuffer[operandB.Length..], offset);
        BinaryPrimitives.WriteUInt16BigEndian(argBuffer[(operandB.Length + sizeof(ushort))..], operation);

        Span<byte> argHash = stackalloc byte[size];
        _ = Hash(argBuffer, policyHashAlgorithm, argHash, pool);
        argBuffer.Clear();

        //policyDigest = H( current || TPM_CC_PolicyNV || argHash || nvName ).
        int length = current.Length + sizeof(uint) + size + nvName.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Span<byte> buffer = owner.Memory.Span[..length];
        int bufferOffset = 0;
        current.CopyTo(buffer);
        bufferOffset += current.Length;
        BinaryPrimitives.WriteUInt32BigEndian(buffer[bufferOffset..], (uint)TpmCcConstants.TPM_CC_PolicyNV);
        bufferOffset += sizeof(uint);
        argHash.CopyTo(buffer[bufferOffset..]);
        bufferOffset += size;
        nvName.CopyTo(buffer[bufferOffset..]);

        int written = Hash(buffer, policyHashAlgorithm, destination, pool);
        buffer.Clear();

        return written;
    }

    /// <summary>
    /// Extends a policyDigest for TPM2_PolicyCounterTimer:
    /// <c>argHash = H(operandB || offset || operation)</c>, then
    /// <c>policyDigest = H(policyDigestold || TPM_CC_PolicyCounterTimer || argHash)</c> (TPM 2.0 Part 3,
    /// clause 23.10).
    /// </summary>
    /// <remarks>
    /// The same argHash shape as <see cref="ExtendForNv"/>, one fold shallower: PolicyCounterTimer has no named
    /// entity to bind (the compared value is the TPM's own live time state, not an NV Index), so the outer fold
    /// carries no trailing Name term.
    /// </remarks>
    /// <param name="current">The current policyDigest (<see cref="Size"/> bytes; all zero for a fresh session).</param>
    /// <param name="operandB">The comparison operand.</param>
    /// <param name="offset">The octet offset into the marshaled TPMS_TIME_INFO.</param>
    /// <param name="operation">The TPM_EO comparison operation value.</param>
    /// <param name="policyHashAlgorithm">The session's policy hash algorithm.</param>
    /// <param name="destination">Receives the new policyDigest; must be at least <see cref="Size"/> bytes.</param>
    /// <param name="pool">The memory pool the argHash and outer-fold scratch buffers are rented from.</param>
    /// <returns>The number of digest bytes written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public static int ExtendForCounterTimer(
        ReadOnlySpan<byte> current,
        ReadOnlySpan<byte> operandB,
        ushort offset,
        ushort operation,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        int size = Size(policyHashAlgorithm);

        //argHash = H( operandB || offset || operation ).
        int argLength = operandB.Length + sizeof(ushort) + sizeof(ushort);
        using IMemoryOwner<byte> argOwner = pool.Rent(argLength);
        Span<byte> argBuffer = argOwner.Memory.Span[..argLength];
        operandB.CopyTo(argBuffer);
        BinaryPrimitives.WriteUInt16BigEndian(argBuffer[operandB.Length..], offset);
        BinaryPrimitives.WriteUInt16BigEndian(argBuffer[(operandB.Length + sizeof(ushort))..], operation);

        Span<byte> argHash = stackalloc byte[size];
        _ = Hash(argBuffer, policyHashAlgorithm, argHash, pool);
        argBuffer.Clear();

        //policyDigest = H( current || TPM_CC_PolicyCounterTimer || argHash ).
        int length = current.Length + sizeof(uint) + size;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Span<byte> buffer = owner.Memory.Span[..length];
        int bufferOffset = 0;
        current.CopyTo(buffer);
        bufferOffset += current.Length;
        BinaryPrimitives.WriteUInt32BigEndian(buffer[bufferOffset..], (uint)TpmCcConstants.TPM_CC_PolicyCounterTimer);
        bufferOffset += sizeof(uint);
        argHash.CopyTo(buffer[bufferOffset..]);

        int written = Hash(buffer, policyHashAlgorithm, destination, pool);
        buffer.Clear();

        return written;
    }

    /// <summary>
    /// Extends a policyDigest for TPM2_PolicyPassword:
    /// <c>policyDigestnew = H(policyDigestold || TPM_CC_PolicyAuthValue)</c>.
    /// </summary>
    /// <remarks>
    /// TPM2_PolicyPassword folds the SAME command code as <see cref="ExtendForAuthValue"/> — TPM_CC_PolicyAuthValue,
    /// not a code of its own (TPM 2.0 Library Part 3, clause 23.18: "the same extend value as used with
    /// TPM2_PolicyAuthValue()") — so a single authPolicy authorizes with either an HMAC over the object's
    /// authValue (TPM2_PolicyAuthValue) or the authValue itself presented as a cleartext password
    /// (TPM2_PolicyPassword); only the session's isPasswordNeeded/isAuthValueNeeded flags and the authorization
    /// wire shape differ between the two commands.
    /// </remarks>
    /// <param name="current">The current policyDigest (<see cref="Size"/> bytes; all zero for a fresh session).</param>
    /// <param name="policyHashAlgorithm">The session's policy hash algorithm.</param>
    /// <param name="destination">Receives the new policyDigest; must be at least <see cref="Size"/> bytes.</param>
    /// <param name="pool">The memory pool forwarded to <see cref="ExtendForAuthValue"/>'s fold scratch buffer.</param>
    /// <returns>The number of digest bytes written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public static int ExtendForPassword(
        ReadOnlySpan<byte> current,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination,
        BaseMemoryPool pool)
    {
        return ExtendForAuthValue(current, policyHashAlgorithm, destination, pool);
    }

    /// <summary>
    /// Extends a policyDigest for TPM2_PolicyCpHash:
    /// <c>policyDigestnew = H(policyDigestold || TPM_CC_PolicyCpHash || cpHashA)</c>.
    /// </summary>
    /// <param name="current">The current policyDigest (<see cref="Size"/> bytes; all zero for a fresh session).</param>
    /// <param name="cpHashA">The command parameter digest the policy binds to.</param>
    /// <param name="policyHashAlgorithm">The session's policy hash algorithm.</param>
    /// <param name="destination">Receives the new policyDigest; must be at least <see cref="Size"/> bytes.</param>
    /// <param name="pool">The memory pool the fold's hash-input scratch buffer is rented from.</param>
    /// <returns>The number of digest bytes written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public static int ExtendForCpHash(
        ReadOnlySpan<byte> current,
        ReadOnlySpan<byte> cpHashA,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //H( current || TPM_CC_PolicyCpHash || cpHashA ); no size prefix, the raw digest bytes are folded.
        int length = current.Length + sizeof(uint) + cpHashA.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Span<byte> buffer = owner.Memory.Span[..length];
        int offset = 0;
        current.CopyTo(buffer);
        offset += current.Length;
        BinaryPrimitives.WriteUInt32BigEndian(buffer[offset..], (uint)TpmCcConstants.TPM_CC_PolicyCpHash);
        offset += sizeof(uint);
        cpHashA.CopyTo(buffer[offset..]);

        int written = Hash(buffer, policyHashAlgorithm, destination, pool);
        buffer.Clear();

        return written;
    }

    /// <summary>
    /// Extends a policyDigest for TPM2_PolicyNameHash:
    /// <c>policyDigestnew = H(policyDigestold || TPM_CC_PolicyNameHash || nameHash)</c>.
    /// </summary>
    /// <param name="current">The current policyDigest (<see cref="Size"/> bytes; all zero for a fresh session).</param>
    /// <param name="nameHash">The digest of the concatenated target Names the policy binds to.</param>
    /// <param name="policyHashAlgorithm">The session's policy hash algorithm.</param>
    /// <param name="destination">Receives the new policyDigest; must be at least <see cref="Size"/> bytes.</param>
    /// <param name="pool">The memory pool the fold's hash-input scratch buffer is rented from.</param>
    /// <returns>The number of digest bytes written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public static int ExtendForNameHash(
        ReadOnlySpan<byte> current,
        ReadOnlySpan<byte> nameHash,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //H( current || TPM_CC_PolicyNameHash || nameHash ); no size prefix, the raw digest bytes are folded.
        int length = current.Length + sizeof(uint) + nameHash.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Span<byte> buffer = owner.Memory.Span[..length];
        int offset = 0;
        current.CopyTo(buffer);
        offset += current.Length;
        BinaryPrimitives.WriteUInt32BigEndian(buffer[offset..], (uint)TpmCcConstants.TPM_CC_PolicyNameHash);
        offset += sizeof(uint);
        nameHash.CopyTo(buffer[offset..]);

        int written = Hash(buffer, policyHashAlgorithm, destination, pool);
        buffer.Clear();

        return written;
    }

    /// <summary>
    /// Extends a policyDigest for TPM2_PolicyTemplate:
    /// <c>policyDigestnew = H(policyDigestold || TPM_CC_PolicyTemplate || templateHash)</c>.
    /// </summary>
    /// <param name="current">The current policyDigest (<see cref="Size"/> bytes; all zero for a fresh session).</param>
    /// <param name="templateHash">The digest of the bound object template.</param>
    /// <param name="policyHashAlgorithm">The session's policy hash algorithm.</param>
    /// <param name="destination">Receives the new policyDigest; must be at least <see cref="Size"/> bytes.</param>
    /// <param name="pool">The memory pool the fold's hash-input scratch buffer is rented from.</param>
    /// <returns>The number of digest bytes written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public static int ExtendForTemplate(
        ReadOnlySpan<byte> current,
        ReadOnlySpan<byte> templateHash,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //H( current || TPM_CC_PolicyTemplate || templateHash ); no size prefix, the raw digest bytes are folded.
        int length = current.Length + sizeof(uint) + templateHash.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Span<byte> buffer = owner.Memory.Span[..length];
        int offset = 0;
        current.CopyTo(buffer);
        offset += current.Length;
        BinaryPrimitives.WriteUInt32BigEndian(buffer[offset..], (uint)TpmCcConstants.TPM_CC_PolicyTemplate);
        offset += sizeof(uint);
        templateHash.CopyTo(buffer[offset..]);

        int written = Hash(buffer, policyHashAlgorithm, destination, pool);
        buffer.Clear();

        return written;
    }

    /// <summary>
    /// Extends a policyDigest for TPM2_PolicyDuplicationSelect (TPM 2.0 Library Part 3, clause 23.15, its equation (8)):
    /// with <paramref name="isObjectIncluded"/> SET,
    /// <c>policyDigestnew = H(policyDigestold || TPM_CC_PolicyDuplicationSelect || objectName.name || newParentName.name || includeObject)</c>;
    /// otherwise <c>policyDigestnew = H(policyDigestold || TPM_CC_PolicyDuplicationSelect || newParentName.name || includeObject)</c>.
    /// Each Name is folded as its <c>name</c> octets alone ("the UINT16 size is not included in the hash") and
    /// includeObject as one TPMI_YES_NO octet (0x01 for YES, 0x00 for NO).
    /// </summary>
    /// <param name="current">The current policyDigest (<see cref="Size"/> bytes; all zero for a fresh session).</param>
    /// <param name="objectName">The Name of the object to be duplicated; folded only when <paramref name="isObjectIncluded"/> is SET.</param>
    /// <param name="newParentName">The Name of the new parent the duplication is qualified to.</param>
    /// <param name="isObjectIncluded">Whether the object Name is folded (YES) or the policy binds the new parent alone (NO).</param>
    /// <param name="policyHashAlgorithm">The session's policy hash algorithm.</param>
    /// <param name="destination">Receives the new policyDigest; must be at least <see cref="Size"/> bytes.</param>
    /// <param name="pool">The memory pool the fold's hash-input scratch buffer is rented from.</param>
    /// <returns>The number of digest bytes written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public static int ExtendForDuplicationSelect(
        ReadOnlySpan<byte> current,
        ReadOnlySpan<byte> objectName,
        ReadOnlySpan<byte> newParentName,
        bool isObjectIncluded,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //H( current || TPM_CC_PolicyDuplicationSelect || [objectName ||] newParentName || includeObject ); the Names
        //are folded without their size prefixes and includeObject as a single TPMI_YES_NO octet.
        int namesLength = (isObjectIncluded ? objectName.Length : 0) + newParentName.Length;
        int length = current.Length + sizeof(uint) + namesLength + sizeof(byte);
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Span<byte> buffer = owner.Memory.Span[..length];
        int offset = 0;
        current.CopyTo(buffer);
        offset += current.Length;
        BinaryPrimitives.WriteUInt32BigEndian(buffer[offset..], (uint)TpmCcConstants.TPM_CC_PolicyDuplicationSelect);
        offset += sizeof(uint);
        if(isObjectIncluded)
        {
            objectName.CopyTo(buffer[offset..]);
            offset += objectName.Length;
        }

        newParentName.CopyTo(buffer[offset..]);
        offset += newParentName.Length;
        buffer[offset] = isObjectIncluded ? (byte)1 : (byte)0;

        int written = Hash(buffer, policyHashAlgorithm, destination, pool);
        buffer.Clear();

        return written;
    }

    /// <summary>
    /// Extends a policyDigest for TPM2_PolicyParameters:
    /// <c>policyDigestnew = H(policyDigestold || TPM_CC_PolicyParameters || pHash)</c> (TPM 2.0 Library Part 3, clause
    /// 23.24).
    /// </summary>
    /// <param name="current">The current policyDigest (<see cref="Size"/> bytes; all zero for a fresh session).</param>
    /// <param name="parametersHash">The digest of the command code and parameters the policy binds to.</param>
    /// <param name="policyHashAlgorithm">The session's policy hash algorithm.</param>
    /// <param name="destination">Receives the new policyDigest; must be at least <see cref="Size"/> bytes.</param>
    /// <param name="pool">The memory pool the fold's hash-input scratch buffer is rented from.</param>
    /// <returns>The number of digest bytes written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public static int ExtendForParameters(
        ReadOnlySpan<byte> current,
        ReadOnlySpan<byte> parametersHash,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //H( current || TPM_CC_PolicyParameters || pHash ); no size prefix, the raw digest bytes are folded.
        int length = current.Length + sizeof(uint) + parametersHash.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Span<byte> buffer = owner.Memory.Span[..length];
        int offset = 0;
        current.CopyTo(buffer);
        offset += current.Length;
        BinaryPrimitives.WriteUInt32BigEndian(buffer[offset..], (uint)TpmCcConstants.TPM_CC_PolicyParameters);
        offset += sizeof(uint);
        parametersHash.CopyTo(buffer[offset..]);

        int written = Hash(buffer, policyHashAlgorithm, destination, pool);
        buffer.Clear();

        return written;
    }

    /// <summary>
    /// Extends a policyDigest for TPM2_PolicyLocality:
    /// <c>policyDigestnew = H(policyDigestold || TPM_CC_PolicyLocality || locality)</c>.
    /// </summary>
    /// <param name="current">The current policyDigest (<see cref="Size"/> bytes; all zero for a fresh session).</param>
    /// <param name="locality">The set of localities the policy admits (Part 2, clause 8.5, Table 39), folded as one octet.</param>
    /// <param name="policyHashAlgorithm">The session's policy hash algorithm.</param>
    /// <param name="destination">Receives the new policyDigest; must be at least <see cref="Size"/> bytes.</param>
    /// <param name="pool">The memory pool the fold's hash-input scratch buffer is rented from.</param>
    /// <returns>The number of digest bytes written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public static int ExtendForLocality(
        ReadOnlySpan<byte> current,
        TpmaLocality locality,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //H( current || TPM_CC_PolicyLocality || locality ); locality is a single TPMA_LOCALITY octet.
        int length = current.Length + sizeof(uint) + sizeof(byte);
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Span<byte> buffer = owner.Memory.Span[..length];
        int offset = 0;
        current.CopyTo(buffer);
        offset += current.Length;
        BinaryPrimitives.WriteUInt32BigEndian(buffer[offset..], (uint)TpmCcConstants.TPM_CC_PolicyLocality);
        offset += sizeof(uint);
        buffer[offset] = (byte)locality;

        int written = Hash(buffer, policyHashAlgorithm, destination, pool);
        buffer.Clear();

        return written;
    }

    /// <summary>
    /// Extends a policyDigest for TPM2_PolicyNvWritten:
    /// <c>policyDigestnew = H(policyDigestold || TPM_CC_PolicyNvWritten || writtenSet)</c>.
    /// </summary>
    /// <param name="current">The current policyDigest (<see cref="Size"/> bytes; all zero for a fresh session).</param>
    /// <param name="isWrittenSet">The required TPMA_NV_WRITTEN state, folded as TPMI_YES_NO (0x01 for YES, 0x00 for NO).</param>
    /// <param name="policyHashAlgorithm">The session's policy hash algorithm.</param>
    /// <param name="destination">Receives the new policyDigest; must be at least <see cref="Size"/> bytes.</param>
    /// <param name="pool">The memory pool the fold's hash-input scratch buffer is rented from.</param>
    /// <returns>The number of digest bytes written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public static int ExtendForNvWritten(
        ReadOnlySpan<byte> current,
        bool isWrittenSet,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //H( current || TPM_CC_PolicyNvWritten || writtenSet ); writtenSet is a single TPMI_YES_NO octet.
        int length = current.Length + sizeof(uint) + sizeof(byte);
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Span<byte> buffer = owner.Memory.Span[..length];
        int offset = 0;
        current.CopyTo(buffer);
        offset += current.Length;
        BinaryPrimitives.WriteUInt32BigEndian(buffer[offset..], (uint)TpmCcConstants.TPM_CC_PolicyNvWritten);
        offset += sizeof(uint);
        buffer[offset] = isWrittenSet ? (byte)1 : (byte)0;

        int written = Hash(buffer, policyHashAlgorithm, destination, pool);
        buffer.Clear();

        return written;
    }

    /// <summary>
    /// Computes the policyDigest for TPM2_PolicyAuthorizeNV:
    /// <c>policyDigest = H(0...0 || TPM_CC_PolicyAuthorizeNV || nvIndex.Name)</c> (TPM 2.0 Library Part 3, clause 23.22,
    /// equation 9).
    /// </summary>
    /// <remarks>
    /// The digest is RESET to zero first, exactly like <see cref="ExtendForAuthorize"/>'s own reset — the
    /// accumulated policyDigest is discarded, never folded in — but unlike <see cref="ExtendForAuthorize"/> there
    /// is no second policyRef hash: this is a single fold over the NV Index's Name alone.
    /// </remarks>
    /// <param name="nvName">The Name of the NV Index whose held authPolicy authorizes the session.</param>
    /// <param name="policyHashAlgorithm">The session's policy hash algorithm.</param>
    /// <param name="destination">Receives the new policyDigest; must be at least <see cref="Size"/> bytes.</param>
    /// <param name="pool">The memory pool the fold's hash-input scratch buffer is rented from.</param>
    /// <returns>The number of digest bytes written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public static int ExtendForAuthorizeNv(
        ReadOnlySpan<byte> nvName,
        TpmAlgIdConstants policyHashAlgorithm,
        Span<byte> destination,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        int size = Size(policyHashAlgorithm);

        //H( zeros(size) || TPM_CC_PolicyAuthorizeNV || nvName ). The digest is RESET to zero first — the
        //accumulated policyDigest is never folded in, exactly as ExtendForAuthorize's own reset.
        int length = size + sizeof(uint) + nvName.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Span<byte> buffer = owner.Memory.Span[..length];
        buffer[..size].Clear();
        BinaryPrimitives.WriteUInt32BigEndian(buffer[size..], (uint)TpmCcConstants.TPM_CC_PolicyAuthorizeNV);
        nvName.CopyTo(buffer[(size + sizeof(uint))..]);

        int written = Hash(buffer, policyHashAlgorithm, destination, pool);
        buffer.Clear();

        return written;
    }

    /// <summary>
    /// Hashes <paramref name="data"/> into <paramref name="destination"/> with the policy hash algorithm.
    /// Routed through the registered <strong>synchronous</strong> digest seam
    /// (<see cref="CryptographicKeyEvents.ComputeDigest"/>) rather than a direct framework hash call — every
    /// caller in this file (<see cref="Verifiable.Tpm.Extensions.Policy.TpmPolicyBuilder"/>-composed policy
    /// prediction, and this simulator's own pure, state-derived <c>OnPolicy*</c> transition functions) is
    /// synchronous by construction with no TPM device round-trip in the digest step itself, matching the
    /// sync-by-nature shape this assembly's own <c>ComputeLivePcrDigest</c> (in <c>TpmLifecycleTransitions</c>)
    /// already uses for the same reason, and the project's documented convention that the sync seam is for
    /// "a hash of public or local data that can never have a hardware-async backend".
    /// </summary>
    /// <param name="data">The bytes to hash.</param>
    /// <param name="policyHashAlgorithm">The policy hash algorithm.</param>
    /// <param name="destination">The buffer that receives the digest; must be at least the algorithm's digest size.</param>
    /// <param name="pool">The memory pool the digest result is rented from.</param>
    /// <returns>The number of digest bytes written.</returns>
    /// <exception cref="NotSupportedException">Thrown for a policy hash algorithm this formula does not support.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    private static int Hash(ReadOnlySpan<byte> data, TpmAlgIdConstants policyHashAlgorithm, Span<byte> destination, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        (Tag tag, int length) = policyHashAlgorithm switch
        {
            TpmAlgIdConstants.TPM_ALG_SHA256 => (CryptoTags.Sha256Digest, 32),
            TpmAlgIdConstants.TPM_ALG_SHA384 => (CryptoTags.Sha384Digest, 48),
            TpmAlgIdConstants.TPM_ALG_SHA512 => (CryptoTags.Sha512Digest, 64),
            _ => throw new NotSupportedException($"Policy hash algorithm '{policyHashAlgorithm}' is not supported.")
        };

        using DigestValue digest = CryptographicKeyEvents.ComputeDigest(data, length, tag, pool);

        //Defensive: a pooled digest buffer is not contractually guaranteed to be exactly the requested length
        //(pool implementations are free to over-allocate), so slice before copying into the caller's buffer
        //rather than relying on this pool's current exact-sizing behaviour.
        digest.AsReadOnlySpan()[..length].CopyTo(destination);

        return length;
    }
}
