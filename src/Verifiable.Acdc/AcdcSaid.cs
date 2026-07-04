using System;
using System.Buffers;
using Verifiable.Cesr;
using Verifiable.Cryptography;

namespace Verifiable.Acdc;

/// <summary>
/// Computes and verifies the Self-Addressing IDentifier (SAID) of an ACDC block over its own serialization bytes,
/// independent of the serialization (JSON, CBOR, MGPK, or CESR-native). An ACDC is a tree of SAIDed blocks: the
/// top-level <c>d</c> is the SAID over the ACDC's most-compact-form serialization, and each section's SAID (the
/// <c>d</c> of an attribute, edge, or rule block, or the <c>$id</c> of a schema block) is the SAID over that
/// section's expanded block. A Verifier checks the tree the way Graduated Disclosure exposes it — verify the SAID
/// of whatever block was disclosed against that block's received bytes, descending as deep as the disclosure goes.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#most-compact-form-said">
/// most compact form SAID</see> derivation: there is one and only one SAID for a compactifiable block, computed on
/// its block-level expanded form, and a Verifier reverses the process by expanding a block, verifying its SAID,
/// then expanding and verifying the SAIDs of its enclosed blocks. This is the genus-specific application of the
/// serialization-neutral <see cref="CesrSaid.RecomputeEmbeddedAsync(ReadOnlyMemory{byte}, string, ComputeDigestDelegate, MemoryPool{byte}, System.Threading.CancellationToken)"/>
/// primitive: the SAID is reset to its dummy placeholder wherever it appears in the received bytes and the digest
/// is recomputed with the algorithm named by the SAID's own derivation code, so it works on any serialization and
/// stays algorithm-agile through the supplied <see cref="ComputeDigestDelegate"/>.
/// </para>
/// <para>
/// This verifies a SAID against received bytes that are already in the form the SAID was taken over — the ACDC in
/// its most-compact form for the top-level SAID, or a section in its block-level expanded form for a section SAID.
/// Deriving the most-compact form by compacting an expanded ACDC (the depth-first computation an issuer runs) is a
/// separate capability built on this one.
/// </para>
/// </remarks>
public static class AcdcSaid
{
    /// <summary>
    /// Recomputes an ACDC block's SAID over its received serialization bytes: resets the SAID to its dummy
    /// placeholder wherever it appears and digests with the algorithm named by the claimed SAID's derivation code.
    /// </summary>
    /// <param name="serialization">The received serialization of the block the SAID was taken over — the ACDC in most-compact form for the top-level SAID, or a section's block-level expanded form for a section SAID.</param>
    /// <param name="said">The block's claimed SAID (the <c>d</c> field value, or a schema's <c>$id</c> value), which names both the algorithm and the placeholder length.</param>
    /// <param name="computeDigest">The digest implementation (caller-supplied or the registered default).</param>
    /// <param name="pool">The pool the working and digest buffers are rented from.</param>
    /// <param name="cancellationToken">Cancels an in-flight digest on a hardware-async backend (TPM2_Hash, KMS).</param>
    /// <returns>The CESR-encoded SAID recomputed over the serialization.</returns>
    /// <exception cref="CesrFormatException">The claimed SAID's leading code is not a supported digest code.</exception>
    public static ValueTask<string> RecomputeAsync(ReadOnlyMemory<byte> serialization, string said, ComputeDigestDelegate computeDigest, MemoryPool<byte> pool, CancellationToken cancellationToken = default)
    {
        return CesrSaid.RecomputeEmbeddedAsync(serialization, said, computeDigest, pool, cancellationToken);
    }


    /// <summary>
    /// Verifies an ACDC block's claimed SAID against its received serialization bytes: recomputes the SAID and
    /// compares.
    /// </summary>
    /// <param name="serialization">The received serialization of the block the SAID was taken over.</param>
    /// <param name="said">The block's claimed SAID (the <c>d</c> field value, or a schema's <c>$id</c> value).</param>
    /// <param name="computeDigest">The digest implementation (caller-supplied or the registered default).</param>
    /// <param name="pool">The pool the working and digest buffers are rented from.</param>
    /// <param name="cancellationToken">Cancels an in-flight digest on a hardware-async backend (TPM2_Hash, KMS).</param>
    /// <returns><see langword="true"/> when the recomputed SAID equals the claimed SAID.</returns>
    /// <exception cref="CesrFormatException">The claimed SAID's leading code is not a supported digest code.</exception>
    public static ValueTask<bool> VerifyAsync(ReadOnlyMemory<byte> serialization, string said, ComputeDigestDelegate computeDigest, MemoryPool<byte> pool, CancellationToken cancellationToken = default)
    {
        return CesrSaid.VerifyEmbeddedAsync(serialization, said, computeDigest, pool, cancellationToken);
    }
}
