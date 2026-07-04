using System;
using System.Buffers;
using Verifiable.Cesr;
using Verifiable.Cryptography;

namespace Verifiable.Keri;

/// <summary>
/// Computes and verifies a KERI key event's Self-Addressing IDentifier (SAID) over the event's own serialization
/// bytes, in a way that is independent of the serialization (JSON, CBOR, MGPK, or CESR-native). This is the
/// genus-specific application of the serialization-neutral <see cref="CesrSaid"/> primitive: it knows the KERI
/// convention that the SAID is carried in the event's <c>d</c> field and that an inception's self-addressing
/// identifier (<c>i</c>) equals that SAID, so both occurrences must be returned to the dummy placeholder before
/// the digest is taken.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the KERI specification's <see href="https://trustoverip.github.io/kswg-keri-specification/#self-addressing-identifier-said">
/// self-addressing identifier</see> derivation and the Self-Addressing IDentifier specification
/// (draft-ssmith-said): a SAID is the digest of the serialization with the SAID field set to a dummy run of the
/// SAID's own length, so verification recomputes the digest over the received bytes with the SAID field reset to
/// that placeholder. Because the SAID is a fixed-length CESR primitive (a 256-bit digest is 44 Base64URL
/// characters, a 512-bit digest 88), the placeholder is exactly as long as the SAID, so the reset is a
/// length-preserving in-place substitution of the SAID's bytes — no re-serialization, and the same operation
/// works on JSON, CBOR, MGPK, or CESR-native bytes alike, since the SAID is embedded in each as the same ASCII
/// characters.
/// </para>
/// <para>
/// The SAID is substituted wherever it appears in the serialization. For an inception the controller identifier
/// (<c>i</c>) equals the SAID (a self-addressing AID), so both the <c>d</c> and <c>i</c> occurrences are reset, as
/// the derivation requires; for a non-inception event the identifier differs from the event SAID and only the
/// <c>d</c> occurrence is present. A coincidental match of the high-entropy digest elsewhere in the body is
/// cryptographically negligible. The digest is taken through the supplied <see cref="ComputeDigestDelegate"/>
/// (caller-supplied or the registered default), so it is algorithm-agile and carries the same telemetry and CBOM
/// stamping as every other digest in the stack, exactly as <see cref="CesrSaid"/> does.
/// </para>
/// </remarks>
public static class KeriEventSaid
{
    /// <summary>
    /// Recomputes a key event's SAID over its received serialization bytes: resets the SAID field to its dummy
    /// placeholder and digests with the algorithm named by the claimed SAID's own derivation code.
    /// </summary>
    /// <param name="serialization">The received event serialization bytes (any supported serialization), with the SAID embedded in its <c>d</c> field.</param>
    /// <param name="said">The event's claimed SAID (the value of its <c>d</c> field), which names both the algorithm and the placeholder length.</param>
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
    /// Verifies a key event's claimed SAID against its received serialization bytes: recomputes the SAID and
    /// compares.
    /// </summary>
    /// <param name="serialization">The received event serialization bytes, with the SAID embedded in its <c>d</c> field.</param>
    /// <param name="said">The event's claimed SAID (the value of its <c>d</c> field).</param>
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
