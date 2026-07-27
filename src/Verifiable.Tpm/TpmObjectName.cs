using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm;

/// <summary>
/// Computes a TPM object's Name and Qualified Name, generalized over the nameAlg carried in the object's
/// public area (TPM 2.0 Library Part 1, clause 16): <c>Name = nameAlg ‖ H_nameAlg(TPMT_PUBLIC)</c> and
/// <c>QN(object) = nameAlg ‖ H_nameAlg(QN(parent) ‖ Name(object))</c>.
/// </summary>
/// <remarks>
/// <para>
/// Every TPM digest here goes through the registered asynchronous digest seam
/// (<see cref="CryptographicKeyEvents"/>'s <c>ComputeDigestAsync</c>), never a direct framework hash — the same
/// seam the simulator's object-creation and attestation paths already use. This type centralizes the
/// nameAlg-agile dispatch so the simulator's creation, load, and attestation paths (and any host-side
/// independent recomputation) share one implementation instead of each duplicating a hardcoded-SHA-256 variant.
/// </para>
/// <para>
/// A nameAlg outside <c>TPM_ALG_SHA1</c>/<c>SHA256</c>/<c>SHA384</c>/<c>SHA512</c> is not a digest this model
/// can compute: callers that received a nameAlg from an untrusted source (a wire template) must reject it
/// before invoking this type rather than rely on the <see cref="NotSupportedException"/> below as their only
/// gate — the simulator's creation and load transitions do so up front, mapping the rejection to
/// <c>TPM_RC_HASH</c> (TPM 2.0 Library Part 3, CreatePrimary/Create/Load error conditions), so this fail-closed
/// exception is reached only by a caller that skipped that precondition.
/// </para>
/// </remarks>
public static class TpmObjectName
{
    /// <summary>The 2-octet nameAlg prefix width common to both the Name and the Qualified Name.</summary>
    private const int NameAlgPrefixSize = sizeof(ushort);

    /// <summary>
    /// Gets the digest width, in octets, of a supported Name algorithm.
    /// </summary>
    /// <param name="nameAlg">The Name algorithm.</param>
    /// <returns>The digest width in octets.</returns>
    /// <exception cref="NotSupportedException"><paramref name="nameAlg"/> is not a Name algorithm this model computes.</exception>
    private static int DigestSize(TpmAlgIdConstants nameAlg) => nameAlg switch
    {
        TpmAlgIdConstants.TPM_ALG_SHA1 => 20,
        TpmAlgIdConstants.TPM_ALG_SHA256 => 32,
        TpmAlgIdConstants.TPM_ALG_SHA384 => 48,
        TpmAlgIdConstants.TPM_ALG_SHA512 => 64,
        _ => throw new NotSupportedException($"Name algorithm '{nameAlg}' is not supported.")
    };

    /// <summary>
    /// Gets the digest tag for a supported Name algorithm, for the registered asynchronous digest seam. SHA-1 is
    /// composed inline (the convenience <see cref="CryptoTags"/> deliberately omit it) exactly as the simulator's
    /// session hash dispatch already does; SHA-256/384/512 reuse the shared convenience tags.
    /// </summary>
    /// <param name="nameAlg">The Name algorithm.</param>
    /// <returns>The digest tag.</returns>
    /// <exception cref="NotSupportedException"><paramref name="nameAlg"/> is not a Name algorithm this model computes.</exception>
    [SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "SHA-1 is a valid TPM nameAlg this model still serves (TPM 2.0 Library Part 1, clause 16); the tag is composed inline, never from a convenience CryptoTags member, so ordinary protocol code cannot reach it by accident.")]
    private static Tag DigestTag(TpmAlgIdConstants nameAlg) => nameAlg switch
    {
        TpmAlgIdConstants.TPM_ALG_SHA1 => Tag.Create(HashAlgorithmName.SHA1).With(Purpose.Digest).With(EncodingScheme.Raw).With(MaterialSemantics.Direct),
        TpmAlgIdConstants.TPM_ALG_SHA256 => CryptoTags.Sha256Digest,
        TpmAlgIdConstants.TPM_ALG_SHA384 => CryptoTags.Sha384Digest,
        TpmAlgIdConstants.TPM_ALG_SHA512 => CryptoTags.Sha512Digest,
        _ => throw new NotSupportedException($"Name algorithm '{nameAlg}' is not supported.")
    };

    /// <summary>
    /// Computes an object's Name: <c>nameAlg ‖ H_nameAlg(TPMT_PUBLIC)</c> (TPM 2.0 Library Part 1, clause 16),
    /// through the registered asynchronous digest seam.
    /// </summary>
    /// <param name="marshalledPublicArea">The marshaled <c>TPMT_PUBLIC</c> (no <c>TPM2B</c> size prefix) to hash.</param>
    /// <param name="nameAlg">The Name algorithm carried in the public area.</param>
    /// <param name="pool">The memory pool backing the returned buffer.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The rented buffer holding the Name, and the number of valid octets within it. The caller owns and disposes the buffer.</returns>
    /// <exception cref="NotSupportedException"><paramref name="nameAlg"/> is not a Name algorithm this model computes.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned buffer transfers to the caller, which disposes it.")]
    public static async ValueTask<(IMemoryOwner<byte> Owner, int Length)> ComputeNameAsync(
        ReadOnlyMemory<byte> marshalledPublicArea, ushort nameAlg, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pool);

        var algorithm = (TpmAlgIdConstants)nameAlg;
        int digestSize = DigestSize(algorithm);
        Tag tag = DigestTag(algorithm);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            marshalledPublicArea, digestSize, tag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return FrameName(nameAlg, digest.AsReadOnlySpan(), pool);
    }

    /// <summary>
    /// Computes an object's Qualified Name: <c>QN = nameAlg ‖ H_nameAlg(QN(parent) ‖ Name(object))</c>
    /// (TPM 2.0 Library Part 1, clause 16), through the registered asynchronous digest seam.
    /// </summary>
    /// <remarks>
    /// For a primary object created directly under a permanent hierarchy — every object this simulator
    /// creates today — <c>QN(parent)</c> is the hierarchy's own Name, which for a permanent handle is defined
    /// to be the 4-octet big-endian handle value itself (Part 1, clause 16); the caller supplies that value
    /// as <paramref name="parentQualifiedName"/>. A future parent that is itself a non-hierarchy loaded object
    /// would instead supply that object's own computed Qualified Name here.
    /// </remarks>
    /// <param name="parentQualifiedName">The parent's Qualified Name (for a permanent hierarchy parent, its 4-octet big-endian handle value).</param>
    /// <param name="name">The object's own Name (<c>nameAlg ‖ H_nameAlg(TPMT_PUBLIC)</c>).</param>
    /// <param name="nameAlg">The Name algorithm (the same algorithm the object's own Name carries).</param>
    /// <param name="pool">The memory pool backing the returned buffer.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The rented buffer holding the Qualified Name, and the number of valid octets within it. The caller owns and disposes the buffer.</returns>
    /// <exception cref="NotSupportedException"><paramref name="nameAlg"/> is not a Name algorithm this model computes.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned buffer transfers to the caller, which disposes it.")]
    public static async ValueTask<(IMemoryOwner<byte> Owner, int Length)> ComputeQualifiedNameAsync(
        ReadOnlyMemory<byte> parentQualifiedName, ReadOnlyMemory<byte> name, ushort nameAlg, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pool);

        var algorithm = (TpmAlgIdConstants)nameAlg;
        int digestSize = DigestSize(algorithm);
        Tag tag = DigestTag(algorithm);

        int messageLength = parentQualifiedName.Length + name.Length;
        using IMemoryOwner<byte> message = pool.Rent(messageLength);
        parentQualifiedName.Span.CopyTo(message.Memory.Span);
        name.Span.CopyTo(message.Memory.Span[parentQualifiedName.Length..messageLength]);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            message.Memory[..messageLength], digestSize, tag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return FrameName(nameAlg, digest.AsReadOnlySpan(), pool);
    }

    /// <summary>
    /// Frames a computed digest into the Name wire form: the 2-octet big-endian nameAlg prefix followed by the
    /// digest octets.
    /// </summary>
    /// <param name="nameAlg">The Name algorithm to write as the prefix.</param>
    /// <param name="digest">The computed digest octets.</param>
    /// <param name="pool">The memory pool backing the returned buffer.</param>
    /// <returns>The rented buffer holding the framed Name, and the number of valid octets within it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned buffer transfers to the caller, which disposes it.")]
    private static (IMemoryOwner<byte> Owner, int Length) FrameName(ushort nameAlg, ReadOnlySpan<byte> digest, MemoryPool<byte> pool)
    {
        int nameLength = NameAlgPrefixSize + digest.Length;
        IMemoryOwner<byte> name = pool.Rent(nameLength);
        try
        {
            Span<byte> nameSpan = name.Memory.Span[..nameLength];
            BinaryPrimitives.WriteUInt16BigEndian(nameSpan, nameAlg);
            digest.CopyTo(nameSpan[NameAlgPrefixSize..]);

            return (name, nameLength);
        }
        catch
        {
            name.Dispose();
            throw;
        }
    }
}
