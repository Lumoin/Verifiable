using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography;

/// <summary>
/// A DHKEM suite's fixed parameters, per
/// <see href="https://www.rfc-editor.org/rfc/rfc9180">RFC 9180</see> Section 7.1, Table 2 ("KEM
/// IDs").
/// </summary>
/// <param name="KemId">
/// The two-octet KEM identifier that names this suite's <c>suite_id</c>
/// (<c>concat("KEM", I2OSP(kem_id, 2))</c>, Section 4.1).
/// </param>
/// <param name="NSecret">The KEM shared-secret length in octets - the <c>L</c> passed to <see cref="Dhkem.ExtractAndExpandAsync"/>.</param>
/// <param name="HashAlgorithm">The suite's underlying HKDF hash algorithm.</param>
public readonly record struct DhkemSuite(ushort KemId, int NSecret, HashAlgorithmName HashAlgorithm);


/// <summary>
/// DHKEM(Group, KDF) - the Diffie-Hellman-based key encapsulation mechanism
/// <see href="https://www.rfc-editor.org/rfc/rfc9180">RFC 9180</see> (HPKE) Section 4.1 builds from
/// a raw Diffie-Hellman shared value and a KDF, composed here over the project's existing RFC 5869
/// <see cref="Hkdf"/> primitive.
/// </summary>
/// <remarks>
/// <para>
/// DHKEM performs no group arithmetic itself. It consumes an already-computed DH shared value
/// <c>dh</c> (for a NIST curve, the affine x-coordinate of the ECDH product per Section 4.1's Ndh
/// definition) and a KEM context (the encapsulated key and recipient/sender public keys,
/// serialized), then derives the KEM shared secret through two labeled HKDF calls (Section 4):
/// </para>
/// <code>
/// LabeledExtract(salt, label, ikm):
///   labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
///   return Extract(salt, labeled_ikm)
///
/// LabeledExpand(prk, label, info, L):
///   labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info)
///   return Expand(prk, labeled_info, L)
///
/// ExtractAndExpand(dh, kem_context):
///   eae_prk = LabeledExtract("", "eae_prk", dh)
///   shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)
///   return shared_secret
/// </code>
/// <para>
/// <c>suite_id</c> is <c>concat("KEM", I2OSP(kem_id, 2))</c> (Section 4.1) - distinct from the
/// <c>"HPKE" || ...</c> suite_id the remainder of HPKE (the AEAD/export layer) uses, so a DHKEM
/// shared secret can never collide with an HPKE context key derived under the same label text
/// (Section 4: "If used inside a KEM algorithm, suite_id MUST start with 'KEM' ...; if used in the
/// remainder of HPKE, it MUST start with 'HPKE' ...").
/// </para>
/// <para>
/// This type computes no group arithmetic (no Encap/Decap, no ephemeral key generation, no point
/// (de)serialization) - those live at the call site, over whatever Diffie-Hellman backend the
/// caller already has. Keeping the group arithmetic out keeps this a pure Section 4/4.1 KDF
/// composition, reusable by any DHKEM instantiation regardless of curve or caller.
/// </para>
/// <para>
/// The inner HMAC routes through the same registered <see cref="ComputeHmacDelegate"/> seam
/// <see cref="Hkdf"/> and <see cref="Kdfa"/> already compose through, so DHKEM inherits identical
/// observability and backend-agility without importing a provider assembly.
/// </para>
/// <para>
/// <c>dh</c> is a secret Diffie-Hellman value and <c>eae_prk</c>/the returned shared secret are
/// derived secrets - every buffer that carries one of these is <see cref="AllocationKind.Pinned"/>
/// and is zeroed before it returns to the pool, matching <see cref="Hkdf"/>'s own discipline. The
/// <c>kem_context</c> (the encapsulated key plus public key material) and the <c>suite_id</c> are
/// not secret and ride <see cref="AllocationKind.Managed"/> rentals - matching <see cref="Kdfa"/>'s
/// treatment of its own public label/context fields - but are still zeroed before their rentals
/// return to the pool.
/// </para>
/// </remarks>
public static class Dhkem
{
    /// <summary>
    /// The Section 4 domain-separation prefix every <c>LabeledExtract</c>/<c>LabeledExpand</c> call
    /// folds into its HKDF input.
    /// </summary>
    private static byte[] HpkeV1Prefix { get; } = "HPKE-v1"u8.ToArray();

    /// <summary>
    /// The Section 4.1 ASCII prefix a KEM's <c>suite_id</c> begins with:
    /// <c>suite_id = concat("KEM", I2OSP(kem_id, 2))</c>.
    /// </summary>
    private static byte[] KemSuiteIdPrefix { get; } = "KEM"u8.ToArray();

    /// <summary>
    /// The Section 4.1 label naming DHKEM's extract stage: <c>eae_prk = LabeledExtract("",
    /// "eae_prk", dh)</c>.
    /// </summary>
    private static byte[] EaePrkLabel { get; } = "eae_prk"u8.ToArray();

    /// <summary>
    /// The Section 4.1 label naming DHKEM's expand stage: <c>shared_secret =
    /// LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)</c>.
    /// </summary>
    private static byte[] SharedSecretLabel { get; } = "shared_secret"u8.ToArray();

    /// <summary>
    /// DHKEM(P-256, HKDF-SHA256) - RFC 9180 Section 7.1, Table 2: <c>kem_id</c> 0x0010,
    /// <c>Nsecret</c> 32 octets (equal to <c>Nh</c>, the HKDF-SHA256 digest size), under
    /// HKDF-SHA256.
    /// </summary>
    public static DhkemSuite P256HkdfSha256 { get; } = new(KemId: 0x0010, NSecret: 32, HashAlgorithm: HashAlgorithmName.SHA256);


    /// <summary>
    /// Performs RFC 9180 Section 4.1's <c>ExtractAndExpand(dh, kem_context)</c>: derives a DHKEM
    /// shared secret from a raw Diffie-Hellman value and a KEM context, under
    /// <paramref name="hashAlgorithm"/> and the suite named by <paramref name="kemId"/>.
    /// </summary>
    /// <param name="hashAlgorithm">The suite's KDF hash algorithm (HKDF-SHA256 for <see cref="P256HkdfSha256"/>).</param>
    /// <param name="dh">
    /// The raw Diffie-Hellman shared value (<c>Ndh</c> octets) - for a NIST curve, the affine
    /// x-coordinate of <c>skX * pkY</c> (Section 4.1: "the size Ndh of the Diffie-Hellman shared
    /// secret is equal to ... the x-coordinate of the resulting elliptic curve point"). Secret.
    /// </param>
    /// <param name="kemContext">
    /// The KEM context Section 4.1 binds into the expand stage - <c>concat(enc, pkRm)</c> for
    /// Encap/Decap, <c>concat(enc, pkRm, pkSm)</c> for AuthEncap/AuthDecap. Not secret.
    /// </param>
    /// <param name="kemId">The KEM identifier naming this call's <c>suite_id</c> (Section 7.1, Table 2).</param>
    /// <param name="nSecret">The requested shared-secret length <c>L</c> in octets (Section 7.1, Table 2's Nsecret column). Must fit <c>I2OSP(L, 2)</c>.</param>
    /// <param name="pool">The memory pool for every allocation this call makes.</param>
    /// <param name="cancellationToken">A token observed across the underlying HKDF calls.</param>
    /// <returns>
    /// A pool-owned, pinned buffer holding the <paramref name="nSecret"/>-byte DHKEM shared secret.
    /// Ownership transfers to the caller, which must zero and dispose it.
    /// </returns>
    public static async ValueTask<IMemoryOwner<byte>> ExtractAndExpandAsync(
        HashAlgorithmName hashAlgorithm,
        ReadOnlyMemory<byte> dh,
        ReadOnlyMemory<byte> kemContext,
        ushort kemId,
        int nSecret,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(nSecret);

        //Section 4: labeled_info's leading field is I2OSP(L, 2) - L must be representable in two octets.
        ArgumentOutOfRangeException.ThrowIfGreaterThan(nSecret, ushort.MaxValue, nameof(nSecret));

        IMemoryOwner<byte> suiteIdOwner = BuildKemSuiteId(kemId, pool, out int suiteIdLength);

        try
        {
            ReadOnlyMemory<byte> suiteId = suiteIdOwner.Memory[..suiteIdLength];

            IMemoryOwner<byte> eaePrk = await LabeledExtractAsync(
                hashAlgorithm, ReadOnlyMemory<byte>.Empty, suiteId, EaePrkLabel, dh, pool, cancellationToken).ConfigureAwait(false);

            try
            {
                return await LabeledExpandAsync(
                    hashAlgorithm, eaePrk.Memory, suiteId, SharedSecretLabel, kemContext, nSecret, pool, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                eaePrk.Memory.Span.Clear();
                eaePrk.Dispose();
            }
        }
        finally
        {
            suiteIdOwner.Memory.Span.Clear();
            suiteIdOwner.Dispose();
        }
    }


    /// <summary>
    /// Performs RFC 9180 Section 4's <c>LabeledExtract(salt, label, ikm)</c>:
    /// <c>HKDF-Extract(salt, concat("HPKE-v1", suite_id, label, ikm))</c>.
    /// </summary>
    /// <param name="hashAlgorithm">The underlying HKDF hash algorithm.</param>
    /// <param name="salt">The HKDF-Extract salt (the empty string for DHKEM's <c>eae_prk</c> call, Section 4.1).</param>
    /// <param name="suiteId">The <c>suite_id</c> this call binds to (Section 4.1). Not secret.</param>
    /// <param name="label">The domain-separation label. Not secret.</param>
    /// <param name="ikm">The input keying material - secret when deriving from a DH value.</param>
    /// <param name="pool">The memory pool for the returned buffer and the labeled-IKM scratch buffer.</param>
    /// <param name="cancellationToken">A token observed by the underlying HKDF-Extract call.</param>
    /// <returns>
    /// A pool-owned, pinned buffer holding the extracted pseudorandom key (PRK). Ownership
    /// transfers to the caller, which must zero and dispose it.
    /// </returns>
    private static async ValueTask<IMemoryOwner<byte>> LabeledExtractAsync(
        HashAlgorithmName hashAlgorithm,
        ReadOnlyMemory<byte> salt,
        ReadOnlyMemory<byte> suiteId,
        ReadOnlyMemory<byte> label,
        ReadOnlyMemory<byte> ikm,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        int labeledIkmLength = HpkeV1Prefix.Length + suiteId.Length + label.Length + ikm.Length;

        //The tail of this buffer is ikm (dh for DHKEM's own call) - secret - so the whole rental is
        //pinned, exactly as Hkdf/Kdfa pin any buffer that carries key material into an HMAC round.
        IMemoryOwner<byte> labeledIkmOwner = pool.Rent(labeledIkmLength, AllocationKind.Pinned);
        Memory<byte> labeledIkmMemory = labeledIkmOwner.Memory[..labeledIkmLength];

        try
        {
            Span<byte> labeledIkm = labeledIkmMemory.Span;
            int offset = 0;

            HpkeV1Prefix.AsSpan().CopyTo(labeledIkm[offset..]);
            offset += HpkeV1Prefix.Length;

            suiteId.Span.CopyTo(labeledIkm[offset..]);
            offset += suiteId.Length;

            label.Span.CopyTo(labeledIkm[offset..]);
            offset += label.Length;

            ikm.Span.CopyTo(labeledIkm[offset..]);

            return await Hkdf.ExtractAsync(hashAlgorithm, salt, labeledIkmMemory, pool, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            labeledIkmMemory.Span.Clear();
            labeledIkmOwner.Dispose();
        }
    }


    /// <summary>
    /// Performs RFC 9180 Section 4's <c>LabeledExpand(prk, label, info, L)</c>:
    /// <c>HKDF-Expand(prk, concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info), L)</c>.
    /// </summary>
    /// <param name="hashAlgorithm">The underlying HKDF hash algorithm.</param>
    /// <param name="prk">The pseudorandom key from <see cref="LabeledExtractAsync"/>. Secret.</param>
    /// <param name="suiteId">The <c>suite_id</c> this call binds to (Section 4.1). Not secret.</param>
    /// <param name="label">The domain-separation label. Not secret.</param>
    /// <param name="info">Context information for the expand stage - the <c>kem_context</c> for DHKEM's <c>shared_secret</c> call. Not secret.</param>
    /// <param name="outputLength">The requested output length <c>L</c> in octets. Must fit <c>I2OSP(L, 2)</c> (at most <see cref="ushort.MaxValue"/>).</param>
    /// <param name="pool">The memory pool for the returned buffer and the labeled-info scratch buffer.</param>
    /// <param name="cancellationToken">A token observed by the underlying HKDF-Expand call.</param>
    /// <returns>
    /// A pool-owned, pinned buffer holding the <paramref name="outputLength"/>-byte output keying
    /// material. Ownership transfers to the caller, which must zero and dispose it.
    /// </returns>
    private static async ValueTask<IMemoryOwner<byte>> LabeledExpandAsync(
        HashAlgorithmName hashAlgorithm,
        ReadOnlyMemory<byte> prk,
        ReadOnlyMemory<byte> suiteId,
        ReadOnlyMemory<byte> label,
        ReadOnlyMemory<byte> info,
        int outputLength,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        int labeledInfoLength = sizeof(ushort) + HpkeV1Prefix.Length + suiteId.Length + label.Length + info.Length;

        //Every field here is public (the length prefix, the fixed prefix/suite/label constants, and
        //info/kem_context), so this rental stays Managed - matching Kdfa's own public label/context buffer.
        IMemoryOwner<byte> labeledInfoOwner = pool.Rent(labeledInfoLength);
        Memory<byte> labeledInfoMemory = labeledInfoOwner.Memory[..labeledInfoLength];

        try
        {
            Span<byte> labeledInfo = labeledInfoMemory.Span;
            BinaryPrimitives.WriteUInt16BigEndian(labeledInfo, checked((ushort)outputLength));
            int offset = sizeof(ushort);

            HpkeV1Prefix.AsSpan().CopyTo(labeledInfo[offset..]);
            offset += HpkeV1Prefix.Length;

            suiteId.Span.CopyTo(labeledInfo[offset..]);
            offset += suiteId.Length;

            label.Span.CopyTo(labeledInfo[offset..]);
            offset += label.Length;

            info.Span.CopyTo(labeledInfo[offset..]);

            return await Hkdf.ExpandAsync(hashAlgorithm, prk, labeledInfoMemory, outputLength, pool, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            labeledInfoMemory.Span.Clear();
            labeledInfoOwner.Dispose();
        }
    }


    /// <summary>
    /// Builds a KEM's <c>suite_id</c>: <c>concat("KEM", I2OSP(kem_id, 2))</c> (Section 4.1). Not
    /// secret - identifies the KEM algorithm in use, never keying material.
    /// </summary>
    /// <param name="kemId">The KEM identifier (Section 7.1, Table 2).</param>
    /// <param name="pool">The memory pool for the returned buffer.</param>
    /// <param name="suiteIdLength">The exact octet count the caller must slice the returned rental to before use.</param>
    /// <returns>A pool-owned buffer holding the five-octet <c>suite_id</c>. Ownership transfers to the caller, which must zero and dispose it.</returns>
    private static IMemoryOwner<byte> BuildKemSuiteId(ushort kemId, BaseMemoryPool pool, out int suiteIdLength)
    {
        suiteIdLength = KemSuiteIdPrefix.Length + sizeof(ushort);
        IMemoryOwner<byte> owner = pool.Rent(suiteIdLength);
        Span<byte> suiteId = owner.Memory.Span[..suiteIdLength];

        KemSuiteIdPrefix.AsSpan().CopyTo(suiteId);
        BinaryPrimitives.WriteUInt16BigEndian(suiteId[KemSuiteIdPrefix.Length..], kemId);

        return owner;
    }
}
