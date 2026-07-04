using System.Buffers;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Text;
using Lumoin.Base;
using Verifiable.Cesr.Text;
using Verifiable.Cryptography;

namespace Verifiable.Cesr;

/// <summary>
/// Computes and verifies a Self-Addressing IDentifier (SAID): a CESR-encoded cryptographic digest of a
/// serialization that embeds the digest as one of the serialization's own fields, making the identifier
/// both content-addressed and self-referential. SAID is the self-hashing primitive shared by KERI key
/// events, ACDC credentials, and SAID-locked schemas.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the Self-Addressing IDentifier specification (draft-ssmith-said), <see href="https://datatracker.ietf.org/doc/draft-ssmith-said/">
/// Generation and Verification Protocols</see>: the SAID field is set to a dummy string of the same length
/// (the dummy character is <c>#</c>, ASCII 35), the serialization is digested with the algorithm named by the
/// SAID's CESR derivation code, and the digest is CESR-encoded to the final SAID of that same length, which is
/// substituted back. The derivation code names the algorithm per the CESR master code table
/// (<see href="https://trustoverip.github.io/kswg-cesr-specification/#master-code-table-for-genusversion--_aaacaa-keriacdc-protocol-stack-version-200">E for Blake3-256, I for SHA2-256, 0G for SHA2-512</see>),
/// which gives cryptographic agility: each serialization may pick a different digest by changing its code.
/// </para>
/// <para>
/// This primitive is serialization-format-neutral: it digests and encodes the bytes the caller supplies and
/// produces the placeholder, but the dummy-fill of the SAID field and its substitution in a concrete
/// serialization (a JSON/CBOR/MGPK field map, or a fixed-field record) belong to the caller, which alone knows
/// the field. The digest is taken through the supplied <see cref="ComputeDigestDelegate"/> (caller-supplied or
/// the registered default) and so its telemetry, CBOM stamping, and event emission, exactly as the did:webvh
/// and did:webplus hash primitives do.
/// </para>
/// </remarks>
public static class CesrSaid
{
    /// <summary>
    /// The dummy character the SAID field is filled with before the serialization is digested: <c>#</c>,
    /// ASCII 35 decimal (0x23 hexadecimal).
    /// </summary>
    public const char DummyCharacter = '#';

    /// <summary>
    /// The largest SAID byte length the placeholder reset accepts, filled entirely from a stack buffer. It sits
    /// above the largest CESR digest full text size (88 characters for a 512-bit digest), so every well-formed SAID
    /// is reset from a bounded stack allocation — the reset is on the verification hot path, so it never allocates on
    /// the heap and never churns the garbage collector — and a longer value is rejected rather than heap-allocated,
    /// so the bound holds whatever the input, without a large-object-heap allocation an adversary could provoke.
    /// </summary>
    private const int MaxStackAllocatedSaidByteCount = 128;

    /// <summary>
    /// The CESR digest derivation codes this primitive supports, mapped to the digest tag that names the
    /// algorithm for the seam. The codes are a subset of <see cref="CesrDigestCodes"/>: the algorithms the
    /// digest seam can currently compute. The remaining digest codes (Blake2 and SHA3 families) are valid SAID
    /// codes that await seam support. The digest length is not stored here; it is the code's raw size from the
    /// master code table (see <see cref="CesrCodeSizing.RawSize"/>).
    /// </summary>
    private static FrozenDictionary<string, Tag> DigestTags { get; } = BuildDigestTags();


    /// <summary>
    /// Whether a string is a well-formed SAID by shape: its leading characters name a CESR digest derivation
    /// code, its total length equals that code's fixed full text size (44 characters for a 256-bit digest, 88
    /// for a 512-bit digest), and every character is a Base64URL character. This is the syntactic SAID form the
    /// <see href="https://datatracker.ietf.org/doc/draft-ssmith-said/">SAID specification</see> and the CESR
    /// master code table define, tested over the FULL set of digest codes (see
    /// <see cref="CesrDigestCodes.IsDigestCode"/>).
    /// </summary>
    /// <remarks>
    /// The shape-valid SAIDs are a superset of the codes this build can actually compute: <see cref="DigestCodeOf"/>
    /// and the compute and verify methods narrow to the seam-computable subset, because computing a digest requires
    /// a registered implementation whereas recognizing a well-formed identifier does not. A caller that only needs
    /// to know whether a string is syntactically a SAID — for example validating the KERI AID that terminates a
    /// did:webs identifier — uses this; a caller that must recompute the digest uses <see cref="VerifyAsync"/>.
    /// </remarks>
    /// <param name="said">The candidate SAID string.</param>
    /// <returns><see langword="true"/> when the string is a shape-valid SAID.</returns>
    public static bool IsWellFormedSaid(string said)
    {
        ArgumentNullException.ThrowIfNull(said);

        if(said.Length == 0 || !CesrCodeTables.HardSizes.TryGetValue(said[0], out int hardSize) || said.Length < hardSize)
        {
            return false;
        }

        string code = said[..hardSize];
        if(!CesrDigestCodes.IsDigestCode(code)
            || !CesrCodeTables.Sizes.TryGetValue(code, out CesrCodeSizing sizing)
            || sizing.FullSize != said.Length)
        {
            return false;
        }

        foreach(char character in said)
        {
            if(!Base64UrlAlphabet.IsBase64Url(character))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// The number of characters a SAID of the given derivation code occupies, which is the length the SAID
    /// field MUST be set to (with dummy characters) before the serialization is digested.
    /// </summary>
    /// <param name="code">The CESR digest derivation code, for example <c>E</c> for Blake3-256.</param>
    /// <returns>The full text-domain length of the SAID.</returns>
    /// <exception cref="CesrFormatException">The code is not a supported SAID digest code.</exception>
    public static int PlaceholderLength(string code)
    {
        ArgumentNullException.ThrowIfNull(code);

        EnsureDigestCode(code);

        return FullSizeOf(code);
    }


    /// <summary>
    /// Produces the dummy placeholder a SAID field is set to before digesting: a run of <see cref="DummyCharacter"/>
    /// of length <see cref="PlaceholderLength(string)"/> for the given derivation code.
    /// </summary>
    /// <param name="code">The CESR digest derivation code.</param>
    /// <returns>The placeholder string.</returns>
    public static string Placeholder(string code)
    {
        return new string(DummyCharacter, PlaceholderLength(code));
    }


    /// <summary>
    /// Computes the SAID of a serialization whose SAID field has already been set to the placeholder for the
    /// given code: digests the bytes with the algorithm named by the code, then CESR-encodes the digest.
    /// </summary>
    /// <param name="serialization">The serialization bytes with the SAID field set to <see cref="Placeholder(string)"/>.</param>
    /// <param name="code">The CESR digest derivation code that selects the algorithm and the SAID length.</param>
    /// <param name="computeDigest">The digest implementation (caller-supplied or the registered default).</param>
    /// <param name="pool">The pool the digest input and output buffers are rented from.</param>
    /// <param name="cancellationToken">Cancels an in-flight digest on a hardware-async backend (TPM2_Hash, KMS).</param>
    /// <returns>The CESR-encoded SAID.</returns>
    /// <exception cref="CesrFormatException">The code is not a supported SAID digest code.</exception>
    public static async ValueTask<string> ComputeAsync(ReadOnlyMemory<byte> serialization, string code, ComputeDigestDelegate computeDigest, MemoryPool<byte> pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(pool);

        (Tag tag, int digestLength) = LookupDigest(code);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            computeDigest, new ReadOnlySequence<byte>(serialization), digestLength, tag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return CesrPrimitiveCodec.EncodeText(code, digest.AsReadOnlySpan());
    }


    /// <summary>
    /// Verifies a claimed SAID against a serialization whose SAID field has been set back to the placeholder:
    /// recomputes the SAID using the algorithm named by the claimed SAID's own derivation code and compares.
    /// </summary>
    /// <param name="serializationWithPlaceholder">The serialization bytes with the SAID field set to <see cref="Placeholder(string)"/>.</param>
    /// <param name="said">The claimed SAID copied from the serialization before the field was reset to the placeholder.</param>
    /// <param name="computeDigest">The digest implementation (caller-supplied or the registered default).</param>
    /// <param name="pool">The pool the digest input and output buffers are rented from.</param>
    /// <param name="cancellationToken">Cancels an in-flight digest on a hardware-async backend (TPM2_Hash, KMS).</param>
    /// <returns><see langword="true"/> when the recomputed SAID equals the claimed SAID.</returns>
    /// <exception cref="CesrFormatException">The claimed SAID's leading code is not a supported SAID digest code.</exception>
    public static async ValueTask<bool> VerifyAsync(ReadOnlyMemory<byte> serializationWithPlaceholder, string said, ComputeDigestDelegate computeDigest, MemoryPool<byte> pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(said);

        string code = DigestCodeOf(said);
        string recomputed = await ComputeAsync(serializationWithPlaceholder, code, computeDigest, pool, cancellationToken).ConfigureAwait(false);

        return string.Equals(recomputed, said, StringComparison.Ordinal);
    }


    /// <summary>
    /// Recomputes the SAID of a serialization that still embeds the claimed SAID: resets every occurrence of the
    /// SAID's bytes back to the placeholder, then digests, in one step. This is the convenience over
    /// <see cref="ComputeAsync(ReadOnlyMemory{byte}, string, ComputeDigestDelegate, MemoryPool{byte}, CancellationToken)"/> for a caller that
    /// holds the serialization with the final SAID already substituted in (as received over the wire) rather than
    /// the placeholder-filled form.
    /// </summary>
    /// <param name="serialization">The serialization bytes with the SAID embedded wherever it appears (for example a field map's SAID field, or a SAID that doubles as a self-addressing identifier).</param>
    /// <param name="said">The claimed SAID, which names both the digest algorithm and the placeholder length, and whose every occurrence in the serialization is reset before digesting.</param>
    /// <param name="computeDigest">The digest implementation (caller-supplied or the registered default).</param>
    /// <param name="pool">The pool the working and digest buffers are rented from.</param>
    /// <param name="cancellationToken">Cancels an in-flight digest on a hardware-async backend (TPM2_Hash, KMS).</param>
    /// <returns>The CESR-encoded SAID recomputed over the serialization.</returns>
    /// <exception cref="CesrFormatException">The claimed SAID's leading code is not a supported SAID digest code.</exception>
    /// <remarks>
    /// Resetting "every occurrence" is the serialization-neutral way to reproduce the placeholder-filled bytes
    /// without knowing the serialization's structure: a SAID is a high-entropy cryptographic digest, so the only
    /// places its exact bytes appear are the field(s) that reference it, and a coincidental match elsewhere is
    /// cryptographically negligible. The SAID is an ASCII CESR primitive, so its byte length equals its character
    /// length and the reset is length-preserving, which means the same operation works on JSON, CBOR, MGPK, or
    /// CESR-native text bytes alike.
    /// </remarks>
    public static async ValueTask<string> RecomputeEmbeddedAsync(ReadOnlyMemory<byte> serialization, string said, ComputeDigestDelegate computeDigest, MemoryPool<byte> pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(said);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(pool);

        string code = DigestCodeOf(said);

        //A SAID occupies exactly its code's fixed full text size (44 characters for a 256-bit digest, 88 for a
        //512-bit one); a claimed SAID of any other length is malformed. This is enforced before the value is used
        //as a length below, because the reset fills a stack buffer sized to the SAID's own length — an unbounded,
        //attacker-controlled length (a valid digest code followed by a long run of Base64URL characters) would
        //otherwise overflow the stack, an uncatchable crash rather than a rejected input.
        int fullSize = FullSizeOf(code);
        if(said.Length != fullSize)
        {
            throw new CesrFormatException($"SAID '{said}' is {said.Length} characters, not the {fullSize} its '{code}' code requires.");
        }

        using IMemoryOwner<byte> owner = pool.Rent(serialization.Length);
        ReadOnlyMemory<byte> buffer = owner.Memory[..serialization.Length];
        serialization.CopyTo(owner.Memory);

        FillEmbeddedSaid(owner.Memory.Span[..serialization.Length], said);

        return await ComputeAsync(buffer, code, computeDigest, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies a claimed SAID against a serialization that still embeds it: recomputes the SAID over the
    /// serialization with every occurrence of the SAID reset to the placeholder and compares.
    /// </summary>
    /// <param name="serialization">The serialization bytes with the SAID embedded wherever it appears.</param>
    /// <param name="said">The claimed SAID copied from the serialization.</param>
    /// <param name="computeDigest">The digest implementation (caller-supplied or the registered default).</param>
    /// <param name="pool">The pool the working and digest buffers are rented from.</param>
    /// <param name="cancellationToken">Cancels an in-flight digest on a hardware-async backend (TPM2_Hash, KMS).</param>
    /// <returns><see langword="true"/> when the recomputed SAID equals the claimed SAID.</returns>
    /// <exception cref="CesrFormatException">The claimed SAID's leading code is not a supported SAID digest code.</exception>
    public static async ValueTask<bool> VerifyEmbeddedAsync(ReadOnlyMemory<byte> serialization, string said, ComputeDigestDelegate computeDigest, MemoryPool<byte> pool, CancellationToken cancellationToken = default)
    {
        string recomputed = await RecomputeEmbeddedAsync(serialization, said, computeDigest, pool, cancellationToken).ConfigureAwait(false);

        return string.Equals(recomputed, said, StringComparison.Ordinal);
    }


    //Resets every occurrence of the SAID's bytes to the dummy character, reproducing the placeholder-filled
    //serialization the SAID was originally digested over. The SAID is ASCII (a CESR Base64URL primitive), so its
    //byte length equals its character length and the fill is length-preserving. The scratch buffer holds only the
    //SAID — a public content-address (a digest of public serialization data), never secret key material — so it
    //needs no zeroing and is a bounded stack allocation rather than a pooled buffer: a SAID is small and fixed
    //length, so the reset never allocates on the heap and never churns the garbage collector on the verification
    //hot path. A length past the bound (which a well-formed SAID never reaches, and the caller rejects earlier)
    //throws rather than falling back to a heap buffer, so the bound holds whatever the input and no adversary can
    //provoke a large-object-heap allocation here.
    private static void FillEmbeddedSaid(Span<byte> serialization, string said)
    {
        int saidByteCount = Encoding.ASCII.GetByteCount(said);
        if(saidByteCount > MaxStackAllocatedSaidByteCount)
        {
            throw new CesrFormatException($"SAID '{said}' is {saidByteCount} bytes, longer than any SAID derivation code produces.");
        }

        Span<byte> saidBytes = stackalloc byte[saidByteCount];
        Encoding.ASCII.GetBytes(said, saidBytes);

        int start = 0;
        while(start <= serialization.Length - saidBytes.Length)
        {
            int index = serialization[start..].IndexOf(saidBytes);
            if(index < 0)
            {
                break;
            }

            int absolute = start + index;
            serialization.Slice(absolute, saidBytes.Length).Fill((byte)DummyCharacter);
            start = absolute + saidBytes.Length;
        }
    }


    /// <summary>
    /// Extracts the digest derivation code from the leading characters of a SAID and validates that it is a
    /// supported SAID digest code.
    /// </summary>
    /// <param name="said">The SAID string.</param>
    /// <returns>The stable digest code, for example <c>E</c> or <c>0G</c>.</returns>
    /// <exception cref="CesrFormatException">The SAID is empty or does not begin with a supported digest code.</exception>
    public static string DigestCodeOf(string said)
    {
        ArgumentNullException.ThrowIfNull(said);

        if(said.Length == 0)
        {
            throw new CesrFormatException("Empty SAID.");
        }

        if(!CesrCodeTables.HardSizes.TryGetValue(said[0], out int hardSize) || said.Length < hardSize)
        {
            throw new CesrFormatException($"SAID '{said}' does not begin with a recognized CESR code.");
        }

        string code = said[..hardSize];
        EnsureDigestCode(code);

        return code;
    }


    private static (Tag Tag, int DigestLength) LookupDigest(string code)
    {
        if(!DigestTags.TryGetValue(code, out Tag? tag))
        {
            throw new CesrFormatException($"CESR code '{code}' is not a supported SAID digest code.");
        }

        return (tag, RawSizeOf(code));
    }


    private static void EnsureDigestCode(string code)
    {
        if(!DigestTags.ContainsKey(code))
        {
            throw new CesrFormatException($"CESR code '{code}' is not a supported SAID digest code.");
        }
    }


    private static int FullSizeOf(string code)
    {
        if(!CesrCodeTables.Sizes.TryGetValue(code, out CesrCodeSizing sizing) || sizing.FullSize is not int fullSize)
        {
            throw new CesrFormatException($"CESR code '{code}' has no fixed full size.");
        }

        return fullSize;
    }


    private static int RawSizeOf(string code)
    {
        if(!CesrCodeTables.Sizes.TryGetValue(code, out CesrCodeSizing sizing) || sizing.RawSize is not int rawSize)
        {
            throw new CesrFormatException($"CESR code '{code}' has no fixed digest length.");
        }

        return rawSize;
    }


    private static FrozenDictionary<string, Tag> BuildDigestTags()
    {
        var tags = new Dictionary<string, Tag>
        {
            //The CESR digest codes whose algorithm the digest seam can compute; the digest length comes from
            //the code's raw size in the master code table.
            [CesrDigestCodes.Blake3Bits256] = CryptoTags.Blake3Digest,
            [CesrDigestCodes.Sha2Bits256] = CryptoTags.Sha256Digest,
            [CesrDigestCodes.Sha2Bits512] = CryptoTags.Sha512Digest,
        };

        return tags.ToFrozenDictionary();
    }
}
