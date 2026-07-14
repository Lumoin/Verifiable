using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.IO;
using System.IO.Compression;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Microsoft;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The PKG-D real-wire capstones' platform-role fixtures for <c>authenticatorLargeBlobs</c> (<c>0x0C</c>)
/// and the <c>largeBlobKey</c> extension (CTAP 2.3 §12.3): DEFLATE compression, AES-256-GCM per-entry
/// encryption, the platform-written large-blob map/serialized-array CBOR shapes, and the §6.10.2 platform
/// read/write flows (lines 7699/7700) — reconstructed OVER THE WIRE against the unchanged
/// <see cref="CtapWave2TransportHarness"/>, mirroring <see cref="CtapWaveLargeBlobsFixtures"/>'s
/// authenticator-side role but confined to what the wave contract's R9 ruling calls the platform's own
/// obligations (spec Finding 1: everything here except truncated SHA-256 is platform-actor, never
/// authenticator-side).
/// </summary>
/// <remarks>
/// <para>
/// <strong>AES-256-GCM.</strong> Delegates to <see cref="MicrosoftKeyAgreementFunctions.AesGcmEncryptAsync"/>/
/// <see cref="MicrosoftKeyAgreementFunctions.AesGcmDecryptAsync"/> — the JWE tenants' existing AEAD
/// seam (house project-crypto-in-tests rule: reach for the project's crypto surface, never
/// <see cref="System.Security.Cryptography"/> directly). Those functions are algorithm-role-generic
/// (plaintext/key/AAD in, ciphertext/nonce/tag out); only the pre-registered
/// <see cref="CryptoTags"/>.<c>AesGcm*</c> constants carry a P-256 ECDH-ES provenance discriminator that
/// does not apply here — a <c>largeBlobKey</c> is a flat, pre-shared 32-byte secret with no key
/// agreement of any kind (CTAP 2.3 §12.3, line 12851). This fixture therefore builds its own ad hoc
/// <see cref="Tag"/> values (<see cref="CryptoAlgorithm.Aes256"/>-discriminated) for the key/ciphertext/
/// nonce/tag/AAD carriers it constructs, rather than reusing the P-256-labelled constants — reuse of the
/// EXISTING GENERIC FUNCTIONS satisfies R9's "check the project crypto surface first" instruction; only
/// the tag METADATA is local to this fixture, per the house tag-selection rule (purpose-specific, not a
/// forced-fit reuse of a differently-provenanced constant).
/// </para>
/// <para>
/// <strong>DEFLATE.</strong> <see cref="DeflateCompress"/>/<see cref="DeflateDecompressExact"/> are the
/// ONE sanctioned <c>TestInfrastructure</c>-only wrap of <see cref="DeflateStream"/> (RFC 1951) R9
/// authorizes: no span-based DEFLATE exists in the BCL, and the no-<c>Stream</c> house rule's hard scope
/// is <c>src/**</c> — this project's own <c>GZipStream</c>-over-<see cref="MemoryStream"/> precedent
/// (<c>Verifiable.Core.StatusList.BitstringStatusListCodec</c>) is mirrored here for DEFLATE instead of
/// GZIP. <c>src/Verifiable.Fido2</c>/<c>src/Verifiable.Cbor</c> stay <see cref="DeflateStream"/>-free —
/// the authenticator's own §6.10.2 algorithm never decompresses (line 7704's MUST NOT).
/// </para>
/// <para>
/// <strong>Large-blob map / serialized array.</strong> §6.10.3's map (<c>ciphertext</c> <c>0x01</c>,
/// <c>nonce</c> <c>0x02</c>, <c>origSize</c> <c>0x03</c>) and §6.10's serialized-array framing (a CBOR
/// array of maps followed by <c>LEFT(SHA-256(array bytes), 16)</c>) are platform-only shapes this wave
/// ships no production codec for (scope boundary: "no span DEFLATE... the authenticator surface is
/// spec-complete without them"); <see cref="BuildSerializedArrayWithSingleEntry"/>/
/// <see cref="DecodeSerializedArraySingleEntry"/> hand-roll them here, the same way
/// <see cref="CtapWave2AuthenticatorFixtures.BuildMakeCredentialExtensionsInput"/> hand-rolls extension
/// input CBOR with <see cref="CborWriter"/> directly.
/// </para>
/// </remarks>
internal static class CtapWaveLargeBlobPlatformFixtures
{
    /// <summary>The AES-256-GCM authentication tag length in bytes (NIST SP 800-38D, 128 bits).</summary>
    private const int GcmTagLength = 16;

    /// <summary>The SHA-256 digest length in bytes.</summary>
    private const int Sha256Length = 32;

    /// <summary>The serialized large-blob array's trailing truncated-hash length in bytes (CTAP 2.3, line 7540: <c>LEFT(SHA-256(...), 16)</c>).</summary>
    private const int TrailingHashLength = 16;

    /// <summary>The large-blob map's <c>ciphertext</c> key (CTAP 2.3 §6.10.3, <c>0x01</c>).</summary>
    private const int LargeBlobMapCiphertextKey = 0x01;

    /// <summary>The large-blob map's <c>nonce</c> key (CTAP 2.3 §6.10.3, <c>0x02</c>).</summary>
    private const int LargeBlobMapNonceKey = 0x02;

    /// <summary>The large-blob map's <c>origSize</c> key (CTAP 2.3 §6.10.3, <c>0x03</c>).</summary>
    private const int LargeBlobMapOrigSizeKey = 0x03;

    /// <summary>The AES-256-GCM associated data's fixed four-byte prefix, the ASCII bytes of "blob" (CTAP 2.3, line 7739: <c>0x626c6f62</c>).</summary>
    private static ReadOnlySpan<byte> AssociatedDataPrefix => "blob"u8;


    /// <summary>
    /// DEFLATE-compresses <paramref name="data"/> (RFC 1951), the platform write flow's first step
    /// (CTAP 2.3, line 7793: "compress-then-encrypt").
    /// </summary>
    /// <param name="data">The opaque large-blob data to compress.</param>
    /// <returns>The DEFLATE-compressed bytes.</returns>
    public static byte[] DeflateCompress(ReadOnlySpan<byte> data)
    {
        using var output = new MemoryStream();
        using(var deflate = new DeflateStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            deflate.Write(data);
        }

        return output.ToArray();
    }


    /// <summary>
    /// DEFLATE-decompresses <paramref name="compressed"/> into exactly <paramref name="origSize"/> bytes,
    /// then confirms no further bytes remain — the platform read flow's own length check (CTAP 2.3, line
    /// 7767: "If the length of the decompression result is not equal to <c>origSize</c>, return an
    /// error").
    /// </summary>
    /// <param name="compressed">The DEFLATE-compressed bytes to decompress.</param>
    /// <param name="origSize">The declared uncompressed length, read from the large-blob map's <c>origSize</c> member.</param>
    /// <returns>The decompressed opaque large-blob data, exactly <paramref name="origSize"/> bytes.</returns>
    /// <exception cref="Fido2FormatException">The decompressed length does not equal <paramref name="origSize"/>.</exception>
    public static byte[] DeflateDecompressExact(ReadOnlySpan<byte> compressed, int origSize)
    {
        using var input = new MemoryStream(compressed.Length);
        input.Write(compressed);
        input.Position = 0;

        using var deflate = new DeflateStream(input, CompressionMode.Decompress);
        byte[] result = new byte[origSize];
        deflate.ReadExactly(result);

        Span<byte> probe = stackalloc byte[1];
        if(deflate.Read(probe) != 0)
        {
            throw new Fido2FormatException("The DEFLATE-decompressed large-blob entry exceeds its declared origSize (CTAP 2.3, line 7767).");
        }

        return result;
    }


    /// <summary>
    /// Builds the AES-256-GCM associated data CTAP 2.3 §6.10.3 (lines 7733-7742) specifies: the four
    /// ASCII bytes of "blob" (<c>0x626c6f62</c>) followed by <paramref name="origSize"/> as a
    /// SIXTY-FOUR-bit little-endian integer — distinct from the per-fragment verify message's
    /// THIRTY-TWO-bit little-endian <c>offset</c> (seams trap 5 / spec scout Finding 11).
    /// </summary>
    /// <param name="origSize">The entry's uncompressed length.</param>
    /// <returns>The twelve-byte associated data.</returns>
    public static byte[] BuildAssociatedData(int origSize)
    {
        byte[] associatedData = new byte[AssociatedDataPrefix.Length + sizeof(ulong)];
        AssociatedDataPrefix.CopyTo(associatedData);
        BinaryPrimitives.WriteUInt64LittleEndian(associatedData.AsSpan(AssociatedDataPrefix.Length), (ulong)origSize);

        return associatedData;
    }


    /// <summary>
    /// Encrypts <paramref name="compressedPlaintext"/> under <paramref name="largeBlobKey"/> with
    /// AES-256-GCM, through <see cref="MicrosoftKeyAgreementFunctions.AesGcmEncryptAsync"/> (this
    /// fixture's own class remark explains the ad hoc <see cref="Tag"/> choice). The returned ciphertext
    /// has the authentication tag appended (CTAP 2.3, line 7719: "implicitly including the AEAD
    /// 'authentication tag' at the end").
    /// </summary>
    /// <param name="compressedPlaintext">The DEFLATE-compressed opaque large-blob data.</param>
    /// <param name="largeBlobKey">The credential's 32-byte <c>largeBlobKey</c>.</param>
    /// <param name="origSize">The entry's uncompressed length, fed into <see cref="BuildAssociatedData"/>.</param>
    /// <param name="pool">The memory pool every allocation uses.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The ciphertext-with-appended-tag bytes and the fresh, random twelve-byte nonce.</returns>
    public static async Task<(byte[] CiphertextWithTag, byte[] Nonce)> EncryptEntryAsync(
        ReadOnlyMemory<byte> compressedPlaintext, ReadOnlyMemory<byte> largeBlobKey, int origSize, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] associatedData = BuildAssociatedData(origSize);

        IMemoryOwner<byte> keyOwner = pool.Rent(largeBlobKey.Length);
        largeBlobKey.Span.CopyTo(keyOwner.Memory.Span);
        using var key = new SymmetricKeyMemory(keyOwner, Tag.Create(CryptoAlgorithm.Aes256).With(Purpose.Encryption).With(EncodingScheme.Raw));

        IMemoryOwner<byte> aadOwner = pool.Rent(associatedData.Length);
        associatedData.AsSpan().CopyTo(aadOwner.Memory.Span);
        using var aad = new AdditionalData(aadOwner, Tag.Create(CryptoAlgorithm.Aes256).With(Purpose.Data).With(EncodingScheme.Raw));

        using AeadEncryptResult result = await MicrosoftKeyAgreementFunctions.AesGcmEncryptAsync(compressedPlaintext, key, aad, pool, cancellationToken)
            .ConfigureAwait(false);

        byte[] ciphertextWithTag = new byte[result.Ciphertext.Length + result.Tag.Length];
        result.Ciphertext.AsReadOnlySpan().CopyTo(ciphertextWithTag);
        result.Tag.AsReadOnlySpan().CopyTo(ciphertextWithTag.AsSpan(result.Ciphertext.Length));
        byte[] nonce = result.Iv.AsReadOnlySpan().ToArray();

        return (ciphertextWithTag, nonce);
    }


    /// <summary>
    /// Decrypts a large-blob entry's <paramref name="ciphertextWithTag"/> under
    /// <paramref name="largeBlobKey"/> with AES-256-GCM, through
    /// <see cref="MicrosoftKeyAgreementFunctions.AesGcmDecryptAsync"/> — the exact inverse of
    /// <see cref="EncryptEntryAsync"/>, splitting the appended authentication tag back off before
    /// decryption.
    /// </summary>
    /// <param name="ciphertextWithTag">The large-blob map's <c>ciphertext</c> bytes (tag appended).</param>
    /// <param name="nonce">The large-blob map's <c>nonce</c> bytes.</param>
    /// <param name="origSize">The large-blob map's <c>origSize</c> value, fed into <see cref="BuildAssociatedData"/>.</param>
    /// <param name="largeBlobKey">The credential's 32-byte <c>largeBlobKey</c>.</param>
    /// <param name="pool">The memory pool every allocation uses.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The decrypted, DEFLATE-compressed plaintext bytes.</returns>
    public static async Task<byte[]> DecryptEntryAsync(
        ReadOnlyMemory<byte> ciphertextWithTag, ReadOnlyMemory<byte> nonce, int origSize, ReadOnlyMemory<byte> largeBlobKey, MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        byte[] associatedData = BuildAssociatedData(origSize);
        int ciphertextLength = ciphertextWithTag.Length - GcmTagLength;

        IMemoryOwner<byte> keyOwner = pool.Rent(largeBlobKey.Length);
        largeBlobKey.Span.CopyTo(keyOwner.Memory.Span);
        using var key = new SymmetricKeyMemory(keyOwner, Tag.Create(CryptoAlgorithm.Aes256).With(Purpose.Encryption).With(EncodingScheme.Raw));

        IMemoryOwner<byte> ivOwner = pool.Rent(nonce.Length);
        nonce.Span.CopyTo(ivOwner.Memory.Span);
        using var iv = new Nonce(ivOwner, Tag.Create(CryptoAlgorithm.Aes256).With(Purpose.Nonce).With(EncodingScheme.Raw));

        IMemoryOwner<byte> ciphertextOwner = pool.Rent(ciphertextLength);
        ciphertextWithTag.Span[..ciphertextLength].CopyTo(ciphertextOwner.Memory.Span);
        using var ciphertext = new Ciphertext(ciphertextOwner, Tag.Create(CryptoAlgorithm.Aes256).With(Purpose.Encryption).With(EncodingScheme.Raw));

        IMemoryOwner<byte> tagOwner = pool.Rent(GcmTagLength);
        ciphertextWithTag.Span[ciphertextLength..].CopyTo(tagOwner.Memory.Span);
        using var tag = new AuthenticationTag(tagOwner, Tag.Create(CryptoAlgorithm.Aes256).With(Purpose.Mac).With(EncodingScheme.Raw));

        IMemoryOwner<byte> aadOwner = pool.Rent(associatedData.Length);
        associatedData.AsSpan().CopyTo(aadOwner.Memory.Span);
        using var aad = new AdditionalData(aadOwner, Tag.Create(CryptoAlgorithm.Aes256).With(Purpose.Data).With(EncodingScheme.Raw));

        using DecryptedContent decrypted = await MicrosoftKeyAgreementFunctions.AesGcmDecryptAsync(ciphertext, key, iv, tag, aad, pool, cancellationToken)
            .ConfigureAwait(false);

        return decrypted.AsReadOnlySpan().ToArray();
    }


    /// <summary>
    /// Builds a byte-exact serialized large-blob array holding exactly ONE large-blob map (CTAP 2.3
    /// §6.10.3): a CTAP2-canonical CBOR array of one map (<c>ciphertext</c>/<c>nonce</c>/<c>origSize</c>)
    /// followed by <c>LEFT(SHA-256(array bytes), 16)</c> — the platform's own write-time framing (line
    /// 7540's construction, generalized from the empty-array case to a one-entry array).
    /// </summary>
    /// <param name="ciphertextWithTag">The entry's <c>ciphertext</c> member (tag appended).</param>
    /// <param name="nonce">The entry's <c>nonce</c> member.</param>
    /// <param name="origSize">The entry's <c>origSize</c> member.</param>
    /// <param name="pool">The memory pool the trailing-hash computation allocates from.</param>
    /// <returns>The complete serialized large-blob array bytes.</returns>
    public static byte[] BuildSerializedArrayWithSingleEntry(ReadOnlyMemory<byte> ciphertextWithTag, ReadOnlyMemory<byte> nonce, int origSize, MemoryPool<byte> pool)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartArray(1);
        writer.WriteStartMap(3);
        writer.WriteInt32(LargeBlobMapCiphertextKey);
        writer.WriteByteString(ciphertextWithTag.Span);
        writer.WriteInt32(LargeBlobMapNonceKey);
        writer.WriteByteString(nonce.Span);
        writer.WriteInt32(LargeBlobMapOrigSizeKey);
        writer.WriteUInt64((ulong)origSize);
        writer.WriteEndMap();
        writer.WriteEndArray();
        byte[] arrayBytes = writer.Encode();

        using DigestValue digest = CryptographicKeyEvents.ComputeDigest(arrayBytes, Sha256Length, CryptoTags.Sha256Digest, pool);
        byte[] serialized = new byte[arrayBytes.Length + TrailingHashLength];
        arrayBytes.CopyTo(serialized, 0);
        digest.AsReadOnlySpan()[..TrailingHashLength].CopyTo(serialized.AsSpan(arrayBytes.Length));

        return serialized;
    }


    /// <summary>
    /// Decodes a serialized large-blob array known to hold exactly ONE large-blob map, the exact inverse
    /// of <see cref="BuildSerializedArrayWithSingleEntry"/> — strips the trailing 16-byte hash and reads
    /// the CBOR array's sole map's three members back out.
    /// </summary>
    /// <param name="serializedArray">The complete serialized large-blob array bytes, trailing hash included.</param>
    /// <returns>The decoded entry's <c>ciphertext</c>, <c>nonce</c>, and <c>origSize</c> members.</returns>
    /// <exception cref="Fido2FormatException">The map carries an unrecognized key.</exception>
    public static (byte[] CiphertextWithTag, byte[] Nonce, int OrigSize) DecodeSerializedArraySingleEntry(ReadOnlyMemory<byte> serializedArray)
    {
        ReadOnlyMemory<byte> arrayBytes = serializedArray[..^TrailingHashLength];
        var reader = new CborReader(arrayBytes, CborConformanceMode.Ctap2Canonical);
        reader.ReadStartArray();
        int? memberCount = reader.ReadStartMap();

        byte[]? ciphertextWithTag = null;
        byte[]? nonce = null;
        int origSize = 0;
        for(int i = 0; i < memberCount!.Value; i++)
        {
            int key = reader.ReadInt32();
            switch(key)
            {
                case(LargeBlobMapCiphertextKey):
                {
                    ciphertextWithTag = reader.ReadByteString();

                    break;
                }
                case(LargeBlobMapNonceKey):
                {
                    nonce = reader.ReadByteString();

                    break;
                }
                case(LargeBlobMapOrigSizeKey):
                {
                    origSize = checked((int)reader.ReadUInt64());

                    break;
                }
                default:
                {
                    throw new Fido2FormatException($"Unexpected large-blob map key 0x{key:X2}.");
                }
            }
        }

        reader.ReadEndMap();
        reader.ReadEndArray();

        return (ciphertextWithTag!, nonce!, origSize);
    }


    /// <summary>
    /// Builds a well-formed, integrity-VALID serialized large-blob array of a chosen total length: an
    /// empty CBOR array (<c>0x80</c>) padded with <paramref name="payloadLength"/> minus 17 filler bytes,
    /// followed by the correct trailing <c>LEFT(SHA-256(preceding bytes), 16)</c> — the capstones' own
    /// mirror of <c>CtapAuthenticatorLargeBlobsTests</c>' identically-shaped private helper, shared here
    /// for the flows that need an arbitrary-length, integrity-valid array without a real per-credential
    /// entry (the authenticator's own algorithm never parses the array's contents beyond the trailing
    /// hash — line 7704's MUST NOT — so filler bytes are exactly as valid as CTAP2-canonical CBOR would be).
    /// </summary>
    /// <param name="pool">The memory pool the digest computation allocates from.</param>
    /// <param name="payloadLength">The total serialized array length, at least 17.</param>
    /// <returns>The byte-exact, integrity-valid array.</returns>
    public static byte[] BuildValidSerializedArray(MemoryPool<byte> pool, int payloadLength)
    {
        byte[] array = new byte[payloadLength];
        array[0] = 0x80;
        for(int i = 1; i < payloadLength - TrailingHashLength; i++)
        {
            array[i] = (byte)(0x41 + i);
        }

        using DigestValue digest = CryptographicKeyEvents.ComputeDigest(array.AsSpan(0, payloadLength - TrailingHashLength), Sha256Length, CryptoTags.Sha256Digest, pool);
        digest.AsReadOnlySpan()[..TrailingHashLength].CopyTo(array.AsSpan(payloadLength - TrailingHashLength));

        return array;
    }


    /// <summary>
    /// Sends exactly ONE <c>set</c> fragment over <paramref name="transceive"/>'s real transport,
    /// computing the fragment's own <c>pinUvAuthParam</c> when <paramref name="token"/> is supplied (the
    /// R5 gate's armed path) or omitting the auth pair entirely when it is <see langword="null"/> (the
    /// tokenless path, line 7682).
    /// </summary>
    /// <param name="transceive">The transport-neutral CTAP2 request/response exchange.</param>
    /// <param name="pool">The memory pool every allocation uses.</param>
    /// <param name="fragment">The fragment's contents.</param>
    /// <param name="offset">The fragment's <c>offset</c>.</param>
    /// <param name="length">The <c>length</c> member — present iff <paramref name="offset"/> is zero.</param>
    /// <param name="token">The authenticating <c>pinUvAuthToken</c>, or <see langword="null"/> for a tokenless write.</param>
    /// <param name="protocolId">Which PIN/UV auth protocol <paramref name="token"/> was issued under.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The raw CTAP2 status byte.</returns>
    public static async Task<byte> SendFragmentAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, ReadOnlyMemory<byte> fragment, int offset, int? length, byte[]? token,
        CtapPinUvAuthProtocolId protocolId, CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte>? pinUvAuthParam = null;
        int? pinUvAuthProtocol = null;
        if(token is not null)
        {
            byte[] param = await CtapWaveLargeBlobsFixtures.ComputeSetSignatureAsync(token, protocolId, offset, fragment, pool, cancellationToken)
                .ConfigureAwait(false);
            pinUvAuthParam = param;
            pinUvAuthProtocol = (int)protocolId;
        }

        var request = new CtapLargeBlobsRequest(Set: fragment, Offset: offset, Length: length, PinUvAuthParam: pinUvAuthParam, PinUvAuthProtocol: pinUvAuthProtocol);
        byte[] envelope = CtapWaveLargeBlobsFixtures.BuildEnvelope(request);
        using PooledMemory response = await transceive(envelope, pool, cancellationToken).ConfigureAwait(false);

        return response.AsReadOnlySpan()[0];
    }


    /// <summary>
    /// Writes <paramref name="fullArray"/> to the authenticator as a complete multi-fragment <c>set</c>
    /// sequence over <paramref name="transceive"/>'s real transport (the platform write flow, CTAP 2.3
    /// line 7700), fragmenting at <paramref name="fragmentLength"/> bytes and driving every fragment
    /// through <see cref="SendFragmentAsync"/> until the sequence commits.
    /// </summary>
    /// <param name="transceive">The transport-neutral CTAP2 request/response exchange.</param>
    /// <param name="pool">The memory pool every allocation uses.</param>
    /// <param name="fullArray">The complete serialized large-blob array to write.</param>
    /// <param name="fragmentLength">The per-fragment chunk size (at most <see cref="CtapAuthenticatorState.MaxFragmentLength"/>).</param>
    /// <param name="token">The authenticating <c>pinUvAuthToken</c>, or <see langword="null"/> for a tokenless write.</param>
    /// <param name="protocolId">Which PIN/UV auth protocol <paramref name="token"/> was issued under.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <exception cref="CtapCommandException">A fragment returned a non-success status.</exception>
    public static async Task WriteSerializedArrayAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, ReadOnlyMemory<byte> fullArray, int fragmentLength, byte[]? token,
        CtapPinUvAuthProtocolId protocolId, CancellationToken cancellationToken)
    {
        int totalLength = fullArray.Length;
        int offset = 0;
        while(offset < totalLength)
        {
            int chunkLength = Math.Min(fragmentLength, totalLength - offset);
            ReadOnlyMemory<byte> chunk = fullArray.Slice(offset, chunkLength);
            int? lengthParameter = offset == 0 ? totalLength : null;

            byte status = await SendFragmentAsync(transceive, pool, chunk, offset, lengthParameter, token, protocolId, cancellationToken).ConfigureAwait(false);
            if(!WellKnownCtapStatusCodes.IsOk(status))
            {
                throw new CtapCommandException(status);
            }

            offset += chunkLength;
        }
    }


    /// <summary>
    /// Reads the ENTIRE stored serialized large-blob array over <paramref name="transceive"/>'s real
    /// transport via the platform read flow (CTAP 2.3, line 7699): repeated <c>get</c> requests each
    /// updating <c>offset</c> to the amount read so far, stopping at the first short (or empty) fragment,
    /// then confirming the platform's own trailing-hash check.
    /// </summary>
    /// <param name="transceive">The transport-neutral CTAP2 request/response exchange.</param>
    /// <param name="pool">The memory pool every allocation uses.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The complete, hash-confirmed serialized large-blob array bytes.</returns>
    /// <exception cref="CtapCommandException">A <c>get</c> request returned a non-success status.</exception>
    /// <exception cref="Fido2FormatException">The read-back array's trailing hash does not match its own preceding bytes (line 7699's own MUST).</exception>
    public static async Task<byte[]> ReadEntireSerializedArrayAsync(Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        var accumulated = new List<byte>();
        int offset = 0;
        while(true)
        {
            var request = new CtapLargeBlobsRequest(Get: CtapAuthenticatorState.MaxFragmentLength, Offset: offset);
            byte[] envelope = CtapWaveLargeBlobsFixtures.BuildEnvelope(request);
            using PooledMemory response = await transceive(envelope, pool, cancellationToken).ConfigureAwait(false);
            byte status = response.AsReadOnlySpan()[0];
            if(!WellKnownCtapStatusCodes.IsOk(status))
            {
                throw new CtapCommandException(status);
            }

            CtapLargeBlobsResponse decoded = CtapLargeBlobsResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
            accumulated.AddRange(decoded.Config.Span.ToArray());
            offset += decoded.Config.Length;
            if(decoded.Config.Length < CtapAuthenticatorState.MaxFragmentLength)
            {
                break;
            }
        }

        byte[] fullArray = [.. accumulated];
        ConfirmTrailingHash(fullArray, pool);

        return fullArray;
    }


    /// <summary>
    /// Compresses, encrypts, frames, and writes a single-entry serialized large-blob array carrying
    /// <paramref name="opaqueData"/> under <paramref name="largeBlobKey"/> — the composed §6.10.4/6.10.5
    /// platform write story (DEFLATE-compress, then AES-256-GCM-encrypt, then CBOR-frame with the
    /// trailing hash, then multi-fragment <c>set</c>) end to end over the real transport.
    /// </summary>
    /// <param name="transceive">The transport-neutral CTAP2 request/response exchange.</param>
    /// <param name="pool">The memory pool every allocation uses.</param>
    /// <param name="opaqueData">The plaintext opaque large-blob data to store.</param>
    /// <param name="largeBlobKey">The credential's 32-byte <c>largeBlobKey</c>.</param>
    /// <param name="fragmentLength">The per-fragment chunk size the write is split into.</param>
    /// <param name="token">The authenticating <c>pinUvAuthToken</c>, or <see langword="null"/> for a tokenless write.</param>
    /// <param name="protocolId">Which PIN/UV auth protocol <paramref name="token"/> was issued under.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    public static async Task WriteEncryptedEntryAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, ReadOnlyMemory<byte> opaqueData, ReadOnlyMemory<byte> largeBlobKey, int fragmentLength,
        byte[]? token, CtapPinUvAuthProtocolId protocolId, CancellationToken cancellationToken)
    {
        byte[] compressed = DeflateCompress(opaqueData.Span);
        (byte[] ciphertextWithTag, byte[] nonce) = await EncryptEntryAsync(compressed, largeBlobKey, opaqueData.Length, pool, cancellationToken).ConfigureAwait(false);
        byte[] serializedArray = BuildSerializedArrayWithSingleEntry(ciphertextWithTag, nonce, opaqueData.Length, pool);

        await WriteSerializedArrayAsync(transceive, pool, serializedArray, fragmentLength, token, protocolId, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Reads back, decodes, decrypts, and decompresses the single entry <see cref="WriteEncryptedEntryAsync"/>
    /// wrote — the composed §6.10.4 platform read story end to end over the real transport.
    /// </summary>
    /// <param name="transceive">The transport-neutral CTAP2 request/response exchange.</param>
    /// <param name="pool">The memory pool every allocation uses.</param>
    /// <param name="largeBlobKey">The credential's 32-byte <c>largeBlobKey</c>.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The recovered plaintext opaque large-blob data.</returns>
    public static async Task<byte[]> ReadAndDecryptEntryAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, ReadOnlyMemory<byte> largeBlobKey, CancellationToken cancellationToken)
    {
        byte[] serializedArray = await ReadEntireSerializedArrayAsync(transceive, pool, cancellationToken).ConfigureAwait(false);
        (byte[] ciphertextWithTag, byte[] nonce, int origSize) = DecodeSerializedArraySingleEntry(serializedArray);
        byte[] compressed = await DecryptEntryAsync(ciphertextWithTag, nonce, origSize, largeBlobKey, pool, cancellationToken).ConfigureAwait(false);

        return DeflateDecompressExact(compressed, origSize);
    }


    /// <summary>
    /// Confirms <paramref name="serializedArray"/>'s trailing 16 bytes equal <c>LEFT(SHA-256(preceding
    /// bytes), 16)</c> — the platform read flow's own confirmation step (CTAP 2.3, line 7699).
    /// </summary>
    /// <param name="serializedArray">The complete serialized large-blob array bytes.</param>
    /// <param name="pool">The memory pool the digest computation allocates from.</param>
    /// <exception cref="Fido2FormatException">The trailing hash does not match.</exception>
    private static void ConfirmTrailingHash(byte[] serializedArray, MemoryPool<byte> pool)
    {
        ReadOnlySpan<byte> precedingBytes = serializedArray.AsSpan(0, serializedArray.Length - TrailingHashLength);
        ReadOnlySpan<byte> trailingHash = serializedArray.AsSpan(serializedArray.Length - TrailingHashLength);

        using DigestValue digest = CryptographicKeyEvents.ComputeDigest(precedingBytes, Sha256Length, CryptoTags.Sha256Digest, pool);
        if(!digest.AsReadOnlySpan()[..TrailingHashLength].SequenceEqual(trailingHash))
        {
            throw new Fido2FormatException("The read-back serialized large-blob array's trailing hash does not match its own preceding bytes (CTAP 2.3, line 7699).");
        }
    }
}
