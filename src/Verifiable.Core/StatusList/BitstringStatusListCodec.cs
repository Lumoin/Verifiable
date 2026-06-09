using System;
using System.Buffers;
using System.Buffers.Text;
using System.IO;
using System.IO.Compression;
using Verifiable.Cryptography;

namespace Verifiable.Core.StatusList;

/// <summary>
/// Encodes and decodes the <c>encodedList</c> value of a W3C Bitstring Status List, the second
/// of the two status-list presentations over the shared bit core (the other being the IETF
/// <see cref="StatusListToken"/>).
/// </summary>
/// <remarks>
/// <para>
/// Per <see href="https://www.w3.org/TR/vc-bitstring-status-list/#bitstringstatuslistcredential">
/// W3C Bitstring Status List §2.2</see>, <c>credentialSubject.encodedList</c> is a
/// Multibase-encoded base64url (no padding) representation of the GZIP-compressed
/// [<see href="https://www.rfc-editor.org/rfc/rfc1952">RFC 1952</see>] bitstring, with the
/// first index at the left-most (most-significant) bit — hence
/// <see cref="BitOrder.MostSignificantFirst"/>. This is the layer at which the W3C and IETF
/// presentations diverge from the shared <see cref="StatusList"/> core: GZIP + Multibase here
/// versus DEFLATE/ZLIB + base64url for the IETF token, and most-significant-first packing here
/// versus least-significant-first there.
/// </para>
/// <para>
/// The Multibase prefix is <c>u</c> (<see cref="MultibaseAlgorithms.Base64Url"/>); unlike the
/// key-oriented <see cref="MultibaseSerializer"/>, no multicodec header is prepended — the
/// payload is the raw compressed bitstring.
/// </para>
/// <para>
/// The uncompressed bitstring MUST hold at least <see cref="MinimumEntries"/> entries (16 KB at
/// <c>statusSize</c> 1) for herd privacy (§2.2, §3.2). Arbitrary <c>statusSize</c> values are
/// constrained to those the byte-aligned core supports (1, 2, 4, 8); conforming processors MAY
/// support only size 1 (§1.3).
/// </para>
/// </remarks>
public static class BitstringStatusListCodec
{
    /// <summary>
    /// The minimum number of entries a conforming Bitstring Status List must hold, established
    /// by W3C Bitstring Status List §3.2 for herd privacy unless a lower bound is set by an
    /// ecosystem specification. At <c>statusSize</c> 1 this is 16 KB of bits.
    /// </summary>
    public const int MinimumEntries = 131_072;

    /// <summary>
    /// The minimum uncompressed byte length corresponding to <see cref="MinimumEntries"/> at
    /// <c>statusSize</c> 1 (16 KB).
    /// </summary>
    public const int MinimumByteLength = MinimumEntries / 8;


    /// <summary>
    /// Encodes a bitstring into the <c>encodedList</c> value: GZIP-compress the most-significant-first
    /// packed bytes, then Multibase base64url-encode (no padding) with a <c>u</c> prefix.
    /// </summary>
    /// <param name="bitstring">
    /// The status bitstring to encode. Must be packed <see cref="BitOrder.MostSignificantFirst"/>
    /// and hold at least <see cref="MinimumEntries"/> entries.
    /// </param>
    /// <param name="compressionLevel">
    /// The GZIP compression level. Defaults to <see cref="CompressionLevel.SmallestSize"/>, matching
    /// the specification's guidance to favor size (status lists are large, compressed once, cached,
    /// and served to many).
    /// </param>
    /// <returns>The Multibase base64url-encoded, GZIP-compressed bitstring.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="bitstring"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="bitstring"/> is not packed most-significant-first or holds
    /// fewer than <see cref="MinimumEntries"/> entries.
    /// </exception>
    public static string EncodeList(StatusList bitstring, CompressionLevel compressionLevel = CompressionLevel.SmallestSize)
    {
        ArgumentNullException.ThrowIfNull(bitstring);

        if(bitstring.BitOrder != BitOrder.MostSignificantFirst)
        {
            throw new ArgumentException(
                "A W3C Bitstring Status List must be packed most-significant-first; the supplied bitstring uses least-significant-first order.",
                nameof(bitstring));
        }

        if(bitstring.Capacity < MinimumEntries)
        {
            throw new ArgumentException(
                $"A W3C Bitstring Status List must hold at least {MinimumEntries} entries; the supplied bitstring holds {bitstring.Capacity}.",
                nameof(bitstring));
        }

        byte[] compressed = GzipCompress(bitstring.AsSpan(), compressionLevel);
        string payload = Base64Url.EncodeToString(compressed);

        return string.Create(payload.Length + 1, payload, static (span, state) =>
        {
            span[0] = MultibaseAlgorithms.Base64Url;
            state.CopyTo(span[1..]);
        });
    }


    /// <summary>
    /// Decodes an <c>encodedList</c> value into a bitstring: strip the Multibase <c>u</c> prefix,
    /// base64url-decode, GZIP-expand, and wrap the most-significant-first packed bytes.
    /// </summary>
    /// <param name="encodedList">The Multibase base64url-encoded, GZIP-compressed bitstring.</param>
    /// <param name="statusSize">
    /// The number of bits per status entry. Per the specification, absent <c>statusSize</c> is
    /// processed as <see cref="StatusListBitSize.OneBit"/>.
    /// </param>
    /// <param name="pool">The memory pool to allocate the expanded bitstring into.</param>
    /// <returns>A <see cref="StatusList"/> packed <see cref="BitOrder.MostSignificantFirst"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="encodedList"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="FormatException">Thrown when the value lacks the <c>u</c> Multibase prefix or is not valid base64url.</exception>
    /// <exception cref="InvalidDataException">Thrown when the payload is not valid GZIP data.</exception>
    public static StatusList DecodeList(string encodedList, StatusListBitSize statusSize, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(encodedList);
        ArgumentNullException.ThrowIfNull(pool);

        if(encodedList.Length < 1 || encodedList[0] != MultibaseAlgorithms.Base64Url)
        {
            throw new FormatException("encodedList must be Multibase base64url-encoded with a 'u' prefix.");
        }

        byte[] compressed = Base64Url.DecodeFromChars(encodedList.AsSpan(1));
        byte[] expanded = GzipDecompress(compressed);

        return StatusList.FromRaw(expanded, statusSize, pool, BitOrder.MostSignificantFirst);
    }


    private static byte[] GzipCompress(ReadOnlySpan<byte> data, CompressionLevel compressionLevel)
    {
        using var output = new MemoryStream();
        using(var gzip = new GZipStream(output, compressionLevel))
        {
            gzip.Write(data);
        }

        return output.ToArray();
    }


    private static byte[] GzipDecompress(ReadOnlySpan<byte> compressed)
    {
        using var input = new MemoryStream(compressed.ToArray());
        using var gzip = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gzip.CopyTo(output);

        return output.ToArray();
    }
}
