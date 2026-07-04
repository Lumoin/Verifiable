using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using Verifiable.Cesr.Text;

namespace Verifiable.Cesr.Streaming;

/// <summary>
/// Reads a CESR stream from a <see cref="PipeReader"/> as a sequence of top-level items. The reader is built on
/// the low-level pipe API over <see cref="ReadOnlySequence{T}"/> (never the <c>System.IO.Stream</c> APIs): it
/// pulls buffered bytes, parses whole top-level items, and reports back how much it consumed so the pipe can
/// release them, applying back-pressure when an item is not yet fully buffered.
/// </summary>
/// <remarks>
/// <para>
/// A CESR stream is self-describing at the top level — per the CESR specification's
/// <see href="https://trustoverip.github.io/kswg-cesr-specification/#stream-parsing-rules">Stream parsing rules</see>
/// the leading tritet says whether the next item is a count code, an op code, or an interleaved non-native
/// mapping. This reader yields count codes in either concrete domain: a genus/version code on its own, or a
/// count code together with the group body it frames (<see cref="ReadBinaryAsync"/> for the binary domain,
/// <see cref="ReadTextAsync"/> for the text domain). A code nested inside a group (a primitive or indexed
/// signature) is ambiguous without the enclosing group's semantics, so the group body is handed back whole for
/// a semantics-aware consumer to descend into rather than being tokenized here.
/// </para>
/// </remarks>
public static class CesrStreamReader
{
    /// <summary>
    /// Tries to parse one whole top-level item from the front of the buffer. Returns <see langword="false"/> when
    /// the item is not yet fully buffered (the caller must read more); throws when the item is malformed or
    /// unsupported.
    /// </summary>
    private delegate bool TryReadTopLevelItem(ReadOnlySequence<byte> buffer, MemoryPool<byte> pool, out CesrToken token, out SequencePosition consumed);


    /// <summary>
    /// Reads the binary-domain (qb2) top-level items of a CESR stream.
    /// </summary>
    /// <param name="reader">The pipe to read from. The caller owns its lifetime and completes it.</param>
    /// <param name="pool">The memory pool the framed group bodies are rented from.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>
    /// The top-level items in order. Each <see cref="CesrToken"/> that owns a body MUST be disposed by the
    /// consumer to return its buffer to the pool.
    /// </returns>
    /// <exception cref="CesrFormatException">The stream is malformed, truncated, or carries an unsupported top-level item.</exception>
    public static IAsyncEnumerable<CesrToken> ReadBinaryAsync(
        PipeReader reader,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(pool);

        return ReadAsync(reader, pool, TryReadTopLevelBinary, cancellationToken);
    }


    /// <summary>
    /// Reads the text-domain (qb64) top-level items of a CESR stream. The framed group body of each
    /// <see cref="CesrTokenKind.CountGroup"/> is handed back as its qb64 characters (one ASCII byte each).
    /// </summary>
    /// <param name="reader">The pipe to read from. The caller owns its lifetime and completes it.</param>
    /// <param name="pool">The memory pool the framed group bodies are rented from.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>
    /// The top-level items in order. Each <see cref="CesrToken"/> that owns a body MUST be disposed by the
    /// consumer to return its buffer to the pool.
    /// </returns>
    /// <exception cref="CesrFormatException">The stream is malformed, truncated, or carries an unsupported top-level item.</exception>
    public static IAsyncEnumerable<CesrToken> ReadTextAsync(
        PipeReader reader,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(pool);

        return ReadAsync(reader, pool, TryReadTopLevelText, cancellationToken);
    }


    /// <summary>
    /// The shared pipe pump: pulls buffered bytes, hands the front of the buffer to the domain-specific parser,
    /// and advances or applies back-pressure per its verdict. Both domains differ only in how a single item is
    /// recognized, so the loop, the consumed/examined bookkeeping, and the truncation rule are shared here.
    /// </summary>
    private static async IAsyncEnumerable<CesrToken> ReadAsync(
        PipeReader reader,
        MemoryPool<byte> pool,
        TryReadTopLevelItem tryReadTopLevel,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        while(true)
        {
            ReadResult result = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            ReadOnlySequence<byte> buffer = result.Buffer;

            if(tryReadTopLevel(buffer, pool, out CesrToken token, out SequencePosition consumed))
            {
                reader.AdvanceTo(consumed);
                yield return token;
                continue;
            }

            //The whole leading item is not yet buffered: nothing consumed, everything examined, so the next
            //read waits for more data.
            reader.AdvanceTo(buffer.Start, buffer.End);

            if(result.IsCompleted)
            {
                if(!buffer.IsEmpty)
                {
                    throw new CesrFormatException("Truncated CESR stream: a trailing item is incomplete.");
                }

                yield break;
            }
        }
    }


    /// <summary>
    /// Tries to parse one whole binary-domain (qb2) top-level item from the front of the buffer. Returns
    /// <see langword="false"/> when the item is not yet fully buffered (the caller must read more); throws when
    /// the item is malformed or unsupported.
    /// </summary>
    private static bool TryReadTopLevelBinary(ReadOnlySequence<byte> buffer, MemoryPool<byte> pool, out CesrToken token, out SequencePosition consumed)
    {
        token = default;
        consumed = buffer.Start;

        if(buffer.IsEmpty)
        {
            return false;
        }

        //The two selector sextets need at most the first two bytes; the whole count code is at most six bytes.
        Span<byte> header = stackalloc byte[6];
        int headerLength = CopyUpTo(buffer, header);
        if(headerLength < 2)
        {
            return false;
        }

        if(IsNonNativeStart(header[0]))
        {
            return TryReadNonNative(buffer, CesrDomain.Binary, pool, out token, out consumed);
        }

        int firstSextet = header[0] >> 2;
        char first = Base64UrlAlphabet.CharOf(firstSextet);
        if(first != CesrCountCodeTables.CountSelector)
        {
            throw new CesrFormatException(first == CesrCountCodeTables.OpCodeSelector
                ? "CESR op codes are not yet supported in stream reading."
                : "Unsupported top-level CESR stream item; only binary count codes are supported.");
        }

        int secondSextet = ((header[0] & 0x03) << 4) | (header[1] >> 4);
        char second = Base64UrlAlphabet.CharOf(secondSextet);
        CesrCountCodeSizing sizing = CesrCountCodeTables.SizingForSelector(first, second);
        int codeBytes = CesrTextCodec.CodeBinaryLength(sizing.FullSize);
        if(headerLength < codeBytes)
        {
            return false;
        }

        CesrParsedCountCode countCode = CesrCountCodeCodec.DecodeBinary(header[..codeBytes]);

        if(countCode.IsGenusVersion)
        {
            consumed = buffer.GetPosition(codeBytes);
            token = new CesrToken(CesrTokenKind.GenusVersion, CesrDomain.Binary, CesrSerializationKind.None, countCode.Code, countCode.Count, null, 0);

            return true;
        }

        long bodyBytes = countCode.BinaryByteCount;
        long total = codeBytes + bodyBytes;
        if(buffer.Length < total)
        {
            return false;
        }

        //The whole group is now buffered, so its size is bounded by the in-memory buffer and narrows to int
        //safely; a group larger than a single pooled buffer can hold cannot be framed, so it is rejected as
        //malformed rather than being allowed to overflow the narrowing. This is only reachable if that many bytes
        //were actually supplied, never from a lying count alone (which stays behind the length guard above).
        if(bodyBytes > Array.MaxLength)
        {
            throw new CesrFormatException($"A CESR count group frames {bodyBytes} bytes, more than can be held in one buffer.");
        }

        int bodyByteCount = (int)bodyBytes;
        IMemoryOwner<byte> bodyOwner = pool.Rent(Math.Max(bodyByteCount, 1));
        buffer.Slice(codeBytes, bodyByteCount).CopyTo(bodyOwner.Memory.Span[..bodyByteCount]);
        consumed = buffer.GetPosition(total);
        token = new CesrToken(CesrTokenKind.CountGroup, CesrDomain.Binary, CesrSerializationKind.None, countCode.Code, countCode.Count, bodyOwner, bodyByteCount);

        return true;
    }


    /// <summary>
    /// Tries to parse one whole text-domain (qb64) top-level item from the front of the buffer. Each qb64
    /// character is one ASCII byte, so the leading byte is the count selector directly (no sextet unpacking) and
    /// the framed body is handed back as its qb64 characters. Returns <see langword="false"/> when the item is
    /// not yet fully buffered (the caller must read more); throws when the item is malformed or unsupported.
    /// </summary>
    private static bool TryReadTopLevelText(ReadOnlySequence<byte> buffer, MemoryPool<byte> pool, out CesrToken token, out SequencePosition consumed)
    {
        token = default;
        consumed = buffer.Start;

        if(buffer.IsEmpty)
        {
            return false;
        }

        //A count code is at most eight characters (the large and genus/version codes), one ASCII byte each.
        Span<byte> header = stackalloc byte[8];
        int headerLength = CopyUpTo(buffer, header);
        if(headerLength < 2)
        {
            return false;
        }

        if(IsNonNativeStart(header[0]))
        {
            return TryReadNonNative(buffer, CesrDomain.Text, pool, out token, out consumed);
        }

        char first = (char)header[0];
        if(first != CesrCountCodeTables.CountSelector)
        {
            throw new CesrFormatException(first == CesrCountCodeTables.OpCodeSelector
                ? "CESR op codes are not yet supported in stream reading."
                : "Unsupported top-level CESR stream item; only text count codes are supported.");
        }

        char second = (char)header[1];
        CesrCountCodeSizing sizing = CesrCountCodeTables.SizingForSelector(first, second);
        int codeChars = sizing.FullSize;
        if(headerLength < codeChars)
        {
            return false;
        }

        Span<char> codeText = stackalloc char[8];
        for(int i = 0; i < codeChars; i++)
        {
            codeText[i] = (char)header[i];
        }

        CesrParsedCountCode countCode = CesrCountCodeCodec.DecodeText(codeText[..codeChars]);

        if(countCode.IsGenusVersion)
        {
            consumed = buffer.GetPosition(codeChars);
            token = new CesrToken(CesrTokenKind.GenusVersion, CesrDomain.Text, CesrSerializationKind.None, countCode.Code, countCode.Count, null, 0);

            return true;
        }

        long bodyChars = countCode.TextCharCount;
        long total = codeChars + bodyChars;
        if(buffer.Length < total)
        {
            return false;
        }

        //As in the binary domain: the group is fully buffered, so its size narrows to int safely, and a group
        //larger than a single pooled buffer can hold is rejected rather than overflowing the narrowing.
        if(bodyChars > Array.MaxLength)
        {
            throw new CesrFormatException($"A CESR count group frames {bodyChars} characters, more than can be held in one buffer.");
        }

        int bodyCharCount = (int)bodyChars;
        IMemoryOwner<byte> bodyOwner = pool.Rent(Math.Max(bodyCharCount, 1));
        buffer.Slice(codeChars, bodyCharCount).CopyTo(bodyOwner.Memory.Span[..bodyCharCount]);
        consumed = buffer.GetPosition(total);
        token = new CesrToken(CesrTokenKind.CountGroup, CesrDomain.Text, CesrSerializationKind.None, countCode.Code, countCode.Count, bodyOwner, bodyCharCount);

        return true;
    }


    /// <summary>
    /// The number of leading bytes scanned for the version string of an interleaved non-native serialization.
    /// The version string MUST be the first field, so it appears within a small, bounded prefix; this bound also
    /// caps the scan so a malformed item carrying no version string is rejected rather than scanned without end.
    /// </summary>
    private const int NonNativeVersionStringSearchLength = 64;


    /// <summary>
    /// Whether a leading byte begins an interleaved non-native (JSON, CBOR, or MGPK) serialization rather than
    /// native CESR framing, by its top-level starting tritet (its top three bits): per the CESR specification's
    /// <see href="https://trustoverip.github.io/kswg-cesr-specification/#stream-parsing-rules">Stream parsing
    /// rules</see> JSON is <c>0b011</c>, MGPK is <c>0b100</c> (FixMap) or <c>0b110</c> (Map16/Map32), and CBOR is
    /// <c>0b101</c>.
    /// </summary>
    private static bool IsNonNativeStart(byte first) => (first >> 5) is >= 0b011 and <= 0b110;


    /// <summary>
    /// Tries to read one whole interleaved non-native (JSON/CBOR/MGPK) serialization from the front of the
    /// buffer. The leading version string gives the serialization kind and total length, so the whole message is
    /// offloaded without deserializing it. Returns <see langword="false"/> when the version string or the whole
    /// serialization is not yet buffered; throws when the item carries no version string within the bounded
    /// prefix or declares a non-positive length.
    /// </summary>
    private static bool TryReadNonNative(ReadOnlySequence<byte> buffer, CesrDomain domain, MemoryPool<byte> pool, out CesrToken token, out SequencePosition consumed)
    {
        token = default;
        consumed = buffer.Start;

        int probeLength = (int)Math.Min(buffer.Length, NonNativeVersionStringSearchLength);
        Span<byte> probe = stackalloc byte[NonNativeVersionStringSearchLength];
        int copied = CopyUpTo(buffer, probe[..probeLength]);
        Span<char> chars = stackalloc char[NonNativeVersionStringSearchLength];
        int charCount = Encoding.ASCII.GetChars(probe[..copied], chars);

        if(!CesrVersionString.TryFind(chars[..charCount], out CesrSerializationKind kind, out int totalLength, out int matchStart))
        {
            //No version string yet. If the whole bounded prefix is buffered it cannot be the first field, so the
            //item is malformed; otherwise wait for more bytes.
            if(copied >= NonNativeVersionStringSearchLength)
            {
                throw new CesrFormatException("Interleaved non-native serialization has no version string in its leading bytes.");
            }

            return false;
        }

        //The version string MUST be the value of the leading version field. Locating it by shape alone would let a
        //version-string-shaped run inside a later field's value be mistaken for the framing and desynchronize the
        //message boundary, so confirm the field label immediately preceding it is the version field for the kind.
        if(!IsLeadingVersionField(probe[..copied], kind, matchStart))
        {
            throw new CesrFormatException("The version string of an interleaved CESR serialization is not the value of its leading version field.");
        }

        if(totalLength <= 0)
        {
            throw new CesrFormatException($"Interleaved non-native serialization declares a non-positive length of {totalLength}.");
        }

        if(buffer.Length < totalLength)
        {
            return false;
        }

        IMemoryOwner<byte> bodyOwner = pool.Rent(totalLength);
        buffer.Slice(0, totalLength).CopyTo(bodyOwner.Memory.Span[..totalLength]);
        consumed = buffer.GetPosition(totalLength);
        token = new CesrToken(CesrTokenKind.NonNative, domain, kind, string.Empty, 0, bodyOwner, totalLength);

        return true;
    }


    /// <summary>
    /// Whether the version string located at <paramref name="matchStart"/> is the value of the interleaved
    /// serialization's leading version field, verified by the field-label framing that must immediately precede it
    /// for the serialization kind: JSON opens with <c>{"v":"</c>, CBOR with the text key <c>v</c>
    /// (<c>0x61 0x76</c>), and MGPK with the fixstr key <c>v</c> (<c>0xA1 0x76</c>). KERI/ACDC serializations are
    /// canonical (no insignificant whitespace), so the JSON framing is an exact leading prefix.
    /// </summary>
    private static bool IsLeadingVersionField(ReadOnlySpan<byte> probe, CesrSerializationKind kind, int matchStart) => kind switch
    {
        CesrSerializationKind.Json => matchStart == "{\"v\":\""u8.Length && probe.StartsWith("{\"v\":\""u8),
        CesrSerializationKind.Cbor => matchStart >= 3 && probe[matchStart - 3] == 0x61 && probe[matchStart - 2] == 0x76,
        CesrSerializationKind.Mgpk => matchStart >= 3 && probe[matchStart - 3] == 0xA1 && probe[matchStart - 2] == 0x76,
        _ => false
    };


    /// <summary>
    /// Copies up to <paramref name="destination"/>'s length of bytes from the front of the sequence, returning
    /// the number copied (fewer than requested when the sequence is shorter).
    /// </summary>
    private static int CopyUpTo(ReadOnlySequence<byte> source, Span<byte> destination)
    {
        int written = 0;
        foreach(ReadOnlyMemory<byte> segment in source)
        {
            ReadOnlySpan<byte> span = segment.Span;
            int take = Math.Min(span.Length, destination.Length - written);
            span[..take].CopyTo(destination[written..]);
            written += take;
            if(written == destination.Length)
            {
                break;
            }
        }

        return written;
    }
}
