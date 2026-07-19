using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using System.Threading.Tasks;
using Lumoin.Base;
using Verifiable.Cesr;
using Verifiable.Cesr.Streaming;
using Verifiable.Cesr.Text;

namespace Verifiable.Tests.Cesr;

/// <summary>
/// Tests for <see cref="CesrStreamReader"/> — reading a CESR stream off a <see cref="PipeReader"/> as top-level
/// items in both the binary (qb2) and text (qb64) domains. A stream is minted with the codecs (a genus/version
/// counter followed by a <c>-V</c> attachment group framing real primitives), then read back: the reader must
/// yield the genus/version modifier and the framed group, the group body must be exactly the framed primitives,
/// and the framing must survive a byte-at-a-time segmented buffer and an incrementally written pipe
/// (back-pressure).
/// </summary>
[TestClass]
internal sealed class CesrStreamReaderTests
{
    private static readonly byte[] PublicKeyRaw = Convert.FromHexString("0ff9dafee5024209554babba1e341af32c637fcaec9e3e65d568ecda03db1ce6");
    private static readonly byte[] SaltRaw = Convert.FromHexString("3f033eef724684dfcdc01ceb16d49d4d");


    /// <summary>
    /// A single contiguous buffer round-trips: genus/version, then the framed group whose body is the two primitives.
    /// </summary>
    [TestMethod]
    public async Task ReadsGenusAndFramedGroupFromContiguousBuffer()
    {
        byte[] keyBytes = PrimitiveBytes("D", PublicKeyRaw);
        byte[] saltBytes = PrimitiveBytes("0A", SaltRaw);
        byte[] body = [.. keyBytes, .. saltBytes];
        byte[] stream = BuildStream(body);

        List<CapturedToken> tokens = await ReadAllAsync(PipeReader.Create(new ReadOnlySequence<byte>(stream)));

        AssertTokens(tokens, body, keyBytes.Length);
    }


    /// <summary>
    /// The same stream split into one-byte segments parses identically, exercising the cross-segment header and
    /// body copies.
    /// </summary>
    [TestMethod]
    public async Task ReadsFromByteAtATimeSegmentedBuffer()
    {
        byte[] keyBytes = PrimitiveBytes("D", PublicKeyRaw);
        byte[] saltBytes = PrimitiveBytes("0A", SaltRaw);
        byte[] body = [.. keyBytes, .. saltBytes];
        byte[] stream = BuildStream(body);

        List<CapturedToken> tokens = await ReadAllAsync(PipeReader.Create(Segment(stream, chunkSize: 1)));

        AssertTokens(tokens, body, keyBytes.Length);
    }


    /// <summary>
    /// A pipe written incrementally (the group split across two flushes) parses identically: the reader applies
    /// back-pressure until the whole group is buffered.
    /// </summary>
    [TestMethod]
    public async Task ReadsFromIncrementallyWrittenPipe()
    {
        byte[] keyBytes = PrimitiveBytes("D", PublicKeyRaw);
        byte[] saltBytes = PrimitiveBytes("0A", SaltRaw);
        byte[] body = [.. keyBytes, .. saltBytes];
        byte[] stream = BuildStream(body);

        var pipe = new Pipe();
        ValueTask writing = WriteInHalvesAsync(pipe.Writer, stream);
        List<CapturedToken> tokens = await ReadAllAsync(pipe.Reader);
        await writing;

        AssertTokens(tokens, body, keyBytes.Length);
    }


    /// <summary>
    /// A stream whose trailing group body is short is reported as truncated rather than yielding a partial group.
    /// </summary>
    [TestMethod]
    public async Task RejectsTruncatedTrailingGroup()
    {
        byte[] keyBytes = PrimitiveBytes("D", PublicKeyRaw);
        byte[] body = keyBytes;
        byte[] stream = BuildStream(body);
        byte[] truncated = stream[..^3];

        await Assert.ThrowsExactlyAsync<CesrFormatException>(async () =>
            await ReadAllAsync(PipeReader.Create(new ReadOnlySequence<byte>(truncated))));
    }


    /// <summary>
    /// A leading <c>{</c> routes to the interleaved non-native path, and a short JSON fragment with no complete
    /// version-string-framed serialization is rejected (here as a truncated stream, since the fragment carries no
    /// version string and the stream then completes). The distinct "unsupported top-level item" selector branch is
    /// covered by <see cref="CesrHardeningTests.RejectsUnsupportedTopLevelStreamItemInBothDomains"/>.
    /// </summary>
    [TestMethod]
    public async Task RejectsUnsupportedTopLevelItem()
    {
        byte[] json = "{\"v\":\"x\"}"u8.ToArray();

        await Assert.ThrowsExactlyAsync<CesrFormatException>(async () =>
            await ReadAllAsync(PipeReader.Create(new ReadOnlySequence<byte>(json))));
    }


    /// <summary>
    /// A single contiguous text (qb64) buffer round-trips: genus/version, then the framed group whose body is
    /// the two primitives as their qb64 characters.
    /// </summary>
    [TestMethod]
    public async Task ReadsTextGenusAndFramedGroupFromContiguousBuffer()
    {
        byte[] keyChars = PrimitiveTextBytes("D", PublicKeyRaw);
        byte[] saltChars = PrimitiveTextBytes("0A", SaltRaw);
        byte[] body = [.. keyChars, .. saltChars];
        byte[] stream = BuildTextStream(body);

        List<CapturedToken> tokens = await ReadAllTextAsync(PipeReader.Create(new ReadOnlySequence<byte>(stream)));

        AssertTextTokens(tokens, body, keyChars.Length);
    }


    /// <summary>
    /// The same text stream split into one-character segments parses identically, exercising the cross-segment
    /// header and body copies.
    /// </summary>
    [TestMethod]
    public async Task ReadsTextFromByteAtATimeSegmentedBuffer()
    {
        byte[] keyChars = PrimitiveTextBytes("D", PublicKeyRaw);
        byte[] saltChars = PrimitiveTextBytes("0A", SaltRaw);
        byte[] body = [.. keyChars, .. saltChars];
        byte[] stream = BuildTextStream(body);

        List<CapturedToken> tokens = await ReadAllTextAsync(PipeReader.Create(Segment(stream, chunkSize: 1)));

        AssertTextTokens(tokens, body, keyChars.Length);
    }


    /// <summary>
    /// A text pipe written incrementally (the group split across two flushes) parses identically: the reader
    /// applies back-pressure until the whole group is buffered.
    /// </summary>
    [TestMethod]
    public async Task ReadsTextFromIncrementallyWrittenPipe()
    {
        byte[] keyChars = PrimitiveTextBytes("D", PublicKeyRaw);
        byte[] saltChars = PrimitiveTextBytes("0A", SaltRaw);
        byte[] body = [.. keyChars, .. saltChars];
        byte[] stream = BuildTextStream(body);

        var pipe = new Pipe();
        ValueTask writing = WriteInHalvesAsync(pipe.Writer, stream);
        List<CapturedToken> tokens = await ReadAllTextAsync(pipe.Reader);
        await writing;

        AssertTextTokens(tokens, body, keyChars.Length);
    }


    /// <summary>
    /// A text stream whose trailing group body is short is reported as truncated rather than yielding a partial group.
    /// </summary>
    [TestMethod]
    public async Task RejectsTruncatedTrailingTextGroup()
    {
        byte[] body = PrimitiveTextBytes("D", PublicKeyRaw);
        byte[] stream = BuildTextStream(body);
        byte[] truncated = stream[..^4];

        await Assert.ThrowsExactlyAsync<CesrFormatException>(async () =>
            await ReadAllTextAsync(PipeReader.Create(new ReadOnlySequence<byte>(truncated))));
    }


    /// <summary>
    /// A text-domain op code (the <c>_</c> selector) at the top level is rejected as not yet supported, distinct
    /// from an unsupported non-count item.
    /// </summary>
    [TestMethod]
    public async Task RejectsTextOpCode()
    {
        byte[] opCode = "_AAB"u8.ToArray();

        await Assert.ThrowsExactlyAsync<CesrFormatException>(async () =>
            await ReadAllTextAsync(PipeReader.Create(new ReadOnlySequence<byte>(opCode))));
    }


    /// <summary>
    /// A JSON body (with a version 2.XX version string) interleaved between a genus/version code and a count
    /// group in a text stream is yielded whole as a non-native token, with the surrounding CESR items intact.
    /// </summary>
    [TestMethod]
    public async Task ReadsInterleavedJsonInTextStream()
    {
        byte[] json = JsonBodyV2();
        byte[] keyChars = PrimitiveTextBytes("D", PublicKeyRaw);
        byte[] genus = CountCodeTextBytes("-_AAA", CesrCountCodeTables.PackVersion(2, 0));
        byte[] counter = CountCodeTextBytes("-V", keyChars.Length / 4);
        byte[] stream = [.. genus, .. json, .. counter, .. keyChars];

        List<CapturedToken> tokens = await ReadAllTextAsync(PipeReader.Create(new ReadOnlySequence<byte>(stream)));

        AssertInterleaved(tokens, json, CesrDomain.Text, keyChars);
    }


    /// <summary>
    /// The same JSON body interleaved in a binary stream is yielded identically (its serialization is the same
    /// bytes in either CESR domain), and the following binary count group still parses even though the JSON body
    /// is not 24-bit aligned.
    /// </summary>
    [TestMethod]
    public async Task ReadsInterleavedJsonInBinaryStream()
    {
        byte[] json = JsonBodyV2();
        byte[] keyBytes = PrimitiveBytes("D", PublicKeyRaw);
        byte[] genus = CountCodeBytes("-_AAA", CesrCountCodeTables.PackVersion(2, 0));
        byte[] counter = CountCodeBytes("-V", keyBytes.Length / 3);
        byte[] stream = [.. genus, .. json, .. counter, .. keyBytes];

        List<CapturedToken> tokens = await ReadAllAsync(PipeReader.Create(new ReadOnlySequence<byte>(stream)));

        AssertInterleaved(tokens, json, CesrDomain.Binary, keyBytes);
    }


    /// <summary>
    /// The interleaved JSON body survives a byte-at-a-time pipe: the reader applies back-pressure until first the
    /// version string and then the whole serialization is buffered.
    /// </summary>
    [TestMethod]
    public async Task ReadsInterleavedJsonFromByteAtATimeStream()
    {
        byte[] json = JsonBodyV2();
        byte[] keyChars = PrimitiveTextBytes("D", PublicKeyRaw);
        byte[] genus = CountCodeTextBytes("-_AAA", CesrCountCodeTables.PackVersion(2, 0));
        byte[] counter = CountCodeTextBytes("-V", keyChars.Length / 4);
        byte[] stream = [.. genus, .. json, .. counter, .. keyChars];

        List<CapturedToken> tokens = await ReadAllTextAsync(PipeReader.Create(Segment(stream, chunkSize: 1)));

        AssertInterleaved(tokens, json, CesrDomain.Text, keyChars);
    }


    /// <summary>
    /// A standalone JSON body framed with a legacy version 1.XX version string is read as a non-native token.
    /// </summary>
    [TestMethod]
    public async Task ReadsLegacyVersion1JsonBody()
    {
        byte[] json = JsonBodyV1();

        List<CapturedToken> tokens = await ReadAllTextAsync(PipeReader.Create(new ReadOnlySequence<byte>(json)));

        Assert.HasCount(1, tokens);
        Assert.AreEqual(CesrTokenKind.NonNative, tokens[0].Kind);
        Assert.AreEqual(CesrSerializationKind.Json, tokens[0].Serialization);
        Assert.AreSequenceEqual(json, tokens[0].Body, "The whole serialization is yielded as the body.");
    }


    /// <summary>
    /// A non-native item whose leading bytes contain no version string is rejected rather than scanned without end.
    /// </summary>
    [TestMethod]
    public async Task RejectsNonNativeWithoutVersionString()
    {
        byte[] noVersionString = Encoding.ASCII.GetBytes("{\"x\":\"" + new string('a', 80) + "\"}");

        await Assert.ThrowsExactlyAsync<CesrFormatException>(async () =>
            await ReadAllTextAsync(PipeReader.Create(new ReadOnlySequence<byte>(noVersionString))));
    }


    private static void AssertInterleaved(List<CapturedToken> tokens, byte[] expectedJson, CesrDomain domain, byte[] expectedGroupBody)
    {
        Assert.HasCount(3, tokens, "The stream has a genus/version modifier, an interleaved JSON body, and a count group.");

        Assert.AreEqual(CesrTokenKind.GenusVersion, tokens[0].Kind);

        Assert.AreEqual(CesrTokenKind.NonNative, tokens[1].Kind);
        Assert.AreEqual(CesrSerializationKind.Json, tokens[1].Serialization, "The interleaved body is JSON.");
        Assert.AreEqual(domain, tokens[1].Domain, "The non-native token records the surrounding stream's domain.");
        Assert.AreSequenceEqual(expectedJson, tokens[1].Body, "The whole JSON serialization is yielded as the body.");

        Assert.AreEqual(CesrTokenKind.CountGroup, tokens[2].Kind);
        Assert.AreSequenceEqual(expectedGroupBody, tokens[2].Body, "The count group after the JSON body still parses.");
    }


    private static void AssertTokens(List<CapturedToken> tokens, byte[] expectedBody, int firstPrimitiveLength)
    {
        Assert.HasCount(2, tokens, "The stream has a genus/version modifier and one framed group.");

        Assert.AreEqual(CesrTokenKind.GenusVersion, tokens[0].Kind);
        Assert.AreEqual(CesrDomain.Binary, tokens[0].Domain, "A binary-domain read yields binary-domain tokens.");
        Assert.AreEqual("-_AAA", tokens[0].Code, "The genus is the KERI/ACDC genus.");
        Assert.AreEqual((2, 0), tokens[0].Version, "The version counter is 2.00.");

        Assert.AreEqual(CesrTokenKind.CountGroup, tokens[1].Kind);
        Assert.AreEqual(CesrDomain.Binary, tokens[1].Domain);
        Assert.AreEqual("-V", tokens[1].Code, "The group is an attachment group.");
        Assert.AreEqual(expectedBody.Length / 3, tokens[1].Count, "The count is the group body's triplet count.");
        Assert.AreSequenceEqual(expectedBody, tokens[1].Body, "The framed body is exactly the concatenated primitives.");

        //The body descends into the framed primitives (the test owns the per-primitive lengths).
        using(CesrParsedPrimitive key = CesrPrimitiveCodec.DecodeBinary(tokens[1].Body.AsSpan(0, firstPrimitiveLength), BaseMemoryPool.Shared))
        {
            Assert.AreEqual("D", key.Code);
            Assert.AreEqual(Convert.ToHexStringLower(PublicKeyRaw), Convert.ToHexStringLower(key.Raw));
        }

        using(CesrParsedPrimitive salt = CesrPrimitiveCodec.DecodeBinary(tokens[1].Body.AsSpan(firstPrimitiveLength), BaseMemoryPool.Shared))
        {
            Assert.AreEqual("0A", salt.Code);
            Assert.AreEqual(Convert.ToHexStringLower(SaltRaw), Convert.ToHexStringLower(salt.Raw));
        }
    }


    private static void AssertTextTokens(List<CapturedToken> tokens, byte[] expectedBody, int firstPrimitiveChars)
    {
        Assert.HasCount(2, tokens, "The stream has a genus/version modifier and one framed group.");

        Assert.AreEqual(CesrTokenKind.GenusVersion, tokens[0].Kind);
        Assert.AreEqual(CesrDomain.Text, tokens[0].Domain, "A text-domain read yields text-domain tokens.");
        Assert.AreEqual("-_AAA", tokens[0].Code, "The genus is the KERI/ACDC genus.");
        Assert.AreEqual((2, 0), tokens[0].Version, "The version counter is 2.00.");

        Assert.AreEqual(CesrTokenKind.CountGroup, tokens[1].Kind);
        Assert.AreEqual(CesrDomain.Text, tokens[1].Domain);
        Assert.AreEqual("-V", tokens[1].Code, "The group is an attachment group.");
        Assert.AreEqual(expectedBody.Length / 4, tokens[1].Count, "The count is the group body's quadlet count.");
        Assert.AreSequenceEqual(expectedBody, tokens[1].Body, "The framed body is exactly the concatenated primitives as qb64 characters.");

        //The body descends into the framed primitives, decoded from their qb64 text (the test owns the per-primitive lengths).
        string bodyText = Encoding.ASCII.GetString(tokens[1].Body);
        using(CesrParsedPrimitive key = CesrPrimitiveCodec.DecodeText(bodyText.AsSpan(0, firstPrimitiveChars), BaseMemoryPool.Shared))
        {
            Assert.AreEqual("D", key.Code);
            Assert.AreEqual(Convert.ToHexStringLower(PublicKeyRaw), Convert.ToHexStringLower(key.Raw));
        }

        using(CesrParsedPrimitive salt = CesrPrimitiveCodec.DecodeText(bodyText.AsSpan(firstPrimitiveChars), BaseMemoryPool.Shared))
        {
            Assert.AreEqual("0A", salt.Code);
            Assert.AreEqual(Convert.ToHexStringLower(SaltRaw), Convert.ToHexStringLower(salt.Raw));
        }
    }


    private static Task<List<CapturedToken>> ReadAllAsync(PipeReader reader) =>
        CaptureAsync(reader, CesrStreamReader.ReadBinaryAsync(reader, BaseMemoryPool.Shared));


    private static Task<List<CapturedToken>> ReadAllTextAsync(PipeReader reader) =>
        CaptureAsync(reader, CesrStreamReader.ReadTextAsync(reader, BaseMemoryPool.Shared));


    private static async Task<List<CapturedToken>> CaptureAsync(PipeReader reader, IAsyncEnumerable<CesrToken> source)
    {
        var captured = new List<CapturedToken>();
        await foreach(CesrToken token in source)
        {
            captured.Add(new CapturedToken(token.Kind, token.Domain, token.Serialization, token.Code, token.Count, token.Version, token.Body.ToArray()));
            token.Dispose();
        }

        await reader.CompleteAsync();

        return captured;
    }


    private static byte[] BuildStream(byte[] body)
    {
        byte[] genus = CountCodeBytes("-_AAA", CesrCountCodeTables.PackVersion(2, 0));
        byte[] counter = CountCodeBytes("-V", body.Length / 3);

        return [.. genus, .. counter, .. body];
    }


    private static byte[] BuildTextStream(byte[] body)
    {
        byte[] genus = CountCodeTextBytes("-_AAA", CesrCountCodeTables.PackVersion(2, 0));
        byte[] counter = CountCodeTextBytes("-V", body.Length / 4);

        return [.. genus, .. counter, .. body];
    }


    private static byte[] CountCodeBytes(string code, int count)
    {
        int byteLength = CesrCountCodeCodec.EncodeText(code, count).Length / 4 * 3;
        using IMemoryOwner<byte> owner = CesrCountCodeCodec.EncodeBinary(code, count, BaseMemoryPool.Shared);

        return owner.Memory.Span[..byteLength].ToArray();
    }


    private static byte[] CountCodeTextBytes(string code, int count) => Encoding.ASCII.GetBytes(CesrCountCodeCodec.EncodeText(code, count));


    private static byte[] PrimitiveBytes(string code, byte[] raw)
    {
        int byteLength = CesrPrimitiveCodec.EncodeText(code, raw).Length * 3 / 4;
        using IMemoryOwner<byte> owner = CesrPrimitiveCodec.EncodeBinary(code, raw, BaseMemoryPool.Shared);

        return owner.Memory.Span[..byteLength].ToArray();
    }


    private static byte[] PrimitiveTextBytes(string code, byte[] raw) => Encoding.ASCII.GetBytes(CesrPrimitiveCodec.EncodeText(code, raw));


    /// <summary>
    /// Mints a JSON body whose first field is a version 2.XX version string (<c>PPPPMmmGggKKKKBBBB.</c>) with the
    /// <c>BBBB</c> length part set to the body's actual base-64 byte length.
    /// </summary>
    private static byte[] JsonBodyV2()
    {
        const string prefix = "{\"v\":\"KERICAACAAJSON";
        const string suffix = ".\",\"d\":\"hello\"}";
        const int lengthSize = 4;
        int total = prefix.Length + lengthSize + suffix.Length;
        string size = CesrTextCodec.IntToBase64(total, lengthSize);

        return Encoding.ASCII.GetBytes(prefix + size + suffix);
    }


    /// <summary>
    /// Mints a JSON body whose first field is a legacy version 1.XX version string (<c>PPPPvvKKKKllllll_</c>) with
    /// the <c>llllll</c> length part set to the body's actual hexadecimal byte length.
    /// </summary>
    private static byte[] JsonBodyV1()
    {
        const string prefix = "{\"v\":\"KERI10JSON";
        const string suffix = "_\",\"d\":\"hi\"}";
        const int lengthSize = 6;
        int total = prefix.Length + lengthSize + suffix.Length;
        string size = total.ToString("x6", System.Globalization.CultureInfo.InvariantCulture);

        return Encoding.ASCII.GetBytes(prefix + size + suffix);
    }


    private static async ValueTask WriteInHalvesAsync(PipeWriter writer, byte[] data)
    {
        int half = data.Length / 2;
        await writer.WriteAsync(data.AsMemory(0, half));
        await Task.Yield();
        await writer.WriteAsync(data.AsMemory(half));
        await writer.CompleteAsync();
    }


    private static ReadOnlySequence<byte> Segment(byte[] data, int chunkSize)
    {
        var first = new MemorySegment(data.AsMemory(0, Math.Min(chunkSize, data.Length)));
        MemorySegment last = first;
        for(int offset = chunkSize; offset < data.Length; offset += chunkSize)
        {
            last = last.Append(data.AsMemory(offset, Math.Min(chunkSize, data.Length - offset)));
        }

        return new ReadOnlySequence<byte>(first, 0, last, last.Memory.Length);
    }


    /// <summary>
    /// The captured contents of a token, taken before the token is disposed.
    /// </summary>
    private sealed record CapturedToken(CesrTokenKind Kind, CesrDomain Domain, CesrSerializationKind Serialization, string Code, int Count, (int Major, int Minor)? Version, byte[] Body);


    /// <summary>
    /// A linked sequence segment used to build a multi-segment <see cref="ReadOnlySequence{T}"/> for the tests.
    /// </summary>
    private sealed class MemorySegment: ReadOnlySequenceSegment<byte>
    {
        public MemorySegment(ReadOnlyMemory<byte> memory)
        {
            Memory = memory;
        }


        public MemorySegment Append(ReadOnlyMemory<byte> memory)
        {
            var segment = new MemorySegment(memory) { RunningIndex = RunningIndex + Memory.Length };
            Next = segment;

            return segment;
        }
    }
}
