using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using System.Threading.Tasks;
using Lumoin.Base;
using Verifiable.Cesr;
using Verifiable.Cesr.Streaming;

namespace Verifiable.Tests.Cesr;

/// <summary>
/// Tests for <see cref="CesrStreamWriter"/> — writing a CESR stream into a <see cref="PipeWriter"/> in both the
/// binary (qb2) and text (qb64) domains. The primary tests are round trips through the shipped path: a stream
/// written with the writer (a genus/version counter then a <c>-V</c> group framing real primitives) is read back
/// with <see cref="CesrStreamReader"/> and must reproduce the genus/version modifier, the framed group, and the
/// exact body.
/// </summary>
[TestClass]
internal sealed class CesrStreamWriterTests
{
    private static readonly byte[] PublicKeyRaw = Convert.FromHexString("0ff9dafee5024209554babba1e341af32c637fcaec9e3e65d568ecda03db1ce6");
    private static readonly byte[] SaltRaw = Convert.FromHexString("3f033eef724684dfcdc01ceb16d49d4d");


    /// <summary>
    /// The test context.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A stream written with the writer reads back identically through the reader (writer/reader are inverses).
    /// </summary>
    [TestMethod]
    public async Task WriterOutputRoundTripsThroughTheReader()
    {
        byte[] keyBytes = PrimitiveBytes("D", PublicKeyRaw);
        byte[] saltBytes = PrimitiveBytes("0A", SaltRaw);
        byte[] body = [.. keyBytes, .. saltBytes];

        var pipe = new Pipe();
        CesrStreamWriter.WriteGenusVersion(pipe.Writer, "-_AAA", 2, 0);
        CesrStreamWriter.WriteGroup(pipe.Writer, "-V", body);
        await pipe.Writer.FlushAsync(TestContext.CancellationToken);
        await pipe.Writer.CompleteAsync();

        var tokens = new List<(CesrTokenKind Kind, string Code, int Count, (int, int)? Version, byte[] Body)>();
        await foreach(CesrToken token in CesrStreamReader.ReadBinaryAsync(pipe.Reader, BaseMemoryPool.Shared, TestContext.CancellationToken))
        {
            tokens.Add((token.Kind, token.Code, token.Count, token.Version, token.Body.ToArray()));
            token.Dispose();
        }

        await pipe.Reader.CompleteAsync();

        Assert.HasCount(2, tokens);
        Assert.AreEqual(CesrTokenKind.GenusVersion, tokens[0].Kind);
        Assert.AreEqual("-_AAA", tokens[0].Code);
        Assert.AreEqual((2, 0), tokens[0].Version);
        Assert.AreEqual(CesrTokenKind.CountGroup, tokens[1].Kind);
        Assert.AreEqual("-V", tokens[1].Code);
        Assert.AreEqual(body.Length / 3, tokens[1].Count);
        CollectionAssert.AreEqual(body, tokens[1].Body);
    }


    /// <summary>
    /// A text stream written with the writer reads back identically through the text reader (writer/reader are inverses).
    /// </summary>
    [TestMethod]
    public async Task TextWriterOutputRoundTripsThroughTheTextReader()
    {
        byte[] keyChars = PrimitiveTextBytes("D", PublicKeyRaw);
        byte[] saltChars = PrimitiveTextBytes("0A", SaltRaw);
        byte[] body = [.. keyChars, .. saltChars];

        var pipe = new Pipe();
        CesrStreamWriter.WriteTextGenusVersion(pipe.Writer, "-_AAA", 2, 0);
        CesrStreamWriter.WriteTextGroup(pipe.Writer, "-V", body);
        await pipe.Writer.FlushAsync(TestContext.CancellationToken);
        await pipe.Writer.CompleteAsync();

        var tokens = new List<(CesrTokenKind Kind, CesrDomain Domain, string Code, int Count, (int, int)? Version, byte[] Body)>();
        await foreach(CesrToken token in CesrStreamReader.ReadTextAsync(pipe.Reader, BaseMemoryPool.Shared, TestContext.CancellationToken))
        {
            tokens.Add((token.Kind, token.Domain, token.Code, token.Count, token.Version, token.Body.ToArray()));
            token.Dispose();
        }

        await pipe.Reader.CompleteAsync();

        Assert.HasCount(2, tokens);
        Assert.AreEqual(CesrTokenKind.GenusVersion, tokens[0].Kind);
        Assert.AreEqual(CesrDomain.Text, tokens[0].Domain);
        Assert.AreEqual("-_AAA", tokens[0].Code);
        Assert.AreEqual((2, 0), tokens[0].Version);
        Assert.AreEqual(CesrTokenKind.CountGroup, tokens[1].Kind);
        Assert.AreEqual(CesrDomain.Text, tokens[1].Domain);
        Assert.AreEqual("-V", tokens[1].Code);
        Assert.AreEqual(body.Length / 4, tokens[1].Count);
        CollectionAssert.AreEqual(body, tokens[1].Body);
    }


    /// <summary>
    /// A group body that is not aligned on a 24-bit (three-byte) boundary is rejected before anything is written.
    /// </summary>
    [TestMethod]
    public void RejectsUnalignedGroupBody()
    {
        var pipe = new Pipe();

        Assert.ThrowsExactly<CesrFormatException>(() => CesrStreamWriter.WriteGroup(pipe.Writer, "-V", new byte[5]));
    }


    /// <summary>
    /// A text group body that is not aligned on a 24-bit (four-character) boundary is rejected before anything is written.
    /// </summary>
    [TestMethod]
    public void RejectsUnalignedTextGroupBody()
    {
        var pipe = new Pipe();

        Assert.ThrowsExactly<CesrFormatException>(() => CesrStreamWriter.WriteTextGroup(pipe.Writer, "-V", new byte[6]));
    }


    private static byte[] PrimitiveBytes(string code, byte[] raw)
    {
        int byteLength = CesrPrimitiveCodec.EncodeText(code, raw).Length * 3 / 4;
        using IMemoryOwner<byte> owner = CesrPrimitiveCodec.EncodeBinary(code, raw, BaseMemoryPool.Shared);

        return owner.Memory.Span[..byteLength].ToArray();
    }


    private static byte[] PrimitiveTextBytes(string code, byte[] raw) => Encoding.ASCII.GetBytes(CesrPrimitiveCodec.EncodeText(code, raw));
}
