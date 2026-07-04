using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Lumoin.Base;
using Verifiable.Cesr;
using Verifiable.Cesr.Streaming;

namespace Verifiable.Tests.Cesr;

/// <summary>
/// Tests for <see cref="CesrGroupReader"/> — walking a count group's body element by element in both the binary
/// (qb2) and text (qb64) domains. A body is minted by concatenating encoded elements (the bytes a framed group
/// carries), then walked back: the walk must recover every element in order with nothing left over, which
/// exercises the consumed-length decode that lets the cursor advance from one element to the next.
/// </summary>
[TestClass]
internal sealed class CesrGroupReaderTests
{
    private static readonly byte[] PublicKeyRaw = Convert.FromHexString("0ff9dafee5024209554babba1e341af32c637fcaec9e3e65d568ecda03db1ce6");
    private static readonly byte[] SaltRaw = Convert.FromHexString("3f033eef724684dfcdc01ceb16d49d4d");
    private static readonly byte[] SignatureRaw = [.. Enumerable.Range(0, 64).Select(i => (byte)i)];


    /// <summary>
    /// A body of two primitives walks back to both primitives in order.
    /// </summary>
    [TestMethod]
    public void WalksPrimitiveGroupBody()
    {
        byte[] key = PrimitiveBytes("D", PublicKeyRaw);
        byte[] salt = PrimitiveBytes("0A", SaltRaw);
        byte[] body = [.. key, .. salt];

        var decoded = new List<(string Code, string Raw)>();
        foreach(CesrParsedPrimitive primitive in CesrGroupReader.ReadPrimitives(body, BaseMemoryPool.Shared))
        {
            decoded.Add((primitive.Code, Convert.ToHexStringLower(primitive.Raw)));
            primitive.Dispose();
        }

        Assert.HasCount(2, decoded);
        Assert.AreEqual(("D", Convert.ToHexStringLower(PublicKeyRaw)), decoded[0]);
        Assert.AreEqual(("0A", Convert.ToHexStringLower(SaltRaw)), decoded[1]);
    }


    /// <summary>
    /// A body of two indexed signatures walks back to both signatures, recovering each index.
    /// </summary>
    [TestMethod]
    public void WalksIndexedSignatureGroupBody()
    {
        byte[] first = IndexedBytes("A", SignatureRaw, index: 0);
        byte[] second = IndexedBytes("A", SignatureRaw, index: 3);
        byte[] body = [.. first, .. second];

        var decoded = new List<(string Code, int Index, string Raw)>();
        foreach(CesrParsedIndexedSignature signature in CesrGroupReader.ReadIndexedSignatures(body, BaseMemoryPool.Shared))
        {
            decoded.Add((signature.Code, signature.Index, Convert.ToHexStringLower(signature.Raw)));
            signature.Dispose();
        }

        Assert.HasCount(2, decoded);
        Assert.AreEqual(("A", 0, Convert.ToHexStringLower(SignatureRaw)), decoded[0]);
        Assert.AreEqual(("A", 3, Convert.ToHexStringLower(SignatureRaw)), decoded[1]);
    }


    /// <summary>
    /// The binary decode reports the exact number of bytes the element occupied.
    /// </summary>
    [TestMethod]
    public void ReportsConsumedLength()
    {
        byte[] key = PrimitiveBytes("D", PublicKeyRaw);

        using(CesrPrimitiveCodec.DecodeBinary(key, BaseMemoryPool.Shared, out int consumed))
        {
            Assert.AreEqual(key.Length, consumed, "A primitive decode consumes exactly the primitive's bytes.");
        }

        byte[] signature = IndexedBytes("A", SignatureRaw, index: 0);
        using(CesrIndexedSignatureCodec.DecodeBinary(signature, BaseMemoryPool.Shared, out int sigConsumed))
        {
            Assert.AreEqual(signature.Length, sigConsumed, "An indexed signature decode consumes exactly the signature's bytes.");
        }
    }


    /// <summary>
    /// A body whose final element is incomplete is rejected rather than yielding a partial element.
    /// </summary>
    [TestMethod]
    public void RejectsTrailingPartialElement()
    {
        byte[] key = PrimitiveBytes("D", PublicKeyRaw);
        byte[] body = [.. key, 0x00];

        Assert.ThrowsExactly<CesrFormatException>(() =>
        {
            foreach(CesrParsedPrimitive primitive in CesrGroupReader.ReadPrimitives(body, BaseMemoryPool.Shared))
            {
                primitive.Dispose();
            }
        });
    }


    /// <summary>
    /// A text-domain (qb64) body of two primitives walks back to both primitives in order.
    /// </summary>
    [TestMethod]
    public void WalksTextPrimitiveGroupBody()
    {
        byte[] key = PrimitiveTextBytes("D", PublicKeyRaw);
        byte[] salt = PrimitiveTextBytes("0A", SaltRaw);
        byte[] body = [.. key, .. salt];

        var decoded = new List<(string Code, string Raw)>();
        foreach(CesrParsedPrimitive primitive in CesrGroupReader.ReadPrimitivesText(body, BaseMemoryPool.Shared))
        {
            decoded.Add((primitive.Code, Convert.ToHexStringLower(primitive.Raw)));
            primitive.Dispose();
        }

        Assert.HasCount(2, decoded);
        Assert.AreEqual(("D", Convert.ToHexStringLower(PublicKeyRaw)), decoded[0]);
        Assert.AreEqual(("0A", Convert.ToHexStringLower(SaltRaw)), decoded[1]);
    }


    /// <summary>
    /// A text-domain (qb64) body of two indexed signatures walks back to both signatures, recovering each index.
    /// </summary>
    [TestMethod]
    public void WalksTextIndexedSignatureGroupBody()
    {
        byte[] first = IndexedTextBytes("A", SignatureRaw, index: 0);
        byte[] second = IndexedTextBytes("A", SignatureRaw, index: 3);
        byte[] body = [.. first, .. second];

        var decoded = new List<(string Code, int Index, string Raw)>();
        foreach(CesrParsedIndexedSignature signature in CesrGroupReader.ReadIndexedSignaturesText(body, BaseMemoryPool.Shared))
        {
            decoded.Add((signature.Code, signature.Index, Convert.ToHexStringLower(signature.Raw)));
            signature.Dispose();
        }

        Assert.HasCount(2, decoded);
        Assert.AreEqual(("A", 0, Convert.ToHexStringLower(SignatureRaw)), decoded[0]);
        Assert.AreEqual(("A", 3, Convert.ToHexStringLower(SignatureRaw)), decoded[1]);
    }


    /// <summary>
    /// The text decode reports the exact number of characters the element occupied.
    /// </summary>
    [TestMethod]
    public void ReportsConsumedTextLength()
    {
        string key = CesrPrimitiveCodec.EncodeText("D", PublicKeyRaw);
        using(CesrPrimitiveCodec.DecodeText(key, BaseMemoryPool.Shared, out int consumed))
        {
            Assert.AreEqual(key.Length, consumed, "A primitive decode consumes exactly the primitive's characters.");
        }

        string signature = CesrIndexedSignatureCodec.EncodeText("A", SignatureRaw, index: 0);
        using(CesrIndexedSignatureCodec.DecodeText(signature, BaseMemoryPool.Shared, out int sigConsumed))
        {
            Assert.AreEqual(signature.Length, sigConsumed, "An indexed signature decode consumes exactly the signature's characters.");
        }
    }


    /// <summary>
    /// A text-domain body whose final element is incomplete is rejected rather than yielding a partial element.
    /// </summary>
    [TestMethod]
    public void RejectsTrailingPartialTextElement()
    {
        byte[] key = PrimitiveTextBytes("D", PublicKeyRaw);
        byte[] body = [.. key, (byte)'0'];

        Assert.ThrowsExactly<CesrFormatException>(() =>
        {
            foreach(CesrParsedPrimitive primitive in CesrGroupReader.ReadPrimitivesText(body, BaseMemoryPool.Shared))
            {
                primitive.Dispose();
            }
        });
    }


    private static byte[] PrimitiveBytes(string code, byte[] raw)
    {
        int byteLength = CesrPrimitiveCodec.EncodeText(code, raw).Length * 3 / 4;
        using IMemoryOwner<byte> owner = CesrPrimitiveCodec.EncodeBinary(code, raw, BaseMemoryPool.Shared);

        return owner.Memory.Span[..byteLength].ToArray();
    }


    private static byte[] IndexedBytes(string code, byte[] raw, int index)
    {
        int byteLength = CesrIndexedSignatureCodec.EncodeText(code, raw, index).Length * 3 / 4;
        using IMemoryOwner<byte> owner = CesrIndexedSignatureCodec.EncodeBinary(code, raw, index, BaseMemoryPool.Shared);

        return owner.Memory.Span[..byteLength].ToArray();
    }


    private static byte[] PrimitiveTextBytes(string code, byte[] raw) => Encoding.ASCII.GetBytes(CesrPrimitiveCodec.EncodeText(code, raw));


    private static byte[] IndexedTextBytes(string code, byte[] raw, int index) => Encoding.ASCII.GetBytes(CesrIndexedSignatureCodec.EncodeText(code, raw, index));
}
