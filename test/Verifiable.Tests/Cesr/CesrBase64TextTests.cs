using System.Collections.Generic;
using Lumoin.Base;
using Verifiable.Cesr;

namespace Verifiable.Tests.Cesr;

/// <summary>
/// Tests for <see cref="CesrBase64Text"/> — the compact string primitive for Base64URL-only text, against known-answer
/// vectors covering the mid-pad and escape mechanics: the empty string, a string that is a leading escape character,
/// and strings whose leading <c>A</c> is ambiguous with the pad, at each length modulo four.
/// </summary>
[TestClass]
internal sealed class CesrBase64TextTests
{
    /// <summary>
    /// Base64-text vectors: the text and its compact string primitive (qb64).
    /// </summary>
    /// <returns>The Base64-text vectors.</returns>
    private static IEnumerable<object[]> Base64TextVectors()
    {
        yield return ["", "4AAA"];
        yield return ["-", "5AABAA--"];
        yield return ["-A", "4AABA--A"];
        yield return ["-A-", "4AAB--A-"];
        yield return ["-A-B", "6AACAAA--A-B"];
        yield return ["-A-BC", "5AACAA--A-BC"];
        yield return ["A", "6AABAAAA"];
        yield return ["AA", "5AABAAAA"];
        yield return ["AAA", "4AAB-AAA"];
        yield return ["AAAA", "6AACAAA-AAAA"];
    }


    /// <summary>
    /// Each Base64-text string encodes to its compact string primitive.
    /// </summary>
    /// <param name="text">The Base64URL text.</param>
    /// <param name="expectedQb64">The expected string primitive.</param>
    [TestMethod]
    [DynamicData(nameof(Base64TextVectors))]
    public void EncodesBase64Text(string text, string expectedQb64)
    {
        Assert.AreEqual(expectedQb64, CesrBase64Text.Encode(text));
    }


    /// <summary>
    /// Each compact string primitive decodes back to its Base64-text string.
    /// </summary>
    /// <param name="text">The expected Base64URL text.</param>
    /// <param name="qb64">The string primitive.</param>
    [TestMethod]
    [DynamicData(nameof(Base64TextVectors))]
    public void DecodesBase64Text(string text, string qb64)
    {
        using CesrParsedPrimitive primitive = CesrPrimitiveCodec.DecodeText(qb64, BaseMemoryPool.Shared, out int consumed);

        Assert.AreEqual(qb64.Length, consumed);
        Assert.AreEqual(text, CesrBase64Text.Decode(primitive.Code, primitive.Raw));
    }
}
