using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using System.Threading.Tasks;
using Lumoin.Base;
using Verifiable.Cesr;
using Verifiable.Cesr.Streaming;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Cesr;

/// <summary>
/// Adversarial hardening regression tests for the CESR codec: each test is the exact malformed wire input that
/// exposed a defect where the decoder crashed with the wrong exception type, silently accepted malformed input,
/// or admitted a non-canonical (malleable) encoding, together with the encoder-side validation gaps that let the
/// producer emit malformed material. The universal contract these pin down is that malformed CESR wire input is
/// rejected with a <see cref="CesrFormatException"/> — never an <see cref="ArgumentOutOfRangeException"/>,
/// <see cref="System.FormatException"/>, <see cref="System.OverflowException"/>, or a silent success — and that
/// the encoders refuse to emit a primitive or signature that does not match its code.
/// </summary>
[TestClass]
internal sealed class CesrHardeningTests
{
    /// <summary>The largest count a five-character large-count-code soft field carries (<c>64^5 - 1</c>).</summary>
    private const int MaxLargeCount = (64 * 64 * 64 * 64 * 64) - 1;


    /// <summary>
    /// A large binary count code whose count is at its maximum frames <c>count * 3</c> bytes, a value that
    /// overflows <see cref="int"/>; computed as <see cref="int"/> it wraps negative and slips past the buffered
    /// -length guard into a negative-length slice. The reader must instead report the group as not-yet-buffered
    /// and, on a completed stream, as a truncated stream — a <see cref="CesrFormatException"/>, not an
    /// <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
    [TestMethod]
    public async Task RejectsBinaryLargeCountCodeWhoseByteCountOverflowsInt()
    {
        byte[] header;
        using(IMemoryOwner<byte> owner = CesrCountCodeCodec.EncodeBinary("--A", MaxLargeCount, BaseMemoryPool.Shared))
        {
            header = owner.Memory.Span[..6].ToArray();
        }

        await Assert.ThrowsExactlyAsync<CesrFormatException>(async () => await DrainBinaryAsync(header));
    }


    /// <summary>
    /// The text-domain twin of <see cref="RejectsBinaryLargeCountCodeWhoseByteCountOverflowsInt"/>: the
    /// eight-character large count code <c>--A_____</c> frames <c>count * 4</c> characters, which overflows
    /// <see cref="int"/> the same way. It is rejected as a truncated stream, not with a negative-length slice.
    /// </summary>
    [TestMethod]
    public async Task RejectsTextLargeCountCodeWhoseCharCountOverflowsInt()
    {
        byte[] header = Encoding.ASCII.GetBytes(CesrCountCodeCodec.EncodeText("--A", MaxLargeCount));

        await Assert.ThrowsExactlyAsync<CesrFormatException>(async () => await DrainTextAsync(header));
    }


    /// <summary>
    /// A native field map whose nested big-map group declares a multi-gigabyte body while supplying none: the
    /// declared character count overflows <see cref="int"/> so the nested end wraps to before the cursor and the
    /// overrun check is defeated, making the decoder silently accept the lying group as an empty map. Computed in
    /// <see cref="long"/> the overrun is caught and the whole message is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsFieldMapNestedGroupThatLiesAboutItsSize()
    {
        //-IAD: outer map, 3 quadlets. 0J_a: label "a". --I_____: big map group declaring 64^5-1 quadlets.
        byte[] message = Encoding.ASCII.GetBytes("-IAD0J_a--I_____");

        Assert.ThrowsExactly<CesrFormatException>(() => CesrFieldMapCodec.DecodeFieldMap(message, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// A field-map value under a decimal code (<c>4H</c>) whose recovered characters are not a number: the decoder
    /// must reject it as a CESR format violation rather than letting the final <c>decimal</c> parse escape as a
    /// <see cref="System.FormatException"/> — a peer can put a decimal code over arbitrary Base64 content.
    /// </summary>
    [TestMethod]
    public void RejectsDecimalFieldValueThatIsNotANumber()
    {
        //A 4H (decimal) primitive whose three raw bytes render to the Base64 text "q83v" — not a valid number.
        string decimalCodedNonNumber = CesrPrimitiveCodec.EncodeText("4H", [0xAB, 0xCD, 0xEF]);

        Assert.ThrowsExactly<CesrFormatException>(() => CesrFieldMapCodec.DecodeValuePrimitive(decimalCodedNonNumber, BaseMemoryPool.Shared, out _));
    }


    /// <summary>
    /// A lead-bearing variable primitive (<c>5A</c>/<c>6A</c>, lead size 1/2) whose soft field declares a zero
    /// quadlet count declares a value too small to even contain its own lead bytes; the recovered raw length goes
    /// negative. The library's own encoder never emits this, but an adversarial producer can send it, and the
    /// decoder must reject it with a <see cref="CesrFormatException"/> rather than a negative-length slice.
    /// </summary>
    [TestMethod]
    [DataRow("5AAA")]
    [DataRow("6AAA")]
    public void RejectsVariablePrimitiveTooShortForItsLeadBytes(string qb64)
    {
        Assert.ThrowsExactly<CesrFormatException>(() => CesrPrimitiveCodec.DecodeText(qb64, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// The binary indexed-signature decoder must reject a non-canonical code packing: two qb2 byte strings that
    /// differ only in the code's unused mid-pad bits (the low nibble of the second byte for a one-character code)
    /// decode to the same index and signature, a malleability. The canonical encoding decodes; setting the mid-pad
    /// bits is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsIndexedSignatureWithNonZeroCodeMidpadBits()
    {
        byte[] raw = new byte[64];
        for(int i = 0; i < raw.Length; i++)
        {
            raw[i] = (byte)(i + 1);
        }

        byte[] canonical;
        using(IMemoryOwner<byte> owner = CesrIndexedSignatureCodec.EncodeBinary("A", raw, index: 0, BaseMemoryPool.Shared))
        {
            canonical = owner.Memory.Span[..66].ToArray();
        }

        using(CesrParsedIndexedSignature parsed = CesrIndexedSignatureCodec.DecodeBinary(canonical, BaseMemoryPool.Shared))
        {
            Assert.AreEqual("A", parsed.Code, "The canonical encoding decodes.");
            Assert.AreEqual(0, parsed.Index);
        }

        byte[] malleated = (byte[])canonical.Clone();
        malleated[1] |= 0x0F;

        Assert.ThrowsExactly<CesrFormatException>(() =>
        {
            using CesrParsedIndexedSignature _ = CesrIndexedSignatureCodec.DecodeBinary(malleated, BaseMemoryPool.Shared);
        });
    }


    /// <summary>
    /// The binary primitive decoder rejects a non-canonical code packing, the malleability that a self-addressing
    /// identifier (SAID) built on this codec cannot tolerate: a two-character code (here <c>0B</c>, an Ed25519
    /// signature) leaves four unused mid-pad bits in its second byte, and setting them yields a distinct byte
    /// string that must not decode to the same primitive.
    /// </summary>
    [TestMethod]
    public void RejectsPrimitiveWithNonZeroCodeMidpadBits()
    {
        byte[] raw = new byte[64];
        for(int i = 0; i < raw.Length; i++)
        {
            raw[i] = (byte)(i + 1);
        }

        byte[] canonical;
        using(IMemoryOwner<byte> owner = CesrPrimitiveCodec.EncodeBinary("0B", raw, BaseMemoryPool.Shared))
        {
            canonical = owner.Memory.Span[..66].ToArray();
        }

        using(CesrParsedPrimitive parsed = CesrPrimitiveCodec.DecodeBinary(canonical, BaseMemoryPool.Shared))
        {
            Assert.AreEqual("0B", parsed.Code, "The canonical encoding decodes.");
        }

        byte[] malleated = (byte[])canonical.Clone();
        malleated[1] |= 0x0F;

        Assert.ThrowsExactly<CesrFormatException>(() =>
        {
            using CesrParsedPrimitive _ = CesrPrimitiveCodec.DecodeBinary(malleated, BaseMemoryPool.Shared);
        });
    }


    /// <summary>
    /// A native field map whose framing count declares more body than the message supplies is rejected (the
    /// declared-longer-than-present half of the framing-confusion guard): <c>-IAB</c> declares one quadlet of body
    /// but carries none.
    /// </summary>
    [TestMethod]
    public void RejectsFieldMapDeclaringMoreBodyThanPresent()
    {
        byte[] message = "-IAB"u8.ToArray();

        Assert.ThrowsExactly<CesrFormatException>(() => CesrFieldMapCodec.DecodeFieldMap(message, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// A signature index beyond the capacity of the code's index field must be rejected, not silently wrapped: the
    /// one-character index of code <c>A</c> holds 0 to 63, so an index of 64 would alias to 0. Silently aliasing a
    /// forged index misattributes a signature to the wrong key-list position in threshold verification.
    /// </summary>
    [TestMethod]
    public void RejectsIndexedSignatureIndexBeyondItsFieldCapacity()
    {
        byte[] raw = new byte[64];

        Assert.ThrowsExactly<CesrFormatException>(() => CesrIndexedSignatureCodec.EncodeText("A", raw, index: 64));
    }


    /// <summary>
    /// A current-list-only indexed code (here <c>0B</c>) carrying a non-zero other-index is a forged dual index and
    /// must be rejected on decode. The wire is minted by taking a valid dual-index <c>0A</c> primitive (which does
    /// carry an other-index) and rewriting its hard code to the current-list-only <c>0B</c> of the same size.
    /// </summary>
    [TestMethod]
    public void RejectsCurrentListOnlyIndexedCodeWithNonZeroOtherIndex()
    {
        byte[] raw = new byte[114];
        string dualIndex = CesrIndexedSignatureCodec.EncodeText("0A", raw, index: 1, ondex: 1);
        string forgedCurrentOnly = "0B" + dualIndex[2..];

        Assert.ThrowsExactly<CesrFormatException>(() => CesrIndexedSignatureCodec.DecodeText(forgedCurrentOnly, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// The indexed-signature encoders reject a raw signature whose length does not match the code, in either
    /// domain, rather than emitting a wrong-length primitive (text) or silently truncating the overflow (binary).
    /// Code <c>A</c> carries exactly 64 raw bytes.
    /// </summary>
    [TestMethod]
    public void RejectsEncodingIndexedSignatureOfWrongRawLength()
    {
        Assert.ThrowsExactly<CesrFormatException>(() => CesrIndexedSignatureCodec.EncodeText("A", new byte[10], index: 0));
        Assert.ThrowsExactly<CesrFormatException>(() =>
        {
            using IMemoryOwner<byte> _ = CesrIndexedSignatureCodec.EncodeBinary("A", new byte[70], index: 0, BaseMemoryPool.Shared);
        });
    }


    /// <summary>
    /// The binary primitive encoder rejects a raw value whose length does not match a fixed code, the same way the
    /// text encoder does; previously the binary encoder packed whatever it was given, silently emitting a corrupt
    /// primitive. Code <c>D</c> (an Ed25519 public key) carries exactly 32 raw bytes.
    /// </summary>
    [TestMethod]
    public void RejectsEncodingFixedPrimitiveOfWrongRawLength()
    {
        Assert.ThrowsExactly<CesrFormatException>(() =>
        {
            using IMemoryOwner<byte> _ = CesrPrimitiveCodec.EncodeBinary("D", new byte[31], BaseMemoryPool.Shared);
        });

        Assert.ThrowsExactly<CesrFormatException>(() => CesrPrimitiveCodec.EncodeText("D", new byte[31]));
    }


    /// <summary>
    /// An interleaved non-native serialization whose leading field is not the version field is rejected, even when
    /// a version-string-shaped run appears inside a later field's value. Locating the version string by shape alone
    /// would let an attacker who controls any earlier field value forge a shorter declared length and desynchronize
    /// message boundaries; the leading <c>{"v":"</c> framing must precede the version string.
    /// </summary>
    [TestMethod]
    public async Task RejectsInterleavedSerializationWhoseVersionStringIsNotTheLeadingField()
    {
        //Valid tiny JSON with no "v" field, but the "x" field's value matches the version-string shape.
        byte[] smuggled = Encoding.ASCII.GetBytes("{\"x\":\"AAAAaaaaaaJSONAAAU.\"}");

        await Assert.ThrowsExactlyAsync<CesrFormatException>(async () => await DrainTextAsync(smuggled));
    }


    /// <summary>
    /// A top-level stream item that is neither a count code, an op code, nor an interleaved non-native
    /// serialization is rejected as an unsupported item — the binary path (a leading byte whose selector sextet is
    /// an ordinary primitive selector) and the text path (a leading primitive character).
    /// </summary>
    [TestMethod]
    public async Task RejectsUnsupportedTopLevelStreamItemInBothDomains()
    {
        //Binary: 0x00 0x00 — the leading selector sextet is 'A', an ordinary primitive selector, not '-'/'_'.
        await Assert.ThrowsExactlyAsync<CesrFormatException>(async () => await DrainBinaryAsync([0x00, 0x00]));

        //Text: "AA" — the leading character 'A' is an ordinary primitive selector, not a count or op code.
        await Assert.ThrowsExactlyAsync<CesrFormatException>(async () => await DrainTextAsync("AA"u8.ToArray()));
    }


    /// <summary>
    /// The message reader rejects a stream that opens with an attachment (count) group before any message: an
    /// attachment with nothing to attach to is a framing error a firewalled verifier of an attacker-supplied
    /// <c>keri.cesr</c> stream must reject.
    /// </summary>
    [TestMethod]
    public async Task RejectsAttachmentGroupBeforeAnyMessage()
    {
        string keyText = CesrPrimitiveCodec.EncodeText("D", new byte[32]);
        byte[] stream = Encoding.ASCII.GetBytes(CesrCountCodeCodec.EncodeText("-V", keyText.Length / 4) + keyText);

        await Assert.ThrowsExactlyAsync<CesrFormatException>(async () => await DrainMessagesTextAsync(stream));
    }


    /// <summary>
    /// A native field map nested past the depth bound is rejected (the anti-resource-exhaustion guard), while a map
    /// nested within the bound round-trips. This pins down that the bound both exists and does not reject legitimate
    /// nesting.
    /// </summary>
    [TestMethod]
    public void RejectsFieldMapNestedPastTheDepthBoundButAdmitsNestingWithinIt()
    {
        Assert.ThrowsExactly<CesrFormatException>(() => DecodeNestedMapOfDepth(40));

        //A modestly nested map round-trips: decoding its own encoding recovers the same nesting depth.
        MessageFieldMap decoded = DecodeNestedMapOfDepth(8);
        Assert.IsNotNull(decoded, "A map nested within the bound decodes.");
    }


    //Builds a map nested `depth` levels deep, encodes it to its native serialization, and decodes it back.
    private static MessageFieldMap DecodeNestedMapOfDepth(int depth)
    {
        var map = new MessageFieldMap(StringComparer.Ordinal) { ["a"] = "x" };
        for(int i = 0; i < depth; i++)
        {
            map = new MessageFieldMap(StringComparer.Ordinal) { ["a"] = map };
        }

        var writer = new ArrayBufferWriter<byte>();
        CesrFieldMapCodec.EncodeFieldMap(map, BaseMemoryPool.Shared, writer);

        return CesrFieldMapCodec.DecodeFieldMap(writer.WrittenMemory, BaseMemoryPool.Shared);
    }


    //Drains the binary-domain top-level items of a stream, disposing each; a helper so a malformed stream's
    //exception surfaces from the enumeration.
    private static async Task DrainBinaryAsync(byte[] stream)
    {
        PipeReader reader = PipeReader.Create(new ReadOnlySequence<byte>(stream));
        await foreach(CesrToken token in CesrStreamReader.ReadBinaryAsync(reader, BaseMemoryPool.Shared))
        {
            token.Dispose();
        }

        await reader.CompleteAsync();
    }


    //Drains the text-domain top-level items of a stream, disposing each.
    private static async Task DrainTextAsync(byte[] stream)
    {
        PipeReader reader = PipeReader.Create(new ReadOnlySequence<byte>(stream));
        await foreach(CesrToken token in CesrStreamReader.ReadTextAsync(reader, BaseMemoryPool.Shared))
        {
            token.Dispose();
        }

        await reader.CompleteAsync();
    }


    //Drains the text-domain messages-with-attachments of a stream, disposing each.
    private static async Task DrainMessagesTextAsync(byte[] stream)
    {
        PipeReader reader = PipeReader.Create(new ReadOnlySequence<byte>(stream));
        await foreach(CesrMessage message in CesrMessageReader.ReadTextAsync(reader, BaseMemoryPool.Shared))
        {
            message.Dispose();
        }

        await reader.CompleteAsync();
    }
}
