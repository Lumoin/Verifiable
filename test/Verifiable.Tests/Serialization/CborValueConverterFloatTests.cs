using System;
using System.Buffers;
using Lumoin.Veritas.Cbor;
using Verifiable.Cbor;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// The float dispatch of <see cref="CborValueConverter"/> over the Veritas reader and writer: each of the
/// three RFC 8949 major-type-7 float widths is read at its own declared width, and a canonical write
/// states a value in the shortest width that preserves it exactly.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.3">RFC 8949 §3.3</see> gives major type 7
/// three float encodings, selected by the additional information: 25 carries an IEEE 754 binary16
/// (<c>0xF9</c> plus two bytes), 26 a binary32 (<c>0xFA</c> plus four bytes) and 27 a binary64
/// (<c>0xFB</c> plus eight bytes). The substrate reads each at its declared width only — it does not widen
/// a narrower encoding into a wider typed read — so the converter's state dispatch must name the matching
/// read for every width. This is ruling S4-8 of the CBOR substrate swap.
/// </para>
/// <para>
/// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see> requires a
/// deterministic encoder to state a float in "the shortest floating-point encoding that preserves the
/// value", which the substrate applies to <c>WriteDouble</c> under the deterministic modes and to no mode
/// otherwise. Every expected byte string below is derived from the IEEE 754 field layout in the test's own
/// doc comment, never read back off the encoder.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CborValueConverterFloatTests
{
    /// <summary>
    /// Reads one hand-typed CBOR document as a CLR value through the converter's non-ref read overload.
    /// </summary>
    /// <param name="cbor">The hand-typed wire bytes holding exactly one data item.</param>
    /// <param name="options">The conformance preset the reader runs under.</param>
    /// <returns>The CLR value the converter produced.</returns>
    private static object? ReadOneValue(byte[] cbor, CborSerializerOptions options)
    {
        var reader = new CborReader(cbor, options);

        return CborValueConverter.ReadValue(reader);
    }


    /// <summary>
    /// Writes one CLR value through the converter and returns the bytes that reached the wire.
    /// </summary>
    /// <param name="value">The CLR value to state in CBOR.</param>
    /// <param name="options">The conformance preset the writer runs under.</param>
    /// <returns>The emitted wire bytes.</returns>
    private static byte[] WriteOneValue(object? value, CborSerializerOptions options)
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, options);
        CborValueConverter.WriteValue(writer, value);

        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Asserts that emitted bytes match a hand-derived expectation, reporting both as hex on failure.
    /// </summary>
    /// <param name="expected">The hand-derived expected bytes.</param>
    /// <param name="actual">The bytes the encoder emitted.</param>
    private static void AssertBytes(byte[] expected, byte[] actual)
    {
        Assert.IsTrue(
            expected.AsSpan().SequenceEqual(actual),
            $"Expected {Convert.ToHexString(expected)}, got {Convert.ToHexString(actual)}.");
    }


    /// <summary>
    /// A half-precision 1.5 read through the converter yields the double 1.5, proving the
    /// <c>HalfPrecisionFloat</c> state dispatches to the half-width read and widens in the converter.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.3">RFC 8949 §3.3</see>: <c>0xF9</c> is
    /// major type 7 with additional information 25, "IEEE 754 Half-Precision Float (16 bits follow)".
    /// </para>
    /// <para>
    /// Derivation of <c>3E 00</c>: binary16 lays out sign (1 bit), exponent (5 bits, bias 15) and
    /// significand (10 bits). <c>0x3E00</c> = <c>0 01111 1000000000</c>: sign 0, exponent field 15 so the
    /// unbiased exponent is 15 − 15 = 0, significand fraction <c>0b1000000000</c> giving the implicit-one
    /// value 1.1₂ = 1.5. So 1.5 × 2⁰ = 1.5.
    /// </para>
    /// <para>
    /// Ruling S4-8: the substrate's <c>ReadDouble</c> accepts the eight-byte marker only, so this state must
    /// dispatch to the half read. The document is read under the lax preset because the width chosen here is
    /// the subject of the test, not the deterministic-mode shortest-form rule.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void HalfPrecisionOneAndAHalfReadsAsTheDoubleOneAndAHalf()
    {
        byte[] cbor = [0xF9, 0x3E, 0x00];

        object? value = ReadOneValue(cbor, CborOptions.Lax);

        double actual = Assert.IsInstanceOfType<double>(value);
        Assert.AreEqual(1.5d, actual);
    }


    /// <summary>
    /// A single-precision 1.5 read through the converter yields the single 1.5, proving the
    /// <c>SinglePrecisionFloat</c> state dispatches to the four-byte read.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.3">RFC 8949 §3.3</see>: <c>0xFA</c> is
    /// major type 7 with additional information 26, "IEEE 754 Single-Precision Float (32 bits follow)".
    /// </para>
    /// <para>
    /// Derivation of <c>3F C0 00 00</c>: binary32 lays out sign (1 bit), exponent (8 bits, bias 127) and
    /// significand (23 bits). <c>0x3FC00000</c> = <c>0 01111111 10000000000000000000000</c>: sign 0,
    /// exponent field 127 so the unbiased exponent is 127 − 127 = 0, significand fraction with only its
    /// leading bit set giving 1.1₂ = 1.5. So 1.5 × 2⁰ = 1.5.
    /// </para>
    /// <para>
    /// Ruling S4-8. Read under the lax preset: a deterministic-mode read would refuse this document under
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see>, since 1.5 is
    /// exactly representable in binary16 and the four-byte form is therefore not the shortest one.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void SinglePrecisionOneAndAHalfReadsAsTheSingleOneAndAHalf()
    {
        byte[] cbor = [0xFA, 0x3F, 0xC0, 0x00, 0x00];

        object? value = ReadOneValue(cbor, CborOptions.Lax);

        float actual = Assert.IsInstanceOfType<float>(value);
        Assert.AreEqual(1.5f, actual);
    }


    /// <summary>
    /// A double-precision pi read through the converter yields the exact double, proving the
    /// <c>DoublePrecisionFloat</c> state dispatches to the eight-byte read with no loss.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.3">RFC 8949 §3.3</see>: <c>0xFB</c> is
    /// major type 7 with additional information 27, "IEEE 754 Double-Precision Float (64 bits follow)".
    /// </para>
    /// <para>
    /// Derivation of <c>40 09 21 FB 54 44 2D 18</c>: binary64 lays out sign (1 bit), exponent (11 bits,
    /// bias 1023) and significand (52 bits). The leading twelve bits <c>0x400</c> = <c>0 10000000000</c>
    /// give sign 0 and exponent field 1024, so the unbiased exponent is 1024 − 1023 = 1; the remaining 52
    /// bits <c>0x921FB54442D18</c> give the implicit-one significand 1.5707963267948966. So
    /// 1.5707963267948966 × 2¹ = 3.141592653589793, which is <see cref="Math.PI"/>.
    /// </para>
    /// <para>
    /// Ruling S4-8. Read under the lax preset for symmetry with the sibling width cases; this document is
    /// in fact already the shortest form, since pi is not exactly representable in binary32 or binary16.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void DoublePrecisionPiReadsAsTheExactDouble()
    {
        byte[] cbor = [0xFB, 0x40, 0x09, 0x21, 0xFB, 0x54, 0x44, 0x2D, 0x18];

        object? value = ReadOneValue(cbor, CborOptions.Lax);

        double actual = Assert.IsInstanceOfType<double>(value);
        Assert.AreEqual(Math.PI, actual);
    }


    /// <summary>
    /// A half-precision NaN read through the converter yields a NaN double rather than a numeric value or a
    /// refusal, proving the half dispatch carries the non-finite payload through the widening.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.3">RFC 8949 §3.3</see> admits NaN in any
    /// of the three float widths.
    /// </para>
    /// <para>
    /// Derivation of <c>7E 00</c>: binary16 signals a NaN with the exponent field all ones and a non-zero
    /// significand. <c>0x7E00</c> = <c>0 11111 1000000000</c>: sign 0, exponent field 31 (all ones),
    /// significand fraction with its most significant bit set — the quiet NaN whose fraction is otherwise
    /// zero. <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.2">RFC 8949 §4.2.2</see> names
    /// exactly this bit pattern as the one a deterministic encoder emits for NaN.
    /// </para>
    /// <para>
    /// Ruling S4-8. Widening a NaN half to double must stay a NaN: a converted numeric value would silently
    /// turn an absent measurement into a real one at every claim that carries a float.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void HalfPrecisionNaNReadsAsANaNDouble()
    {
        byte[] cbor = [0xF9, 0x7E, 0x00];

        object? value = ReadOneValue(cbor, CborOptions.Lax);

        double actual = Assert.IsInstanceOfType<double>(value);
        Assert.IsTrue(double.IsNaN(actual), "A half-precision NaN MUST widen to a NaN double.");
    }


    /// <summary>
    /// Writing the double 1.5 under the RFC canonical preset emits the three-byte half form, proving the
    /// deterministic shortest-float rule reaches the converter's write path.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see>: a
    /// deterministically encoded value uses "the shortest floating-point encoding that preserves the value
    /// being encoded", trying binary16 before binary32 before binary64.
    /// </para>
    /// <para>
    /// Derivation of <c>F9 3E 00</c>: 1.5 = 1.1₂ × 2⁰ is exactly representable in binary16, so binary16 is
    /// the shortest preserving width. Encoding it there gives sign 0, exponent field 0 + 15 = 15 =
    /// <c>0b01111</c>, significand fraction <c>0b1000000000</c>, i.e. <c>0 01111 1000000000</c> =
    /// <c>0x3E00</c>; the head byte is major type 7 with additional information 25 = <c>0xF9</c>.
    /// </para>
    /// <para>
    /// Ruling S4-8 accepts this shortening as spec-faithful.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void WritingOneAndAHalfUnderRfcCanonicalEmitsTheHalfPrecisionForm()
    {
        byte[] emitted = WriteOneValue(1.5d, CborOptions.RfcCanonical);

        AssertBytes([0xF9, 0x3E, 0x00], emitted);
    }


    /// <summary>
    /// Writing an epoch-seconds double that binary32 cannot hold exactly under the RFC canonical preset
    /// keeps the nine-byte binary64 form, proving the shortest-float rule shortens only where the value
    /// survives it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see> conditions the
    /// shortening on preserving the value; a value no narrower width holds exactly stays at binary64.
    /// </para>
    /// <para>
    /// Derivation of the value's width: 1756800123 is odd and lies in [2³⁰, 2³¹), so writing it as a
    /// significand times a power of two needs 31 significant bits. binary32 carries 24 significand bits and
    /// binary16 carries 11, so neither preserves it; binary64's 53 bits do.
    /// </para>
    /// <para>
    /// Derivation of <c>FB 41 DA 2D A9 1E C0 00 00</c>: the unbiased exponent is 30 (since
    /// 2³⁰ ≤ 1756800123 &lt; 2³¹), so the exponent field is 30 + 1023 = 1053 = <c>0b10000011101</c>, and
    /// with sign 0 the leading twelve bits are <c>0100 0001 1101</c> = <c>0x41D</c>. The significand
    /// fraction is (1756800123 − 2³⁰) / 2³⁰ = 683058299 / 2³⁰, whose 52-bit field is
    /// 683058299 × 2²² = <c>0xA2DA91EC00000</c>. Concatenating gives
    /// <c>0x41DA2DA91EC00000</c>; the head byte is major type 7 with additional information 27 = <c>0xFB</c>.
    /// </para>
    /// <para>
    /// Ruling S4-8 states that the epoch timestamps this library writes stay binary64. The ruling's own
    /// illustrative value 1756800000 does NOT hold that property — see
    /// <see cref="WritingABinary32RepresentableEpochSecondUnderRfcCanonicalShortensToBinary32"/>.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void WritingAnEpochSecondsDoubleUnderRfcCanonicalStaysBinary64()
    {
        byte[] emitted = WriteOneValue(1756800123.0d, CborOptions.RfcCanonical);

        AssertBytes([0xFB, 0x41, 0xDA, 0x2D, 0xA9, 0x1E, 0xC0, 0x00, 0x00], emitted);
    }


    /// <summary>
    /// Writing an epoch second that binary32 does hold exactly under the RFC canonical preset shortens to
    /// the five-byte binary32 form — the adversarial companion showing that "epoch timestamps stay
    /// binary64" is a property of the individual value, not of epoch seconds as a class.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see>: the shortest
    /// preserving width MUST be used, so a value that binary32 preserves MUST NOT be stated in binary64.
    /// </para>
    /// <para>
    /// Derivation of the width: 1756800000 = 1715625 × 2¹⁰ and 1715625 &lt; 2²⁴, so 24 significand bits
    /// suffice and binary32 preserves the value exactly. binary16's 11 bits do not.
    /// </para>
    /// <para>
    /// Derivation of <c>FA 4E D1 6D 48</c>: the unbiased exponent is 30, so the exponent field is
    /// 30 + 127 = 157 = <c>0b10011101</c>, and with sign 0 the leading nine bits are <c>0 10011101</c>. The
    /// significand fraction is (1756800000 − 2³⁰) / 2³⁰ = 683058176 / 2³⁰, whose 23-bit field is
    /// 683058176 / 2⁷ = 5336392 = <c>0x516D48</c>. Concatenating <c>0 10011101</c> with
    /// <c>101 0001 0110 1101 0100 1000</c> gives <c>0x4ED16D48</c>; the head byte is major type 7 with
    /// additional information 26 = <c>0xFA</c>.
    /// </para>
    /// <para>
    /// Ruling S4-8. Any wire fixture or signed payload that embeds a round epoch second as a canonical
    /// double therefore changes length under the substrate, and must be re-derived rather than assumed.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void WritingABinary32RepresentableEpochSecondUnderRfcCanonicalShortensToBinary32()
    {
        byte[] emitted = WriteOneValue(1756800000.0d, CborOptions.RfcCanonical);

        AssertBytes([0xFA, 0x4E, 0xD1, 0x6D, 0x48], emitted);
    }


    /// <summary>
    /// Writing the double 1.5 under the lax preset keeps the nine-byte binary64 form, proving the
    /// shortest-float reduction is confined to the deterministic modes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see> states the
    /// shortest-form requirement as part of deterministically encoded CBOR, a profile a generic encoder is
    /// not obliged to apply; <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.3">§3.3</see>
    /// admits any of the three widths for a value outside that profile.
    /// </para>
    /// <para>
    /// Derivation of <c>FB 3F F8 00 00 00 00 00 00</c>: 1.5 = 1.1₂ × 2⁰, so in binary64 the exponent field
    /// is 0 + 1023 = 1023 = <c>0b01111111111</c> and the significand fraction has only its leading bit set.
    /// With sign 0 the leading twelve bits are <c>0011 1111 1111</c> = <c>0x3FF</c>, followed by
    /// <c>0x8000000000000</c>; the head byte is major type 7 with additional information 27 = <c>0xFB</c>.
    /// </para>
    /// <para>
    /// Ruling S4-8. This is the guard on the other side of the shortening: a lax writer must not silently
    /// change the width a caller's bytes were pinned at.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void WritingOneAndAHalfUnderLaxStaysBinary64()
    {
        byte[] emitted = WriteOneValue(1.5d, CborOptions.Lax);

        AssertBytes([0xFB, 0x3F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], emitted);
    }


    /// <summary>
    /// A single that no narrower width preserves survives a write-then-read cycle under the RFC canonical
    /// preset, proving the converter's write and read float dispatches agree on the four-byte width.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.3">RFC 8949 §3.3</see> for the binary32
    /// encoding; <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">§4.2.1</see> for the
    /// shortest-form rule the round trip must satisfy at both ends.
    /// </para>
    /// <para>
    /// Choice of value: the converter states a CLR <c>float</c> at its declared binary32 width under every
    /// mode, so a round trip under a deterministic reader only holds for a value binary16 cannot preserve.
    /// The binary32 nearest 0.1 is <c>0x3DCCCCCD</c>; the binary16 nearest 0.1 is <c>0x2E66</c>, whose
    /// value 0.0999755859375 differs, so binary16 does not preserve it and the four-byte form is the
    /// shortest one. A value such as 1.5 would instead be refused on the read side under this preset.
    /// </para>
    /// <para>
    /// Ruling S4-8.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void ASingleThatBinary16CannotPreserveRoundTripsUnderRfcCanonical()
    {
        byte[] emitted = WriteOneValue(0.1f, CborOptions.RfcCanonical);
        AssertBytes([0xFA, 0x3D, 0xCC, 0xCC, 0xCD], emitted);

        object? value = ReadOneValue(emitted, CborOptions.RfcCanonical);

        float actual = Assert.IsInstanceOfType<float>(value);
        Assert.AreEqual(0.1f, actual);
    }
}
