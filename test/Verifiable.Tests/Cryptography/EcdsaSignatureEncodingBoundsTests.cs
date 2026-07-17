using System.Formats.Asn1;
using System.Security.Cryptography;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Tests for the length/bounds guards in <see cref="EcdsaSignatureEncoding"/> that no other test in the
/// suite forces: every P1363 input elsewhere comes from a genuine signature (always even-length, in
/// bounds), and the existing "malformed wire signature" tests exercise <see cref="AsnReader"/>'s own
/// tag/structure validation rather than these two specific bounds checks on an otherwise well-formed
/// value.
/// </summary>
[TestClass]
internal sealed class EcdsaSignatureEncodingBoundsTests
{
    /// <summary>
    /// <see cref="EcdsaSignatureEncoding.ConvertP1363ToDer"/> rejects a zero-length P1363 input.
    /// </summary>
    [TestMethod]
    public void ConvertP1363ToDerRejectsZeroLengthInput()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            EcdsaSignatureEncoding.ConvertP1363ToDer(ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared, out _));
    }


    /// <summary>
    /// <see cref="EcdsaSignatureEncoding.ConvertP1363ToDer"/> rejects an odd-length P1363 input — a
    /// fixed-width <c>r ‖ s</c> encoding can never split evenly into two components at an odd length.
    /// </summary>
    [TestMethod]
    public void ConvertP1363ToDerRejectsOddLengthInput()
    {
        byte[] oddLengthSignature = new byte[33];

        Assert.ThrowsExactly<ArgumentException>(() =>
            EcdsaSignatureEncoding.ConvertP1363ToDer(oddLengthSignature, BaseMemoryPool.Shared, out _));
    }


    /// <summary>
    /// <see cref="EcdsaSignatureEncoding.ConvertDerToP1363"/> rejects a well-formed DER
    /// <c>Ecdsa-Sig-Value</c> whose <c>r</c> coordinate is longer than the target curve's field width —
    /// the field-width overflow guard, distinct from <see cref="AsnReader"/>'s own structural validation
    /// that the other "malformed signature" tests in the suite exercise.
    /// </summary>
    [TestMethod]
    public void ConvertDerToP1363RejectsACoordinateExceedingTheFieldWidth()
    {
        //A 33-byte r component (one byte over the 32-byte P-256 field width), high bit clear so DER
        //needs no extra sign-extension byte, plus a trivial well-formed 1-byte s component.
        byte[] rBytes = new byte[33];
        for(int i = 0; i < rBytes.Length; i++)
        {
            rBytes[i] = (byte)(i + 1);
        }
        rBytes[0] = 0x01;

        byte[] sBytes = [0x01];

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteIntegerUnsigned(rBytes);
            writer.WriteIntegerUnsigned(sBytes);
        }
        byte[] derSignature = writer.Encode();

        CryptographicException exception = Assert.ThrowsExactly<CryptographicException>(() =>
            EcdsaSignatureEncoding.ConvertDerToP1363(derSignature, fieldWidth: 32, BaseMemoryPool.Shared, out _));

        Assert.Contains("field width", exception.Message);
    }
}
