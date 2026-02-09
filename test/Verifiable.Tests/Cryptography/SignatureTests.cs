using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Tests for <see cref="Signature"/>.
/// </summary>
[TestClass]
internal sealed class SignatureTests
{
    //Deterministic test bytes for signature content.
    private static readonly byte[] SignatureBytes1 = [0x30, 0x44, 0x02, 0x20, 0xAB, 0xCD, 0xEF, 0x01];
    private static readonly byte[] SignatureBytes2 = [0x30, 0x44, 0x02, 0x20, 0xFF, 0xEE, 0xDD, 0xCC];
    private static readonly byte[] LongSignatureBytes =
    [
        0x30, 0x44, 0x02, 0x20, 0xAB, 0xCD, 0xEF, 0x01,
        0x23, 0x45, 0x67, 0x89, 0xDE, 0xAD, 0xBE, 0xEF,
        0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04
    ];


    [TestMethod]
    public void IdenticalBytesAreEqual()
    {
        using var sig1 = CreateSignature(SignatureBytes1, CryptoTags.P256Signature);
        using var sig2 = CreateSignature(SignatureBytes1, CryptoTags.P256Signature);

        Assert.IsTrue(sig1.Equals(sig2), "Signatures with identical bytes should be equal.");
        Assert.IsTrue(sig1 == sig2, "== operator should return true for identical bytes.");
        Assert.IsFalse(sig1 != sig2, "!= operator should return false for identical bytes.");
    }


    [TestMethod]
    public void DifferentBytesAreNotEqual()
    {
        using var sig1 = CreateSignature(SignatureBytes1, CryptoTags.P256Signature);
        using var sig2 = CreateSignature(SignatureBytes2, CryptoTags.P256Signature);

        Assert.IsFalse(sig1.Equals(sig2), "Signatures with different bytes should not be equal.");
        Assert.IsFalse(sig1 == sig2, "== operator should return false for different bytes.");
        Assert.IsTrue(sig1 != sig2, "!= operator should return true for different bytes.");
    }


    [TestMethod]
    public void EqualityIgnoresTag()
    {
        using var sig1 = CreateSignature(SignatureBytes1, CryptoTags.P256Signature);
        using var sig2 = CreateSignature(SignatureBytes1, CryptoTags.Ed25519Signature);

        Assert.IsTrue(sig1.Equals(sig2), "Equality is content-based and should ignore the tag.");
    }


    [TestMethod]
    public void EqualsReturnsFalseForNull()
    {
        using var sig = CreateSignature(SignatureBytes1, CryptoTags.P256Signature);

        Assert.IsFalse(sig.Equals((Signature?)null), "Equals(null) should return false.");
        Assert.IsFalse(sig.Equals((object?)null), "Equals((object)null) should return false.");
    }


    [TestMethod]
    public void EqualsReturnsFalseForDifferentType()
    {
        using var sig = CreateSignature(SignatureBytes1, CryptoTags.P256Signature);

        Assert.IsFalse(sig.Equals(new object()), "Equals(different type) should return false.");
        Assert.IsFalse(sig.Equals("not a signature"), "Equals(string) should return false.");
    }


    [TestMethod]
    [SuppressMessage("Maintainability", "CA1508:Avoid dead conditional code", Justification = "The operators need to be explicitly tested.")]
    public void NullOperatorEquality()
    {
        using var sig = CreateSignature(SignatureBytes1, CryptoTags.P256Signature);

        Assert.IsFalse(sig == null, "Non-null == null should be false.");
        Assert.IsFalse(null == sig, "null == non-null should be false.");
        Assert.IsTrue(sig != null, "Non-null != null should be true.");
        Assert.IsTrue(null != sig, "null != non-null should be true.");

        Signature? nullSig1 = null;
        Signature? nullSig2 = null;
        Assert.IsTrue(nullSig1 == nullSig2, "null == null should be true.");
        Assert.IsFalse(nullSig1 != nullSig2, "null != null should be false.");
    }


    [TestMethod]
    public void HashCodeContractForEqualSignatures()
    {
        using var sig1 = CreateSignature(SignatureBytes1, CryptoTags.P256Signature);
        using var sig2 = CreateSignature(SignatureBytes1, CryptoTags.P256Signature);

        Assert.AreEqual(sig1.GetHashCode(), sig2.GetHashCode(), "Equal signatures must have equal hash codes.");
    }


    [TestMethod]
    public void HashCodesAreDistinctForDifferentSignatures()
    {
        using var sig1 = CreateSignature(SignatureBytes1, CryptoTags.P256Signature);
        using var sig2 = CreateSignature(SignatureBytes2, CryptoTags.P256Signature);

        Assert.AreNotEqual(sig1.GetHashCode(), sig2.GetHashCode(), "Different signatures should have different hash codes.");
    }


    [TestMethod]
    public void LengthReturnsCorrectByteCount()
    {
        using var sig = CreateSignature(SignatureBytes1, CryptoTags.P256Signature);

        Assert.AreEqual(SignatureBytes1.Length, sig.Length);
    }


    [TestMethod]
    public void ImplicitConversionToReadOnlySpanPreservesContent()
    {
        using var sig = CreateSignature(SignatureBytes1, CryptoTags.P256Signature);

        ReadOnlySpan<byte> span = sig;

        Assert.AreEqual(SignatureBytes1.Length, span.Length);
        Assert.IsTrue(span.SequenceEqual(SignatureBytes1), "Implicit span conversion should preserve all bytes.");
    }


    [TestMethod]
    public void AccessAfterDisposeThrows()
    {
        var sig = CreateSignature(SignatureBytes1, CryptoTags.P256Signature);
        sig.Dispose();

        Assert.Throws<ObjectDisposedException>(() => sig.AsReadOnlySpan());
    }


    [TestMethod]
    public void AccessMemoryAfterDisposeThrows()
    {
        var sig = CreateSignature(SignatureBytes1, CryptoTags.P256Signature);
        sig.Dispose();

        Assert.Throws<ObjectDisposedException>(() => sig.AsReadOnlyMemory());
    }


    [TestMethod]
    public void DisposeReleasesMemory()
    {
        var sig = CreateSignature(SignatureBytes1, CryptoTags.P256Signature);
        sig.Dispose();

        //Double dispose should not throw.
        sig.Dispose();
    }


    [TestMethod]
    public void ToStringReturnsDebuggerDisplay()
    {
        using var sig = CreateSignature(SignatureBytes1, CryptoTags.P256Signature);

        string display = sig.ToString()!;

        Assert.IsNotNull(display);
        Assert.Contains("Signature(", display, StringComparison.Ordinal, "Display should start with 'Signature('.");
        Assert.Contains("P256", display, StringComparison.Ordinal, "Display should contain the algorithm name.");
        Assert.Contains($"{SignatureBytes1.Length} bytes", display, StringComparison.Ordinal, "Display should contain the byte count.");
        Assert.Contains("304402", display, StringComparison.Ordinal, "Display should contain a hex preview of the content.");
    }


    [TestMethod]
    public void DebuggerDisplayTruncatesLongSignatures()
    {
        using var sig = CreateSignature(LongSignatureBytes, CryptoTags.P256Signature);

        string display = sig.ToString()!;

        Assert.Contains("...", display, StringComparison.Ordinal, "Long signatures should show ellipsis in the display.");
        Assert.Contains($"{LongSignatureBytes.Length} bytes", display, StringComparison.Ordinal, "Display should show the full byte count.");
    }


    [TestMethod]
    public void DebuggerDisplayShowsUnknownForMissingAlgorithm()
    {
        using var sig = CreateSignature(SignatureBytes1, Tag.Empty);

        string display = sig.ToString()!;

        Assert.Contains("Unknown", display, StringComparison.Ordinal, "Display should show 'Unknown' when no algorithm is in the tag.");
    }


    /// <summary>
    /// Creates a <see cref="Signature"/> from raw bytes using <see cref="SensitiveMemoryPool{T}"/>.
    /// </summary>
    private static Signature CreateSignature(byte[] bytes, Tag tag)
    {
        var pool = SensitiveMemoryPool<byte>.Shared;
        var owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new Signature(owner, tag);
    }
}