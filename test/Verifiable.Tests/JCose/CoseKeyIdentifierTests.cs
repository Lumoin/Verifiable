using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Tests for <see cref="CoseKeyIdentifier"/>: the borrowed-view round trip, the <see cref="KeyId"/>
/// hex projection, and the content-based <see cref="IEquatable{T}"/> implementation — two independently
/// constructed instances over independently allocated buffers with identical bytes must compare equal
/// and report the same hash code, while any differing byte must break equality.
/// </summary>
/// <remarks>
/// Every buffer under test is a freshly allocated array, never a shared reference, so a passing positive
/// equality test proves content equality rather than the reference/alias equality
/// <see cref="ReadOnlyMemory{T}"/>'s own default comparison would give two independent buffers — the
/// anti-trap this carrier exists to close (see the type remarks).
/// </remarks>
[TestClass]
internal sealed class CoseKeyIdentifierTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary><see cref="CoseKeyIdentifier.Value"/> round-trips the exact bytes handed to the constructor.</summary>
    [TestMethod]
    public void ValueRoundTripsConstructorBytes()
    {
        byte[] bytes = [0x30, 0x05, 0x02, 0x01, 0x2A, 0x0C, 0x00];
        CoseKeyIdentifier kid = new(bytes);

        Assert.IsTrue(bytes.AsSpan().SequenceEqual(kid.Value.Span));
    }


    /// <summary>
    /// <see cref="CoseKeyIdentifier.ToKeyId"/> projects the opaque bytes to their lower-case hexadecimal
    /// rendering, against a known vector.
    /// </summary>
    [TestMethod]
    public void ToKeyIdReturnsLowerCaseHexOfTheBytes()
    {
        CoseKeyIdentifier kid = new(new byte[] { 0x01, 0xAB });

        KeyId keyId = kid.ToKeyId();

        Assert.AreEqual("01ab", keyId.Value);
    }


    /// <summary>
    /// Two carriers over independently allocated but byte-identical buffers compare equal, satisfy both
    /// equality operators, and report the same hash code — the anti-trap proof a record's synthesized
    /// <see cref="ReadOnlyMemory{T}"/> equality would fail (see the type remarks).
    /// </summary>
    [TestMethod]
    public void CarriersWithEqualContentFromIndependentBuffersAreEqual()
    {
        byte[] bufferA = [1, 2, 3, 4];
        byte[] bufferB = [1, 2, 3, 4];
        Assert.AreNotSame(bufferA, bufferB);

        CoseKeyIdentifier kidA = new(bufferA);
        CoseKeyIdentifier kidB = new(bufferB);

        Assert.IsTrue(kidA.Equals(kidB));
        Assert.IsTrue(kidA.Equals((object)kidB));
        Assert.IsTrue(kidA == kidB);
        Assert.IsFalse(kidA != kidB);
        Assert.AreEqual(kidA.GetHashCode(), kidB.GetHashCode());
    }


    /// <summary>A differing byte breaks equality even when every other byte and the length match.</summary>
    [TestMethod]
    public void DifferingContentBreaksEquality()
    {
        CoseKeyIdentifier kidA = new(new byte[] { 1, 2, 3, 4 });
        CoseKeyIdentifier kidB = new(new byte[] { 1, 2, 3, 5 });

        Assert.IsFalse(kidA.Equals(kidB));
        Assert.IsFalse(kidA == kidB);
        Assert.IsTrue(kidA != kidB);
    }


    /// <summary>A differing length breaks equality even when every shared-index byte matches.</summary>
    [TestMethod]
    public void DifferingLengthBreaksEquality()
    {
        CoseKeyIdentifier kidA = new(new byte[] { 1, 2, 3 });
        CoseKeyIdentifier kidB = new(new byte[] { 1, 2, 3, 4 });

        Assert.IsFalse(kidA.Equals(kidB));
    }


    /// <summary>
    /// <see cref="CoseKeyIdentifier.Equals(CoseKeyIdentifier?)"/> reports <see langword="false"/> against
    /// <see langword="null"/>, the <c>==</c>/<c>!=</c> operators agree, and two <see langword="null"/>
    /// references compare equal — matching this codebase's carrier-equality convention.
    /// </summary>
    [TestMethod]
    public void NullHandlingMatchesCarrierConvention()
    {
        CoseKeyIdentifier kid = new(new byte[] { 1, 2, 3, 4 });
        CoseKeyIdentifier? nullKidA = null;
        CoseKeyIdentifier? nullKidB = null;

        Assert.IsFalse(kid.Equals(null));
        Assert.IsFalse(kid.Equals((object?)null));
        Assert.IsFalse(kid == nullKidA);
        Assert.IsFalse(nullKidA == kid);
        Assert.IsTrue(kid != nullKidA);
        Assert.IsTrue(nullKidA == nullKidB);
    }


    /// <summary>
    /// <see cref="CoseKeyIdentifier.Equals(object?)"/> reports <see langword="false"/> for a non-<see cref="CoseKeyIdentifier"/>
    /// object. The comparison is deliberately cross-type: it is the <see cref="object.Equals(object?)"/> contract's own
    /// "different type" case, proved here with a <see cref="string"/> operand.
    /// </summary>
    [TestMethod]
    public void EqualsObjectReturnsFalseForUnrelatedType()
    {
        CoseKeyIdentifier kid = new(new byte[] { 1, 2, 3, 4 });

        Assert.IsFalse(kid.Equals("not a CoseKeyIdentifier"));
    }
}
