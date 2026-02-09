using System.Buffers;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Tests for <see cref="PublicKeyMemory"/> <see cref="IEquatable{T}"/> implementation.
/// </summary>
[TestClass]
internal sealed class PublicKeyMemoryEquatableTests
{
    [TestMethod]
    public void InstancesFromDifferentSizedBuffersAreNotEqual()
    {
        using var pkm1 = CreatePublicKeyMemory(1);
        using var pkm2 = CreatePublicKeyMemory(2);

        Assert.IsFalse(pkm1.Equals(pkm2));
        Assert.IsFalse(pkm1 == pkm2);
        Assert.IsTrue(pkm1 != pkm2);
    }


    [TestMethod]
    public void InstancesFromSameSizeBuffersAreEqual()
    {
        using var pkm1 = CreatePublicKeyMemory(1);
        using var pkm2 = CreatePublicKeyMemory(1);

        Assert.IsTrue(pkm1.Equals(pkm2));
        Assert.IsTrue(pkm1 == pkm2);
        Assert.IsFalse(pkm1 != pkm2);
    }


    [TestMethod]
    public void SameLengthInstancesWithDifferentDataAreNotEqual()
    {
        using var pkm1 = CreatePublicKeyMemory(1);
        using var pkm2 = CreatePublicKeyMemory(1, fillByte: 0x01);

        Assert.IsFalse(pkm1.Equals(pkm2));
        Assert.IsTrue(pkm1 != pkm2);
        Assert.IsFalse(pkm1 == pkm2);
    }


    [TestMethod]
    public void ComparisonWithTypeAndObjectSucceeds()
    {
        using var pkm1 = CreatePublicKeyMemory(1);
        using var pkm2 = CreatePublicKeyMemory(1);

        Assert.IsTrue((object)pkm1 == pkm2);
        Assert.IsTrue(pkm1 == (object)pkm2);
        Assert.IsFalse((object)pkm1 != pkm2);
        Assert.IsFalse(pkm1 != (object)pkm2);
    }


    [TestMethod]
    public void EqualsWithTypeAndObjectSucceeds()
    {
        using var pkm1 = CreatePublicKeyMemory(1);
        using var pkm2 = CreatePublicKeyMemory(1);

        Assert.IsTrue(((object)pkm1).Equals(pkm2));
        Assert.IsTrue(pkm1.Equals((object)pkm2));
    }


    [TestMethod]
    public void ComparisonWithObjectAndObjectFails()
    {
        using var pkm1 = CreatePublicKeyMemory(1);
        using var pkm2 = CreatePublicKeyMemory(1);

        //The reason for this is that the == operator is resolved
        //at compile time. The compiler does not find the overloads
        //and so the test fails. This is included here for the sake
        //of completeness. See EqualsWithObjectAndObjectSucceeds.
#pragma warning disable MSTEST0037 // Use proper 'Assert' methods
        Assert.IsFalse((object)pkm1 == (object)pkm2);
#pragma warning restore MSTEST0037 // Use proper 'Assert' methods
    }


    [TestMethod]
    public void EqualsWithObjectAndObjectSucceeds()
    {
        //As opposed to ComparisonWithObjectAndObjectFails,
        //.Equals is a runtime construct and it does find
        //the overloads and so this comparison succeeds.
        using var pkm1 = CreatePublicKeyMemory(1);
        using var pkm2 = CreatePublicKeyMemory(1);

        Assert.IsTrue(((object)pkm1).Equals(pkm2));
    }


    /// <summary>
    /// Creates a <see cref="PublicKeyMemory"/> with the specified buffer size.
    /// </summary>
    /// <param name="size">The buffer size in bytes.</param>
    /// <param name="fillByte">Optional byte value to fill the buffer with.</param>
    /// <returns>A new public key memory instance. The caller must dispose it.</returns>
    private static PublicKeyMemory CreatePublicKeyMemory(int size, byte fillByte = 0x00)
    {
        IMemoryOwner<byte> buffer = SensitiveMemoryPool<byte>.Shared.Rent(size);
        buffer.Memory.Span.Fill(fillByte);

        return new PublicKeyMemory(buffer, Tag.Empty);
    }
}