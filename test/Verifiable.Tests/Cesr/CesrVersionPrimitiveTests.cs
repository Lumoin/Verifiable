using System.Collections.Generic;
using Verifiable.Cesr;

namespace Verifiable.Tests.Cesr;

/// <summary>
/// Tests for <see cref="CesrVersionPrimitive"/> — the native version primitive's protocol-and-version soft to
/// in-memory placeholder version string transform, shared by the KERI and ACDC native serializations. The vectors
/// are the placeholder version strings the KERI and ACDC native worked examples show, whose length field is a
/// base-64 count of the whole native serialization.
/// </summary>
[TestClass]
internal sealed class CesrVersionPrimitiveTests
{
    /// <summary>
    /// Version-primitive vectors: the placeholder version string, its protocol-and-version prefix (the primitive's
    /// soft), and the total serialization length its length field encodes.
    /// </summary>
    /// <returns>The version vectors.</returns>
    private static IEnumerable<object[]> VersionVectors()
    {
        yield return ["ACDCCAACAACESRAADc.", "ACDCCAACAA", 220];
        yield return ["KERICAACAACESRAAJM.", "KERICAACAA", 588];
    }


    /// <summary>
    /// The protocol-and-version prefix drops the serialization kind, length, and terminator the native framing carries.
    /// </summary>
    /// <param name="versionString">The full placeholder version string.</param>
    /// <param name="protocolAndVersion">The expected protocol-and-version prefix.</param>
    /// <param name="totalLength">The total serialization length (unused here).</param>
    [TestMethod]
    [DynamicData(nameof(VersionVectors))]
    public void ExtractsProtocolAndVersion(string versionString, string protocolAndVersion, int totalLength)
    {
        _ = totalLength;

        Assert.AreEqual(protocolAndVersion, CesrVersionPrimitive.ProtocolAndVersion(versionString));
    }


    /// <summary>
    /// Reconstructing from the protocol-and-version prefix and the total length rebuilds the placeholder version string.
    /// </summary>
    /// <param name="versionString">The expected full placeholder version string.</param>
    /// <param name="protocolAndVersion">The protocol-and-version prefix.</param>
    /// <param name="totalLength">The total serialization length.</param>
    [TestMethod]
    [DynamicData(nameof(VersionVectors))]
    public void ReconstructsVersionString(string versionString, string protocolAndVersion, int totalLength)
    {
        Assert.AreEqual(versionString, CesrVersionPrimitive.Reconstruct(protocolAndVersion, totalLength));
    }


    /// <summary>
    /// A string too short to be a version 2.XX version string is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsTooShortVersionString()
    {
        Assert.ThrowsExactly<CesrFormatException>(() => CesrVersionPrimitive.ProtocolAndVersion("ACDC"));
    }
}
