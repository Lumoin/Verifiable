using System.Security.Cryptography;
using CsCheck;
using Verifiable.Cryptography;
using Verifiable.Fido2;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Property-based tests (CsCheck) for <see cref="Fido2ClientDataHash.Compute"/>: the invariant that its
/// output equals an independent <see cref="SHA256.HashData(ReadOnlySpan{byte})"/> oracle holds across the
/// full range of <c>clientDataJSON</c> byte lengths, not just the hand-picked vector checked in
/// <see cref="Fido2ClientDataHashOracleTests"/>.
/// </summary>
[TestClass]
internal sealed class Fido2ClientDataHashOraclePropertyTests
{
    /// <summary>
    /// Property test: for any byte length in [0, 4096], <see cref="Fido2ClientDataHash.Compute"/> equals
    /// the independent SHA-256 oracle — not merely for one hand-picked vector, so a defect confined to a
    /// particular input length or alignment would still surface.
    /// </summary>
    [TestMethod]
    public void ComputeEqualsIndependentSha256OracleAcrossInputLengths()
    {
        Gen.Byte.Array[0, 4096].Sample(clientDataJson =>
        {
            using DigestValue hash = Fido2ClientDataHash.Compute(clientDataJson, BaseMemoryPool.Shared);
            byte[] expected = SHA256.HashData(clientDataJson);

            Assert.IsTrue(hash.AsReadOnlySpan().SequenceEqual(expected));
        });
    }
}
