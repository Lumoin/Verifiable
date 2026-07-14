using CsCheck;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Property-based tests (CsCheck) for the RFC 8230 §4 RSA support in <see cref="CoseKey"/> and
/// <see cref="CoseKeyExtensions.ToPublicKeyMemory"/>: invariants that must hold for every input in
/// a class, not just the hand-picked vectors in <see cref="CoseKeyRsaTests"/>.
/// </summary>
[TestClass]
internal sealed class CoseKeyRsaPropertyTests
{
    /// <summary>
    /// Property test: for any modulus byte length in [1, 600], building an RSA <see cref="CoseKey"/>
    /// and calling <see cref="CoseKeyExtensions.ToPublicKeyMemory"/> succeeds if and only if the
    /// length is one of the two registered RSA key sizes (256 or 512 bytes).
    /// </summary>
    [TestMethod]
    public void ModulusLengthGateAcceptsOnlyRegisteredRsaKeySizes()
    {
        Gen.Int[1, 600].Sample(length =>
        {
            byte[] modulus = new byte[length];
            modulus[0] = 0x80;
            CoseKey coseKey = new(kty: CoseKeyTypes.Rsa, n: modulus, e: CoseKeyRsaTests.DefaultPublicExponent);
            bool isRegisteredSize = length is 256 or 512;

            if(isRegisteredSize)
            {
                using PublicKeyMemory publicKey = coseKey.ToPublicKeyMemory(BaseMemoryPool.Shared);
                Assert.IsNotNull(publicKey);
            }
            else
            {
                Assert.ThrowsExactly<ArgumentException>(() => coseKey.ToPublicKeyMemory(BaseMemoryPool.Shared));
            }
        });
    }
}
