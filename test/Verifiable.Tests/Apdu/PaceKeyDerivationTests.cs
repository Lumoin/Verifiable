using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Apdu.Pace;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates the ICAO Doc 9303 Part 11 PACE key derivation and nonce decryption (AES-128 profile)
/// against the worked examples in Appendix H.1 (ECDH integrated mapping) and Appendix I (the MRZ
/// password example). The key-derivation function and the nonce cipher are independent of the
/// mapping type, so these vectors exercise the symmetric foundation directly.
/// </summary>
[TestClass]
internal sealed class PaceKeyDerivationTests
{
    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task DerivesNonceKeyKpiPerAppendixI()
    {
        //Appendix I: Kpi = KDF(K, 3) with SHA-1, first 16 octets.
        byte[] password = Convert.FromHexString("894D03F148C6265E89845B218856EA34D00EF8E8");

        using SymmetricKeyMemory nonceKey = await PaceKeyDerivation.DerivePasswordKeyAsync(
            password, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual("4E6F6FBF7BE748B932C7B74161BBA9DF", Convert.ToHexString(nonceKey.AsReadOnlySpan()),
            "Kpi must match Doc 9303 Appendix I.");
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Both session keys are disposed in the finally block.")]
    public async Task DerivesSessionKeysPerAppendixH1()
    {
        //Appendix H.1: KSenc = KDF(K, 1), KSmac = KDF(K, 2) with SHA-1 over the 32-byte shared secret.
        byte[] sharedSecret = Convert.FromHexString(
            "4F150FDE1D4F0E38E95017B891BAE17133A0DF45B0D3E18B60BA7BEAFDC2C713");

        (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) =
            await PaceKeyDerivation.DeriveSessionKeysAsync(sharedSecret, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            Assert.AreEqual("0D3FEB33251A6370893D62AE8DAAF51B", Convert.ToHexString(encryptionKey.AsReadOnlySpan()),
                "KSenc must match Doc 9303 Appendix H.1.");
            Assert.AreEqual("B01E89E3D9E8719E586B50B4A7506E0B", Convert.ToHexString(macKey.AsReadOnlySpan()),
                "KSmac must match Doc 9303 Appendix H.1.");
        }
        finally
        {
            encryptionKey.Dispose();
            macKey.Dispose();
        }
    }


    [TestMethod]
    public async Task DecryptsTheEncryptedNoncePerAppendixH1()
    {
        //Appendix H.1: s = AES-128-CBC-decrypt(Kpi, z) with a zero IV.
        using SymmetricKeyMemory nonceKey = CreateKey("591468CDA83D65219CCCB8560233600F");
        byte[] encryptedNonce = Convert.FromHexString("143DC40C08C8E891FBED7DEDB92B64AD");

        using DecryptedContent nonce = await PaceKeyDerivation.DecryptNonceAsync(
            nonceKey, encryptedNonce, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual("2923BE84E16CD6AE529049F1F1BBE9EB", Convert.ToHexString(nonce.AsReadOnlySpan()),
            "The decrypted nonce s must match Doc 9303 Appendix H.1.");
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned SymmetricKeyMemory, which the caller disposes.")]
    private static SymmetricKeyMemory CreateKey(string hex)
    {
        byte[] bytes = Convert.FromHexString(hex);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new SymmetricKeyMemory(owner, CryptoTags.Aes128Cbc);
    }
}
