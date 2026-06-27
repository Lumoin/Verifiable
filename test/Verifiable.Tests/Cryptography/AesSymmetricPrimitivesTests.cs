using System;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Known-answer tests for the AES symmetric primitives that ICAO Doc 9303 PACE and AES Secure
/// Messaging build on: AES-CMAC against the RFC 4493 Section 4 test vectors, and AES-128 CBC
/// against the NIST FIPS 197 / SP 800-38A known answer. Every operation runs through the
/// registered registry delegate.
/// </summary>
[TestClass]
internal sealed class AesSymmetricPrimitivesTests
{
    //The RFC 4493 / NIST AES-128 key shared by all the vectors below.
    private const string Key = "2B7E151628AED2A6ABF7158809CF4F3C";


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task AesCmacMatchesRfc4493EmptyMessage()
    {
        await AssertCmac("", "BB1D6929E95937287FA37D129B756746").ConfigureAwait(false);
    }


    [TestMethod]
    public async Task AesCmacMatchesRfc4493SingleBlock()
    {
        await AssertCmac("6BC1BEE22E409F96E93D7E117393172A", "070A16B46B4D4144F79BDD9DD04A287C").ConfigureAwait(false);
    }


    [TestMethod]
    public async Task AesCmacMatchesRfc4493PartialBlock()
    {
        //40 bytes - not block aligned; CMAC pads internally per RFC 4493 (the Retail MAC would not).
        await AssertCmac(
            "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411",
            "DFA66747DE9AE63030CA32611497C827").ConfigureAwait(false);
    }


    [TestMethod]
    public async Task AesCmacMatchesRfc4493FourBlocks()
    {
        await AssertCmac(
            "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
            "51F0BEBF7E3B9D92FC49741779363CFE").ConfigureAwait(false);
    }


    [TestMethod]
    public async Task Aes128CbcEncryptsTheNistKnownAnswerAndRoundTrips()
    {
        //NIST FIPS 197 single-block known answer: with an all-zero IV the first CBC block equals ECB.
        const string plaintext = "6BC1BEE22E409F96E93D7E117393172A";
        const string ciphertext = "3AD77BB40D7A3660A89ECAF32466EF97";
        byte[] zeroIv = new byte[16];

        SymmetricEncryptDelegate encrypt = Resolve<SymmetricEncryptDelegate>();
        SymmetricDecryptDelegate decrypt = Resolve<SymmetricDecryptDelegate>();

        (Ciphertext encrypted, _) = await encrypt(
            Convert.FromHexString(plaintext), Convert.FromHexString(Key), zeroIv,
            CryptoTags.Aes128Cbc, BaseMemoryPool.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            Assert.AreEqual(ciphertext, Convert.ToHexString(encrypted.AsReadOnlySpan()),
                "AES-128 CBC ciphertext must match the NIST known answer.");

            (DecryptedContent recovered, _) = await decrypt(
                encrypted.AsReadOnlyMemory(), Convert.FromHexString(Key), zeroIv,
                CryptoTags.Aes128CbcDecryptedContent, BaseMemoryPool.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);
            try
            {
                Assert.AreEqual(plaintext, Convert.ToHexString(recovered.AsReadOnlySpan()),
                    "AES-128 CBC decryption must recover the plaintext.");
            }
            finally
            {
                recovered.Dispose();
            }
        }
        finally
        {
            encrypted.Dispose();
        }
    }


    private async Task AssertCmac(string messageHex, string expectedMacHex)
    {
        byte[] message = messageHex.Length == 0 ? [] : Convert.FromHexString(messageHex);
        ComputeBlockCipherMacDelegate compute = Resolve<ComputeBlockCipherMacDelegate>();

        (MacValue result, _) = await compute(
            message, Convert.FromHexString(Key), expectedMacHex.Length / 2,
            CryptoTags.Aes128Cmac, BaseMemoryPool.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            Assert.AreEqual(expectedMacHex, Convert.ToHexString(result.AsReadOnlySpan()),
                "AES-CMAC must match the RFC 4493 test vector.");
        }
        finally
        {
            result.Dispose();
        }
    }


    private static TDelegate Resolve<TDelegate>() where TDelegate: Delegate =>
        CryptographicKeyFactory.GetFunction<TDelegate>(typeof(TDelegate))
            ?? throw new InvalidOperationException($"No {typeof(TDelegate).Name} has been registered.");
}
