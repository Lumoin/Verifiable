using System;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Known-answer tests for the eMRTD Secure Messaging symmetric primitives — two-key
/// Triple-DES in CBC mode and the ISO/IEC 9797-1 MAC Algorithm 3 ("Retail MAC") — against
/// the worked example in ICAO Doc 9303 Part 11, Eighth Edition (2021), Appendix D.
/// </summary>
/// <remarks>
/// <para>
/// The vectors are the deterministic intermediate values the specification publishes for
/// Basic Access Control and 3DES Secure Messaging (Appendix D.3 and D.4). They exercise the
/// primitives exactly as the Secure Messaging layer will: zero IV, no cipher padding (the
/// data objects arrive already padded with ISO 9797-1 method 2), and an 8-byte Retail MAC
/// over a pre-padded message. Every operation is driven through the registered registry
/// delegate, so a passing test also proves the backend is wired.
/// </para>
/// </remarks>
[TestClass]
internal sealed class EmrtdSecureMessagingCryptoTests
{
    /// <summary>The 8-byte all-zero IV that ICAO Doc 9303 3DES Secure Messaging uses for every CBC operation.</summary>
    private static readonly byte[] ZeroIv = new byte[8];

    /// <summary>The KSEnc session encryption key from Appendix D.3/D.4.</summary>
    private const string Ksenc = "979EC13B1CBFE9DCD01AB0FED307EAE5";

    /// <summary>The KSMAC session MAC key from Appendix D.3/D.4.</summary>
    private const string Ksmac = "F1CB1F1FB5ADF208806B89DC579DC1F8";


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task TripleDesCbcEncryptsSelectCommandDataPerAppendixD4()
    {
        //Appendix D.4, step 1: SELECT EF.COM. Padded data 011E80...00 encrypts under KSEnc to DO'87' content.
        await AssertEncrypt(Ksenc, "011E800000000000", "6375432908C044F6").ConfigureAwait(false);
    }


    [TestMethod]
    public async Task TripleDesCbcEncryptsAuthenticationDataPerAppendixD3()
    {
        //Appendix D.3: the inspection system encrypts S (RND.IFD || RND.IC || KIFD) under KEnc to form EIFD.
        //Four-block vector — exercises CBC chaining, not just a single ECB-equivalent block.
        const string kenc = "AB94FDECF2674FDFB9B391F85D7F76F2";
        const string s = "781723860C06C2264608F91988702212" + "0B795240CB7049B01C19B33E32804F0B";
        const string eifd = "72C29C2371CC9BDB65B779B8E8D37B29" + "ECC154AA56A8799FAE2F498F76ED92F2";
        await AssertEncrypt(kenc, s, eifd).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task TripleDesCbcDecryptsSingleBlockResponsePerAppendixD4()
    {
        //Appendix D.4, step 1: DO'87' ciphertext of the EF.COM length read decrypts to 60145F01 plus padding.
        await AssertDecrypt(Ksenc, "9FF0EC34F9922651", "60145F0180000000").ConfigureAwait(false);
    }


    [TestMethod]
    public async Task TripleDesCbcDecryptsMultiBlockResponsePerAppendixD4()
    {
        //Appendix D.4, step 3: the 24-byte DO'87' ciphertext decrypts to the remaining EF.COM bytes plus padding.
        const string ciphertext = "FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A";
        const string plaintext = "04303130365F36063034303030305C026175" + "800000000000";
        await AssertDecrypt(Ksenc, ciphertext, plaintext).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task TripleDesCbcRoundTripsThroughEncryptAndDecrypt()
    {
        const string plaintext = "011E800000000000";
        SymmetricEncryptDelegate encrypt = ResolveEncrypt();
        SymmetricDecryptDelegate decrypt = ResolveDecrypt();

        (Ciphertext ciphertext, _) = await encrypt(
            Convert.FromHexString(plaintext), Convert.FromHexString(Ksenc), ZeroIv,
            CryptoTags.TripleDesCbc, BaseMemoryPool.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            (DecryptedContent recovered, _) = await decrypt(
                ciphertext.AsReadOnlyMemory(), Convert.FromHexString(Ksenc), ZeroIv,
                CryptoTags.TripleDesCbcDecryptedContent, BaseMemoryPool.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);
            try
            {
                Assert.AreEqual(plaintext, Convert.ToHexString(recovered.AsReadOnlySpan()),
                    "Decrypting the ciphertext must recover the original padded plaintext.");
            }
            finally
            {
                recovered.Dispose();
            }
        }
        finally
        {
            ciphertext.Dispose();
        }
    }


    [TestMethod]
    public async Task RetailMacAuthenticatesSelectCommandPerAppendixD4()
    {
        //Appendix D.4, step 1f: CC = MAC(KSMAC) over SSC || CmdHeader || DO'87', method-2 padded.
        const string paddedMessage = "887022120C06C227" + "0CA4020C80000000" + "8709016375432908C044F6" + "8000000000";
        await AssertMac(Ksmac, paddedMessage, "BF8B92D635FF24F8").ConfigureAwait(false);
    }


    [TestMethod]
    public async Task RetailMacAuthenticatesSelectResponsePerAppendixD4()
    {
        //Appendix D.4, step 1j: CC' = MAC(KSMAC) over SSC || DO'99', method-2 padded.
        const string paddedMessage = "887022120C06C228" + "9902900080000000";
        await AssertMac(Ksmac, paddedMessage, "FA855A5D4C50A8ED").ConfigureAwait(false);
    }


    [TestMethod]
    public async Task RetailMacAuthenticatesReadBinaryCommandPerAppendixD4()
    {
        //Appendix D.4, step 2d: CC = MAC(KSMAC) over SSC || CmdHeader || DO'97', method-2 padded.
        const string paddedMessage = "887022120C06C229" + "0CB0000080000000" + "970104" + "8000000000";
        await AssertMac(Ksmac, paddedMessage, "ED6705417E96BA55").ConfigureAwait(false);
    }


    [TestMethod]
    public async Task RetailMacVerifyAcceptsGenuineTagAndRejectsTamperedTag()
    {
        const string paddedMessage = "887022120C06C227" + "0CA4020C80000000" + "8709016375432908C044F6" + "8000000000";
        byte[] message = Convert.FromHexString(paddedMessage);
        byte[] genuine = Convert.FromHexString("BF8B92D635FF24F8");

        VerifyBlockCipherMacDelegate verify = ResolveVerify();

        (bool genuineValid, _) = await verify(
            message, Convert.FromHexString(Ksmac), genuine,
            CryptoTags.RetailMac, BaseMemoryPool.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(genuineValid, "Verification must accept the genuine Doc 9303 Retail MAC.");

        byte[] tampered = (byte[])genuine.Clone();
        tampered[0] ^= 0x01;
        (bool tamperedValid, _) = await verify(
            message, Convert.FromHexString(Ksmac), tampered,
            CryptoTags.RetailMac, BaseMemoryPool.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(tamperedValid, "Verification must reject a MAC whose first byte is flipped.");
    }


    [TestMethod]
    public async Task RetailMacDiffersUnderTheWrongKey()
    {
        const string paddedMessage = "887022120C06C227" + "0CA4020C80000000" + "8709016375432908C044F6" + "8000000000";
        //KSEnc is the wrong key for a MAC — it must not reproduce the KSMAC tag.
        await AssertMacNotEqual(Ksenc, paddedMessage, "BF8B92D635FF24F8").ConfigureAwait(false);
    }


    private async Task AssertEncrypt(string keyHex, string plaintextHex, string expectedCiphertextHex)
    {
        SymmetricEncryptDelegate encrypt = ResolveEncrypt();
        (Ciphertext result, CryptoEvent? evt) = await encrypt(
            Convert.FromHexString(plaintextHex), Convert.FromHexString(keyHex), ZeroIv,
            CryptoTags.TripleDesCbc, BaseMemoryPool.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            Assert.AreEqual(expectedCiphertextHex, Convert.ToHexString(result.AsReadOnlySpan()),
                "Triple-DES CBC ciphertext must match the Doc 9303 Appendix D worked example.");
            Assert.IsInstanceOfType<SymmetricCipherPerformedEvent>(evt,
                "The operation must emit a SymmetricCipherPerformedEvent for CBOM provenance.");
        }
        finally
        {
            result.Dispose();
        }
    }


    private async Task AssertDecrypt(string keyHex, string ciphertextHex, string expectedPlaintextHex)
    {
        SymmetricDecryptDelegate decrypt = ResolveDecrypt();
        (DecryptedContent result, _) = await decrypt(
            Convert.FromHexString(ciphertextHex), Convert.FromHexString(keyHex), ZeroIv,
            CryptoTags.TripleDesCbcDecryptedContent, BaseMemoryPool.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            Assert.AreEqual(expectedPlaintextHex, Convert.ToHexString(result.AsReadOnlySpan()),
                "Triple-DES CBC plaintext must match the Doc 9303 Appendix D worked example.");
        }
        finally
        {
            result.Dispose();
        }
    }


    private async Task AssertMac(string keyHex, string messageHex, string expectedMacHex)
    {
        ComputeBlockCipherMacDelegate compute = ResolveCompute();
        (MacValue result, CryptoEvent? evt) = await compute(
            Convert.FromHexString(messageHex), Convert.FromHexString(keyHex), expectedMacHex.Length / 2,
            CryptoTags.RetailMac, BaseMemoryPool.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            Assert.AreEqual(expectedMacHex, Convert.ToHexString(result.AsReadOnlySpan()),
                "Retail MAC must match the Doc 9303 Appendix D worked example.");
            Assert.IsInstanceOfType<BlockCipherMacComputedEvent>(evt,
                "The operation must emit a BlockCipherMacComputedEvent for CBOM provenance.");
        }
        finally
        {
            result.Dispose();
        }
    }


    private async Task AssertMacNotEqual(string keyHex, string messageHex, string unexpectedMacHex)
    {
        ComputeBlockCipherMacDelegate compute = ResolveCompute();
        (MacValue result, _) = await compute(
            Convert.FromHexString(messageHex), Convert.FromHexString(keyHex), unexpectedMacHex.Length / 2,
            CryptoTags.RetailMac, BaseMemoryPool.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            Assert.AreNotEqual(unexpectedMacHex, Convert.ToHexString(result.AsReadOnlySpan()),
                "A MAC computed under the wrong key must not reproduce the genuine tag.");
        }
        finally
        {
            result.Dispose();
        }
    }


    private static SymmetricEncryptDelegate ResolveEncrypt() =>
        CryptographicKeyFactory.GetFunction<SymmetricEncryptDelegate>(typeof(SymmetricEncryptDelegate))
            ?? throw new InvalidOperationException("No SymmetricEncryptDelegate has been registered.");


    private static SymmetricDecryptDelegate ResolveDecrypt() =>
        CryptographicKeyFactory.GetFunction<SymmetricDecryptDelegate>(typeof(SymmetricDecryptDelegate))
            ?? throw new InvalidOperationException("No SymmetricDecryptDelegate has been registered.");


    private static ComputeBlockCipherMacDelegate ResolveCompute() =>
        CryptographicKeyFactory.GetFunction<ComputeBlockCipherMacDelegate>(typeof(ComputeBlockCipherMacDelegate))
            ?? throw new InvalidOperationException("No ComputeBlockCipherMacDelegate has been registered.");


    private static VerifyBlockCipherMacDelegate ResolveVerify() =>
        CryptographicKeyFactory.GetFunction<VerifyBlockCipherMacDelegate>(typeof(VerifyBlockCipherMacDelegate))
            ?? throw new InvalidOperationException("No VerifyBlockCipherMacDelegate has been registered.");
}
