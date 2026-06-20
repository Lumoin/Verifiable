using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Verifiable.Tpm.Infrastructure.Sessions;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Known-answer tests for <see cref="TpmParameterEncryption.XorAsync"/> (TPM 2.0 Library Part 1,
/// Section 9.4.7.3, equation (4): <c>mask := KDFa(hashAlg, key, "XOR", contextU, contextV, data.size·8)</c>,
/// then XOR over the data).
/// </summary>
/// <remarks>
/// <para>
/// The oracle is .NET's <see cref="SP800108HmacCounterKdf"/> — an independent implementation of the KDFa
/// construction — composed with a hand-written XOR. The system under test routes through the project's KDFa
/// and registered HMAC primitive, so a divergence in the label, field order, counter, or byte layout fails the
/// comparison. This is the same non-circular oracle strategy as <c>KdfaTests</c>.
/// </para>
/// <para>
/// The session-key and per-command nonces are unobservable secret state with no public accessor, so this
/// primitive-level KAT (plus the hardware encrypted-GetRandom test) is how parameter-encryption correctness is
/// validated without a production test seam.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmParameterEncryptionTests
{
    public TestContext TestContext { get; set; } = null!;

    private static byte[] Key { get; } = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];

    private static byte[] NonceNewer { get; } = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];

    private static byte[] NonceOlder { get; } = [0xB0, 0xB1, 0xB2, 0xB3];

    [TestMethod]
    [DataRow("SHA1", 1)]
    [DataRow("SHA256", 16)]
    [DataRow("SHA256", 20)]   //Spans more than one SHA-256 block via KDFa.
    [DataRow("SHA256", 32)]
    [DataRow("SHA256", 48)]   //Two blocks.
    [DataRow("SHA384", 50)]
    [DataRow("SHA512", 70)]
    public async Task XorMatchesSp800108MaskOracle(string algName, int dataLength)
    {
        HashAlgorithmName algorithm = Hash(algName);

        byte[] plaintext = new byte[dataLength];
        for(int i = 0; i < dataLength; i++)
        {
            plaintext[i] = (byte)(0x30 + i);
        }

        //Independent oracle: mask = KDFa(...,"XOR",...) via SP800-108, then XOR by hand.
        byte[] mask = SP800108HmacCounterKdf.DeriveBytes(
            Key, algorithm, Encoding.ASCII.GetBytes("XOR"), Concat(NonceNewer, NonceOlder), dataLength);
        byte[] expected = new byte[dataLength];
        for(int i = 0; i < dataLength; i++)
        {
            expected[i] = (byte)(plaintext[i] ^ mask[i]);
        }

        byte[] actual = (byte[])plaintext.Clone();
        await TpmParameterEncryption.XorAsync(
            algorithm, Key, NonceNewer, NonceOlder, actual, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(actual.AsSpan().SequenceEqual(expected),
            $"XOR({algName}, {dataLength} bytes) must equal data XOR the SP800-108 'XOR'-label mask.");
    }

    [TestMethod]
    public async Task XorIsSelfInverse()
    {
        byte[] plaintext = new byte[40];
        RandomNumberGenerator.Fill(plaintext);
        byte[] working = (byte[])plaintext.Clone();

        //Obfuscate then recover with the identical key and nonces (the same call serves encrypt and decrypt).
        await TpmParameterEncryption.XorAsync(
            HashAlgorithmName.SHA256, Key, NonceNewer, NonceOlder, working, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(working.AsSpan().SequenceEqual(plaintext), "Obfuscation must change the data.");

        await TpmParameterEncryption.XorAsync(
            HashAlgorithmName.SHA256, Key, NonceNewer, NonceOlder, working, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(working.AsSpan().SequenceEqual(plaintext), "Applying XOR twice must recover the original data.");
    }

    [TestMethod]
    public async Task SwappedNonceOrderProducesDifferentMask()
    {
        //Command and response use opposite nonce orderings (nonceNewer/nonceOlder swap). The mask must differ,
        //so a direction bug cannot silently produce a matching mask.
        byte[] forward = new byte[32];
        byte[] swapped = new byte[32];

        await TpmParameterEncryption.XorAsync(
            HashAlgorithmName.SHA256, Key, NonceNewer, NonceOlder, forward, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        await TpmParameterEncryption.XorAsync(
            HashAlgorithmName.SHA256, Key, NonceOlder, NonceNewer, swapped, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(forward.AsSpan().SequenceEqual(swapped), "Swapping nonceNewer and nonceOlder must change the mask.");
    }

    [TestMethod]
    public async Task EmptyDataIsNoOp()
    {
        byte[] empty = [];

        //Must not throw (KDFa rejects a zero-length output, so the primitive short-circuits empty data).
        await TpmParameterEncryption.XorAsync(
            HashAlgorithmName.SHA256, Key, NonceNewer, NonceOlder, empty, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(empty);
    }

    //NIST SP800-38A, Appendix F.3.13 (CFB128-AES128.Encrypt) — the gold-standard, independent known-answer
    //vector for full-block CFB. Anchors the cipher core absolutely; the SUT (AesCfb) shares no code with it.
    private static byte[] NistKey { get; } = Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c");

    private static byte[] NistIv { get; } = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");

    private static byte[] NistPlaintext { get; } = Convert.FromHexString(
        "6bc1bee22e409f96e93d7e117393172a" +
        "ae2d8a571e03ac9c9eb76fac45af8e51" +
        "30c81c46a35ce411e5fbc1191a0a52ef" +
        "f69f2445df4f9b17ad2b417be66c3710");

    private static byte[] NistCipher { get; } = Convert.FromHexString(
        "3b3fd92eb72dad20333449f8e83cfb4a" +
        "c8a64537a0b3a93fcde3cdad9f1ce58b" +
        "26751f67a3cbb140b1808cf187a4f4df" +
        "c04b05357c5d1c0eeac4c66f9ff7f2e6");

    [TestMethod]
    public void AesCfb128MatchesNistSp80038aVectors()
    {
        byte[] ciphertext = (byte[])NistPlaintext.Clone();
        TpmParameterEncryption.AesCfb(NistKey, NistIv, ciphertext, encrypting: true);
        Assert.IsTrue(ciphertext.AsSpan().SequenceEqual(NistCipher),
            "AES-CFB128 encryption must match the NIST SP800-38A F.3.13 vector.");

        byte[] recovered = (byte[])NistCipher.Clone();
        TpmParameterEncryption.AesCfb(NistKey, NistIv, recovered, encrypting: false);
        Assert.IsTrue(recovered.AsSpan().SequenceEqual(NistPlaintext),
            "AES-CFB128 decryption must invert the NIST SP800-38A F.3.13 vector.");
    }

    [TestMethod]
    [DataRow(17)]   //One full block plus a partial final block.
    [DataRow(31)]   //Just short of two blocks.
    [DataRow(45)]   //Two full blocks plus a partial final block.
    public void AesCfb128PartialBlockMatchesNistVectorPrefix(int length)
    {
        //CFB-128 is a stream over the per-block keystream, so the leading 'length' ciphertext octets are
        //independent of the total length. The first 'length' octets of the F.3.13 ciphertext are therefore an
        //independent known-answer for a partial-final-block input — pinning the partial path, not just a
        //self-consistent round-trip.
        byte[] partial = NistPlaintext.AsSpan(0, length).ToArray();
        TpmParameterEncryption.AesCfb(NistKey, NistIv, partial, encrypting: true);
        Assert.IsTrue(partial.AsSpan().SequenceEqual(NistCipher.AsSpan(0, length)),
            $"AES-CFB128 of the first {length} bytes must equal the NIST ciphertext prefix.");

        TpmParameterEncryption.AesCfb(NistKey, NistIv, partial, encrypting: false);
        Assert.IsTrue(partial.AsSpan().SequenceEqual(NistPlaintext.AsSpan(0, length)),
            $"AES-CFB128 must invert the first {length} bytes.");
    }

    [TestMethod]
    [DataRow(16, 1)]
    [DataRow(16, 15)]
    [DataRow(16, 16)]
    [DataRow(16, 17)]   //Spans a full block plus a partial final block.
    [DataRow(16, 31)]
    [DataRow(16, 33)]
    [DataRow(16, 64)]
    [DataRow(32, 17)]   //AES-256 key, exercises the keyBits path + partial block.
    [DataRow(32, 48)]
    public void AesCfbRoundTripsArbitraryLengths(int keyBytes, int dataLength)
    {
        //Deterministic inputs: the round-trip property is the assertion, and determinism avoids the ~1/256
        //chance a tiny ciphertext coincides with its plaintext. Non-triviality is pinned by the NIST KAT above.
        byte[] key = new byte[keyBytes];
        byte[] iv = new byte[16];
        byte[] plaintext = new byte[dataLength];
        for(int i = 0; i < key.Length; i++)
        {
            key[i] = (byte)(0x40 + i);
        }
        for(int i = 0; i < iv.Length; i++)
        {
            iv[i] = (byte)(0x90 + i);
        }
        for(int i = 0; i < plaintext.Length; i++)
        {
            plaintext[i] = (byte)(0x11 + i);
        }

        byte[] working = (byte[])plaintext.Clone();
        TpmParameterEncryption.AesCfb(key, iv, working, encrypting: true);
        TpmParameterEncryption.AesCfb(key, iv, working, encrypting: false);
        Assert.IsTrue(working.AsSpan().SequenceEqual(plaintext),
            $"AES-CFB ({keyBytes * 8}-bit key) must round-trip {dataLength} bytes, including a partial final block.");
    }

    [TestMethod]
    public async Task CfbAsyncRoundTripsThroughKdfa()
    {
        //The full KDFa("CFB") → key/IV → AES-CFB composition must round-trip when the same hash, key, nonces,
        //and key size are used with the direction flipped.
        byte[] plaintext = new byte[40];
        RandomNumberGenerator.Fill(plaintext);
        byte[] working = (byte[])plaintext.Clone();

        await TpmParameterEncryption.CfbAsync(
            HashAlgorithmName.SHA256, 128, Key, NonceNewer, NonceOlder, working, encrypting: true, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(working.AsSpan().SequenceEqual(plaintext), "Encryption must change the data.");

        await TpmParameterEncryption.CfbAsync(
            HashAlgorithmName.SHA256, 128, Key, NonceNewer, NonceOlder, working, encrypting: false, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(working.AsSpan().SequenceEqual(plaintext), "Applying CFB encrypt then decrypt with the same key/nonces must recover the original.");
    }

    private static HashAlgorithmName Hash(string algName) => algName switch
    {
        "SHA1" => HashAlgorithmName.SHA1,
        "SHA256" => HashAlgorithmName.SHA256,
        "SHA384" => HashAlgorithmName.SHA384,
        "SHA512" => HashAlgorithmName.SHA512,
        _ => throw new ArgumentException($"Unmapped hash algorithm '{algName}'.", nameof(algName))
    };

    private static byte[] Concat(byte[] first, byte[] second)
    {
        byte[] result = new byte[first.Length + second.Length];
        first.CopyTo(result, 0);
        second.CopyTo(result, first.Length);

        return result;
    }
}
