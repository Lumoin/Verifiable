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
