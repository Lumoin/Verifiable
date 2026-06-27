using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Apdu.SecureMessaging;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates the AES-128 Secure Messaging profile (the PACE profile) of <see cref="SecureMessagingSession"/>.
/// ICAO Doc 9303 publishes no AES Secure Messaging worked example with full intermediate values (unlike
/// the 3DES Appendix D.4), so the AES protect step is checked for self-consistency by independently
/// re-deriving the per-command IV (<c>E(KSenc, SSC)</c>), decrypting the cryptogram back to the original
/// command data, and recomputing the MAC — all through the same registered primitives — and confirming
/// the session's output matches. The 3DES Appendix D.4 test guards the shared framing against regression.
/// </summary>
/// <remarks>
/// <para>
/// The session keys are the Appendix G.1 PACE session keys. A published AES Secure Messaging
/// conformance vector (for example from BSI TR-03105 test data) remains a useful future cross-check.
/// </para>
/// </remarks>
[TestClass]
internal sealed class AesSecureMessagingSessionTests
{
    private const string Ksenc = "F5F0E35C0D7161EE6724EE513A0D9A7F";
    private const string Ksmac = "FE251C7858B356B24514B3BD5F4297D1";
    private const string CommandData = "011E";

    private const int AesBlockSize = 16;
    private const int MacLength = 8;


    public required TestContext TestContext { get; set; }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The session takes ownership of the two keys and is disposed via its using declaration.")]
    public async Task AesProtectIsSelfConsistentWithTheRegisteredPrimitives()
    {
        using SecureMessagingSession session = new(
            CreateKey(Ksenc, CryptoTags.Aes128Cbc), CreateKey(Ksmac, CryptoTags.Aes128Cmac),
            new byte[AesBlockSize], SecureMessagingProfile.Aes128, BaseMemoryPool.Shared);

        using ProtectedCommandApdu protectedApdu = await session.ProtectCommandAsync(
            0x00, 0xA4, 0x02, 0x0C, Convert.FromHexString(CommandData), expectedResponseLength: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] apdu = protectedApdu.AsReadOnlySpan().ToArray();

        //Protected APDU: 0C A4 02 0C | Lc | 87 11 01 <16-byte cryptogram> | 8E 08 <8-byte MAC> | 00.
        Assert.AreEqual(0x87, apdu[5], "The first protected data object must be DO'87'.");
        Assert.AreEqual(0x8E, apdu[24], "The second protected data object must be DO'8E'.");
        byte[] cryptogram = apdu[8..24];
        byte[] mac = apdu[26..34];
        byte[] cryptogramObject = apdu[5..24];

        //The SSC advances to 1 for the first command; the IV is E(KSenc, SSC).
        byte[] sequenceCounter = new byte[AesBlockSize];
        sequenceCounter[^1] = 0x01;
        byte[] iv = await EncryptAsync(sequenceCounter, Ksenc, new byte[AesBlockSize]).ConfigureAwait(false);

        //Decrypting the cryptogram with the independently derived IV must recover the padded command data.
        byte[] recovered = await DecryptAsync(cryptogram, Ksenc, iv).ConfigureAwait(false);
        int unpaddedLength = Iso9797Padding.UnpaddedLength(recovered);
        Assert.AreEqual(CommandData, Convert.ToHexString(recovered.AsSpan(0, unpaddedLength)),
            "Decrypting DO'87' with E(KSenc, SSC) must recover the original command data.");

        //Recompute the MAC over SSC || padded-header || DO'87', method-2 padded to the AES block.
        byte[] paddedHeader = new byte[AesBlockSize];
        Iso9797Padding.Pad([0x0C, 0xA4, 0x02, 0x0C], AesBlockSize, paddedHeader);
        byte[] macSource = Concatenate(sequenceCounter, paddedHeader, cryptogramObject);
        byte[] paddedMacSource = new byte[Iso9797Padding.PaddedLength(macSource.Length, AesBlockSize)];
        Iso9797Padding.Pad(macSource, AesBlockSize, paddedMacSource);
        byte[] expectedMac = await ComputeMacAsync(paddedMacSource, Ksmac).ConfigureAwait(false);

        Assert.AreEqual(Convert.ToHexString(expectedMac), Convert.ToHexString(mac),
            "The DO'8E' MAC must equal an independent AES-CMAC over the SSC-prefixed, padded message.");
    }


    private async Task<byte[]> EncryptAsync(byte[] plaintext, string keyHex, byte[] iv)
    {
        SymmetricEncryptDelegate encrypt = Resolve<SymmetricEncryptDelegate>();
        (Ciphertext result, _) = await encrypt(
            plaintext, Convert.FromHexString(keyHex), iv, CryptoTags.Aes128Cbc,
            BaseMemoryPool.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            return result.AsReadOnlySpan().ToArray();
        }
        finally
        {
            result.Dispose();
        }
    }


    private async Task<byte[]> DecryptAsync(byte[] ciphertext, string keyHex, byte[] iv)
    {
        SymmetricDecryptDelegate decrypt = Resolve<SymmetricDecryptDelegate>();
        (DecryptedContent result, _) = await decrypt(
            ciphertext, Convert.FromHexString(keyHex), iv, CryptoTags.Aes128CbcDecryptedContent,
            BaseMemoryPool.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            return result.AsReadOnlySpan().ToArray();
        }
        finally
        {
            result.Dispose();
        }
    }


    private async Task<byte[]> ComputeMacAsync(byte[] message, string keyHex)
    {
        ComputeBlockCipherMacDelegate compute = Resolve<ComputeBlockCipherMacDelegate>();
        (MacValue result, _) = await compute(
            message, Convert.FromHexString(keyHex), MacLength, CryptoTags.Aes128Cmac,
            BaseMemoryPool.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            return result.AsReadOnlySpan().ToArray();
        }
        finally
        {
            result.Dispose();
        }
    }


    private static byte[] Concatenate(byte[] first, byte[] second, byte[] third)
    {
        byte[] result = new byte[first.Length + second.Length + third.Length];
        first.CopyTo(result, 0);
        second.CopyTo(result, first.Length);
        third.CopyTo(result, first.Length + second.Length);

        return result;
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned SymmetricKeyMemory, which the session disposes.")]
    private static SymmetricKeyMemory CreateKey(string hex, Tag tag)
    {
        byte[] bytes = Convert.FromHexString(hex);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new SymmetricKeyMemory(owner, tag);
    }


    private static TDelegate Resolve<TDelegate>() where TDelegate: Delegate =>
        CryptographicKeyFactory.GetFunction<TDelegate>(typeof(TDelegate))
            ?? throw new InvalidOperationException($"No {typeof(TDelegate).Name} has been registered.");
}
