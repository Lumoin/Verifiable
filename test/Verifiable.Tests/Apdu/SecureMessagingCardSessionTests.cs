using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Apdu;
using Verifiable.Apdu.SecureMessaging;
using Verifiable.Cryptography;
using Verifiable.Foundation;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates the card side of Secure Messaging by driving a full round trip against the terminal-side
/// <see cref="SecureMessagingSession"/>: a command protected by the terminal unprotects on the card with
/// the header and data intact, and a response protected by the card unprotects on the terminal. Both the
/// 3DES (BAC) and AES (PACE) profiles are exercised, plus an extended-length command and response that
/// exceed the 255-byte short-length ceiling, proving the two sides keep the send-sequence counter in
/// lockstep across the short and extended Lc/Le framings. This card-side engine is what a software eMRTD
/// needs to serve a terminal over a session.
/// </summary>
[TestClass]
internal sealed class SecureMessagingCardSessionTests
{
    private const string EncryptionKeyHex = "0123456789ABCDEF0123456789ABCDEF";
    private const string MacKeyHex = "FEDCBA9876543210FEDCBA9876543210";


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task TripleDesCommandAndResponseRoundTripBetweenTerminalAndCard()
    {
        await RoundTripAsync(SecureMessagingProfile.TripleDes, CryptoTags.TripleDesCbc, CryptoTags.RetailMac, blockSize: 8, commandDataLength: 6, responseDataLength: 5).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task AesCommandAndResponseRoundTripBetweenTerminalAndCard()
    {
        await RoundTripAsync(SecureMessagingProfile.Aes128, CryptoTags.Aes128Cbc, CryptoTags.Aes128Cmac, blockSize: 16, commandDataLength: 6, responseDataLength: 5).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task ExtendedLengthCommandAndResponseRoundTripBetweenTerminalAndCard()
    {
        //A command and response whose protected data exceeds the 255-byte short-length ceiling — the case a
        //large RSA card-verifiable certificate presented in Terminal Authentication produces — must round-trip
        //through the extended-length Lc/Le framing with the data recovered byte-for-byte.
        await RoundTripAsync(SecureMessagingProfile.Aes128, CryptoTags.Aes128Cbc, CryptoTags.Aes128Cmac, blockSize: 16, commandDataLength: 400, responseDataLength: 512).ConfigureAwait(false);
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the session keys transfers to the terminal and card sessions, which are disposed via using and dispose the keys; the working buffers are disposed via using.")]
    private async Task RoundTripAsync(SecureMessagingProfile profile, Tag encryptionTag, Tag macTag, int blockSize, int commandDataLength, int responseDataLength)
    {
        using IMemoryOwner<byte> sendSequenceCounter = BaseMemoryPool.Shared.Rent(blockSize);
        using IMemoryOwner<byte> commandOwner = BaseMemoryPool.Shared.Rent(commandDataLength);
        using IMemoryOwner<byte> responseOwner = BaseMemoryPool.Shared.Rent(responseDataLength);
        sendSequenceCounter.Memory.Span[..blockSize].Clear();
        Fill(commandOwner.Memory.Span[..commandDataLength], 0x40);
        Fill(responseOwner.Memory.Span[..responseDataLength], 0x80);
        ReadOnlyMemory<byte> commandData = commandOwner.Memory[..commandDataLength];
        ReadOnlyMemory<byte> responseData = responseOwner.Memory[..responseDataLength];

        using var terminal = new SecureMessagingSession(
            CreateKey(EncryptionKeyHex, encryptionTag), CreateKey(MacKeyHex, macTag), sendSequenceCounter.Memory.Span[..blockSize], profile, BaseMemoryPool.Shared);
        using var card = new SecureMessagingCardSession(
            CreateKey(EncryptionKeyHex, encryptionTag), CreateKey(MacKeyHex, macTag), sendSequenceCounter.Memory.Span[..blockSize], profile, BaseMemoryPool.Shared);

        //Terminal protects a command; the card unprotects it and recovers the header and data.
        using ProtectedCommandApdu protectedCommand = await terminal.ProtectCommandAsync(
            0x00, 0x22, 0x41, 0xA6, commandData, expectedResponseLength: null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        using SecureMessagingCommand command = await card.UnprotectCommandAsync(
            protectedCommand.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual((byte)0x00, command.Cla, "The Secure Messaging class bits are cleared.");
        Assert.AreEqual((byte)0x22, command.Instruction, "INS must round-trip.");
        Assert.AreEqual((byte)0x41, command.Parameter1, "P1 must round-trip.");
        Assert.AreEqual((byte)0xA6, command.Parameter2, "P2 must round-trip.");
        Assert.AreEqual(Convert.ToHexString(commandData.Span), Convert.ToHexString(command.Data), "The command data must round-trip.");

        //Card protects a response; the terminal unprotects it and recovers the data and status word.
        using ProtectedResponseApdu protectedResponse = await card.ProtectResponseAsync(
            responseData, StatusWord.Success, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        using SecureMessagingResponse response = await terminal.UnprotectResponseAsync(
            protectedResponse.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(response.StatusWord.IsSuccess, "The response status word must round-trip as 9000.");
        Assert.AreEqual(Convert.ToHexString(responseData.Span), Convert.ToHexString(response.Data), "The response data must round-trip.");
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the session keys transfers to the terminal and card sessions, which are disposed via using and dispose the keys; the working buffers are disposed via using.")]
    public async Task CardRejectsATamperedCommand()
    {
        using IMemoryOwner<byte> sendSequenceCounter = BaseMemoryPool.Shared.Rent(8);
        using IMemoryOwner<byte> commandOwner = BaseMemoryPool.Shared.Rent(4);
        sendSequenceCounter.Memory.Span[..8].Clear();
        Fill(commandOwner.Memory.Span[..4], 0x10);
        ReadOnlyMemory<byte> commandData = commandOwner.Memory[..4];

        using var terminal = new SecureMessagingSession(
            CreateKey(EncryptionKeyHex, CryptoTags.TripleDesCbc), CreateKey(MacKeyHex, CryptoTags.RetailMac), sendSequenceCounter.Memory.Span[..8], SecureMessagingProfile.TripleDes, BaseMemoryPool.Shared);
        using var card = new SecureMessagingCardSession(
            CreateKey(EncryptionKeyHex, CryptoTags.TripleDesCbc), CreateKey(MacKeyHex, CryptoTags.RetailMac), sendSequenceCounter.Memory.Span[..8], SecureMessagingProfile.TripleDes, BaseMemoryPool.Shared);

        using ProtectedCommandApdu protectedCommand = await terminal.ProtectCommandAsync(
            0x00, 0x22, 0x41, 0xA6, commandData, expectedResponseLength: null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //Copy the protected command into a pooled buffer and flip a byte of the encrypted data.
        int length = protectedCommand.AsReadOnlySpan().Length;
        using IMemoryOwner<byte> tampered = BaseMemoryPool.Shared.Rent(length);
        protectedCommand.AsReadOnlySpan().CopyTo(tampered.Memory.Span);
        tampered.Memory.Span[7] ^= 0x01;

        await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            async () =>
            {
                using SecureMessagingCommand _ = await card.UnprotectCommandAsync(
                    tampered.Memory[..length], BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            },
            "The card must reject a command whose MAC does not verify.").ConfigureAwait(false);
    }


    /// <summary>Fills a span with a deterministic pattern, each octet the seed plus its index.</summary>
    private static void Fill(Span<byte> destination, byte seed)
    {
        for(int i = 0; i < destination.Length; i++)
        {
            destination[i] = (byte)(seed + i);
        }
    }


    /// <summary>Mints a session key carrier from a hex string, consuming the decoded bytes inline into the tracked carrier.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented key buffer transfers to the returned SymmetricKeyMemory, which the session disposes.")]
    private static SymmetricKeyMemory CreateKey(string hex, Tag tag)
    {
        byte[] bytes = Convert.FromHexString(hex);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new SymmetricKeyMemory(owner, tag);
    }
}
