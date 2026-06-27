using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Apdu;
using Verifiable.Apdu.SecureMessaging;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Drives the ICAO Doc 9303 Part 11 (8th ed., 2021) Appendix D.4 Secure Messaging worked example
/// end to end through a single <see cref="SecureMessagingSession"/>: SELECT EF.COM, a four-byte
/// READ BINARY, and an 18-byte READ BINARY, protecting each command and unprotecting each response.
/// </summary>
/// <remarks>
/// <para>
/// Running the whole exchange through one session is the strongest available check: the
/// send-sequence counter must advance correctly across three command/response round-trips, every
/// protected APDU must equal the byte string the specification publishes, and every response MAC
/// must verify before its data decrypts. The session keys and initial SSC are the values
/// Appendix D.3 establishes.
/// </para>
/// </remarks>
[TestClass]
internal sealed class SecureMessagingSessionTests
{
    private const string Ksenc = "979EC13B1CBFE9DCD01AB0FED307EAE5";
    private const string Ksmac = "F1CB1F1FB5ADF208806B89DC579DC1F8";
    private const string InitialSsc = "887022120C06C226";


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task ProtectsAndUnprotectsTheAppendixD4ExchangeThroughOneSession()
    {
        using SecureMessagingSession session = CreateSession();

        //Command 1: SELECT EF.COM (00 A4 02 0C 02 011E) - Case 3, no Le.
        await AssertProtectedCommand(session, 0x00, 0xA4, 0x02, 0x0C, "011E", null,
            "0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800").ConfigureAwait(false);
        await AssertUnprotectedResponse(session, "990290008E08FA855A5D4C50A8ED9000", "").ConfigureAwait(false);

        //Command 2: READ BINARY first four bytes (00 B0 00 00 04) - Case 2, Le = 4, no data.
        await AssertProtectedCommand(session, 0x00, 0xB0, 0x00, 0x00, "", 4,
            "0CB000000D9701048E08ED6705417E96BA5500").ConfigureAwait(false);
        await AssertUnprotectedResponse(session, "8709019FF0EC34F9922651990290008E08AD55CC17140B2DED9000", "60145F01").ConfigureAwait(false);

        //Command 3: READ BINARY remaining 18 bytes from offset 4 (00 B0 00 04 12) - Case 2, Le = 18.
        await AssertProtectedCommand(session, 0x00, 0xB0, 0x00, 0x04, "", 18,
            "0CB000040D9701128E082EA28A70F3C7B53500").ConfigureAwait(false);
        await AssertUnprotectedResponse(session,
            "871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A990290008E08C8B2787EAEA07D749000",
            "04303130365F36063034303030305C026175").ConfigureAwait(false);
    }


    [TestMethod]
    public async Task UnprotectRejectsAResponseWithATamperedMac()
    {
        using SecureMessagingSession session = CreateSession();

        //Advance the session exactly as the genuine exchange would before the first response.
        using(ProtectedCommandApdu _ = await session.ProtectCommandAsync(
            0x00, 0xA4, 0x02, 0x0C, Convert.FromHexString("011E"), null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false))
        {
        }

        //Flip the last byte of DO'8E' in the genuine SELECT response.
        byte[] tampered = Convert.FromHexString("990290008E08FA855A5D4C50A8ED9000");
        tampered[^3] ^= 0x01;

        bool threw = false;
        try
        {
            using SecureMessagingResponse _ = await session.UnprotectResponseAsync(
                tampered, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(InvalidOperationException)
        {
            threw = true;
        }

        Assert.IsTrue(threw, "Unprotect must reject a response whose MAC has been tampered with.");
    }


    private async Task AssertProtectedCommand(
        SecureMessagingSession session,
        byte cla, byte ins, byte p1, byte p2,
        string commandDataHex, int? expectedResponseLength,
        string expectedApduHex)
    {
        byte[] commandData = commandDataHex.Length == 0 ? [] : Convert.FromHexString(commandDataHex);
        using ProtectedCommandApdu protectedApdu = await session.ProtectCommandAsync(
            cla, ins, p1, p2, commandData, expectedResponseLength,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedApduHex, Convert.ToHexString(protectedApdu.AsReadOnlySpan()),
            "The protected command APDU must match the Doc 9303 Appendix D.4 worked example.");
    }


    private async Task AssertUnprotectedResponse(
        SecureMessagingSession session,
        string responseApduHex,
        string expectedDataHex)
    {
        using SecureMessagingResponse response = await session.UnprotectResponseAsync(
            Convert.FromHexString(responseApduHex), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedDataHex, Convert.ToHexString(response.Data),
            "The decrypted response data must match the Doc 9303 Appendix D.4 worked example.");
        Assert.AreEqual((ushort)0x9000, response.StatusWord.Value,
            "The DO'99' status word must decode to 9000.");
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of both session keys transfers to the returned SecureMessagingSession, which the caller disposes.")]
    private static SecureMessagingSession CreateSession()
    {
        SymmetricKeyMemory encryptionKey = CreateKey(Ksenc, CryptoTags.TripleDesCbc);
        SymmetricKeyMemory macKey = CreateKey(Ksmac, CryptoTags.RetailMac);

        return new SecureMessagingSession(encryptionKey, macKey, Convert.FromHexString(InitialSsc), SecureMessagingProfile.TripleDes, BaseMemoryPool.Shared);
    }


    private static SymmetricKeyMemory CreateKey(string hex, Tag tag)
    {
        byte[] bytes = Convert.FromHexString(hex);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new SymmetricKeyMemory(owner, tag);
    }
}
