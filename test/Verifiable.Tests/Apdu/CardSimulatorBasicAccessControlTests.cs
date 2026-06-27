using System;
using System.Threading.Tasks;
using Verifiable.Apdu;
using Verifiable.Apdu.Automata;
using Verifiable.Apdu.Bac;
using Verifiable.Apdu.Lds;
using Verifiable.Apdu.SecureMessaging;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Drives the real ICAO Doc 9303 Part 11 Basic Access Control terminal (<see cref="BasicAccessControl"/>)
/// against the stateful <see cref="CardSimulator"/>: the card answers GET CHALLENGE with the chip nonce it
/// generated, then on EXTERNAL AUTHENTICATE derives the access keys from its own EF.DG1 MRZ, verifies the
/// terminal's token, and returns its own — establishing a matching Secure Messaging session. Both sides are
/// production code that agree only on the wire bytes, so the terminal's success is proof the card performed
/// the inverse handshake correctly.
/// </summary>
[TestClass]
internal sealed class CardSimulatorBasicAccessControlTests
{
    private const string Td2MachineReadableZone =
        "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<" +
        "L898902C<3UTO6908061F9406236<<<<<<<8";

    private const string DocumentNumber = "L898902C<";
    private const string DateOfBirth = "690806";
    private const string DateOfExpiry = "940623";


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task EstablishesBasicAccessControlAgainstTheRealTerminal()
    {
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);
        using var card = new CardSimulator("passport-bac", [dataGroup1], FillAscending);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        //The terminal derives the same access keys from the MRZ it read optically off the data page.
        string mrzInformation = BasicAccessControl.BuildMrzInformation(DocumentNumber, DateOfBirth, DateOfExpiry);
        (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) = await BasicAccessControl.DeriveAccessKeysAsync(
            mrzInformation, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] terminalNonce = Convert.FromHexString("1122334455667788");
        byte[] terminalKeyingMaterial = Convert.FromHexString("112233445566778899AABBCCDDEEFF00");
        try
        {
            //If the card's side of BAC is correct, the terminal's mutual authentication completes and it
            //returns an established session (it verified the card's MAC and the echoed terminal nonce).
            using SecureMessagingSession session = await BasicAccessControl.EstablishSessionAsync(
                device, encryptionKey, macKey, terminalNonce, terminalKeyingMaterial, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(CardLifecyclePhase.SecureMessaging, card.Phase,
                "The card records that Basic Access Control established Secure Messaging.");
        }
        finally
        {
            encryptionKey.Dispose();
            macKey.Dispose();
        }
    }


    [TestMethod]
    public async Task ReadsFilesOverSecureMessagingAfterBasicAccessControl()
    {
        using ElementaryFile efCom = EfCom.Write("0106", "040000", [0x61, 0x75], BaseMemoryPool.Shared);
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);
        using var card = new CardSimulator("passport-sm-read", [efCom, dataGroup1], FillAscending);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        (SecureMessagingSession session, SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) =
            await EstablishAsync(device).ConfigureAwait(false);
        using(encryptionKey)
        using(macKey)
        using(session)
        {
            //The same terminal channel that reads a real chip now reads the simulator over Secure Messaging.
            var channel = new SecureMessagingChannel(device, session);

            using ElementaryFile readEfCom = await channel.ReadElementaryFileAsync(efCom.FileIdentifier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(Convert.ToHexString(efCom.Content), Convert.ToHexString(readEfCom.Content),
                "EF.COM must read back byte-for-byte over Secure Messaging.");

            using ElementaryFile readDataGroup1 = await channel.ReadElementaryFileAsync(dataGroup1.FileIdentifier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(Convert.ToHexString(dataGroup1.Content), Convert.ToHexString(readDataGroup1.Content),
                "EF.DG1 must read back byte-for-byte over Secure Messaging.");
        }
    }


    [TestMethod]
    public async Task RejectsPlaintextCommandsAfterSecureMessagingIsEstablished()
    {
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);
        using var card = new CardSimulator("passport-sm-gate", [dataGroup1], FillAscending);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        (SecureMessagingSession session, SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) =
            await EstablishAsync(device).ConfigureAwait(false);
        using(encryptionKey)
        using(macKey)
        using(session)
        {
            //A plaintext READ BINARY once Secure Messaging is established is refused (6982).
            using CommandApdu plaintextRead = CommandApdu.BuildCase2(
                0x00, InstructionCode.ReadBinary.Code, 0x00, 0x00, 4, useExtended: false, BaseMemoryPool.Shared);
            ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
                device, plaintextRead.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            using ApduResponse response = result.Value;
            Assert.AreEqual(0x6982, response.StatusWord.Value, "A plaintext command after BAC is refused with 6982.");
        }
    }


    /// <summary>
    /// Runs the real terminal Basic Access Control against the card and returns the established session and
    /// the borrowed access keys (the caller disposes all three).
    /// </summary>
    private async Task<(SecureMessagingSession Session, SymmetricKeyMemory EncryptionKey, SymmetricKeyMemory MacKey)> EstablishAsync(ApduDevice device)
    {
        string mrzInformation = BasicAccessControl.BuildMrzInformation(DocumentNumber, DateOfBirth, DateOfExpiry);
        (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) = await BasicAccessControl.DeriveAccessKeysAsync(
            mrzInformation, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] terminalNonce = Convert.FromHexString("1122334455667788");
        byte[] terminalKeyingMaterial = Convert.FromHexString("112233445566778899AABBCCDDEEFF00");

        SecureMessagingSession session = await BasicAccessControl.EstablishSessionAsync(
            device, encryptionKey, macKey, terminalNonce, terminalKeyingMaterial, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        return (session, encryptionKey, macKey);
    }


    [TestMethod]
    public async Task RejectsExternalAuthenticateWithoutAChallenge()
    {
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);
        using var card = new CardSimulator("passport-bac-nochallenge", [dataGroup1], FillAscending);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        //EXTERNAL AUTHENTICATE before any GET CHALLENGE: the card has issued no nonce.
        byte[] token = new byte[40];
        using CommandApdu command = CommandApdu.BuildCase4(
            0x00, InstructionCode.ExternalAuthenticate.Code, 0x00, 0x00, token, 40, BaseMemoryPool.Shared);

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, command.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(result.IsTransportError, "The card transport must not error.");

        using ApduResponse response = result.Value;
        Assert.AreEqual(0x6985, response.StatusWord.Value, "EXTERNAL AUTHENTICATE without a challenge is refused with 6985.");
        Assert.AreEqual(CardLifecyclePhase.Operational, card.Phase, "A refused EXTERNAL AUTHENTICATE leaves the card operational.");
    }


    /// <summary>A deterministic RNG backend filling the destination with ascending octets from <c>0xA0</c>.</summary>
    private static void FillAscending(Span<byte> destination)
    {
        for(int i = 0; i < destination.Length; i++)
        {
            destination[i] = (byte)(0xA0 + i);
        }
    }
}
