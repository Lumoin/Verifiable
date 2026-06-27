using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Apdu;
using Verifiable.Apdu.Automata;
using Verifiable.Apdu.Bac;
using Verifiable.Apdu.Lds;
using Verifiable.Apdu.SecureMessaging;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Drives the real EACv1 Chip Authentication terminal (<see cref="ChipAuthentication.EstablishAsync"/>)
/// against the stateful <see cref="CardSimulator"/>, over an established Basic Access Control session. The
/// card holds its static Chip Authentication private key as personalisation and, on MSE:Set KAT, agrees the
/// static–ephemeral ECDH secret against its own DG14 key, re-keys Secure Messaging, and acknowledges with a
/// protected <c>9000</c> under the prior session. Unlike a passive transceiver, the card derives the new
/// keys itself — so a subsequent file read over the terminal's re-keyed session is the proof both sides
/// independently agreed the same Chip Authentication keys. Both sides are production code that agree only on
/// the wire bytes.
/// </summary>
[TestClass]
internal sealed class CardSimulatorChipAuthenticationTests
{
    private const string Td2MachineReadableZone =
        "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<" +
        "L898902C<3UTO6908061F9406236<<<<<<<8";

    private const string DocumentNumber = "L898902C<";
    private const string DateOfBirth = "690806";
    private const string DateOfExpiry = "940623";

    //brainpoolP256r1 private scalars — valid keys reused from the Doc 9303 Appendix G.1 worked example.
    private const string ChipStaticPrivateKey = "107CF58696EF6155053340FD633392BA81909DF7B9706F226F32086C7AFF974A";
    private const string TerminalEphemeralPrivateKey = "A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595";


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task EstablishesAes128ChipAuthenticationAndReadsOverTheReKeyedSession()
    {
        await RunChipAuthenticationReadAsync(ChipAuthenticationCipher.Aes128, keyId: null).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task EstablishesTripleDesChipAuthenticationWithAKeyIdentifier()
    {
        await RunChipAuthenticationReadAsync(ChipAuthenticationCipher.TripleDes, keyId: 5).ConfigureAwait(false);
    }


    /// <summary>
    /// Mints a chip with the given Chip Authentication cipher and key identifier, runs Basic Access Control
    /// then Chip Authentication against it through the real terminals, and reads EF.COM and EF.DG1 back over
    /// the re-keyed Secure Messaging session — proving the card and terminal agreed the same keys.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The re-keyed session takes ownership of the Chip Authentication keys and is disposed via using; the Basic Access Control session and its access keys are disposed in the finally.")]
    private async Task RunChipAuthenticationReadAsync(ChipAuthenticationCipher cipher, int? keyId)
    {
        Tag curve = CryptoTags.BrainpoolP256r1ExchangePublicKey;
        EcMultiplyGeneratorDelegate multiplyGenerator = Resolve<EcMultiplyGeneratorDelegate>();
        ReadOnlyMemory<byte> chipStaticPrivateKey = Convert.FromHexString(ChipStaticPrivateKey);
        ReadOnlyMemory<byte> terminalEphemeralPrivateKey = Convert.FromHexString(TerminalEphemeralPrivateKey);

        using EncodedEcPoint chipStaticPublicKey = await multiplyGenerator(
            chipStaticPrivateKey, curve, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using ElementaryFile dataGroup14File = DataGroup14.Write(chipStaticPublicKey, cipher, version: 1, keyId, BaseMemoryPool.Shared);
        using ElementaryFile efCom = EfCom.Write("0106", "040000", [0x61, 0x6E], BaseMemoryPool.Shared);
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);
        using ChipAuthenticationKey chipKey = CreateChipKey(ChipStaticPrivateKey, keyId);

        using var card = new CardSimulator(
            "passport-chip-auth", [efCom, dataGroup1, dataGroup14File], chipAuthenticationKeys: [chipKey]);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        (SecureMessagingSession bacSession, SymmetricKeyMemory accessEncryptionKey, SymmetricKeyMemory accessMacKey) =
            await EstablishBacAsync(device).ConfigureAwait(false);
        using(accessEncryptionKey)
        using(accessMacKey)
        using(bacSession)
        {
            //Firewall: the terminal reconstructs the chip key, cipher, and key id from the DG14 wire bytes.
            using DataGroup14 dataGroup14 = DataGroup14.Parse(dataGroup14File.AsReadOnlySpan(), BaseMemoryPool.Shared);
            ChipAuthenticationPublicKeyInfo chipKeyInfo = dataGroup14.ChipAuthenticationPublicKeyInfos[0];
            ChipAuthenticationCipher announcedCipher = dataGroup14.ChipAuthenticationInfos[0].Cipher;

            (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) = await ChipAuthentication.EstablishAsync(
                device, bacSession, chipKeyInfo.PublicKey, announcedCipher, terminalEphemeralPrivateKey, chipKeyInfo.KeyId,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            //Both sides re-key Secure Messaging with the send-sequence counter reset to zero.
            SecureMessagingProfile profile = ProfileFor(cipher);
            using SecureMessagingSession reKeyed = new(encryptionKey, macKey, new byte[profile.BlockSize], profile, BaseMemoryPool.Shared);
            var channel = new SecureMessagingChannel(device, reKeyed);

            using ElementaryFile readEfCom = await channel.ReadElementaryFileAsync(efCom.FileIdentifier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(Convert.ToHexString(efCom.Content), Convert.ToHexString(readEfCom.Content),
                "EF.COM must read back byte-for-byte over the Chip-Authentication re-keyed session, proving both sides agreed the keys.");

            using ElementaryFile readDataGroup1 = await channel.ReadElementaryFileAsync(dataGroup1.FileIdentifier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(Convert.ToHexString(dataGroup1.Content), Convert.ToHexString(readDataGroup1.Content),
                "EF.DG1 must read back byte-for-byte over the Chip-Authentication re-keyed session.");
        }
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The Basic Access Control session and its access keys are disposed in the using blocks.")]
    public async Task RefusesChipAuthenticationWithoutAMatchingKeyAndKeepsTheSession()
    {
        Tag curve = CryptoTags.BrainpoolP256r1ExchangePublicKey;
        EcMultiplyGeneratorDelegate multiplyGenerator = Resolve<EcMultiplyGeneratorDelegate>();
        ReadOnlyMemory<byte> chipStaticPrivateKey = Convert.FromHexString(ChipStaticPrivateKey);
        ReadOnlyMemory<byte> terminalEphemeralPrivateKey = Convert.FromHexString(TerminalEphemeralPrivateKey);

        using EncodedEcPoint chipStaticPublicKey = await multiplyGenerator(
            chipStaticPrivateKey, curve, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using ElementaryFile dataGroup14File = DataGroup14.Write(chipStaticPublicKey, ChipAuthenticationCipher.Aes128, version: 1, keyId: null, BaseMemoryPool.Shared);
        using ElementaryFile efCom = EfCom.Write("0106", "040000", [0x61, 0x6E], BaseMemoryPool.Shared);
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);

        //The card announces a Chip Authentication key in DG14 but holds no matching private key.
        using var card = new CardSimulator("passport-chip-auth-nokey", [efCom, dataGroup1, dataGroup14File]);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        (SecureMessagingSession bacSession, SymmetricKeyMemory accessEncryptionKey, SymmetricKeyMemory accessMacKey) =
            await EstablishBacAsync(device).ConfigureAwait(false);
        using(accessEncryptionKey)
        using(accessMacKey)
        using(bacSession)
        {
            using DataGroup14 dataGroup14 = DataGroup14.Parse(dataGroup14File.AsReadOnlySpan(), BaseMemoryPool.Shared);
            ChipAuthenticationPublicKeyInfo chipKeyInfo = dataGroup14.ChipAuthenticationPublicKeyInfos[0];

            //The chip rejects MSE:Set KAT (no private key), so the terminal's establishment throws before it
            //returns any keys to dispose.
            await Assert.ThrowsExactlyAsync<InvalidOperationException>(
                async () => await ChipAuthentication.EstablishAsync(
                    device, bacSession, chipKeyInfo.PublicKey, ChipAuthenticationCipher.Aes128, terminalEphemeralPrivateKey, chipKeyInfo.KeyId,
                    BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

            //A failed Chip Authentication leaves the Basic Access Control session intact and usable.
            var channel = new SecureMessagingChannel(device, bacSession);
            using ElementaryFile readEfCom = await channel.ReadElementaryFileAsync(efCom.FileIdentifier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(Convert.ToHexString(efCom.Content), Convert.ToHexString(readEfCom.Content),
                "The Basic Access Control session must still read after a refused Chip Authentication.");
        }
    }


    /// <summary>
    /// Runs the real terminal Basic Access Control against the card and returns the established session plus
    /// the borrowed access keys (the caller disposes all three).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the session and the access keys transfers to the caller, which disposes all three.")]
    private async Task<(SecureMessagingSession Session, SymmetricKeyMemory EncryptionKey, SymmetricKeyMemory MacKey)> EstablishBacAsync(ApduDevice device)
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


    /// <summary>
    /// The Secure Messaging profile a Chip Authentication cipher establishes (only the SHA-1 KDF profiles).
    /// </summary>
    private static SecureMessagingProfile ProfileFor(ChipAuthenticationCipher cipher) =>
        cipher == ChipAuthenticationCipher.Aes128 ? SecureMessagingProfile.Aes128 : SecureMessagingProfile.TripleDes;


    /// <summary>
    /// Mints a Chip Authentication private-key carrier from a hex scalar.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned ChipAuthenticationKey, which the caller disposes.")]
    private static ChipAuthenticationKey CreateChipKey(string privateKeyHex, int? keyId)
    {
        byte[] bytes = Convert.FromHexString(privateKeyHex);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new ChipAuthenticationKey(owner, keyId);
    }


    private static TDelegate Resolve<TDelegate>() where TDelegate: Delegate =>
        CryptographicKeyFactory.GetFunction<TDelegate>(typeof(TDelegate))
            ?? throw new InvalidOperationException($"No {typeof(TDelegate).Name} has been registered.");
}
