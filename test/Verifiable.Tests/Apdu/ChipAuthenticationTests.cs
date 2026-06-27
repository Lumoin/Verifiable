using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Apdu;
using Verifiable.Apdu.Lds;
using Verifiable.Apdu.Pace;
using Verifiable.Apdu.SecureMessaging;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Drives the EACv1 Chip Authentication protocol (<see cref="ChipAuthentication.EstablishAsync"/>) over a
/// device backed by the card-side <see cref="SecureMessagingCardSession"/>: the terminal mints its
/// ephemeral key, sends MSE:Set KAT under the access-protocol Secure Messaging session — which the card
/// unprotects and acknowledges with a protected <c>9000</c> — and derives the new session keys. The chip's
/// static key is read back from an EF.DG14 minted by <see cref="DataGroup14.Write"/>, so the terminal works
/// only from the wire bytes. The oracle is the chip's own view: it derives the same KSenc / KSmac
/// independently from its private key and the terminal's ephemeral public key, and the re-keyed Secure
/// Messaging round-trips, proving the static–ephemeral ECDH agrees both ways.
/// </summary>
[TestClass]
internal sealed class ChipAuthenticationTests
{
    //brainpoolP256r1 private scalars — valid keys reused from the Doc 9303 Appendix G.1 worked example.
    private const string ChipStaticPrivateKey = "107CF58696EF6155053340FD633392BA81909DF7B9706F226F32086C7AFF974A";
    private const string TerminalEphemeralPrivateKey = "A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595";

    //The access-protocol (PACE) Secure Messaging session keys the MSE:Set KAT command travels under.
    private static readonly byte[] TransportEncryptionKey = Convert.FromHexString("0123456789ABCDEF0123456789ABCDEF");
    private static readonly byte[] TransportMacKey = Convert.FromHexString("FEDCBA9876543210FEDCBA9876543210");


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task EstablishesAes128KeysMatchingTheChipSide()
    {
        await EstablishesKeysMatchingTheChipSideAsync(
            ChipAuthenticationCipher.Aes128, CryptoTags.Aes128Cbc, CryptoTags.Aes128Cmac, keyId: null).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task EstablishesTripleDesKeysMatchingTheChipSideWithKeyIdentifier()
    {
        await EstablishesKeysMatchingTheChipSideAsync(
            ChipAuthenticationCipher.TripleDes, CryptoTags.TripleDesCbc, CryptoTags.RetailMac, keyId: 5).ConfigureAwait(false);
    }


    /// <summary>
    /// Runs Chip Authentication for a cipher and asserts the terminal's derived KSenc / KSmac equal the keys
    /// the chip derives independently — the strong synthetic oracle that the ECDH agrees both ways.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The derived session keys are disposed in the finally blocks; the transport session keys transfer to the sessions disposed via using.")]
    private async Task EstablishesKeysMatchingTheChipSideAsync(ChipAuthenticationCipher cipher, Tag encryptionTag, Tag macTag, int? keyId)
    {
        Tag curve = CryptoTags.BrainpoolP256r1ExchangePublicKey;
        EcMultiplyGeneratorDelegate multiplyGenerator = Resolve<EcMultiplyGeneratorDelegate>();

        ReadOnlyMemory<byte> chipStaticPrivateKey = Convert.FromHexString(ChipStaticPrivateKey);
        ReadOnlyMemory<byte> terminalEphemeralPrivateKey = Convert.FromHexString(TerminalEphemeralPrivateKey);

        //Mint the chip's static Chip Authentication key pair and the EF.DG14 that announces it.
        using EncodedEcPoint chipStaticPublicKey = await multiplyGenerator(
            chipStaticPrivateKey, curve, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using ElementaryFile dataGroup14File = DataGroup14.Write(
            chipStaticPublicKey, cipher, version: 1, keyId, BaseMemoryPool.Shared);

        //Firewall: the terminal reconstructs the chip key, cipher, and key id from the DG14 wire bytes.
        using DataGroup14 dataGroup14 = DataGroup14.Parse(dataGroup14File.AsReadOnlySpan(), BaseMemoryPool.Shared);
        ChipAuthenticationPublicKeyInfo chipKeyInfo = dataGroup14.ChipAuthenticationPublicKeyInfos[0];
        ChipAuthenticationCipher announcedCipher = dataGroup14.ChipAuthenticationInfos[0].Cipher;

        (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) = await RunChipAuthenticationAsync(
            chipKeyInfo.PublicKey, announcedCipher, terminalEphemeralPrivateKey, chipKeyInfo.KeyId).ConfigureAwait(false);
        try
        {
            //Oracle (the chip's view): K = SK_chip · PK_term, derived independently to the same session keys.
            (SymmetricKeyMemory chipEncryptionKey, SymmetricKeyMemory chipMacKey) = await DeriveChipSideKeysAsync(
                chipStaticPrivateKey, terminalEphemeralPrivateKey, curve, encryptionTag, macTag).ConfigureAwait(false);
            try
            {
                Assert.AreEqual(Convert.ToHexString(chipEncryptionKey.AsReadOnlySpan()), Convert.ToHexString(encryptionKey.AsReadOnlySpan()),
                    "KSenc must match the key the chip derives from its private key and the terminal's ephemeral public key.");
                Assert.AreEqual(Convert.ToHexString(chipMacKey.AsReadOnlySpan()), Convert.ToHexString(macKey.AsReadOnlySpan()),
                    "KSmac must match the chip-derived key.");
            }
            finally
            {
                chipEncryptionKey.Dispose();
                chipMacKey.Dispose();
            }
        }
        finally
        {
            encryptionKey.Dispose();
            macKey.Dispose();
        }
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The re-keyed session keys transfer to the new terminal and card sessions, which are disposed via using and dispose the keys.")]
    public async Task ReKeyedSecureMessagingRoundTripsAfterChipAuthentication()
    {
        Tag curve = CryptoTags.BrainpoolP256r1ExchangePublicKey;
        EcMultiplyGeneratorDelegate multiplyGenerator = Resolve<EcMultiplyGeneratorDelegate>();

        ReadOnlyMemory<byte> chipStaticPrivateKey = Convert.FromHexString(ChipStaticPrivateKey);
        ReadOnlyMemory<byte> terminalEphemeralPrivateKey = Convert.FromHexString(TerminalEphemeralPrivateKey);

        using EncodedEcPoint chipStaticPublicKey = await multiplyGenerator(
            chipStaticPrivateKey, curve, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using ElementaryFile dataGroup14File = DataGroup14.Write(
            chipStaticPublicKey, ChipAuthenticationCipher.Aes128, version: 1, keyId: null, BaseMemoryPool.Shared);
        using DataGroup14 dataGroup14 = DataGroup14.Parse(dataGroup14File.AsReadOnlySpan(), BaseMemoryPool.Shared);
        ChipAuthenticationPublicKeyInfo chipKeyInfo = dataGroup14.ChipAuthenticationPublicKeyInfos[0];

        //The terminal establishes Chip Authentication; the chip derives the matching keys independently.
        (SymmetricKeyMemory terminalEncryptionKey, SymmetricKeyMemory terminalMacKey) = await RunChipAuthenticationAsync(
            chipKeyInfo.PublicKey, ChipAuthenticationCipher.Aes128, terminalEphemeralPrivateKey, chipKeyInfo.KeyId).ConfigureAwait(false);
        (SymmetricKeyMemory chipEncryptionKey, SymmetricKeyMemory chipMacKey) = await DeriveChipSideKeysAsync(
            chipStaticPrivateKey, terminalEphemeralPrivateKey, curve, CryptoTags.Aes128Cbc, CryptoTags.Aes128Cmac).ConfigureAwait(false);

        //Both sides build a fresh Secure Messaging session with the send-sequence counter reset to zero.
        byte[] reKeyedSendSequenceCounter = new byte[SecureMessagingProfile.Aes128.BlockSize];
        using var terminal = new SecureMessagingSession(
            terminalEncryptionKey, terminalMacKey, reKeyedSendSequenceCounter, SecureMessagingProfile.Aes128, BaseMemoryPool.Shared);
        using var card = new SecureMessagingCardSession(
            chipEncryptionKey, chipMacKey, reKeyedSendSequenceCounter, SecureMessagingProfile.Aes128, BaseMemoryPool.Shared);

        //If the keys agree, a command protected by the re-keyed terminal session unprotects on the card.
        byte[] commandData = [0x60, 0x0E];
        using ProtectedCommandApdu protectedCommand = await terminal.ProtectCommandAsync(
            0x00, 0xA4, 0x02, 0x0C, commandData, expectedResponseLength: null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using SecureMessagingCommand command = await card.UnprotectCommandAsync(
            protectedCommand.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(Convert.ToHexString(commandData), Convert.ToHexString(command.Data),
            "The re-keyed Secure Messaging command data must round-trip, proving the Chip Authentication keys interoperate.");

        byte[] responseData = [0x90, 0x91, 0x92];
        using ProtectedResponseApdu protectedResponse = await card.ProtectResponseAsync(
            responseData, StatusWord.Success, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using SecureMessagingResponse response = await terminal.UnprotectResponseAsync(
            protectedResponse.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(response.StatusWord.IsSuccess, "The re-keyed response status word must round-trip as 9000.");
        Assert.AreEqual(Convert.ToHexString(responseData), Convert.ToHexString(response.Data), "The re-keyed response data must round-trip.");
    }


    /// <summary>
    /// Drives <see cref="ChipAuthentication.EstablishAsync"/> over a device backed by a card-side Secure
    /// Messaging session, returning the terminal's newly derived KSenc / KSmac.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The transport session keys transfer to the terminal and card sessions, which are disposed via using and dispose the keys; the returned session keys are the caller's to dispose.")]
    private async Task<(SymmetricKeyMemory EncryptionKey, SymmetricKeyMemory MacKey)> RunChipAuthenticationAsync(
        EncodedEcPoint chipPublicKey, ChipAuthenticationCipher cipher, ReadOnlyMemory<byte> terminalEphemeralPrivateKey, int? keyId)
    {
        byte[] initialSendSequenceCounter = new byte[SecureMessagingProfile.Aes128.BlockSize];
        using var terminalSession = new SecureMessagingSession(
            CreateKey(TransportEncryptionKey, CryptoTags.Aes128Cbc), CreateKey(TransportMacKey, CryptoTags.Aes128Cmac),
            initialSendSequenceCounter, SecureMessagingProfile.Aes128, BaseMemoryPool.Shared);
        using var cardSession = new SecureMessagingCardSession(
            CreateKey(TransportEncryptionKey, CryptoTags.Aes128Cbc), CreateKey(TransportMacKey, CryptoTags.Aes128Cmac),
            initialSendSequenceCounter, SecureMessagingProfile.Aes128, BaseMemoryPool.Shared);

        var transceiver = new SecureMessagingCardTransceiver(cardSession);
        using ApduDevice device = ApduDevice.Create(transceiver.TransceiveAsync);

        return await ChipAuthentication.EstablishAsync(
            device, terminalSession, chipPublicKey, cipher, terminalEphemeralPrivateKey, keyId, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Derives the session keys from the chip's perspective: the ECDH secret of its private key with the
    /// terminal's ephemeral public key, run through the same KDF the terminal uses.
    /// </summary>
    private async Task<(SymmetricKeyMemory EncryptionKey, SymmetricKeyMemory MacKey)> DeriveChipSideKeysAsync(
        ReadOnlyMemory<byte> chipStaticPrivateKey, ReadOnlyMemory<byte> terminalEphemeralPrivateKey, Tag curve, Tag encryptionTag, Tag macTag)
    {
        EcMultiplyGeneratorDelegate multiplyGenerator = Resolve<EcMultiplyGeneratorDelegate>();

        using EncodedEcPoint terminalEphemeralPublicKey = await multiplyGenerator(
            terminalEphemeralPrivateKey, curve, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using SharedSecret chipSharedSecret = await PaceGenericMapping.AgreeSharedSecretAsync(
            chipStaticPrivateKey, terminalEphemeralPublicKey.AsReadOnlyMemory(), curve, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        return await PaceKeyDerivation.DeriveSessionKeysAsync(
            chipSharedSecret.AsReadOnlyMemory(), encryptionTag, macTag, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented key buffer transfers to the returned SymmetricKeyMemory, which the session disposes.")]
    private static SymmetricKeyMemory CreateKey(byte[] bytes, Tag tag)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new SymmetricKeyMemory(owner, tag);
    }


    private static TDelegate Resolve<TDelegate>() where TDelegate: Delegate =>
        CryptographicKeyFactory.GetFunction<TDelegate>(typeof(TDelegate))
            ?? throw new InvalidOperationException($"No {typeof(TDelegate).Name} has been registered.");


    /// <summary>
    /// A device transceiver backed by a card-side Secure Messaging session: it unprotects each command,
    /// acknowledges it with <c>9000</c>, and protects the response — a minimal software card that lets a
    /// terminal protocol run over an established session.
    /// </summary>
    private sealed class SecureMessagingCardTransceiver(SecureMessagingCardSession session)
    {
        /// <summary>
        /// Unprotects the command, then returns a protected status-only <c>9000</c> response.
        /// </summary>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "ApduResponse takes ownership of the rented buffer; the caller disposes the returned result.")]
        public async ValueTask<ApduResult<ApduResponse>> TransceiveAsync(
            ReadOnlyMemory<byte> commandApdu, MemoryPool<byte> pool, CancellationToken cancellationToken)
        {
            using SecureMessagingCommand command = await session.UnprotectCommandAsync(
                commandApdu, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            using ProtectedResponseApdu protectedResponse = await session.ProtectResponseAsync(
                ReadOnlyMemory<byte>.Empty, StatusWord.Success, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            ReadOnlySpan<byte> responseBytes = protectedResponse.AsReadOnlySpan();
            IMemoryOwner<byte> owner = pool.Rent(responseBytes.Length);
            responseBytes.CopyTo(owner.Memory.Span);

            var response = new ApduResponse(owner, responseBytes.Length);

            return ApduResult<ApduResponse>.Success(response, response.StatusWord);
        }
    }
}
