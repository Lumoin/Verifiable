using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Verifiable.Apdu;
using Verifiable.Apdu.Automata;
using Verifiable.Apdu.Bac;
using Verifiable.Apdu.Lds;
using Verifiable.Apdu.Pace;
using Verifiable.Apdu.SecureMessaging;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Exercises the card side of ICAO Doc 9303 Part 11 PACE with Generic Mapping against the
/// <see cref="CardSimulator"/>. The focused first test covers MSE:Set AT and the encrypted-nonce round (the
/// card derives the PACE password key from its own EF.DG1 MRZ, draws the nonce, and returns it encrypted),
/// recovering the nonce from the wire by deriving the same key independently. The end-to-end tests drive the
/// real <see cref="PaceProtocol"/> terminal through all four GENERAL AUTHENTICATE rounds against the card: a
/// successful run proves the card performed the inverse mapping, key agreement, and mutual authentication
/// correctly (the terminal verified the chip's token), and the resulting AES session reads files back. Both
/// sides are production code that agree only on the wire bytes.
/// </summary>
[TestClass]
internal sealed class CardSimulatorPaceTests
{
    private const string Td2MachineReadableZone =
        "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<" +
        "L898902C<3UTO6908061F9406236<<<<<<<8";

    private const string DocumentNumber = "L898902C<";
    private const string DateOfBirth = "690806";
    private const string DateOfExpiry = "940623";

    //The PACE-ECDH-GM-AES-CBC-CMAC-128 OID and the terminal's ephemeral private keys from Doc 9303 Appendix G.1.
    private const string PaceOid = "04007F00070202040202";
    private const string MappingPrivateIfd = "7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99";
    private const string KeyAgreementPrivateIfd = "A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595";

    //The PACE-ECDH-IM-AES-CBC-CMAC-128 OID (protocol byte 0x04) and the terminal's additional nonce t from Doc 9303 Appendix H.1.
    private const string IntegratedMappingPaceOid = "04007F00070202040402";
    private const string AdditionalNonceT = "5DD4CBFC96F5453B130D890A1CDBAE32";

    //The PACE-ECDH-CAM-AES-CBC-CMAC-128 OID (protocol byte 0x06) and two static Chip Authentication scalars on the PACE curve.
    private const string ChipAuthenticationMappingPaceOid = "04007F00070202040602";
    private const string StaticChipPrivateKey = "86C88A4579CE48135878E6348A734B5D47CE5BC1E54C0E8978687B49FDE2E2C2";
    private const string WrongStaticChipPrivateKey = "5D8BB87BD74D985A4B7D4325B9F7B976FE835122773400798914AA22738135CC";


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task EncryptsThePaceNonceUnderTheMrzDerivedKey()
    {
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);
        using var card = new CardSimulator("passport-pace", [dataGroup1], FillAscending);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        //MSE:Set AT selecting the PACE-ECDH-GM-AES128 mechanism (DO'80' OID) for the MRZ password (DO'83').
        byte[] setAtData = Convert.FromHexString("800A04007F00070202040202830101");
        using CommandApdu setAt = CommandApdu.BuildCase3(
            0x00, InstructionCode.ManageSecurityEnvironment.Code, 0xC1, 0xA4, setAtData, BaseMemoryPool.Shared);
        (StatusWord setAtStatus, _) = await TransmitAsync(device, setAt).ConfigureAwait(false);
        Assert.IsTrue(setAtStatus.IsSuccess, "MSE:Set AT must succeed.");
        Assert.AreEqual(CardLifecyclePhase.Pace, card.Phase, "The card enters the PACE phase.");

        //GENERAL AUTHENTICATE round 1: an empty dynamic authentication data object requests the encrypted nonce.
        using CommandApdu round1 = CommandApdu.BuildCase4(0x10, 0x86, 0x00, 0x00, [0x7C, 0x00], 0, BaseMemoryPool.Shared);
        (StatusWord round1Status, byte[] round1Data) = await TransmitAsync(device, round1).ConfigureAwait(false);
        Assert.IsTrue(round1Status.IsSuccess, "GENERAL AUTHENTICATE round 1 must succeed.");

        //The response is 7C 12 80 10 <z>; recover the 16-byte encrypted nonce z.
        Assert.AreEqual(0x7C, round1Data[0], "The response is a dynamic authentication data object.");
        Assert.AreEqual(0x80, round1Data[2], "It carries the encrypted nonce (DO'80').");
        byte[] encryptedNonce = round1Data[4..20];

        //Independently derive Kπ from the MRZ (K = SHA-1(MRZ information), Kπ = KDF(K, 3)) and decrypt z.
        string mrzInformation = BasicAccessControl.BuildMrzInformation(DocumentNumber, DateOfBirth, DateOfExpiry);
        using DigestValue passwordSeed = await ComputeSha1Async(mrzInformation).ConfigureAwait(false);
        using SymmetricKeyMemory nonceKey = await PaceKeyDerivation.DerivePasswordKeyAsync(
            passwordSeed.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using DecryptedContent nonce = await PaceKeyDerivation.DecryptNonceAsync(
            nonceKey, encryptedNonce, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual("A0A1A2A3A4A5A6A7A8A9AAABACADAEAF", Convert.ToHexString(nonce.AsReadOnlySpan()),
            "The decrypted PACE nonce must equal the octets the card's RNG produced.");
    }


    [TestMethod]
    public async Task EstablishesPaceSessionAgainstTheRealTerminal()
    {
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);
        using var card = new CardSimulator("passport-pace-establish", [dataGroup1], paceCurve: CryptoTags.BrainpoolP256r1ExchangePublicKey);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        //EstablishAsync runs all four GENERAL AUTHENTICATE rounds and verifies the chip's token T_IC; reaching
        //the session keys without throwing proves the card's inverse mapping, agreement, and token are correct.
        (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) = await EstablishPaceAsync(
            device, Convert.FromHexString(PaceOid), Convert.FromHexString(MappingPrivateIfd)).ConfigureAwait(false);
        using(encryptionKey)
        using(macKey)
        {
            Assert.AreEqual(CardLifecyclePhase.SecureMessaging, card.Phase,
                "PACE must leave the card in the Secure Messaging phase.");
            Assert.AreEqual(16, encryptionKey.AsReadOnlySpan().Length, "KSenc is an AES-128 key.");
            Assert.AreEqual(16, macKey.AsReadOnlySpan().Length, "KSmac is an AES-128 key.");
        }
    }


    [TestMethod]
    public async Task EstablishesPaceSessionWithIntegratedMappingAgainstTheRealTerminal()
    {
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);
        using var card = new CardSimulator("passport-pace-im", [dataGroup1], paceCurve: CryptoTags.BrainpoolP256r1ExchangePublicKey);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        //Integrated Mapping: the terminal sends the additional nonce t in DO'81' and the chip answers with an
        //empty DO'82'; both map the nonce to Ĝ = f_G(R_p(s,t)) independently. Reaching the session keys (the
        //terminal verified the chip's token) proves the two sides derived the same generator over the wire.
        (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) = await EstablishPaceAsync(
            device, Convert.FromHexString(IntegratedMappingPaceOid), Convert.FromHexString(AdditionalNonceT)).ConfigureAwait(false);
        using(encryptionKey)
        using(macKey)
        {
            Assert.AreEqual(CardLifecyclePhase.SecureMessaging, card.Phase,
                "PACE with Integrated Mapping must leave the card in the Secure Messaging phase.");
            Assert.AreEqual(16, encryptionKey.AsReadOnlySpan().Length, "KSenc is an AES-128 key.");
            Assert.AreEqual(16, macKey.AsReadOnlySpan().Length, "KSmac is an AES-128 key.");
        }
    }


    [TestMethod]
    public async Task EstablishesPaceSessionWithChipAuthenticationMappingAgainstTheRealTerminal()
    {
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);

        //Mint the chip's static Chip Authentication key pair on the PACE curve: the card holds SK_IC, the terminal PK_IC.
        (ChipAuthenticationKey staticKey, EncodedEcPoint staticPublicKey) = await MintStaticChipKeyAsync(StaticChipPrivateKey).ConfigureAwait(false);
        using(staticKey)
        using(staticPublicKey)
        {
            using var card = new CardSimulator("passport-pace-cam", [dataGroup1],
                paceCurve: CryptoTags.BrainpoolP256r1ExchangePublicKey, paceChipAuthenticationKey: staticKey);
            using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

            //Chip Authentication Mapping: round 4 carries the chip token (DO'86') and the Encrypted Chip
            //Authentication Data (DO'8A'); the terminal recovers CA_IC and checks PK_Map,IC = CA_IC * PK_IC.
            //Reaching the session keys proves the chip authenticated with its static key over the wire.
            (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) = await EstablishPaceAsync(
                device, Convert.FromHexString(ChipAuthenticationMappingPaceOid), Convert.FromHexString(MappingPrivateIfd), staticPublicKey.AsReadOnlyMemory()).ConfigureAwait(false);
            using(encryptionKey)
            using(macKey)
            {
                Assert.AreEqual(CardLifecyclePhase.SecureMessaging, card.Phase,
                    "PACE with Chip Authentication Mapping must leave the card in the Secure Messaging phase.");
                Assert.AreEqual(16, encryptionKey.AsReadOnlySpan().Length, "KSenc is an AES-128 key.");
                Assert.AreEqual(16, macKey.AsReadOnlySpan().Length, "KSmac is an AES-128 key.");
            }
        }
    }


    [TestMethod]
    public async Task ChipAuthenticationMappingRejectsAWrongStaticPublicKey()
    {
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);

        //The card holds one static key; the terminal verifies against a different one, so PK_Map,IC = CA_IC * PK_IC fails.
        (ChipAuthenticationKey staticKey, EncodedEcPoint staticPublicKey) = await MintStaticChipKeyAsync(StaticChipPrivateKey).ConfigureAwait(false);
        (ChipAuthenticationKey wrongKey, EncodedEcPoint wrongPublicKey) = await MintStaticChipKeyAsync(WrongStaticChipPrivateKey).ConfigureAwait(false);
        using(staticKey)
        using(staticPublicKey)
        using(wrongKey)
        using(wrongPublicKey)
        {
            using var card = new CardSimulator("passport-pace-cam-wrong-key", [dataGroup1],
                paceCurve: CryptoTags.BrainpoolP256r1ExchangePublicKey, paceChipAuthenticationKey: staticKey);
            using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

            await Assert.ThrowsExactlyAsync<InvalidOperationException>(
                async () => await EstablishPaceAsync(
                    device, Convert.FromHexString(ChipAuthenticationMappingPaceOid), Convert.FromHexString(MappingPrivateIfd), wrongPublicKey.AsReadOnlyMemory()).ConfigureAwait(false)).ConfigureAwait(false);
        }
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The Secure Messaging session takes ownership of the two PACE session keys and is disposed via its using declaration.")]
    public async Task ReadsFilesOverSecureMessagingAfterPace()
    {
        using ElementaryFile efCom = EfCom.Write("0106", "040000", [0x61, 0x75], BaseMemoryPool.Shared);
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);
        using var card = new CardSimulator("passport-pace-sm-read", [efCom, dataGroup1], paceCurve: CryptoTags.BrainpoolP256r1ExchangePublicKey);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) = await EstablishPaceAsync(
            device, Convert.FromHexString(PaceOid), Convert.FromHexString(MappingPrivateIfd)).ConfigureAwait(false);

        //PACE initialises the AES Secure Messaging send-sequence counter to zero on both sides.
        using SecureMessagingSession session = new(
            encryptionKey, macKey, new byte[16], SecureMessagingProfile.Aes128, BaseMemoryPool.Shared);
        var channel = new SecureMessagingChannel(device, session);

        using ElementaryFile readEfCom = await channel.ReadElementaryFileAsync(efCom.FileIdentifier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(Convert.ToHexString(efCom.Content), Convert.ToHexString(readEfCom.Content),
            "EF.COM must read back byte-for-byte over the PACE AES Secure Messaging session.");

        using ElementaryFile readDataGroup1 = await channel.ReadElementaryFileAsync(dataGroup1.FileIdentifier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(Convert.ToHexString(dataGroup1.Content), Convert.ToHexString(readDataGroup1.Content),
            "EF.DG1 must read back byte-for-byte over the PACE AES Secure Messaging session.");
    }


    [TestMethod]
    public async Task RefusesAMappingRoundBeforeTheEncryptedNonceRound()
    {
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);
        using var card = new CardSimulator("passport-pace-order", [dataGroup1], FillAscending, paceCurve: CryptoTags.BrainpoolP256r1ExchangePublicKey);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        byte[] setAtData = Convert.FromHexString("800A04007F00070202040202830101");
        using CommandApdu setAt = CommandApdu.BuildCase3(
            0x00, InstructionCode.ManageSecurityEnvironment.Code, 0xC1, 0xA4, setAtData, BaseMemoryPool.Shared);
        (StatusWord setAtStatus, _) = await TransmitAsync(device, setAt).ConfigureAwait(false);
        Assert.IsTrue(setAtStatus.IsSuccess, "MSE:Set AT must succeed.");

        //A mapping round (DO'81') sent before the encrypted-nonce round: the card has no nonce to map.
        byte[] mappingKey = new byte[65];
        mappingKey[0] = 0x04;
        byte[] mappingData = [0x7C, 0x43, 0x81, 0x41, .. mappingKey];
        using CommandApdu mappingRound = CommandApdu.BuildCase4(0x10, 0x86, 0x00, 0x00, mappingData, 0, BaseMemoryPool.Shared);
        (StatusWord mappingStatus, _) = await TransmitAsync(device, mappingRound).ConfigureAwait(false);

        Assert.AreEqual(0x6985, mappingStatus.Value, "A mapping round without a nonce is refused with 6985.");
        Assert.AreEqual(CardLifecyclePhase.Operational, card.Phase, "A refused PACE round abandons the exchange.");
    }


    /// <summary>
    /// Derives the PACE password key Kπ from the MRZ and runs the real <see cref="PaceProtocol"/> terminal
    /// against the card for the given mechanism, returning the established AES session keys (the caller disposes both).
    /// </summary>
    /// <param name="device">The card device.</param>
    /// <param name="objectIdentifier">The PACE protocol OID selecting the mechanism (Generic, Integrated, or Chip Authentication Mapping).</param>
    /// <param name="mappingMaterial">The terminal's round-2 contribution: the mapping private key for Generic / Chip Authentication Mapping, or the nonce t for Integrated Mapping.</param>
    /// <param name="staticChipPublicKey">The chip's static public key PK_IC, required for Chip Authentication Mapping; default for the other mappings.</param>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned session keys transfers to the caller; the nonce key and password seed are disposed here.")]
    private async Task<(SymmetricKeyMemory EncryptionKey, SymmetricKeyMemory MacKey)> EstablishPaceAsync(
        ApduDevice device, ReadOnlyMemory<byte> objectIdentifier, ReadOnlyMemory<byte> mappingMaterial, ReadOnlyMemory<byte> staticChipPublicKey = default)
    {
        string mrzInformation = BasicAccessControl.BuildMrzInformation(DocumentNumber, DateOfBirth, DateOfExpiry);
        using DigestValue passwordSeed = await ComputeSha1Async(mrzInformation).ConfigureAwait(false);
        using SymmetricKeyMemory nonceKey = await PaceKeyDerivation.DerivePasswordKeyAsync(
            passwordSeed.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey, EncodedEcPoint chipEphemeralPublicKey) = await PaceProtocol.EstablishAsync(
            device, nonceKey, objectIdentifier, passwordReference: 0x01,
            CryptoTags.BrainpoolP256r1ExchangePublicKey,
            mappingMaterial, Convert.FromHexString(KeyAgreementPrivateIfd),
            BaseMemoryPool.Shared, staticChipPublicKey, TestContext.CancellationToken).ConfigureAwait(false);

        //These tests assert only the session keys; the chip's PACE ephemeral public key (used to derive the
        //Terminal Authentication chip identifier) is not needed here, so it is released.
        chipEphemeralPublicKey.Dispose();

        return (encryptionKey, macKey);
    }


    /// <summary>
    /// Runs a command through the real <see cref="ApduExecutor"/> against the card device and returns the
    /// status word and a copy of the response data.
    /// </summary>
    private async Task<(StatusWord Status, byte[] Data)> TransmitAsync(ApduDevice device, CommandApdu command)
    {
        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, command.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(result.IsTransportError, "The card transport must not error.");

        using ApduResponse response = result.Value;

        return (response.StatusWord, response.Data.ToArray());
    }


    /// <summary>
    /// Computes a SHA-1 digest of ASCII text through the registered <see cref="ComputeDigestDelegate"/> — the
    /// codebase's hash mechanism — rather than a direct framework hash call.
    /// </summary>
    private async Task<DigestValue> ComputeSha1Async(string text)
    {
        ComputeDigestDelegate digest = CryptographicKeyFactory.GetFunction<ComputeDigestDelegate>(typeof(ComputeDigestDelegate))
            ?? throw new InvalidOperationException("No ComputeDigestDelegate has been registered.");
        Tag sha1 = Tag.Create(
            (typeof(HashAlgorithmName), HashAlgorithmName.SHA1),
            (typeof(Purpose), Purpose.Digest),
            (typeof(EncodingScheme), EncodingScheme.Raw));

        (DigestValue value, _) = await digest(
            new ReadOnlySequence<byte>(Encoding.ASCII.GetBytes(text)), 20, sha1, BaseMemoryPool.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);

        return value;
    }


    /// <summary>A deterministic RNG backend filling the destination with ascending octets from <c>0xA0</c>.</summary>
    private static void FillAscending(Span<byte> destination)
    {
        for(int i = 0; i < destination.Length; i++)
        {
            destination[i] = (byte)(0xA0 + i);
        }
    }


    /// <summary>
    /// Mints a static Chip Authentication key pair on the PACE curve: a borrowed <see cref="ChipAuthenticationKey"/>
    /// for the card and the matching public key PK_IC for the terminal.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the private key transfers to the returned ChipAuthenticationKey and of the public key to the caller, which disposes both; the private key is disposed if the public-key computation throws.")]
    private async Task<(ChipAuthenticationKey StaticKey, EncodedEcPoint PublicKey)> MintStaticChipKeyAsync(string privateKeyHex)
    {
        EcMultiplyGeneratorDelegate multiplyGenerator = Resolve<EcMultiplyGeneratorDelegate>();

        IMemoryOwner<byte> privateKey = BaseMemoryPool.Shared.Rent(privateKeyHex.Length / 2, AllocationKind.Pinned);
        try
        {
            Convert.FromHexString(privateKeyHex).AsSpan().CopyTo(privateKey.Memory.Span);
            EncodedEcPoint publicKey = await multiplyGenerator(
                privateKey.Memory, CryptoTags.BrainpoolP256r1ExchangePublicKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            return (new ChipAuthenticationKey(privateKey, keyId: null), publicKey);
        }
        catch
        {
            privateKey.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Resolves a registered cryptographic delegate or throws.
    /// </summary>
    private static TDelegate Resolve<TDelegate>() where TDelegate: Delegate =>
        CryptographicKeyFactory.GetFunction<TDelegate>(typeof(TDelegate))
            ?? throw new InvalidOperationException($"No {typeof(TDelegate).Name} has been registered.");
}
