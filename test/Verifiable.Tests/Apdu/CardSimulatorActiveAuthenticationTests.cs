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
/// Drives the real Active Authentication terminal (<see cref="ActiveAuthentication.AuthenticateAsync(ApduDevice, EncodedEcPoint, ReadOnlyMemory{byte}, BaseMemoryPool, System.Threading.CancellationToken)"/>)
/// against the stateful <see cref="CardSimulator"/>. The card holds its Active Authentication private key as
/// personalisation and, on INTERNAL AUTHENTICATE, reads the curve from its own EF.DG15, signs the terminal's
/// challenge, and answers with the signature; the terminal verifies it against the EF.DG15 public key it
/// reconstructs from the wire bytes. A successful verification proves the chip holds the private key matching
/// its announced DG15 — the anti-cloning property. Both sides are production code that agree only on the wire
/// bytes, exercised over an elliptic curve verified through the Microsoft backend (P-256) and the BouncyCastle
/// backend (brainpoolP224r1), and once over a Basic Access Control Secure Messaging session.
/// </summary>
[TestClass]
internal sealed class CardSimulatorActiveAuthenticationTests
{
    private const string Td2MachineReadableZone =
        "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<" +
        "L898902C<3UTO6908061F9406236<<<<<<<8";

    private const string DocumentNumber = "L898902C<";
    private const string DateOfBirth = "690806";
    private const string DateOfExpiry = "940623";

    //Valid private scalars reused from the Doc 9303 Appendix G.1 worked example. Both are below the P-256 and
    //brainpool group orders, so they serve as keys on any of those curves; the 28-byte value fits brainpoolP224r1.
    private const string P256ActiveAuthenticationPrivateKey = "107CF58696EF6155053340FD633392BA81909DF7B9706F226F32086C7AFF974A";
    private const string ClonedActiveAuthenticationPrivateKey = "A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595";
    private const string BrainpoolP224r1ActiveAuthenticationPrivateKey = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567";

    /// <summary>The terminal's Active Authentication challenge RND.IFD (eMRTD uses 8 bytes).</summary>
    private const string Challenge = "0102030405060708";


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task AuthenticatesP256ActiveAuthenticationInPlaintext()
    {
        await RunPlaintextAuthenticationAsync(
            CryptoTags.P256ExchangePublicKey, P256ActiveAuthenticationPrivateKey, P256ActiveAuthenticationPrivateKey, expected: true).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task AuthenticatesBrainpoolP224r1ActiveAuthenticationInPlaintext()
    {
        await RunPlaintextAuthenticationAsync(
            CryptoTags.BrainpoolP224r1ExchangePublicKey, BrainpoolP224r1ActiveAuthenticationPrivateKey, BrainpoolP224r1ActiveAuthenticationPrivateKey, expected: true).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task RejectsActiveAuthenticationFromAClonedKey()
    {
        //A clone copied the DG15 file but could not extract the private key, so it signs with a different key:
        //the chip's signature does not verify against the genuine DG15 public key.
        await RunPlaintextAuthenticationAsync(
            CryptoTags.P256ExchangePublicKey, P256ActiveAuthenticationPrivateKey, ClonedActiveAuthenticationPrivateKey, expected: false).ConfigureAwait(false);
    }


    /// <summary>
    /// Mints a chip whose EF.DG15 announces the public key of <paramref name="publicKeyScalarHex"/> while the
    /// chip signs with <paramref name="heldKeyScalarHex"/>, runs Active Authentication against it in the clear
    /// through the real terminal, and asserts the verification outcome. When the two scalars match the
    /// signature verifies; when they differ (a clone) it does not.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "All carriers are disposed via using; the Active Authentication key carrier is disposed via using.")]
    private async Task RunPlaintextAuthenticationAsync(Tag curve, string publicKeyScalarHex, string heldKeyScalarHex, bool expected)
    {
        EcMultiplyGeneratorDelegate multiplyGenerator = Resolve<EcMultiplyGeneratorDelegate>();
        ReadOnlyMemory<byte> publicKeyScalar = Convert.FromHexString(publicKeyScalarHex);

        using EncodedEcPoint activeAuthenticationPublicKey = await multiplyGenerator(
            publicKeyScalar, curve, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using ElementaryFile dataGroup15File = DataGroup15.Write(activeAuthenticationPublicKey, BaseMemoryPool.Shared);
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);
        using ActiveAuthenticationKey activeAuthenticationKey = CreateActiveAuthenticationKey(heldKeyScalarHex);

        using var card = new CardSimulator(
            "passport-active-auth", [dataGroup1, dataGroup15File], activeAuthenticationKey: activeAuthenticationKey);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        //Firewall: the terminal reconstructs the Active Authentication public key from the DG15 wire bytes.
        using DataGroup15 parsedDataGroup15 = DataGroup15.Parse(dataGroup15File.AsReadOnlySpan(), BaseMemoryPool.Shared);
        byte[] challenge = Convert.FromHexString(Challenge);

        bool authenticated = await ActiveAuthentication.AuthenticateAsync(
            device, parsedDataGroup15.EllipticCurvePublicKey, challenge, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expected, authenticated,
            expected
                ? "The chip's signature over the challenge must verify against its genuine DG15 public key."
                : "A signature produced with a key other than the announced DG15 key must not verify.");
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "All carriers are disposed via using; the Active Authentication key carrier is disposed via using.")]
    public async Task AuthenticatesWhenTheVerificationKeyIsTaggedCompressed()
    {
        //The terminal need not hold the DG15 uncompressed point: a verification key whose tag declares the
        //compressed SEC1 encoding works just as well, so Active Authentication is robust to either encoding.
        EcMultiplyGeneratorDelegate multiplyGenerator = Resolve<EcMultiplyGeneratorDelegate>();
        ReadOnlyMemory<byte> privateKeyScalar = Convert.FromHexString(P256ActiveAuthenticationPrivateKey);

        using EncodedEcPoint uncompressedPublicKey = await multiplyGenerator(
            privateKeyScalar, CryptoTags.P256ExchangePublicKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using ElementaryFile dataGroup15File = DataGroup15.Write(uncompressedPublicKey, BaseMemoryPool.Shared);
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);
        using ActiveAuthenticationKey activeAuthenticationKey = CreateActiveAuthenticationKey(P256ActiveAuthenticationPrivateKey);

        using var card = new CardSimulator(
            "passport-active-auth-compressed", [dataGroup1, dataGroup15File], activeAuthenticationKey: activeAuthenticationKey);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        using EncodedEcPoint compressedPublicKey = CompressVerificationKey(uncompressedPublicKey);
        byte[] challenge = Convert.FromHexString(Challenge);

        bool authenticated = await ActiveAuthentication.AuthenticateAsync(
            device, compressedPublicKey, challenge, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(authenticated, "A verification key tagged compressed must verify as well as the uncompressed DG15 form.");
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The Basic Access Control session and its access keys are disposed in the using blocks; all carriers are disposed via using.")]
    public async Task AuthenticatesP256ActiveAuthenticationOverSecureMessaging()
    {
        Tag curve = CryptoTags.P256ExchangePublicKey;
        EcMultiplyGeneratorDelegate multiplyGenerator = Resolve<EcMultiplyGeneratorDelegate>();
        ReadOnlyMemory<byte> privateKeyScalar = Convert.FromHexString(P256ActiveAuthenticationPrivateKey);

        using EncodedEcPoint activeAuthenticationPublicKey = await multiplyGenerator(
            privateKeyScalar, curve, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using ElementaryFile dataGroup15File = DataGroup15.Write(activeAuthenticationPublicKey, BaseMemoryPool.Shared);
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);
        using ActiveAuthenticationKey activeAuthenticationKey = CreateActiveAuthenticationKey(P256ActiveAuthenticationPrivateKey);

        using var card = new CardSimulator(
            "passport-active-auth-sm", [dataGroup1, dataGroup15File], activeAuthenticationKey: activeAuthenticationKey);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        (SecureMessagingSession session, SymmetricKeyMemory accessEncryptionKey, SymmetricKeyMemory accessMacKey) =
            await EstablishBacAsync(device).ConfigureAwait(false);
        using(accessEncryptionKey)
        using(accessMacKey)
        using(session)
        {
            using DataGroup15 parsedDataGroup15 = DataGroup15.Parse(dataGroup15File.AsReadOnlySpan(), BaseMemoryPool.Shared);
            byte[] challenge = Convert.FromHexString(Challenge);

            bool authenticated = await ActiveAuthentication.AuthenticateAsync(
                device, session, parsedDataGroup15.EllipticCurvePublicKey, challenge, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(authenticated,
                "The chip's Active Authentication signature must verify over the Secure Messaging session, the realistic eMRTD ordering.");

            //The Secure Messaging session is still in step afterwards: a protected file read still succeeds.
            var channel = new SecureMessagingChannel(device, session);
            using ElementaryFile readDataGroup1 = await channel.ReadElementaryFileAsync(dataGroup1.FileIdentifier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(Convert.ToHexString(dataGroup1.Content), Convert.ToHexString(readDataGroup1.Content),
                "The Secure Messaging session must remain usable after Active Authentication.");
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
    /// Re-encodes an uncompressed SEC1 public point as a compressed verification key, tagged compressed, to
    /// exercise the Active Authentication terminal's encoding-agnostic key handling.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned carrier transfers to the caller, which disposes it via using.")]
    private static EncodedEcPoint CompressVerificationKey(EncodedEcPoint uncompressedPublicKey)
    {
        ReadOnlySpan<byte> point = uncompressedPublicKey.AsReadOnlySpan();
        int coordinateSize = (point.Length - 1) / 2;
        byte[] compressed = EllipticCurveUtilities.Compress(point.Slice(1, coordinateSize), point.Slice(1 + coordinateSize, coordinateSize));

        return EncodedEcPoint.FromBytes(compressed, CryptoTags.P256PublicKey, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Mints an Active Authentication private-key carrier from a hex scalar.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned ActiveAuthenticationKey, which the caller disposes.")]
    private static ActiveAuthenticationKey CreateActiveAuthenticationKey(string privateKeyHex)
    {
        byte[] bytes = Convert.FromHexString(privateKeyHex);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new ActiveAuthenticationKey(owner);
    }


    private static TDelegate Resolve<TDelegate>() where TDelegate: Delegate =>
        CryptographicKeyFactory.GetFunction<TDelegate>(typeof(TDelegate))
            ?? throw new InvalidOperationException($"No {typeof(TDelegate).Name} has been registered.");
}
