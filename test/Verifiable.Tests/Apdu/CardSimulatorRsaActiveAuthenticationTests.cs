using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Apdu;
using Verifiable.Apdu.Automata;
using Verifiable.Apdu.Bac;
using Verifiable.Apdu.Lds;
using Verifiable.Apdu.SecureMessaging;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Drives the real RSA Active Authentication terminal
/// (<see cref="ActiveAuthentication.AuthenticateAsync(ApduDevice, RsaPublicKey, ReadOnlyMemory{byte}, BaseMemoryPool, System.Threading.CancellationToken)"/>)
/// against the stateful <see cref="CardSimulator"/>. The card holds its RSA Active Authentication private key
/// as personalisation and, on INTERNAL AUTHENTICATE, signs the terminal's challenge with ISO/IEC 9796-2
/// Digital Signature scheme 1 (message recovery); the terminal recovers the chip's random block and verifies
/// the embedded hash against the EF.DG15 RSA public key it reconstructs from the wire bytes. A successful
/// verification proves the chip holds the private key matching its announced DG15 — the anti-cloning property.
/// </summary>
/// <remarks>
/// The key pair is minted with the .NET base class library RSA (independent of the BouncyCastle signing path),
/// but ISO/IEC 9796-2 has no base-class-library implementation, so the signature is produced and verified by
/// the same BouncyCastle backend: this is a self-consistent firewalled round trip (both parties agree only on
/// the wire bytes) rather than a cross-implementation conformance check. A 1024-bit key is used because eMRTD
/// RSA Active Authentication keys are sized so the signature fits a short Le response. The minted key material
/// is held in pooled carriers (<see cref="RsaPublicKey"/>, <see cref="ActiveAuthenticationKey"/>) disposed via
/// <c>using</c>, never naked arrays.
/// </remarks>
[TestClass]
internal sealed class CardSimulatorRsaActiveAuthenticationTests
{
    private const string Td2MachineReadableZone =
        "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<" +
        "L898902C<3UTO6908061F9406236<<<<<<<8";

    private const string DocumentNumber = "L898902C<";
    private const string DateOfBirth = "690806";
    private const string DateOfExpiry = "940623";

    /// <summary>The terminal's Active Authentication challenge RND.IFD (eMRTD uses 8 bytes).</summary>
    private const string Challenge = "0102030405060708";


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task AuthenticatesRsaActiveAuthenticationInPlaintext()
    {
        (RsaPublicKey publicKey, ActiveAuthenticationKey privateKey) = MintRsaActiveAuthenticationKeyPair();
        using(publicKey)
        using(privateKey)
        {
            await RunPlaintextAuthenticationAsync(publicKey, privateKey, expected: true).ConfigureAwait(false);
        }
    }


    [TestMethod]
    public async Task RejectsRsaActiveAuthenticationFromAClonedKey()
    {
        //A clone copied the DG15 file but could not extract the private key, so it signs with a different RSA
        //key: the chip's signature does not recover against the genuine DG15 public key. DG15 announces the
        //genuine public key while the chip holds the cloned private key.
        (RsaPublicKey genuinePublicKey, ActiveAuthenticationKey genuinePrivateKey) = MintRsaActiveAuthenticationKeyPair();
        (RsaPublicKey clonePublicKey, ActiveAuthenticationKey clonePrivateKey) = MintRsaActiveAuthenticationKeyPair();
        using(genuinePublicKey)
        using(genuinePrivateKey)
        using(clonePublicKey)
        using(clonePrivateKey)
        {
            await RunPlaintextAuthenticationAsync(genuinePublicKey, clonePrivateKey, expected: false).ConfigureAwait(false);
        }
    }


    [TestMethod]
    public async Task RejectsRsaActiveAuthenticationKeyWithExponentOne()
    {
        //A chip that announces an EF.DG15 RSA public key with public exponent 1 turns ISO/IEC 9796-2 verification
        //into the identity map: the recovered message equals the signature, so any hash is forged. The terminal
        //must reject the degenerate key and fail closed, whatever signature accompanies it (the key is rejected
        //before the signature is ever processed).
        using RSA rsa = RSA.Create(1024);
        byte[] modulus = rsa.ExportParameters(includePrivateParameters: false).Modulus!;
        using RsaPublicKey exponentOneKey = BuildRsaPublicKey(modulus, [0x01]);

        RecoverableVerificationDelegate verify = RecoverableSignatureFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(
            CryptoAlgorithm.RsaIso9796d2, Purpose.Verification);

        bool verified = await verify(
            Convert.FromHexString(Challenge), new byte[128], exponentOneKey.AsReadOnlyMemory(), null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(verified, "An RSA Active Authentication key with a public exponent of 1 is an identity-map forgery vector and must be rejected.");
    }


    /// <summary>
    /// Builds a PKCS#1 <c>RSAPublicKey</c> (a SEQUENCE of the modulus and public exponent) from the raw integers
    /// into a pooled <see cref="RsaPublicKey"/> carrier — the same wire form and carrier EF.DG15 provides — so the
    /// key material lives in a tracked, zeroised buffer rather than a naked array. The caller disposes it.
    /// </summary>
    private static RsaPublicKey BuildRsaPublicKey(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> exponent)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteInteger(new BigInteger(modulus, isUnsigned: true, isBigEndian: true));
            writer.WriteInteger(new BigInteger(exponent, isUnsigned: true, isBigEndian: true));
        }

        return RsaPublicKey.FromBytes(writer.Encode(), BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Mints a chip whose EF.DG15 announces <paramref name="announcedPublicKey"/> while the chip holds
    /// <paramref name="heldPrivateKey"/>, runs RSA Active Authentication against it in the clear through the
    /// real terminal, and asserts the verification outcome. When the keys match the signature recovers and
    /// verifies; when they differ (a clone) it does not.
    /// </summary>
    private async Task RunPlaintextAuthenticationAsync(RsaPublicKey announcedPublicKey, ActiveAuthenticationKey heldPrivateKey, bool expected)
    {
        using ElementaryFile dataGroup15File = DataGroup15.Write(announcedPublicKey, BaseMemoryPool.Shared);
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);

        using var card = new CardSimulator(
            "passport-rsa-active-auth", [dataGroup1, dataGroup15File], activeAuthenticationKey: heldPrivateKey);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        //Firewall: the terminal reconstructs the Active Authentication public key from the DG15 wire bytes.
        using DataGroup15 parsedDataGroup15 = DataGroup15.Parse(dataGroup15File.AsReadOnlySpan(), BaseMemoryPool.Shared);

        bool authenticated = await ActiveAuthentication.AuthenticateAsync(
            device, parsedDataGroup15.RsaPublicKey, Convert.FromHexString(Challenge), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expected, authenticated,
            expected
                ? "The chip's ISO-9796-2 signature over the challenge must recover and verify against its genuine DG15 public key."
                : "A signature produced with a key other than the announced DG15 key must not verify.");
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The Basic Access Control session and its access keys are disposed in the using blocks; all carriers are disposed via using.")]
    public async Task AuthenticatesRsaActiveAuthenticationOverSecureMessaging()
    {
        (RsaPublicKey publicKey, ActiveAuthenticationKey privateKey) = MintRsaActiveAuthenticationKeyPair();
        using(publicKey)
        using(privateKey)
        {
            using ElementaryFile dataGroup15File = DataGroup15.Write(publicKey, BaseMemoryPool.Shared);
            using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);

            using var card = new CardSimulator(
                "passport-rsa-active-auth-sm", [dataGroup1, dataGroup15File], activeAuthenticationKey: privateKey);
            using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

            (SecureMessagingSession session, SymmetricKeyMemory accessEncryptionKey, SymmetricKeyMemory accessMacKey) =
                await EstablishBacAsync(device).ConfigureAwait(false);
            using(accessEncryptionKey)
            using(accessMacKey)
            using(session)
            {
                using DataGroup15 parsedDataGroup15 = DataGroup15.Parse(dataGroup15File.AsReadOnlySpan(), BaseMemoryPool.Shared);

                bool authenticated = await ActiveAuthentication.AuthenticateAsync(
                    device, session, parsedDataGroup15.RsaPublicKey, Convert.FromHexString(Challenge), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(authenticated,
                    "The chip's RSA Active Authentication signature must verify over the Secure Messaging session, the realistic eMRTD ordering.");

                //The Secure Messaging session is still in step afterwards: a protected file read still succeeds.
                var channel = new SecureMessagingChannel(device, session);
                using ElementaryFile readDataGroup1 = await channel.ReadElementaryFileAsync(dataGroup1.FileIdentifier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(Convert.ToHexString(dataGroup1.Content), Convert.ToHexString(readDataGroup1.Content),
                    "The Secure Messaging session must remain usable after RSA Active Authentication.");
            }
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

        SecureMessagingSession session = await BasicAccessControl.EstablishSessionAsync(
            device, encryptionKey, macKey, Convert.FromHexString("1122334455667788"), Convert.FromHexString("112233445566778899AABBCCDDEEFF00"),
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        return (session, encryptionKey, macKey);
    }


    /// <summary>
    /// Mints an RSA Active Authentication key pair with an independent oracle (the base class library RSA) into
    /// pooled carriers: the chip's <see cref="RsaPublicKey"/> for EF.DG15 and its <see cref="ActiveAuthenticationKey"/>
    /// (the PKCS#1 DER private key). The caller disposes both. The base-class-library export returns a transient
    /// array consumed inline; the key material lives in the pooled carriers, not a naked buffer.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of both carriers transfers to the caller, which disposes them via using; the catch disposes the public-key carrier if minting the private-key carrier fails.")]
    private static (RsaPublicKey PublicKey, ActiveAuthenticationKey PrivateKey) MintRsaActiveAuthenticationKeyPair()
    {
        using RSA rsa = RSA.Create(1024);

        RsaPublicKey publicKey = RsaPublicKey.FromBytes(rsa.ExportRSAPublicKey(), BaseMemoryPool.Shared);
        try
        {
            ActiveAuthenticationKey privateKey = CreateRsaActiveAuthenticationKey(rsa.ExportRSAPrivateKey());

            return (publicKey, privateKey);
        }
        catch
        {
            publicKey.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Mints an RSA Active Authentication private-key carrier, copying the PKCS#1 DER <c>RSAPrivateKey</c> into
    /// pooled memory the carrier owns and zeroizes on disposal.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned ActiveAuthenticationKey, which the caller disposes; the catch disposes it on failure.")]
    private static ActiveAuthenticationKey CreateRsaActiveAuthenticationKey(ReadOnlySpan<byte> derPrivateKey)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(derPrivateKey.Length);
        try
        {
            derPrivateKey.CopyTo(owner.Memory.Span);

            return new ActiveAuthenticationKey(owner);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }
}
