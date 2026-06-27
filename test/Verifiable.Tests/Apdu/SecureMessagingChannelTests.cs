using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Apdu;
using Verifiable.Apdu.SecureMessaging;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates reading a transparent elementary file over a Secure Messaging session against the ICAO
/// Doc 9303 Part 11 Appendix D.4 worked example, which selects EF.COM and reads it in two READ BINARY
/// chunks (a four-byte header read to learn the length, then the remainder). The
/// <see cref="VirtualCard"/> is registered with the exact protected command/response pairs, so a
/// passing read proves the channel issues each protected command correctly and reassembles the file.
/// </summary>
[TestClass]
internal sealed class SecureMessagingChannelTests
{
    private const string Ksenc = "979EC13B1CBFE9DCD01AB0FED307EAE5";
    private const string Ksmac = "F1CB1F1FB5ADF208806B89DC579DC1F8";
    private const string InitialSsc = "887022120C06C226";
    private const ushort EfCom = 0x011E;
    private const string EfComContents = "60145F0104303130365F36063034303030305C026175";


    public required TestContext TestContext { get; set; }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The session takes ownership of the two keys and is disposed via its using declaration.")]
    public async Task ReadsEfComOverSecureMessagingPerAppendixD4()
    {
        var card = new VirtualCard();
        //SELECT EF.COM.
        card.Register(Convert.FromHexString("0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800"),
            Convert.FromHexString("990290008E08FA855A5D4C50A8ED9000"));
        //READ BINARY of the first four bytes (the file header).
        card.Register(Convert.FromHexString("0CB000000D9701048E08ED6705417E96BA5500"),
            Convert.FromHexString("8709019FF0EC34F9922651990290008E08AD55CC17140B2DED9000"));
        //READ BINARY of the remaining eighteen bytes from offset four.
        card.Register(Convert.FromHexString("0CB000040D9701128E082EA28A70F3C7B53500"),
            Convert.FromHexString("871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A990290008E08C8B2787EAEA07D749000"));

        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);
        using SecureMessagingSession session = new(
            CreateKey(Ksenc, CryptoTags.TripleDesCbc), CreateKey(Ksmac, CryptoTags.RetailMac),
            Convert.FromHexString(InitialSsc), SecureMessagingProfile.TripleDes, BaseMemoryPool.Shared);

        var channel = new SecureMessagingChannel(device, session);

        using ElementaryFile file = await channel.ReadElementaryFileAsync(
            EfCom, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EfComContents, Convert.ToHexString(file.Content),
            "The channel must reassemble EF.COM exactly as the Appendix D.4 worked example reads it.");
        Assert.AreEqual(EfCom, file.FileIdentifier, "The carrier must record the file it was read from.");
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned SymmetricKeyMemory, which the session disposes.")]
    private static SymmetricKeyMemory CreateKey(string hex, Tag tag)
    {
        byte[] bytes = Convert.FromHexString(hex);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new SymmetricKeyMemory(owner, tag);
    }
}
