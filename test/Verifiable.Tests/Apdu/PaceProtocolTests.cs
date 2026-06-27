using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Apdu;
using Verifiable.Apdu.Pace;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Drives the full ICAO Doc 9303 Part 11 PACE Generic Mapping (ECDH) protocol against a
/// <see cref="VirtualCard"/> registered with the exact MSE:Set AT and GENERAL AUTHENTICATE
/// command/response pairs of Appendix G.1, with the terminal's ephemeral keys injected from the
/// worked example. Because the card matches commands by content, a passing run proves PACE builds
/// every command (mapping key, ephemeral key, terminal token) correctly, and reaching the Appendix
/// G.1 session keys proves the whole protocol end to end.
/// </summary>
[TestClass]
internal sealed class PaceProtocolTests
{
    private const string Oid = "04007F00070202040202";
    private const string NonceKeyKpi = "89DED1B26624EC1E634C1989302849DD";
    private const string MappingPrivateIfd = "7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99";
    private const string KeyAgreementPrivateIfd = "A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595";

    private const string MappingPublicIfd = "04" +
        "7ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E" +
        "544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D";
    private const string MappingPublicIc = "04" +
        "824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57" +
        "30D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54";
    private const string KeyAgreementPublicIfd = "04" +
        "2DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C" +
        "3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB36462";
    private const string KeyAgreementPublicIc = "04" +
        "9E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB" +
        "7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094";


    public required TestContext TestContext { get; set; }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The nonce key and both session keys are disposed in the finally blocks.")]
    public async Task EstablishesPaceSessionKeysPerAppendixG1()
    {
        var card = new VirtualCard();
        //MSE:Set AT (PACE OID + MRZ password reference).
        card.Register(Convert.FromHexString("0022C1A40F800A" + Oid + "830101"), Convert.FromHexString("9000"));
        //GENERAL AUTHENTICATE round 1: request the encrypted nonce.
        card.Register(Convert.FromHexString("10860000027C0000"),
            Convert.FromHexString("7C12801095A3A016522EE98D01E76CB6B98B42C39000"));
        //Round 2: terminal mapping key -> chip mapping key.
        card.Register(Convert.FromHexString("10860000457C438141" + MappingPublicIfd + "00"),
            Convert.FromHexString("7C438241" + MappingPublicIc + "9000"));
        //Round 3: terminal ephemeral key -> chip ephemeral key.
        card.Register(Convert.FromHexString("10860000457C438341" + KeyAgreementPublicIfd + "00"),
            Convert.FromHexString("7C438441" + KeyAgreementPublicIc + "9000"));
        //Round 4: terminal token -> chip token.
        card.Register(Convert.FromHexString("008600000C7C0A8508C2B0BD78D94BA86600"),
            Convert.FromHexString("7C0A86083ABB9674BCE93C089000"));

        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);
        using SymmetricKeyMemory nonceKey = CreateKey(NonceKeyKpi);

        (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey, EncodedEcPoint chipEphemeralPublicKey) = await PaceProtocol.EstablishAsync(
            device, nonceKey, Convert.FromHexString(Oid), passwordReference: 0x01,
            CryptoTags.BrainpoolP256r1ExchangePublicKey,
            Convert.FromHexString(MappingPrivateIfd), Convert.FromHexString(KeyAgreementPrivateIfd),
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            Assert.AreEqual("F5F0E35C0D7161EE6724EE513A0D9A7F", Convert.ToHexString(encryptionKey.AsReadOnlySpan()),
                "KSenc must match Doc 9303 Appendix G.1.");
            Assert.AreEqual("FE251C7858B356B24514B3BD5F4297D1", Convert.ToHexString(macKey.AsReadOnlySpan()),
                "KSmac must match Doc 9303 Appendix G.1.");
        }
        finally
        {
            encryptionKey.Dispose();
            macKey.Dispose();
            chipEphemeralPublicKey.Dispose();
        }
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned SymmetricKeyMemory, which the caller disposes.")]
    private static SymmetricKeyMemory CreateKey(string hex)
    {
        byte[] bytes = Convert.FromHexString(hex);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new SymmetricKeyMemory(owner, CryptoTags.Aes128Cbc);
    }
}
