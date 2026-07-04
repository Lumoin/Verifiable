using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Validates the elliptic-curve point arithmetic seam (scalar·G, scalar·P, P+Q) against the ICAO
/// Doc 9303 Part 11 Appendix G.1 PACE Generic Mapping worked example (brainpoolP256r1): the mapping
/// shared point H, the mapped generator Ĝ = s·G + H, and the key agreement over Ĝ down to the shared
/// secret K. Every operation runs through the registered delegate.
/// </summary>
[TestClass]
internal sealed class PaceGenericMappingEcTests
{
    //Appendix G.1 ephemeral private scalars.
    private const string MappingPrivateIfd = "7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99";
    private const string MappingPrivateIc = "498FF49756F2DC1587840041839A85982BE7761D14715FB091EFA7BCE9058560";
    private const string Nonce = "3F00C4D39D153F2B2A214A078D899B22";
    private const string KeyAgreementPrivateIfd = "A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595";
    private const string KeyAgreementPrivateIc = "107CF58696EF6155053340FD633392BA81909DF7B9706F226F32086C7AFF974A";

    //Appendix G.1 ephemeral public points (SEC1 uncompressed, 0x04 || X || Y).
    private const string MappingPublicIfd = "04" +
        "7ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E" +
        "544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D";
    private const string MappingPublicIc = "04" +
        "824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57" +
        "30D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54";
    private const string SharedPointH = "04" +
        "60332EF2450B5D247EF6D3868397D398852ED6E8CAF6FFEEF6BF85CA57057FD5" +
        "0840CA7415BAF3E43BD414D35AA4608B93A2CAF3A4E3EA4E82C9C13D03EB7181";
    private const string MappedGenerator = "04" +
        "8CED63C91426D4F0EB1435E7CB1D74A46723A0AF21C89634F65A9AE87A9265E2" +
        "8C879506743F8611AC33645C5B985C80B5F09A0B83407C1B6A4D857AE76FE522";
    private const string KeyAgreementPublicIfd = "04" +
        "2DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C" +
        "3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB36462";
    private const string KeyAgreementPublicIc = "04" +
        "9E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB" +
        "7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094";
    private const string SharedSecretK = "28768D20701247DAE81804C9E780EDE582A9996DB4A315020B2733197DB84925";


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task GeneratorMultiplyProducesTheMappingPublicKey()
    {
        //PK_Map_IFD = SK_Map_IFD · G.
        string point = await MultiplyGenerator(MappingPrivateIfd).ConfigureAwait(false);
        Assert.AreEqual(MappingPublicIfd, point, "SK_Map_IFD · G must equal the Appendix G.1 mapping public key.");
    }


    [TestMethod]
    public async Task PointMultiplyProducesTheMappingSharedPointH()
    {
        //H = SK_Map_IFD · PK_Map_IC = SK_Map_IC · PK_Map_IFD.
        string fromTerminal = await MultiplyPoint(MappingPrivateIfd, MappingPublicIc).ConfigureAwait(false);
        string fromChip = await MultiplyPoint(MappingPrivateIc, MappingPublicIfd).ConfigureAwait(false);

        Assert.AreEqual(SharedPointH, fromTerminal, "SK_Map_IFD · PK_Map_IC must equal the Appendix G.1 shared point H.");
        Assert.AreEqual(SharedPointH, fromChip, "Both sides must agree on H.");
    }


    [TestMethod]
    public async Task GenericMappingProducesTheMappedGenerator()
    {
        //Ĝ = s · G + H.
        string sTimesG = await MultiplyGenerator(Nonce).ConfigureAwait(false);
        string mapped = await AddPoints(sTimesG, SharedPointH).ConfigureAwait(false);

        Assert.AreEqual(MappedGenerator, mapped, "s · G + H must equal the Appendix G.1 mapped generator Ĝ.");
    }


    [TestMethod]
    public async Task KeyAgreementOverTheMappedGeneratorProducesThePublicKey()
    {
        //PK_IFD = SK_IFD · Ĝ — key agreement runs over the mapped generator, not the standard one.
        string point = await MultiplyPoint(KeyAgreementPrivateIfd, MappedGenerator).ConfigureAwait(false);
        Assert.AreEqual(KeyAgreementPublicIfd, point, "SK_IFD · Ĝ must equal the Appendix G.1 ephemeral public key.");
    }


    [TestMethod]
    public async Task KeyAgreementProducesTheSharedSecretXCoordinate()
    {
        //K = x-coordinate of (SK_IC · PK_IFD) = x-coordinate of (SK_IFD · PK_IC).
        string fromChip = await MultiplyPoint(KeyAgreementPrivateIc, KeyAgreementPublicIfd).ConfigureAwait(false);
        string fromTerminal = await MultiplyPoint(KeyAgreementPrivateIfd, KeyAgreementPublicIc).ConfigureAwait(false);

        //Skip the 0x04 prefix (2 hex chars) and take the 32-byte X-coordinate (64 hex chars).
        Assert.AreEqual(SharedSecretK, fromChip.Substring(2, 64), "The X-coordinate must equal the Appendix G.1 shared secret K.");
        Assert.AreEqual(fromChip, fromTerminal, "Both sides must agree on the shared point.");
    }


    [TestMethod]
    public async Task PointMultiplyRejectsThePointAtInfinity()
    {
        //The SEC1 point at infinity — a single 0x00 byte — multiplies to the identity for any scalar, collapsing
        //the ECDH shared secret to a fixed, key-independent value: a full PACE / Chip Authentication bypass. The
        //point is rejected before it reaches the curve arithmetic.
        await Assert.ThrowsExactlyAsync<ArgumentException>(
            async () => await MultiplyPoint(KeyAgreementPrivateIfd, "00").ConfigureAwait(false)).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task PointMultiplyRejectsAPointNotOnTheCurve()
    {
        //An uncompressed point of the correct length whose coordinates do not satisfy the curve equation is not a
        //valid public key; multiplying by it is an invalid-curve foothold, so it is rejected.
        string offCurvePoint = "04" + new string('7', 128);
        await Assert.ThrowsExactlyAsync<ArgumentException>(
            async () => await MultiplyPoint(KeyAgreementPrivateIfd, offCurvePoint).ConfigureAwait(false)).ConfigureAwait(false);
    }


    private async Task<string> MultiplyGenerator(string scalarHex)
    {
        EcMultiplyGeneratorDelegate multiply = Resolve<EcMultiplyGeneratorDelegate>();
        using EncodedEcPoint result = await multiply(
            Convert.FromHexString(scalarHex), CryptoTags.BrainpoolP256r1ExchangePublicKey,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        return Convert.ToHexString(result.AsReadOnlySpan());
    }


    private async Task<string> MultiplyPoint(string scalarHex, string pointHex)
    {
        EcMultiplyPointDelegate multiply = Resolve<EcMultiplyPointDelegate>();
        using EncodedEcPoint result = await multiply(
            Convert.FromHexString(scalarHex), Convert.FromHexString(pointHex), CryptoTags.BrainpoolP256r1ExchangePublicKey,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        return Convert.ToHexString(result.AsReadOnlySpan());
    }


    private async Task<string> AddPoints(string pointHex, string addendHex)
    {
        EcAddPointsDelegate add = Resolve<EcAddPointsDelegate>();
        using EncodedEcPoint result = await add(
            Convert.FromHexString(pointHex), Convert.FromHexString(addendHex), CryptoTags.BrainpoolP256r1ExchangePublicKey,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        return Convert.ToHexString(result.AsReadOnlySpan());
    }


    private static TDelegate Resolve<TDelegate>() where TDelegate: Delegate =>
        CryptographicKeyFactory.GetFunction<TDelegate>(typeof(TDelegate))
            ?? throw new InvalidOperationException($"No {typeof(TDelegate).Name} has been registered.");
}
