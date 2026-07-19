using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Apdu;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Pins <see cref="ApduExecutor"/>'s <c>61xx</c> response-chaining reassembly against the exact bytes
/// of CTAP 2.3, section 11.3.6 ("Fragmentation")'s worked example: the second and third exchanges of
/// a chained <c>authenticatorMakeCredential</c> response, sent to the authenticator over short-length
/// NFCCTAP_MSG framing. This is the pending byte-level verification the recon left open — the executor
/// is generic ISO/IEC 7816-4 machinery with no CTAP awareness, so no fix inside the Ctap subtree was
/// needed once these bytes were traced through it.
/// </summary>
[TestClass]
internal sealed class CtapNfcFragmentationWorkedExampleTests
{
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The second short-APDU-chained NFCCTAP_MSG command from the spec's worked example: the final
    /// segment of an outbound-chained <c>authenticatorMakeCredential</c> request (CLA 0x80, final
    /// segment, Le=0x00).
    /// </summary>
    private const string SecondCommandHex =
        "80 10 00 00 17" +
        "726BF50850FC43AAA411D948CC6C37068B8DA1D5080901" +
        "00";

    /// <summary>The authenticator's response to <see cref="SecondCommandHex"/>: partial data, SW=6100.</summary>
    private const string SecondResponseHex =
        "00" +
        "A301667061636B6564025900A20021F5FC0B85CD22E60623BCD7D1CA48948909" +
        "249B4776EB515154E57B66AE12C500000055F8A011F38C0A4D15800617111F9E" +
        "DC7D0010F4D57B23DD0CB785680CDAA7F7E44F60A5010203262001215820DF01" +
        "7D0B286795BEA153D166A0A15B4F6B67A3AF4A101E10E8496F3DD3C5D1A92258" +
        "2094B22551E6325D7733C41BB2F5A642ADEE417C97E0906197B5B0CD8B8D6C6B" +
        "A7A16B686D61632D736563726574F503A363616C672663736967584730450220" +
        "7CCAC57A1E43DF24B0847EEBF119D28DCDC5048F7DCD8EDD79E79721C41BCF2D" +
        "022100D89EC75B92CE8FF9E46FE7F8C87995694A63E5B78AB85C47B9DA" +
        "6100";

    /// <summary>The spec's third exchange: GET RESPONSE with Le=0x00 (the first chained command's requested Le, clamped per ISO/IEC 7816-4 Annex A.4).</summary>
    private const string ThirdCommandHex = "80 C0 00 00 00";

    /// <summary>The authenticator's response to <see cref="ThirdCommandHex"/>: more data, SW=61A7.</summary>
    private const string ThirdResponseHex =
        "1C580A8EC83A63783563815901973082019330820138A003020102020900859B" +
        "726CB24B4C29300A06082A8648CE3D0403023047310B30090603550406130255" +
        "5331143012060355040A0C0B59756269636F205465737431223020060355040B" +
        "0C1941757468656E74696361746F72204174746573746174696F6E301E170D31" +
        "36313230343131353530305A170D3236313230323131353530305A3047310B30" +
        "0906035504061302555331143012060355040A0C0B59756269636F2054657374" +
        "31223020060355040B0C1941757468656E74696361746F722041747465737461" +
        "74696F6E3059301306072A8648CE3D020106082A8648CE3D030107034200" +
        "61A7";

    /// <summary>The spec's fourth exchange: GET RESPONSE with Le=0xA7 (SW2 from the third exchange).</summary>
    private const string FourthCommandHex = "80 C0 00 00 A7";

    /// <summary>The authenticator's final response: the remaining data, SW=9000.</summary>
    private const string FourthResponseHex =
        "04AD11EB0E8852E53AD5DFED86B41E6134A18EC4E1AF8F221A3C7D6E636C80EA" +
        "13C3D504FF2E76211BB44525B196C44CB4849979CF6F896ECD2BB860DE1BF437" +
        "6BA30D300B30090603551D1304023000300A06082A8648CE3D04030203490030" +
        "46022100E9A39F1B03197525F7373E10CE77E78021731B94D0C03F3FDA1FD22D" +
        "B3D030E7022100C4FAEC3445A820CF43129CDB00AABEFD9AE2D874F9C5D343CB" +
        "2F113DA23723F3" +
        "9000";

    [TestMethod]
    public async Task ExecutorReassemblesWorkedExampleChainByteForByte()
    {
        byte[] secondCommand = ParseHex(SecondCommandHex);
        byte[] secondResponse = ParseHex(SecondResponseHex);
        byte[] thirdCommand = ParseHex(ThirdCommandHex);
        byte[] thirdResponse = ParseHex(ThirdResponseHex);
        byte[] fourthCommand = ParseHex(FourthCommandHex);
        byte[] fourthResponse = ParseHex(FourthResponseHex);

        var issuedGetResponseCommands = new List<byte[]>();
        int callCount = 0;

        ValueTask<ApduResult<ApduResponse>> Handler(
            ReadOnlyMemory<byte> commandApdu, MemoryPool<byte> pool, CancellationToken cancellationToken)
        {
            callCount++;
            byte[] response = callCount switch
            {
                1 => secondResponse,
                2 => thirdResponse,
                _ => fourthResponse
            };

            if(callCount > 1)
            {
                issuedGetResponseCommands.Add(commandApdu.ToArray());
            }

            IMemoryOwner<byte> owner = pool.Rent(response.Length);
            response.CopyTo(owner.Memory.Span);
            var apduResponse = new ApduResponse(owner, response.Length);

            return ValueTask.FromResult(ApduResult<ApduResponse>.Success(apduResponse, apduResponse.StatusWord));
        }

        using var device = ApduDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, secondCommand, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using ApduResponse assembled = result.Value;
        Assert.IsTrue(assembled.StatusWord.IsSuccess);

        //Exactly the two GET RESPONSE commands the spec's worked example shows, byte-for-byte.
        Assert.HasCount(2, issuedGetResponseCommands);
        Assert.AreSequenceEqual(thirdCommand, issuedGetResponseCommands[0]);
        Assert.AreSequenceEqual(fourthCommand, issuedGetResponseCommands[1]);

        //The assembled data is exactly the three responses' data fields (status word stripped), concatenated.
        byte[] expectedData =
        [
            .. secondResponse.AsSpan(0, secondResponse.Length - ApduConstants.StatusWordSize).ToArray(),
            .. thirdResponse.AsSpan(0, thirdResponse.Length - ApduConstants.StatusWordSize).ToArray(),
            .. fourthResponse.AsSpan(0, fourthResponse.Length - ApduConstants.StatusWordSize).ToArray()
        ];
        Assert.AreSequenceEqual(expectedData, assembled.Data.ToArray());
    }

    /// <summary>
    /// Strips the whitespace and line breaks the constants above use for readability, and decodes the
    /// remaining hex digits.
    /// </summary>
    /// <param name="hex">The hex string, with optional embedded whitespace.</param>
    /// <returns>The decoded bytes.</returns>
    private static byte[] ParseHex(string hex)
    {
        Span<char> compact = stackalloc char[hex.Length];
        int written = 0;
        foreach(char c in hex)
        {
            if(!char.IsWhiteSpace(c))
            {
                compact[written++] = c;
            }
        }

        return Convert.FromHexString(compact[..written]);
    }
}
