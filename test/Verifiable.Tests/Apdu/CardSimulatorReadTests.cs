using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Apdu;
using Verifiable.Apdu.Automata;
using Verifiable.Apdu.Lds;
using Verifiable.Cryptography;
using Verifiable.Foundation.Automata;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Drives the plaintext eMRTD read path against the stateful <see cref="CardSimulator"/> — the
/// computes-from-state inverse of a terminal, built on the same <see cref="PushdownAutomaton{TState, TInput, TStackSymbol}"/>
/// as the TPM simulator. The simulator backs an <see cref="ApduDevice"/> through the
/// <see cref="TransceiveDelegate"/> seam, so the real <see cref="CommandApdu"/> builders and
/// <see cref="ApduExecutor"/> drive SELECT and READ BINARY against it; a minted EF.COM and EF.DG1 read back
/// byte-for-byte (whole and in chunks), the error paths return the ISO/IEC 7816-4 status words, and the
/// state-level trace stream records each transition.
/// </summary>
[TestClass]
internal sealed class CardSimulatorReadTests
{
    private const string Td2MachineReadableZone =
        "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<" +
        "L898902C<3UTO6908061F9406236<<<<<<<8";


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task ServesMintedEfComAndDataGroup1ByteForByte()
    {
        using ElementaryFile efCom = EfCom.Write("0106", "040000", [0x61, 0x75], BaseMemoryPool.Shared);
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);

        using var card = new CardSimulator("passport", [efCom, dataGroup1]);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        await AssertReadsBackAsync(device, efCom, chunkSize: 256).ConfigureAwait(false);
        await AssertReadsBackAsync(device, dataGroup1, chunkSize: 256).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task ReassemblesAFileAcrossMultipleReadBinaries()
    {
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);

        using var card = new CardSimulator("passport-chunked", [dataGroup1]);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        //Reading in 8-byte chunks forces many READ BINARYs at increasing offsets.
        await AssertReadsBackAsync(device, dataGroup1, chunkSize: 8).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task RejectsInvalidCommands()
    {
        using ElementaryFile efCom = EfCom.Write("0106", "040000", [0x61, 0x75], BaseMemoryPool.Shared);

        using var card = new CardSimulator("passport-errors", [efCom]);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        //READ BINARY before any SELECT has no current EF.
        (StatusWord noCurrentEf, _) = await ReadBinaryAsync(device, offset: 0, length: 4).ConfigureAwait(false);
        Assert.AreEqual(0x6986, noCurrentEf.Value, "A READ BINARY before any SELECT is refused with 6986.");

        //Selecting a file the card does not hold returns 6A82 and leaves no current EF.
        StatusWord notFound = await SelectAsync(device, 0x011D).ConfigureAwait(false);
        Assert.AreEqual(0x6A82, notFound.Value, "Selecting an absent file returns 6A82.");

        //A SELECT mode other than by-file-identifier (here P1=04, select by AID) is not modelled.
        StatusWord wrongMode = await SelectWithParametersAsync(device, p1: 0x04, p2: 0x0C, [0x01, 0x02]).ConfigureAwait(false);
        Assert.AreEqual(0x6A86, wrongMode.Value, "A SELECT mode other than by-file-identifier returns 6A86.");

        //A valid SELECT, then a READ BINARY starting at the end of the file.
        Assert.IsTrue((await SelectAsync(device, efCom.FileIdentifier).ConfigureAwait(false)).IsSuccess, "SELECT of EF.COM must succeed.");
        (StatusWord pastEnd, _) = await ReadBinaryAsync(device, offset: efCom.Length, length: 1).ConfigureAwait(false);
        Assert.AreEqual(0x6B00, pastEnd.Value, "Reading at or beyond the end of the file returns 6B00.");

        //An instruction this slice does not model (READ RECORD).
        using CommandApdu readRecord = CommandApdu.BuildCase2(
            0x00, InstructionCode.ReadRecord.Code, 0x00, 0x00, le: 0x08, useExtended: false, BaseMemoryPool.Shared);
        (StatusWord unsupported, _) = await TransmitAsync(device, readRecord).ConfigureAwait(false);
        Assert.AreEqual(0x6D00, unsupported.Value, "An unmodelled instruction returns 6D00.");

        //A command shorter than a header is framed directly without disturbing the selected-file state.
        ApduResult<ApduResponse> malformedResult = await device.TransceiveAsync(
            new byte[] { 0x00, 0xA4 }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using ApduResponse malformed = malformedResult.Value;
        Assert.AreEqual(0x6700, malformed.StatusWord.Value, "A command shorter than a header returns 6700.");
    }


    [TestMethod]
    public async Task EmitsTraceEntriesForSelectAndRead()
    {
        using ElementaryFile efCom = EfCom.Write("0106", "040000", [0x61, 0x75], BaseMemoryPool.Shared);

        using var card = new CardSimulator("passport-trace", [efCom]);
        var observer = new TestObserver<TraceEntry<CardSimulatorState, CardSimulatorInput>>();
        using IDisposable subscription = card.Subscribe(observer);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        Assert.IsTrue((await SelectAsync(device, efCom.FileIdentifier).ConfigureAwait(false)).IsSuccess, "SELECT must succeed.");
        (StatusWord readStatus, _) = await ReadBinaryAsync(device, offset: 0, length: efCom.Length).ConfigureAwait(false);
        Assert.IsTrue(readStatus.IsSuccess, "READ BINARY must succeed.");

        IReadOnlyList<TraceEntry<CardSimulatorState, CardSimulatorInput>> entries = observer.Received;
        Assert.HasCount(2, entries, "One trace entry per processed command.");

        Assert.IsInstanceOfType<SelectElementaryFileRequested>(entries[0].Input, "The first input is a SELECT.");
        Assert.AreEqual(TraceOutcome.Transitioned, entries[0].Outcome, "The SELECT transitioned.");
        Assert.IsNull(entries[0].StateBefore.SelectedFile, "No file is selected before the SELECT.");
        Assert.AreEqual((ushort?)efCom.FileIdentifier, entries[0].StateAfter.SelectedFile, "The SELECT makes EF.COM the current file.");
        Assert.AreEqual("passport-trace", entries[0].RunId, "The trace carries the card identifier.");

        Assert.IsInstanceOfType<ReadBinaryRequested>(entries[1].Input, "The second input is a READ BINARY.");
        Assert.IsInstanceOfType<BinaryReadResponse>(entries[1].StateAfter.ResponseIntent, "The READ BINARY produced a data response.");
    }


    /// <summary>
    /// Selects a file, reads it whole in <paramref name="chunkSize"/>-octet steps, and asserts the bytes
    /// match the minted file.
    /// </summary>
    private async Task AssertReadsBackAsync(ApduDevice device, ElementaryFile file, int chunkSize)
    {
        StatusWord selectStatus = await SelectAsync(device, file.FileIdentifier).ConfigureAwait(false);
        Assert.IsTrue(selectStatus.IsSuccess, $"SELECT of 0x{file.FileIdentifier:X4} must succeed.");

        byte[] read = new byte[file.Length];
        int offset = 0;
        while(offset < file.Length)
        {
            int request = Math.Min(chunkSize, file.Length - offset);
            (StatusWord status, byte[] data) = await ReadBinaryAsync(device, offset, request).ConfigureAwait(false);
            Assert.IsTrue(status.IsSuccess, $"READ BINARY at offset {offset} must succeed.");
            Assert.IsNotEmpty(data, $"READ BINARY at offset {offset} must return data.");
            data.CopyTo(read, offset);
            offset += data.Length;
        }

        Assert.AreEqual(Convert.ToHexString(file.Content), Convert.ToHexString(read),
            $"File 0x{file.FileIdentifier:X4} must read back byte-for-byte.");
    }


    /// <summary>
    /// Sends a SELECT of an elementary file by its identifier (P1=02, P2=0C) and returns the status word.
    /// </summary>
    private Task<StatusWord> SelectAsync(ApduDevice device, ushort fileIdentifier) =>
        SelectWithParametersAsync(device, 0x02, 0x0C, [(byte)(fileIdentifier >> 8), (byte)fileIdentifier]);


    /// <summary>
    /// Sends a SELECT with explicit parameters and data, and returns the status word.
    /// </summary>
    private async Task<StatusWord> SelectWithParametersAsync(ApduDevice device, byte p1, byte p2, byte[] data)
    {
        using CommandApdu command = CommandApdu.BuildCase3(0x00, InstructionCode.Select.Code, p1, p2, data, BaseMemoryPool.Shared);
        (StatusWord status, _) = await TransmitAsync(device, command).ConfigureAwait(false);

        return status;
    }


    /// <summary>
    /// Sends a READ BINARY with a 15-bit offset in P1-P2 and returns the status word and response data.
    /// </summary>
    private async Task<(StatusWord Status, byte[] Data)> ReadBinaryAsync(ApduDevice device, int offset, int length)
    {
        byte p1 = (byte)((offset >> 8) & 0x7F);
        byte p2 = (byte)(offset & 0xFF);
        byte expectedLength = (byte)(length >= 256 ? 0 : length);

        using CommandApdu command = CommandApdu.BuildCase2(
            0x00, InstructionCode.ReadBinary.Code, p1, p2, expectedLength, useExtended: false, BaseMemoryPool.Shared);

        return await TransmitAsync(device, command).ConfigureAwait(false);
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
}
