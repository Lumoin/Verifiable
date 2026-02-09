using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Verifiable.Tpm.EventLog;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Tests for <see cref="TcgEventLogParser"/>.
/// </summary>
[TestClass]
internal class TcgEventLogParserTests
{
    [TestMethod]
    public void ParseReturnsErrorForEmptyData()
    {
        var result = TcgEventLogParser.Parse(ReadOnlySpan<byte>.Empty);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual((uint)TcgEventLogError.LogTooSmall, result.TransportErrorCode);
    }

    [TestMethod]
    public void ParseReturnsErrorForDataTooSmall()
    {
        byte[] tooSmall = new byte[16];

        var result = TcgEventLogParser.Parse(tooSmall);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual((uint)TcgEventLogError.LogTooSmall, result.TransportErrorCode);
    }

    [TestMethod]
    public void ParseLegacyEventSucceeds()
    {
        byte[] legacyLog = BuildLegacyEvent(
            pcrIndex: 0,
            eventType: TcgEventType.EV_POST_CODE,
            digest: new byte[20],
            eventData: Encoding.ASCII.GetBytes("POST CODE"));

        var result = TcgEventLogParser.Parse(legacyLog);

        Assert.IsTrue(result.IsSuccess);
        Assert.IsNotNull(result.Value);
        Assert.HasCount(1, result.Value.Events);

        var evt = result.Value.Events[0];
        Assert.AreEqual(0, evt.PcrIndex);
        Assert.AreEqual(TcgEventType.EV_POST_CODE, evt.EventType);
        Assert.AreEqual("EV_POST_CODE", evt.EventTypeName);
        Assert.HasCount(1, evt.Digests);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA1, evt.Digests[0].Algorithm);
    }

    [TestMethod]
    public void ParseCryptoAgileLogSucceeds()
    {
        byte[] cryptoAgileLog = BuildCryptoAgileLog();

        var result = TcgEventLogParser.Parse(cryptoAgileLog);

        Assert.IsTrue(result.IsSuccess);
        Assert.IsNotNull(result.Value);
        Assert.AreEqual("Spec ID Event03", result.Value.SpecVersion);
        Assert.IsTrue(result.Value.DigestSizes.ContainsKey(TpmAlgIdConstants.TPM_ALG_SHA256));
    }

    [TestMethod]
    public void ParseSeparatorEventSuccessValue()
    {
        byte[] separatorData = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(separatorData, 0x00000000);

        byte[] log = BuildLegacyEvent(
            pcrIndex: 7,
            eventType: TcgEventType.EV_SEPARATOR,
            digest: new byte[20],
            eventData: separatorData);

        var result = TcgEventLogParser.Parse(log);

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual("Separator (Success)", result.Value!.Events[0].EventDataDescription);
    }

    [TestMethod]
    public void ParseSeparatorEventErrorValue()
    {
        byte[] separatorData = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(separatorData, 0xFFFFFFFF);

        byte[] log = BuildLegacyEvent(
            pcrIndex: 7,
            eventType: TcgEventType.EV_SEPARATOR,
            digest: new byte[20],
            eventData: separatorData);

        var result = TcgEventLogParser.Parse(log);

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual("Separator (Error)", result.Value!.Events[0].EventDataDescription);
    }

    [TestMethod]
    public void ParseMultipleLegacyEventsSucceeds()
    {
        var events = new List<byte[]>
        {
            BuildLegacyEvent(0, TcgEventType.EV_S_CRTM_VERSION, new byte[20], Encoding.ASCII.GetBytes("1.0")),
            BuildLegacyEvent(0, TcgEventType.EV_POST_CODE, new byte[20], Encoding.ASCII.GetBytes("BIOS")),
            BuildLegacyEvent(7, TcgEventType.EV_SEPARATOR, new byte[20], new byte[4])
        };

        byte[] log = CombineEvents(events);

        var result = TcgEventLogParser.Parse(log);

        Assert.IsTrue(result.IsSuccess);
        Assert.HasCount(3, result.Value!.Events);
        Assert.AreEqual(0, result.Value.Events[0].PcrIndex);
        Assert.AreEqual(0, result.Value.Events[1].PcrIndex);
        Assert.AreEqual(7, result.Value.Events[2].PcrIndex);
    }

    [TestMethod]
    public void ParseTruncatedLogSetsTruncatedFlag()
    {
        byte[] validEvent = BuildLegacyEvent(0, TcgEventType.EV_POST_CODE, new byte[20], Encoding.ASCII.GetBytes("OK"));

        //Add partial second event (truncated).
        byte[] truncated = new byte[validEvent.Length + 10];
        validEvent.CopyTo(truncated, 0);

        var result = TcgEventLogParser.Parse(truncated);

        Assert.IsTrue(result.IsSuccess);
        Assert.IsTrue(result.Value!.IsTruncated);
        Assert.HasCount(1, result.Value.Events);
    }

    [TestMethod]
    public void EventIndexIsSequential()
    {
        var events = new List<byte[]>
        {
            BuildLegacyEvent(0, TcgEventType.EV_POST_CODE, new byte[20], []),
            BuildLegacyEvent(1, TcgEventType.EV_POST_CODE, new byte[20], []),
            BuildLegacyEvent(2, TcgEventType.EV_POST_CODE, new byte[20], [])
        };

        byte[] log = CombineEvents(events);
        var result = TcgEventLogParser.Parse(log);

        Assert.IsTrue(result.IsSuccess);
        for(int i = 0; i < result.Value!.Events.Count; i++)
        {
            Assert.AreEqual(i, result.Value.Events[i].Index);
        }
    }

    [TestMethod]
    public void GetEventsForPcrFiltersCorrectly()
    {
        var events = new List<byte[]>
        {
            BuildLegacyEvent(0, TcgEventType.EV_POST_CODE, new byte[20], []),
            BuildLegacyEvent(7, TcgEventType.EV_SEPARATOR, new byte[20], new byte[4]),
            BuildLegacyEvent(0, TcgEventType.EV_POST_CODE, new byte[20], []),
            BuildLegacyEvent(4, TcgEventType.EV_POST_CODE, new byte[20], [])
        };

        byte[] log = CombineEvents(events);
        var result = TcgEventLogParser.Parse(log);

        Assert.IsTrue(result.IsSuccess);

        var pcr0Events = new List<TcgEvent>(result.Value!.GetEventsForPcr(0));
        Assert.HasCount(2, pcr0Events);

        var pcr7Events = new List<TcgEvent>(result.Value.GetEventsForPcr(7));
        Assert.HasCount(1, pcr7Events);

        var pcr4Events = new List<TcgEvent>(result.Value.GetEventsForPcr(4));
        Assert.HasCount(1, pcr4Events);
    }

    [TestMethod]
    public void GetEventsByTypeFiltersCorrectly()
    {
        var events = new List<byte[]>
        {
            BuildLegacyEvent(0, TcgEventType.EV_POST_CODE, new byte[20], []),
            BuildLegacyEvent(7, TcgEventType.EV_SEPARATOR, new byte[20], new byte[4]),
            BuildLegacyEvent(0, TcgEventType.EV_POST_CODE, new byte[20], [])
        };

        byte[] log = CombineEvents(events);
        var result = TcgEventLogParser.Parse(log);

        Assert.IsTrue(result.IsSuccess);

        var postCodeEvents = new List<TcgEvent>(result.Value!.GetEventsByType(TcgEventType.EV_POST_CODE));
        Assert.HasCount(2, postCodeEvents);

        var separatorEvents = new List<TcgEvent>(result.Value.GetEventsByType(TcgEventType.EV_SEPARATOR));
        Assert.HasCount(1, separatorEvents);
    }

    private static byte[] BuildLegacyEvent(uint pcrIndex, uint eventType, byte[] digest, byte[] eventData)
    {
        //TCG_PCClientPCREvent: PCRIndex(4) + EventType(4) + Digest(20) + EventSize(4) + Event(variable).
        byte[] result = new byte[4 + 4 + 20 + 4 + eventData.Length];
        int offset = 0;

        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(offset, 4), pcrIndex);
        offset += 4;

        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(offset, 4), eventType);
        offset += 4;

        digest.AsSpan(0, Math.Min(20, digest.Length)).CopyTo(result.AsSpan(offset, 20));
        offset += 20;

        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(offset, 4), (uint)eventData.Length);
        offset += 4;

        eventData.CopyTo(result.AsSpan(offset));

        return result;
    }

    private static byte[] BuildCryptoAgileLog()
    {
        //Build spec ID event (first event is always legacy format).
        byte[] specIdEventData = BuildSpecIdEventData();
        byte[] firstEvent = BuildLegacyEvent(0, TcgEventType.EV_NO_ACTION, new byte[20], specIdEventData);

        //Build crypto-agile event.
        byte[] cryptoAgileEvent = BuildCryptoAgileEvent(0, TcgEventType.EV_POST_CODE, [], TpmAlgIdConstants.TPM_ALG_SHA256, 32);

        return CombineEvents([firstEvent, cryptoAgileEvent]);
    }

    private static byte[] BuildSpecIdEventData()
    {
        //TCG_EfiSpecIdEvent: Signature(16) + PlatformClass(4) + SpecVersionMinor(1) +
        //SpecVersionMajor(1) + SpecErrata(1) + UintnSize(1) + NumberOfAlgorithms(4) +
        //DigestSizes(variable) + VendorInfoSize(1).
        var data = new List<byte>();

        //Signature: "Spec ID Event03\0".
        byte[] signature = new byte[16];
        Encoding.ASCII.GetBytes("Spec ID Event03").CopyTo(signature, 0);
        data.AddRange(signature);

        //PlatformClass (0 = client).
        data.AddRange(BitConverter.GetBytes((uint)0));

        //Spec version: 2.0.2.
        data.Add(0); //Minor.
        data.Add(2); //Major.
        data.Add(2); //Errata.

        //UintnSize (4 = 32-bit).
        data.Add(4);

        //NumberOfAlgorithms.
        data.AddRange(BitConverter.GetBytes((uint)2));

        //Algorithm 1: SHA1.
        data.AddRange(BitConverter.GetBytes((ushort)TpmAlgIdConstants.TPM_ALG_SHA1));
        data.AddRange(BitConverter.GetBytes((ushort)20));

        //Algorithm 2: SHA256.
        data.AddRange(BitConverter.GetBytes((ushort)TpmAlgIdConstants.TPM_ALG_SHA256));
        data.AddRange(BitConverter.GetBytes((ushort)32));

        //VendorInfoSize.
        data.Add(0);

        return [.. data];
    }

    private static byte[] BuildCryptoAgileEvent(uint pcrIndex, uint eventType, byte[] eventData, TpmAlgIdConstants algorithm, int digestSize)
    {
        //TCG_PCR_EVENT2: PCRIndex(4) + EventType(4) + DigestCount(4) +
        //[AlgId(2) + Digest(variable)]* + EventSize(4) + Event(variable).
        var data = new List<byte>();

        data.AddRange(BitConverter.GetBytes(pcrIndex));
        data.AddRange(BitConverter.GetBytes(eventType));

        //Digest count.
        data.AddRange(BitConverter.GetBytes((uint)1));

        //Digest.
        data.AddRange(BitConverter.GetBytes((ushort)algorithm));
        data.AddRange(new byte[digestSize]);

        //Event data.
        data.AddRange(BitConverter.GetBytes((uint)eventData.Length));
        data.AddRange(eventData);

        return [.. data];
    }

    private static byte[] CombineEvents(IEnumerable<byte[]> events)
    {
        var combined = new List<byte>();
        foreach(var evt in events)
        {
            combined.AddRange(evt);
        }

        return [.. combined];
    }
}