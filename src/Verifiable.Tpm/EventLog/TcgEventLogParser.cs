using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.EventLog;

/// <summary>
/// Parses TCG event logs in both legacy (SHA1) and crypto-agile (TPM 2.0) formats.
/// </summary>
/// <remarks>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/">
/// TCG PC Client Platform Firmware Profile Specification</see>
/// (Section 10 "Event Logging").
/// </para>
/// <para>
/// The parser handles two formats:
/// </para>
/// <list type="bullet">
///   <item>
///     <term>Legacy format</term>
///     <description>
///     <c>TCG_PCClientPCREvent</c> with fixed 20-byte SHA1 digest (Section 10.2.1).
///     </description>
///   </item>
///   <item>
///     <term>Crypto-agile format</term>
///     <description>
///     <c>TCG_PCR_EVENT2</c> with multiple digests per event (Section 10.2.2).
///     Identified by "Spec ID Event03" signature in the first event.
///     </description>
///   </item>
/// </list>
/// </remarks>
public static class TcgEventLogParser
{
    /// <summary>
    /// SHA1 digest size in bytes.
    /// </summary>
    private const int Sha1DigestSize = 20;

    /// <summary>
    /// Signature identifying crypto-agile log format (TCG PFP Section 10.2.1.1).
    /// </summary>
    private const string SpecIdEvent03Signature = "Spec ID Event03";

    /// <summary>
    /// Minimum size for a valid event log (one legacy event header).
    /// TCG_PCClientPCREvent: PCRIndex(4) + EventType(4) + Digest(20) + EventSize(4) = 32 bytes.
    /// </summary>
    private const int MinimumLogSize = 32;

    /// <summary>
    /// Minimum size for TCG_EfiSpecIdEvent structure.
    /// Signature(16) + PlatformClass(4) + SpecVersion(3) + UintnSize(1) + NumberOfAlgorithms(4) = 28 bytes.
    /// </summary>
    private const int MinimumSpecIdEventSize = 28;

    /// <summary>
    /// Maximum allowed event data size (1 MB sanity limit).
    /// </summary>
    private const int MaxEventDataSize = 0x100000;

    /// <summary>
    /// Maximum number of digest algorithms in a single event (sanity limit).
    /// </summary>
    private const int MaxDigestCount = 16;

    /// <summary>
    /// Size of the signature field in TCG_EfiSpecIdEvent.
    /// </summary>
    private const int SpecIdSignatureSize = 16;

    /// <summary>
    /// EFI device path type for file path nodes.
    /// </summary>
    private const byte DevicePathTypeMediaDevice = 4;

    /// <summary>
    /// EFI device path subtype for file path nodes.
    /// </summary>
    private const byte DevicePathSubtypeFilePath = 4;

    /// <summary>
    /// EFI device path end type.
    /// </summary>
    private const byte DevicePathTypeEnd = 0x7F;

    /// <summary>
    /// EFI device path end subtype (entire path).
    /// </summary>
    private const byte DevicePathSubtypeEndEntire = 0xFF;

    /// <summary>
    /// Separator value indicating successful pre-OS to OS-present transition.
    /// </summary>
    private const uint SeparatorSuccess = 0x00000000;

    /// <summary>
    /// Separator value indicating error during pre-OS phase.
    /// </summary>
    private const uint SeparatorError = 0xFFFFFFFF;

    /// <summary>
    /// Parses a binary TCG event log.
    /// </summary>
    /// <param name="logData">The raw event log bytes.</param>
    /// <returns>The parsed event log, or an error.</returns>
    public static TpmResult<TcgEventLog> Parse(ReadOnlySpan<byte> logData)
    {
        if(logData.Length < MinimumLogSize)
        {
            return TpmResult<TcgEventLog>.TransportError((uint)TcgEventLogError.LogTooSmall);
        }

        try
        {
            return ParseInternal(logData);
        }
        catch
        {
            return TpmResult<TcgEventLog>.TransportError((uint)TcgEventLogError.ParseException);
        }
    }

    private static TpmResult<TcgEventLog> ParseInternal(ReadOnlySpan<byte> data)
    {
        int offset = 0;

        //First event is always TCG_PCR_EVENT (legacy format) containing spec ID.
        var firstEventResult = ParseLegacyEvent(data, ref offset);
        if(!firstEventResult.IsSuccess)
        {
            return TpmResult<TcgEventLog>.TransportError((uint)TcgEventLogError.InvalidFirstEvent);
        }

        var firstEvent = firstEventResult.Value!;

        //Check if this is a crypto-agile log.
        bool isCryptoAgile = false;
        string specVersion = "Legacy";
        uint platformClass = 0;
        (byte Major, byte Minor, byte Errata) specVersionNumber = (1, 0, 0);
        byte uintnSize = 4;
        Dictionary<TpmAlgIdConstants, ushort> digestSizes = new();

        if(firstEvent.EventType == TcgEventType.EV_NO_ACTION && firstEvent.EventData.Length > SpecIdSignatureSize)
        {
            var specIdResult = ParseSpecIdEvent(firstEvent.EventData);
            if(specIdResult.IsSuccess)
            {
                var specId = specIdResult.Value!;
                isCryptoAgile = specId.IsCryptoAgile;
                specVersion = specId.Signature;
                platformClass = specId.PlatformClass;
                specVersionNumber = (specId.SpecVersionMajor, specId.SpecVersionMinor, specId.SpecErrata);
                uintnSize = specId.UintnSize;
                digestSizes = new Dictionary<TpmAlgIdConstants, ushort>(specId.DigestSizes);
            }
        }

        var events = new List<TcgEvent>();
        int eventIndex = 0;

        //Add first event.
        events.Add(CreateTcgEvent(eventIndex++, firstEvent));

        //Parse remaining events.
        bool truncated = false;
        while(offset < data.Length)
        {
            if(isCryptoAgile)
            {
                var eventResult = ParseCryptoAgileEvent(data, ref offset, digestSizes);
                if(!eventResult.IsSuccess)
                {
                    truncated = true;
                    break;
                }

                events.Add(CreateTcgEvent(eventIndex++, eventResult.Value!));
            }
            else
            {
                var eventResult = ParseLegacyEvent(data, ref offset);
                if(!eventResult.IsSuccess)
                {
                    truncated = true;
                    break;
                }

                events.Add(CreateTcgEvent(eventIndex++, eventResult.Value!));
            }
        }

        var log = new TcgEventLog(
            specVersion,
            platformClass,
            specVersionNumber,
            uintnSize,
            digestSizes,
            events,
            truncated);

        return TpmResult<TcgEventLog>.Success(log);
    }

    private static TpmResult<LegacyEvent> ParseLegacyEvent(ReadOnlySpan<byte> data, ref int offset)
    {
        //TCG_PCClientPCREvent: PCRIndex(4) + EventType(4) + Digest(20) + EventSize(4) = 32 bytes minimum.
        if(offset + MinimumLogSize > data.Length)
        {
            return TpmResult<LegacyEvent>.TransportError((uint)TcgEventLogError.UnexpectedEndOfData);
        }

        uint pcrIndex = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, sizeof(uint)));
        offset += sizeof(uint);

        uint eventType = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, sizeof(uint)));
        offset += sizeof(uint);

        byte[] digest = data.Slice(offset, Sha1DigestSize).ToArray();
        offset += Sha1DigestSize;

        uint eventSize = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, sizeof(uint)));
        offset += sizeof(uint);

        if(eventSize > MaxEventDataSize || offset + (int)eventSize > data.Length)
        {
            return TpmResult<LegacyEvent>.TransportError((uint)TcgEventLogError.EventDataTooLarge);
        }

        byte[] eventData = data.Slice(offset, (int)eventSize).ToArray();
        offset += (int)eventSize;

        return TpmResult<LegacyEvent>.Success(new LegacyEvent(pcrIndex, eventType, digest, eventData));
    }

    private static TpmResult<CryptoAgileEvent> ParseCryptoAgileEvent(
        ReadOnlySpan<byte> data,
        ref int offset,
        IReadOnlyDictionary<TpmAlgIdConstants, ushort> digestSizes)
    {
        //TCG_PCR_EVENT2: PCRIndex(4) + EventType(4) = 8 bytes minimum header.
        const int headerSize = sizeof(uint) + sizeof(uint);
        if(offset + headerSize > data.Length)
        {
            return TpmResult<CryptoAgileEvent>.TransportError((uint)TcgEventLogError.UnexpectedEndOfData);
        }

        uint pcrIndex = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, sizeof(uint)));
        offset += sizeof(uint);

        uint eventType = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, sizeof(uint)));
        offset += sizeof(uint);

        //TPML_DIGEST_VALUES: Count(4) + variable digests.
        if(offset + sizeof(uint) > data.Length)
        {
            return TpmResult<CryptoAgileEvent>.TransportError((uint)TcgEventLogError.UnexpectedEndOfData);
        }

        uint digestCount = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, sizeof(uint)));
        offset += sizeof(uint);

        if(digestCount > MaxDigestCount)
        {
            return TpmResult<CryptoAgileEvent>.TransportError((uint)TcgEventLogError.TooManyDigests);
        }

        var digests = new List<(TpmAlgIdConstants Algorithm, byte[] Digest)>();

        for(int i = 0; i < digestCount; i++)
        {
            //TPMT_HA: HashAlg(2) + Digest(variable).
            if(offset + sizeof(ushort) > data.Length)
            {
                return TpmResult<CryptoAgileEvent>.TransportError((uint)TcgEventLogError.UnexpectedEndOfData);
            }

            ushort algId = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset, sizeof(ushort)));
            offset += sizeof(ushort);

            var algorithm = (TpmAlgIdConstants)algId;
            int digestSize;

            if(digestSizes.TryGetValue(algorithm, out ushort specifiedSize))
            {
                digestSize = specifiedSize;
            }
            else
            {
                int? knownSize = algorithm.GetDigestSize();
                if(knownSize is null)
                {
                    return TpmResult<CryptoAgileEvent>.TransportError((uint)TcgEventLogError.UnknownAlgorithm);
                }

                digestSize = knownSize.Value;
            }

            if(offset + digestSize > data.Length)
            {
                return TpmResult<CryptoAgileEvent>.TransportError((uint)TcgEventLogError.UnexpectedEndOfData);
            }

            byte[] digest = data.Slice(offset, digestSize).ToArray();
            offset += digestSize;

            digests.Add((algorithm, digest));
        }

        //EventSize(4) + Event(variable).
        if(offset + sizeof(uint) > data.Length)
        {
            return TpmResult<CryptoAgileEvent>.TransportError((uint)TcgEventLogError.UnexpectedEndOfData);
        }

        uint eventSize = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, sizeof(uint)));
        offset += sizeof(uint);

        if(eventSize > MaxEventDataSize || offset + (int)eventSize > data.Length)
        {
            return TpmResult<CryptoAgileEvent>.TransportError((uint)TcgEventLogError.EventDataTooLarge);
        }

        byte[] eventData = data.Slice(offset, (int)eventSize).ToArray();
        offset += (int)eventSize;

        return TpmResult<CryptoAgileEvent>.Success(
            new CryptoAgileEvent(pcrIndex, eventType, digests, eventData));
    }

    private static TpmResult<SpecIdEvent> ParseSpecIdEvent(byte[] eventData)
    {
        if(eventData.Length < MinimumSpecIdEventSize)
        {
            return TpmResult<SpecIdEvent>.TransportError((uint)TcgEventLogError.InvalidSpecIdEvent);
        }

        int offset = 0;

        string signature = Encoding.ASCII.GetString(eventData, offset, SpecIdSignatureSize).TrimEnd('\0');
        offset += SpecIdSignatureSize;

        bool isCryptoAgile = signature == SpecIdEvent03Signature;

        uint platformClass = BinaryPrimitives.ReadUInt32LittleEndian(eventData.AsSpan(offset, sizeof(uint)));
        offset += sizeof(uint);

        byte specVersionMinor = eventData[offset++];
        byte specVersionMajor = eventData[offset++];
        byte specErrata = eventData[offset++];
        byte uintnSize = eventData[offset++];

        var digestSizes = new Dictionary<TpmAlgIdConstants, ushort>();

        if(isCryptoAgile && offset + sizeof(uint) <= eventData.Length)
        {
            uint numberOfAlgorithms = BinaryPrimitives.ReadUInt32LittleEndian(eventData.AsSpan(offset, sizeof(uint)));
            offset += sizeof(uint);

            //Each algorithm entry is AlgId(2) + DigestSize(2) = 4 bytes.
            const int algorithmEntrySize = sizeof(ushort) + sizeof(ushort);
            for(int i = 0; i < numberOfAlgorithms && offset + algorithmEntrySize <= eventData.Length; i++)
            {
                ushort algId = BinaryPrimitives.ReadUInt16LittleEndian(eventData.AsSpan(offset, sizeof(ushort)));
                offset += sizeof(ushort);

                ushort digestSize = BinaryPrimitives.ReadUInt16LittleEndian(eventData.AsSpan(offset, sizeof(ushort)));
                offset += sizeof(ushort);

                digestSizes[(TpmAlgIdConstants)algId] = digestSize;
            }
        }

        return TpmResult<SpecIdEvent>.Success(new SpecIdEvent(
            signature,
            platformClass,
            specVersionMajor,
            specVersionMinor,
            specErrata,
            uintnSize,
            isCryptoAgile,
            digestSizes));
    }

    private static TcgEvent CreateTcgEvent(int index, LegacyEvent legacy)
    {
        var digests = new List<TcgEventDigest>
        {
            new(TpmAlgIdConstants.TPM_ALG_SHA1, legacy.Digest)
        };

        string? description = TryParseEventData(legacy.EventType, legacy.EventData);

        return new TcgEvent(
            index,
            (int)legacy.PcrIndex,
            legacy.EventType,
            digests,
            legacy.EventData,
            description);
    }

    private static TcgEvent CreateTcgEvent(int index, CryptoAgileEvent agile)
    {
        var digests = new List<TcgEventDigest>();

        foreach(var (algorithm, digest) in agile.Digests)
        {
            digests.Add(new TcgEventDigest(algorithm, digest));
        }

        string? description = TryParseEventData(agile.EventType, agile.EventData);

        return new TcgEvent(
            index,
            (int)agile.PcrIndex,
            agile.EventType,
            digests,
            agile.EventData,
            description);
    }

    private static string? TryParseEventData(uint eventType, byte[] eventData)
    {
        try
        {
            return eventType switch
            {
                TcgEventType.EV_NO_ACTION => TryParseNoAction(eventData),
                TcgEventType.EV_SEPARATOR => ParseSeparator(eventData),
                TcgEventType.EV_ACTION or TcgEventType.EV_EFI_ACTION => ParseAsciiString(eventData),
                TcgEventType.EV_POST_CODE => ParseAsciiString(eventData),
                TcgEventType.EV_S_CRTM_VERSION => ParseAsciiOrUnicodeString(eventData),
                TcgEventType.EV_EFI_VARIABLE_DRIVER_CONFIG or
                TcgEventType.EV_EFI_VARIABLE_BOOT or
                TcgEventType.EV_EFI_VARIABLE_BOOT2 or
                TcgEventType.EV_EFI_VARIABLE_AUTHORITY => TryParseEfiVariable(eventData),
                TcgEventType.EV_EFI_BOOT_SERVICES_APPLICATION or
                TcgEventType.EV_EFI_BOOT_SERVICES_DRIVER or
                TcgEventType.EV_EFI_RUNTIME_SERVICES_DRIVER => TryParseImageLoadEvent(eventData),
                _ => null
            };
        }
        catch
        {
            return null;
        }
    }

    private static string? TryParseNoAction(byte[] eventData)
    {
        if(eventData.Length >= SpecIdSignatureSize)
        {
            string sig = Encoding.ASCII.GetString(eventData, 0, SpecIdSignatureSize).TrimEnd('\0');
            if(sig.StartsWith("Spec ID Event"))
            {
                return sig;
            }

            //StartupLocality event: signature(16) + locality(1).
            const int startupLocalitySize = 17;
            if(sig == "StartupLocality" && eventData.Length >= startupLocalitySize)
            {
                return $"StartupLocality: {eventData[SpecIdSignatureSize]}";
            }
        }

        return null;
    }

    private static string ParseSeparator(byte[] eventData)
    {
        if(eventData.Length == sizeof(uint))
        {
            uint value = BinaryPrimitives.ReadUInt32LittleEndian(eventData);
            return value switch
            {
                SeparatorSuccess => "Separator (Success)",
                SeparatorError => "Separator (Error)",
                _ => $"Separator (0x{value:X8})"
            };
        }

        return "Separator";
    }

    private static string? ParseAsciiString(byte[] eventData)
    {
        if(eventData.Length == 0)
        {
            return null;
        }

        foreach(byte b in eventData)
        {
            //Allow printable ASCII (0x20-0x7E) and null terminator.
            if(b != 0 && (b < 0x20 || b > 0x7E))
            {
                return null;
            }
        }

        return Encoding.ASCII.GetString(eventData).TrimEnd('\0');
    }

    private static string? ParseAsciiOrUnicodeString(byte[] eventData)
    {
        if(eventData.Length == 0)
        {
            return null;
        }

        //Try UTF-16LE first (common for UEFI strings).
        if(eventData.Length >= 2 && eventData.Length % 2 == 0)
        {
            bool looksLikeUtf16 = true;
            for(int i = 1; i < eventData.Length && looksLikeUtf16; i += 2)
            {
                //High byte should be 0 for ASCII characters in UTF-16LE.
                if(eventData[i] != 0 && eventData[i - 1] < 0x20)
                {
                    looksLikeUtf16 = false;
                }
            }

            if(looksLikeUtf16)
            {
                try
                {
                    return Encoding.Unicode.GetString(eventData).TrimEnd('\0');
                }
                catch
                {
                    //Fall through to ASCII.
                }
            }
        }

        return ParseAsciiString(eventData);
    }

    private static string? TryParseEfiVariable(byte[] eventData)
    {
        //EFI_VARIABLE_DATA: GUID(16) + UnicodeNameLength(8) + VariableDataLength(8) + UnicodeName(variable).
        const int efiVariableHeaderSize = 32;
        if(eventData.Length < efiVariableHeaderSize)
        {
            return null;
        }

        //Skip GUID (16 bytes), read name length at offset 16.
        const int nameLengthOffset = 16;
        ulong nameLength = BinaryPrimitives.ReadUInt64LittleEndian(eventData.AsSpan(nameLengthOffset, sizeof(ulong)));

        //Name starts at offset 32, each character is 2 bytes (UTF-16LE).
        const int nameOffset = 32;
        const int maxNameLength = 1000;
        if(nameLength > 0 && nameLength < maxNameLength && nameOffset + (int)nameLength * 2 <= eventData.Length)
        {
            string name = Encoding.Unicode.GetString(eventData, nameOffset, (int)nameLength * 2).TrimEnd('\0');
            return $"Variable: {name}";
        }

        return null;
    }

    private static string? TryParseImageLoadEvent(byte[] eventData)
    {
        //UEFI_IMAGE_LOAD_EVENT: ImageLocationInMemory(8) + ImageLengthInMemory(8) +
        //ImageLinkTimeAddress(8) + LengthOfDevicePath(8) + DevicePath(variable).
        const int imageLoadHeaderSize = 32;
        if(eventData.Length < imageLoadHeaderSize)
        {
            return null;
        }

        const int devicePathLengthOffset = 24;
        ulong devicePathLength = BinaryPrimitives.ReadUInt64LittleEndian(eventData.AsSpan(devicePathLengthOffset, sizeof(ulong)));

        const int devicePathOffset = 32;
        if(devicePathLength > 0 && devicePathOffset + (int)devicePathLength <= eventData.Length)
        {
            byte[] pathData = eventData.AsSpan(devicePathOffset, (int)devicePathLength).ToArray();
            string? path = TryExtractDevicePathString(pathData);
            if(path is not null)
            {
                return $"Image: {path}";
            }
        }

        return null;
    }

    private static string? TryExtractDevicePathString(byte[] pathData)
    {
        //EFI device path node: Type(1) + SubType(1) + Length(2) + Data(variable).
        const int nodeHeaderSize = 4;
        int offset = 0;

        while(offset + nodeHeaderSize <= pathData.Length)
        {
            byte type = pathData[offset];
            byte subtype = pathData[offset + 1];
            ushort length = BinaryPrimitives.ReadUInt16LittleEndian(pathData.AsSpan(offset + 2, sizeof(ushort)));

            if(length < nodeHeaderSize || offset + length > pathData.Length)
            {
                break;
            }

            //File path node contains UTF-16LE path string.
            if(type == DevicePathTypeMediaDevice && subtype == DevicePathSubtypeFilePath && length > nodeHeaderSize)
            {
                try
                {
                    string path = Encoding.Unicode.GetString(pathData, offset + nodeHeaderSize, length - nodeHeaderSize).TrimEnd('\0');
                    if(!string.IsNullOrWhiteSpace(path))
                    {
                        return path;
                    }
                }
                catch
                {
                    //Continue looking.
                }
            }

            //End of device path.
            if(type == DevicePathTypeEnd && subtype == DevicePathSubtypeEndEntire)
            {
                break;
            }

            offset += length;
        }

        return null;
    }

    private sealed record LegacyEvent(uint PcrIndex, uint EventType, byte[] Digest, byte[] EventData);

    private sealed record CryptoAgileEvent(
        uint PcrIndex,
        uint EventType,
        List<(TpmAlgIdConstants Algorithm, byte[] Digest)> Digests,
        byte[] EventData);

    private sealed record SpecIdEvent(
        string Signature,
        uint PlatformClass,
        byte SpecVersionMajor,
        byte SpecVersionMinor,
        byte SpecErrata,
        byte UintnSize,
        bool IsCryptoAgile,
        Dictionary<TpmAlgIdConstants, ushort> DigestSizes);
}