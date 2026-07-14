using System.Formats.Cbor;
using Verifiable.Core.Model.Mdoc;
using Verifiable.JCose;

namespace Verifiable.Cbor.Mdoc;

/// <summary>
/// CBOR reader for the Mobile Security Object per ISO/IEC 18013-5 §9.1.2.4.
/// Produces the format-agnostic <see cref="MdocMobileSecurityObject"/>
/// view from the bytes that live as the payload of an <c>issuerAuth</c>
/// COSE_Sign1.
/// </summary>
/// <remarks>
/// <para>
/// The reader walks the MSO's text-keyed CBOR map, recognising the six
/// required fields per §9.1.2.4. Unknown keys are skipped per the spec's
/// forward-compatibility convention. Nested sub-readers handle
/// <c>valueDigests</c> (namespace → digestID → bytes), <c>deviceKeyInfo</c>
/// (delegates to <see cref="MdocCborCoseKeyReader"/> for the COSE_Key), and
/// <c>validityInfo</c> (tdate timestamps wrapped in CBOR Tag 0).
/// </para>
/// <para>
/// Per spec the MSO payload is itself wrapped in CBOR Tag 24 inside the
/// COSE_Sign1 — that wrapping is handled by the caller
/// (<see cref="MdocCborIssuerAuthReader"/>); this reader takes the inner
/// MSO map bytes directly.
/// </para>
/// </remarks>
public static class MdocCborMsoReader
{
    /// <summary>
    /// Reads an MSO from the supplied CBOR bytes.
    /// </summary>
    /// <param name="encodedMso">The CBOR-encoded MSO map bytes (the inner map, not the Tag 24 wrapper).</param>
    /// <returns>The parsed <see cref="MdocMobileSecurityObject"/>.</returns>
    /// <exception cref="CborContentException">
    /// Thrown when any required field is missing or carries an unexpected type.
    /// </exception>
    public static MdocMobileSecurityObject Read(ReadOnlySpan<byte> encodedMso)
    {
        var reader = new CborReader(encodedMso.ToArray(), CborConformanceMode.Lax);

        int? entryCount = reader.ReadStartMap();

        string? version = null;
        string? digestAlgorithm = null;
        IReadOnlyDictionary<string, IReadOnlyDictionary<uint, ReadOnlyMemory<byte>>>? valueDigests = null;
        MdocDeviceKeyInfo? deviceKeyInfo = null;
        string? docType = null;
        MdocValidityInfo? validityInfo = null;

        int entriesRead = 0;
        while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
        {
            string key = reader.ReadTextString();
            entriesRead++;

            _ = key switch
            {
                MdocMsoWellKnownKeys.Version => AssignVersion(reader, ref version),
                MdocMsoWellKnownKeys.DigestAlgorithm => AssignDigestAlgorithm(reader, ref digestAlgorithm),
                MdocMsoWellKnownKeys.ValueDigests => AssignValueDigests(reader, ref valueDigests),
                MdocMsoWellKnownKeys.DeviceKeyInfo => AssignDeviceKeyInfo(reader, ref deviceKeyInfo),
                MdocMsoWellKnownKeys.DocType => AssignDocType(reader, ref docType),
                MdocMsoWellKnownKeys.ValidityInfo => AssignValidityInfo(reader, ref validityInfo),
                _ => SkipValue(reader)
            };
        }

        reader.ReadEndMap();

        if(version is null || digestAlgorithm is null || valueDigests is null
            || deviceKeyInfo is null || docType is null || validityInfo is null)
        {
            throw new CborContentException(
                "MobileSecurityObject is missing one or more required fields per ISO/IEC 18013-5 §9.1.2.4: " +
                "version, digestAlgorithm, valueDigests, deviceKeyInfo, docType, validityInfo.");
        }

        return new MdocMobileSecurityObject(
            version: version,
            digestAlgorithm: digestAlgorithm,
            valueDigests: valueDigests,
            deviceKeyInfo: deviceKeyInfo,
            docType: docType,
            validityInfo: validityInfo);

        //Assigns the decoded MSO version string.
        static bool AssignVersion(CborReader reader, ref string? version)
        {
            version = reader.ReadTextString();

            return true;
        }

        //Assigns the decoded digest-algorithm identifier.
        static bool AssignDigestAlgorithm(CborReader reader, ref string? digestAlgorithm)
        {
            digestAlgorithm = reader.ReadTextString();

            return true;
        }

        //Assigns the decoded namespace -> digestID -> digest map.
        static bool AssignValueDigests(CborReader reader, ref IReadOnlyDictionary<string, IReadOnlyDictionary<uint, ReadOnlyMemory<byte>>>? valueDigests)
        {
            valueDigests = ReadValueDigests(reader);

            return true;
        }

        //Assigns the decoded DeviceKeyInfo.
        static bool AssignDeviceKeyInfo(CborReader reader, ref MdocDeviceKeyInfo? deviceKeyInfo)
        {
            deviceKeyInfo = ReadDeviceKeyInfo(reader);

            return true;
        }

        //Assigns the decoded docType string.
        static bool AssignDocType(CborReader reader, ref string? docType)
        {
            docType = reader.ReadTextString();

            return true;
        }

        //Assigns the decoded ValidityInfo.
        static bool AssignValidityInfo(CborReader reader, ref MdocValidityInfo? validityInfo)
        {
            validityInfo = ReadValidityInfo(reader);

            return true;
        }

        //Unknown keys: forward-compat skip per ISO 18013-5.
        static bool SkipValue(CborReader reader)
        {
            reader.SkipValue();

            return true;
        }
    }


    private static Dictionary<string, IReadOnlyDictionary<uint, ReadOnlyMemory<byte>>> ReadValueDigests(CborReader reader)
    {
        //valueDigests = { + NameSpace => DigestIDs }; DigestIDs = { + DigestID => Digest }
        int? namespaceCount = reader.ReadStartMap();
        Dictionary<string, IReadOnlyDictionary<uint, ReadOnlyMemory<byte>>> namespaces =
            new(StringComparer.Ordinal);

        int nsRead = 0;
        while(namespaceCount is null ? reader.PeekState() != CborReaderState.EndMap : nsRead < namespaceCount.Value)
        {
            string nameSpace = reader.ReadTextString();
            nsRead++;

            int? digestCount = reader.ReadStartMap();
            Dictionary<uint, ReadOnlyMemory<byte>> digests = digestCount is null
                ? []
                : new Dictionary<uint, ReadOnlyMemory<byte>>(digestCount.Value);

            int digestsRead = 0;
            while(digestCount is null ? reader.PeekState() != CborReaderState.EndMap : digestsRead < digestCount.Value)
            {
                uint digestId = (uint)reader.ReadUInt64();
                byte[] digest = reader.ReadByteString();
                digests[digestId] = digest;
                digestsRead++;
            }

            reader.ReadEndMap();
            namespaces[nameSpace] = digests;
        }

        reader.ReadEndMap();

        return namespaces;
    }


    private static MdocDeviceKeyInfo ReadDeviceKeyInfo(CborReader reader)
    {
        int? entryCount = reader.ReadStartMap();

        CoseKey? deviceKey = null;
        ReadOnlyMemory<byte>? encodedKeyAuthorizations = null;
        ReadOnlyMemory<byte>? encodedKeyInfo = null;

        int entriesRead = 0;
        while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
        {
            string key = reader.ReadTextString();
            entriesRead++;

            _ = key switch
            {
                MdocMsoWellKnownKeys.DeviceKey => AssignDeviceKey(reader, ref deviceKey),
                MdocMsoWellKnownKeys.KeyAuthorizations => AssignKeyAuthorizations(reader, ref encodedKeyAuthorizations),
                MdocMsoWellKnownKeys.KeyInfo => AssignKeyInfo(reader, ref encodedKeyInfo),
                _ => SkipValue(reader)
            };
        }

        reader.ReadEndMap();

        if(deviceKey is null)
        {
            throw new CborContentException(
                "DeviceKeyInfo is missing the mandatory deviceKey field per ISO/IEC 18013-5 §9.1.2.4.");
        }

        return new MdocDeviceKeyInfo(
            deviceKey: deviceKey,
            encodedKeyAuthorizations: encodedKeyAuthorizations,
            encodedKeyInfo: encodedKeyInfo);

        //Assigns the decoded COSE_Key device key.
        static bool AssignDeviceKey(CborReader reader, ref CoseKey? deviceKey)
        {
            deviceKey = MdocCborCoseKeyReader.ReadFromReader(reader);

            return true;
        }

        //Assigns the encoded keyAuthorizations value.
        static bool AssignKeyAuthorizations(CborReader reader, ref ReadOnlyMemory<byte>? encodedKeyAuthorizations)
        {
            encodedKeyAuthorizations = reader.ReadEncodedValue();

            return true;
        }

        //Assigns the encoded keyInfo value.
        static bool AssignKeyInfo(CborReader reader, ref ReadOnlyMemory<byte>? encodedKeyInfo)
        {
            encodedKeyInfo = reader.ReadEncodedValue();

            return true;
        }

        static bool SkipValue(CborReader reader)
        {
            reader.SkipValue();

            return true;
        }
    }


    private static MdocValidityInfo ReadValidityInfo(CborReader reader)
    {
        int? entryCount = reader.ReadStartMap();

        DateTimeOffset? signed = null;
        DateTimeOffset? validFrom = null;
        DateTimeOffset? validUntil = null;
        DateTimeOffset? expectedUpdate = null;

        int entriesRead = 0;
        while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
        {
            string key = reader.ReadTextString();
            entriesRead++;

            _ = key switch
            {
                MdocMsoWellKnownKeys.Signed => signed = ReadTdate(reader),
                MdocMsoWellKnownKeys.ValidFrom => validFrom = ReadTdate(reader),
                MdocMsoWellKnownKeys.ValidUntil => validUntil = ReadTdate(reader),
                MdocMsoWellKnownKeys.ExpectedUpdate => expectedUpdate = ReadTdate(reader),
                _ => SkipValue(reader)
            };
        }

        reader.ReadEndMap();

        if(signed is null || validFrom is null || validUntil is null)
        {
            throw new CborContentException(
                "ValidityInfo is missing one or more required fields per ISO/IEC 18013-5 §9.1.2.4: " +
                "signed, validFrom, validUntil.");
        }

        return new MdocValidityInfo(
            signed: signed.Value,
            validFrom: validFrom.Value,
            validUntil: validUntil.Value,
            expectedUpdate: expectedUpdate);

        static DateTimeOffset? SkipValue(CborReader reader)
        {
            reader.SkipValue();

            return null;
        }
    }


    /// <summary>
    /// Reads a CBOR tdate value (Tag 0 wrapping an RFC 3339 string) per
    /// RFC 8949 §3.4.1.
    /// </summary>
    private static DateTimeOffset ReadTdate(CborReader reader)
    {
        CborTag tag = reader.ReadTag();
        if(tag != CborTag.DateTimeString)
        {
            throw new CborContentException(
                $"Expected tdate (Tag 0) per ISO/IEC 18013-5 §9.1.2.4; got Tag {(int)tag}.");
        }

        string rfc3339 = reader.ReadTextString();

        return DateTimeOffset.Parse(rfc3339, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.RoundtripKind);
    }
}
