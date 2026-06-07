using System.Formats.Cbor;
using Verifiable.Core.Model.Mdoc;

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

            switch(key)
            {
                case MdocMsoWellKnownKeys.Version:
                {
                    version = reader.ReadTextString();

                    break;
                }
                case MdocMsoWellKnownKeys.DigestAlgorithm:
                {
                    digestAlgorithm = reader.ReadTextString();

                    break;
                }
                case MdocMsoWellKnownKeys.ValueDigests:
                {
                    valueDigests = ReadValueDigests(reader);

                    break;
                }
                case MdocMsoWellKnownKeys.DeviceKeyInfo:
                {
                    deviceKeyInfo = ReadDeviceKeyInfo(reader);

                    break;
                }
                case MdocMsoWellKnownKeys.DocType:
                {
                    docType = reader.ReadTextString();

                    break;
                }
                case MdocMsoWellKnownKeys.ValidityInfo:
                {
                    validityInfo = ReadValidityInfo(reader);

                    break;
                }
                default:
                {
                    //Unknown keys: forward-compat skip per ISO 18013-5.
                    reader.SkipValue();

                    break;
                }
            }
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

        MdocCoseKey? deviceKey = null;
        ReadOnlyMemory<byte>? encodedKeyAuthorizations = null;
        ReadOnlyMemory<byte>? encodedKeyInfo = null;

        int entriesRead = 0;
        while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
        {
            string key = reader.ReadTextString();
            entriesRead++;

            switch(key)
            {
                case MdocMsoWellKnownKeys.DeviceKey:
                {
                    deviceKey = MdocCborCoseKeyReader.ReadFromReader(reader);

                    break;
                }
                case MdocMsoWellKnownKeys.KeyAuthorizations:
                {
                    encodedKeyAuthorizations = reader.ReadEncodedValue();

                    break;
                }
                case MdocMsoWellKnownKeys.KeyInfo:
                {
                    encodedKeyInfo = reader.ReadEncodedValue();

                    break;
                }
                default:
                {
                    reader.SkipValue();

                    break;
                }
            }
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

            switch(key)
            {
                case MdocMsoWellKnownKeys.Signed:
                {
                    signed = ReadTdate(reader);

                    break;
                }
                case MdocMsoWellKnownKeys.ValidFrom:
                {
                    validFrom = ReadTdate(reader);

                    break;
                }
                case MdocMsoWellKnownKeys.ValidUntil:
                {
                    validUntil = ReadTdate(reader);

                    break;
                }
                case MdocMsoWellKnownKeys.ExpectedUpdate:
                {
                    expectedUpdate = ReadTdate(reader);

                    break;
                }
                default:
                {
                    reader.SkipValue();

                    break;
                }
            }
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
