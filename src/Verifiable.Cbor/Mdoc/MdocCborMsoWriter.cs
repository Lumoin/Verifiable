using System.Formats.Cbor;
using Verifiable.Core.Model.Mdoc;

namespace Verifiable.Cbor.Mdoc;

/// <summary>
/// Writes an <see cref="MdocMobileSecurityObject"/> to its on-wire CBOR map
/// per ISO/IEC 18013-5 §9.1.2.4. Paired with <see cref="MdocCborMsoReader"/>.
/// </summary>
/// <remarks>
/// <para>
/// The MSO map carries six required fields with text-string keys. Canonical
/// conformance mode sorts the keys for us; the order they appear here is
/// irrelevant to the output bytes.
/// </para>
/// <para>
/// Nested writers handle <c>valueDigests</c> (namespace → digestID → digest
/// bytes), <c>deviceKeyInfo</c> (delegates to
/// <see cref="MdocCborCoseKeyWriter"/>), and <c>validityInfo</c> (tdate
/// fields wrapped in CBOR Tag 0).
/// </para>
/// </remarks>
public static class MdocCborMsoWriter
{
    /// <summary>
    /// Encodes the supplied MSO as a CBOR map.
    /// </summary>
    /// <returns>The canonical CBOR encoding of the MSO map (no Tag 24 wrapper).</returns>
    public static ReadOnlyMemory<byte> Write(MdocMobileSecurityObject mso)
    {
        ArgumentNullException.ThrowIfNull(mso);

        var writer = new CborWriter(CborConformanceMode.Canonical);

        writer.WriteStartMap(6);

        writer.WriteTextString(MdocMsoWellKnownKeys.Version);
        writer.WriteTextString(mso.Version);

        writer.WriteTextString(MdocMsoWellKnownKeys.DigestAlgorithm);
        writer.WriteTextString(mso.DigestAlgorithm);

        writer.WriteTextString(MdocMsoWellKnownKeys.ValueDigests);
        WriteValueDigests(writer, mso.ValueDigests);

        writer.WriteTextString(MdocMsoWellKnownKeys.DeviceKeyInfo);
        WriteDeviceKeyInfo(writer, mso.DeviceKeyInfo);

        writer.WriteTextString(MdocMsoWellKnownKeys.DocType);
        writer.WriteTextString(mso.DocType);

        writer.WriteTextString(MdocMsoWellKnownKeys.ValidityInfo);
        WriteValidityInfo(writer, mso.ValidityInfo);

        writer.WriteEndMap();

        return writer.Encode();
    }


    private static void WriteValueDigests(
        CborWriter writer,
        IReadOnlyDictionary<string, IReadOnlyDictionary<uint, ReadOnlyMemory<byte>>> valueDigests)
    {
        writer.WriteStartMap(valueDigests.Count);
        foreach(KeyValuePair<string, IReadOnlyDictionary<uint, ReadOnlyMemory<byte>>> nsEntry in valueDigests)
        {
            writer.WriteTextString(nsEntry.Key);

            writer.WriteStartMap(nsEntry.Value.Count);
            foreach(KeyValuePair<uint, ReadOnlyMemory<byte>> digestEntry in nsEntry.Value)
            {
                writer.WriteUInt32(digestEntry.Key);
                writer.WriteByteString(digestEntry.Value.Span);
            }
            writer.WriteEndMap();
        }
        writer.WriteEndMap();
    }


    private static void WriteDeviceKeyInfo(CborWriter writer, MdocDeviceKeyInfo deviceKeyInfo)
    {
        int entries = 1
            + (deviceKeyInfo.EncodedKeyAuthorizations is null ? 0 : 1)
            + (deviceKeyInfo.EncodedKeyInfo is null ? 0 : 1);

        writer.WriteStartMap(entries);

        writer.WriteTextString(MdocMsoWellKnownKeys.DeviceKey);
        ReadOnlyMemory<byte> deviceKeyBytes = MdocCborCoseKeyWriter.Write(deviceKeyInfo.DeviceKey);
        writer.WriteEncodedValue(deviceKeyBytes.Span);

        if(deviceKeyInfo.EncodedKeyAuthorizations is ReadOnlyMemory<byte> authz)
        {
            writer.WriteTextString(MdocMsoWellKnownKeys.KeyAuthorizations);
            writer.WriteEncodedValue(authz.Span);
        }

        if(deviceKeyInfo.EncodedKeyInfo is ReadOnlyMemory<byte> info)
        {
            writer.WriteTextString(MdocMsoWellKnownKeys.KeyInfo);
            writer.WriteEncodedValue(info.Span);
        }

        writer.WriteEndMap();
    }


    private static void WriteValidityInfo(CborWriter writer, MdocValidityInfo validityInfo)
    {
        int entries = 3 + (validityInfo.ExpectedUpdate is null ? 0 : 1);

        writer.WriteStartMap(entries);

        writer.WriteTextString(MdocMsoWellKnownKeys.Signed);
        WriteTdate(writer, validityInfo.Signed);

        writer.WriteTextString(MdocMsoWellKnownKeys.ValidFrom);
        WriteTdate(writer, validityInfo.ValidFrom);

        writer.WriteTextString(MdocMsoWellKnownKeys.ValidUntil);
        WriteTdate(writer, validityInfo.ValidUntil);

        if(validityInfo.ExpectedUpdate is DateTimeOffset expectedUpdate)
        {
            writer.WriteTextString(MdocMsoWellKnownKeys.ExpectedUpdate);
            WriteTdate(writer, expectedUpdate);
        }

        writer.WriteEndMap();
    }


    private static void WriteTdate(CborWriter writer, DateTimeOffset value)
    {
        writer.WriteTag(CborTag.DateTimeString);
        writer.WriteTextString(value.ToUniversalTime().ToString(
            "yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture));
    }
}
