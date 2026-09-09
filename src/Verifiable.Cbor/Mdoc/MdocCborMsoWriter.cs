using System.Buffers;
using Lumoin.Veritas.Cbor;
using Verifiable.Cbor.StatusList;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Core.StatusList;

namespace Verifiable.Cbor.Mdoc;

/// <summary>
/// Writes an <see cref="MdocMobileSecurityObject"/> to its on-wire CBOR map
/// per ISO/IEC 18013-5 §9.1.2.4. Paired with <see cref="MdocCborMsoReader"/>.
/// </summary>
/// <remarks>
/// <para>
/// The MSO map carries six required fields with text-string keys, plus the
/// optional <c>status</c> member the second edition of ISO/IEC 18013-5
/// (under ballot as a DIS) adds. Canonical conformance mode sorts the keys
/// for us; the order they appear here is irrelevant to the output bytes.
/// </para>
/// <para>
/// Nested writers handle <c>valueDigests</c> (namespace → digestID → digest
/// bytes), <c>deviceKeyInfo</c> (delegates to
/// <see cref="MdocCborCoseKeyWriter"/>), <c>validityInfo</c> (tdate
/// fields wrapped in CBOR Tag 0), and <c>status</c> (the Token Status List
/// Status CBOR structure per Section 6.3; only the <c>status_list</c>
/// mechanism is writable, the sole mechanism this library models). A
/// <see cref="StatusClaim"/> carries at most one <c>status_list</c> entry
/// by construction, so the EU implementing act's per-MSO uniqueness rule
/// for the status index and URI combination holds automatically.
/// </para>
/// </remarks>
public static class MdocCborMsoWriter
{
    /// <summary>
    /// Encodes the supplied MSO as a CBOR map.
    /// </summary>
    /// <returns>The canonical CBOR encoding of the MSO map (no Tag 24 wrapper).</returns>
    /// <exception cref="NotSupportedException">
    /// Thrown when <paramref name="mso"/> carries a
    /// <see cref="MdocMobileSecurityObject.Status"/> whose
    /// <see cref="StatusClaim.Mechanisms"/> names a mechanism other than
    /// <see cref="StatusMechanismNames.StatusList"/> — the only
    /// mechanism this writer can encode.
    /// </exception>
    public static ReadOnlyMemory<byte> Write(MdocMobileSecurityObject mso)
    {
        ArgumentNullException.ThrowIfNull(mso);

        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);

        int entryCount = 6 + (mso.Status is null ? 0 : 1);
        writer.WriteStartMap(entryCount);

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

        if(mso.Status is StatusClaim status)
        {
            writer.WriteTextString(MdocMsoWellKnownKeys.Status);
            WriteStatus(writer, status);
        }

        writer.WriteEndMap();

        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Writes the <c>status</c> map — the Token Status List Status CBOR
    /// structure per Section 6.3 — refusing any mechanism this library does
    /// not model for encoding. The declared map size is taken from what this
    /// method actually writes, not from <see cref="StatusClaim.Mechanisms"/>'s
    /// count, so the declared length and the written entries share one
    /// source rather than two that merely happen to agree.
    /// </summary>
    /// <exception cref="NotSupportedException">
    /// Thrown when <paramref name="status"/> names a mechanism other than
    /// <see cref="StatusMechanismNames.StatusList"/>.
    /// </exception>
    private static void WriteStatus(CborWriter writer, StatusClaim status)
    {
        foreach(string mechanism in status.Mechanisms)
        {
            if(!string.Equals(mechanism, StatusMechanismNames.StatusList, StringComparison.Ordinal))
            {
                throw new NotSupportedException(
                    $"MSO status mechanism '{mechanism}' cannot be written: only " +
                    $"'{StatusMechanismNames.StatusList}' is modelled for encoding per Token Status List Section 6.3.");
            }
        }

        writer.WriteStartMap(status.StatusList is null ? 0 : 1);

        if(status.StatusList is StatusListReference statusList)
        {
            writer.WriteTextString(StatusMechanismNames.StatusList);
            new StatusListReferenceCborConverter().Write(writer, statusList);
        }

        writer.WriteEndMap();
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
