using System.Formats.Cbor;
using Verifiable.Core.Model.Mdoc;

namespace Verifiable.Cbor.Mdoc;

/// <summary>
/// Encodes an <see cref="MdocDeviceNameSpaces"/> into its on-wire
/// Tag-24-wrapped CBOR form per ISO/IEC 18013-5 §8.3.2.1.2.3 — the
/// <c>DeviceNameSpacesBytes</c> field on the wire AND the same byte form
/// the <c>DeviceAuthentication</c> array commits to.
/// </summary>
/// <remarks>
/// <para>
/// Two outputs are useful:
/// <see cref="EncodeInnerMap"/> for the inner CBOR map (no Tag 24 wrapper),
/// <see cref="EncodeWrapped"/> for the Tag-24-wrapped form
/// (<see cref="EncodedCborItem"/>). The wrapped form is what
/// <see cref="MdocDeviceSigned.EncodedDeviceNameSpacesBytes"/> and the
/// <c>DeviceAuthentication</c> array carry.
/// </para>
/// </remarks>
public static class MdocCborDeviceNameSpacesEncoder
{
    /// <summary>
    /// Encodes the inner <c>DeviceNameSpaces</c> map. The result is a CBOR
    /// map under canonical conformance — empty map when the device asserts
    /// no claims of its own, which is the common case.
    /// </summary>
    public static ReadOnlyMemory<byte> EncodeInnerMap(MdocDeviceNameSpaces nameSpaces)
    {
        ArgumentNullException.ThrowIfNull(nameSpaces);

        var writer = new CborWriter(CborConformanceMode.Canonical);

        writer.WriteStartMap(nameSpaces.Entries.Count);

        foreach(KeyValuePair<string, IReadOnlyDictionary<string, ReadOnlyMemory<byte>>> nsEntry in nameSpaces.Entries)
        {
            writer.WriteTextString(nsEntry.Key);

            writer.WriteStartMap(nsEntry.Value.Count);
            foreach(KeyValuePair<string, ReadOnlyMemory<byte>> elementEntry in nsEntry.Value)
            {
                writer.WriteTextString(elementEntry.Key);
                writer.WriteEncodedValue(elementEntry.Value.Span);
            }
            writer.WriteEndMap();
        }

        writer.WriteEndMap();

        return writer.Encode();
    }


    /// <summary>
    /// Encodes the Tag-24-wrapped form of <paramref name="nameSpaces"/>.
    /// The wrapper bytes are what the device signature commits to via the
    /// <c>DeviceAuthentication</c> array.
    /// </summary>
    public static ReadOnlyMemory<byte> EncodeWrapped(MdocDeviceNameSpaces nameSpaces)
    {
        ReadOnlyMemory<byte> inner = EncodeInnerMap(nameSpaces);

        return EncodedCborItem.Wrap(inner.Span).WireBytes;
    }
}
