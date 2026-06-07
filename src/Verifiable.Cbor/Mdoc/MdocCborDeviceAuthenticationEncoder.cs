using System.Formats.Cbor;
using Verifiable.Core.Model.Mdoc;

namespace Verifiable.Cbor.Mdoc;

/// <summary>
/// Encodes the <c>DeviceAuthentication</c> to-be-signed array per
/// ISO/IEC 18013-5 §9.1.3.4. The device signature / MAC commits to the
/// Tag-24-wrapped encoding of this array.
/// </summary>
/// <remarks>
/// <para>
/// The wire shape is:
/// </para>
/// <code>
/// DeviceAuthentication = [
///     "DeviceAuthentication",         ; context string
///     SessionTranscript,              ; transport-defined
///     DocType,                        ; from the enclosing Document
///     DeviceNameSpacesBytes           ; #6.24(bstr .cbor DeviceNameSpaces)
/// ]
/// </code>
/// <para>
/// The encoded array is then Tag-24-wrapped to produce
/// <c>DeviceAuthenticationBytes</c>, which feeds into the COSE_Sign1
/// <c>Sig_structure</c> as the <c>payload</c> field per ISO 18013-5
/// §9.1.3.4. The COSE_Sign1 itself uses a nil payload on the wire — the
/// verifier reconstructs <c>DeviceAuthenticationBytes</c> from the
/// session-transcript context, the doctype, and the
/// <c>DeviceNameSpacesBytes</c> already on the wire in
/// <see cref="MdocDeviceSigned.EncodedDeviceNameSpacesBytes"/>.
/// </para>
/// <para>
/// <c>SessionTranscript</c> is left as opaque caller-supplied bytes. The
/// concrete shape depends on the transport binding (BLE, NFC, or
/// OID4VP-over-HTTP per the upcoming draft-ietf-oauth-mdoc-iso). The
/// device side and the verifier side MUST agree on these bytes byte-for-
/// byte or the signature/verification won't match — the SessionTranscript
/// is what binds the presentation to its session.
/// </para>
/// </remarks>
public static class MdocCborDeviceAuthenticationEncoder
{
    /// <summary>
    /// Encodes the <c>DeviceAuthentication</c> array (no Tag 24 wrapper).
    /// </summary>
    /// <param name="encodedSessionTranscript">
    /// The CBOR-encoded SessionTranscript bytes for the active session.
    /// The transport supplies these; the data model treats them as opaque.
    /// </param>
    /// <param name="docType">The enclosing document's docType URI.</param>
    /// <param name="encodedDeviceNameSpacesBytes">
    /// The Tag-24-wrapped <c>DeviceNameSpaces</c> bytes — from
    /// <see cref="MdocCborDeviceNameSpacesEncoder.EncodeWrapped"/> on the
    /// signer side, or from
    /// <see cref="MdocDeviceSigned.EncodedDeviceNameSpacesBytes"/> on the
    /// verifier side.
    /// </param>
    /// <returns>The encoded array (no Tag 24 wrapper).</returns>
    public static ReadOnlyMemory<byte> EncodeArray(
        ReadOnlyMemory<byte> encodedSessionTranscript,
        string docType,
        ReadOnlyMemory<byte> encodedDeviceNameSpacesBytes)
    {
        ArgumentException.ThrowIfNullOrEmpty(docType);

        var writer = new CborWriter(CborConformanceMode.Canonical);

        writer.WriteStartArray(4);
        writer.WriteTextString(MdocWellKnownKeys.DeviceAuthenticationContext);
        writer.WriteEncodedValue(encodedSessionTranscript.Span);
        writer.WriteTextString(docType);
        writer.WriteEncodedValue(encodedDeviceNameSpacesBytes.Span);
        writer.WriteEndArray();

        return writer.Encode();
    }


    /// <summary>
    /// Encodes the <c>DeviceAuthentication</c> array AND wraps the result
    /// in CBOR Tag 24, producing <c>DeviceAuthenticationBytes</c>. This is
    /// the value that feeds the COSE Sig_structure's <c>payload</c> field.
    /// </summary>
    public static ReadOnlyMemory<byte> EncodeAuthenticationBytes(
        ReadOnlyMemory<byte> encodedSessionTranscript,
        string docType,
        ReadOnlyMemory<byte> encodedDeviceNameSpacesBytes)
    {
        ReadOnlyMemory<byte> arrayBytes = EncodeArray(encodedSessionTranscript, docType, encodedDeviceNameSpacesBytes);

        return EncodedCborItem.Wrap(arrayBytes.Span).WireBytes;
    }
}
