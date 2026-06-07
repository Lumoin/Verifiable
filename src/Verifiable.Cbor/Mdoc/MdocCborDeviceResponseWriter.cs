using System.Formats.Cbor;
using Verifiable.Core.Model.Mdoc;

namespace Verifiable.Cbor.Mdoc;

/// <summary>
/// Encodes the outer ISO/IEC 18013-5 §8.3.2.1 wire shapes —
/// <c>IssuerSigned</c>, <c>Document</c>, and <c>DeviceResponse</c> — into
/// canonical CBOR. Each item's preserved
/// <see cref="MdocIssuerSignedItem.WireBytes"/> is reused verbatim so the
/// MSO digest commitments still resolve at the verifier side.
/// </summary>
/// <remarks>
/// <para>
/// The four nested wire shapes (top-down): <c>DeviceResponse</c> envelope
/// → <c>Document</c> map → <c>IssuerSigned</c> map → namespaced ordered
/// arrays of Tag-24-wrapped <c>IssuerSignedItemBytes</c>. The
/// <c>DeviceSigned</c> slot on each Document is the on-wire CBOR
/// representation of <see cref="MdocDeviceSigned"/>; the device-signer
/// produced one of those plus its preserved
/// <see cref="MdocDeviceSigned.EncodedDeviceNameSpacesBytes"/>, so the
/// writer here just composes them into the outer document.
/// </para>
/// <para>
/// Two overload families exist because the codebase models the issuance
/// shape and the presentation shape as distinct types
/// (<see cref="MdocDocument"/> owned vs <see cref="MdocPresentationDocument"/>
/// borrowed): <see cref="EncodeDocument(MdocDocument)"/> is the
/// issuance-side encoder (e.g. for storing a freshly-signed mdoc back to
/// the wire), and <see cref="EncodeDocument(MdocPresentationDocument)"/>
/// plus <see cref="EncodeDeviceResponse"/> drive the wallet's OID4VP
/// presentation path. Both delegate to a single internal writer over the
/// structural parts (docType + namespaces + IssuerAuth + DeviceSigned).
/// </para>
/// <para>
/// Mirrors <see cref="MdocCborMsoReader"/> + <see cref="MdocCborIssuerAuthReader"/>
/// on the inverse direction; a full read-path parser for the wire
/// envelope can land later (round-trip parsing of a complete
/// DeviceResponse is out of scope here — the OID4VP wallet/verifier flow
/// uses the typed model directly).
/// </para>
/// </remarks>
public static class MdocCborDeviceResponseWriter
{
    /// <summary>
    /// Encodes a single owned <see cref="MdocDocument"/> as its
    /// <c>Document</c> CBOR map. The device half is included when non-null.
    /// </summary>
    public static ReadOnlyMemory<byte> EncodeDocument(MdocDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        WriteDocument(writer, document.DocType, document.IssuerSigned.NameSpaces, document.IssuerSigned.IssuerAuth, document.DeviceSigned);

        return writer.Encode();
    }


    /// <summary>
    /// Encodes a single presentation-side <see cref="MdocPresentationDocument"/>
    /// as its <c>Document</c> CBOR map.
    /// </summary>
    public static ReadOnlyMemory<byte> EncodeDocument(MdocPresentationDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        WriteDocument(writer, document.DocType, document.IssuerSigned.NameSpaces, document.IssuerSigned.IssuerAuth, document.DeviceSigned);

        return writer.Encode();
    }


    /// <summary>
    /// Encodes a complete <see cref="MdocDeviceResponse"/> envelope per
    /// ISO/IEC 18013-5 §8.3.2.1.1. The result is the byte form that
    /// transports as the OID4VP <c>vp_token</c> value (after base64url
    /// encoding).
    /// </summary>
    public static ReadOnlyMemory<byte> EncodeDeviceResponse(MdocDeviceResponse deviceResponse)
    {
        ArgumentNullException.ThrowIfNull(deviceResponse);

        var writer = new CborWriter(CborConformanceMode.Canonical);

        int entries = 2 //version + status
            + (deviceResponse.Documents.Count > 0 ? 1 : 0)
            + (deviceResponse.EncodedDocumentErrors is null ? 0 : 1);

        writer.WriteStartMap(entries);

        writer.WriteTextString(MdocWellKnownKeys.Version);
        writer.WriteTextString(deviceResponse.Version);

        if(deviceResponse.Documents.Count > 0)
        {
            writer.WriteTextString(MdocWellKnownKeys.Documents);
            writer.WriteStartArray(deviceResponse.Documents.Count);
            foreach(MdocPresentationDocument document in deviceResponse.Documents)
            {
                WriteDocument(writer, document.DocType, document.IssuerSigned.NameSpaces, document.IssuerSigned.IssuerAuth, document.DeviceSigned);
            }
            writer.WriteEndArray();
        }

        if(deviceResponse.EncodedDocumentErrors is ReadOnlyMemory<byte> errs)
        {
            writer.WriteTextString(MdocWellKnownKeys.DocumentErrors);
            writer.WriteEncodedValue(errs.Span);
        }

        writer.WriteTextString(MdocWellKnownKeys.Status);
        writer.WriteUInt32(deviceResponse.Status);

        writer.WriteEndMap();

        return writer.Encode();
    }


    private static void WriteDocument(
        CborWriter writer,
        string docType,
        IReadOnlyDictionary<string, IReadOnlyList<MdocIssuerSignedItem>> nameSpaces,
        MdocIssuerAuth issuerAuth,
        MdocDeviceSigned? deviceSigned)
    {
        int entries = 2 + (deviceSigned is null ? 0 : 1);
        writer.WriteStartMap(entries);

        writer.WriteTextString(MdocWellKnownKeys.DocType);
        writer.WriteTextString(docType);

        writer.WriteTextString(MdocWellKnownKeys.IssuerSigned);
        WriteIssuerSigned(writer, nameSpaces, issuerAuth);

        if(deviceSigned is MdocDeviceSigned deviceSignedNonNull)
        {
            writer.WriteTextString(MdocWellKnownKeys.DeviceSigned);
            WriteDeviceSigned(writer, deviceSignedNonNull);
        }

        writer.WriteEndMap();
    }


    private static void WriteIssuerSigned(
        CborWriter writer,
        IReadOnlyDictionary<string, IReadOnlyList<MdocIssuerSignedItem>> nameSpaces,
        MdocIssuerAuth issuerAuth)
    {
        int entries = 1 + (nameSpaces.Count > 0 ? 1 : 0);
        writer.WriteStartMap(entries);

        if(nameSpaces.Count > 0)
        {
            writer.WriteTextString(MdocWellKnownKeys.NameSpaces);
            writer.WriteStartMap(nameSpaces.Count);
            foreach(KeyValuePair<string, IReadOnlyList<MdocIssuerSignedItem>> nsEntry in nameSpaces)
            {
                writer.WriteTextString(nsEntry.Key);

                writer.WriteStartArray(nsEntry.Value.Count);
                foreach(MdocIssuerSignedItem item in nsEntry.Value)
                {
                    writer.WriteEncodedValue(item.WireBytes.Span);
                }
                writer.WriteEndArray();
            }
            writer.WriteEndMap();
        }

        writer.WriteTextString(MdocWellKnownKeys.IssuerAuth);
        writer.WriteEncodedValue(issuerAuth.EncodedCoseSign1.AsReadOnlySpan());

        writer.WriteEndMap();
    }


    private static void WriteDeviceSigned(CborWriter writer, MdocDeviceSigned deviceSigned)
    {
        writer.WriteStartMap(2);

        writer.WriteTextString(MdocWellKnownKeys.NameSpaces);
        writer.WriteEncodedValue(deviceSigned.EncodedDeviceNameSpacesBytes.Span);

        writer.WriteTextString(MdocWellKnownKeys.DeviceAuth);
        WriteDeviceAuth(writer, deviceSigned.DeviceAuth);

        writer.WriteEndMap();
    }


    private static void WriteDeviceAuth(CborWriter writer, MdocDeviceAuth deviceAuth)
    {
        writer.WriteStartMap(1);

        if(deviceAuth.DeviceSignature is MdocDeviceSignature signature)
        {
            writer.WriteTextString(MdocWellKnownKeys.DeviceSignature);
            writer.WriteEncodedValue(signature.EncodedCoseSign1.AsReadOnlySpan());
        }
        else if(deviceAuth.DeviceMac is MdocDeviceMac mac)
        {
            writer.WriteTextString(MdocWellKnownKeys.DeviceMac);
            writer.WriteEncodedValue(mac.EncodedCoseMac0.AsReadOnlySpan());
        }
        else
        {
            throw new InvalidOperationException(
                "DeviceAuth carries neither a signature nor a MAC.");
        }

        writer.WriteEndMap();
    }
}
