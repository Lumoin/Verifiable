using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// Shared CTAP2-canonical CBOR codec helpers for <c>authenticatorBioEnrollment</c>'s nested,
/// integer-keyed <c>TemplateInfo</c> structure — the array element <c>templateInfos</c> (response
/// member <c>0x07</c>) carries.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment">
/// CTAP 2.3, section 6.7: authenticatorBioEnrollment (0x09)</see>, the <c>TemplateInfo</c> definition
/// (snapshot lines 6534-6553): <c>templateId</c> (<c>0x01</c>, Required) then
/// <c>templateFriendlyName</c> (<c>0x02</c>, Optional) — already ascending integer-key order, so no
/// run-time sort is needed. Mirrors <see cref="CtapCommandEntityCborCodec"/>'s "write/read directly into
/// the passed <see cref="CborWriter"/>/<see cref="CborReader"/>, no separate buffer tag" shape for a
/// nested entity, following the bare-noun naming convention that type's own remarks document for a
/// REUSED nested codec (as opposed to a command-prefixed <c>Ctap*</c> type).
/// </remarks>
internal static class TemplateInfoCborCodec
{
    /// <summary>
    /// Writes one <see cref="CtapBioEnrollmentTemplateInfo"/> map: <c>templateId</c> (required byte
    /// string), then <c>templateFriendlyName</c> (optional text string) if present.
    /// </summary>
    /// <param name="writer">The CBOR writer positioned to write the map.</param>
    /// <param name="templateInfo">The template info to write.</param>
    public static void Write(CborWriter writer, CtapBioEnrollmentTemplateInfo templateInfo)
    {
        int memberCount = 1 + (templateInfo.TemplateFriendlyName is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(WellKnownCtapBioEnrollmentSubCommandParamsKeys.TemplateId);
        writer.WriteByteString(templateInfo.TemplateId.Span);

        if(templateInfo.TemplateFriendlyName is string templateFriendlyName)
        {
            writer.WriteInt32(WellKnownCtapBioEnrollmentSubCommandParamsKeys.TemplateFriendlyName);
            writer.WriteTextString(templateFriendlyName);
        }

        writer.WriteEndMap();
    }


    /// <summary>
    /// Reads one <see cref="CtapBioEnrollmentTemplateInfo"/> map, tolerating any unrecognized member.
    /// </summary>
    /// <param name="reader">The CBOR reader positioned at the map.</param>
    /// <returns>The decoded template info.</returns>
    /// <exception cref="Fido2FormatException">The map omits the required <c>templateId</c> member.</exception>
    public static CtapBioEnrollmentTemplateInfo Read(CborReader reader)
    {
        int? count = reader.ReadStartMap();
        byte[]? templateId = null;
        string? templateFriendlyName = null;

        int read = 0;
        while(count is null ? reader.PeekState() != CborReaderState.EndMap : read < count.Value)
        {
            int key = checked((int)reader.ReadInt64());
            read++;

            if(key == WellKnownCtapBioEnrollmentSubCommandParamsKeys.TemplateId)
            {
                templateId = reader.ReadByteString();
            }
            else if(key == WellKnownCtapBioEnrollmentSubCommandParamsKeys.TemplateFriendlyName)
            {
                templateFriendlyName = reader.ReadTextString();
            }
            else
            {
                reader.SkipValue();
            }
        }

        reader.ReadEndMap();

        if(templateId is null)
        {
            throw new Fido2FormatException("A TemplateInfo entry is missing the required 'templateId' (0x01) member.");
        }

        return new CtapBioEnrollmentTemplateInfo(templateId, templateFriendlyName);
    }


    /// <summary>
    /// Writes a definite-length CBOR array of <see cref="CtapBioEnrollmentTemplateInfo"/> maps.
    /// </summary>
    /// <param name="writer">The CBOR writer positioned to write the array.</param>
    /// <param name="templateInfos">The template infos to write, in wire order.</param>
    public static void WriteArray(CborWriter writer, IReadOnlyList<CtapBioEnrollmentTemplateInfo> templateInfos)
    {
        writer.WriteStartArray(templateInfos.Count);
        foreach(CtapBioEnrollmentTemplateInfo templateInfo in templateInfos)
        {
            Write(writer, templateInfo);
        }

        writer.WriteEndArray();
    }


    /// <summary>
    /// Reads a definite-length CBOR array of <see cref="CtapBioEnrollmentTemplateInfo"/> maps.
    /// </summary>
    /// <param name="reader">The CBOR reader positioned at the array.</param>
    /// <returns>The decoded template infos, in wire order.</returns>
    public static List<CtapBioEnrollmentTemplateInfo> ReadArray(CborReader reader)
    {
        int? count = reader.ReadStartArray();
        var templateInfos = new List<CtapBioEnrollmentTemplateInfo>();

        int read = 0;
        while(count is null ? reader.PeekState() != CborReaderState.EndArray : read < count.Value)
        {
            templateInfos.Add(Read(reader));
            read++;
        }

        reader.ReadEndArray();

        return templateInfos;
    }
}
