using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.DidComm;

namespace Verifiable.Json.Converters;

/// <summary>
/// Converts a <see cref="DidCommMessage"/> to and from its
/// <c>application/didcomm-plain+json</c> wire shape, as defined in
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#plaintext-message-structure">DIDComm Messaging v2.1 §Plaintext Message Structure</see>
/// and §Message Headers.
/// </summary>
/// <remarks>
/// <para>
/// The wire member names come from <see cref="WellKnownDidCommMemberNames"/> — the snake_case spec
/// tokens (<c>created_time</c>, <c>expires_time</c>, <c>from_prior</c>, …) matched and written
/// against their UTF-8 spans, allocation-free, so no naming policy is applied. The predefined
/// headers map onto the strongly-typed members of <see cref="DidCommMessage"/>; every other
/// top-level member with a value carries through <see cref="DidCommMessage.AdditionalHeaders"/> so
/// an unrecognized extension header survives a pack/unpack cycle. An extension header whose value
/// is JSON <c>null</c> conveys no value and is dropped — a legal "ignore" of an unknown header,
/// since the requirement is only that an unknown header MUST NOT cause failure
/// (DIDComm v2.1 §Message Headers).
/// </para>
/// <para>
/// Property dispatch uses the same allocation-free <c>NameEquals(...u8)</c> if-chain as
/// <see cref="ServiceConverter"/>; a switch over the property name would force a string allocation
/// per member. The arbitrary-JSON members (<c>body</c>, an attachment's <c>jws</c> and <c>json</c>,
/// and each extension header) are materialized with
/// <see cref="JsonElementConversion.Convert(JsonElement)"/> on read and emitted with
/// <see cref="ManualJsonWriter.WriteValue(Utf8JsonWriter, object?)"/> on write, the same
/// arbitrary-value path the DID/VC converters use.
/// </para>
/// <para>
/// The integer typing of <c>created_time</c> and <c>expires_time</c> is enforced here at the wire
/// level: a fractional, string, or otherwise non-integer value is rejected with
/// <see cref="JsonThrowHelper.ThrowJsonException(string)"/>. The domain-level structural validation
/// (required headers, message-type-URI shape, recipient identifier shape) is applied above this
/// converter by <see cref="DidCommPlaintextExtensions.UnpackPlaintext"/>.
/// </para>
/// </remarks>
public sealed class DidCommMessageConverter: JsonConverter<DidCommMessage>
{
    /// <inheritdoc/>
    public override DidCommMessage Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            JsonThrowHelper.ThrowJsonException("A DIDComm plaintext message MUST be a JSON object.");
        }

        using(var document = JsonDocument.ParseValue(ref reader))
        {
            return ReadMessage(document.RootElement);
        }
    }


    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, DidCommMessage value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        writer.WriteStartObject();

        if(value.Id is not null)
        {
            writer.WriteString(WellKnownDidCommMemberNames.IdUtf8, value.Id);
        }

        if(value.Type is not null)
        {
            writer.WriteString(WellKnownDidCommMemberNames.TypeUtf8, value.Type);
        }

        if(value.From is not null)
        {
            writer.WriteString(WellKnownDidCommMemberNames.FromUtf8, value.From);
        }

        if(value.To is not null)
        {
            writer.WriteStartArray(WellKnownDidCommMemberNames.ToUtf8);
            foreach(string recipient in value.To)
            {
                writer.WriteStringValue(recipient);
            }

            writer.WriteEndArray();
        }

        if(value.ThreadId is not null)
        {
            writer.WriteString(WellKnownDidCommMemberNames.ThreadIdUtf8, value.ThreadId);
        }

        if(value.ParentThreadId is not null)
        {
            writer.WriteString(WellKnownDidCommMemberNames.ParentThreadIdUtf8, value.ParentThreadId);
        }

        if(value.CreatedTime is not null)
        {
            writer.WriteNumber(WellKnownDidCommMemberNames.CreatedTimeUtf8, value.CreatedTime.Value);
        }

        if(value.ExpiresTime is not null)
        {
            writer.WriteNumber(WellKnownDidCommMemberNames.ExpiresTimeUtf8, value.ExpiresTime.Value);
        }

        if(value.FromPrior is not null)
        {
            writer.WriteString(WellKnownDidCommMemberNames.FromPriorUtf8, value.FromPrior);
        }

        if(value.PleaseAck is not null)
        {
            writer.WriteStartArray(WellKnownDidCommMemberNames.PleaseAckUtf8);
            foreach(string messageId in value.PleaseAck)
            {
                writer.WriteStringValue(messageId);
            }

            writer.WriteEndArray();
        }

        if(value.Ack is not null)
        {
            writer.WriteStartArray(WellKnownDidCommMemberNames.AckUtf8);
            foreach(string messageId in value.Ack)
            {
                writer.WriteStringValue(messageId);
            }

            writer.WriteEndArray();
        }

        if(value.Body is not null)
        {
            writer.WritePropertyName(WellKnownDidCommMemberNames.BodyUtf8);
            ManualJsonWriter.WriteValue(writer, value.Body);
        }

        if(value.Attachments is not null)
        {
            writer.WriteStartArray(WellKnownDidCommMemberNames.AttachmentsUtf8);
            foreach(Attachment attachment in value.Attachments)
            {
                WriteAttachment(writer, attachment);
            }

            writer.WriteEndArray();
        }

        if(value.AdditionalHeaders is not null)
        {
            foreach(KeyValuePair<string, object> header in value.AdditionalHeaders)
            {
                writer.WritePropertyName(header.Key);
                ManualJsonWriter.WriteValue(writer, header.Value);
            }
        }

        writer.WriteEndObject();
    }


    //Reads the message object, mapping each predefined header onto its typed member and carrying
    //every other top-level member into AdditionalHeaders verbatim (DIDComm v2.1 §Message Headers).
    private static DidCommMessage ReadMessage(JsonElement element)
    {
        var message = new DidCommMessage();
        Dictionary<string, object>? additionalHeaders = null;

        foreach(JsonProperty property in element.EnumerateObject())
        {
            if(property.NameEquals(WellKnownDidCommMemberNames.IdUtf8))
            {
                message.Id = property.Value.GetString();
            }
            else if(property.NameEquals(WellKnownDidCommMemberNames.TypeUtf8))
            {
                message.Type = property.Value.GetString();
            }
            else if(property.NameEquals(WellKnownDidCommMemberNames.FromUtf8))
            {
                message.From = property.Value.GetString();
            }
            else if(property.NameEquals(WellKnownDidCommMemberNames.ToUtf8))
            {
                message.To = ReadStringArray(property.Value, WellKnownDidCommMemberNames.To);
            }
            else if(property.NameEquals(WellKnownDidCommMemberNames.ThreadIdUtf8))
            {
                message.ThreadId = property.Value.GetString();
            }
            else if(property.NameEquals(WellKnownDidCommMemberNames.ParentThreadIdUtf8))
            {
                message.ParentThreadId = property.Value.GetString();
            }
            else if(property.NameEquals(WellKnownDidCommMemberNames.CreatedTimeUtf8))
            {
                message.CreatedTime = ReadIntegerMember(property.Value, WellKnownDidCommMemberNames.CreatedTime);
            }
            else if(property.NameEquals(WellKnownDidCommMemberNames.ExpiresTimeUtf8))
            {
                message.ExpiresTime = ReadIntegerMember(property.Value, WellKnownDidCommMemberNames.ExpiresTime);
            }
            else if(property.NameEquals(WellKnownDidCommMemberNames.FromPriorUtf8))
            {
                message.FromPrior = property.Value.GetString();
            }
            else if(property.NameEquals(WellKnownDidCommMemberNames.PleaseAckUtf8))
            {
                message.PleaseAck = ReadStringArray(property.Value, WellKnownDidCommMemberNames.PleaseAck);
            }
            else if(property.NameEquals(WellKnownDidCommMemberNames.AckUtf8))
            {
                message.Ack = ReadStringArray(property.Value, WellKnownDidCommMemberNames.Ack);
            }
            else if(property.NameEquals(WellKnownDidCommMemberNames.BodyUtf8))
            {
                message.Body = ReadObject(property.Value, WellKnownDidCommMemberNames.Body);
            }
            else if(property.NameEquals(WellKnownDidCommMemberNames.AttachmentsUtf8))
            {
                message.Attachments = ReadAttachments(property.Value);
            }
            else
            {
                additionalHeaders ??= new Dictionary<string, object>(StringComparer.Ordinal);
                object? headerValue = JsonElementConversion.Convert(property.Value);
                if(headerValue is not null)
                {
                    additionalHeaders[property.Name] = headerValue;
                }
            }
        }

        if(additionalHeaders is not null)
        {
            message.AdditionalHeaders = additionalHeaders;
        }

        return message;
    }


    private static List<Attachment> ReadAttachments(JsonElement element)
    {
        if(element.ValueKind != JsonValueKind.Array)
        {
            JsonThrowHelper.ThrowJsonException("The DIDComm 'attachments' member MUST be a JSON array.");
        }

        var attachments = new List<Attachment>();
        foreach(JsonElement item in element.EnumerateArray())
        {
            attachments.Add(ReadAttachment(item));
        }

        return attachments;
    }


    private static Attachment ReadAttachment(JsonElement element)
    {
        if(element.ValueKind != JsonValueKind.Object)
        {
            JsonThrowHelper.ThrowJsonException("A DIDComm attachment MUST be a JSON object.");
        }

        var attachment = new Attachment();
        foreach(JsonProperty property in element.EnumerateObject())
        {
            if(property.NameEquals(WellKnownDidCommMemberNames.IdUtf8))
            {
                attachment.Id = property.Value.GetString();
            }
            else if(property.NameEquals(WellKnownDidCommMemberNames.DescriptionUtf8))
            {
                attachment.Description = property.Value.GetString();
            }
            else if(property.NameEquals(WellKnownDidCommMemberNames.FilenameUtf8))
            {
                attachment.Filename = property.Value.GetString();
            }
            else if(property.NameEquals(WellKnownDidCommMemberNames.MediaTypeUtf8))
            {
                attachment.MediaType = property.Value.GetString();
            }
            else if(property.NameEquals(WellKnownDidCommMemberNames.FormatUtf8))
            {
                attachment.Format = property.Value.GetString();
            }
            else if(property.NameEquals(WellKnownDidCommMemberNames.LastModifiedTimeUtf8))
            {
                attachment.LastModifiedTime = ReadIntegerMember(property.Value, WellKnownDidCommMemberNames.LastModifiedTime);
            }
            else if(property.NameEquals(WellKnownDidCommMemberNames.ByteCountUtf8))
            {
                attachment.ByteCount = ReadIntegerMember(property.Value, WellKnownDidCommMemberNames.ByteCount);
            }
            else if(property.NameEquals(WellKnownDidCommMemberNames.DataUtf8))
            {
                attachment.Data = ReadAttachmentData(property.Value);
            }
        }

        return attachment;
    }


    private static AttachmentData ReadAttachmentData(JsonElement element)
    {
        if(element.ValueKind != JsonValueKind.Object)
        {
            JsonThrowHelper.ThrowJsonException("A DIDComm attachment 'data' member MUST be a JSON object.");
        }

        var data = new AttachmentData();
        foreach(JsonProperty property in element.EnumerateObject())
        {
            if(property.NameEquals(WellKnownDidCommMemberNames.JwsUtf8))
            {
                data.Jws = JsonElementConversion.Convert(property.Value);
            }
            else if(property.NameEquals(WellKnownDidCommMemberNames.HashUtf8))
            {
                data.Hash = property.Value.GetString();
            }
            else if(property.NameEquals(WellKnownDidCommMemberNames.LinksUtf8))
            {
                data.Links = ReadStringArray(property.Value, WellKnownDidCommMemberNames.Links);
            }
            else if(property.NameEquals(WellKnownDidCommMemberNames.Base64Utf8))
            {
                data.Base64 = property.Value.GetString();
            }
            else if(property.NameEquals(WellKnownDidCommMemberNames.JsonUtf8))
            {
                data.Json = JsonElementConversion.Convert(property.Value);
            }
        }

        return data;
    }


    private static void WriteAttachment(Utf8JsonWriter writer, Attachment attachment)
    {
        writer.WriteStartObject();

        if(attachment.Id is not null)
        {
            writer.WriteString(WellKnownDidCommMemberNames.IdUtf8, attachment.Id);
        }

        if(attachment.Description is not null)
        {
            writer.WriteString(WellKnownDidCommMemberNames.DescriptionUtf8, attachment.Description);
        }

        if(attachment.Filename is not null)
        {
            writer.WriteString(WellKnownDidCommMemberNames.FilenameUtf8, attachment.Filename);
        }

        if(attachment.MediaType is not null)
        {
            writer.WriteString(WellKnownDidCommMemberNames.MediaTypeUtf8, attachment.MediaType);
        }

        if(attachment.Format is not null)
        {
            writer.WriteString(WellKnownDidCommMemberNames.FormatUtf8, attachment.Format);
        }

        if(attachment.LastModifiedTime is not null)
        {
            writer.WriteNumber(WellKnownDidCommMemberNames.LastModifiedTimeUtf8, attachment.LastModifiedTime.Value);
        }

        if(attachment.ByteCount is not null)
        {
            writer.WriteNumber(WellKnownDidCommMemberNames.ByteCountUtf8, attachment.ByteCount.Value);
        }

        if(attachment.Data is not null)
        {
            writer.WritePropertyName(WellKnownDidCommMemberNames.DataUtf8);
            WriteAttachmentData(writer, attachment.Data);
        }

        writer.WriteEndObject();
    }


    private static void WriteAttachmentData(Utf8JsonWriter writer, AttachmentData data)
    {
        writer.WriteStartObject();

        if(data.Jws is not null)
        {
            writer.WritePropertyName(WellKnownDidCommMemberNames.JwsUtf8);
            ManualJsonWriter.WriteValue(writer, data.Jws);
        }

        if(data.Hash is not null)
        {
            writer.WriteString(WellKnownDidCommMemberNames.HashUtf8, data.Hash);
        }

        if(data.Links is not null)
        {
            writer.WriteStartArray(WellKnownDidCommMemberNames.LinksUtf8);
            foreach(string link in data.Links)
            {
                writer.WriteStringValue(link);
            }

            writer.WriteEndArray();
        }

        if(data.Base64 is not null)
        {
            writer.WriteString(WellKnownDidCommMemberNames.Base64Utf8, data.Base64);
        }

        if(data.Json is not null)
        {
            writer.WritePropertyName(WellKnownDidCommMemberNames.JsonUtf8);
            ManualJsonWriter.WriteValue(writer, data.Json);
        }

        writer.WriteEndObject();
    }


    //An arbitrary JSON object member (body) materialized as a string-keyed dictionary; a non-object
    //value is a wire violation.
    private static Dictionary<string, object> ReadObject(JsonElement element, string memberName)
    {
        if(element.ValueKind != JsonValueKind.Object)
        {
            JsonThrowHelper.ThrowJsonException($"The DIDComm '{memberName}' member MUST be a JSON object.");
        }

        return (Dictionary<string, object>)JsonElementConversion.Convert(element)!;
    }


    private static List<string> ReadStringArray(JsonElement element, string memberName)
    {
        if(element.ValueKind != JsonValueKind.Array)
        {
            JsonThrowHelper.ThrowJsonException($"The DIDComm '{memberName}' member MUST be a JSON array of strings.");
        }

        var list = new List<string>();
        foreach(JsonElement item in element.EnumerateArray())
        {
            if(item.ValueKind != JsonValueKind.String)
            {
                JsonThrowHelper.ThrowJsonException($"The DIDComm '{memberName}' member MUST contain only string values.");
            }

            list.Add(item.GetString()!);
        }

        return list;
    }


    //An integer-valued member — the UTC-epoch-seconds headers created_time / expires_time
    //(DIDComm v2.1 §Message Headers) and the attachment lastmod_time / byte_count (§Attachments) —
    //MUST be a JSON integer; a fractional number, a string, or any other kind is rejected so the
    //wire-level integer discipline holds.
    private static long ReadIntegerMember(JsonElement element, string memberName)
    {
        if(element.ValueKind != JsonValueKind.Number || !element.TryGetInt64(out long value))
        {
            JsonThrowHelper.ThrowJsonException(
                $"The DIDComm '{memberName}' member MUST be a JSON integer.");

            return default;
        }

        return value;
    }
}
