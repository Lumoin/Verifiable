using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.WebPlus;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Did;

namespace Verifiable.Json.Converters;

/// <summary>
/// Converts <see cref="DidDocument"/> to and from JSON, preserving any top-level members that are not part of
/// the W3C DID core data model in <see cref="DidDocument.AdditionalData"/> rather than dropping them.
/// </summary>
/// <remarks>
/// <para>
/// The W3C core members are (de)serialized through their own registered converters via
/// <see cref="JsonSerializerOptions.GetTypeInfo"/> — the same idiom the DID resolution-result converter uses —
/// so member fidelity is unchanged from the source-generated path. Every other top-level member is materialized
/// into <see cref="DidDocument.AdditionalData"/> on read and written back on write, giving an arbitrary DID
/// document a faithful round-trip. The data is preserved, not trusted: the depth of untrusted input is bounded
/// by the caller's reader, and verification runs over the received wire bytes, never this model.
/// </para>
/// <para>
/// <see cref="CanConvert"/> matches <see cref="DidDocument"/> and its subtypes so a received document is
/// materialized as the right type: the method is read from the <c>id</c> and a <c>did:webplus</c> document
/// becomes a typed <see cref="WebPlusDidDocument"/> (its control fields surfaced as typed properties), while any
/// other method becomes a base <see cref="DidDocument"/>. The member types this converter delegates to are not
/// <see cref="DidDocument"/> subtypes, so it is not re-entered.
/// </para>
/// </remarks>
public sealed class DidDocumentConverter: JsonConverter<DidDocument>
{
    //The id prefix that selects the typed did:webplus subtype, computed once from the well-known method name.
    private static readonly string WebPlusMethodPrefix = WellKnownDidMethodPrefixes.WebPlusDidMethodPrefix + ":";


    /// <inheritdoc />
    public override bool CanConvert(Type typeToConvert)
    {
        return typeof(DidDocument).IsAssignableFrom(typeToConvert);
    }


    /// <inheritdoc />
    public override DidDocument Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if(reader.TokenType != JsonTokenType.StartObject)
        {
            JsonThrowHelper.ThrowJsonException("A DID document MUST be a JSON object.");
        }

        using JsonDocument document = JsonDocument.ParseValue(ref reader);
        JsonElement root = document.RootElement;

        //The method is read from the id so the document is materialized as the recognized typed subtype.
        DidDocument didDocument = CreateForMethod(root);
        WebPlusDidDocument? webPlus = didDocument as WebPlusDidDocument;
        Dictionary<string, object>? additionalData = null;

        foreach(JsonProperty property in root.EnumerateObject())
        {
            if(property.NameEquals("@context"u8))
            {
                didDocument.Context = Deserialize<Context>(property.Value, options);
            }
            else if(property.NameEquals("id"u8))
            {
                didDocument.Id = Deserialize<GenericDidMethod>(property.Value, options);
            }
            else if(property.NameEquals("alsoKnownAs"u8))
            {
                didDocument.AlsoKnownAs = Deserialize<string[]>(property.Value, options);
            }
            else if(property.NameEquals("controller"u8))
            {
                didDocument.Controller = Deserialize<Controller[]>(property.Value, options);
            }
            else if(property.NameEquals("verificationMethod"u8))
            {
                didDocument.VerificationMethod = Deserialize<VerificationMethod[]>(property.Value, options);
            }
            else if(property.NameEquals("authentication"u8))
            {
                didDocument.Authentication = Deserialize<AuthenticationMethod[]>(property.Value, options);
            }
            else if(property.NameEquals("assertionMethod"u8))
            {
                didDocument.AssertionMethod = Deserialize<AssertionMethod[]>(property.Value, options);
            }
            else if(property.NameEquals("keyAgreement"u8))
            {
                didDocument.KeyAgreement = Deserialize<KeyAgreementMethod[]>(property.Value, options);
            }
            else if(property.NameEquals("capabilityInvocation"u8))
            {
                didDocument.CapabilityInvocation = Deserialize<CapabilityInvocationMethod[]>(property.Value, options);
            }
            else if(property.NameEquals("capabilityDelegation"u8))
            {
                didDocument.CapabilityDelegation = Deserialize<CapabilityDelegationMethod[]>(property.Value, options);
            }
            else if(property.NameEquals("service"u8))
            {
                didDocument.Service = Deserialize<Service[]>(property.Value, options);
            }
            else if(webPlus is not null && TryReadWebPlusField(webPlus, property))
            {
                //A recognized did:webplus control field was read into a typed property.
            }
            else
            {
                //An unrecognized member is preserved verbatim as a detached JsonElement (cloned so it outlives
                //the JsonDocument disposed at the end of this method), so it round-trips byte-faithfully.
                additionalData ??= new Dictionary<string, object>(StringComparer.Ordinal);
                additionalData[property.Name] = property.Value.Clone();
            }
        }

        didDocument.AdditionalData = additionalData;

        return didDocument;
    }


    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, DidDocument value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(options);

        writer.WriteStartObject();

        //W3C core members in declaration order, each omitted when null (matching the WhenWritingNull default).
        WriteMember(writer, "@context"u8, value.Context, options);
        WriteMember(writer, "id"u8, value.Id, options);
        WriteMember(writer, "alsoKnownAs"u8, value.AlsoKnownAs, options);
        WriteMember(writer, "controller"u8, value.Controller, options);
        WriteMember(writer, "verificationMethod"u8, value.VerificationMethod, options);
        WriteMember(writer, "authentication"u8, value.Authentication, options);
        WriteMember(writer, "assertionMethod"u8, value.AssertionMethod, options);
        WriteMember(writer, "keyAgreement"u8, value.KeyAgreement, options);
        WriteMember(writer, "capabilityInvocation"u8, value.CapabilityInvocation, options);
        WriteMember(writer, "capabilityDelegation"u8, value.CapabilityDelegation, options);
        WriteMember(writer, "service"u8, value.Service, options);

        if(value is WebPlusDidDocument webPlus)
        {
            WriteWebPlusFields(writer, webPlus);
        }

        if(value.AdditionalData is not null)
        {
            foreach(KeyValuePair<string, object> entry in value.AdditionalData)
            {
                writer.WritePropertyName(entry.Key);
                ManualJsonWriter.WriteValue(writer, entry.Value);
            }
        }

        writer.WriteEndObject();
    }


    //Selects the concrete type to materialize from the document's id method: a did:webplus id yields the typed
    //WebPlusDidDocument, every other (or absent) id yields the base DidDocument.
    private static DidDocument CreateForMethod(JsonElement root)
    {
        if(root.TryGetProperty("id"u8, out JsonElement idElement)
            && idElement.ValueKind == JsonValueKind.String
            && idElement.GetString() is { } id
            && id.StartsWith(WebPlusMethodPrefix, StringComparison.Ordinal))
        {
            return new WebPlusDidDocument();
        }

        return new DidDocument();
    }


    //Reads a did:webplus control field into its typed property. Returns true when the property is a recognized
    //control field with a conforming shape; a recognized field with an unexpected shape returns false so the
    //value is preserved verbatim in AdditionalData rather than silently coerced.
    private static bool TryReadWebPlusField(WebPlusDidDocument webPlus, JsonProperty property)
    {
        if(property.NameEquals("selfHash"u8))
        {
            if(property.Value.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            webPlus.SelfHash = property.Value.GetString();

            return true;
        }

        if(property.NameEquals("prevDIDDocumentSelfHash"u8))
        {
            if(property.Value.ValueKind == JsonValueKind.String)
            {
                webPlus.PrevDidDocumentSelfHash = property.Value.GetString();

                return true;
            }

            //A JSON null marks a root document; it is recognized and left as the default null typed property.
            return property.Value.ValueKind == JsonValueKind.Null;
        }

        if(property.NameEquals("updateRules"u8))
        {
            webPlus.UpdateRules = property.Value.Clone();

            return true;
        }

        if(property.NameEquals("validFrom"u8))
        {
            if(property.Value.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            webPlus.ValidFrom = property.Value.GetString();

            return true;
        }

        if(property.NameEquals("versionId"u8))
        {
            if(property.Value.ValueKind != JsonValueKind.Number || !property.Value.TryGetUInt64(out ulong versionId))
            {
                return false;
            }

            webPlus.VersionId = versionId;

            return true;
        }

        return false;
    }


    //Writes the typed did:webplus control fields, each omitted when null (matching the WhenWritingNull default).
    private static void WriteWebPlusFields(Utf8JsonWriter writer, WebPlusDidDocument webPlus)
    {
        if(webPlus.SelfHash is not null)
        {
            writer.WriteString("selfHash"u8, webPlus.SelfHash);
        }

        if(webPlus.PrevDidDocumentSelfHash is not null)
        {
            writer.WriteString("prevDIDDocumentSelfHash"u8, webPlus.PrevDidDocumentSelfHash);
        }

        if(webPlus.UpdateRules is not null)
        {
            writer.WritePropertyName("updateRules"u8);
            ManualJsonWriter.WriteValue(writer, webPlus.UpdateRules);
        }

        if(webPlus.ValidFrom is not null)
        {
            writer.WriteString("validFrom"u8, webPlus.ValidFrom);
        }

        if(webPlus.VersionId is ulong versionId)
        {
            writer.WriteNumber("versionId"u8, versionId);
        }
    }


    //Deserializes a core member through its own registered converter (resolved via GetTypeInfo), so member
    //fidelity is identical to the source-generated path and this converter is not re-entered.
    private static T? Deserialize<T>(JsonElement element, JsonSerializerOptions options)
    {
        return element.Deserialize((JsonTypeInfo<T>)options.GetTypeInfo(typeof(T)));
    }


    //Writes a core member's property name and value when the value is non-null, delegating the value to its
    //registered converter via GetTypeInfo.
    private static void WriteMember<T>(Utf8JsonWriter writer, ReadOnlySpan<byte> name, T? value, JsonSerializerOptions options)
    {
        if(value is null)
        {
            return;
        }

        writer.WritePropertyName(name);
        JsonSerializer.Serialize(writer, value, (JsonTypeInfo<T>)options.GetTypeInfo(typeof(T)));
    }
}
