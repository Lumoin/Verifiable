using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using Verifiable.OAuth.Oid4Vp;

namespace Verifiable.Json.Converters;

/// <summary>
/// Converts a <see cref="VerifierClientMetadata"/> to and from its OID4VP 1.0 §11
/// <c>client_metadata</c> wire shape, with snake_case member names independent of the
/// enclosing options' naming policy.
/// </summary>
/// <remarks>
/// <para>
/// The <c>Verifiable.OAuth</c> POCO carries no <c>System.Text.Json</c> attributes (the
/// serialization firewall bans STJ from that assembly), so the wire knowledge lives
/// here. Three members need shape control the default property serializer cannot give:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <c>jwks</c> is held as a raw JSON string and MUST be emitted as a JSON object
///     (not a quoted string); it is read back as its raw text.
///   </description></item>
///   <item><description>
///     <c>vp_formats_supported</c> is the bare format map (see
///     <see cref="VpFormatsSupportedConverter"/>), not the C# <c>Formats</c> wrapper.
///   </description></item>
///   <item><description>
///     <see cref="VerifierClientMetadata.AdditionalParameters"/> are inlined as
///     sibling members and, on read, capture any members not covered by the typed
///     properties.
///   </description></item>
/// </list>
/// </remarks>
public sealed class VerifierClientMetadataConverter: JsonConverter<VerifierClientMetadata>
{
    /// <inheritdoc/>
    [return: NotNull]
    public override VerifierClientMetadata Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException($"Expected StartObject for client_metadata but got {reader.TokenType}.");
        }

        string? clientId = null;
        string? jwks = null;
        VpFormatsSupported? vpFormatsSupported = null;
        List<string>? encValues = null;
        List<string>? algValues = null;
        Dictionary<string, object>? additionalParameters = null;

        while(reader.Read())
        {
            if(reader.TokenType == JsonTokenType.EndObject)
            {
                break;
            }

            if(reader.TokenType != JsonTokenType.PropertyName)
            {
                throw new JsonException($"Expected PropertyName but got {reader.TokenType}.");
            }

            string propertyName = reader.GetString()!;
            reader.Read();

            //Match against the well-known member names via their Is* helpers. The names
            //are static readonly (not const), so this is a guarded switch, not case labels.
            switch(propertyName)
            {
                case var name when Oid4VpClientMetadataParameterNames.IsClientId(name):
                {
                    clientId = reader.GetString();
                    break;
                }
                case var name when Oid4VpClientMetadataParameterNames.IsJwks(name):
                {
                    //Capture the JWKS as raw JSON text — the application parses it with its own JWKS library.
                    jwks = ReadRawJson(ref reader);
                    break;
                }
                case var name when Oid4VpClientMetadataParameterNames.IsVpFormatsSupported(name):
                {
                    var typeInfo = (JsonTypeInfo<VpFormatsSupported>)options.GetTypeInfo(typeof(VpFormatsSupported));
                    vpFormatsSupported = JsonSerializer.Deserialize(ref reader, typeInfo);
                    break;
                }
                case var name when Oid4VpClientMetadataParameterNames.IsEncryptedResponseEncValuesSupported(name):
                {
                    encValues = ReadStringList(ref reader);
                    break;
                }
                case var name when Oid4VpClientMetadataParameterNames.IsEncryptedResponseAlgValuesSupported(name):
                {
                    algValues = ReadStringList(ref reader);
                    break;
                }
                default:
                {
                    //Preserve any unrecognised members as additional parameters (raw JSON values).
                    additionalParameters ??= new Dictionary<string, object>(StringComparer.Ordinal);
                    additionalParameters[propertyName] = ReadRawElement(ref reader);
                    break;
                }
            }
        }

        return new VerifierClientMetadata
        {
            ClientId = clientId,
            Jwks = jwks,
            VpFormatsSupported = vpFormatsSupported,
            EncryptedResponseEncValuesSupported = encValues,
            EncryptedResponseAlgValuesSupported = algValues,
            AdditionalParameters = additionalParameters
        };

        //The reader helpers below are used only here, so they are local static
        //functions; each takes the Utf8JsonReader by ref (a ref struct).
        static string ReadRawJson(ref Utf8JsonReader reader)
        {
            using JsonDocument document = JsonDocument.ParseValue(ref reader);

            return document.RootElement.GetRawText();
        }

        static JsonElement ReadRawElement(ref Utf8JsonReader reader)
        {
            using JsonDocument document = JsonDocument.ParseValue(ref reader);

            return document.RootElement.Clone();
        }

        static List<string> ReadStringList(ref Utf8JsonReader reader)
        {
            if(reader.TokenType != JsonTokenType.StartArray)
            {
                throw new JsonException($"Expected StartArray but got {reader.TokenType}.");
            }

            var list = new List<string>();

            while(reader.Read())
            {
                if(reader.TokenType == JsonTokenType.EndArray)
                {
                    break;
                }

                if(reader.TokenType != JsonTokenType.String)
                {
                    throw new JsonException($"Expected String but got {reader.TokenType}.");
                }

                list.Add(reader.GetString()!);
            }

            return list;
        }
    }


    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, VerifierClientMetadata value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(options);

        writer.WriteStartObject();

        if(value.ClientId is not null)
        {
            writer.WriteString(Oid4VpClientMetadataParameterNames.ClientId, value.ClientId);
        }

        if(value.Jwks is not null)
        {
            //jwks is held as raw JSON — emit it verbatim as a JSON object, not a quoted string.
            writer.WritePropertyName(Oid4VpClientMetadataParameterNames.Jwks);
            writer.WriteRawValue(value.Jwks);
        }

        if(value.VpFormatsSupported is not null)
        {
            writer.WritePropertyName(Oid4VpClientMetadataParameterNames.VpFormatsSupported);
            var typeInfo = (JsonTypeInfo<VpFormatsSupported>)options.GetTypeInfo(typeof(VpFormatsSupported));
            JsonSerializer.Serialize(writer, value.VpFormatsSupported, typeInfo);
        }

        if(value.EncryptedResponseEncValuesSupported is not null)
        {
            WriteStringArray(writer, Oid4VpClientMetadataParameterNames.EncryptedResponseEncValuesSupported,
                value.EncryptedResponseEncValuesSupported);
        }

        if(value.EncryptedResponseAlgValuesSupported is not null)
        {
            WriteStringArray(writer, Oid4VpClientMetadataParameterNames.EncryptedResponseAlgValuesSupported,
                value.EncryptedResponseAlgValuesSupported);
        }

        if(value.AdditionalParameters is not null)
        {
            foreach(KeyValuePair<string, object> parameter in value.AdditionalParameters)
            {
                writer.WritePropertyName(parameter.Key);
                WriteInlineValue(writer, parameter.Value);
            }
        }

        writer.WriteEndObject();
    }


    private static void WriteStringArray(Utf8JsonWriter writer, string propertyName, IReadOnlyList<string> values)
    {
        writer.WritePropertyName(propertyName);
        writer.WriteStartArray();
        foreach(string item in values)
        {
            writer.WriteStringValue(item);
        }

        writer.WriteEndArray();
    }


    private static void WriteInlineValue(Utf8JsonWriter writer, object? value)
    {
        switch(value)
        {
            case null:
            {
                writer.WriteNullValue();
                break;
            }
            case JsonElement element:
            {
                element.WriteTo(writer);
                break;
            }
            case string s:
            {
                writer.WriteStringValue(s);
                break;
            }
            case bool b:
            {
                writer.WriteBooleanValue(b);
                break;
            }
            case int i:
            {
                writer.WriteNumberValue(i);
                break;
            }
            case long l:
            {
                writer.WriteNumberValue(l);
                break;
            }
            case double d:
            {
                writer.WriteNumberValue(d);
                break;
            }
            default:
            {
                throw new JsonException(
                    $"Unsupported client_metadata additional-parameter value type '{value.GetType()}'. " +
                    $"Round-tripped values are JsonElement; programmatic values must be a JSON primitive.");
            }
        }
    }
}
