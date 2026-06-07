using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using static Verifiable.Json.Converters.CredentialConverterShared;

namespace Verifiable.Json.Converters;

/// <summary>
/// Converts <see cref="EnvelopedVerifiablePresentation"/> to and from its wire form: a
/// JSON object whose <c>@context</c> MUST be present, whose <c>id</c> MUST be a
/// <c>data:</c> URL carrying the enveloping-secured presentation, and whose <c>type</c>
/// MUST be <c>EnvelopedVerifiablePresentation</c> (VC-DM 2.0 §4.13 Enveloped Verifiable
/// Presentations). The converter is faithful — it round-trips the members; the MUSTs are
/// the producer's and consumer's to enforce.
/// </summary>
public class EnvelopedVerifiablePresentationConverter: JsonConverter<EnvelopedVerifiablePresentation>
{
    /// <inheritdoc/>
    public override EnvelopedVerifiablePresentation Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if(reader.TokenType != JsonTokenType.StartObject)
        {
            JsonThrowHelper.ThrowJsonException("Expected StartObject when reading an EnvelopedVerifiablePresentation.");
        }

        using var document = JsonDocument.ParseValue(ref reader);
        var root = document.RootElement;

        var enveloped = new EnvelopedVerifiablePresentation();

        if(root.TryGetProperty("@context", out var contextElement))
        {
            enveloped.Context = Deserialize<Context>(contextElement, options);
        }

        if(root.TryGetProperty("id", out var idElement))
        {
            enveloped.Id = idElement.GetString();
        }

        if(root.TryGetProperty("type", out var typeElement))
        {
            enveloped.Type = ReadStringList(typeElement);
        }

        return enveloped;
    }


    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, EnvelopedVerifiablePresentation value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(options);

        writer.WriteStartObject();

        if(value.Context is not null)
        {
            writer.WritePropertyName("@context");
            WriteMember(writer, typeof(Context), value.Context, options);
        }

        if(value.Id is not null)
        {
            writer.WriteString("id", value.Id);
        }

        if(value.Type is not null)
        {
            WriteStringList(writer, "type", value.Type);
        }

        writer.WriteEndObject();
    }
}
