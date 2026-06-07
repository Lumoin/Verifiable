using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using static Verifiable.Json.Converters.CredentialConverterShared;

namespace Verifiable.Json.Converters;

/// <summary>
/// Converts <see cref="VerifiablePresentation"/> to and from JSON, flattening the
/// open-world <see cref="VerifiablePresentation.AdditionalData"/> bucket at the object root
/// and handling the heterogeneous <c>verifiableCredential</c> array.
/// </summary>
/// <remarks>
/// <para>
/// VC Data Model 2.0 carries both JSON-LD credentials and enveloping-secured credentials
/// inside the single <c>verifiableCredential</c> array. The model splits these into two
/// typed lists — <see cref="VerifiablePresentation.VerifiableCredential"/> and
/// <see cref="VerifiablePresentation.EnvelopedVerifiableCredential"/> — which this converter
/// merges on write and discriminates on read: an element whose <c>type</c> contains
/// <see cref="CredentialConstants.EnvelopedVerifiableCredentialType"/> and whose <c>id</c>
/// is a <c>data:</c> URL is an <see cref="EnvelopedVerifiableCredential"/>; any other element
/// is a <see cref="VerifiableCredential"/> (its securing state resolved by
/// <see cref="VerifiableCredentialConverter"/>).
/// </para>
/// <para>
/// The presentation's securing state mirrors the credential side: a present <c>proof</c>
/// member reads as a <see cref="DataIntegritySecuredPresentation"/> (upcasting keeps the
/// proof from being silently dropped when a caller deserializes the open base type), and
/// the member is written only for an embedded-secured instance.
/// </para>
/// </remarks>
public class VerifiablePresentationConverter: JsonConverter<VerifiablePresentation>
{
    private const string DataUrlScheme = "data:";


    /// <inheritdoc/>
    public override bool CanConvert(Type typeToConvert)
    {
        return typeToConvert == typeof(VerifiablePresentation)
            || typeToConvert == typeof(DataIntegritySecuredPresentation);
    }


    /// <inheritdoc/>
    public override VerifiablePresentation Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if(reader.TokenType != JsonTokenType.StartObject)
        {
            JsonThrowHelper.ThrowJsonException("Expected StartObject when reading a VerifiablePresentation.");
        }

        using var document = JsonDocument.ParseValue(ref reader);
        var root = document.RootElement;

        var hasProof = root.TryGetProperty("proof", out var proofElement)
            && proofElement.ValueKind != JsonValueKind.Null;

        var presentation = hasProof || typeToConvert == typeof(DataIntegritySecuredPresentation)
            ? new DataIntegritySecuredPresentation()
            : new VerifiablePresentation();

        Dictionary<string, object>? additionalData = null;

        foreach(var property in root.EnumerateObject())
        {
            switch(property.Name)
            {
                case "@context":
                {
                    presentation.Context = Deserialize<Context>(property.Value, options);
                    break;
                }
                case "id":
                {
                    presentation.Id = property.Value.GetString();
                    break;
                }
                case "type":
                {
                    presentation.Type = ReadStringList(property.Value);
                    break;
                }
                case "holder":
                {
                    presentation.Holder = property.Value.GetString();
                    break;
                }
                case "verifiableCredential":
                {
                    ReadCredentialArray(property.Value, presentation, options);
                    break;
                }
                case "proof":
                {
                    if(hasProof)
                    {
                        ((DataIntegritySecuredPresentation)presentation).Proof = ReadProofs(property.Value, options);
                    }

                    break;
                }
                case "termsOfUse":
                {
                    presentation.TermsOfUse = Deserialize<List<TermsOfUse>>(property.Value, options);
                    break;
                }
                default:
                {
                    AdditionalDataJson.AddFromElement(ref additionalData, property.Name, property.Value);
                    break;
                }
            }
        }

        presentation.AdditionalData = additionalData;

        return presentation;
    }


    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, VerifiablePresentation value, JsonSerializerOptions options)
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

        if(value.Holder is not null)
        {
            writer.WriteString("holder", value.Holder);
        }

        WriteCredentialArray(writer, value, options);

        if(value is DataIntegritySecuredPresentation secured && secured.Proof is not null)
        {
            writer.WritePropertyName("proof");
            WriteMember(writer, typeof(List<DataIntegrityProof>), secured.Proof, options);
        }

        if(value.TermsOfUse is not null)
        {
            writer.WritePropertyName("termsOfUse");
            WriteMember(writer, typeof(List<TermsOfUse>), value.TermsOfUse, options);
        }

        AdditionalDataJson.WriteEntries(writer, value.AdditionalData);

        writer.WriteEndObject();
    }


    //Reads the heterogeneous verifiableCredential array, routing each element to either the
    //enveloped-credential list or the credential list per its type/id discriminators.
    private static void ReadCredentialArray(JsonElement array, VerifiablePresentation presentation, JsonSerializerOptions options)
    {
        if(array.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        List<VerifiableCredential>? credentials = null;
        List<EnvelopedVerifiableCredential>? enveloped = null;

        foreach(var element in array.EnumerateArray())
        {
            if(IsEnveloped(element))
            {
                enveloped ??= [];
                enveloped.Add(ReadEnveloped(element, options));
            }
            else
            {
                credentials ??= [];
                credentials.Add(Deserialize<VerifiableCredential>(element, options)!);
            }
        }

        presentation.VerifiableCredential = credentials;
        presentation.EnvelopedVerifiableCredential = enveloped;
    }


    //An element is an EnvelopedVerifiableCredential when its type names that token and its
    //id is a data: URL carrying the secured credential (VC-DM 2.0 §3.3).
    private static bool IsEnveloped(JsonElement element)
    {
        if(element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        if(!element.TryGetProperty("id", out var idElement)
            || idElement.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        var id = idElement.GetString();
        if(id is null || !id.StartsWith(DataUrlScheme, StringComparison.Ordinal))
        {
            return false;
        }

        if(!element.TryGetProperty("type", out var typeElement))
        {
            return false;
        }

        return TypeContains(typeElement, CredentialConstants.EnvelopedVerifiableCredentialType);
    }


    private static bool TypeContains(JsonElement typeElement, string expected)
    {
        if(typeElement.ValueKind == JsonValueKind.String)
        {
            return string.Equals(typeElement.GetString(), expected, StringComparison.Ordinal);
        }

        if(typeElement.ValueKind == JsonValueKind.Array)
        {
            foreach(var item in typeElement.EnumerateArray())
            {
                if(item.ValueKind == JsonValueKind.String
                    && string.Equals(item.GetString(), expected, StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }


    private static EnvelopedVerifiableCredential ReadEnveloped(JsonElement element, JsonSerializerOptions options)
    {
        var enveloped = new EnvelopedVerifiableCredential();

        if(element.TryGetProperty("@context", out var contextElement))
        {
            enveloped.Context = Deserialize<Context>(contextElement, options);
        }

        if(element.TryGetProperty("id", out var idElement))
        {
            enveloped.Id = idElement.GetString();
        }

        if(element.TryGetProperty("type", out var typeElement))
        {
            enveloped.Type = ReadStringList(typeElement);
        }

        return enveloped;
    }


    //Writes both credential lists into the single verifiableCredential array. The array is
    //omitted entirely when neither list is present, preserving the prior null-omission shape.
    private static void WriteCredentialArray(Utf8JsonWriter writer, VerifiablePresentation value, JsonSerializerOptions options)
    {
        var credentials = value.VerifiableCredential;
        var enveloped = value.EnvelopedVerifiableCredential;
        if(credentials is null && enveloped is null)
        {
            return;
        }

        writer.WriteStartArray("verifiableCredential");

        if(credentials is not null)
        {
            for(int i = 0; i < credentials.Count; ++i)
            {
                WriteMember(writer, typeof(VerifiableCredential), credentials[i], options);
            }
        }

        if(enveloped is not null)
        {
            for(int i = 0; i < enveloped.Count; ++i)
            {
                WriteEnveloped(writer, enveloped[i], options);
            }
        }

        writer.WriteEndArray();
    }


    private static void WriteEnveloped(Utf8JsonWriter writer, EnvelopedVerifiableCredential enveloped, JsonSerializerOptions options)
    {
        writer.WriteStartObject();

        //VC-DM 2.0: the enveloped object's @context MUST be present, also when the
        //object rides inside the presentation's verifiableCredential array.
        if(enveloped.Context is not null)
        {
            writer.WritePropertyName("@context");
            WriteMember(writer, typeof(Context), enveloped.Context, options);
        }

        if(enveloped.Id is not null)
        {
            writer.WriteString("id", enveloped.Id);
        }

        if(enveloped.Type is not null)
        {
            WriteStringList(writer, "type", enveloped.Type);
        }

        writer.WriteEndObject();
    }
}
