using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Did;

namespace Verifiable.Json.Converters;

/// <summary>
/// A factory that creates converters for <see cref="VerificationMethodReference"/> subclasses.
/// </summary>
/// <remarks>
/// <para>
/// This factory creates type-specific converters for each verification relationship type
/// (<see cref="AuthenticationMethod"/>, <see cref="AssertionMethod"/>, etc.). The factory
/// pattern is required because System.Text.Json needs to instantiate the correct generic
/// converter for each concrete type.
/// </para>
/// <para>
/// <strong>Important:</strong> This factory only handles concrete subclasses, not the abstract
/// <see cref="VerificationMethodReference"/> base class directly. When deserializing properties
/// typed as the abstract base (such as in proof structures), the containing type's converter
/// must handle instantiation based on contextual information like <c>proofPurpose</c>.
/// </para>
/// </remarks>
public class VerificationMethodReferenceConverterFactory: JsonConverterFactory
{
    /// <inheritdoc/>
    public override bool CanConvert(Type typeToConvert)
    {
        //Only handle concrete subclasses, not the abstract base.
        if(typeToConvert == typeof(VerificationMethodReference))
        {
            return false;
        }

        return typeof(VerificationMethodReference).IsAssignableFrom(typeToConvert);
    }


    /// <inheritdoc/>
    public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options)
    {
        return (JsonConverter)Activator.CreateInstance(
            typeof(VerificationMethodReferenceConverter<>).MakeGenericType(typeToConvert),
            BindingFlags.Instance | BindingFlags.Public,
            binder: null,
            args: null,
            culture: null)!;
    }
}


/// <summary>
/// Converts <see cref="VerificationMethodReference"/> subclasses to and from JSON.
/// </summary>
/// <typeparam name="T">The specific verification relationship type.</typeparam>
/// <remarks>
/// <para>
/// Verification method references can be serialized in two forms:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>String:</strong> A DID URL reference like <c>"#key-1"</c> or
/// <c>"did:example:123#key-1"</c>.
/// </description></item>
/// <item><description>
/// <strong>Object:</strong> An embedded <see cref="VerificationMethod"/> with full key details.
/// </description></item>
/// </list>
/// <para>
/// This converter is used for DID document verification relationships where the
/// property name determines the purpose (e.g., <c>authentication</c>, <c>assertionMethod</c>).
/// </para>
/// </remarks>
public class VerificationMethodReferenceConverter<T>: JsonConverter<T> where T : VerificationMethodReference
{
    /// <inheritdoc/>
    public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if(reader.TokenType != JsonTokenType.String && reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException($"Expected string or object for verification method reference, but got {reader.TokenType}.");
        }

        object? constructorParameter;
        if(reader.TokenType == JsonTokenType.String)
        {
            constructorParameter = reader.GetString() ?? string.Empty;
        }
        else
        {
            constructorParameter = JsonSerializer.Deserialize<VerificationMethod>(ref reader, options);
        }

        return (T)Activator.CreateInstance(typeof(T), new object[] { constructorParameter! })!;
    }


    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
    {
        if(value.IsEmbeddedVerification)
        {
            JsonSerializer.Serialize(writer, value.EmbeddedVerification, options);
        }
        else
        {
            writer.WriteStringValue(value.VerificationReferenceId);
        }
    }
}