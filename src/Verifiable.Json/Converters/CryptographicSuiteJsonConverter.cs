using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Did.CryptographicSuites;

namespace Verifiable.Json.Converters;

/// <summary>
/// Factory delegate for resolving verification method type names to
/// <see cref="VerificationMethodTypeInfo"/> instances.
/// </summary>
/// <param name="verificationMethodTypeName">
/// The verification method type name from the JSON <c>type</c> property.
/// </param>
/// <returns>The corresponding <see cref="VerificationMethodTypeInfo"/> instance.</returns>
public delegate VerificationMethodTypeInfo VerificationMethodTypeInfoFactoryDelegate(string verificationMethodTypeName);


/// <summary>
/// Converts <see cref="VerificationMethodTypeInfo"/> to and from JSON.
/// </summary>
public class CryptographicSuiteJsonConverter: JsonConverter<VerificationMethodTypeInfo>
{
    private VerificationMethodTypeInfoFactoryDelegate FactoryDelegate { get; }


    /// <inheritdoc />
    public override bool CanConvert(Type typeToConvert) => typeof(VerificationMethodTypeInfo).IsAssignableFrom(typeToConvert);


    /// <summary>
    /// Creates a converter using the specified factory delegate.
    /// </summary>
    /// <param name="factoryDelegate">
    /// The delegate that resolves type name strings to <see cref="VerificationMethodTypeInfo"/>.
    /// </param>
    public CryptographicSuiteJsonConverter(VerificationMethodTypeInfoFactoryDelegate factoryDelegate)
    {
        ArgumentNullException.ThrowIfNull(factoryDelegate);
        FactoryDelegate = factoryDelegate;
    }


    /// <inheritdoc />
    public override VerificationMethodTypeInfo Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? suite = reader.GetString();
        if(suite is null)
        {
            JsonThrowHelper.ThrowJsonException("Crypto suite identifier must be a valid identifier string.");
        }

        return FactoryDelegate(suite);
    }


    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, VerificationMethodTypeInfo value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);
        writer.WriteStringValue(value.TypeName);
    }
}