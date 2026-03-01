using System.Text.Json;
using Verifiable.Core.Model.Did;

namespace Verifiable.Json.Converters;

/// <summary>
/// Reads a key format from a JSON property. The delegate receives the property
/// (with both name and value accessible) and returns the deserialized
/// <see cref="KeyFormat"/> if the property name matches, or <see langword="null"/>
/// to pass through to the next handler in a chain.
/// </summary>
/// <remarks>
/// <para>
/// Key formats in DID documents are polymorphic based on the JSON property name
/// rather than a type discriminator value inside the object. The delegate uses
/// <see cref="JsonProperty.NameEquals(ReadOnlySpan{byte})"/> for zero-allocation
/// UTF-8 property name matching.
/// </para>
/// <para>
/// <strong>Extensibility:</strong>
/// </para>
/// <code>
/// var baseReader = KeyFormatDefaults.Reader;
/// KeyFormatReaderDelegate myReader = (property, options) =>
/// {
///     if(property.NameEquals("publicKeyBase64Url"u8))
///     {
///         return new PublicKeyBase64Url(property.Value.GetString()!);
///     }
///
///     return baseReader(property, options);
/// };
/// </code>
/// </remarks>
/// <param name="property">The JSON property with name and value.</param>
/// <param name="options">The serializer options for nested deserialization.</param>
/// <returns>The deserialized key format, or <see langword="null"/> if the property name is not recognized.</returns>
public delegate KeyFormat? KeyFormatReaderDelegate(JsonProperty property, JsonSerializerOptions options);

/// <summary>
/// Writes a key format to JSON. The delegate receives the writer and the
/// <see cref="KeyFormat"/> instance, and returns <see langword="true"/> if it
/// handled the write, or <see langword="false"/> to pass through to the next
/// handler in a chain.
/// </summary>
/// <remarks>
/// <para>
/// The delegate is responsible for writing both the JSON property name and value
/// (e.g., <c>"publicKeyMultibase": "z6Mk..."</c>).
/// </para>
/// <para>
/// <strong>Extensibility:</strong>
/// </para>
/// <code>
/// var baseWriter = KeyFormatDefaults.Writer;
/// KeyFormatWriterDelegate myWriter = (writer, keyFormat) =>
/// {
///     if(keyFormat is PublicKeyBase64Url b64)
///     {
///         writer.WriteString("publicKeyBase64Url"u8, b64.Key);
///         return true;
///     }
///
///     return baseWriter(writer, keyFormat);
/// };
/// </code>
/// </remarks>
/// <param name="writer">The JSON writer.</param>
/// <param name="keyFormat">The key format to serialize.</param>
/// <returns><see langword="true"/> if the key format was handled; <see langword="false"/> otherwise.</returns>
public delegate bool KeyFormatWriterDelegate(Utf8JsonWriter writer, KeyFormat keyFormat);

/// <summary>
/// Provides default key format reader and writer delegates for standard DID Core key formats.
/// </summary>
/// <remarks>
/// <para>
/// Supported key formats:
/// </para>
/// <list type="bullet">
/// <item><description><c>publicKeyMultibase</c> — <see cref="PublicKeyMultibase"/>.</description></item>
/// <item><description><c>publicKeyJwk</c> — <see cref="PublicKeyJwk"/>.</description></item>
/// <item><description><c>publicKeyBase58</c> — <see cref="PublicKeyBase58"/>.</description></item>
/// <item><description><c>publicKeyPem</c> — <see cref="PublicKeyPem"/>.</description></item>
/// <item><description><c>publicKeyHex</c> — <see cref="PublicKeyHex"/>.</description></item>
/// </list>
/// </remarks>
#pragma warning disable CS0618
public static class KeyFormatDefaults
{
    /// <summary>
    /// Default reader that recognizes all standard DID Core key format property names.
    /// Returns <see langword="null"/> for unrecognized properties.
    /// </summary>
    public static KeyFormatReaderDelegate Reader { get; } = (property, options) =>
    {
        if(property.NameEquals("publicKeyMultibase"u8))
        {
            return new PublicKeyMultibase(property.Value.GetString()!);
        }

        if(property.NameEquals("publicKeyJwk"u8))
        {
            var headers = JsonSerializer.Deserialize<Dictionary<string, object>>(property.Value.GetRawText(), options)!;
            return new PublicKeyJwk { Header = headers };
        }

        if(property.NameEquals("publicKeyBase58"u8))
        {
            return new PublicKeyBase58(property.Value.GetString()!);
        }

        if(property.NameEquals("publicKeyPem"u8))
        {
            return new PublicKeyPem(property.Value.GetString()!);
        }

        if(property.NameEquals("publicKeyHex"u8))
        {
            return new PublicKeyHex(property.Value.GetString()!);
        }

        return null;
    };

    /// <summary>
    /// Default writer that handles all standard DID Core key format types.
    /// Returns <see langword="false"/> for unrecognized types.
    /// </summary>
    public static KeyFormatWriterDelegate Writer { get; } = (writer, keyFormat) =>
    {
        switch(keyFormat)
        {
            case PublicKeyMultibase mb:
            {
                writer.WriteString("publicKeyMultibase"u8, mb.Key);
                return true;
            }
            case PublicKeyJwk jwk:
            {
                writer.WriteStartObject("publicKeyJwk"u8);
                foreach(var header in jwk.Header)
                {
                    writer.WriteString(header.Key, (string)header.Value);
                }

                writer.WriteEndObject();
                return true;
            }
            case PublicKeyBase58 b58:
            {
                writer.WriteString("publicKeyBase58"u8, b58.Key);
                return true;
            }
            case PublicKeyPem pem:
            {
                writer.WriteString("publicKeyPem"u8, pem.Key);
                return true;
            }
            case PublicKeyHex hex:
            {
                writer.WriteString("publicKeyHex"u8, hex.Key);
                return true;
            }
            default:
            {
                return false;
            }
        }
    };
}
#pragma warning restore CS0618