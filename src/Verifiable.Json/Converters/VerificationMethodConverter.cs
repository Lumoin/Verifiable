using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;

namespace Verifiable.Json.Converters;

/// <summary>
/// Converts <see cref="VerificationMethod"/> to and from JSON.
/// </summary>
/// <remarks>
/// <para>
/// This converter handles three distinct dispatch mechanisms:
/// </para>
/// <list type="number">
/// <item>
/// <description>
/// <strong>Subclass dispatch</strong> via <see cref="VerificationMethodTypeSelector"/>:
/// determines which .NET type to instantiate based on the <c>type</c> discriminator.
/// Enables subclasses that carry additional properties as permitted by CID 1.1.
/// </description>
/// </item>
/// <item>
/// <description>
/// <strong>Crypto suite metadata</strong> via <see cref="VerificationMethodTypeInfoFactoryDelegate"/>:
/// maps the <c>type</c> string to <see cref="VerificationMethodTypeInfo"/> for suite-specific behavior.
/// </description>
/// </item>
/// <item>
/// <description>
/// <strong>Key format dispatch</strong> via <see cref="KeyFormatReaderDelegate"/> and
/// <see cref="KeyFormatWriterDelegate"/>: the JSON property name determines the
/// <see cref="KeyFormat"/> subclass on read, and the runtime type determines the
/// property name on write. Both delegates use pattern matching and support
/// chaining for user-defined key formats.
/// </description>
/// </item>
/// </list>
/// <para>
/// When the type selector returns <c>typeof(VerificationMethod)</c> (the default for all
/// known suite types), the converter manually parses the JSON object. This avoids
/// re-entrant serialization and keeps the converter fully AOT-compatible. When the selector
/// returns a derived type, the converter uses <see cref="JsonSerializerOptions.GetTypeInfo"/>
/// for AOT-friendly deserialization. Since <see cref="CanConvert"/> only matches the base
/// <see cref="VerificationMethod"/> type, STJ handles derived types without re-entering.
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
///
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
///
/// options.Converters.Add(new VerificationMethodConverter(
///     VerificationMethodTypeSelectors.Default,
///     myReader,
///     myWriter));
/// </code>
/// </remarks>
public class VerificationMethodConverter: JsonConverter<VerificationMethod>
{
    private static VerificationMethodTypeInfoFactoryDelegate DefaultTypeInfoFactory { get; } = typeName => typeName switch
    {
        _ when typeName == VerificationMethodTypeInfo.JsonWebKey2020.TypeName => VerificationMethodTypeInfo.JsonWebKey2020, "JsonWebKey" => VerificationMethodTypeInfo.JsonWebKey2020,
        _ when typeName == VerificationMethodTypeInfo.Ed25519VerificationKey2020.TypeName => VerificationMethodTypeInfo.Ed25519VerificationKey2020,
        _ when typeName == VerificationMethodTypeInfo.Secp256k1VerificationKey2018.TypeName => VerificationMethodTypeInfo.Secp256k1VerificationKey2018,
        _ when typeName == VerificationMethodTypeInfo.Multikey.TypeName => VerificationMethodTypeInfo.Multikey,
        _ when typeName == VerificationMethodTypeInfo.RsaVerificationKey2018.TypeName => VerificationMethodTypeInfo.RsaVerificationKey2018,
        _ when typeName == VerificationMethodTypeInfo.JwsVerificationKey2020.TypeName => VerificationMethodTypeInfo.JwsVerificationKey2020,
        _ when typeName == VerificationMethodTypeInfo.Ed25519VerificationKey2018.TypeName => VerificationMethodTypeInfo.Ed25519VerificationKey2018,
        _ when typeName == VerificationMethodTypeInfo.X25519KeyAgreementKey2020.TypeName => VerificationMethodTypeInfo.X25519KeyAgreementKey2020,
        _ when typeName == VerificationMethodTypeInfo.X25519KeyAgreementKey2019.TypeName => VerificationMethodTypeInfo.X25519KeyAgreementKey2019,
        _ => throw new ArgumentException($"Unknown verification method type: '{typeName}'.")
    };

    private VerificationMethodTypeSelector TypeSelector { get; }
    private VerificationMethodTypeInfoFactoryDelegate TypeInfoFactory { get; }
    private KeyFormatReaderDelegate KeyFormatReader { get; }
    private KeyFormatWriterDelegate KeyFormatWriter { get; }


    /// <summary>
    /// Creates a converter with all default settings.
    /// </summary>
    public VerificationMethodConverter()
        : this(VerificationMethodTypeSelectors.Default, DefaultTypeInfoFactory, KeyFormatDefaults.Reader, KeyFormatDefaults.Writer)
    {
    }


    /// <summary>
    /// Creates a converter with a custom type selector and default handling for
    /// crypto suites and key formats.
    /// </summary>
    /// <param name="typeSelector">
    /// The delegate that maps verification method <c>type</c> strings to .NET types.
    /// </param>
    public VerificationMethodConverter(VerificationMethodTypeSelector typeSelector): this(typeSelector, DefaultTypeInfoFactory, KeyFormatDefaults.Reader, KeyFormatDefaults.Writer)
    {
    }


    /// <summary>
    /// Creates a converter with custom type selector and key format delegates.
    /// </summary>
    /// <param name="typeSelector">
    /// The delegate that maps verification method <c>type</c> strings to .NET types.
    /// </param>
    /// <param name="keyFormatReader">
    /// The delegate that reads key format from a JSON property by matching the property name.
    /// </param>
    /// <param name="keyFormatWriter">
    /// The delegate that writes key format to JSON by matching the runtime type.
    /// </param>
    public VerificationMethodConverter(
        VerificationMethodTypeSelector typeSelector,
        KeyFormatReaderDelegate keyFormatReader,
        KeyFormatWriterDelegate keyFormatWriter)
        : this(typeSelector, DefaultTypeInfoFactory, keyFormatReader, keyFormatWriter)
    {
    }


    /// <summary>
    /// Creates a converter with full control over all dispatch mechanisms.
    /// </summary>
    /// <param name="typeSelector">
    /// The delegate that maps verification method <c>type</c> strings to .NET types.
    /// </param>
    /// <param name="typeInfoFactory">
    /// The delegate that maps type strings to <see cref="VerificationMethodTypeInfo"/> for
    /// crypto suite metadata.
    /// </param>
    /// <param name="keyFormatReader">
    /// The delegate that reads key format from a JSON property by matching the property name.
    /// </param>
    /// <param name="keyFormatWriter">
    /// The delegate that writes key format to JSON by matching the runtime type.
    /// </param>
    public VerificationMethodConverter(
        VerificationMethodTypeSelector typeSelector,
        VerificationMethodTypeInfoFactoryDelegate typeInfoFactory,
        KeyFormatReaderDelegate keyFormatReader,
        KeyFormatWriterDelegate keyFormatWriter)
    {
        ArgumentNullException.ThrowIfNull(typeSelector);
        ArgumentNullException.ThrowIfNull(typeInfoFactory);
        ArgumentNullException.ThrowIfNull(keyFormatReader);
        ArgumentNullException.ThrowIfNull(keyFormatWriter);
        TypeSelector = typeSelector;
        TypeInfoFactory = typeInfoFactory;
        KeyFormatReader = keyFormatReader;
        KeyFormatWriter = keyFormatWriter;
    }


    /// <inheritdoc />
    public override bool CanConvert(Type typeToConvert)
    {
        return typeToConvert == typeof(VerificationMethod);
    }


    /// <inheritdoc />
    public override VerificationMethod Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if(reader.TokenType != JsonTokenType.StartObject)
        {
            JsonThrowHelper.ThrowJsonException();
        }

        using(var document = JsonDocument.ParseValue(ref reader))
        {
            var element = document.RootElement;

            if(!element.TryGetProperty("type", out var typeElement))
            {
                JsonThrowHelper.ThrowJsonException("Verification method is missing the required 'type' property.");
            }

            var typeString = typeElement.GetString();
            if(string.IsNullOrEmpty(typeString))
            {
                JsonThrowHelper.ThrowJsonException("Verification method 'type' property must not be null or empty.");
            }

            Type targetType = TypeSelector(typeString);

            //Base type: manual parse to avoid re-entering this converter.
            if(targetType == typeof(VerificationMethod))
            {
                return ReadBaseVerificationMethod(element, typeString, options);
            }

            //Derived type: AOT-friendly deserialization. Since CanConvert only
            //matches typeof(VerificationMethod), STJ won't re-enter this converter.
            var typeInfo = options.GetTypeInfo(targetType);
            var derived = (VerificationMethod)JsonSerializer.Deserialize(element, typeInfo)!;
            derived.Type = TypeInfoFactory(typeString).TypeName;

            //Key format dispatch for derived types too.
            foreach(var property in element.EnumerateObject())
            {
                var keyFormat = KeyFormatReader(property, options);
                if(keyFormat is not null)
                {
                    derived.KeyFormat = keyFormat;
                    return derived;
                }
            }

            JsonThrowHelper.ThrowJsonException($"Could not find a key format for verification method type '{typeString}'.");
            return null!;
        }
    }


    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, VerificationMethod value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(options);

        //Derived type: AOT-friendly serialization. Since CanConvert only matches
        //typeof(VerificationMethod), STJ won't re-enter this converter.
        if(value.GetType() != typeof(VerificationMethod))
        {
            var typeInfo = options.GetTypeInfo(value.GetType());
            JsonSerializer.Serialize(writer, value, typeInfo);
            return;
        }

        //Base type: manual write to avoid re-entering this converter.
        WriteBaseVerificationMethod(writer, value);
    }


    /// <summary>
    /// Manually parses a <see cref="VerificationMethod"/> from a JSON object. Reads
    /// known properties, resolves crypto suite metadata via <see cref="TypeInfoFactory"/>,
    /// and dispatches key format via <see cref="KeyFormatReader"/>.
    /// </summary>
    private VerificationMethod ReadBaseVerificationMethod(
        JsonElement element,
        string typeString,
        JsonSerializerOptions options)
    {
        //Convert the type string to the canonical type name via the factory.
        var vm = new VerificationMethod
        {
            Type = TypeInfoFactory(typeString).TypeName
        };

        KeyFormat? keyFormat = null;

        foreach(var property in element.EnumerateObject())
        {
            if(property.NameEquals("id"u8))
            {
                vm.Id = property.Value.GetString();
            }
            else if(property.NameEquals("type"u8))
            {
                //Already handled via TypeInfoFactory above.
            }
            else if(property.NameEquals("controller"u8))
            {
                vm.Controller = property.Value.GetString();
            }
            else if(property.NameEquals("expires"u8))
            {
                vm.Expires = property.Value.GetString();
            }
            else if(property.NameEquals("revoked"u8))
            {
                vm.Revoked = property.Value.GetString();
            }
            else
            {
                //Try key format delegate for any unrecognized property.
                var kf = KeyFormatReader(property, options);
                if(kf is not null)
                {
                    keyFormat = kf;
                }
            }
        }

        if(keyFormat is not null)
        {
            vm.KeyFormat = keyFormat;
        }

        return vm;
    }


    /// <summary>
    /// Manually writes a base <see cref="VerificationMethod"/> to JSON, including the
    /// key format via <see cref="KeyFormatWriter"/>.
    /// </summary>
    private void WriteBaseVerificationMethod(Utf8JsonWriter writer, VerificationMethod vm)
    {
        writer.WriteStartObject();

        if(vm.Id is not null)
        {
            writer.WriteString("id"u8, vm.Id);
        }

        if(vm.Type is not null)
        {
            writer.WriteString("type"u8, vm.Type);
        }

        if(vm.Controller is not null)
        {
            writer.WriteString("controller"u8, vm.Controller);
        }

        if(vm.Expires is not null)
        {
            writer.WriteString("expires"u8, vm.Expires);
        }

        if(vm.Revoked is not null)
        {
            writer.WriteString("revoked"u8, vm.Revoked);
        }

        if(vm.KeyFormat is not null)
        {
            if(!KeyFormatWriter(writer, vm.KeyFormat))
            {
                JsonThrowHelper.ThrowJsonException($"No handler for key format type '{vm.KeyFormat.GetType().Name}'.");
            }
        }

        writer.WriteEndObject();
    }
}