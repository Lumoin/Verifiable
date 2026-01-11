using System.Formats.Cbor;

namespace Verifiable.Cbor;

/// <summary>
/// Provides options for controlling CBOR serialization and deserialization behavior.
/// </summary>
/// <remarks>
/// <para>
/// This class follows the pattern established by <see cref="System.Text.Json.JsonSerializerOptions"/>
/// to provide a familiar configuration experience. Options include conformance mode for
/// deterministic encoding, custom converters, and handling of unknown properties.
/// </para>
/// <para>
/// For cryptographic applications requiring deterministic encoding (such as signing),
/// use <see cref="CborConformanceMode.Canonical"/> or <see cref="CborConformanceMode.Ctap2Canonical"/>
/// as specified in RFC 8949 §4.2.
/// </para>
/// </remarks>
public sealed class CborSerializerOptions
{
    /// <summary>
    /// Gets the default serializer options with canonical encoding enabled.
    /// </summary>
    /// <remarks>
    /// Uses <see cref="CborConformanceMode.Canonical"/> for deterministic output
    /// suitable for cryptographic operations.
    /// </remarks>
    public static CborSerializerOptions Default { get; } = new CborSerializerOptions
    {
        ConformanceMode = CborConformanceMode.Canonical
    }.MakeReadOnly();


    /// <summary>
    /// Gets or sets the CBOR conformance mode for encoding.
    /// </summary>
    /// <value>
    /// The default is <see cref="CborConformanceMode.Lax"/>. For deterministic encoding
    /// required by cryptographic operations, use <see cref="CborConformanceMode.Canonical"/>.
    /// </value>
    /// <exception cref="InvalidOperationException">Thrown when the options instance is read-only.</exception>
    public CborConformanceMode ConformanceMode
    {
        get;
        set
        {
            VerifyMutable();
            field = value;
        }
    } = CborConformanceMode.Lax;


    /// <summary>
    /// Gets or sets a value indicating whether to allow reading of indefinite-length CBOR items.
    /// </summary>
    /// <value>
    /// <see langword="true"/> to allow indefinite-length items during reading;
    /// <see langword="false"/> to throw on indefinite-length items. The default is <see langword="true"/>.
    /// </value>
    /// <remarks>
    /// SD-CWT specification requires definite-length encoding. Set this to <see langword="false"/>
    /// when strict compliance is required.
    /// </remarks>
    /// <exception cref="InvalidOperationException">Thrown when the options instance is read-only.</exception>
    public bool AllowIndefiniteLength
    {
        get;
        set
        {
            VerifyMutable();
            field = value;
        }
    } = true;


    /// <summary>
    /// Gets or sets a value indicating whether to ignore unknown properties during deserialization.
    /// </summary>
    /// <value>
    /// <see langword="true"/> to silently skip unknown properties; <see langword="false"/> to throw.
    /// The default is <see langword="true"/>.
    /// </value>
    /// <exception cref="InvalidOperationException">Thrown when the options instance is read-only.</exception>
    public bool IgnoreUnknownProperties
    {
        get;
        set
        {
            VerifyMutable();
            field = value;
        }
    } = true;


    /// <summary>
    /// Gets or sets a value indicating whether to write null values.
    /// </summary>
    /// <value>
    /// <see langword="true"/> to write null values; <see langword="false"/> to omit them.
    /// The default is <see langword="false"/>.
    /// </value>
    /// <exception cref="InvalidOperationException">Thrown when the options instance is read-only.</exception>
    public bool WriteNullValues
    {
        get;
        set
        {
            VerifyMutable();
            field = value;
        }
    }


    /// <summary>
    /// Gets the list of custom converters to use during serialization.
    /// </summary>
    /// <remarks>
    /// Converters are checked in order. The first converter that can handle a type is used.
    /// Add both <see cref="CborConverter{T}"/> and <see cref="CborConverterFactory"/> instances.
    /// </remarks>
    public IList<object> Converters { get; } = [];


    /// <summary>
    /// Gets a value indicating whether this options instance is read-only.
    /// </summary>
    public bool IsReadOnly { get; private set; }


    /// <summary>
    /// Creates a new instance of <see cref="CborSerializerOptions"/>.
    /// </summary>
    public CborSerializerOptions()
    {
    }


    /// <summary>
    /// Creates a new instance of <see cref="CborSerializerOptions"/> by copying settings from another instance.
    /// </summary>
    /// <param name="options">The options instance to copy from.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is null.</exception>
    public CborSerializerOptions(CborSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        ConformanceMode = options.ConformanceMode;
        AllowIndefiniteLength = options.AllowIndefiniteLength;
        IgnoreUnknownProperties = options.IgnoreUnknownProperties;
        WriteNullValues = options.WriteNullValues;

        foreach(object converter in options.Converters)
        {
            Converters.Add(converter);
        }
    }


    /// <summary>
    /// Makes this options instance read-only.
    /// </summary>
    /// <returns>This instance for method chaining.</returns>
    public CborSerializerOptions MakeReadOnly()
    {
        IsReadOnly = true;
        return this;
    }


    /// <summary>
    /// Gets a converter for the specified type.
    /// </summary>
    /// <param name="typeToConvert">The type to get a converter for.</param>
    /// <returns>A converter for the type, or <see langword="null"/> if no converter is found.</returns>
    public CborConverter<T>? GetConverter<T>(Type? typeToConvert = null)
    {
        typeToConvert ??= typeof(T);

        foreach(object converter in Converters)
        {
            if(converter is CborConverter<T> typedConverter && typedConverter.CanConvert(typeToConvert))
            {
                return typedConverter;
            }

            if(converter is CborConverterFactory factory && factory.CanConvert(typeToConvert))
            {
                var created = factory.CreateConverter(typeToConvert, this);
                if(created is CborConverter<T> createdTyped)
                {
                    return createdTyped;
                }
            }
        }

        return null;
    }


    private void VerifyMutable()
    {
        if(IsReadOnly)
        {
            throw new InvalidOperationException("This CborSerializerOptions instance is read-only.");
        }
    }
}