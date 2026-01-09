namespace Verifiable.Cbor;

/// <summary>
/// Base class for converter factories that create <see cref="CborConverter{T}"/> instances
/// for specific types at runtime.
/// </summary>
/// <remarks>
/// <para>
/// Converter factories are useful when a single converter class can handle multiple
/// related types, such as all subclasses of a base type or all implementations of an interface.
/// </para>
/// <para>
/// This follows the same pattern as <see cref="System.Text.Json.Serialization.JsonConverterFactory"/>.
/// </para>
/// </remarks>
public abstract class CborConverterFactory
{
    /// <summary>
    /// Determines whether this factory can create a converter for the specified type.
    /// </summary>
    /// <param name="typeToConvert">The type to check.</param>
    /// <returns><see langword="true"/> if this factory can create a converter; otherwise, <see langword="false"/>.</returns>
    public abstract bool CanConvert(Type typeToConvert);


    /// <summary>
    /// Creates a converter for the specified type.
    /// </summary>
    /// <param name="typeToConvert">The type being converted.</param>
    /// <param name="options">The serializer options to use.</param>
    /// <returns>A converter instance for the specified type.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the factory cannot create a converter for the specified type.
    /// </exception>
    public abstract CborConverter CreateConverter(Type typeToConvert, CborSerializerOptions options);
}


/// <summary>
/// Non-generic base class for CBOR converters to enable polymorphic storage in collections.
/// </summary>
/// <remarks>
/// This class exists to allow both <see cref="CborConverter{T}"/> and <see cref="CborConverterFactory"/>
/// instances to be stored in the same collection within <see cref="CborSerializerOptions"/>.
/// </remarks>
public abstract class CborConverter
{
    /// <summary>
    /// Determines whether the specified type can be converted by this converter.
    /// </summary>
    /// <param name="typeToConvert">The type to check.</param>
    /// <returns><see langword="true"/> if the type can be converted; otherwise, <see langword="false"/>.</returns>
    public abstract bool CanConvert(Type typeToConvert);


    /// <summary>
    /// Gets the type that this converter handles.
    /// </summary>
    internal abstract Type TypeToConvert { get; }
}