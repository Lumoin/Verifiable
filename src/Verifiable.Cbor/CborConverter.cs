using System.Formats.Cbor;

namespace Verifiable.Cbor;

/// <summary>
/// Base class for CBOR converters that handle serialization and deserialization
/// of specific types to and from CBOR format.
/// </summary>
/// <typeparam name="T">The type to convert.</typeparam>
/// <remarks>
/// <para>
/// This follows the same pattern as <see cref="System.Text.Json.Serialization.JsonConverter{T}"/>
/// to provide a familiar API for library consumers. Unlike JSON converters, CBOR converters
/// work with <see cref="CborReader"/> and <see cref="CborWriter"/> from System.Formats.Cbor.
/// </para>
/// <para>
/// Implementations should handle deterministic encoding requirements when
/// <see cref="CborSerializerOptions.ConformanceMode"/> is set to
/// <see cref="CborConformanceMode.Canonical"/> or <see cref="CborConformanceMode.Ctap2Canonical"/>.
/// </para>
/// </remarks>
public abstract class CborConverter<T>
{
    /// <summary>
    /// Determines whether the specified type can be converted by this converter.
    /// </summary>
    /// <param name="typeToConvert">The type to check.</param>
    /// <returns><see langword="true"/> if the type can be converted; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// The default implementation returns <see langword="true"/> if <paramref name="typeToConvert"/>
    /// is assignable to <typeparamref name="T"/>.
    /// </remarks>
    public virtual bool CanConvert(Type typeToConvert)
    {
        return typeof(T).IsAssignableFrom(typeToConvert);
    }


    /// <summary>
    /// Reads and converts CBOR data to the target type.
    /// </summary>
    /// <param name="reader">The CBOR reader to read from.</param>
    /// <param name="typeToConvert">The type being converted.</param>
    /// <param name="options">The serializer options to use.</param>
    /// <returns>The deserialized value.</returns>
    /// <exception cref="CborContentException">Thrown when the CBOR content is invalid for the target type.</exception>
    public abstract T? Read(ref CborReader reader, Type typeToConvert, CborSerializerOptions options);


    /// <summary>
    /// Writes a value as CBOR.
    /// </summary>
    /// <param name="writer">The CBOR writer to write to.</param>
    /// <param name="value">The value to convert.</param>
    /// <param name="options">The serializer options to use.</param>
    public abstract void Write(CborWriter writer, T value, CborSerializerOptions options);
}