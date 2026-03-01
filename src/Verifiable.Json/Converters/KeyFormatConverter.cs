using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Did;

namespace Verifiable.Json.Converters;

/// <summary>
/// Provides write-side serialization of <see cref="KeyFormat"/> for STJ.
/// </summary>
/// <remarks>
/// <para>
/// This converter wraps a <see cref="KeyFormatWriterDelegate"/> so that STJ
/// can correctly serialize the polymorphic <see cref="KeyFormat"/> property
/// when <see cref="VerificationMethodConverter"/> delegates to inner options.
/// </para>
/// <para>
/// Read-side deserialization is not handled here because the JSON property name
/// (e.g., <c>publicKeyMultibase</c>, <c>publicKeyJwk</c>) determines the
/// <see cref="KeyFormat"/> subclass, and STJ has already consumed the property
/// name before calling the converter. The <see cref="VerificationMethodConverter"/>
/// performs read-side dispatch by scanning the JSON object with a
/// <see cref="KeyFormatReaderDelegate"/>.
/// </para>
/// <para>
/// This converter is internal plumbing used by <see cref="VerificationMethodConverter"/>
/// in its inner options. Application developers interact with
/// <see cref="KeyFormatReaderDelegate"/> and <see cref="KeyFormatWriterDelegate"/>
/// directly.
/// </para>
/// </remarks>
internal sealed class KeyFormatConverter: JsonConverter<KeyFormat>
{
    private KeyFormatWriterDelegate WriterDelegate { get; }


    /// <summary>
    /// Creates a converter wrapping the specified write delegate.
    /// </summary>
    /// <param name="writerDelegate">The delegate that handles key format serialization.</param>
    public KeyFormatConverter(KeyFormatWriterDelegate writerDelegate)
    {
        ArgumentNullException.ThrowIfNull(writerDelegate);
        WriterDelegate = writerDelegate;
    }


    /// <inheritdoc />
    public override bool CanConvert(Type typeToConvert)
    {
        return typeof(KeyFormat).IsAssignableFrom(typeToConvert);
    }


    /// <inheritdoc />
    public override KeyFormat Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        //Read-side dispatch requires the JSON property name, which STJ has already
        //consumed before calling the converter. VerificationMethodConverter handles
        //read-side key format dispatch by scanning the JSON object with a
        //KeyFormatReaderDelegate. This method is never called during normal operation.
        throw new NotSupportedException(
            "KeyFormat read-side dispatch requires the JSON property name. " +
            "Use VerificationMethodConverter for deserialization.");
    }


    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, KeyFormat value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        if(!WriterDelegate(writer, value))
        {
            JsonThrowHelper.ThrowJsonException($"No handler for key format type '{value.GetType().Name}'.");
        }
    }
}