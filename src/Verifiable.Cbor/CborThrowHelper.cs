using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using System.Runtime.CompilerServices;

namespace Verifiable.Cbor;

/// <summary>
/// Helper methods to throw exceptions. Extracting throw makes conditional branches smaller,
/// more inlinable, and reduces generic codegen size.
/// </summary>
/// <remarks>
/// Based on the pattern from System.Text.Json ThrowHelper classes. Using dedicated throw
/// helpers improves JIT optimization of hot paths by keeping exception-throwing code
/// out of line.
/// </remarks>
public static class CborThrowHelper
{
    /// <summary>
    /// Throws a <see cref="CborContentException"/> with no message.
    /// </summary>
    [DoesNotReturn]
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void ThrowCborContentException()
    {
        throw new CborContentException("Invalid CBOR content.");
    }


    /// <summary>
    /// Throws a <see cref="CborContentException"/> with the specified message.
    /// </summary>
    /// <param name="message">The exception message.</param>
    [DoesNotReturn]
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void ThrowCborContentException(string message)
    {
        throw new CborContentException(message);
    }


    /// <summary>
    /// Throws a <see cref="CborContentException"/> indicating an unexpected CBOR type.
    /// </summary>
    /// <param name="expected">The expected CBOR reader state.</param>
    /// <param name="actual">The actual CBOR reader state encountered.</param>
    [DoesNotReturn]
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void ThrowUnexpectedCborType(CborReaderState expected, CborReaderState actual)
    {
        throw new CborContentException($"Expected CBOR type {expected}, but encountered {actual}.");
    }


    /// <summary>
    /// Throws a <see cref="CborContentException"/> indicating an unexpected CBOR type with context.
    /// </summary>
    /// <param name="expected">The expected CBOR reader state.</param>
    /// <param name="actual">The actual CBOR reader state encountered.</param>
    /// <param name="context">Additional context about where the error occurred.</param>
    [DoesNotReturn]
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void ThrowUnexpectedCborType(CborReaderState expected, CborReaderState actual, string context)
    {
        throw new CborContentException($"Expected CBOR type {expected} for {context}, but encountered {actual}.");
    }


    /// <summary>
    /// Throws a <see cref="CborContentException"/> indicating an unexpected CBOR type.
    /// </summary>
    /// <param name="expectedDescription">Description of the expected CBOR type.</param>
    /// <param name="actual">The actual CBOR reader state encountered.</param>
    [DoesNotReturn]
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void ThrowUnexpectedCborType(string expectedDescription, CborReaderState actual)
    {
        throw new CborContentException($"Expected {expectedDescription}, but encountered {actual}.");
    }


    /// <summary>
    /// Throws a <see cref="CborContentException"/> indicating an invalid array length.
    /// </summary>
    /// <param name="expected">The expected array length.</param>
    /// <param name="actual">The actual array length.</param>
    [DoesNotReturn]
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void ThrowInvalidArrayLength(int expected, int actual)
    {
        throw new CborContentException($"Expected CBOR array with {expected} elements, but found {actual}.");
    }


    /// <summary>
    /// Throws a <see cref="CborContentException"/> indicating an invalid array length range.
    /// </summary>
    /// <param name="minimum">The minimum expected array length.</param>
    /// <param name="maximum">The maximum expected array length.</param>
    /// <param name="actual">The actual array length.</param>
    [DoesNotReturn]
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void ThrowInvalidArrayLengthRange(int minimum, int maximum, int actual)
    {
        throw new CborContentException($"Expected CBOR array with {minimum}-{maximum} elements, but found {actual}.");
    }


    /// <summary>
    /// Throws a <see cref="CborContentException"/> indicating a missing required property.
    /// </summary>
    /// <param name="propertyName">The name of the missing property.</param>
    [DoesNotReturn]
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void ThrowMissingRequiredProperty(string propertyName)
    {
        throw new CborContentException($"Missing required property: '{propertyName}'.");
    }


    /// <summary>
    /// Throws a <see cref="CborContentException"/> indicating a missing required map key.
    /// </summary>
    /// <param name="key">The missing map key.</param>
    [DoesNotReturn]
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void ThrowMissingRequiredMapKey(long key)
    {
        throw new CborContentException($"Missing required map key: {key}.");
    }


    /// <summary>
    /// Throws a <see cref="CborContentException"/> indicating an unknown map key.
    /// </summary>
    /// <param name="key">The unknown map key.</param>
    [DoesNotReturn]
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void ThrowUnknownMapKey(long key)
    {
        throw new CborContentException($"Unknown map key: {key}.");
    }


    /// <summary>
    /// Throws a <see cref="CborContentException"/> indicating an unknown map key.
    /// </summary>
    /// <param name="key">The unknown map key.</param>
    [DoesNotReturn]
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void ThrowUnknownMapKey(string key)
    {
        throw new CborContentException($"Unknown map key: '{key}'.");
    }


    /// <summary>
    /// Throws a <see cref="CborContentException"/> indicating indefinite-length encoding is not allowed.
    /// </summary>
    [DoesNotReturn]
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void ThrowIndefiniteLengthNotAllowed()
    {
        throw new CborContentException("Indefinite-length CBOR encoding is not allowed.");
    }


    /// <summary>
    /// Throws a <see cref="CborContentException"/> indicating a duplicate map key.
    /// </summary>
    /// <param name="key">The duplicate map key.</param>
    [DoesNotReturn]
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void ThrowDuplicateMapKey(long key)
    {
        throw new CborContentException($"Duplicate map key: {key}.");
    }


    /// <summary>
    /// Throws a <see cref="CborContentException"/> indicating a duplicate map key.
    /// </summary>
    /// <param name="key">The duplicate map key.</param>
    [DoesNotReturn]
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void ThrowDuplicateMapKey(string key)
    {
        throw new CborContentException($"Duplicate map key: '{key}'.");
    }


    /// <summary>
    /// Throws an <see cref="InvalidOperationException"/> indicating a converter was not found.
    /// </summary>
    /// <param name="type">The type for which no converter was found.</param>
    [DoesNotReturn]
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void ThrowConverterNotFound(Type type)
    {
        ArgumentNullException.ThrowIfNull(type);
        throw new InvalidOperationException($"No CBOR converter found for type '{type.FullName}'.");
    }


    /// <summary>
    /// Throws an <see cref="InvalidOperationException"/> for a null converter result.
    /// </summary>
    /// <param name="type">The type being converted.</param>
    [DoesNotReturn]
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void ThrowNullConverterResult(Type type)
    {
        ArgumentNullException.ThrowIfNull(type);
        throw new InvalidOperationException($"Converter for type '{type.FullName}' returned null.");
    }
}