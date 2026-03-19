using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace Verifiable.Json;

/// <summary>
/// Provides AOT-safe overloads for <see cref="JsonSerializer"/> that resolve
/// <see cref="JsonTypeInfo{T}"/> from a <see cref="JsonSerializerOptions"/> instance.
/// </summary>
/// <remarks>
/// The standard <see cref="JsonSerializer"/> overloads that accept <see cref="JsonSerializerOptions"/>
/// are marked <see cref="System.Diagnostics.CodeAnalysis.RequiresUnreferencedCodeAttribute"/> and
/// produce IL2026 warnings under the trim analyzer. These overloads extract
/// <see cref="JsonTypeInfo{T}"/> from the options' configured
/// <see cref="JsonSerializerOptions.TypeInfoResolver"/> — typically a
/// <see cref="System.Text.Json.Serialization.JsonSerializerContext"/> — and delegate to the
/// trim-safe <c>JsonTypeInfo&lt;T&gt;</c> overloads.
/// <para>
/// Requires <typeparamref name="T"/> to be registered in the resolver. Throws
/// <see cref="InvalidOperationException"/> if the type is not registered.
/// </para>
/// </remarks>
public static class JsonSerializerExtensions
{
    private static JsonTypeInfo<T> GetTypeInfo<T>(JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return (JsonTypeInfo<T>)options.GetTypeInfo(typeof(T));
    }


    /// <summary>
    /// Serializes <paramref name="value"/> to a JSON string using type information
    /// resolved from <paramref name="options"/>.
    /// </summary>
    public static string Serialize<T>(T value, JsonSerializerOptions options)
    {
        JsonTypeInfo<T> typeInfo = GetTypeInfo<T>(options);

        return JsonSerializer.Serialize(value, typeInfo);
    }


    /// <summary>
    /// Serializes <paramref name="value"/> to a UTF-8 encoded JSON byte array using
    /// type information resolved from <paramref name="options"/>.
    /// </summary>
    public static byte[] SerializeToUtf8Bytes<T>(T value, JsonSerializerOptions options)
    {
        JsonTypeInfo<T> typeInfo = GetTypeInfo<T>(options);

        return JsonSerializer.SerializeToUtf8Bytes(value, typeInfo);
    }


    /// <summary>
    /// Deserializes a JSON string to <typeparamref name="T"/> using type information
    /// resolved from <paramref name="options"/>.
    /// </summary>
    public static T? Deserialize<T>(string json, JsonSerializerOptions options)
    {
        JsonTypeInfo<T> typeInfo = GetTypeInfo<T>(options);

        return JsonSerializer.Deserialize(json, typeInfo);
    }


    /// <summary>
    /// Deserializes a UTF-8 encoded JSON byte span to <typeparamref name="T"/> using
    /// type information resolved from <paramref name="options"/>.
    /// </summary>
    public static T? Deserialize<T>(ReadOnlySpan<byte> utf8Json, JsonSerializerOptions options)
    {
        JsonTypeInfo<T> typeInfo = GetTypeInfo<T>(options);

        return JsonSerializer.Deserialize(utf8Json, typeInfo);
    }
}