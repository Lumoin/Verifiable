using System;
using System.Collections.Generic;
using System.Text.Json;

namespace Verifiable.Json;

/// <summary>
/// Shared read/write helpers for the open-world JSON-LD "additional data" bucket that
/// several POCO types expose (for example <c>VerifiableCredential.AdditionalData</c>,
/// <c>Service.AdditionalData</c>, <c>CredentialSubject.AdditionalData</c>). The bucket
/// holds any member the typed model does not name; it is flattened at the object root on
/// the wire (the keys are top-level properties, not a nested <c>additionalData</c> object).
/// </summary>
/// <remarks>
/// <para>
/// Two reader entry points mirror the two converter styles used in this assembly:
/// <see cref="AddFromElement"/> for converters that buffer into a
/// <see cref="JsonDocument"/> (random property access), and <see cref="AddFromReader"/>
/// for converters that stream a <see cref="Utf8JsonReader"/>. Both materialize values
/// through the same narrowing rules (<see cref="JsonElementConversion"/> /
/// <see cref="ManualJsonReader"/>) and both store a JSON <c>null</c> value as a bucket
/// entry: the null is data belonging to the member, not an absent member, so it is kept
/// under its property name rather than dropped.
/// </para>
/// </remarks>
internal static class AdditionalDataJson
{
    /// <summary>
    /// Writes each entry of the open-world bucket as a top-level property on the object
    /// the writer is currently building. No-op when <paramref name="additionalData"/> is
    /// <see langword="null"/>.
    /// </summary>
    internal static void WriteEntries(Utf8JsonWriter writer, IDictionary<string, object>? additionalData, string? excludedKey = null)
    {
        if(additionalData is null)
        {
            return;
        }

        foreach(var kvp in additionalData)
        {
            //A converter that has already emitted a bucket key through a typed property (for example the DID
            //Resolution metadata's "deactivated") excludes it here so it is not written twice.
            if(excludedKey is not null && string.Equals(kvp.Key, excludedKey, StringComparison.Ordinal))
            {
                continue;
            }

            writer.WritePropertyName(kvp.Key);
            ManualJsonWriter.WriteValue(writer, kvp.Value);
        }
    }


    /// <summary>
    /// Adds one unknown property (read from a buffered <see cref="JsonElement"/>) to the
    /// lazily-created bucket, materializing the value via
    /// <see cref="JsonElementConversion.Convert"/>. This is the entry point every
    /// production converter with an open-world bucket calls. A JSON <c>null</c> value is
    /// stored as the entry's value: it is data belonging to the member, not an absent
    /// member, so it is kept under its property name rather than dropped.
    /// </summary>
    internal static void AddFromElement(ref Dictionary<string, object>? bucket, string name, JsonElement value)
    {
        bucket ??= new Dictionary<string, object>(StringComparer.Ordinal);
        bucket[name] = JsonElementConversion.Convert(value)!;
    }


    /// <summary>
    /// Adds one unknown property (read from a streaming <see cref="Utf8JsonReader"/>
    /// positioned on the value token) to the lazily-created bucket, materializing the
    /// value via <see cref="ManualJsonReader.ReadValue"/>. A JSON <c>null</c> value is
    /// stored as the entry's value: it is data belonging to the member, not an absent
    /// member.
    /// </summary>
    internal static void AddFromReader(ref Dictionary<string, object>? bucket, string name, ref Utf8JsonReader reader)
    {
        bucket ??= new Dictionary<string, object>(StringComparer.Ordinal);
        bucket[name] = ManualJsonReader.ReadValue(ref reader)!;
    }
}
