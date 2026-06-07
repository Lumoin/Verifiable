using System;
using System.Collections.Generic;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// Shared payload-reading and -writing helpers for the typed event records:
/// tolerant single-member reads over the parsed <see cref="SecurityEvent.Payload"/>
/// shapes (strings, numbers, nested <c>Dictionary&lt;string, object&gt;</c>,
/// arrays as <c>List&lt;object&gt;</c>).
/// </summary>
internal static class EventPayloadReading
{
    /// <summary>Reads an optional string member; <see langword="null"/> when absent or not a string.</summary>
    internal static string? ReadOptionalString(IReadOnlyDictionary<string, object> payload, string name) =>
        payload.TryGetValue(name, out object? value) && value is string text ? text : null;


    /// <summary>Reads an optional Unix-seconds member; <see langword="null"/> when absent or not a number.</summary>
    internal static DateTimeOffset? ReadUnixSeconds(IReadOnlyDictionary<string, object> payload, string name)
    {
        if(!payload.TryGetValue(name, out object? value))
        {
            return null;
        }

        return value switch
        {
            int i => DateTimeOffset.FromUnixTimeSeconds(i),
            long l => DateTimeOffset.FromUnixTimeSeconds(l),
            decimal d when d >= long.MinValue && d <= long.MaxValue => DateTimeOffset.FromUnixTimeSeconds((long)d),
            _ => null
        };
    }


    /// <summary>
    /// Reads an optional BCP47-keyed localizable message object (the
    /// <c>reason_admin</c>/<c>reason_user</c> shape of CAEP 1.0 §2);
    /// <see langword="null"/> when absent or not an object. Non-string member
    /// values are skipped.
    /// </summary>
    internal static Dictionary<string, string>? ReadLocalizableMap(
        IReadOnlyDictionary<string, object> payload, string name)
    {
        if(!payload.TryGetValue(name, out object? value) || value is not IReadOnlyDictionary<string, object> map)
        {
            return null;
        }

        var messages = new Dictionary<string, string>(map.Count, StringComparer.Ordinal);
        foreach(KeyValuePair<string, object> entry in map)
        {
            if(entry.Value is string message)
            {
                messages[entry.Key] = message;
            }
        }

        return messages;
    }


    /// <summary>
    /// Reads an optional array-of-strings member; <see langword="null"/> when
    /// absent or not an array. Non-string elements are skipped.
    /// </summary>
    internal static List<string>? ReadStringList(IReadOnlyDictionary<string, object> payload, string name)
    {
        if(!payload.TryGetValue(name, out object? value) || value is not IReadOnlyList<object> elements)
        {
            return null;
        }

        var strings = new List<string>(elements.Count);
        foreach(object element in elements)
        {
            if(element is string text)
            {
                strings.Add(text);
            }
        }

        return strings;
    }


    /// <summary>Content equality for two localizable message maps (both-null is equal).</summary>
    internal static bool MapsEqual(
        IReadOnlyDictionary<string, string>? mapA, IReadOnlyDictionary<string, string>? mapB)
    {
        if(mapA is null || mapB is null)
        {
            return ReferenceEquals(mapA, mapB);
        }

        if(mapA.Count != mapB.Count)
        {
            return false;
        }

        foreach(KeyValuePair<string, string> entry in mapA)
        {
            if(!mapB.TryGetValue(entry.Key, out string? message)
                || !string.Equals(entry.Value, message, StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>Ordinal content equality for two string lists (both-null is equal).</summary>
    internal static bool ListsEqual(IReadOnlyList<string>? listA, IReadOnlyList<string>? listB)
    {
        if(listA is null || listB is null)
        {
            return ReferenceEquals(listA, listB);
        }

        if(listA.Count != listB.Count)
        {
            return false;
        }

        for(int i = 0; i < listA.Count; ++i)
        {
            if(!string.Equals(listA[i], listB[i], StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>Copies a localizable message map into its wire object shape.</summary>
    internal static Dictionary<string, object> ToWireMap(IReadOnlyDictionary<string, string> messages)
    {
        var wire = new Dictionary<string, object>(messages.Count, StringComparer.Ordinal);
        foreach(KeyValuePair<string, string> entry in messages)
        {
            wire[entry.Key] = entry.Value;
        }

        return wire;
    }


    /// <summary>Copies a string list into its wire array shape.</summary>
    internal static List<object> ToWireList(IReadOnlyList<string> strings)
    {
        var wire = new List<object>(strings.Count);
        foreach(string text in strings)
        {
            wire.Add(text);
        }

        return wire;
    }
}
