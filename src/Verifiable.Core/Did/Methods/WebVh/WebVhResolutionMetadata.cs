using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Verifiable.Core.Resolvers;

namespace Verifiable.Core.Did.Methods.WebVh;

/// <summary>
/// did:webvh-specific DID Resolution document metadata, carried in the open-world
/// <see cref="DidDocumentMetadata.AdditionalData"/> bucket rather than a method-specific subtype. The DID
/// Resolution document metadata is a flat open map, so the method's properties (<c>scid</c>, <c>portable</c>,
/// <c>ttl</c>, <c>versionTime</c>, <c>witness</c>, <c>watchers</c>) are top-level keys that serialize without a
/// type discriminator and let any property a peer resolver emits round-trip (did:webvh v1.0, Read). This type
/// owns the property keys, builds the bucket from the resolved (last valid) state, and exposes strongly-typed
/// read accessors over it.
/// </summary>
/// <remarks>
/// Per did:webvh v1.0 the numeric <c>ttl</c> and the witness <c>threshold</c> are carried as strings because
/// the DID Resolution specification requires DID metadata not to contain integers; a client converts them
/// before use.
/// </remarks>
public static class WebVhResolutionMetadata
{
    /// <summary>The metadata property key for the resolved version's <c>versionTime</c>.</summary>
    public const string VersionTimeKey = "versionTime";

    /// <summary>The metadata property key for the self-certifying identifier.</summary>
    public const string ScidKey = "scid";

    /// <summary>The metadata property key for the portability flag.</summary>
    public const string PortableKey = "portable";

    /// <summary>The metadata property key for the (string-valued) cache time-to-live in seconds.</summary>
    public const string TtlKey = "ttl";

    /// <summary>The metadata property key for the active witness configuration.</summary>
    public const string WitnessKey = "witness";

    /// <summary>The metadata property key for the active watcher URL list.</summary>
    public const string WatchersKey = "watchers";

    /// <summary>
    /// The metadata property key for the deactivation flag. A did:webvh resolution always determines the
    /// deactivation status, so the flag is carried here as an explicit boolean (true OR false) — the
    /// did:webvh metadata example shows <c>"deactivated": false</c> present, not omitted.
    /// </summary>
    public const string DeactivatedKey = "deactivated";


    /// <summary>
    /// Builds the open-world metadata bucket from the resolved (last valid) state: the SCID, portability, ttl
    /// (string), versionTime, the active witness and watcher configuration, and the explicit deactivation flag
    /// (did:webvh v1.0, Read).
    /// </summary>
    /// <param name="state">The resolved (last valid) replay state.</param>
    /// <param name="isDeactivated">Whether the resolution determined the DID is deactivated.</param>
    /// <returns>The method-specific metadata bucket.</returns>
    public static IDictionary<string, object> Build(WebVhState state, bool isDeactivated)
    {
        ArgumentNullException.ThrowIfNull(state);

        var data = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [ScidKey] = state.Parameters.Scid,
            [PortableKey] = state.Parameters.Portable,
            [TtlKey] = state.Parameters.Ttl.ToString(CultureInfo.InvariantCulture),

            //A did:webvh resolution always determines the deactivation status, so the flag is emitted
            //explicitly (true OR false), matching the did:webvh metadata example (did:webvh v1.0, Read).
            [DeactivatedKey] = isDeactivated
        };

        if(state.VersionTime is { Length: > 0 } versionTime)
        {
            data[VersionTimeKey] = versionTime;
        }

        //An active watcher configuration is surfaced even when the list is empty: an explicit empty array []
        //distinguishes "watchers are configured but none are listed" from "no watcher parameter" (did:webvh
        //v1.0, Read). The watchers parameter defaults to [] and is part of the resolved configuration, so the
        //key is always present.
        data[WatchersKey] = ToObjectList(state.Parameters.Watchers);

        if(state.Parameters.Witness is { } rule)
        {
            data[WitnessKey] = BuildWitness(rule);
        }

        return data;
    }


    /// <summary>Parses a did:webvh <c>versionTime</c> string into the metadata's <c>created</c>/<c>updated</c> timestamp.</summary>
    /// <param name="versionTime">The entry's <c>versionTime</c> string, or <see langword="null"/>.</param>
    /// <returns>The parsed timestamp, or <see langword="null"/> when absent or unparseable.</returns>
    public static DateTimeOffset? ParseTimestamp(string? versionTime)
    {
        return versionTime is { Length: > 0 }
            && DateTimeOffset.TryParse(versionTime, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTimeOffset parsed)
            ? parsed
            : null;
    }


    /// <summary>Reads the active watchers, or an empty list when none are present.</summary>
    public static IReadOnlyList<string> GetWatchers(this DidDocumentMetadata metadata)
    {
        return ReadStrings(metadata, WatchersKey);
    }


    /// <summary>Reads the self-certifying identifier, or <see langword="null"/> when absent.</summary>
    public static string? GetScid(this DidDocumentMetadata metadata)
    {
        return ReadString(metadata, ScidKey);
    }


    /// <summary>Reads the portability flag, or <see langword="null"/> when absent.</summary>
    public static bool? GetPortable(this DidDocumentMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        return metadata.AdditionalData is { } data && data.TryGetValue(PortableKey, out object? value) && value is bool flag
            ? flag
            : null;
    }


    /// <summary>Reads the (string-valued) ttl, or <see langword="null"/> when absent.</summary>
    public static string? GetTtl(this DidDocumentMetadata metadata)
    {
        return ReadString(metadata, TtlKey);
    }


    /// <summary>Reads the resolved version's versionTime, or <see langword="null"/> when absent.</summary>
    public static string? GetVersionTime(this DidDocumentMetadata metadata)
    {
        return ReadString(metadata, VersionTimeKey);
    }


    private static Dictionary<string, object> BuildWitness(WebVhWitnessRule rule)
    {
        var witnesses = new List<object>(rule.Witnesses.Length);
        foreach(string id in rule.Witnesses)
        {
            witnesses.Add(new Dictionary<string, object>(StringComparer.Ordinal) { ["id"] = id });
        }

        return new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["threshold"] = rule.Threshold.ToString(CultureInfo.InvariantCulture),
            ["witnesses"] = witnesses
        };
    }


    private static List<object> ToObjectList(IReadOnlyList<string> values)
    {
        var list = new List<object>(values.Count);
        foreach(string value in values)
        {
            list.Add(value);
        }

        return list;
    }


    private static string? ReadString(DidDocumentMetadata metadata, string key)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        return metadata.AdditionalData is { } data && data.TryGetValue(key, out object? value) && value is string text
            ? text
            : null;
    }


    private static List<string> ReadStrings(DidDocumentMetadata metadata, string key)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        if(metadata.AdditionalData is { } data && data.TryGetValue(key, out object? value) && value is IEnumerable<object> items)
        {
            return items.OfType<string>().ToList();
        }

        return [];
    }
}
