using System;
using System.Collections.Generic;
using Verifiable.JCose;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// Projects a verified SET payload (a parsed JSON object) into the typed
/// <see cref="SecurityEventToken"/>. Pure dictionary navigation over the values
/// the JSON layer produces — strings, numbers (narrowed to <see cref="int"/>,
/// <see cref="long"/>, or <see cref="decimal"/>), nested objects as
/// <c>Dictionary&lt;string, object&gt;</c>, and arrays as <c>List&lt;object&gt;</c>.
/// </summary>
/// <remarks>
/// Parsing is tolerant: it never throws on shape mismatch, leaving an absent or
/// malformed claim <see langword="null"/>/empty for the verification pipeline to
/// judge. It does not verify signatures or validate claim values — callers run
/// it only on an already-verified payload.
/// </remarks>
public static class SecurityEventTokenParsing
{
    /// <summary>
    /// Parses the SET claims from <paramref name="payload"/>.
    /// </summary>
    /// <param name="payload">The verified SET payload (claim name to value).</param>
    /// <returns>The typed token projection.</returns>
    public static SecurityEventToken Parse(IReadOnlyDictionary<string, object> payload)
    {
        ArgumentNullException.ThrowIfNull(payload);

        return new SecurityEventToken
        {
            Issuer = ReadString(payload, WellKnownJwtClaimNames.Iss),
            IssuedAt = ReadUnixSeconds(payload, WellKnownJwtClaimNames.Iat),
            JwtId = ReadString(payload, WellKnownJwtClaimNames.Jti),
            Audiences = ReadAudiences(payload),
            TimeOfEvent = ReadUnixSeconds(payload, SecurityEventTokenClaimNames.Toe),
            Transaction = ReadString(payload, SecurityEventTokenClaimNames.Txn),
            SubjectId = ReadSubjectId(payload),
            Events = ReadEvents(payload)
        };
    }


    private static string? ReadString(IReadOnlyDictionary<string, object> obj, string name) =>
        obj.TryGetValue(name, out object? value) && value is string s ? s : null;


    private static DateTimeOffset? ReadUnixSeconds(IReadOnlyDictionary<string, object> obj, string name)
    {
        if(!obj.TryGetValue(name, out object? value))
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


    private static List<string> ReadAudiences(IReadOnlyDictionary<string, object> obj)
    {
        if(!obj.TryGetValue(WellKnownJwtClaimNames.Aud, out object? value))
        {
            return [];
        }

        if(value is string single)
        {
            return [single];
        }

        var list = new List<string>();
        if(value is IEnumerable<object> items)
        {
            foreach(object item in items)
            {
                if(item is string s)
                {
                    list.Add(s);
                }
            }
        }

        return list;
    }


    private static SubjectIdentifier? ReadSubjectId(IReadOnlyDictionary<string, object> obj) =>
        obj.TryGetValue(SecurityEventTokenClaimNames.SubId, out object? value) && value is IReadOnlyDictionary<string, object> subId
            ? SubjectIdentifier.FromWireObject(subId)
            : null;


    private static List<SecurityEvent> ReadEvents(IReadOnlyDictionary<string, object> obj)
    {
        if(!obj.TryGetValue(SecurityEventTokenClaimNames.Events, out object? value) || value is not IReadOnlyDictionary<string, object> events)
        {
            return [];
        }

        var list = new List<SecurityEvent>(events.Count);
        foreach(KeyValuePair<string, object> entry in events)
        {
            IReadOnlyDictionary<string, object> eventPayload =
                entry.Value as IReadOnlyDictionary<string, object> ?? EmptyPayload;

            list.Add(new SecurityEvent
            {
                EventType = entry.Key,
                Payload = eventPayload
            });
        }

        return list;
    }


    private static readonly IReadOnlyDictionary<string, object> EmptyPayload =
        new Dictionary<string, object>(0, StringComparer.Ordinal);
}
