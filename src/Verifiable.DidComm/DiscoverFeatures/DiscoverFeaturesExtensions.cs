using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.DidComm.DiscoverFeatures;

/// <summary>
/// Build and interpret for the DIDComm Discover Features Protocol 2.0 — turning a semantic
/// <see cref="DiscoverFeaturesQuery"/>/<see cref="DiscoverFeaturesDisclose"/> into a wire
/// <see cref="DidCommMessage"/> and back, and matching a query against a feature catalog to produce a
/// disclosure, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#discover-features-protocol-20">DIDComm Messaging v2.1 §Discover Features Protocol 2.0</see>.
/// </summary>
/// <remarks>
/// <para>
/// The <c>Create…</c> builders are producer-side and MAY throw on bad caller arguments; the
/// <c>TryInterpret…</c> readers consume attacker-controlled wire input and are fail-closed — they never throw,
/// returning <see langword="false"/> for any structurally non-conformant message. The dictionary <c>body</c> is
/// only the wire intermediate; callers operate on the typed records.
/// </para>
/// <para>
/// <see cref="MatchDisclosures"/> is the responder behavior: it matches a query's descriptors against the
/// catalog the application chooses to expose (selective disclosure is the caller's choice of catalog — DIDComm
/// v2.1 §Privacy Considerations) using the <c>*</c> wildcard, and naturally honors the rule that unrecognized
/// <c>feature-type</c> values MUST be ignored — a descriptor whose feature type the catalog does not declare
/// matches nothing rather than erroring (DIDComm v2.1 §Discover Features Protocol 2.0).
/// </para>
/// </remarks>
public static class DiscoverFeaturesExtensions
{
    //The query/disclose Message Type URIs, parsed once for semver-compatible handler dispatch.
    private static MessageTypeUri QueryMessageType { get; } = MessageTypeUri.Parse(WellKnownDiscoverFeaturesNames.QueryType);
    private static MessageTypeUri DiscloseMessageType { get; } = MessageTypeUri.Parse(WellKnownDiscoverFeaturesNames.DiscloseType);


    /// <summary>Whether <paramref name="message"/> is a discover-features query — its <c>type</c> is the <c>queries</c> Message Type URI (DIDComm v2.1 §query Message Type).</summary>
    /// <param name="message">The message to inspect.</param>
    /// <returns><see langword="true"/> when the message type is the query Message Type URI.</returns>
    public static bool IsDiscoverFeaturesQuery(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return MessageTypeUri.TryParse(message.Type, out MessageTypeUri? messageType)
            && messageType.IsSameMessageType(QueryMessageType);
    }


    /// <summary>Whether <paramref name="message"/> is a discover-features disclose — its <c>type</c> is the <c>disclose</c> Message Type URI (DIDComm v2.1 §disclose Message Type).</summary>
    /// <param name="message">The message to inspect.</param>
    /// <returns><see langword="true"/> when the message type is the disclose Message Type URI.</returns>
    public static bool IsDiscoverFeaturesDisclose(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return MessageTypeUri.TryParse(message.Type, out MessageTypeUri? messageType)
            && messageType.IsSameMessageType(DiscloseMessageType);
    }


    /// <summary>
    /// Builds a discover-features <c>query</c> message: <c>type</c> is the <c>queries</c> Message Type URI and
    /// <c>body.queries</c> carries the query descriptors (DIDComm v2.1 §query Message Type).
    /// </summary>
    /// <param name="query">The semantic query; MUST carry at least one descriptor.</param>
    /// <param name="id">REQUIRED. The message id.</param>
    /// <param name="from">OPTIONAL. The sender identifier.</param>
    /// <returns>The query message.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="id"/> is null/empty, the query has no descriptors, or a descriptor's <c>feature-type</c>/<c>match</c> is null/empty.</exception>
    public static DidCommMessage CreateDiscoverFeaturesQuery(this DiscoverFeaturesQuery query, string id, string? from = null)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(query.Queries);
        ArgumentException.ThrowIfNullOrEmpty(id);

        if(query.Queries.Count == 0)
        {
            throw new ArgumentException("A discover-features query MUST carry at least one query descriptor (DIDComm v2.1 §query Message Type).", nameof(query));
        }

        var descriptors = new List<object>(query.Queries.Count);
        foreach(FeatureQuery descriptor in query.Queries)
        {
            ArgumentNullException.ThrowIfNull(descriptor);
            ArgumentException.ThrowIfNullOrEmpty(descriptor.FeatureType);
            ArgumentException.ThrowIfNullOrEmpty(descriptor.Match);

            descriptors.Add(new Dictionary<string, object>
            {
                [WellKnownDiscoverFeaturesNames.FeatureType] = descriptor.FeatureType,
                [WellKnownDiscoverFeaturesNames.Match] = descriptor.Match
            });
        }

        return new DidCommMessage
        {
            Id = id,
            Type = WellKnownDiscoverFeaturesNames.QueryType,
            From = from,
            Body = new Dictionary<string, object> { [WellKnownDiscoverFeaturesNames.Queries] = descriptors }
        };
    }


    /// <summary>
    /// Builds a discover-features <c>disclose</c> message answering a query: <c>type</c> is the <c>disclose</c>
    /// Message Type URI, <c>thid</c> continues the query's thread, and <c>body.disclosures</c> carries the
    /// disclosure descriptors (DIDComm v2.1 §disclose Message Type). An empty disclosure set is permitted
    /// (DIDComm v2.1 §Sparse Responses).
    /// </summary>
    /// <param name="disclose">The semantic disclosure.</param>
    /// <param name="id">REQUIRED. The message id.</param>
    /// <param name="threadId">The thread this disclose answers — the queried message's <c>id</c> (a request~response continuation). Pass null/empty for a proactive, unsolicited disclosure.</param>
    /// <param name="from">OPTIONAL. The sender identifier.</param>
    /// <returns>The disclose message.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="id"/> is null/empty, or a disclosure's <c>feature-type</c>/<c>id</c> is null/empty.</exception>
    public static DidCommMessage CreateDiscoverFeaturesDisclose(this DiscoverFeaturesDisclose disclose, string id, string? threadId, string? from = null)
    {
        ArgumentNullException.ThrowIfNull(disclose);
        ArgumentNullException.ThrowIfNull(disclose.Disclosures);
        ArgumentException.ThrowIfNullOrEmpty(id);

        var descriptors = new List<object>(disclose.Disclosures.Count);
        foreach(FeatureDisclosure descriptor in disclose.Disclosures)
        {
            ArgumentNullException.ThrowIfNull(descriptor);
            ArgumentException.ThrowIfNullOrEmpty(descriptor.FeatureType);
            ArgumentException.ThrowIfNullOrEmpty(descriptor.Id);

            var entry = new Dictionary<string, object>
            {
                [WellKnownDiscoverFeaturesNames.FeatureType] = descriptor.FeatureType,
                [WellKnownDiscoverFeaturesNames.Id] = descriptor.Id
            };

            if(descriptor.Roles is not null)
            {
                entry[WellKnownDiscoverFeaturesNames.Roles] = new List<object>(descriptor.Roles);
            }

            if(descriptor.AdditionalFields is not null)
            {
                foreach(KeyValuePair<string, object> field in descriptor.AdditionalFields)
                {
                    if(!IsReservedDisclosureMember(field.Key))
                    {
                        entry[field.Key] = field.Value;
                    }
                }
            }

            descriptors.Add(entry);
        }

        return new DidCommMessage
        {
            Id = id,
            Type = WellKnownDiscoverFeaturesNames.DiscloseType,
            From = from,
            ThreadId = string.IsNullOrEmpty(threadId) ? null : threadId,
            Body = new Dictionary<string, object> { [WellKnownDiscoverFeaturesNames.Disclosures] = descriptors }
        };
    }


    /// <summary>
    /// Interprets <paramref name="message"/> as a discover-features query — fail-closed: returns
    /// <see langword="false"/> without throwing for any message that is not a conformant query (DIDComm v2.1
    /// §query Message Type). An unrecognized <c>feature-type</c> VALUE is kept verbatim (the matcher ignores it);
    /// only structural malformation fails closed.
    /// </summary>
    /// <param name="message">The received message to interpret.</param>
    /// <param name="query">The recovered query when interpretation succeeds.</param>
    /// <returns><see langword="true"/> when the message is a query whose <c>body.queries</c> is a non-empty array of well-formed descriptors.</returns>
    public static bool TryInterpretDiscoverFeaturesQuery(this DidCommMessage message, [NotNullWhen(true)] out DiscoverFeaturesQuery? query)
    {
        ArgumentNullException.ThrowIfNull(message);

        query = null;

        if(!message.IsDiscoverFeaturesQuery())
        {
            return false;
        }

        if(message.Body is not { } body
            || !TryReadDescriptorArray(body, WellKnownDiscoverFeaturesNames.Queries, out IReadOnlyList<IDictionary<string, object>>? rawDescriptors))
        {
            return false;
        }

        var descriptors = new List<FeatureQuery>(rawDescriptors.Count);
        foreach(IDictionary<string, object> raw in rawDescriptors)
        {
            if(!TryReadRequiredString(raw, WellKnownDiscoverFeaturesNames.FeatureType, out string? featureType)
                || !TryReadRequiredString(raw, WellKnownDiscoverFeaturesNames.Match, out string? matchValue))
            {
                return false;
            }

            descriptors.Add(new FeatureQuery { FeatureType = featureType, Match = matchValue });
        }

        //A query MUST contain one or more descriptors (DIDComm v2.1 §query Message Type).
        if(descriptors.Count == 0)
        {
            return false;
        }

        query = new DiscoverFeaturesQuery { Queries = descriptors };

        return true;
    }


    /// <summary>
    /// Interprets <paramref name="message"/> as a discover-features disclose — fail-closed: returns
    /// <see langword="false"/> without throwing for any message that is not a conformant disclose (DIDComm v2.1
    /// §disclose Message Type). An empty <c>disclosures</c> array is valid (DIDComm v2.1 §Sparse Responses).
    /// </summary>
    /// <param name="message">The received message to interpret.</param>
    /// <param name="disclose">The recovered disclosure when interpretation succeeds.</param>
    /// <returns><see langword="true"/> when the message is a disclose whose <c>body.disclosures</c> is an array (possibly empty) of well-formed descriptors.</returns>
    public static bool TryInterpretDiscoverFeaturesDisclose(this DidCommMessage message, [NotNullWhen(true)] out DiscoverFeaturesDisclose? disclose)
    {
        ArgumentNullException.ThrowIfNull(message);

        disclose = null;

        if(!message.IsDiscoverFeaturesDisclose())
        {
            return false;
        }

        if(message.Body is not { } body
            || !TryReadDescriptorArray(body, WellKnownDiscoverFeaturesNames.Disclosures, out IReadOnlyList<IDictionary<string, object>>? rawDescriptors))
        {
            return false;
        }

        var descriptors = new List<FeatureDisclosure>(rawDescriptors.Count);
        foreach(IDictionary<string, object> raw in rawDescriptors)
        {
            if(!TryReadRequiredString(raw, WellKnownDiscoverFeaturesNames.FeatureType, out string? featureType)
                || !TryReadRequiredString(raw, WellKnownDiscoverFeaturesNames.Id, out string? id))
            {
                return false;
            }

            if(!TryReadOptionalStringArray(raw, WellKnownDiscoverFeaturesNames.Roles, out IReadOnlyList<string>? roles))
            {
                return false;
            }

            Dictionary<string, object>? additionalFields = null;
            foreach(KeyValuePair<string, object> member in raw)
            {
                if(!IsReservedDisclosureMember(member.Key))
                {
                    additionalFields ??= new Dictionary<string, object>();
                    additionalFields[member.Key] = member.Value;
                }
            }

            descriptors.Add(new FeatureDisclosure { FeatureType = featureType, Id = id, Roles = roles, AdditionalFields = additionalFields });
        }

        disclose = new DiscoverFeaturesDisclose { Disclosures = descriptors };

        return true;
    }


    /// <summary>
    /// Matches <paramref name="query"/> against the feature <paramref name="catalog"/> the application chooses to
    /// expose, producing the disclosure to send (DIDComm v2.1 §Discover Features Protocol 2.0). For each query
    /// descriptor, every catalog entry of the SAME <c>feature-type</c> whose <c>id</c> matches the descriptor's
    /// <c>match</c> (with the trailing <c>*</c> wildcard) is disclosed, de-duplicated by (feature-type, id). A
    /// descriptor whose feature type the catalog does not declare matches nothing — so unrecognized feature types
    /// are ignored rather than erroring. The empty result of a no-match query is a valid (sparse) disclosure, NOT
    /// "I support nothing" (DIDComm v2.1 §Sparse Responses).
    /// </summary>
    /// <param name="query">The received query.</param>
    /// <param name="catalog">The features the application is willing to disclose — its selective-disclosure choice.</param>
    /// <returns>The disclosure answering the query.</returns>
    public static DiscoverFeaturesDisclose MatchDisclosures(this DiscoverFeaturesQuery query, IReadOnlyList<FeatureDisclosure> catalog)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(query.Queries);
        ArgumentNullException.ThrowIfNull(catalog);

        var matched = new List<FeatureDisclosure>();
        var seen = new HashSet<(string FeatureType, string Id)>();
        foreach(FeatureQuery descriptor in query.Queries)
        {
            foreach(FeatureDisclosure feature in catalog)
            {
                if(string.Equals(descriptor.FeatureType, feature.FeatureType, StringComparison.Ordinal)
                    && MatchesIdentifier(descriptor.Match, feature.Id)
                    && seen.Add((feature.FeatureType, feature.Id)))
                {
                    matched.Add(feature);
                }
            }
        }

        return new DiscoverFeaturesDisclose { Disclosures = matched };
    }


    //The reserved disclosure-descriptor members the typed FeatureDisclosure models directly; everything else is
    //carried verbatim in FeatureDisclosure.AdditionalFields (DIDComm v2.1 §disclose Message Type — additional
    //optional fields).
    private static bool IsReservedDisclosureMember(string member) =>
        string.Equals(member, WellKnownDiscoverFeaturesNames.FeatureType, StringComparison.Ordinal)
        || string.Equals(member, WellKnownDiscoverFeaturesNames.Id, StringComparison.Ordinal)
        || string.Equals(member, WellKnownDiscoverFeaturesNames.Roles, StringComparison.Ordinal);


    //The discover-features match semantics (DIDComm v2.1 §query Message Type): a trailing '*' makes the match a
    //prefix match (a bare '*' matches anything); otherwise the match is exact. The spec defines ONLY the trailing
    //'*'; a mid-string '*' is therefore compared literally and matches nothing real — the privacy-safe direction
    //(it never over-discloses). Ordinal throughout.
    private static bool MatchesIdentifier(string match, string candidate)
    {
        if(match.EndsWith('*'))
        {
            return candidate.StartsWith(match[..^1], StringComparison.Ordinal);
        }

        return string.Equals(match, candidate, StringComparison.Ordinal);
    }


    //Reads a REQUIRED descriptor-array body member: present, a JSON array (not a string), every element a JSON
    //object. Fails closed otherwise; an empty array yields an empty list (the caller enforces any non-empty rule).
    private static bool TryReadDescriptorArray(IDictionary<string, object> body, string member, [NotNullWhen(true)] out IReadOnlyList<IDictionary<string, object>>? descriptors)
    {
        descriptors = null;
        if(!body.TryGetValue(member, out object? raw) || raw is null)
        {
            return false;
        }

        //A string is IEnumerable but is not a JSON array; reject it explicitly.
        if(raw is string || raw is not System.Collections.IEnumerable elements)
        {
            return false;
        }

        var collected = new List<IDictionary<string, object>>();
        foreach(object? element in elements)
        {
            if(element is not IDictionary<string, object> entry)
            {
                return false;
            }

            collected.Add(entry);
        }

        descriptors = collected;

        return true;
    }


    //Reads a REQUIRED non-empty string descriptor member: present and a non-empty string, else false.
    private static bool TryReadRequiredString(IDictionary<string, object> descriptor, string member, [NotNullWhen(true)] out string? value)
    {
        value = null;
        if(!descriptor.TryGetValue(member, out object? raw) || raw is not string text || text.Length == 0)
        {
            return false;
        }

        value = text;

        return true;
    }


    //Reads an OPTIONAL string-array member (roles): absent or JSON-null yields null with success; a present value
    //that is not a JSON array, or that holds a non-string element, is a malformation and fails closed.
    private static bool TryReadOptionalStringArray(IDictionary<string, object> descriptor, string member, out IReadOnlyList<string>? values)
    {
        values = null;
        if(!descriptor.TryGetValue(member, out object? raw) || raw is null)
        {
            return true;
        }

        if(raw is string || raw is not System.Collections.IEnumerable elements)
        {
            return false;
        }

        var collected = new List<string>();
        foreach(object? element in elements)
        {
            if(element is not string text)
            {
                return false;
            }

            collected.Add(text);
        }

        values = collected;

        return true;
    }
}