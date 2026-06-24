using Verifiable.Cryptography.Text;

namespace Verifiable.DidComm.DiscoverFeatures;

/// <summary>
/// The well-known names of the DIDComm Discover Features Protocol 2.0 — the protocol identifier URI, the
/// <c>queries</c>/<c>disclose</c> Message Type URIs, the <c>body</c> member names, and the recognized
/// <c>feature-type</c> values — per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#discover-features-protocol-20">DIDComm Messaging v2.1 §Discover Features Protocol 2.0</see>.
/// </summary>
/// <remarks>
/// The type URIs and body member names follow the UTF-8-literal + <see cref="Utf8Constants.ToInternedString"/>
/// idiom of <see cref="WellKnownProblemReportNames"/>. The <c>feature-type</c> VALUES (<c>protocol</c>,
/// <c>goal-code</c>, <c>header</c>) are enumerated descriptor tokens used for comparison and dispatch, not
/// converter-matched wire keys, so — like <see cref="WellKnownProblemCodes"/> — they are plain string constants.
/// </remarks>
public static class WellKnownDiscoverFeaturesNames
{
    /// <summary>The UTF-8 source literal of <see cref="DiscoverFeaturesProtocol"/>.</summary>
    public static ReadOnlySpan<byte> DiscoverFeaturesProtocolUtf8 => "https://didcomm.org/discover-features/2.0"u8;

    /// <summary>The protocol identifier URI (PIURI) of Discover Features Protocol 2.0 (DIDComm v2.1 §Discover Features Protocol 2.0).</summary>
    public static readonly string DiscoverFeaturesProtocol = Utf8Constants.ToInternedString(DiscoverFeaturesProtocolUtf8);

    /// <summary>The UTF-8 source literal of <see cref="QueryType"/>.</summary>
    public static ReadOnlySpan<byte> QueryTypeUtf8 => "https://didcomm.org/discover-features/2.0/queries"u8;

    /// <summary>
    /// The <c>queries</c> Message Type URI — the <c>type</c> of a discover-features query message. The URI ends
    /// in the plural <c>queries</c> even though the protocol role is "query" (DIDComm v2.1 §query Message Type).
    /// </summary>
    public static readonly string QueryType = Utf8Constants.ToInternedString(QueryTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DiscloseType"/>.</summary>
    public static ReadOnlySpan<byte> DiscloseTypeUtf8 => "https://didcomm.org/discover-features/2.0/disclose"u8;

    /// <summary>The <c>disclose</c> Message Type URI — the <c>type</c> of a discover-features disclose message (DIDComm v2.1 §disclose Message Type).</summary>
    public static readonly string DiscloseType = Utf8Constants.ToInternedString(DiscloseTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Queries"/>.</summary>
    public static ReadOnlySpan<byte> QueriesUtf8 => "queries"u8;

    /// <summary>The query message <c>body.queries</c> member — the array of query descriptors (DIDComm v2.1 §query Message Type).</summary>
    public static readonly string Queries = Utf8Constants.ToInternedString(QueriesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Disclosures"/>.</summary>
    public static ReadOnlySpan<byte> DisclosuresUtf8 => "disclosures"u8;

    /// <summary>The disclose message <c>body.disclosures</c> member — the array of disclosure descriptors (DIDComm v2.1 §disclose Message Type).</summary>
    public static readonly string Disclosures = Utf8Constants.ToInternedString(DisclosuresUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FeatureType"/>.</summary>
    public static ReadOnlySpan<byte> FeatureTypeUtf8 => "feature-type"u8;

    /// <summary>The <c>feature-type</c> member of a query/disclosure descriptor — <c>protocol</c>, <c>goal-code</c>, <c>header</c>, or another value (DIDComm v2.1 §Discover Features Protocol 2.0).</summary>
    public static readonly string FeatureType = Utf8Constants.ToInternedString(FeatureTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Match"/>.</summary>
    public static ReadOnlySpan<byte> MatchUtf8 => "match"u8;

    /// <summary>The query descriptor <c>match</c> member — an identifier, optionally ending in a <c>*</c> wildcard (DIDComm v2.1 §query Message Type).</summary>
    public static readonly string Match = Utf8Constants.ToInternedString(MatchUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Id"/>.</summary>
    public static ReadOnlySpan<byte> IdUtf8 => "id"u8;

    /// <summary>The disclosure descriptor <c>id</c> member — the unambiguous identifier of the disclosed feature (DIDComm v2.1 §disclose Message Type).</summary>
    public static readonly string Id = Utf8Constants.ToInternedString(IdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Roles"/>.</summary>
    public static ReadOnlySpan<byte> RolesUtf8 => "roles"u8;

    /// <summary>The disclosure descriptor <c>roles</c> member — OPTIONAL, protocol-only: the roles the agent can play (DIDComm v2.1 §disclose Message Type).</summary>
    public static readonly string Roles = Utf8Constants.ToInternedString(RolesUtf8);


    /// <summary>The <c>protocol</c> feature type — its identifiers are PIURIs (DIDComm v2.1 §Discover Features Protocol 2.0).</summary>
    public static string Protocol => "protocol";

    /// <summary>The <c>goal-code</c> feature type — its identifiers are goal code values (DIDComm v2.1 §Discover Features Protocol 2.0).</summary>
    public static string GoalCode => "goal-code";

    /// <summary>The <c>header</c> feature type — its identifiers are header names (DIDComm v2.1 §Discover Features Protocol 2.0).</summary>
    public static string Header => "header";
}
