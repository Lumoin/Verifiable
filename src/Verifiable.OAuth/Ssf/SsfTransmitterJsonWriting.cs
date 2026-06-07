using System.Text;
using Verifiable.Core.SecurityEvents;

namespace Verifiable.OAuth.Ssf;

/// <summary>
/// Hand-built JSON writers for the Shared Signals transmitter wire — the
/// Transmitter Configuration Metadata document (SSF 1.0 §7.1) and stream
/// configurations (§8.1.1) — through <see cref="JsonAppender"/> per the
/// <c>Verifiable.OAuth</c> serialization firewall.
/// </summary>
/// <remarks>
/// These writers are the emission half of the wire contract whose consumption
/// half is the strict receiver parsing in <c>Verifiable.Json</c>
/// (<c>SsfDiscoveryJsonParsing</c> / <c>SsfStreamJsonParsing</c>); property
/// tests round-trip arbitrary values through write-then-parse to keep the two
/// halves inverse. Kept separate from the endpoint orchestration so the string
/// building is directly testable.
/// </remarks>
public static class SsfTransmitterJsonWriting
{
    //The numerical spec version of the implemented final Shared Signals
    //Framework specification, per the OpenID naming convention SSF §7.1 cites.
    private const string SpecVersionFinal = "1_0";


    /// <summary>
    /// Serialises the SSF §7.1 Transmitter Configuration Metadata: the REQUIRED
    /// <c>issuer</c>, the <c>spec_version</c> of the implemented final spec, the
    /// caller-derived endpoint members (for example <c>jwks_uri</c> and
    /// <c>configuration_endpoint</c> read off the endpoint chain), and the
    /// contribution-supplied deployment policy.
    /// </summary>
    /// <param name="issuer">The Transmitter's Issuer Identifier.</param>
    /// <param name="endpointMembers">Metadata member name to advertised URL, in emission order.</param>
    /// <param name="contribution">The application-supplied deployment policy.</param>
    public static string BuildTransmitterConfigurationJson(
        Uri issuer,
        IReadOnlyList<KeyValuePair<string, string>> endpointMembers,
        SsfTransmitterMetadataContribution contribution)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(endpointMembers);
        ArgumentNullException.ThrowIfNull(contribution);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');

            bool first = true;
            JsonAppender.AppendUriField(sb, SsfMetadataParameterNames.Issuer, issuer, ref first);
            JsonAppender.AppendStringField(sb, SsfMetadataParameterNames.SpecVersion, SpecVersionFinal, ref first);

            foreach(KeyValuePair<string, string> member in endpointMembers)
            {
                JsonAppender.AppendStringField(sb, member.Key, member.Value, ref first);
            }

            if(contribution.DeliveryMethodsSupported is { Count: > 0 } deliveryMethods)
            {
                JsonAppender.AppendStringArrayField(
                    sb, SsfMetadataParameterNames.DeliveryMethodsSupported, deliveryMethods, ref first);
            }

            if(contribution.CriticalSubjectMembers is { Count: > 0 } criticalMembers)
            {
                JsonAppender.AppendStringArrayField(
                    sb, SsfMetadataParameterNames.CriticalSubjectMembers, criticalMembers, ref first);
            }

            if(contribution.AuthorizationSchemeSpecUrns is { Count: > 0 } specUrns)
            {
                AppendAuthorizationSchemes(sb, specUrns, ref first);
            }

            if(!string.IsNullOrEmpty(contribution.DefaultSubjects))
            {
                JsonAppender.AppendStringField(
                    sb, SsfMetadataParameterNames.DefaultSubjects, contribution.DefaultSubjects, ref first);
            }

            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Serialises one stream configuration (SSF §8.1.1). The same writer backs
    /// the create (201), read (200), and update/replace (200) responses so the
    /// wire shape cannot diverge between operations.
    /// </summary>
    public static string BuildStreamConfigurationJson(SsfStreamConfiguration stream)
    {
        ArgumentNullException.ThrowIfNull(stream);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            AppendStreamConfiguration(sb, stream);

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Serialises a list of stream configurations as the JSON array a
    /// no-<c>stream_id</c> read returns (SSF §8.1.1.2).
    /// </summary>
    public static string BuildStreamConfigurationsJson(IReadOnlyList<SsfStreamConfiguration> streams)
    {
        ArgumentNullException.ThrowIfNull(streams);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('[');
            for(int i = 0; i < streams.Count; ++i)
            {
                if(i > 0)
                {
                    sb.Append(',');
                }

                AppendStreamConfiguration(sb, streams[i]);
            }

            sb.Append(']');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Serialises a stream status (SSF §8.1.2) — the body of a status read (200)
    /// and a status update (200) response.
    /// </summary>
    public static string BuildStreamStatusJson(SsfStreamStatus status)
    {
        ArgumentNullException.ThrowIfNull(status);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');

            bool first = true;
            JsonAppender.AppendStringField(sb, SsfStreamStatusParameterNames.StreamId, status.StreamId, ref first);
            JsonAppender.AppendStringField(sb, SsfStreamStatusParameterNames.Status, status.Status, ref first);
            if(!string.IsNullOrEmpty(status.Reason))
            {
                JsonAppender.AppendStringField(sb, SsfStreamStatusParameterNames.Reason, status.Reason, ref first);
            }

            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    //SSF §7.1.1: authorization_schemes is an array of objects each carrying the
    //REQUIRED spec_urn naming the authorization protocol.
    private static void AppendAuthorizationSchemes(
        StringBuilder sb, IReadOnlyList<string> specUrns, ref bool first)
    {
        if(!first)
        {
            sb.Append(',');
        }

        sb.Append('"');
        JsonAppender.AppendEscapedString(sb, SsfMetadataParameterNames.AuthorizationSchemes);
        sb.Append("\":[");

        for(int i = 0; i < specUrns.Count; ++i)
        {
            if(i > 0)
            {
                sb.Append(',');
            }

            sb.Append("{\"");
            JsonAppender.AppendEscapedString(sb, SsfMetadataParameterNames.SpecUrn);
            sb.Append("\":\"");
            JsonAppender.AppendEscapedString(sb, specUrns[i]);
            sb.Append("\"}");
        }

        sb.Append(']');

        first = false;
    }


    private static void AppendStreamConfiguration(StringBuilder sb, SsfStreamConfiguration stream)
    {
        sb.Append('{');

        bool first = true;
        JsonAppender.AppendStringField(sb, SsfStreamConfigParameterNames.StreamId, stream.StreamId, ref first);
        JsonAppender.AppendStringField(sb, SsfStreamConfigParameterNames.Iss, stream.Issuer, ref first);
        JsonAppender.AppendStringArrayField(sb, SsfStreamConfigParameterNames.Aud, stream.Audiences, ref first);
        AppendDelivery(sb, stream.Delivery, ref first);

        if(stream.EventsSupported is { Count: > 0 } supported)
        {
            JsonAppender.AppendStringArrayField(sb, SsfStreamConfigParameterNames.EventsSupported, supported, ref first);
        }

        if(stream.EventsRequested is { Count: > 0 } requested)
        {
            JsonAppender.AppendStringArrayField(sb, SsfStreamConfigParameterNames.EventsRequested, requested, ref first);
        }

        if(stream.EventsDelivered is { Count: > 0 } delivered)
        {
            JsonAppender.AppendStringArrayField(sb, SsfStreamConfigParameterNames.EventsDelivered, delivered, ref first);
        }

        if(stream.MinVerificationInterval is int minInterval)
        {
            JsonAppender.AppendInt64Field(sb, SsfStreamConfigParameterNames.MinVerificationInterval, minInterval, ref first);
        }

        if(!string.IsNullOrEmpty(stream.Description))
        {
            JsonAppender.AppendStringField(sb, SsfStreamConfigParameterNames.Description, stream.Description, ref first);
        }

        if(stream.InactivityTimeout is int inactivity)
        {
            JsonAppender.AppendInt64Field(sb, SsfStreamConfigParameterNames.InactivityTimeout, inactivity, ref first);
        }

        sb.Append('}');
    }


    private static void AppendDelivery(StringBuilder sb, SsfDeliveryConfiguration delivery, ref bool first)
    {
        if(!first)
        {
            sb.Append(',');
        }

        sb.Append('"');
        JsonAppender.AppendEscapedString(sb, SsfStreamConfigParameterNames.Delivery);
        sb.Append("\":{");

        bool deliveryFirst = true;
        JsonAppender.AppendStringField(sb, SsfDeliveryParameterNames.Method, delivery.Method, ref deliveryFirst);
        if(!string.IsNullOrEmpty(delivery.EndpointUrl))
        {
            JsonAppender.AppendStringField(sb, SsfDeliveryParameterNames.EndpointUrl, delivery.EndpointUrl, ref deliveryFirst);
        }

        if(!string.IsNullOrEmpty(delivery.AuthorizationHeader))
        {
            JsonAppender.AppendStringField(sb, SsfDeliveryParameterNames.AuthorizationHeader, delivery.AuthorizationHeader, ref deliveryFirst);
        }

        sb.Append('}');

        first = false;
    }
}
