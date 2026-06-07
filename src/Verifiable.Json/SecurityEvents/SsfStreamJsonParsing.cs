using System;
using System.Text.Json;
using Verifiable.Core.SecurityEvents;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> parsers for the Shared Signals stream-management
/// bodies — Stream Configuration (SSF 1.0 §8.1.1) and Stream Status (§8.1.2) — the
/// JSON side the <c>Verifiable.Core</c> serialization firewall keeps out of the core.
/// </summary>
/// <remarks>
/// Faithful and strict (mirrors <see cref="SsfDiscoveryJsonParsing"/>): required
/// members absent, wrongly typed, or a non-conformant <c>status</c> value yields
/// <see langword="null"/>; never throws. These bodies are shared by the Receiver
/// (which reads them and supplies parts) and the Transmitter (which returns them).
/// </remarks>
public static class SsfStreamJsonParsing
{
    /// <summary>
    /// Parses a Stream Configuration object. <c>stream_id</c>, <c>iss</c>, <c>aud</c>, and a
    /// <c>delivery</c> object carrying <c>method</c> are required; returns <see langword="null"/>
    /// if any is missing or malformed.
    /// </summary>
    public static SsfStreamConfiguration? ParseStreamConfiguration(string configJson)
    {
        ArgumentNullException.ThrowIfNull(configJson);

        try
        {
            using JsonDocument document = JsonDocument.Parse(configJson, SsfJsonReadHelpers.DocumentOptions);
            JsonElement root = document.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            string? streamId = SsfJsonReadHelpers.ReadOptionalString(root, SsfStreamConfigParameterNames.StreamId);
            string? issuer = SsfJsonReadHelpers.ReadOptionalString(root, SsfStreamConfigParameterNames.Iss);
            var audiences = SsfJsonReadHelpers.ReadAudiences(root, SsfStreamConfigParameterNames.Aud);
            SsfDeliveryConfiguration? delivery = ReadDelivery(root);

            if(string.IsNullOrEmpty(streamId) || string.IsNullOrEmpty(issuer) || audiences is not { Count: > 0 } || delivery is null)
            {
                return null;
            }

            return new SsfStreamConfiguration
            {
                StreamId = streamId,
                Issuer = issuer,
                Audiences = audiences,
                Delivery = delivery,
                EventsSupported = SsfJsonReadHelpers.ReadStringArray(root, SsfStreamConfigParameterNames.EventsSupported),
                EventsRequested = SsfJsonReadHelpers.ReadStringArray(root, SsfStreamConfigParameterNames.EventsRequested),
                EventsDelivered = SsfJsonReadHelpers.ReadStringArray(root, SsfStreamConfigParameterNames.EventsDelivered),
                MinVerificationInterval = SsfJsonReadHelpers.ReadOptionalInt(root, SsfStreamConfigParameterNames.MinVerificationInterval),
                Description = SsfJsonReadHelpers.ReadOptionalString(root, SsfStreamConfigParameterNames.Description),
                InactivityTimeout = SsfJsonReadHelpers.ReadOptionalInt(root, SsfStreamConfigParameterNames.InactivityTimeout)
            };
        }
        catch(Exception ex) when(SsfJsonReadHelpers.IsParseFailure(ex))
        {
            return null;
        }
    }


    /// <summary>
    /// Parses a Stream Status object. <c>stream_id</c> and a conformant <c>status</c>
    /// (<c>enabled</c>/<c>paused</c>/<c>disabled</c>) are required; <c>reason</c> is optional.
    /// Returns <see langword="null"/> on any failure.
    /// </summary>
    public static SsfStreamStatus? ParseStreamStatus(string statusJson)
    {
        ArgumentNullException.ThrowIfNull(statusJson);

        try
        {
            using JsonDocument document = JsonDocument.Parse(statusJson, SsfJsonReadHelpers.DocumentOptions);
            JsonElement root = document.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            string? streamId = SsfJsonReadHelpers.ReadOptionalString(root, SsfStreamStatusParameterNames.StreamId);
            string? status = SsfJsonReadHelpers.ReadOptionalString(root, SsfStreamStatusParameterNames.Status);

            if(string.IsNullOrEmpty(streamId) || status is null || !SsfStreamStatusValues.IsAllowed(status))
            {
                return null;
            }

            return new SsfStreamStatus
            {
                StreamId = streamId,
                Status = status,
                Reason = SsfJsonReadHelpers.ReadOptionalString(root, SsfStreamStatusParameterNames.Reason)
            };
        }
        catch(Exception ex) when(SsfJsonReadHelpers.IsParseFailure(ex))
        {
            return null;
        }
    }


    /// <summary>
    /// Parses a Create Stream request (§8.1.1.1). All members are optional — an
    /// absent <c>delivery</c> means poll delivery. Returns <see langword="null"/> only
    /// for a non-object body or a wrongly-typed member.
    /// </summary>
    public static SsfStreamCreateRequest? ParseStreamCreateRequest(string requestJson)
    {
        ArgumentNullException.ThrowIfNull(requestJson);

        try
        {
            using JsonDocument document = JsonDocument.Parse(requestJson, SsfJsonReadHelpers.DocumentOptions);
            JsonElement root = document.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            return new SsfStreamCreateRequest
            {
                Delivery = ReadOptionalDelivery(root),
                EventsRequested = SsfJsonReadHelpers.ReadStringArray(root, SsfStreamConfigParameterNames.EventsRequested),
                Description = SsfJsonReadHelpers.ReadOptionalString(root, SsfStreamConfigParameterNames.Description)
            };
        }
        catch(Exception ex) when(SsfJsonReadHelpers.IsParseFailure(ex))
        {
            return null;
        }
    }


    /// <summary>
    /// Parses an Update (PATCH, §8.1.1.3) or Replace (PUT, §8.1.1.4) Stream request.
    /// <c>stream_id</c> is required; all other members are the optional properties to
    /// change or the Transmitter-supplied echoes to match. Returns <see langword="null"/>
    /// on failure.
    /// </summary>
    public static SsfStreamUpdateRequest? ParseStreamUpdateRequest(string requestJson)
    {
        ArgumentNullException.ThrowIfNull(requestJson);

        try
        {
            using JsonDocument document = JsonDocument.Parse(requestJson, SsfJsonReadHelpers.DocumentOptions);
            JsonElement root = document.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            string? streamId = SsfJsonReadHelpers.ReadOptionalString(root, SsfStreamConfigParameterNames.StreamId);
            if(string.IsNullOrEmpty(streamId))
            {
                return null;
            }

            return new SsfStreamUpdateRequest
            {
                StreamId = streamId,
                Delivery = ReadOptionalDelivery(root),
                EventsRequested = SsfJsonReadHelpers.ReadStringArray(root, SsfStreamConfigParameterNames.EventsRequested),
                Description = SsfJsonReadHelpers.ReadOptionalString(root, SsfStreamConfigParameterNames.Description),
                Issuer = SsfJsonReadHelpers.ReadOptionalString(root, SsfStreamConfigParameterNames.Iss),
                Audiences = SsfJsonReadHelpers.ReadAudiences(root, SsfStreamConfigParameterNames.Aud),
                EventsSupported = SsfJsonReadHelpers.ReadStringArray(root, SsfStreamConfigParameterNames.EventsSupported),
                EventsDelivered = SsfJsonReadHelpers.ReadStringArray(root, SsfStreamConfigParameterNames.EventsDelivered)
            };
        }
        catch(Exception ex) when(SsfJsonReadHelpers.IsParseFailure(ex))
        {
            return null;
        }
    }


    /// <summary>
    /// Parses an Add Subject request (§8.1.3.2). <c>stream_id</c> and a well-formed
    /// <c>subject</c> are required; <c>verified</c> is optional. Returns <see langword="null"/> on failure.
    /// </summary>
    public static SsfAddSubjectRequest? ParseAddSubjectRequest(string requestJson)
    {
        ArgumentNullException.ThrowIfNull(requestJson);

        try
        {
            using JsonDocument document = JsonDocument.Parse(requestJson, SsfJsonReadHelpers.DocumentOptions);
            JsonElement root = document.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            string? streamId = SsfJsonReadHelpers.ReadOptionalString(root, SsfStreamManagementParameterNames.StreamId);
            SubjectIdentifier? subject = SsfJsonReadHelpers.ReadSubject(root, SsfStreamManagementParameterNames.Subject);
            if(string.IsNullOrEmpty(streamId) || subject is null)
            {
                return null;
            }

            return new SsfAddSubjectRequest
            {
                StreamId = streamId,
                Subject = subject,
                Verified = SsfJsonReadHelpers.ReadOptionalBool(root, SsfStreamManagementParameterNames.Verified)
            };
        }
        catch(Exception ex) when(SsfJsonReadHelpers.IsParseFailure(ex))
        {
            return null;
        }
    }


    /// <summary>
    /// Parses a Remove Subject request (§8.1.3.3). <c>stream_id</c> and a well-formed
    /// <c>subject</c> are required. Returns <see langword="null"/> on failure.
    /// </summary>
    public static SsfRemoveSubjectRequest? ParseRemoveSubjectRequest(string requestJson)
    {
        ArgumentNullException.ThrowIfNull(requestJson);

        try
        {
            using JsonDocument document = JsonDocument.Parse(requestJson, SsfJsonReadHelpers.DocumentOptions);
            JsonElement root = document.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            string? streamId = SsfJsonReadHelpers.ReadOptionalString(root, SsfStreamManagementParameterNames.StreamId);
            SubjectIdentifier? subject = SsfJsonReadHelpers.ReadSubject(root, SsfStreamManagementParameterNames.Subject);
            if(string.IsNullOrEmpty(streamId) || subject is null)
            {
                return null;
            }

            return new SsfRemoveSubjectRequest { StreamId = streamId, Subject = subject };
        }
        catch(Exception ex) when(SsfJsonReadHelpers.IsParseFailure(ex))
        {
            return null;
        }
    }


    /// <summary>
    /// Parses a Trigger Verification request (§8.1.4.2). <c>stream_id</c> is required;
    /// <c>state</c> is optional. Returns <see langword="null"/> on failure.
    /// </summary>
    public static SsfVerificationRequest? ParseVerificationRequest(string requestJson)
    {
        ArgumentNullException.ThrowIfNull(requestJson);

        try
        {
            using JsonDocument document = JsonDocument.Parse(requestJson, SsfJsonReadHelpers.DocumentOptions);
            JsonElement root = document.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            string? streamId = SsfJsonReadHelpers.ReadOptionalString(root, SsfStreamManagementParameterNames.StreamId);
            if(string.IsNullOrEmpty(streamId))
            {
                return null;
            }

            return new SsfVerificationRequest
            {
                StreamId = streamId,
                State = SsfJsonReadHelpers.ReadOptionalString(root, SsfStreamManagementParameterNames.State)
            };
        }
        catch(Exception ex) when(SsfJsonReadHelpers.IsParseFailure(ex))
        {
            return null;
        }
    }


    //For create/update requests delivery is OPTIONAL: absent is fine (create
    //defaults to poll), but a present delivery object missing its method is a
    //malformed request rather than "no delivery".
    private static SsfDeliveryConfiguration? ReadOptionalDelivery(JsonElement root)
    {
        if(!root.TryGetProperty(SsfStreamConfigParameterNames.Delivery, out _))
        {
            return null;
        }

        SsfDeliveryConfiguration? delivery = ReadDelivery(root);
        if(delivery is null)
        {
            throw new JsonException(
                $"Field '{SsfStreamConfigParameterNames.Delivery}' must carry '{SsfDeliveryParameterNames.Method}'.");
        }

        return delivery;
    }


    private static SsfDeliveryConfiguration? ReadDelivery(JsonElement root)
    {
        if(!root.TryGetProperty(SsfStreamConfigParameterNames.Delivery, out JsonElement delivery))
        {
            return null;
        }

        if(delivery.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException($"Field '{SsfStreamConfigParameterNames.Delivery}' must be a JSON object.");
        }

        string? method = SsfJsonReadHelpers.ReadOptionalString(delivery, SsfDeliveryParameterNames.Method);
        if(string.IsNullOrEmpty(method))
        {
            return null;
        }

        return new SsfDeliveryConfiguration
        {
            Method = method,
            EndpointUrl = SsfJsonReadHelpers.ReadOptionalString(delivery, SsfDeliveryParameterNames.EndpointUrl),
            AuthorizationHeader = SsfJsonReadHelpers.ReadOptionalString(delivery, SsfDeliveryParameterNames.AuthorizationHeader)
        };
    }
}
