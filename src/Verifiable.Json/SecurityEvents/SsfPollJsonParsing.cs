using System;
using System.Collections.Generic;
using System.Text.Json;
using Verifiable.Core.SecurityEvents;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> parsers for the poll-delivery bodies of
/// <see href="https://www.rfc-editor.org/rfc/rfc8936">RFC 8936</see> — the poll
/// request a Receiver sends and the poll response a Transmitter returns. Faithful
/// and strict, mirroring the other Shared Signals parsers; never throws.
/// </summary>
public static class SsfPollJsonParsing
{
    /// <summary>
    /// Parses a poll request (§2.2). All members are optional (an empty object is a valid
    /// poll-only request); a non-object body yields <see langword="null"/>.
    /// </summary>
    public static SsfPollRequest? ParsePollRequest(string requestJson)
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

            var acks = SsfJsonReadHelpers.ReadStringArray(root, SsfPollParameterNames.Ack);
            Dictionary<string, SsfSetError>? setErrors = ReadSetErrors(root);

            return new SsfPollRequest
            {
                MaxEvents = SsfJsonReadHelpers.ReadOptionalInt(root, SsfPollParameterNames.MaxEvents),
                ReturnImmediately = SsfJsonReadHelpers.ReadOptionalBool(root, SsfPollParameterNames.ReturnImmediately),
                Acks = acks ?? [],
                SetErrors = setErrors ?? new Dictionary<string, SsfSetError>(StringComparer.Ordinal)
            };
        }
        catch(Exception ex) when(SsfJsonReadHelpers.IsParseFailure(ex))
        {
            return null;
        }
    }


    /// <summary>
    /// Parses a poll response (§2.3): <c>sets</c> (jti → compact SET string) and the
    /// optional <c>moreAvailable</c> flag. A non-object body yields <see langword="null"/>.
    /// </summary>
    public static SsfPollResponse? ParsePollResponse(string responseJson)
    {
        ArgumentNullException.ThrowIfNull(responseJson);

        try
        {
            using JsonDocument document = JsonDocument.Parse(responseJson, SsfJsonReadHelpers.DocumentOptions);
            JsonElement root = document.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            Dictionary<string, string>? sets = ReadSets(root);

            return new SsfPollResponse
            {
                Sets = sets ?? new Dictionary<string, string>(StringComparer.Ordinal),
                MoreAvailable = SsfJsonReadHelpers.ReadOptionalBool(root, SsfPollParameterNames.MoreAvailable) ?? false
            };
        }
        catch(Exception ex) when(SsfJsonReadHelpers.IsParseFailure(ex))
        {
            return null;
        }
    }


    private static Dictionary<string, SsfSetError>? ReadSetErrors(JsonElement root)
    {
        if(!root.TryGetProperty(SsfPollParameterNames.SetErrs, out JsonElement value))
        {
            return null;
        }

        if(value.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException($"Field '{SsfPollParameterNames.SetErrs}' must be a JSON object.");
        }

        var errors = new Dictionary<string, SsfSetError>(StringComparer.Ordinal);
        foreach(JsonProperty entry in value.EnumerateObject())
        {
            if(entry.Value.ValueKind != JsonValueKind.Object)
            {
                throw new JsonException($"Each '{SsfPollParameterNames.SetErrs}' entry must be a JSON object.");
            }

            string? err = SsfJsonReadHelpers.ReadOptionalString(entry.Value, SsfSetErrorParameterNames.Err);
            if(string.IsNullOrEmpty(err))
            {
                throw new JsonException($"A '{SsfPollParameterNames.SetErrs}' entry is missing required '{SsfSetErrorParameterNames.Err}'.");
            }

            errors[entry.Name] = new SsfSetError
            {
                Err = err,
                Description = SsfJsonReadHelpers.ReadOptionalString(entry.Value, SsfSetErrorParameterNames.Description)
            };
        }

        return errors;
    }


    private static Dictionary<string, string>? ReadSets(JsonElement root)
    {
        if(!root.TryGetProperty(SsfPollParameterNames.Sets, out JsonElement value))
        {
            return null;
        }

        if(value.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException($"Field '{SsfPollParameterNames.Sets}' must be a JSON object.");
        }

        var sets = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach(JsonProperty entry in value.EnumerateObject())
        {
            if(entry.Value.ValueKind != JsonValueKind.String)
            {
                throw new JsonException($"Each '{SsfPollParameterNames.Sets}' value must be a string (a compact SET).");
            }

            sets[entry.Name] = entry.Value.GetString()!;
        }

        return sets;
    }
}
