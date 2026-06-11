using System.Text.Json;
using Verifiable.Core;
using Verifiable.OAuth;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> parser for the RFC 9396 <c>authorization_details</c>
/// request parameter — the JSON side the <c>Verifiable.OAuth</c> serialization firewall keeps
/// out of the core library. Wire it onto an
/// <see cref="Verifiable.OAuth.Server.AuthorizationServerIntegration"/> with
/// <see cref="AuthorizationDetailsJsonExtensions.UseDefaultAuthorizationDetailsJsonParsing"/>.
/// </summary>
public static class AuthorizationDetailsJsonParsing
{
    /// <summary>
    /// Parses an <c>authorization_details</c> value: a JSON array of objects, each carrying the
    /// RFC 9396 §2 REQUIRED string <c>type</c>, the §2.2 common data fields
    /// (<c>locations</c>/<c>actions</c>/<c>datatypes</c>/<c>identifier</c>/<c>privileges</c>),
    /// and any type-specific members preserved verbatim in
    /// <see cref="AuthorizationDetail.ExtensionData"/>.
    /// </summary>
    /// <remarks>
    /// STRICT only on the RFC 9396 structure: a value that is not a JSON array of objects, or an
    /// entry without a string <c>type</c>, yields <see langword="null"/> — the endpoint then
    /// responds <c>invalid_authorization_details</c>. The per-type shape checks (supported type,
    /// required fields) are applied by the library's
    /// <see cref="Verifiable.OAuth.Server.AuthorizationDetailTypeRegistry"/> after the parse.
    /// </remarks>
    /// <param name="authorizationDetailsJson">The parameter value, verbatim from the request.</param>
    /// <param name="context">The per-request context bag.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static ValueTask<IReadOnlyList<AuthorizationDetail>?> ParseAuthorizationDetails(
        string authorizationDetailsJson, ExchangeContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorizationDetailsJson);

        try
        {
            using JsonDocument doc = JsonDocument.Parse(authorizationDetailsJson);
            JsonElement root = doc.RootElement;
            if(root.ValueKind != JsonValueKind.Array)
            {
                return ValueTask.FromResult<IReadOnlyList<AuthorizationDetail>?>(null);
            }

            List<AuthorizationDetail> details = [];
            foreach(JsonElement entry in root.EnumerateArray())
            {
                if(entry.ValueKind != JsonValueKind.Object
                    || !entry.TryGetProperty(AuthorizationDetailsParameterNames.Type, out JsonElement typeElement)
                    || typeElement.ValueKind != JsonValueKind.String)
                {
                    return ValueTask.FromResult<IReadOnlyList<AuthorizationDetail>?>(null);
                }

                details.Add(ReadDetail(entry, typeElement.GetString()!));
            }

            return ValueTask.FromResult<IReadOnlyList<AuthorizationDetail>?>(details);
        }
        catch(JsonException)
        {
            return ValueTask.FromResult<IReadOnlyList<AuthorizationDetail>?>(null);
        }
    }


    /// <summary>
    /// Reads one authorization details object: promotes the §2.2 common fields to their typed
    /// slots and carries every remaining member, keyed by its JSON member name, into
    /// <see cref="AuthorizationDetail.ExtensionData"/> as the raw JSON text of its value. A common
    /// field present with the wrong JSON type stays out of its slot and is recorded in
    /// <see cref="AuthorizationDetail.MalformedCommonFields"/> so a strict handler can refuse it
    /// as an RFC 9396 §5 wrong-type abort, while the lenient <c>openid_credential</c> profile
    /// treats it as absent.
    /// </summary>
    private static AuthorizationDetail ReadDetail(JsonElement entry, string type)
    {
        Dictionary<string, string> extensionData = new(StringComparer.Ordinal);
        foreach(JsonProperty member in entry.EnumerateObject())
        {
            if(IsCommonOrTypeMember(member.Name))
            {
                continue;
            }

            extensionData[member.Name] = member.Value.GetRawText();
        }

        List<string> malformedCommonFields = [];

        return new AuthorizationDetail
        {
            Type = type,
            Locations = ReadOptionalStringArray(entry, AuthorizationDetailsParameterNames.Locations, malformedCommonFields),
            Actions = ReadOptionalStringArray(entry, AuthorizationDetailsParameterNames.Actions, malformedCommonFields),
            DataTypes = ReadOptionalStringArray(entry, AuthorizationDetailsParameterNames.DataTypes, malformedCommonFields),
            Identifier = ReadOptionalString(entry, AuthorizationDetailsParameterNames.Identifier, malformedCommonFields),
            Privileges = ReadOptionalStringArray(entry, AuthorizationDetailsParameterNames.Privileges, malformedCommonFields),
            ExtensionData = extensionData,
            MalformedCommonFields = malformedCommonFields
        };
    }


    /// <summary>
    /// Whether <paramref name="memberName"/> is the §2 <c>type</c> or one of the §2.2 common
    /// fields — the members promoted to typed slots and so excluded from
    /// <see cref="AuthorizationDetail.ExtensionData"/>.
    /// </summary>
    private static bool IsCommonOrTypeMember(string memberName)
    {
        return string.Equals(memberName, AuthorizationDetailsParameterNames.Type, StringComparison.Ordinal)
            || string.Equals(memberName, AuthorizationDetailsParameterNames.Locations, StringComparison.Ordinal)
            || string.Equals(memberName, AuthorizationDetailsParameterNames.Actions, StringComparison.Ordinal)
            || string.Equals(memberName, AuthorizationDetailsParameterNames.DataTypes, StringComparison.Ordinal)
            || string.Equals(memberName, AuthorizationDetailsParameterNames.Identifier, StringComparison.Ordinal)
            || string.Equals(memberName, AuthorizationDetailsParameterNames.Privileges, StringComparison.Ordinal);
    }


    /// <summary>
    /// Reads a §2.2 common field that RFC 9396 defines as a string (<c>identifier</c>). Absent
    /// yields <see langword="null"/> silently; present-but-not-a-string records the member in
    /// <paramref name="malformedCommonFields"/> and yields <see langword="null"/>.
    /// </summary>
    private static string? ReadOptionalString(JsonElement entry, string member, List<string> malformedCommonFields)
    {
        if(!entry.TryGetProperty(member, out JsonElement value))
        {
            return null;
        }

        if(value.ValueKind != JsonValueKind.String)
        {
            malformedCommonFields.Add(member);

            return null;
        }

        return value.GetString();
    }


    /// <summary>
    /// Reads a §2.2 common field that RFC 9396 defines as an array of strings
    /// (<c>locations</c>/<c>actions</c>/<c>datatypes</c>/<c>privileges</c>). Absent yields
    /// <see langword="null"/> silently; present but not an array, or an array carrying a
    /// non-string element, records the member in <paramref name="malformedCommonFields"/> and
    /// yields <see langword="null"/>.
    /// </summary>
    private static List<string>? ReadOptionalStringArray(JsonElement entry, string member, List<string> malformedCommonFields)
    {
        if(!entry.TryGetProperty(member, out JsonElement value))
        {
            return null;
        }

        if(value.ValueKind != JsonValueKind.Array)
        {
            malformedCommonFields.Add(member);

            return null;
        }

        List<string> values = [];
        foreach(JsonElement item in value.EnumerateArray())
        {
            if(item.ValueKind != JsonValueKind.String)
            {
                malformedCommonFields.Add(member);

                return null;
            }

            values.Add(item.GetString()!);
        }

        return values;
    }
}
