using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.StatusList;
using Verifiable.JCose;

namespace Verifiable.Json.StatusList;

/// <summary>
/// System.Text.Json converter for <see cref="StatusListToken"/> handling the JWT Claims Set
/// (<c>sub</c>/<c>iat</c>/<c>exp</c>/<c>ttl</c>/<c>status_list</c>) defined in Section 5.1 of the
/// specification — the JSON tier's own copy of the claims-set shape <c>StatusListTokenCborConverter</c>
/// already implements for CWT, symmetric member for member.
/// </summary>
/// <remarks>
/// <para>
/// Reads and writes the following JSON structure:
/// </para>
/// <code>
/// {
///   "sub": "https://example.com/statuslists/1",
///   "iat": 1686920170,
///   "exp": 2291720170,
///   "ttl": 43200,
///   "status_list": {
///     "bits": 1,
///     "lst": "eNrbuRgAAhcBXQ"
///   }
/// }
/// </code>
/// <para>
/// "sub: REQUIRED." / "iat: REQUIRED." / "status_list: REQUIRED." — a missing value for any of these
/// is a read failure naming the claim. "exp: RECOMMENDED." / "ttl: RECOMMENDED. … The value of the
/// claim MUST be a positive number encoded in JSON as a number." — both optional, and a present but
/// non-positive or non-numeric <c>ttl</c> is a read failure. "The JWT MAY contain other claims." —
/// every other member is skipped.
/// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
/// </para>
/// </remarks>
public sealed class StatusListTokenJsonConverter: JsonConverter<StatusListToken>
{
    /// <summary>The nested converter for the <c>status_list</c> member's Status List.</summary>
    private StatusListJsonConverter StatusListConverter { get; }

    /// <summary>
    /// Creates a new converter using the specified memory pool for the nested Status List.
    /// </summary>
    /// <param name="pool">The memory pool for allocating decompressed data.</param>
    public StatusListTokenJsonConverter(BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        StatusListConverter = new StatusListJsonConverter(pool);
    }

    /// <inheritdoc/>
    public override StatusListToken Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException("Expected start of JSON object for StatusListToken.");
        }

        string? subject = null;
        long? issuedAt = null;
        long? expirationTime = null;
        long? timeToLive = null;
        Core.StatusList.StatusList? statusList = null;

        //status_list can precede a later member that turns out missing or malformed (member order in
        //JSON is arbitrary, and the required-claim checks below run only once every member has been
        //read); every exit past a successful status_list decode disposes it before propagating, so a
        //late refusal never leaks the pooled Status List it already rented.
        try
        {
            while(reader.Read())
            {
                if(reader.TokenType == JsonTokenType.EndObject)
                {
                    break;
                }

                if(reader.TokenType != JsonTokenType.PropertyName)
                {
                    throw new JsonException("Expected property name.");
                }

                string propertyName = reader.GetString()!;
                reader.Read();

                switch(propertyName)
                {
                    case string name when name == WellKnownJwtClaimNames.Sub:
                        subject = reader.GetString();
                        break;
                    case string name when name == WellKnownJwtClaimNames.Iat:
                        issuedAt = reader.GetInt64();
                        break;
                    case string name when name == WellKnownJwtClaimNames.Exp:
                        expirationTime = reader.GetInt64();
                        break;
                    case string name when name == WellKnownJwtClaimNames.TimeToLive:
                        if(reader.TokenType != JsonTokenType.Number || !reader.TryGetInt64(out long ttl) || ttl <= 0)
                        {
                            throw new JsonException($"Claim '{WellKnownJwtClaimNames.TimeToLive}' MUST be a positive number.");
                        }

                        timeToLive = ttl;
                        break;
                    case string name when name == StatusListJsonConstants.StatusList:
                        statusList = StatusListConverter.Read(ref reader, typeof(Core.StatusList.StatusList), options);
                        break;
                    default:
                        reader.Skip();
                        break;
                }
            }

            if(subject is null)
            {
                throw new JsonException($"Missing required property '{WellKnownJwtClaimNames.Sub}'.");
            }

            if(!issuedAt.HasValue)
            {
                throw new JsonException($"Missing required property '{WellKnownJwtClaimNames.Iat}'.");
            }

            if(statusList is null)
            {
                throw new JsonException($"Missing required property '{StatusListJsonConstants.StatusList}'.");
            }

            return new StatusListToken(subject, DateTimeOffset.FromUnixTimeSeconds(issuedAt.Value), statusList)
            {
                ExpirationTime = expirationTime.HasValue ? DateTimeOffset.FromUnixTimeSeconds(expirationTime.Value) : null,
                TimeToLive = timeToLive
            };
        }
        catch(Exception)
        {
            statusList?.Dispose();

            throw;
        }
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, StatusListToken value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        writer.WriteStartObject();
        writer.WriteString(WellKnownJwtClaimNames.Sub, value.Subject);
        writer.WriteNumber(WellKnownJwtClaimNames.Iat, value.IssuedAt.ToUnixTimeSeconds());

        if(value.ExpirationTime.HasValue)
        {
            writer.WriteNumber(WellKnownJwtClaimNames.Exp, value.ExpirationTime.Value.ToUnixTimeSeconds());
        }

        if(value.TimeToLive.HasValue)
        {
            writer.WriteNumber(WellKnownJwtClaimNames.TimeToLive, value.TimeToLive.Value);
        }

        writer.WritePropertyName(StatusListJsonConstants.StatusList);
        StatusListConverter.Write(writer, value.StatusList, options);

        writer.WriteEndObject();
    }
}
