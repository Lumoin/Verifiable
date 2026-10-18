using System.Buffers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.StatusLists;
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
/// non-positive or non-numeric <c>ttl</c> is a read failure, while a positive fraction is a
/// <c>ttl</c> like any other. "The JWT MAY contain other claims." — every other member is skipped.
/// The <c>iat</c> and <c>exp</c> are NumericDates (RFC 7519 Section 2), read from the number token
/// exactly as written by the library's one reading of the type (<see cref="NumericDate.FromJsonNumber"/>):
/// a fraction is a date like any other, and a value that is no JSON number or names an instant no
/// clock represents is a read failure, never an exception of the date's construction.
/// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
/// </para>
/// </remarks>
public sealed class StatusListTokenJsonConverter : JsonConverter<StatusListToken>
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
        var issuedAt = default(NumericDate);
        var expirationTime = default(NumericDate);
        var timeToLive = default(DecimalNumber);
        Core.StatusLists.StatusList? statusList = null;

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
                _ = reader.Read();

                switch(propertyName)
                {
                    case string name when name == WellKnownJwtClaimNames.Sub:
                        subject = reader.GetString();
                        break;
                    case string name when name == WellKnownJwtClaimNames.Iat:
                        issuedAt = NumericDateOf(ref reader, WellKnownJwtClaimNames.Iat);
                        break;
                    case string name when name == WellKnownJwtClaimNames.Exp:
                        expirationTime = NumericDateOf(ref reader, WellKnownJwtClaimNames.Exp);
                        break;
                    case string name when name == WellKnownJwtClaimNames.TimeToLive:
                        timeToLive = NumberOf(ref reader);

                        if(timeToLive is null || timeToLive.IsZero || timeToLive.IsNegative)
                        {
                            throw new JsonException($"Claim '{WellKnownJwtClaimNames.TimeToLive}' MUST be a positive number.");
                        }

                        break;
                    case string name when name == StatusListJsonConstants.StatusList:
                        statusList = StatusListConverter.Read(ref reader, typeof(Core.StatusLists.StatusList), options);
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

            if(issuedAt is null)
            {
                throw new JsonException($"Missing required property '{WellKnownJwtClaimNames.Iat}'.");
            }

            if(statusList is null)
            {
                throw new JsonException($"Missing required property '{StatusListJsonConstants.StatusList}'.");
            }

            return new StatusListToken(subject, issuedAt, statusList)
            {
                ExpirationTime = expirationTime,
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
        writer.WritePropertyName(WellKnownJwtClaimNames.Iat);
        writer.WriteRawValue(value.IssuedAt.ToString());

        if(value.ExpirationTime is not null)
        {
            writer.WritePropertyName(WellKnownJwtClaimNames.Exp);
            writer.WriteRawValue(value.ExpirationTime.ToString());
        }

        if(value.TimeToLive is not null)
        {
            writer.WritePropertyName(WellKnownJwtClaimNames.TimeToLive);
            writer.WriteRawValue(value.TimeToLive.ToString());
        }

        writer.WritePropertyName(StatusListJsonConstants.StatusList);
        StatusListConverter.Write(writer, value.StatusList, options);

        writer.WriteEndObject();
    }


    /// <summary>
    /// The NumericDate the current number token names, every digit kept (<see cref="NumericDate.FromJsonNumber"/>).
    /// </summary>
    /// <param name="reader">The reader, positioned on the claim's value.</param>
    /// <param name="claimName">The claim's name, for the refusal.</param>
    /// <returns>The date.</returns>
    /// <exception cref="JsonException">The value is no JSON number, or names an instant no clock represents.</exception>
    private static NumericDate NumericDateOf(ref Utf8JsonReader reader, string claimName) =>
        NumberOf(ref reader) is DecimalNumber seconds && NumericDate.FromSeconds(seconds) is NumericDate date
            ? date
            : throw new JsonException($"Claim '{claimName}' MUST be a NumericDate naming an instant a clock represents.");


    /// <summary>
    /// The number the current token names, exactly as written (<see cref="DecimalNumber.FromJsonNumber"/>), or
    /// <see langword="null"/> when the token is no number.
    /// </summary>
    /// <param name="reader">The reader, positioned on the value.</param>
    /// <returns>The number, or <see langword="null"/>.</returns>
    private static DecimalNumber? NumberOf(ref Utf8JsonReader reader)
    {
        if(reader.TokenType != JsonTokenType.Number)
        {
            return null;
        }

        return reader.HasValueSequence
            ? DecimalNumber.FromJsonNumber(reader.ValueSequence.ToArray())
            : DecimalNumber.FromJsonNumber(reader.ValueSpan);
    }
}
