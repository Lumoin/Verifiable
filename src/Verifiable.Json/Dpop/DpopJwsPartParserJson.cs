using System.Text.Json;
using Verifiable.JCose;
using Verifiable.OAuth.Dpop;

namespace Verifiable.Json;

/// <summary>
/// The concrete <c>System.Text.Json</c> implementation of <see cref="DpopJwsPartParser"/>: reads the protected header
/// and the payload of a DPoP proof (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section
/// 4.2</see>) into <see cref="DpopProofHeader"/> and <see cref="DpopProofClaims"/> for
/// <see cref="DpopProofValidator"/>, the inbound counterpart of <see cref="DpopJwsPartSerializerJson"/>.
/// </summary>
/// <remarks>
/// <para>
/// A host passes <see cref="Default"/> as the <c>parser</c> argument of either <c>ValidateAsync</c> overload of
/// <see cref="DpopProofValidator"/> where it wires its <see cref="ValidateDpopProofDelegate"/>, or wires it as
/// <see cref="Verifiable.OAuth.Server.AuthorizationServerCodecs.DpopProofParser"/> for the library default
/// <see cref="DefaultDpopProofValidation"/>; no registry names it. Every refusal is a
/// <see cref="FormatException"/>, what <see cref="DpopJwsPartParser"/> requires of a refusal, which the validator answers as
/// <see cref="DpopProofValidationFailureReason.Malformed"/>: a segment that is not JSON, and a member name or string
/// value whose escapes encode no Unicode text, an unpaired UTF-16 surrogate among them
/// (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.2">RFC 8259 Section 8.2</see>: "the ABNF in this
/// specification allows member names and string values to contain bit sequences that cannot encode Unicode
/// characters"), alike.
/// </para>
/// <para>
/// Every object of either segment is read with <see cref="JsonDocumentOptions.AllowDuplicateProperties"/> off, so a
/// member name repeated in one object is refused rather than read as one of its occurrences: in the header,
/// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4">RFC 7515 Section 4</see>, "The Header Parameter names
/// within the JOSE Header MUST be unique; JWS parsers MUST either reject JWSs with duplicate Header Parameter names or
/// use a JSON parser that returns only the lexically last duplicate member name"; in the payload,
/// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4">RFC 7519 Section 4</see>, "The Claim Names within a JWT
/// Claims Set MUST be unique; JWT parsers MUST either reject JWTs with duplicate Claim Names or use a JSON parser that
/// returns only the lexically last duplicate member name"; and in the header's <c>jwk</c>,
/// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4">RFC 7517 Section 4</see>, "The member names within a
/// JWK MUST be unique; JWK parsers MUST either reject JWKs with duplicate member names or use a JSON parser that
/// returns only the lexically last duplicate member name".
/// </para>
/// <para>
/// The header: <c>alg</c> a JSON string, required; <c>typ</c> a JSON string, read as the empty string when absent so
/// the validator answers <see cref="DpopProofValidationFailureReason.InvalidTyp"/>; <c>jwk</c> a JSON object,
/// required. Of the <c>jwk</c>'s members, each holding a JSON string is kept; each whose name
/// <see cref="WellKnownJwkMemberNames.IsPrivateOrSymmetricMember(string)"/> names is kept whatever its JSON type, its
/// value the member's raw JSON text, so the validator's refusal of private key material reads it
/// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 7: "The jwk JOSE
/// Header Parameter does not contain a private key."; <c>oth</c> is always an array,
/// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7">RFC 7518 Section 6.3.2.7</see>); the <c>use</c>
/// member is kept whatever its JSON type, its value the member's raw JSON text, so the validator's check of the public
/// key's use reads it and refuses a <c>use</c> of any JSON type other than the string <c>sig</c>
/// (<see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.2">RFC 7517 Section 4.2</see>: "The "use" value is a
/// case-sensitive string."); and every other member of another JSON type is ignored
/// (<see href="https://www.rfc-editor.org/rfc/rfc7517#section-4">RFC 7517 Section 4</see>: "Additional members can be
/// present in the JWK; if not understood by implementations encountering them, they MUST be ignored."). The checks
/// the validator makes answer the rest of the <c>jwk</c>: the members its thumbprint requires, the refusal of a
/// private member, the <c>use</c> member, and the binding of the public key to <c>alg</c>. <c>key_ops</c> is a JSON
/// array (<see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.3">RFC 7517 Section 4.3</see>: "Its value is an
/// array of key operation values."), so it is not kept, and the validator does not read it.
/// </para>
/// <para>
/// The payload: <c>jti</c>, <c>htm</c> and <c>htu</c> JSON strings and <c>iat</c> a JSON number, each required
/// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>: "The payload of a DPoP
/// proof MUST contain at least the following claims"; Section 4.3, check 3: "All required claims per Section 4.2 are
/// contained in the JWT."), <c>iat</c> read as a NumericDate
/// (<see href="https://www.rfc-editor.org/rfc/rfc7519#section-2">RFC 7519 Section 2</see>: "A JSON numeric value
/// representing the number of seconds from 1970-01-01T00:00:00Z UTC until the specified UTC date/time, ignoring leap
/// seconds.") to the whole second its number, as written, falls in; <c>nonce</c> and <c>ath</c> JSON strings when
/// present, their conditions the validator's. A member of another JSON type than the one named, or a segment that is
/// not one JSON object, is refused.
/// </para>
/// </remarks>
public static class DpopJwsPartParserJson
{
    /// <summary>
    /// The default <see cref="DpopJwsPartParser"/>: <see cref="DpopJwsPartParser.ParseHeader"/> and
    /// <see cref="DpopJwsPartParser.ParseClaims"/> over the UTF-8 JSON of the two segments, each refusal a
    /// <see cref="FormatException"/>.
    /// </summary>
    public static DpopJwsPartParser Default { get; } = new()
    {
        ParseHeader = ParseHeader,
        ParseClaims = ParseClaims
    };


    /// <summary>
    /// The options both segments are read with: a member name repeated inside one object is refused (RFC 7515 Section
    /// 4 for the header, RFC 7519 Section 4 for the payload, RFC 7517 Section 4 for the <c>jwk</c>).
    /// </summary>
    private static JsonDocumentOptions ParseOptions { get; } = new() { AllowDuplicateProperties = false };

    /// <summary>The name of the header segment in a refusal's message.</summary>
    private static string HeaderPart { get; } = "header";

    /// <summary>The name of the payload segment in a refusal's message.</summary>
    private static string PayloadPart { get; } = "payload";

    /// <summary>
    /// The least NumericDate a <see cref="DateTimeOffset"/> represents, 0001-01-01T00:00:00Z in seconds from the
    /// epoch.
    /// </summary>
    private static long MinimumNumericDate { get; } = DateTimeOffset.MinValue.ToUnixTimeSeconds();

    /// <summary>
    /// The greatest NumericDate a <see cref="DateTimeOffset"/> represents, 9999-12-31T23:59:59Z in seconds from the
    /// epoch.
    /// </summary>
    private static long MaximumNumericDate { get; } = DateTimeOffset.MaxValue.ToUnixTimeSeconds();


    /// <summary>
    /// Reads the protected header of a DPoP proof: <c>alg</c>, <c>typ</c> and the members of <c>jwk</c> the reading
    /// keeps.
    /// </summary>
    /// <param name="segment">The UTF-8 JSON of the decoded header segment.</param>
    /// <returns>The header.</returns>
    /// <exception cref="FormatException">The segment is not one JSON object with unique member names, a name or string encodes no Unicode text, or a member is absent or of another JSON type than the one it names.</exception>
    private static DpopProofHeader ParseHeader(ReadOnlyMemory<byte> segment) => ReadSegment(segment, HeaderPart, ReadHeader);


    /// <summary>
    /// Reads the payload of a DPoP proof: <c>jti</c>, <c>htm</c>, <c>htu</c>, <c>iat</c>, and <c>nonce</c> and
    /// <c>ath</c> when present.
    /// </summary>
    /// <param name="segment">The UTF-8 JSON of the decoded payload segment.</param>
    /// <returns>The claims.</returns>
    /// <exception cref="FormatException">
    /// The segment is not one JSON object with unique member names, a name or string encodes no Unicode text, a required
    /// claim is absent (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check
    /// 3: "All required claims per Section 4.2 are contained in the JWT."), or a member is of another JSON type than the
    /// one it names.
    /// </exception>
    private static DpopProofClaims ParseClaims(ReadOnlyMemory<byte> segment) => ReadSegment(segment, PayloadPart, ReadClaims);


    /// <summary>
    /// Parses <paramref name="segment"/> as one JSON object whose objects carry each member name once and reads it with
    /// <paramref name="read"/>, so that every failure of the parse or of the reading is a <see cref="FormatException"/>
    /// naming the segment: a <see cref="JsonException"/> of the parse, and the <see cref="InvalidOperationException"/> the
    /// decoding of a member name or string value throws when its escapes encode no Unicode text.
    /// </summary>
    /// <typeparam name="T">The value the segment is read into.</typeparam>
    /// <param name="segment">The UTF-8 JSON of a decoded segment.</param>
    /// <param name="part">The segment's name, for the refusal's message.</param>
    /// <param name="read">Reads the segment's object.</param>
    /// <returns>The value read.</returns>
    /// <exception cref="FormatException">The segment is refused.</exception>
    private static T ReadSegment<T>(ReadOnlyMemory<byte> segment, string part, Func<JsonElement, T> read)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(segment, ParseOptions);
            JsonElement root = document.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                throw new FormatException($"The DPoP proof {part} is not a JSON object.");
            }

            return read(root);
        }
        catch(JsonException exception)
        {
            throw new FormatException($"The DPoP proof {part} is not JSON with unique member names.", exception);
        }
        catch(InvalidOperationException exception)
        {
            throw new FormatException($"The DPoP proof {part} carries a member name or string value that encodes no Unicode text.", exception);
        }
    }


    /// <summary>Reads the header's object: <c>alg</c>, <c>typ</c> and <c>jwk</c>.</summary>
    /// <param name="root">The header's object.</param>
    /// <returns>The header.</returns>
    /// <exception cref="FormatException">A member is absent or of another JSON type than the one it names.</exception>
    private static DpopProofHeader ReadHeader(JsonElement root)
    {
        string alg = ReadRequiredString(root, WellKnownJoseHeaderNames.Alg, HeaderPart);
        string typ = ReadOptionalString(root, WellKnownJoseHeaderNames.Typ, HeaderPart) ?? string.Empty;
        Dictionary<string, string> jwk = ReadJwk(root);

        return new DpopProofHeader { Alg = alg, Typ = typ, Jwk = jwk };
    }


    /// <summary>Reads the payload's object: the four required claims and the two conditional ones.</summary>
    /// <param name="root">The payload's object.</param>
    /// <returns>The claims.</returns>
    /// <exception cref="FormatException">A required claim is absent, or a member is of another JSON type than the one it names.</exception>
    private static DpopProofClaims ReadClaims(JsonElement root)
    {
        string jti = ReadRequiredString(root, WellKnownJwtClaimNames.Jti, PayloadPart);
        string htm = ReadRequiredString(root, WellKnownJwtClaimNames.Htm, PayloadPart);
        string htu = ReadRequiredString(root, WellKnownJwtClaimNames.Htu, PayloadPart);
        DateTimeOffset iat = root.TryGetProperty(WellKnownJwtClaimNames.Iat, out JsonElement iatElement) switch
        {
            true => ReadNumericDate(iatElement),
            false => throw new FormatException($"The DPoP proof {PayloadPart} carries no '{WellKnownJwtClaimNames.Iat}'.")
        };
        string? nonce = ReadOptionalString(root, WellKnownJwtClaimNames.Nonce, PayloadPart);
        string? ath = ReadOptionalString(root, WellKnownJwtClaimNames.Ath, PayloadPart);

        return new DpopProofClaims
        {
            Jti = jti,
            Htm = htm,
            Htu = htu,
            Iat = iat,
            Nonce = nonce,
            Ath = ath
        };
    }


    /// <summary>Reads the member <paramref name="name"/> of <paramref name="root"/>, which must be present and a JSON string.</summary>
    /// <param name="root">The segment's object.</param>
    /// <param name="name">The member name.</param>
    /// <param name="part">The segment's name, for the refusal's message.</param>
    /// <returns>The member's text.</returns>
    /// <exception cref="FormatException">The member is absent or is not a JSON string.</exception>
    private static string ReadRequiredString(JsonElement root, string name, string part) =>
        ReadOptionalString(root, name, part)
            ?? throw new FormatException($"The DPoP proof {part} carries no '{name}'.");


    /// <summary>Reads the member <paramref name="name"/> of <paramref name="root"/> when present, which must then be a JSON string.</summary>
    /// <param name="root">The segment's object.</param>
    /// <param name="name">The member name.</param>
    /// <param name="part">The segment's name, for the refusal's message.</param>
    /// <returns>The member's text, or <see langword="null"/> when the member is absent.</returns>
    /// <exception cref="FormatException">The member is present and is not a JSON string.</exception>
    private static string? ReadOptionalString(JsonElement root, string name, string part)
    {
        if(!root.TryGetProperty(name, out JsonElement element))
        {
            return null;
        }

        return element.ValueKind switch
        {
            JsonValueKind.String => element.GetString(),
            _ => throw new FormatException($"The DPoP proof {part} member '{name}' is not a JSON string.")
        };
    }


    /// <summary>
    /// Reads the header's <c>jwk</c>, which must be present and a JSON object: each member holding a JSON string is kept
    /// with its text; each member whose name <see cref="WellKnownJwkMemberNames.IsPrivateOrSymmetricMember(string)"/>
    /// names is kept whatever its JSON type, with its raw JSON text, so the validator's refusal of private key material
    /// (RFC 9449 Section 4.3, check 7) reads it; the <c>use</c> member is kept whatever its JSON type, with its raw JSON
    /// text, so the validator's check of the public key's use (RFC 7517 Section 4.2: "The "use" value is a
    /// case-sensitive string.") reads it and refuses every value other than the string <c>sig</c>; and each other member
    /// of another JSON type is ignored (RFC 7517 Section 4).
    /// </summary>
    /// <param name="root">The header's object.</param>
    /// <returns>The members of the <c>jwk</c> the reading keeps.</returns>
    /// <exception cref="FormatException">The <c>jwk</c> is absent or is not a JSON object.</exception>
    private static Dictionary<string, string> ReadJwk(JsonElement root)
    {
        if(!root.TryGetProperty(WellKnownJoseHeaderNames.Jwk, out JsonElement jwkElement))
        {
            throw new FormatException("The DPoP proof header carries no 'jwk'.");
        }

        if(jwkElement.ValueKind != JsonValueKind.Object)
        {
            throw new FormatException("The DPoP proof header member 'jwk' is not a JSON object.");
        }

        Dictionary<string, string> jwk = new(StringComparer.Ordinal);
        foreach(JsonProperty member in jwkElement.EnumerateObject())
        {
            string name = member.Name;
            string? value = member.Value.ValueKind switch
            {
                JsonValueKind.String => member.Value.GetString(),
                _ when WellKnownJwkMemberNames.IsPrivateOrSymmetricMember(name) => member.Value.GetRawText(),
                _ when WellKnownJwkMemberNames.IsUse(name) => member.Value.GetRawText(),
                _ => null
            };
            if(value is not null)
            {
                jwk[name] = value;
            }
        }

        return jwk;
    }


    /// <summary>
    /// Reads <c>iat</c> as a NumericDate (RFC 7519 Section 2: "A JSON numeric value representing the number of seconds
    /// from 1970-01-01T00:00:00Z UTC") to the whole second its number, as written, falls in: an integer is read as it
    /// is, and any other number from the digits and exponent of its own JSON text (<see cref="FloorOfNumberText"/>),
    /// never through a binary <see cref="double"/> or a <see cref="decimal"/>, whose rounding can carry a value just short
    /// of a second into the next.
    /// </summary>
    /// <param name="element">The <c>iat</c> member's value.</param>
    /// <returns>The instant.</returns>
    /// <exception cref="FormatException">The value is not a JSON number, or it names no instant a <see cref="DateTimeOffset"/> represents.</exception>
    private static DateTimeOffset ReadNumericDate(JsonElement element)
    {
        if(element.ValueKind != JsonValueKind.Number)
        {
            throw new FormatException("The DPoP proof payload member 'iat' is not a JSON number.");
        }

        long wholeSeconds = element.TryGetInt64(out long integerSeconds) switch
        {
            true => integerSeconds,
            false => FloorOfNumberText(element.GetRawText())
        };
        if(wholeSeconds < MinimumNumericDate || wholeSeconds > MaximumNumericDate)
        {
            throw new FormatException("The DPoP proof payload member 'iat' names no representable instant.");
        }

        return DateTimeOffset.FromUnixTimeSeconds(wholeSeconds);
    }


    /// <summary>
    /// The whole second the JSON number <paramref name="numberText"/> falls in, the floor of its value read from its own
    /// digits: <see href="https://www.rfc-editor.org/rfc/rfc8259#section-6">RFC 8259 Section 6</see>,
    /// <c>number = [ minus ] int [ frac ] [ exp ]</c>. The digits of <c>int</c> and <c>frac</c> are one digit string
    /// whose decimal point the exponent shifts; the digits before the shifted point are the whole part, and the digits
    /// after it decide the floor of a negative value, one second below the whole part whenever any of them is not zero.
    /// No floating or decimal arithmetic takes part, so a fraction of any number of digits is read exactly.
    /// </summary>
    /// <param name="numberText">The raw JSON text of a number that is no 64-bit integer.</param>
    /// <returns>The whole seconds.</returns>
    /// <exception cref="FormatException">The whole second lies outside the instants a <see cref="DateTimeOffset"/> represents.</exception>
    private static long FloorOfNumberText(string numberText)
    {
        ReadOnlySpan<char> text = numberText;
        bool isNegative = text.StartsWith('-');
        if(isNegative)
        {
            text = text[1..];
        }

        int exponentStart = text.IndexOfAny('e', 'E');
        int mantissaLength = exponentStart switch
        {
            < 0 => text.Length,
            _ => exponentStart
        };
        long exponent = exponentStart switch
        {
            < 0 => 0,
            _ => ReadSaturatedExponent(text[(exponentStart + 1)..])
        };
        ReadOnlySpan<char> mantissa = text[..mantissaLength];

        int pointIndex = mantissa.IndexOf('.');
        int integerLength = pointIndex switch
        {
            < 0 => mantissa.Length,
            _ => pointIndex
        };
        int fractionStart = pointIndex switch
        {
            < 0 => mantissa.Length,
            _ => pointIndex + 1
        };
        ReadOnlySpan<char> integerDigits = mantissa[..integerLength];
        ReadOnlySpan<char> fractionDigits = mantissa[fractionStart..];

        //The value is 0.d1d2...dn times ten to the power of the shifted point, where d1 is the first digit that is not
        //zero: the leading zeros of the integer digits, and of the fraction digits after a zero integer part, move the
        //point and carry no value.
        int leadingZeros = 0;
        int digitCount = integerDigits.Length + fractionDigits.Length;
        while(leadingZeros < digitCount && DigitAt(integerDigits, fractionDigits, leadingZeros) == '0')
        {
            leadingZeros++;
        }

        if(leadingZeros == digitCount)
        {
            //Every digit is zero: the value is zero, whatever its sign or exponent.
            return 0;
        }

        long shiftedPoint = integerDigits.Length - leadingZeros + exponent;
        int significantCount = digitCount - leadingZeros;
        long wholeDigitCount = Math.Clamp(shiftedPoint, 0, significantCount);
        if(shiftedPoint > MaximumWholeSecondDigits)
        {
            throw new FormatException("The DPoP proof payload member 'iat' names no representable instant.");
        }

        //The whole part: the significant digits before the shifted point, then a zero for each place the point lies
        //past the last digit.
        long magnitude = 0;
        for(int i = 0; i < wholeDigitCount; i++)
        {
            magnitude = (magnitude * 10) + (DigitAt(integerDigits, fractionDigits, leadingZeros + i) - '0');
        }

        for(long i = significantCount; i < shiftedPoint; i++)
        {
            magnitude *= 10;
        }

        bool hasFraction = false;
        for(long i = wholeDigitCount; i < significantCount && !hasFraction; i++)
        {
            hasFraction = DigitAt(integerDigits, fractionDigits, leadingZeros + (int)i) != '0';
        }

        long wholeSeconds = (isNegative, hasFraction) switch
        {
            (false, _) => magnitude,
            (true, false) => -magnitude,
            (true, true) => -magnitude - 1
        };
        if(wholeSeconds < MinimumNumericDate || wholeSeconds > MaximumNumericDate)
        {
            throw new FormatException("The DPoP proof payload member 'iat' names no representable instant.");
        }

        return wholeSeconds;
    }


    /// <summary>
    /// The digit at <paramref name="index"/> of the digit string the integer digits and the fraction digits of a JSON
    /// number form together.
    /// </summary>
    /// <param name="integerDigits">The digits of <c>int</c>.</param>
    /// <param name="fractionDigits">The digits of <c>frac</c> after its decimal point.</param>
    /// <param name="index">The position in the joined digit string.</param>
    /// <returns>The digit character.</returns>
    private static char DigitAt(ReadOnlySpan<char> integerDigits, ReadOnlySpan<char> fractionDigits, int index) =>
        (index < integerDigits.Length) switch
        {
            true => integerDigits[index],
            false => fractionDigits[index - integerDigits.Length]
        };


    /// <summary>
    /// The value of a JSON number's exponent digits (<c>exp = e [ minus / plus ] 1*DIGIT</c>, RFC 8259 Section 6),
    /// held within plus or minus <see cref="ExponentSaturation"/>: an exponent past that bound places the point beyond
    /// any digit a JSON text of this size carries, so its exact value changes no whole second.
    /// </summary>
    /// <param name="exponentText">The exponent's text after the <c>e</c> or <c>E</c>.</param>
    /// <returns>The exponent, saturated.</returns>
    private static long ReadSaturatedExponent(ReadOnlySpan<char> exponentText)
    {
        bool isNegative = exponentText.StartsWith('-');
        ReadOnlySpan<char> digits = exponentText.TrimStart("+-");
        long value = 0;
        foreach(char digit in digits)
        {
            value = Math.Min((value * 10) + (digit - '0'), ExponentSaturation);
        }

        return isNegative switch
        {
            true => -value,
            false => value
        };
    }


    /// <summary>
    /// The bound an exponent is held within: larger than the digits any JSON text a DPoP proof carries can hold, and
    /// small enough that a point shifted by it stays a 64-bit value.
    /// </summary>
    private static long ExponentSaturation => 1_000_000_000L;


    /// <summary>
    /// The greatest number of digits the whole part of a representable NumericDate has: twelve, the digits of
    /// 253402300799, the second of 9999-12-31T23:59:59Z; a whole part of more digits is refused before it is summed.
    /// </summary>
    private static long MaximumWholeSecondDigits => 12;
}
