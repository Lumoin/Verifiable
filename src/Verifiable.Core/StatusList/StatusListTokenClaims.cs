using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Core.StatusList;

/// <summary>
/// Why <see cref="StatusListTokenClaims.TryFromPayload"/> refused a claims set, so a caller — the
/// JWT verification's own <c>StatusListTokenVerificationFailure</c> mapping among them — can classify
/// the refusal without inspecting the accompanying message text.
/// </summary>
public enum StatusListTokenClaimsDefect
{
    /// <summary>The claims set was read; see the accompanying <see cref="StatusListToken"/>.</summary>
    None = 0,

    /// <summary>A REQUIRED claim (<c>sub</c>/<c>iat</c>/<c>status_list</c>/its <c>bits</c>/<c>lst</c>) is absent or of the wrong shape.</summary>
    RequiredClaimMissing,

    /// <summary>A present claim's value does not conform (e.g. a non-positive <c>ttl</c> or a <c>bits</c> outside 1/2/4/8).</summary>
    ClaimValueInvalid,

    /// <summary>The <c>lst</c> member does not decode to a Status List — not base64url, or not a zlib-compressed byte array.</summary>
    ListUnreadable
}


/// <summary>
/// The one mapping between a <see cref="StatusListToken"/> and its Section 5.1 JWT claims set
/// (<c>sub</c>/<c>iat</c>/<c>exp</c>/<c>ttl</c>/<c>status_list</c>), used by both the JWT composition
/// and the JWT verification so the claims-set shape is defined exactly once.
/// </summary>
/// <remarks>
/// <para>
/// This class reads and writes claims only through <see cref="JwtPayload"/> — the JCose-declared
/// claims dictionary — never through a JSON serializer directly (<c>Verifiable.Core</c> keeps
/// <c>System.Text.Json</c> out of its own source; the actual JSON encode/decode of the payload bytes
/// is the caller's leaf-supplied <c>JwtPayloadSerializer</c>/<c>JwtClaimsDeserializer</c> delegate).
/// The pooled <see cref="StatusList"/> a successful <see cref="TryFromPayload"/> call returns inside
/// the token is owned by the caller, exactly as the JSON and CBOR converters' returned lists are.
/// </para>
/// </remarks>
public static class StatusListTokenClaims
{
    /// <summary>
    /// Builds the Section 5.1 claims set for <paramref name="token"/>.
    /// </summary>
    /// <param name="token">The Status List Token to encode.</param>
    /// <param name="base64UrlEncoder">Encodes the compressed Status List bytes as base64url for the <c>lst</c> member.</param>
    /// <returns>
    /// A <see cref="JwtPayload"/> carrying <c>sub</c>/<c>iat</c>/<c>status_list</c> — REQUIRED per
    /// "sub: REQUIRED. … The sub (subject) claim MUST specify the URI of the Status List Token." /
    /// "iat: REQUIRED. … The iat (issued at) claim MUST specify the time at which the Status List
    /// Token was issued." / "status_list: REQUIRED. The status_list (status list) claim MUST specify
    /// the Status List conforming to the structure defined in Section 4.2." — plus <c>exp</c>/<c>ttl</c>
    /// when <paramref name="token"/> carries them (RECOMMENDED: "exp: RECOMMENDED. … if present, MUST
    /// specify the time at which the Status List Token is considered expired…" / "ttl: RECOMMENDED. …
    /// if present, MUST specify the maximum amount of time, in seconds, that the Status List Token can
    /// be cached…").
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="token"/> or <paramref name="base64UrlEncoder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="token"/>'s Status List is packed <c>MostSignificantFirst</c> (the
    /// W3C Bitstring Status List's order) rather than the <c>LeastSignificantFirst</c> order Section
    /// 4.1 requires of a Token Status List — see <see cref="StatusList.EnsureIetfBitOrder"/>.
    /// </exception>
    public static JwtPayload ToPayload(StatusListToken token, EncodeDelegate base64UrlEncoder)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        StatusList.EnsureIetfBitOrder(token.StatusList, nameof(token));

        var statusListClaim = new Dictionary<string, object>(3)
        {
            [StatusListMemberNames.Bits] = (long)token.StatusList.BitSize,
            [StatusListMemberNames.List] = base64UrlEncoder(token.StatusList.Compress())
        };

        if(token.StatusList.AggregationUri is not null)
        {
            statusListClaim[StatusListMemberNames.AggregationUri] = token.StatusList.AggregationUri;
        }

        JwtPayload payload = new(5)
        {
            [WellKnownJwtClaimNames.Sub] = token.Subject,
            [WellKnownJwtClaimNames.Iat] = token.IssuedAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.StatusList] = statusListClaim
        };

        if(token.ExpirationTime.HasValue)
        {
            payload[WellKnownJwtClaimNames.Exp] = token.ExpirationTime.Value.ToUnixTimeSeconds();
        }

        if(token.TimeToLive.HasValue)
        {
            payload[WellKnownJwtClaimNames.TimeToLive] = token.TimeToLive.Value;
        }

        return payload;
    }


    /// <summary>
    /// Reads a <see cref="StatusListToken"/> from a Section 5.1 claims set, fail-closed on any
    /// required-claim absence or malformation — this parses claims already handed back by the leaf's
    /// <c>JwtClaimsDeserializer</c>, never a raw wire payload, so a shape violation is a defect in the
    /// token, not a caller misuse, and is reported rather than thrown.
    /// </summary>
    /// <param name="payload">The verified JWT claims set.</param>
    /// <param name="base64UrlDecoder">Decodes the <c>lst</c> member's base64url text into the compressed Status List bytes.</param>
    /// <param name="pool">The pool the decompressed <see cref="Core.StatusList.StatusList"/> is allocated from.</param>
    /// <param name="token">On success, the decoded token; otherwise <see langword="null"/>.</param>
    /// <param name="defect">On failure, names the missing or malformed claim; otherwise <see langword="null"/>.</param>
    /// <param name="defectKind">
    /// On failure, classifies <paramref name="defect"/> without a caller having to inspect its text;
    /// <see cref="StatusListTokenClaimsDefect.None"/> on success.
    /// </param>
    /// <returns><see langword="true"/> when every REQUIRED claim was present and well-formed.</returns>
    /// <remarks>
    /// "sub: REQUIRED." / "iat: REQUIRED." / "status_list: REQUIRED. … MUST specify the Status List
    /// conforming to the structure defined in Section 4.2" (so <c>bits</c>/<c>lst</c> are themselves
    /// required within it) — a missing or wrongly-typed value for any of these is a read failure naming
    /// the claim, per Section 8.3 step 3.b ("Check for the existence of the required claims"). "ttl: …
    /// The value of the claim MUST be a positive number encoded in JSON as a number." — a present but
    /// non-positive or non-integer <c>ttl</c> is likewise a read failure. "The JWT MAY contain other
    /// claims." — every claim not read here is tolerated. Integer-valued claims arrive boxed by the
    /// leaf deserializer as one of the .NET integer families or <see cref="decimal"/> (a too-large or
    /// fractional JSON number); a fractional value is refused as non-conforming.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="payload"/>, <paramref name="base64UrlDecoder"/>, or <paramref name="pool"/> is <see langword="null"/>.
    /// </exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The decoded Status List's ownership transfers to the returned token on every "
            + "success path; the try/catch around FromCompressed disposes only the intermediate "
            + "compressed-bytes buffer and never constructs the Status List on a path this method fails.")]
    public static bool TryFromPayload(
        JwtPayload payload,
        DecodeDelegate base64UrlDecoder,
        BaseMemoryPool pool,
        out StatusListToken? token,
        out string? defect,
        out StatusListTokenClaimsDefect defectKind)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        token = null;

        if(!payload.TryGetValue(WellKnownJwtClaimNames.Sub, out object? subValue)
            || subValue is not string subject
            || string.IsNullOrWhiteSpace(subject))
        {
            defect = $"Missing required claim '{WellKnownJwtClaimNames.Sub}'.";
            defectKind = StatusListTokenClaimsDefect.RequiredClaimMissing;

            return false;
        }

        if(!payload.TryGetValue(WellKnownJwtClaimNames.Iat, out object? iatValue) || !TryToInt64(iatValue, out long issuedAtSeconds))
        {
            defect = $"Missing required claim '{WellKnownJwtClaimNames.Iat}'.";
            defectKind = StatusListTokenClaimsDefect.RequiredClaimMissing;

            return false;
        }

        if(!payload.TryGetValue(WellKnownJwtClaimNames.StatusList, out object? statusListValue)
            || statusListValue is not IReadOnlyDictionary<string, object> statusListClaim)
        {
            defect = $"Missing required claim '{WellKnownJwtClaimNames.StatusList}'.";
            defectKind = StatusListTokenClaimsDefect.RequiredClaimMissing;

            return false;
        }

        if(!statusListClaim.TryGetValue(StatusListMemberNames.Bits, out object? bitsValue)
            || !TryToInt64(bitsValue, out long bits)
            || bits is < 1 or > 8
            || !Enum.IsDefined(typeof(StatusListBitSize), (int)bits))
        {
            defect = $"Missing or invalid '{StatusListMemberNames.Bits}' in '{WellKnownJwtClaimNames.StatusList}'.";
            defectKind = StatusListTokenClaimsDefect.RequiredClaimMissing;

            return false;
        }

        if(!statusListClaim.TryGetValue(StatusListMemberNames.List, out object? listValue) || listValue is not string encodedList)
        {
            defect = $"Missing required '{StatusListMemberNames.List}' in '{WellKnownJwtClaimNames.StatusList}'.";
            defectKind = StatusListTokenClaimsDefect.RequiredClaimMissing;

            return false;
        }

        //"lst: REQUIRED. … The value of the lst claim MUST be the base64url-encoded compressed byte
        //array" — an empty or whitespace value is a REQUIRED claim reduced to nothing, refused before
        //any decode reaches the base64url decoder (an empty input otherwise reaches it as an
        //ArgumentException, per Section 4.2).
        if(string.IsNullOrWhiteSpace(encodedList))
        {
            defect = $"Claim '{StatusListMemberNames.List}' in '{WellKnownJwtClaimNames.StatusList}' MUST specify the base64url-encoded compressed byte array; it was empty.";
            defectKind = StatusListTokenClaimsDefect.RequiredClaimMissing;

            return false;
        }

        DateTimeOffset? expirationTime = null;
        if(payload.TryGetValue(WellKnownJwtClaimNames.Exp, out object? expValue))
        {
            if(!TryToInt64(expValue, out long expSeconds))
            {
                defect = $"Claim '{WellKnownJwtClaimNames.Exp}' is not a JWT NumericDate value.";
                defectKind = StatusListTokenClaimsDefect.ClaimValueInvalid;

                return false;
            }

            expirationTime = DateTimeOffset.FromUnixTimeSeconds(expSeconds);
        }

        long? timeToLive = null;
        if(payload.TryGetValue(WellKnownJwtClaimNames.TimeToLive, out object? ttlValue))
        {
            if(!TryToInt64(ttlValue, out long ttlSeconds) || ttlSeconds <= 0)
            {
                defect = $"Claim '{WellKnownJwtClaimNames.TimeToLive}' MUST be a positive number.";
                defectKind = StatusListTokenClaimsDefect.ClaimValueInvalid;

                return false;
            }

            timeToLive = ttlSeconds;
        }

        //The compressed bytes and their decompression are both attacker-controlled: a non-base64url
        //lst decodes with FormatException or ArgumentException, and a base64url value that decodes to
        //something that is not a valid zlib stream (or inflates past StatusList's decompression-bomb
        //ceiling) raises InvalidDataException from FromCompressed. None of the three
        //may escape this read — Section 8.3's closing SHOULD reserves that outcome for a refusal, never
        //a fault.
        IMemoryOwner<byte>? compressedOwner = null;
        Core.StatusList.StatusList? statusList = null;
        try
        {
            compressedOwner = base64UrlDecoder(encodedList, pool);
            statusList = Core.StatusList.StatusList.FromCompressed(
                compressedOwner.Memory.Span, (StatusListBitSize)bits, pool, BitOrder.LeastSignificantFirst);
        }
        catch(Exception exception) when(exception is FormatException or ArgumentException or InvalidDataException)
        {
            defect = $"Claim '{StatusListMemberNames.List}' in '{WellKnownJwtClaimNames.StatusList}' MUST be the base64url-encoded compressed byte array conforming to Section 4.2: {exception.Message}";
            defectKind = StatusListTokenClaimsDefect.ListUnreadable;

            return false;
        }
        finally
        {
            compressedOwner?.Dispose();
        }

        if(statusListClaim.TryGetValue(StatusListMemberNames.AggregationUri, out object? aggregationUriValue)
            && aggregationUriValue is string aggregationUri)
        {
            statusList.AggregationUri = aggregationUri;
        }

        token = new StatusListToken(subject, DateTimeOffset.FromUnixTimeSeconds(issuedAtSeconds), statusList)
        {
            ExpirationTime = expirationTime,
            TimeToLive = timeToLive
        };
        defect = null;
        defectKind = StatusListTokenClaimsDefect.None;

        return true;
    }


    /// <summary>
    /// Accepts the integer families a JWT payload deserializer boxes a JSON number claim as, plus the
    /// decimal fallback for a value too large or fractional to fit a long; refuses a genuinely
    /// fractional decimal rather than truncating it, since a truncated NumericDate or ttl would
    /// silently corrupt a temporal check.
    /// </summary>
    /// <param name="value">The boxed claim value.</param>
    /// <param name="result">On success, the value as a <see cref="long"/>.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is a whole number that fits a <see cref="long"/>.</returns>
    private static bool TryToInt64(object value, out long result)
    {
        (result, bool isWholeNumber) = value switch
        {
            long l => (l, true),
            int i => ((long)i, true),
            short s => ((long)s, true),
            byte b => ((long)b, true),
            uint ui => ((long)ui, true),
            ulong ul when ul <= long.MaxValue => ((long)ul, true),
            sbyte sb => ((long)sb, true),
            ushort us => ((long)us, true),
            decimal d when d >= long.MinValue && d <= long.MaxValue && d == Math.Truncate(d) => ((long)d, true),
            _ => (0L, false)
        };

        return isWholeNumber;
    }
}
