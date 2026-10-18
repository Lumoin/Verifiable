using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Validation;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The rules of RFC 7523 Section 3 a client assertion's claims break, each naming one fact about the claims - and, where a
/// claim is the fact's subject, the claim - never the value judged. A client authentication by an assertion that breaks one is
/// answered <c>invalid_client</c> (RFC 7523 Section 3.2).
/// </summary>
public enum ClientAssertionClaimRefusal
{
    /// <summary>
    /// The assertion's <c>iss</c> or <c>sub</c> is absent, is no string, or is not the client's identifier (RFC 7523 Section 3
    /// items 1 and 2.B: "For client authentication, the subject MUST be the "client_id" of the OAuth client").
    /// </summary>
    NotTheClient,

    /// <summary>
    /// The assertion's <c>aud</c> is absent, is neither a string nor a non-empty array of strings, or names any value beside the
    /// authorization server's own identities (RFC 7523 Section 3 item 3; RFC 9126 Section 2).
    /// </summary>
    AudienceNotThisServer,

    /// <summary>The assertion carries no <c>exp</c> (RFC 7523 Section 3 item 4: "The JWT MUST contain an "exp" (expiration time) claim").</summary>
    ExpiryNotPresented,

    /// <summary>The assertion's <c>exp</c> is no NumericDate: a JSON number naming an instant a clock represents (RFC 7519 Sections 2 and 4.1.4).</summary>
    ExpiryNotANumericDate,

    /// <summary>The assertion carries an <c>iat</c> that is no NumericDate (RFC 7519 Section 4.1.6: its value "MUST be a number containing a NumericDate value").</summary>
    IssuedAtNotANumericDate,

    /// <summary>The assertion's <c>exp</c> is at or before its <c>iat</c>: an assertion issued with no lifetime, whose window never opens.</summary>
    ExpiryNotAfterIssuedAt,

    /// <summary>The assertion's <c>iat</c> lies after the current instant beyond the clock-skew tolerance (RFC 7519 Section 4.1.6).</summary>
    IssuedInTheFuture,

    /// <summary>The assertion carries an <c>nbf</c> that is no NumericDate (RFC 7519 Section 4.1.5: its value "MUST be a number containing a NumericDate value").</summary>
    NotBeforeNotANumericDate,

    /// <summary>The assertion's <c>exp</c> is at or before its <c>nbf</c>: a window that never opens (RFC 7519 Sections 4.1.4 and 4.1.5).</summary>
    ExpiryNotAfterNotBefore,

    /// <summary>
    /// The assertion's <c>nbf</c> lies after the current instant beyond the clock-skew tolerance (RFC 7519 Section 4.1.5: "the
    /// current date/time MUST be after or equal to the not-before date/time"; RFC 7523 Section 3 item 5).
    /// </summary>
    NotYetValid,

    /// <summary>
    /// The assertion's <c>exp</c> has passed by the clock-skew tolerance or more (RFC 7523 Section 3 item 4; RFC 7519 Section
    /// 4.1.4: "the current date/time MUST be before the expiration date/time", with "some small leeway ... to account for clock
    /// skew").
    /// </summary>
    Expired,

    /// <summary>
    /// The assertion carries no <c>jti</c>, or one that names no identifier - no string, or one of white space alone
    /// (<see cref="ClientAssertionClaimRules.IsIdentifier"/>): nothing a replay guard could hold it to a single use by (RFC 7523
    /// Section 3 item 7; OpenID Connect Core 1.0 Section 9 has the claim REQUIRED).
    /// </summary>
    IdentifierNotPresented,

    /// <summary>The replay guard found the assertion's <c>jti</c> presented before within the window it is accepted in (RFC 7523 Section 3 item 7).</summary>
    IdentifierReplayed,

    /// <summary>The replay guard tracks no such <c>jti</c>, so the assertion cannot be held to a single use (<see cref="JtiReplayOutcome.Unacceptable"/>).</summary>
    IdentifierNotTrackable,

    /// <summary>The replay guard could not prove the record of the assertion's <c>jti</c> (<see cref="JtiReplayOutcome.StoreUnavailable"/>), so no first use is assumed.</summary>
    ReplayRecordUnavailable,

    /// <summary>The replay guard answered an outcome no rule here reads: nothing established a first use.</summary>
    ReplayOutcomeNotRecognised
}


/// <summary>
/// Consults the replay guard for the first use of a client assertion's <c>jti</c>, the record kept for as long as the assertion
/// is accepted (RFC 7523 Section 3 item 7: kept "for the length of time for which the JWT would be considered valid"), until
/// <see cref="ClientAssertionClaimRules.ReplayRecordKeptUntil"/>. The caller binds the guard, the tenant and the assertion's
/// issuer; <see cref="JtiReplayGuard.ConsultClientAssertionAsync"/> is the library's own.
/// </summary>
/// <param name="jti">The assertion's <c>jti</c>.</param>
/// <param name="recordKeptUntil">The instant the record of its first use is kept until.</param>
/// <param name="cancellationToken">Cancels the consultation.</param>
/// <returns>The guard's outcome.</returns>
public delegate ValueTask<JtiReplayOutcome> ConsultClientAssertionFirstUseDelegate(string jti, DateTimeOffset recordKeptUntil, CancellationToken cancellationToken);


/// <summary>
/// The judgement of a client assertion's claims (<see cref="ClientAssertionClaimRules"/>): accepted, naming its <c>jti</c>, the
/// <c>exp</c> it is accepted under, whether that window reaches the clock's end and the instant the record of its first use is
/// kept until; or refused under the one rule it broke first.
/// </summary>
public sealed record ClientAssertionClaimsJudgement
{
    /// <summary>Creates a judgement.</summary>
    /// <param name="refusal">The rule broken, or <see langword="null"/> for an accepted assertion.</param>
    /// <param name="jti">The accepted assertion's <c>jti</c>.</param>
    /// <param name="expiry">The accepted assertion's <c>exp</c>, as written.</param>
    /// <param name="acceptedToTheClocksEnd">Whether the accepted assertion's window reaches the clock's end.</param>
    /// <param name="replayRecordKeptUntil">The instant the record of the accepted assertion's first use is kept until.</param>
    private ClientAssertionClaimsJudgement(
        ClientAssertionClaimRefusal? refusal, string? jti, NumericDate? expiry, bool acceptedToTheClocksEnd, DateTimeOffset? replayRecordKeptUntil)
    {
        Refusal = refusal;
        Jti = jti;
        Expiry = expiry;
        AcceptedToTheClocksEnd = acceptedToTheClocksEnd;
        ReplayRecordKeptUntil = replayRecordKeptUntil;
    }


    /// <summary>The rule the claims broke first, or <see langword="null"/> when every rule holds.</summary>
    public ClientAssertionClaimRefusal? Refusal { get; }

    /// <summary>The accepted assertion's <c>jti</c>; <see langword="null"/> for a refused one.</summary>
    public string? Jti { get; }

    /// <summary>The accepted assertion's <c>exp</c>, as written; <see langword="null"/> for a refused one.</summary>
    public NumericDate? Expiry { get; }

    /// <summary>
    /// Whether the accepted assertion's window, its <c>exp</c> extended by the clock-skew tolerance, reaches past the clock's last
    /// instant, so no instant the clock represents refuses it as expired
    /// (<see cref="ClientAssertionClaimRules.IsAcceptedToTheClocksEnd"/>); <see langword="false"/> for a refused one.
    /// </summary>
    public bool AcceptedToTheClocksEnd { get; }

    /// <summary>
    /// The instant the record of the accepted assertion's first use is kept until
    /// (<see cref="ClientAssertionClaimRules.ReplayRecordKeptUntil"/>): the instant from which it is refused as expired, or the
    /// clock's last instant where <see cref="AcceptedToTheClocksEnd"/>; <see langword="null"/> for a refused one.
    /// </summary>
    public DateTimeOffset? ReplayRecordKeptUntil { get; }

    /// <summary>Whether every rule holds.</summary>
    public bool IsAccepted => Refusal is null;


    /// <summary>The judgement of claims every rule holds for.</summary>
    /// <param name="jti">The assertion's <c>jti</c>.</param>
    /// <param name="expiry">The assertion's <c>exp</c>, as written.</param>
    /// <param name="clockSkewTolerance">The tolerance the assertion was accepted under.</param>
    /// <returns>The judgement.</returns>
    /// <exception cref="ArgumentException">The jti names no identifier (<see cref="ClientAssertionClaimRules.IsIdentifier"/>).</exception>
    public static ClientAssertionClaimsJudgement Accepted(string jti, NumericDate expiry, TimeSpan clockSkewTolerance)
    {
        ArgumentNullException.ThrowIfNull(jti);
        ArgumentNullException.ThrowIfNull(expiry);

        if(!ClientAssertionClaimRules.IsIdentifier(jti))
        {
            throw new ArgumentException("An accepted client assertion's jti names an identifier: a string holding a character other than white space.", nameof(jti));
        }

        return new ClientAssertionClaimsJudgement(
            refusal: null,
            jti,
            expiry,
            ClientAssertionClaimRules.IsAcceptedToTheClocksEnd(expiry, clockSkewTolerance),
            ClientAssertionClaimRules.ReplayRecordKeptUntil(expiry, clockSkewTolerance));
    }


    /// <summary>The judgement of claims that broke a rule.</summary>
    /// <param name="refusal">The rule.</param>
    /// <returns>The judgement.</returns>
    public static ClientAssertionClaimsJudgement Refused(ClientAssertionClaimRefusal refusal) =>
        new(refusal, jti: null, expiry: null, acceptedToTheClocksEnd: false, replayRecordKeptUntil: null);
}


/// <summary>
/// The claim rules of RFC 7523 Section 3 a client assertion is judged by once its signature or MAC verified (RFC 7519 Section 7.2
/// validates a JWS before its payload is read), the one judgement every key source and every assertion method shares - an
/// assertion under a key the client registered or published (<c>private_key_jwt</c>) and one MACed under its secret
/// (<c>client_secret_jwt</c>, OpenID Connect Core 1.0 Section 9) alike:
/// <list type="number">
/// <item><description><c>iss</c> and <c>sub</c> are the client's identifier (items 1 and 2.B);</description></item>
/// <item><description><c>aud</c> names the authorization server's own identities and nothing else - one string, or a non-empty array
/// every element of which is one (item 3; RFC 9126 Section 2 has the server accept its issuer identifier, its token endpoint URL and
/// its pushed authorization request endpoint URL), since an assertion audienced at another server as well is one that server could
/// replay here;</description></item>
/// <item><description><c>exp</c> is present and a NumericDate (item 4), an <c>iat</c> or an <c>nbf</c> the assertion carries is one,
/// lies before <c>exp</c> and no further ahead of the current instant than the clock-skew tolerance (item 5), and <c>exp</c> has not
/// passed by the tolerance;</description></item>
/// <item><description>a <c>jti</c> is present (OpenID Connect Core 1.0 Section 9 makes it REQUIRED, and replay protection is a property
/// of accepting an assertion at all) and, where a replay guard is consulted, its first use (item 7), kept until the assertion stops
/// being accepted.</description></item>
/// </list>
/// The rules are judged in that order and the first broken is named.
/// </summary>
/// <remarks>
/// A NumericDate is read by the library's one reading of the type (<see cref="NumericDate.Of"/>), every digit kept, and each bound
/// is judged against the date written exactly: a date any part of a tick past a bound is past it, and a string of digits is none.
/// </remarks>
public static class ClientAssertionClaimRules
{
    /// <summary>
    /// The JWT Claims Set of a client assertion whose signature or MAC verified, read as RFC 7519 Section 7.2 reads one once the
    /// JWS validated: the payload segment base64url-decoded, exactly one JSON object naming each member once (step 10: "a
    /// completely valid JSON object"; Section 4: claim names are unique), parsed by the payload reader given; <see langword="null"/>
    /// for a payload of any other content, never throwing.
    /// </summary>
    /// <param name="compactJws">The compact JWS, three base64url segments, whose signature or MAC verified.</param>
    /// <param name="base64UrlDecoder">Decodes the payload segment.</param>
    /// <param name="payloadDeserializer">Reads the object's members.</param>
    /// <param name="pool">The pool the decoded payload is rented from.</param>
    /// <returns>The claims, or <see langword="null"/>.</returns>
    public static IReadOnlyDictionary<string, object>? ReadClaimsSet(
        string compactJws, DecodeDelegate base64UrlDecoder, JwtPayloadDeserializer payloadDeserializer, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(compactJws);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(payloadDeserializer);
        ArgumentNullException.ThrowIfNull(pool);

        var payloadStart = compactJws.IndexOf('.', StringComparison.Ordinal) + 1;
        var payloadEnd = compactJws.LastIndexOf('.', StringComparison.Ordinal);

        if(payloadStart <= 0 || payloadEnd <= payloadStart)
        {
            return null;
        }

        try
        {
            using var decoded = base64UrlDecoder(compactJws.AsSpan(payloadStart, payloadEnd - payloadStart), pool);
            var octets = decoded.Memory.Span[..((payloadEnd - payloadStart) * 3 / 4)];

            return octets.TrimStart(" \t\n\r"u8) is [(byte)'{', ..] && JwkJsonReader.IsWellFormedJsonDocument(octets)
                ? payloadDeserializer(octets)
                : null;
        }
        catch(Exception exception) when(exception is FormatException or InvalidOperationException or System.Text.Json.JsonException)
        {
            return null;
        }
    }


    /// <summary>
    /// Judges a client assertion's verified claims by every rule but the replay guard's: the identity, the audience, the dates and
    /// the presence of a <c>jti</c>.
    /// </summary>
    /// <param name="claims">The claims set of an assertion whose signature or MAC verified.</param>
    /// <param name="clientId">The client the assertion authenticates, which its <c>iss</c> and <c>sub</c> must both be.</param>
    /// <param name="acceptedAudiences">The authorization server's identities its <c>aud</c> may name.</param>
    /// <param name="now">The current instant, by the authorization server's clock.</param>
    /// <param name="clockSkewTolerance">The tolerance the dates are judged under.</param>
    /// <returns>The judgement.</returns>
    public static ClientAssertionClaimsJudgement Judge(
        IReadOnlyDictionary<string, object> claims,
        string clientId,
        IReadOnlyCollection<string> acceptedAudiences,
        DateTimeOffset now,
        TimeSpan clockSkewTolerance)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentException.ThrowIfNullOrEmpty(clientId);
        ArgumentNullException.ThrowIfNull(acceptedAudiences);

        if(StringClaimOf(claims, WellKnownJwtClaimNames.Iss) is not string issuer
            || StringClaimOf(claims, WellKnownJwtClaimNames.Sub) is not string subject
            || !string.Equals(issuer, clientId, StringComparison.Ordinal)
            || !string.Equals(subject, clientId, StringComparison.Ordinal))
        {
            return ClientAssertionClaimsJudgement.Refused(ClientAssertionClaimRefusal.NotTheClient);
        }

        if(!claims.TryGetValue(WellKnownJwtClaimNames.Aud, out var audience) || !AudienceNamesOnly(audience, acceptedAudiences))
        {
            return ClientAssertionClaimsJudgement.Refused(ClientAssertionClaimRefusal.AudienceNotThisServer);
        }

        if(!claims.TryGetValue(WellKnownJwtClaimNames.Exp, out var expiryValue))
        {
            return ClientAssertionClaimsJudgement.Refused(ClientAssertionClaimRefusal.ExpiryNotPresented);
        }

        if(NumericDate.Of(expiryValue) is not NumericDate expiry)
        {
            return ClientAssertionClaimsJudgement.Refused(ClientAssertionClaimRefusal.ExpiryNotANumericDate);
        }

        //RFC 7519 Section 4.1.6: an iat names the instant the assertion was issued, so it lies before exp and, by this server's
        //clock, no further ahead than the tolerance.
        if(claims.TryGetValue(WellKnownJwtClaimNames.Iat, out var issuedAtValue))
        {
            if(NumericDate.Of(issuedAtValue) is not NumericDate issuedAt)
            {
                return ClientAssertionClaimsJudgement.Refused(ClientAssertionClaimRefusal.IssuedAtNotANumericDate);
            }

            if(expiry.CompareTo(issuedAt) <= 0)
            {
                return ClientAssertionClaimsJudgement.Refused(ClientAssertionClaimRefusal.ExpiryNotAfterIssuedAt);
            }

            if(issuedAt.CompareToLaterBy(now, clockSkewTolerance) > 0)
            {
                return ClientAssertionClaimsJudgement.Refused(ClientAssertionClaimRefusal.IssuedInTheFuture);
            }
        }

        //RFC 7519 Section 4.1.5 with RFC 7523 Section 3 item 5: an nbf names the instant the assertion may first be accepted, so it
        //lies before exp and, by this server's clock, is reached within the tolerance.
        if(claims.TryGetValue(WellKnownJwtClaimNames.Nbf, out var notBeforeValue))
        {
            if(NumericDate.Of(notBeforeValue) is not NumericDate notBefore)
            {
                return ClientAssertionClaimsJudgement.Refused(ClientAssertionClaimRefusal.NotBeforeNotANumericDate);
            }

            if(expiry.CompareTo(notBefore) <= 0)
            {
                return ClientAssertionClaimsJudgement.Refused(ClientAssertionClaimRefusal.ExpiryNotAfterNotBefore);
            }

            if(notBefore.CompareToLaterBy(now, clockSkewTolerance) > 0)
            {
                return ClientAssertionClaimsJudgement.Refused(ClientAssertionClaimRefusal.NotYetValid);
            }
        }

        //RFC 7519 Section 4.1.4: the present lies before exp extended by the tolerance, judged against the exp as written and
        //without forming the extended instant, so an exp the tolerance carries past the clock's last instant is judged exactly.
        if(!JwtTemporalChecks.IsBeforeExpiry(now, expiry, clockSkewTolerance))
        {
            return ClientAssertionClaimsJudgement.Refused(ClientAssertionClaimRefusal.Expired);
        }

        if(StringClaimOf(claims, WellKnownJwtClaimNames.Jti) is not { } jti || !IsIdentifier(jti))
        {
            return ClientAssertionClaimsJudgement.Refused(ClientAssertionClaimRefusal.IdentifierNotPresented);
        }

        return ClientAssertionClaimsJudgement.Accepted(jti, expiry, clockSkewTolerance);
    }


    /// <summary>
    /// Judges a client assertion's verified claims by every rule (<see cref="Judge"/>), the replay guard's last: an assertion every
    /// other rule accepts is accepted only on the first use of its <c>jti</c>, kept until the assertion stops being accepted.
    /// </summary>
    /// <param name="claims">The claims set of an assertion whose signature or MAC verified.</param>
    /// <param name="clientId">The client the assertion authenticates.</param>
    /// <param name="acceptedAudiences">The authorization server's identities its <c>aud</c> may name.</param>
    /// <param name="now">The current instant, by the authorization server's clock.</param>
    /// <param name="clockSkewTolerance">The tolerance the dates are judged under.</param>
    /// <param name="consultFirstUse">The replay guard, bound to the tenant and the assertion's issuer.</param>
    /// <param name="cancellationToken">Cancels the consultation.</param>
    /// <returns>The judgement.</returns>
    public static async ValueTask<ClientAssertionClaimsJudgement> JudgeAsync(
        IReadOnlyDictionary<string, object> claims,
        string clientId,
        IReadOnlyCollection<string> acceptedAudiences,
        DateTimeOffset now,
        TimeSpan clockSkewTolerance,
        ConsultClientAssertionFirstUseDelegate consultFirstUse,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(consultFirstUse);

        var judged = Judge(claims, clientId, acceptedAudiences, now, clockSkewTolerance);

        if(judged is not { IsAccepted: true, Jti: { } jti, ReplayRecordKeptUntil: { } recordKeptUntil })
        {
            return judged;
        }

        var outcome = await consultFirstUse(jti, recordKeptUntil, cancellationToken).ConfigureAwait(false);

        return RefusalOf(outcome) is ClientAssertionClaimRefusal refusal ? ClientAssertionClaimsJudgement.Refused(refusal) : judged;
    }


    /// <summary>
    /// The rule a replay guard's outcome breaks, or <see langword="null"/> for a first use: every outcome but a first use refuses
    /// the assertion (RFC 7523 Section 3 item 7), each under its own name.
    /// </summary>
    /// <param name="outcome">The guard's outcome.</param>
    /// <returns>The rule, or <see langword="null"/>.</returns>
    public static ClientAssertionClaimRefusal? RefusalOf(JtiReplayOutcome outcome) => outcome switch
    {
        JtiReplayOutcome.FirstUse => null,
        JtiReplayOutcome.Replayed => ClientAssertionClaimRefusal.IdentifierReplayed,
        JtiReplayOutcome.Unacceptable => ClientAssertionClaimRefusal.IdentifierNotTrackable,
        JtiReplayOutcome.StoreUnavailable => ClientAssertionClaimRefusal.ReplayRecordUnavailable,
        _ => ClientAssertionClaimRefusal.ReplayOutcomeNotRecognised
    };


    /// <summary>
    /// Whether the window a client assertion is accepted in reaches the clock's end: its <c>exp</c> extended by the clock-skew
    /// tolerance (RFC 7519 Section 4.1.4: the present must be before <c>exp</c>, and a reader "may provide for some small leeway,
    /// usually no more than a few minutes, to account for clock skew") lies past the latest instant a <see cref="DateTimeOffset"/>
    /// represents, so no instant this clock holds refuses the assertion as expired. Judged exactly, against the <c>exp</c> as
    /// written, without forming the extended instant.
    /// </summary>
    /// <param name="expiry">The assertion's <c>exp</c>, as written.</param>
    /// <param name="clockSkewTolerance">The tolerance.</param>
    /// <returns><see langword="true"/> when the window reaches past the clock's last instant.</returns>
    public static bool IsAcceptedToTheClocksEnd(NumericDate expiry, TimeSpan clockSkewTolerance)
    {
        ArgumentNullException.ThrowIfNull(expiry);

        return JwtTemporalChecks.IsBeforeExpiry(DateTimeOffset.MaxValue, expiry, clockSkewTolerance);
    }


    /// <summary>
    /// The instant the replay record of a client assertion's <c>jti</c> is kept until (RFC 7523 Section 3 item 7: "for the length
    /// of time for which the JWT would be considered valid"): the first instant a <see cref="DateTimeOffset"/> holds at or after its
    /// <c>exp</c> extended by the clock-skew tolerance, the instant from which the expiry rule refuses it, or the clock's last
    /// instant where the window reaches the clock's end (<see cref="IsAcceptedToTheClocksEnd"/>), since a record holds an instant
    /// and the window outlasts every instant the clock represents (<see cref="NumericDate.AtOrAfterLaterBy"/>). The record is so
    /// kept for as long as the assertion is accepted, and the expiry rule judges the <c>exp</c> itself, never this instant.
    /// </summary>
    /// <param name="expiry">The assertion's <c>exp</c>, as written.</param>
    /// <param name="clockSkewTolerance">The tolerance.</param>
    /// <returns>The instant the record is kept until.</returns>
    public static DateTimeOffset ReplayRecordKeptUntil(NumericDate expiry, TimeSpan clockSkewTolerance)
    {
        ArgumentNullException.ThrowIfNull(expiry);

        return expiry.AtOrAfterLaterBy(clockSkewTolerance);
    }


    /// <summary>
    /// Whether an <c>aud</c> claim names the authorization server's own identities and nothing else (RFC 7523 Section 3 item 3):
    /// one string that is one of them, or a non-empty array - a sequence of strings or of values, as the claims set holds it - every
    /// element of which is a string that is one of them. A value of any other shape names nothing. The comparison is ordinal: RFC
    /// 7519 Section 2 compares a StringOrURI "as case-sensitive strings with no transformations or canonicalizations applied".
    /// </summary>
    /// <param name="audience">The claim's value as the claims set holds it.</param>
    /// <param name="acceptedAudiences">The authorization server's identities.</param>
    /// <returns><see langword="true"/> when every value the claim names is one of the identities.</returns>
    public static bool AudienceNamesOnly(object? audience, IReadOnlyCollection<string> acceptedAudiences)
    {
        ArgumentNullException.ThrowIfNull(acceptedAudiences);

        return audience switch
        {
            string single => IsAccepted(single, acceptedAudiences),
            IEnumerable<string> strings => AreAllAccepted(strings, acceptedAudiences),
            IEnumerable<object> values => AreAllAccepted(values.Select(StringOf), acceptedAudiences),
            _ => false
        };
    }


    /// <summary>
    /// The one contract of a client assertion's identifier every reader of an assertion holds it to: its <c>jti</c> is a string
    /// holding a character other than white space. RFC 7519 Section 4.1.7 has the value "a case-sensitive string" a replay guard
    /// keys by; a string of white space alone names nothing an issuer told apart from another, so the judgement refuses it
    /// (<see cref="ClientAssertionClaimRefusal.IdentifierNotPresented"/>) before any success is built, and every success factory
    /// accepts exactly what the judgement accepts.
    /// </summary>
    /// <param name="jti">The claim's value.</param>
    /// <returns><see langword="true"/> when it names an identifier.</returns>
    public static bool IsIdentifier(string? jti) => !string.IsNullOrWhiteSpace(jti);


    /// <summary>A string claim's value, or <see langword="null"/> for any other value or none.</summary>
    /// <param name="claims">The claims set.</param>
    /// <param name="claimName">The claim.</param>
    /// <returns>The string, or <see langword="null"/>.</returns>
    private static string? StringClaimOf(IReadOnlyDictionary<string, object> claims, string claimName) =>
        claims.TryGetValue(claimName, out var value) ? StringOf(value) : null;


    /// <summary>A value as a string, or <see langword="null"/> for any other value.</summary>
    /// <param name="value">The value.</param>
    /// <returns>The string, or <see langword="null"/>.</returns>
    private static string? StringOf(object? value) => value switch
    {
        string text => text,
        _ => null
    };


    /// <summary>Whether one value is one of the identities.</summary>
    /// <param name="value">The value, or <see langword="null"/> for one that is no string.</param>
    /// <param name="acceptedAudiences">The identities.</param>
    /// <returns><see langword="true"/> when it is one.</returns>
    private static bool IsAccepted(string? value, IReadOnlyCollection<string> acceptedAudiences) =>
        value is { Length: > 0 } && acceptedAudiences.Any(identity => string.Equals(identity, value, StringComparison.Ordinal));


    /// <summary>Whether a sequence holds at least one value and every value is one of the identities.</summary>
    /// <param name="values">The values, each <see langword="null"/> where it is no string.</param>
    /// <param name="acceptedAudiences">The identities.</param>
    /// <returns><see langword="true"/> when every value is one, and there is one.</returns>
    private static bool AreAllAccepted(IEnumerable<string?> values, IReadOnlyCollection<string> acceptedAudiences)
    {
        var sawAny = false;

        foreach(var value in values)
        {
            if(!IsAccepted(value, acceptedAudiences))
            {
                return false;
            }

            sawAny = true;
        }

        return sawAny;
    }
}
