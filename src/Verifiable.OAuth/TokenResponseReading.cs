using System.Globalization;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth.AuthCode;

namespace Verifiable.OAuth;

/// <summary>
/// A token endpoint's answer as the one reading of its body answers it (<see cref="OAuthResponseParsers.ReadTokenResponse"/>):
/// the token or the refusal of the answer (<see cref="Outcome"/>), and beside it the credential members that very reading
/// observed (<see cref="Credentials"/>), success and refusal alike, so a client deciding what to withhold and what a receipt
/// records reads both from the library and reads the body no second time. Its text names no credential.
/// </summary>
/// <param name="Outcome">The token response, the error the answer names, or the refusal of the answer.</param>
/// <param name="Credentials">The credential members the reading observed, never their values.</param>
public sealed record TokenResponseReading(Result<TokenResponse, OAuthParseError> Outcome, TokenAnswerCredentialObservations Credentials)
{
    /// <summary>The reading as text: whether it succeeded and how many credential occurrences it observed, never a credential.</summary>
    /// <returns>The text.</returns>
    public override string ToString() =>
        $"token response reading (success: {Outcome.IsSuccess.ToString(CultureInfo.InvariantCulture)}, {Credentials})";
}


/// <summary>
/// The occurrences of the credential members at the top level of a token endpoint's answer - <c>access_token</c>,
/// <c>refresh_token</c> and <c>id_token</c>, the parameters RFC 6749 section 5.1 and OpenID Connect Core 1.0 section 3.1.3.3
/// put at the highest structure level - each observed by the one reading of the body without its value
/// (<see cref="JsonValueObservation"/>), in document order: a string naming Unicode text with the length of its decoded text in
/// UTF-16 code units, the measure a decoded credential's <see cref="string.Length"/> gives; a string naming no Unicode text; or
/// a value that is no string. A member the answer repeats is observed at every occurrence, so the count of a member's
/// occurrences is the length of its list. The observations are read from every answer the reading judged as one well-formed
/// JSON object - one refused for a repeated name or for a member naming no Unicode text included - and an answer that is no such
/// object observes none. No credential text is carried, here or in any refusal.
/// </summary>
/// <param name="AccessToken">Every occurrence of <c>access_token</c>, in document order.</param>
/// <param name="RefreshToken">Every occurrence of <c>refresh_token</c>, in document order.</param>
/// <param name="IdToken">Every occurrence of <c>id_token</c>, in document order.</param>
public sealed record TokenAnswerCredentialObservations(
    IReadOnlyList<JsonValueObservation> AccessToken,
    IReadOnlyList<JsonValueObservation> RefreshToken,
    IReadOnlyList<JsonValueObservation> IdToken)
{
    /// <summary>The observations of an answer whose body is empty or is no one well-formed JSON object: no occurrence of any member.</summary>
    public static TokenAnswerCredentialObservations None { get; } = new([], [], []);


    /// <summary>
    /// The credential members a reading of an answer's body observed: from the top-level members it answered, or from the
    /// account a refusal of a well-formed object carries; none from a body that is no one well-formed JSON object.
    /// </summary>
    /// <param name="reading">The reading of the answer's body.</param>
    /// <returns>The observations.</returns>
    public static TokenAnswerCredentialObservations Of(JsonTopLevelReading reading)
    {
        ArgumentNullException.ThrowIfNull(reading);

        var account = reading switch
        {
            JsonTopLevelMembers members => members.TopLevel,
            JsonRepeatedMemberName repeated => repeated.TopLevel,
            JsonUndecodableMember undecodable => undecodable.TopLevel,
            _ => JsonTopLevelAccount.None
        };

        return new TokenAnswerCredentialObservations(
            account.OccurrencesOf(OAuthRequestParameterNames.AccessToken),
            account.OccurrencesOf(OAuthRequestParameterNames.RefreshToken),
            account.OccurrencesOf(OAuthRequestParameterNames.IdToken));
    }


    /// <summary>Whether other observations hold equal occurrences of each member in the same order.</summary>
    /// <param name="other">The other observations.</param>
    /// <returns><see langword="true"/> when both hold the same occurrences.</returns>
    public bool Equals(TokenAnswerCredentialObservations? other) =>
        other is not null
        && AccessToken.SequenceEqual(other.AccessToken)
        && RefreshToken.SequenceEqual(other.RefreshToken)
        && IdToken.SequenceEqual(other.IdToken);


    /// <summary>A hash of the occurrences of each member, in order.</summary>
    /// <returns>The hash.</returns>
    public override int GetHashCode()
    {
        var hash = new HashCode();

        foreach(var occurrence in AccessToken.Concat(RefreshToken).Concat(IdToken))
        {
            hash.Add(occurrence);
        }

        return hash.ToHashCode();
    }


    /// <summary>The observations as text: how many occurrences of each member, never a credential.</summary>
    /// <returns>The text.</returns>
    public override string ToString() =>
        $"credential occurrences ({OAuthRequestParameterNames.AccessToken}: {AccessToken.Count.ToString(CultureInfo.InvariantCulture)}, "
        + $"{OAuthRequestParameterNames.RefreshToken}: {RefreshToken.Count.ToString(CultureInfo.InvariantCulture)}, "
        + $"{OAuthRequestParameterNames.IdToken}: {IdToken.Count.ToString(CultureInfo.InvariantCulture)})";
}
