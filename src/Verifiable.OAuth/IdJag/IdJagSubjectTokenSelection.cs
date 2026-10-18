using System.Diagnostics;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.IdJag;

/// <summary>Which of the tokens a client holds from a person's sign-in at an identity provider it presents as an ID-JAG mint's subject.</summary>
public enum IdJagSubjectTokenPreference
{
    /// <summary>
    /// The ID Token, while it has not run out: draft-ietf-oauth-identity-assertion-authz-grant-04 §4.3, "Implementations of this
    /// specification MUST accept Identity Assertions".
    /// </summary>
    IdToken,

    /// <summary>
    /// The refresh token the provider issued beside it, where it issued one: §4.3, "a Refresh Token previously issued by the IdP
    /// Authorization Server for that resource owner", valid only where "bound to the authenticated client" (§4.3.3).
    /// </summary>
    RefreshToken
}


/// <summary>The tokens a client holds from a person's sign-in at an identity provider, which an ID-JAG mint's subject is chosen from.</summary>
/// <param name="IdToken">The verified ID Token the provider issued the client.</param>
/// <param name="IdTokenExpiresAt">The ID Token's <c>exp</c>.</param>
/// <param name="RefreshToken">The refresh token the provider issued beside it, or <see langword="null"/>.</param>
public sealed record IdJagHeldSubject(string IdToken, DateTimeOffset IdTokenExpiresAt, string? RefreshToken)
{
    /// <summary>Names the held subject by its expiry alone, never its tokens.</summary>
    /// <returns>The text.</returns>
    public override string ToString() => $"{nameof(IdJagHeldSubject)} {{ {nameof(IdTokenExpiresAt)} = {IdTokenExpiresAt:O} }}";
}


/// <summary>The subject an ID-JAG mint presents: the token and its type (<see cref="IdJagMintOptions.SubjectToken"/>, <see cref="IdJagMintOptions.SubjectTokenType"/>).</summary>
/// <param name="Token">The token.</param>
/// <param name="Type">Its type.</param>
[DebuggerDisplay("IdJagSubjectToken Type={Type}")]
public sealed record IdJagSubjectToken(string Token, TokenType Type)
{
    /// <summary>Names the subject by its type alone, never its token.</summary>
    /// <returns>The text.</returns>
    public override string ToString() => $"{nameof(IdJagSubjectToken)} {{ {nameof(Type)} = {TokenTypeNames.GetName(Type)} }}";
}


/// <summary>
/// The choice of an ID-JAG mint's subject (draft-ietf-oauth-identity-assertion-authz-grant-04 §4.3) from the tokens a client
/// holds for a person, by the preference its registration at the provider names.
/// </summary>
public static class IdJagSubjectTokenSelection
{
    /// <summary>
    /// The subject a mint presents: under <see cref="IdJagSubjectTokenPreference.IdToken"/> the ID Token while its <c>exp</c>
    /// lies after the instant given (RFC 7519 §4.1.4: "the JWT MUST NOT be accepted for processing" on or after it), typed
    /// <see cref="TokenType.IdToken"/>; under <see cref="IdJagSubjectTokenPreference.RefreshToken"/> the refresh token where
    /// one is held, typed <see cref="TokenType.RefreshToken"/>; otherwise none, which sends the person back to sign in.
    /// </summary>
    /// <param name="held">The tokens held.</param>
    /// <param name="preference">The preference.</param>
    /// <param name="now">The instant the mint is composed at.</param>
    /// <returns>The subject, or <see langword="null"/>.</returns>
    public static IdJagSubjectToken? Select(IdJagHeldSubject held, IdJagSubjectTokenPreference preference, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(held);

        return preference switch
        {
            IdJagSubjectTokenPreference.IdToken when held.IdTokenExpiresAt > now => new IdJagSubjectToken(held.IdToken, TokenType.IdToken),
            IdJagSubjectTokenPreference.RefreshToken when held.RefreshToken is { Length: > 0 } refresh => new IdJagSubjectToken(refresh, TokenType.RefreshToken),
            _ => null
        };
    }
}
