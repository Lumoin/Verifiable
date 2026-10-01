namespace Verifiable.OAuth;

/// <summary>
/// Checks a <c>scope</c> value against the grammar of
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 Section 3.3</see>:
/// <code>
/// scope       = scope-token *( SP scope-token )
/// scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
/// </code>
/// This is the one check of the grammar the library holds. The ID-JAG redeem reads it for the grant's
/// <c>scope</c> claim, which
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>
/// makes a list "in the format described in Section 3.3 of [RFC6749]";
/// <see cref="AuthCode.AuthCodeEndpoints"/> reads it for the scope the authorization seam grants at the
/// ID-JAG mint; and <see cref="ProtectedResource.BearerTokenChallenge.BuildChallenge"/> reads it for the
/// <c>scope</c> attribute of a challenge, which
/// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 Section 3</see> restates from the
/// same section.
/// </summary>
internal static class ScopeTokenSyntax
{
    /// <summary>
    /// Whether <paramref name="value"/> is a scope value by the grammar: at least one token, tokens delimited by
    /// single spaces, and every other character in the token set. The empty string, a leading, trailing or
    /// doubled space, a tab and a character outside the set each break it. The value is read one UTF-16 code
    /// unit at a time, so a character outside the ASCII range, a surrogate half included, is outside the set.
    /// </summary>
    /// <param name="value">The scope value to check.</param>
    /// <returns><see langword="true"/> when the value matches the grammar.</returns>
    internal static bool IsScopeList(string value)
    {
        bool isAtTokenStart = true;
        foreach(char character in value)
        {
            if(character == ' ')
            {
                if(isAtTokenStart)
                {
                    return false;
                }

                isAtTokenStart = true;

                continue;
            }

            bool isTokenCharacter = character is '!' or (>= '#' and <= '[') or (>= ']' and <= '~');
            if(!isTokenCharacter)
            {
                return false;
            }

            isAtTokenStart = false;
        }

        return !isAtTokenStart;
    }
}
