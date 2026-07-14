namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared hand-built OAuth 2.0 HTTP JSON response bodies (PAR and token endpoint responses) for the
/// authorization-code flow and attack-mitigation test corpus.
/// </summary>
internal static class OAuthJsonResponseFixtures
{
    /// <summary>Builds a Pushed Authorization Request (RFC 9126) success response body.</summary>
    /// <param name="requestUri">The <c>request_uri</c> value.</param>
    /// <param name="expiresIn">The <c>expires_in</c> value, in seconds.</param>
    /// <returns>The PAR response JSON text.</returns>
    internal static string BuildParJson(string requestUri, int expiresIn) =>
        /*lang=json,strict*/ $"{{\"request_uri\":\"{requestUri}\",\"expires_in\":{expiresIn}}}";


    /// <summary>Builds a token endpoint success response body.</summary>
    /// <param name="accessToken">The <c>access_token</c> value.</param>
    /// <param name="tokenType">The <c>token_type</c> value.</param>
    /// <param name="expiresIn">The <c>expires_in</c> value, in seconds.</param>
    /// <param name="refreshToken">The <c>refresh_token</c> value, or <see langword="null"/> to omit it.</param>
    /// <returns>The token response JSON text.</returns>
    internal static string BuildTokenJson(string accessToken, string tokenType, int expiresIn, string? refreshToken) =>
        refreshToken is null
            ? /*lang=json,strict*/ $"{{\"access_token\":\"{accessToken}\",\"token_type\":\"{tokenType}\",\"expires_in\":{expiresIn}}}"
            : /*lang=json,strict*/ $"{{\"access_token\":\"{accessToken}\",\"token_type\":\"{tokenType}\",\"expires_in\":{expiresIn},\"refresh_token\":\"{refreshToken}\"}}";
}
