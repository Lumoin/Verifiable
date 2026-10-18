using Verifiable.OAuth;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The recognitions of the token response's credential parameter names and of the authentication request's <c>nonce</c>
/// (<see cref="OAuthRequestParameterNames.IsAccessToken"/>, <see cref="OAuthRequestParameterNames.IsRefreshToken"/>,
/// <see cref="OAuthRequestParameterNames.IsIdToken"/>, <see cref="OAuthRequestParameterNames.IsNonce"/>): each names its parameter
/// exactly, compared as the case-sensitive text a parameter name is (RFC 6749 section 3.1), and no other name.
/// </summary>
[TestClass]
internal sealed class OAuthRequestParameterNameRecognitionTests
{
    /// <summary>
    /// Each recognition answers its own parameter's name and refuses the other three, a spelling differing in case and one
    /// carrying white space: a parameter name is compared exactly, so none of them names the parameter.
    /// </summary>
    /// <param name="name">The name handed to every recognition.</param>
    /// <param name="expected">Which recognition answers it, or <see langword="null"/> when none does.</param>
    [TestMethod]
    [DataRow("access_token", "access_token", DisplayName = "access_token")]
    [DataRow("refresh_token", "refresh_token", DisplayName = "refresh_token")]
    [DataRow("id_token", "id_token", DisplayName = "id_token")]
    [DataRow("nonce", "nonce", DisplayName = "nonce")]
    [DataRow("Refresh_Token", null, DisplayName = "refresh_token spelled in another case")]
    [DataRow("ID_TOKEN", null, DisplayName = "id_token spelled in another case")]
    [DataRow("Nonce", null, DisplayName = "nonce spelled in another case")]
    [DataRow("nonce ", null, DisplayName = "nonce with trailing white space")]
    [DataRow("id_token_hint", null, DisplayName = "A parameter whose name begins with id_token")]
    [DataRow("", null, DisplayName = "The empty name")]
    public void EachRecognitionNamesItsParameterExactlyAndNoOther(string name, string? expected)
    {
        Assert.AreEqual(string.Equals(expected, OAuthRequestParameterNames.AccessToken, StringComparison.Ordinal), OAuthRequestParameterNames.IsAccessToken(name));
        Assert.AreEqual(string.Equals(expected, OAuthRequestParameterNames.RefreshToken, StringComparison.Ordinal), OAuthRequestParameterNames.IsRefreshToken(name));
        Assert.AreEqual(string.Equals(expected, OAuthRequestParameterNames.IdToken, StringComparison.Ordinal), OAuthRequestParameterNames.IsIdToken(name));
        Assert.AreEqual(string.Equals(expected, OAuthRequestParameterNames.Nonce, StringComparison.Ordinal), OAuthRequestParameterNames.IsNonce(name));
    }
}
