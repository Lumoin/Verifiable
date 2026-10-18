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
    /// carrying white space: a parameter name is compared exactly, so none of them names the parameter. Each row states the answer
    /// of every recognition explicitly.
    /// </summary>
    /// <param name="name">The name handed to every recognition.</param>
    /// <param name="accessToken">The answer of <see cref="OAuthRequestParameterNames.IsAccessToken"/>.</param>
    /// <param name="refreshToken">The answer of <see cref="OAuthRequestParameterNames.IsRefreshToken"/>.</param>
    /// <param name="idToken">The answer of <see cref="OAuthRequestParameterNames.IsIdToken"/>.</param>
    /// <param name="nonce">The answer of <see cref="OAuthRequestParameterNames.IsNonce"/>.</param>
    [TestMethod]
    [DataRow("access_token", true, false, false, false, DisplayName = "access_token")]
    [DataRow("refresh_token", false, true, false, false, DisplayName = "refresh_token")]
    [DataRow("id_token", false, false, true, false, DisplayName = "id_token")]
    [DataRow("nonce", false, false, false, true, DisplayName = "nonce")]
    [DataRow("Refresh_Token", false, false, false, false, DisplayName = "refresh_token spelled in another case")]
    [DataRow("ID_TOKEN", false, false, false, false, DisplayName = "id_token spelled in another case")]
    [DataRow("Nonce", false, false, false, false, DisplayName = "nonce spelled in another case")]
    [DataRow("nonce ", false, false, false, false, DisplayName = "nonce with trailing white space")]
    [DataRow("id_token_hint", false, false, false, false, DisplayName = "A parameter whose name begins with id_token")]
    [DataRow("", false, false, false, false, DisplayName = "The empty name")]
    public void EachRecognitionNamesItsParameterExactlyAndNoOther(string name, bool accessToken, bool refreshToken, bool idToken, bool nonce)
    {
        Assert.AreEqual(accessToken, OAuthRequestParameterNames.IsAccessToken(name), name);
        Assert.AreEqual(refreshToken, OAuthRequestParameterNames.IsRefreshToken(name), name);
        Assert.AreEqual(idToken, OAuthRequestParameterNames.IsIdToken(name), name);
        Assert.AreEqual(nonce, OAuthRequestParameterNames.IsNonce(name), name);
    }
}
