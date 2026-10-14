using System.Text.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.Tests.OAuth;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The real-wire steps the rows of the DPoP authorization code binding share
/// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-10">RFC 9449 Section 10</see> and
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10.1">Section 10.1</see>): the DPoP proofs a client sends
/// with a pushed authorization request and with a code redemption, the pushed request sent with or without a
/// <c>DPoP</c> field, and the readings of the answers a row asserts: an OAuth error body
/// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>) and an issued access
/// token's <c>token_type</c> and <c>cnf.jkt</c>
/// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">RFC 9449 Section 6.1</see>).
/// </summary>
internal static class DpopCodeBindingWire
{
    /// <summary>
    /// The 64-character lowercase hexadecimal spelling of a SHA-256 digest, which is no JWK SHA-256 Thumbprint in the
    /// spelling <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">RFC 9449 Section 6.1</see> names ("the
    /// base64url encoding (as defined in [RFC7515]) of the JWK SHA-256 Thumbprint"), which for 32 octets is 43
    /// characters. A constant, not a property, because a data row's attribute argument must be one.
    /// </summary>
    public const string HexadecimalSha256Digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";


    /// <summary>
    /// Builds a DPoP proof by <paramref name="key"/> for a pushed authorization request: <c>htm</c> <c>POST</c> and
    /// <c>htu</c> the pushed authorization request endpoint of <paramref name="segment"/>, carrying no <c>ath</c>.
    /// </summary>
    /// <param name="host">The fixture owning the listener.</param>
    /// <param name="segment">The tenant route segment.</param>
    /// <param name="key">The DPoP key that signs the proof.</param>
    /// <param name="nonce">The <c>nonce</c> claim, or <see langword="null"/> for none.</param>
    /// <param name="issuedAt">The <c>iat</c> claim.</param>
    /// <param name="cancellationToken">Cancellation of the signing call.</param>
    /// <returns>The compact DPoP proof.</returns>
    public static Task<string> BuildPushedRequestProofAsync(
        TestHostShell host, string segment, DpopKey key, string? nonce, DateTimeOffset issuedAt,
        CancellationToken cancellationToken) =>
        ResourceDpopProofs.BuildAsync(
            key, WellKnownHttpMethods.Post, RawAuthCodeWirePushers.ResolveParEndpointUri(host, segment).OriginalString,
            accessToken: null, nonce, issuedAt, cancellationToken);


    /// <summary>
    /// Builds a DPoP proof by <paramref name="key"/> for a token request: <c>htm</c> <c>POST</c> and <c>htu</c> the
    /// token endpoint of <paramref name="segment"/>, carrying no <c>ath</c>.
    /// </summary>
    /// <param name="host">The fixture owning the listener.</param>
    /// <param name="segment">The tenant route segment.</param>
    /// <param name="key">The DPoP key that signs the proof.</param>
    /// <param name="nonce">The <c>nonce</c> claim, or <see langword="null"/> for none.</param>
    /// <param name="issuedAt">The <c>iat</c> claim.</param>
    /// <param name="cancellationToken">Cancellation of the signing call.</param>
    /// <returns>The compact DPoP proof.</returns>
    public static Task<string> BuildTokenProofAsync(
        TestHostShell host, string segment, DpopKey key, string? nonce, DateTimeOffset issuedAt,
        CancellationToken cancellationToken) =>
        ResourceDpopProofs.BuildAsync(
            key, WellKnownHttpMethods.Post, RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment).OriginalString,
            accessToken: null, nonce, issuedAt, cancellationToken);


    /// <summary>
    /// Sends a pushed authorization request of <paramref name="fields"/>, exactly as given, over the real wire,
    /// carrying <paramref name="dpopProof"/> in its one <c>DPoP</c> field or no such field when it is
    /// <see langword="null"/>; the listener is started on first use.
    /// </summary>
    /// <param name="host">The fixture owning the listener.</param>
    /// <param name="segment">The tenant route segment.</param>
    /// <param name="fields">The form fields, repeats included.</param>
    /// <param name="dpopProof">The DPoP proof, or <see langword="null"/> to send none.</param>
    /// <param name="cancellationToken">Cancellation of the wire exchange.</param>
    /// <returns>The whole response, its fields included.</returns>
    public static async Task<HttpResponseData> PushAsync(
        TestHostShell host, string segment, IReadOnlyCollection<KeyValuePair<string, string>> fields, string? dpopProof,
        CancellationToken cancellationToken)
    {
        await host.StartHttpHostAsync(cancellationToken).ConfigureAwait(false);
        OutgoingHeaders headers = dpopProof switch
        {
            null => OutgoingHeaders.Empty,
            _ => OutgoingHeaders.Empty.WithDpop(dpopProof)
        };

        return await RawAuthCodeWirePushers.PushRawParRequestAsync(
            host.Host("default"), segment, fields, headers, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Reads the authorization code out of an authorize response: asserts the <c>302</c> and returns the
    /// <c>code</c> query parameter of its <c>Location</c>.
    /// </summary>
    /// <param name="statusCode">The authorize response's status code.</param>
    /// <param name="location">The authorize response's <c>Location</c>.</param>
    /// <returns>The authorization code.</returns>
    public static string ReadCode(int statusCode, Uri? location)
    {
        Assert.AreEqual(302, statusCode, "The authorization endpoint answers with a redirect.");
        Assert.IsNotNull(location, "The redirect carries a Location.");

        return TestBrowser.ExtractQueryParam(location.ToString(), OAuthRequestParameterNames.Code)
            ?? throw new AssertFailedException($"The redirect carries no code: '{location}'.");
    }


    /// <summary>
    /// Asserts an error response of <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section
    /// 5.2</see>: the status, and the <c>error</c> and <c>error_description</c> members of the JSON body, each equal to
    /// the literal expected.
    /// </summary>
    /// <param name="statusCode">The response's status code.</param>
    /// <param name="body">The response's body.</param>
    /// <param name="expectedStatusCode">The expected status code.</param>
    /// <param name="expectedError">The expected <c>error</c>.</param>
    /// <param name="expectedDescription">The expected <c>error_description</c>.</param>
    public static void AssertError(
        int statusCode, string body, int expectedStatusCode, string expectedError, string expectedDescription)
    {
        Assert.AreEqual(expectedStatusCode, statusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(expectedError, document.RootElement.GetProperty("error").GetString(), body);
        Assert.AreEqual(expectedDescription, document.RootElement.GetProperty("error_description").GetString(), body);
    }


    /// <summary>
    /// Asserts that <paramref name="body"/> is an error response's JSON body naming its <c>error</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>: "The parameters are
    /// included in the entity-body of the HTTP response using the "application/json" media type"), before any reading
    /// parses it, so an answer with an empty or non-JSON body fails at this assertion.
    /// </summary>
    /// <param name="body">The response's body.</param>
    public static void AssertCarriesJsonErrorBody(string body)
    {
        Assert.Contains("\"error\":\"", body, $"The answer carries a JSON error body naming its error; the body was '{body}'.");
    }


    /// <summary>
    /// Asserts a successful token response: status <c>200</c>, <c>token_type</c> equal to
    /// <paramref name="expectedTokenType"/>, and the issued access token's <c>cnf.jkt</c> equal to
    /// <paramref name="expectedJwkThumbprint"/>, or no <c>cnf</c> claim when that is <see langword="null"/>.
    /// </summary>
    /// <param name="statusCode">The response's status code.</param>
    /// <param name="body">The response's body.</param>
    /// <param name="expectedTokenType">The expected <c>token_type</c>.</param>
    /// <param name="expectedJwkThumbprint">The expected <c>cnf.jkt</c>, or <see langword="null"/> for an unbound token.</param>
    public static void AssertIssued(int statusCode, string body, string expectedTokenType, string? expectedJwkThumbprint)
    {
        Assert.AreEqual(200, statusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(expectedTokenType, document.RootElement.GetProperty("token_type").GetString(), body);
        string accessToken = document.RootElement.GetProperty("access_token").GetString()!;
        if(expectedJwkThumbprint is null)
        {
            Assert.IsFalse(JwtPayloadReader.HasCnfClaim(accessToken), "The unbound access token carries no cnf claim.");

            return;
        }

        Assert.AreEqual(expectedJwkThumbprint, JwtPayloadReader.ReadCnfJkt(accessToken),
            "The access token's cnf.jkt is the thumbprint of the DPoP key the code is bound to.");
    }
}
