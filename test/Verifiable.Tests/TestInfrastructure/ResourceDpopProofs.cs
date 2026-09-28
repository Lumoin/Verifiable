using Verifiable.OAuth.Dpop;
using Verifiable.Tests.OAuth;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Builds the DPoP proofs a test presents with an access token at a protected resource
/// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 §4.2</see> and §7.1), reads
/// the resource nonce a challenge carries, and spells the literal <c>DPoP</c> challenges the library's
/// resources answer with, so every resource-side test builds its proofs and states its expected
/// challenges the same way and varies only the member it names.
/// </summary>
/// <remarks>
/// A proof carries <c>htm</c>, <c>htu</c>, <c>iat</c>, <c>jti</c>, the <c>ath</c> hash of the
/// presented token and, when given, the resource <c>nonce</c>; it is signed by the ES256 key the caller
/// names, whose public half the header's <c>jwk</c> carries. A caller can rewrite the serialized
/// protected header before signing, so the proof still verifies under its own key while declaring a
/// header the test names.
/// </remarks>
internal static class ResourceDpopProofs
{
    /// <summary>
    /// The <c>algs</c> value of every <c>DPoP</c> challenge the library's resources answer with, written
    /// out: RFC 9449 §7.1 "The value of the parameter is a space-delimited list of JWS alg (Algorithm)
    /// header values".
    /// </summary>
    public static string AcceptedProofAlgorithms { get; } = "ES256 ES384 ES512 RS256 RS384 RS512 PS256 PS384 PS512 EdDSA";


    /// <summary>The literal <c>DPoP</c> challenge carrying <paramref name="error"/> and the <c>algs</c> parameter.</summary>
    /// <param name="error">The challenge's <c>error</c>.</param>
    /// <returns>The <c>WWW-Authenticate</c> value.</returns>
    public static string DpopChallenge(string error) => $"DPoP error=\"{error}\", algs=\"{AcceptedProofAlgorithms}\"";


    /// <summary>
    /// Builds and signs a DPoP proof for a request to a protected resource.
    /// </summary>
    /// <param name="key">The DPoP key that signs the proof and whose public half the header carries.</param>
    /// <param name="httpMethod">The <c>htm</c> value.</param>
    /// <param name="htu">The <c>htu</c> value.</param>
    /// <param name="accessToken">The access token the <c>ath</c> claim hashes.</param>
    /// <param name="nonce">The <c>nonce</c> value, or <see langword="null"/> to carry none.</param>
    /// <param name="issuedAt">The <c>iat</c> value.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="jti">The <c>jti</c> value, or <see langword="null"/> for a fresh unique one.</param>
    /// <param name="alterHeader">Rewrites the serialized protected header before signing, or <see langword="null"/> to keep it.</param>
    /// <returns>The compact DPoP proof.</returns>
    public static async Task<string> BuildAsync(
        DpopKey key,
        string httpMethod,
        string htu,
        string accessToken,
        string? nonce,
        DateTimeOffset issuedAt,
        CancellationToken cancellationToken,
        string? jti = null,
        Action<Dictionary<string, object>>? alterHeader = null)
    {
        ArgumentNullException.ThrowIfNull(key);

        string ath = await DpopProofValidator.ComputeAthAsync(
            accessToken, TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool, cancellationToken)
            .ConfigureAwait(false);

        DpopProofClaims claims = new()
        {
            Htm = httpMethod,
            Htu = htu,
            Iat = issuedAt,
            Jti = jti ?? Guid.NewGuid().ToString("N"),
            Nonce = nonce,
            Ath = ath
        };

        DpopJwsPartSerializer serializer = alterHeader is null
            ? DpopTestSupport.Serializer
            : DpopTestSupport.Serializer with
            {
                SerializeHeader = header =>
                {
                    Dictionary<string, object> altered = new(DpopTestSupport.Serializer.SerializeHeader(header), StringComparer.Ordinal);
                    alterHeader(altered);

                    return altered;
                }
            };

        return await DpopProofConstruction.BuildAsync(
            claims, key, TestHostShell.Base64UrlEncoder, serializer,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool, cancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Reads the single <c>DPoP-Nonce</c> header of a resource's nonce challenge.
    /// </summary>
    /// <param name="response">The challenge response.</param>
    /// <returns>The nonce the resource provided.</returns>
    public static string ReadNonce(HttpResponseMessage response)
    {
        ArgumentNullException.ThrowIfNull(response);

        return response.Headers.TryGetValues("DPoP-Nonce", out IEnumerable<string>? nonces)
            ? nonces.Single()
            : throw new AssertFailedException($"The response ({(int)response.StatusCode}) carries no DPoP-Nonce header.");
    }
}
