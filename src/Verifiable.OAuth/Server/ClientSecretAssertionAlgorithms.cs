using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The family of algorithms a client's assertion is verified under, chosen by the authentication method the client registered and
/// never by the assertion's own header (RFC 8725 Section 3.1).
/// </summary>
public enum ClientAssertionFamily
{
    /// <summary>
    /// The method is known to authenticate by no client assertion: <c>none</c> (RFC 7591 Section 2), <c>client_secret_basic</c> and
    /// <c>client_secret_post</c> (RFC 6749 Section 2.3.1), and the mutual TLS methods <c>tls_client_auth</c> and
    /// <c>self_signed_tls_client_auth</c> (RFC 8705 Section 2).
    /// </summary>
    NoAssertion,

    /// <summary>
    /// <c>client_secret_jwt</c>: an assertion MACed under the octets of the client's secret by one of RFC 7518 Section 3.2's HMAC
    /// algorithms (OpenID Connect Core 1.0 Section 9), verified under the secret alone and never under a key.
    /// </summary>
    MessageAuthenticationCode,

    /// <summary>
    /// <c>private_key_jwt</c>: an assertion signed under a key the client registered or published (RFC 7523 Section 2.2), verified
    /// under its public half alone and never handed to an HMAC.
    /// </summary>
    DigitalSignature,

    /// <summary>
    /// The rule classifies the method under no family: an application-defined method (<see cref="ClientAuthenticationMethod.Create"/>),
    /// or one whose credential neither family judges - <c>attest_jwt_client_auth</c>'s attestation and proof of possession and
    /// <c>spiffe_jwt</c>'s JWT-SVID under its trust domain's bundle. Nothing is concluded about whether it presents an assertion: a
    /// caller verifies no assertion of such a client under either family, and refuses it.
    /// </summary>
    Unsupported
}


/// <summary>
/// The rule choosing the family of algorithms a client's assertion is verified under by the method the client registered
/// (RFC 7591 Section 2 <c>token_endpoint_auth_method</c>): a client registered for <c>client_secret_jwt</c> is held to the HMAC
/// algorithms its secret keys, and one registered for <c>private_key_jwt</c> to the signature algorithms of its keys. Whatever its
/// header names, an assertion of the other family is refused before any secret or key is read, so no public key ever keys an HMAC
/// - the key confusion RFC 8725 Section 3.1 has a verifier rule out by binding each key to one algorithm.
/// </summary>
public static class ClientAssertionFamilies
{
    /// <summary>
    /// The family an assertion of a client registered under a method is verified under, each known method classified by name and
    /// every other answered <see cref="ClientAssertionFamily.Unsupported"/>, never taken for a method that presents no assertion.
    /// </summary>
    /// <param name="method">The method the client registered.</param>
    /// <returns>
    /// The family; <see cref="ClientAssertionFamily.NoAssertion"/> for a method known to present no assertion; or
    /// <see cref="ClientAssertionFamily.Unsupported"/> for one this rule classifies under no family.
    /// </returns>
    public static ClientAssertionFamily Of(ClientAuthenticationMethod method) =>
        method == ClientAuthenticationMethod.ClientSecretJwt ? ClientAssertionFamily.MessageAuthenticationCode
        : method == ClientAuthenticationMethod.PrivateKeyJwt ? ClientAssertionFamily.DigitalSignature
        : method == ClientAuthenticationMethod.None
            || method == ClientAuthenticationMethod.ClientSecretBasic
            || method == ClientAuthenticationMethod.ClientSecretPost
            || method == ClientAuthenticationMethod.TlsClientAuth
            || method == ClientAuthenticationMethod.SelfSignedTlsClientAuth ? ClientAssertionFamily.NoAssertion
        : ClientAssertionFamily.Unsupported;
}


/// <summary>
/// The HMAC algorithms an authorization server accepts a <c>client_secret_jwt</c> assertion under (OpenID Connect Core 1.0 Section
/// 9; RFC 7518 Section 3.2), named once and read by the verification and by the discovery that advertises them alike
/// (<c>token_endpoint_auth_signing_alg_values_supported</c>, RFC 8414 Section 2): an assertion whose header names an algorithm off
/// the list is refused before the secret is read, and the list advertised is the list accepted.
/// </summary>
/// <remarks>
/// Every algorithm named must be one of the HMAC algorithms the client's composition MACs under and the server's verification
/// recomputes (<see cref="ClientSecretAssertionVerification"/>): a list naming a signature algorithm, <c>none</c>, an unknown
/// name, a name twice, or no name at all is refused when it is made, before it accepts anything. The algorithms are compared
/// exactly (RFC 7515 Section 4.1.1: <c>alg</c> is a case-sensitive string).
/// </remarks>
public sealed class ClientSecretAssertionAlgorithms
{
    /// <summary>Makes a list, holding each algorithm it names to being one of RFC 7518 Section 3.2's HMAC algorithms.</summary>
    /// <param name="algorithms">The JWS algorithms, in the order they are advertised.</param>
    /// <exception cref="ArgumentException">The list is empty, names an algorithm twice, or names one that is no HMAC algorithm.</exception>
    public ClientSecretAssertionAlgorithms(IReadOnlyList<string> algorithms)
    {
        ArgumentNullException.ThrowIfNull(algorithms);

        if(algorithms.Count == 0)
        {
            throw new ArgumentException("A client_secret_jwt assertion is accepted under at least one HMAC algorithm.", nameof(algorithms));
        }

        var named = new HashSet<string>(StringComparer.Ordinal);

        foreach(var algorithm in algorithms)
        {
            if(algorithm is null || ClientSecretMac.Of(algorithm) is null)
            {
                throw new ArgumentException(
                    $"'{algorithm}' is no HMAC algorithm of RFC 7518 Section 3.2, so no client_secret_jwt assertion is verified under it.",
                    nameof(algorithms));
            }

            if(!named.Add(algorithm))
            {
                throw new ArgumentException($"'{algorithm}' is named twice.", nameof(algorithms));
            }
        }

        Algorithms = [.. algorithms];
    }


    /// <summary>The algorithms, in the order they are advertised.</summary>
    public IReadOnlyList<string> Algorithms { get; }


    /// <summary>Whether an algorithm a protected header names is on the list, compared exactly.</summary>
    /// <param name="algorithm">The header's <c>alg</c>, or <see langword="null"/> when it names none.</param>
    /// <returns><see langword="true"/> when the list names it.</returns>
    public bool Accepts(string? algorithm) =>
        algorithm is not null && Algorithms.Any(accepted => string.Equals(accepted, algorithm, StringComparison.Ordinal));
}
