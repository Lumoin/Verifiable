using System.Diagnostics;
using System.Globalization;

namespace Verifiable.OAuth.Client;

/// <summary>
/// The rule a client authentication assertion's key refuses (<see cref="ClientAssertionCredential"/>), before anything is signed
/// or sent.
/// </summary>
public enum ClientAssertionCredentialRefusalReason
{
    /// <summary>
    /// A <c>client_secret_jwt</c> assertion names an algorithm other than an HMAC algorithm of RFC 7518 Section 3.2
    /// (<c>HS256</c>, <c>HS384</c>, <c>HS512</c>): OpenID Connect Core 1.0 Section 9, "The JWT MUST be signed using an HMAC
    /// SHA algorithm".
    /// </summary>
    AlgorithmIsNotAnHmac,

    /// <summary>
    /// The client secret carries fewer octets than the hash output of the HMAC algorithm it keys: RFC 7518 Section 3.2,
    /// "A key of the same size as the hash output (for instance, 256 bits for "HS256") or larger MUST be used with this
    /// algorithm."
    /// </summary>
    ClientSecretShorterThanHashOutput,

    /// <summary>
    /// A <c>client_secret_jwt</c> assertion's options name a key identifier: the secret is the client's own, which its
    /// identifier already names (OpenID Connect Core 1.0 Section 9), so options naming a <c>kid</c> were composed for a
    /// signing key, never for a secret.
    /// </summary>
    ClientSecretNamesAKeyIdentifier,

    /// <summary>
    /// A <c>private_key_jwt</c> assertion's options name no key identifier, which the authorization server resolves the
    /// client's key by (RFC 7515 Section 4.1.4). A key identifier that is empty or white space only names none.
    /// </summary>
    PrivateKeyNamesNoKeyIdentifier,

    /// <summary>
    /// The registration names a client authentication method known to present no client assertion
    /// (<see cref="Verifiable.OAuth.Server.ClientAssertionFamily.NoAssertion"/>): <c>none</c>, <c>client_secret_basic</c>,
    /// <c>client_secret_post</c> and the two mutual TLS methods; only <c>private_key_jwt</c> (RFC 7523 Section 2.2) and
    /// <c>client_secret_jwt</c> (OpenID Connect Core 1.0 Section 9) authenticate the client with one here.
    /// </summary>
    MethodPresentsNoAssertion,

    /// <summary>
    /// The registration names a client authentication method classified under no assertion family
    /// (<see cref="Verifiable.OAuth.Server.ClientAssertionFamily.Unsupported"/>): an application-defined method, or one whose
    /// credential neither family composes - <c>attest_jwt_client_auth</c>'s attestation and proof of possession and
    /// <c>spiffe_jwt</c>'s JWT-SVID. Nothing is concluded about whether it presents an assertion; this composition forms no
    /// credential for it.
    /// </summary>
    MethodNotSupported,

    /// <summary>
    /// The registration names an assertion method but carries no authentication key material: neither the private key a
    /// <c>private_key_jwt</c> assertion is signed with nor the client secret a <c>client_secret_jwt</c> assertion is MACed
    /// with.
    /// </summary>
    RegistrationCarriesNoKey,

    /// <summary>
    /// The MAC a <c>client_secret_jwt</c> assertion carries is not the client secret's HMAC of the assertion's signing input
    /// under the algorithm judged, or the assertion is no compact JWS carrying one: RFC 7523 Section 3 item 9, "The
    /// authorization server MUST reject any JWT with an invalid signature or Message Authentication Code". The authorization
    /// server's verification of the assertion refuses by it (<see cref="Verifiable.OAuth.Server.ClientSecretAssertionVerification"/>).
    /// </summary>
    MacDoesNotVerify
}


/// <summary>
/// A client authentication assertion refused before anything is signed or sent: the rule broken
/// (<see cref="Reason"/>) and the values it was judged on, which a caller and a record carry as they are and render
/// through <see cref="Describe"/>.
/// </summary>
[DebuggerDisplay("ClientAssertionCredentialRefusal Reason={Reason} Algorithm={Algorithm}")]
public sealed record ClientAssertionCredentialRefusal
{
    /// <summary>The rule broken.</summary>
    public required ClientAssertionCredentialRefusalReason Reason { get; init; }

    /// <summary>
    /// The JWS <c>alg</c> the assertion was to be signed or MACed under, as the options or the key named it; or
    /// <see langword="null"/> for <see cref="ClientAssertionCredentialRefusalReason.MethodPresentsNoAssertion"/>,
    /// <see cref="ClientAssertionCredentialRefusalReason.MethodNotSupported"/> and
    /// <see cref="ClientAssertionCredentialRefusalReason.RegistrationCarriesNoKey"/>, refused before any algorithm is named.
    /// </summary>
    public string? Algorithm { get; init; }

    /// <summary>
    /// The client authentication method the registration names, for
    /// <see cref="ClientAssertionCredentialRefusalReason.MethodPresentsNoAssertion"/>,
    /// <see cref="ClientAssertionCredentialRefusalReason.MethodNotSupported"/> and
    /// <see cref="ClientAssertionCredentialRefusalReason.RegistrationCarriesNoKey"/>; <see langword="null"/> for every other
    /// reason.
    /// </summary>
    public ClientAuthenticationMethod? Method { get; init; }

    /// <summary>
    /// The octets the client secret carries, for <see cref="ClientAssertionCredentialRefusalReason.ClientSecretShorterThanHashOutput"/>;
    /// zero for every other reason.
    /// </summary>
    public int SecretOctets { get; init; }

    /// <summary>
    /// The fewest octets the algorithm's key may carry, its hash output, for
    /// <see cref="ClientAssertionCredentialRefusalReason.ClientSecretShorterThanHashOutput"/>; zero for every other reason.
    /// </summary>
    public int RequiredOctets { get; init; }


    /// <summary>The refusal in words, derived from the rule and the values it was judged on.</summary>
    /// <returns>The sentence naming the rule broken.</returns>
    public string Describe() => Reason switch
    {
        ClientAssertionCredentialRefusalReason.AlgorithmIsNotAnHmac => string.Create(
            CultureInfo.InvariantCulture,
            $"A client_secret_jwt assertion is MACed under an HMAC algorithm of RFC 7518 Section 3.2 (HS256, HS384 or HS512); '{Algorithm}' is none."),
        ClientAssertionCredentialRefusalReason.ClientSecretShorterThanHashOutput => string.Create(
            CultureInfo.InvariantCulture,
            $"RFC 7518 Section 3.2: a key of the same size as the hash output or larger MUST be used with {Algorithm}; the client secret carries {SecretOctets} octets and {Algorithm} needs {RequiredOctets}."),
        ClientAssertionCredentialRefusalReason.ClientSecretNamesAKeyIdentifier =>
            "A client_secret_jwt assertion names no key identifier: the secret is the client's own, which its identifier already names (OpenID Connect Core 1.0 Section 9).",
        ClientAssertionCredentialRefusalReason.PrivateKeyNamesNoKeyIdentifier =>
            "A private_key_jwt assertion names the key identifier the authorization server resolves the client's key by (RFC 7515 Section 4.1.4).",
        ClientAssertionCredentialRefusalReason.MethodPresentsNoAssertion => string.Create(
            CultureInfo.InvariantCulture,
            $"The registration names {MethodName()}, which presents no client assertion: only private_key_jwt (RFC 7523 Section 2.2) and client_secret_jwt (OpenID Connect Core 1.0 Section 9) do."),
        ClientAssertionCredentialRefusalReason.MethodNotSupported => string.Create(
            CultureInfo.InvariantCulture,
            $"The registration names {MethodName()}, which no client assertion family classifies, so no credential is formed for it: only private_key_jwt (RFC 7523 Section 2.2) and client_secret_jwt (OpenID Connect Core 1.0 Section 9) are composed."),
        ClientAssertionCredentialRefusalReason.RegistrationCarriesNoKey => string.Create(
            CultureInfo.InvariantCulture,
            $"The registration names {MethodName()} but carries no authentication key material to sign or MAC its assertion with."),
        ClientAssertionCredentialRefusalReason.MacDoesNotVerify => string.Create(
            CultureInfo.InvariantCulture,
            $"The client_secret_jwt assertion carries no MAC the client secret verifies under {Algorithm} (RFC 7523 Section 3 item 9)."),
        _ => throw new UnreachableException($"The refusal reason '{Reason}' has no description.")
    };


    /// <summary>The registered name of <see cref="Method"/>, or a word saying the refusal named none.</summary>
    /// <returns>The name.</returns>
    private string MethodName() =>
        Method is ClientAuthenticationMethod method ? ClientAuthenticationMethodNames.GetName(method) : "no client authentication method";
}
