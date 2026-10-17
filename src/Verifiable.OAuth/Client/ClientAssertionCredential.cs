using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Client;

/// <summary>
/// The credential a client authentication assertion (RFC 7523 Section 2.2) is signed under - a private key or a client
/// secret - with the header inputs and the signing operation it supplies to the assertion's one composition
/// (<see cref="ClientAssertionSigning"/>): a private key for <c>private_key_jwt</c>, its <c>alg</c> named by the key's <see cref="Tag"/>, its <c>kid</c> the identifier the
/// authorization server resolves the key by, and its signing function the one the registry holds for the key; or the
/// client secret a <c>client_secret_jwt</c> assertion is MACed with (OpenID Connect Core 1.0 Section 9), its <c>alg</c> one
/// of RFC 7518 Section 3.2's HMAC algorithms, no <c>kid</c>, and its signing operation the HMAC computed through the
/// registered <see cref="ComputeHmacDelegate"/>. A secret is judged as the key is formed: a refusal is a
/// <see cref="ClientAssertionCredentialRefusal"/> the caller carries, and a formed key signs without refusing.
/// </summary>
/// <remarks>
/// The key's octets are not owned: the caller keeps the <see cref="PrivateKeyMemory"/> alive and disposes it.
/// </remarks>
[DebuggerDisplay("ClientAssertionCredential Algorithm={Algorithm} KeyId={KeyId}")]
public sealed class ClientAssertionCredential
{
    /// <summary>Forms a key from its parts.</summary>
    /// <param name="key">The key's octets, not owned.</param>
    /// <param name="algorithm">The JWS <c>alg</c> the header names.</param>
    /// <param name="keyId">The <c>kid</c> the header names, or <see langword="null"/> for none.</param>
    /// <param name="sign">The signing operation the composition is handed.</param>
    private ClientAssertionCredential(PrivateKeyMemory key, string algorithm, string? keyId, SigningDelegate sign)
    {
        Key = key;
        Algorithm = algorithm;
        KeyId = keyId;
        Sign = sign;
    }


    /// <summary>The key's octets, not owned by this instance.</summary>
    public PrivateKeyMemory Key { get; }

    /// <summary>The JWS <c>alg</c> the assertion's protected header names.</summary>
    public string Algorithm { get; }

    /// <summary>The <c>kid</c> the assertion's protected header names, or <see langword="null"/> when it names none.</summary>
    public string? KeyId { get; }

    /// <summary>The signing operation the assertion's composition computes its signature with.</summary>
    internal SigningDelegate Sign { get; }


    /// <summary>
    /// The private key a <c>private_key_jwt</c> assertion is signed with (RFC 7523 Section 2.2): the <c>alg</c> its
    /// <see cref="Tag"/> names, the <c>kid</c> the authorization server resolves it by, and the signing function the
    /// registry holds for its algorithm and purpose.
    /// </summary>
    /// <param name="signingKey">The client's signing key, not owned.</param>
    /// <param name="signingKeyId">The <c>kid</c> header parameter value identifying the key to the authorization server.</param>
    /// <returns>The key.</returns>
    public static ClientAssertionCredential OfPrivateKey(PrivateKeyMemory signingKey, string signingKeyId)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(signingKeyId);

        var algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
        var sign = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(
            signingKey.Tag.Get<CryptoAlgorithm>(), signingKey.Tag.Get<Purpose>());

        return new ClientAssertionCredential(signingKey, algorithm, signingKeyId, sign);
    }


    /// <summary>
    /// The client secret a <c>client_secret_jwt</c> assertion is MACed with (OpenID Connect Core 1.0 Section 9): "The JWT
    /// MUST be signed using an HMAC SHA algorithm, such as HMAC SHA-256. The HMAC (Hash-based Message Authentication Code) is
    /// calculated using the octets of the UTF-8 representation of the client_secret as the shared key." The header names the
    /// algorithm and no <c>kid</c>: the secret is the client's own, which its identifier already names.
    /// </summary>
    /// <param name="clientSecret">The octets of the UTF-8 representation of the client secret, not owned.</param>
    /// <param name="algorithm">The HMAC algorithm: <see cref="WellKnownJwaValues.Hs256"/>, <see cref="WellKnownJwaValues.Hs384"/> or <see cref="WellKnownJwaValues.Hs512"/>.</param>
    /// <returns>
    /// The key; or the refusal of an algorithm none of RFC 7518 Section 3.2's HMAC algorithms names
    /// (<see cref="ClientAssertionCredentialRefusalReason.AlgorithmIsNotAnHmac"/>), or of a secret shorter than the algorithm's hash
    /// output, which RFC 7518 Section 3.2 makes the fewest octets its key may carry
    /// (<see cref="ClientAssertionCredentialRefusalReason.ClientSecretShorterThanHashOutput"/>).
    /// </returns>
    public static Result<ClientAssertionCredential, ClientAssertionCredentialRefusal> OfClientSecret(PrivateKeyMemory clientSecret, string algorithm)
    {
        ArgumentNullException.ThrowIfNull(clientSecret);
        ArgumentNullException.ThrowIfNull(algorithm);

        if(ClientSecretMac.Of(algorithm) is not ClientSecretMac mac)
        {
            return Result<ClientAssertionCredential, ClientAssertionCredentialRefusal>.Failure(new ClientAssertionCredentialRefusal
            {
                Reason = ClientAssertionCredentialRefusalReason.AlgorithmIsNotAnHmac,
                Algorithm = algorithm
            });
        }

        var secretOctets = clientSecret.AsReadOnlySpan().Length;

        if(secretOctets < mac.Length)
        {
            return Result<ClientAssertionCredential, ClientAssertionCredentialRefusal>.Failure(new ClientAssertionCredentialRefusal
            {
                Reason = ClientAssertionCredentialRefusalReason.ClientSecretShorterThanHashOutput,
                Algorithm = mac.Algorithm,
                SecretOctets = secretOctets,
                RequiredOctets = mac.Length
            });
        }

        return Result<ClientAssertionCredential, ClientAssertionCredentialRefusal>.Success(
            new ClientAssertionCredential(clientSecret, mac.Algorithm, keyId: null, mac.SignAsync));
    }


    /// <summary>
    /// The key a registration's assertion method composes its assertions under, read from
    /// <see cref="ClientRegistration.AuthenticationKeyMaterial"/> and the options: for <c>private_key_jwt</c> the private
    /// key under the options' <see cref="ClientAssertionOptions.SigningKeyId"/> (<see cref="OfPrivateKey"/>), and for
    /// <c>client_secret_jwt</c> the client secret under the options' <see cref="ClientAssertionOptions.ClientSecretAlgorithm"/>
    /// (<see cref="OfClientSecret"/>), whose options name no key identifier. A key identifier that is empty or white space
    /// only names none.
    /// </summary>
    /// <param name="registration">The registration naming the method and carrying its key.</param>
    /// <param name="options">The assertion options composed for the request.</param>
    /// <returns>
    /// The key; or the refusal of a registration naming a method known to present no assertion
    /// (<see cref="ClientAssertionCredentialRefusalReason.MethodPresentsNoAssertion"/>), naming one classified under no
    /// assertion family (<see cref="ClientAssertionCredentialRefusalReason.MethodNotSupported"/>), or carrying no key
    /// (<see cref="ClientAssertionCredentialRefusalReason.RegistrationCarriesNoKey"/>), of options naming no key identifier
    /// for a private key (<see cref="ClientAssertionCredentialRefusalReason.PrivateKeyNamesNoKeyIdentifier"/>) or naming one
    /// for a client secret (<see cref="ClientAssertionCredentialRefusalReason.ClientSecretNamesAKeyIdentifier"/>), or of the
    /// secret itself (<see cref="OfClientSecret"/>).
    /// </returns>
    public static Result<ClientAssertionCredential, ClientAssertionCredentialRefusal> Of(ClientRegistration registration, ClientAssertionOptions options)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(options);

        var method = registration.AuthenticationMethod;

        //The one classification of a registered method: a method known to present no assertion and one classified under no
        //assertion family are refused apart, so a method this composition does not support is never recorded as one known to
        //present no assertion.
        var family = ClientAssertionFamilies.Of(method);

        if(family is ClientAssertionFamily.NoAssertion or ClientAssertionFamily.Unsupported)
        {
            return Result<ClientAssertionCredential, ClientAssertionCredentialRefusal>.Failure(new ClientAssertionCredentialRefusal
            {
                Reason = family == ClientAssertionFamily.NoAssertion
                    ? ClientAssertionCredentialRefusalReason.MethodPresentsNoAssertion
                    : ClientAssertionCredentialRefusalReason.MethodNotSupported,
                Method = method
            });
        }

        var isPrivateKey = family == ClientAssertionFamily.DigitalSignature;

        if(registration.AuthenticationKeyMaterial?.PrivateKey is not PrivateKeyMemory key)
        {
            return Result<ClientAssertionCredential, ClientAssertionCredentialRefusal>.Failure(new ClientAssertionCredentialRefusal
            {
                Reason = ClientAssertionCredentialRefusalReason.RegistrationCarriesNoKey,
                Method = method
            });
        }

        var signingKeyId = string.IsNullOrWhiteSpace(options.SigningKeyId) ? null : options.SigningKeyId;

        if(isPrivateKey)
        {
            return signingKeyId is not null
                ? Result<ClientAssertionCredential, ClientAssertionCredentialRefusal>.Success(OfPrivateKey(key, signingKeyId))
                : Result<ClientAssertionCredential, ClientAssertionCredentialRefusal>.Failure(new ClientAssertionCredentialRefusal
                {
                    Reason = ClientAssertionCredentialRefusalReason.PrivateKeyNamesNoKeyIdentifier,
                    Algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(key.Tag)
                });
        }

        if(signingKeyId is not null)
        {
            return Result<ClientAssertionCredential, ClientAssertionCredentialRefusal>.Failure(new ClientAssertionCredentialRefusal
            {
                Reason = ClientAssertionCredentialRefusalReason.ClientSecretNamesAKeyIdentifier,
                Algorithm = options.ClientSecretAlgorithm
            });
        }

        return OfClientSecret(key, options.ClientSecretAlgorithm);
    }
}
