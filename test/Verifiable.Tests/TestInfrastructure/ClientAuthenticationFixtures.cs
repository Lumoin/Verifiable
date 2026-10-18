using System.Buffers;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.Tests.OAuth;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The client-authentication wiring a client-side wire row composes against <see cref="TestHostShell"/>: the shared
/// secret a <c>client_secret_post</c> or <c>client_secret_basic</c> registration presents, the JWK set a
/// <c>private_key_jwt</c> registration publishes, and the server-side declaration of the method the registration
/// authenticates with.
/// </summary>
internal static class ClientAuthenticationFixtures
{
    /// <summary>
    /// Builds a <see cref="PublicPrivateKeyMaterial{TPublicKeyMemory, TPrivateKeyMemory}"/> carrying
    /// <paramref name="secret"/> as the private-key bytes <c>client_secret_post</c>/
    /// <c>client_secret_basic</c> attach as the shared secret. The public half is never read by
    /// either method but the pair type requires one regardless.
    /// </summary>
    /// <param name="secret">The shared secret.</param>
    /// <param name="pool">The pool both halves are rented from.</param>
    /// <returns>The pair; the caller disposes both halves.</returns>
    internal static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> BuildSecretKeyMaterial(string secret, BaseMemoryPool pool)
    {
        PrivateKeyMemory? privateKey = null;
        PublicKeyMemory? publicKey = null;
        try
        {
            IMemoryOwner<byte> secretOwner = pool.Rent(Encoding.UTF8.GetByteCount(secret));
            _ = Encoding.UTF8.GetBytes(secret, secretOwner.Memory.Span);
            privateKey = new PrivateKeyMemory(secretOwner, Tag.Empty);
            publicKey = new PublicKeyMemory(pool.Rent(1), Tag.Empty);
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> pair = new(publicKey, privateKey);
            publicKey = null;
            privateKey = null;

            return pair;
        }
        finally
        {
            //Whatever was created and not handed on to the pair is released here.
            publicKey?.Dispose();
            privateKey?.Dispose();
        }
    }


    /// <summary>
    /// Declares <paramref name="method"/> as the client's registered token-endpoint authentication
    /// method (and, for <c>private_key_jwt</c>, publishes <paramref name="clientJwks"/>) and adds it
    /// to the server's advertised <c>ClientAuthenticationMethodsSupported</c> set so the declared-
    /// method-coherence gate admits the exchange.
    /// </summary>
    /// <param name="host">The host whose registration and integration are altered.</param>
    /// <param name="material">The registration the method is declared for.</param>
    /// <param name="method">The method the registration authenticates with.</param>
    /// <param name="clientJwks">The JWK set a <c>private_key_jwt</c> registration publishes, or <see langword="null"/>.</param>
    /// <param name="assertionSigningAlgorithm">The client assertion's signing algorithm the server admits, or <see langword="null"/>.</param>
    /// <returns>A task that completes when the registration and the integration are published.</returns>
    internal static async Task DeclareServerSideAuthMethodAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        ClientAuthenticationMethod method,
        string? clientJwks = null,
        string? assertionSigningAlgorithm = null)
    {
        HostedAuthorizationServer hosted = host.Host("default");
        _ = await host.SetTokenEndpointAuthMethodAsync(material, method, clientJwks).ConfigureAwait(false);

        await TestHostShell.AlterAsync(hosted.Server, candidateIntegration =>
        {
            candidateIntegration.ClientAuthenticationMethodsSupported =
                [ClientAuthenticationMethod.None, method];
            if(assertionSigningAlgorithm is not null)
            {
                candidateIntegration.ClientAssertionSigningAlgorithmsSupported = [assertionSigningAlgorithm];
            }
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds a JWKS JSON document publishing one key under <paramref name="kid"/>, the shape
    /// <see cref="PrivateKeyJwtClientAuthentication.BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Verifiable.OAuth.Server.Pipeline.ResolveJwksUriDelegate?,ClientAssertionAudiencePolicy?)"/>
    /// resolves the client's signing key from.
    /// </summary>
    /// <param name="jwk">The key's JWK members.</param>
    /// <param name="kid">The key identifier the key is published under.</param>
    /// <returns>The JWK set's JSON text.</returns>
    internal static string BuildJwksJson(IReadOnlyDictionary<string, string> jwk, string kid)
    {
        StringBuilder sb = new();
        _ = sb.Append('{').Append('"').Append(WellKnownJwkMemberNames.Keys).Append("\":[{");
        foreach(KeyValuePair<string, string> member in jwk)
        {
            _ = sb.Append('"').Append(member.Key).Append("\":\"").Append(member.Value).Append("\",");
        }

        _ = sb.Append('"').Append(WellKnownJwkMemberNames.Kid).Append("\":\"").Append(kid).Append("\"}]}");

        return sb.ToString();
    }
}
