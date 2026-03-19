using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

using Verifiable.OAuth.Server;

namespace Verifiable.OAuth;

/// <summary>
/// Internal helpers for resolving a <see cref="KeyId"/> at a library signing call
/// site, honouring <see cref="AuthorizationServerCryptography.SelectSigningKey"/>
/// when set and falling back to the registration's default when not.
/// </summary>
/// <remarks>
/// Every library call site that signs something for a given
/// <see cref="KeyUsageContext"/> goes through
/// <see cref="ResolveSigningKeyIdAsync"/>. Applications that wire
/// <see cref="AuthorizationServerCryptography.SelectSigningKey"/> see their
/// delegate invoked; applications that do not get the default behaviour from
/// <see cref="ClientRegistration.GetDefaultSigningKeyId"/>.
/// </remarks>
internal static class SigningKeySelection
{
    /// <summary>
    /// Resolves the <see cref="KeyId"/> to sign with for the given registration
    /// and usage context. Invokes the application-supplied
    /// <see cref="SelectSigningKeyDelegate"/> when one is configured, otherwise
    /// returns the first <see cref="KeyId"/> in
    /// <see cref="SigningKeySet.Current"/> for the given usage.
    /// </summary>
    /// <param name="server">The Authorization Server instance carrying the optional selection delegate.</param>
    /// <param name="registration">The client registration.</param>
    /// <param name="usage">The protocol usage context that identifies which signing key set to consult.</param>
    /// <param name="context">The per-request context bag.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The <see cref="KeyId"/> to sign with.</returns>
    public static ValueTask<KeyId> ResolveSigningKeyIdAsync(
        AuthorizationServer server,
        ClientRegistration registration,
        KeyUsageContext usage,
        IReadOnlyDictionary<string, object> context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        if(server.Cryptography.SelectSigningKey is not null)
        {
            return server.Cryptography.SelectSigningKey(registration, usage, context, cancellationToken);
        }

        return ValueTask.FromResult(registration.GetDefaultSigningKeyId(usage));
    }
}
