using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.OAuth;
using Verifiable.Tests.OAuth;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Gives a registration distinct access-token and ID Token issuance keys, so a test can tell the two
/// usages apart: the key it signs one kind of token under is then a key the registration lists for
/// the other kind only.
/// </summary>
/// <remarks>
/// <see cref="TestHostShell.RegisterDpopClientAsync"/> lists one signing key under both
/// <see cref="KeyUsageContext.AccessTokenIssuance"/> and <see cref="KeyUsageContext.IdTokenIssuance"/>.
/// This helper allocates a fresh key through <see cref="TestHostShell.AllocateSigningKey"/> and lists it
/// as the current ID Token key through <see cref="TestHostShell.UpdateSigningKeysAsync"/>, leaving the
/// access-token set (<see cref="VerifierKeyMaterial.SigningKeyId"/>) as it was.
/// </remarks>
internal static class IssuanceKeySeparation
{
    /// <summary>
    /// Lists a freshly allocated key as the registration's only ID Token issuance key, keeping every
    /// other usage's set.
    /// </summary>
    /// <param name="host">The host holding the registration and its key stores.</param>
    /// <param name="material">The registration whose ID Token key is separated.</param>
    /// <returns>The identifier of the registration's ID Token key.</returns>
    public static async Task<KeyId> SeparateIdTokenKeyAsync(TestHostShell host, VerifierKeyMaterial material)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(material);

        KeyId idTokenKeyId = host.AllocateSigningKey();
        Dictionary<KeyUsageContext, SigningKeySet> signingKeys = new(material.Registration.SigningKeys)
        {
            [KeyUsageContext.IdTokenIssuance] = new SigningKeySet { Current = [idTokenKeyId] }
        };
        await host.UpdateSigningKeysAsync(material.Registration.TenantId.Value, signingKeys).ConfigureAwait(false);

        return idTokenKeyId;
    }
}
