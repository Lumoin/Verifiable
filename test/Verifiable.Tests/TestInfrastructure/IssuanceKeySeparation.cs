using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.OAuth;
using Verifiable.Tests.OAuth;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Lists a freshly allocated key under one of a registration's key usages, so a test can tell the
/// usages apart: the key it signs one kind of token under is then a key the registration lists for
/// another usage only.
/// </summary>
/// <remarks>
/// <see cref="TestHostShell.RegisterDpopClientAsync"/> lists one signing key under both
/// <see cref="KeyUsageContext.AccessTokenIssuance"/> and <see cref="KeyUsageContext.IdTokenIssuance"/>.
/// This helper allocates a fresh key through <see cref="TestHostShell.AllocateSigningKey"/> and lists it
/// as the current key of the named usage through <see cref="TestHostShell.UpdateSigningKeysAsync"/>,
/// leaving every other usage's set (the access-token set <see cref="VerifierKeyMaterial.SigningKeyId"/>
/// among them) as it was.
/// </remarks>
internal static class IssuanceKeySeparation
{
    /// <summary>
    /// Lists a freshly allocated key as the registration's only key of <paramref name="usage"/>,
    /// keeping every other usage's set.
    /// </summary>
    /// <param name="host">The host holding the registration and its key stores.</param>
    /// <param name="material">The registration whose key set is extended.</param>
    /// <param name="usage">The usage the fresh key is listed under.</param>
    /// <returns>The identifier of the key now listed for <paramref name="usage"/>.</returns>
    public static async Task<KeyId> ListFreshKeyAsync(TestHostShell host, VerifierKeyMaterial material, KeyUsageContext usage)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(material);

        KeyId freshKeyId = host.AllocateSigningKey();
        Dictionary<KeyUsageContext, SigningKeySet> signingKeys = new(material.Registration.SigningKeys)
        {
            [usage] = new SigningKeySet { Current = [freshKeyId] }
        };
        await host.UpdateSigningKeysAsync(material.Registration.TenantId.Value, signingKeys).ConfigureAwait(false);

        return freshKeyId;
    }
}
