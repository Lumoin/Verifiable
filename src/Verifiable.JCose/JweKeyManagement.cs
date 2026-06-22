namespace Verifiable.JCose;

/// <summary>
/// Shared resolution of key-management facts from the <see cref="JweAlgorithm"/> descriptor,
/// used by the General JSON encrypt and decrypt orchestration so neither re-derives the key
/// encryption key length from the <c>alg</c> string.
/// </summary>
internal static class JweKeyManagement
{
    /// <summary>
    /// Returns the key encryption key length in bits for a Key Agreement with Key Wrapping
    /// algorithm, read from its <see cref="JweAlgorithm"/> descriptor.
    /// </summary>
    /// <param name="keyManagementAlgorithm">The wire <c>alg</c> value.</param>
    /// <returns>The KEK length in bits (128, 192, or 256).</returns>
    /// <exception cref="FormatException">
    /// Thrown when <paramref name="keyManagementAlgorithm"/> is not a Key Agreement with Key
    /// Wrapping algorithm this library implements.
    /// </exception>
    public static int RequireKeyWrapBits(string keyManagementAlgorithm)
    {
        JweAlgorithm? descriptor = JweAlgorithm.FromWellKnownName(keyManagementAlgorithm);
        if(descriptor is null || descriptor.Value.Mode != JweKeyManagementMode.KeyAgreementWithKeyWrapping)
        {
            throw new FormatException(
                $"Key management algorithm '{keyManagementAlgorithm}' is not a Key Agreement with " +
                "Key Wrapping algorithm.");
        }

        return descriptor.Value.KeyWrapBits;
    }
}
