using System.Collections.Frozen;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cesr;

/// <summary>
/// The well-known CESR verification-key derivation codes — the codes whose primitive value is a public key
/// usable to verify a signature made by the corresponding private key — mapped to the crypto facts
/// (<see cref="CesrVerificationKeyInfo"/>) needed to verify that signature.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the CESR master code table, <see href="https://trustoverip.github.io/kswg-cesr-specification/#master-code-table-for-genusversion--_aaacaa-keriacdc-protocol-stack-version-200">
/// genus/version <c>-_AAACAA</c></see>. This is the algorithm-agility seam for KERI/CESR key resolution: a
/// forward-only data table from code to <see cref="CryptoAlgorithm"/> and wire <see cref="Tag"/>s, never a
/// switch, so new algorithms register here as the build gains the ability to verify their signatures. An
/// unmapped code fails closed.
/// </para>
/// </remarks>
public static class CesrVerificationKeyCodes
{
    /// <summary>The transferable Ed25519 public verification-key code (<c>D</c>).</summary>
    public static string Ed25519 { get; } = "D";

    /// <summary>The non-transferable (Ed25519N) public verification-key code (<c>B</c>).</summary>
    public static string Ed25519NonTransferable { get; } = "B";

    /// <summary>
    /// The CESR verification-key codes whose signatures the crypto layer can verify; more algorithms register
    /// here as they are supported.
    /// </summary>
    private static FrozenDictionary<string, CesrVerificationKeyInfo> Bindings { get; } = BuildBindings();


    /// <summary>
    /// Resolves a CESR verification-key derivation code to the crypto facts needed to verify a signature made
    /// by that key.
    /// </summary>
    /// <param name="code">The stable verification-key code, for example <c>D</c>.</param>
    /// <param name="info">The resolved crypto facts, when the code is known.</param>
    /// <returns><see langword="true"/> when the code names a supported verification key.</returns>
    public static bool TryGetVerificationKeyInfo(string code, [NotNullWhen(true)] out CesrVerificationKeyInfo? info)
    {
        ArgumentNullException.ThrowIfNull(code);

        return Bindings.TryGetValue(code, out info);
    }


    /// <summary>
    /// Whether the given stable code is a CESR verification-key derivation code with a registered crypto
    /// binding.
    /// </summary>
    /// <param name="code">The stable (hard) code.</param>
    /// <returns><see langword="true"/> when the code names a supported verification key.</returns>
    public static bool IsVerificationKeyCode(string code)
    {
        ArgumentNullException.ThrowIfNull(code);

        return Bindings.ContainsKey(code);
    }


    /// <summary>
    /// Builds the forward map from CESR verification-key derivation code to the crypto facts needed to verify
    /// a signature made by that key.
    /// </summary>
    /// <returns>The frozen code-to-binding map.</returns>
    private static FrozenDictionary<string, CesrVerificationKeyInfo> BuildBindings()
    {
        var bindings = new Dictionary<string, CesrVerificationKeyInfo>
        {
            //The CESR verification-key codes whose signatures the crypto layer can verify; more algorithms
            //(secp256k1/secp256r1, the NIST PQC family) register here as they are supported.
            [Ed25519] = new CesrVerificationKeyInfo(CryptoAlgorithm.Ed25519, CryptoTags.Ed25519PublicKey, CryptoTags.Ed25519Signature),
            [Ed25519NonTransferable] = new CesrVerificationKeyInfo(CryptoAlgorithm.Ed25519, CryptoTags.Ed25519PublicKey, CryptoTags.Ed25519Signature),
        };

        return bindings.ToFrozenDictionary();
    }
}
