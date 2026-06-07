using System.Diagnostics;
using System.Text;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Groups the cryptographic-material delegates by which the Authorization Server
/// resolves private keys for signing and decryption, public keys for verification,
/// and assembles the JWKS document.
/// </summary>
/// <remarks>
/// <para>
/// The library never owns key material directly. All keys are resolved on demand
/// through the delegates on this group, which read from whatever store the
/// application maintains — an in-memory dictionary, a database, a hardware
/// security module, a TPM, or a cloud KMS.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthorizationServerCryptography Validated={IsValidated}")]
public sealed class AuthorizationServerCryptography
{
    /// <summary>
    /// Resolves a private signing key by identifier. Required.
    /// </summary>
    public ServerSigningKeyResolverDelegate? SigningKeyResolver { get; set; }

    /// <summary>
    /// Resolves a private decryption key by identifier. Required when
    /// <see cref="WellKnownCapabilityIdentifiers.VcVerifiablePresentation"/> is enabled
    /// for any registration, otherwise optional.
    /// </summary>
    public ServerDecryptionKeyResolverDelegate? DecryptionKeyResolver { get; set; }

    /// <summary>
    /// Resolves a public verification key by identifier. Required.
    /// </summary>
    public ServerVerificationKeyResolverDelegate? VerificationKeyResolver { get; set; }

    /// <summary>
    /// Selects which <see cref="KeyId"/> to sign with at a given library call site.
    /// Optional. When <see langword="null"/>, the library calls
    /// <see cref="ClientRecord.GetDefaultSigningKeyId"/> which returns the
    /// first entry in the registration's <c>SigningKeys[usage].Current</c> list.
    /// </summary>
    /// <remarks>
    /// Applications set this delegate to implement per-caller key binding,
    /// algorithm-specific selection across multi-algorithm deployments, or any
    /// other selection policy that depends on request context. The delegate
    /// receives the full per-request context bag so it can read caller identity,
    /// tenant-scoped attributes, and whatever else the skin chose to surface.
    /// </remarks>
    public SelectSigningKeyDelegate? SelectSigningKey { get; set; }

    /// <summary>
    /// Builds the <see cref="JwksDocument"/> to serve at the JWKS endpoint.
    /// Required when <see cref="WellKnownCapabilityIdentifiers.OAuthJwksEndpoint"/> is enabled
    /// for any registration, otherwise optional.
    /// </summary>
    /// <remarks>
    /// The implementation receives the resolved <see cref="ClientRecord"/>
    /// and the per-request context bag, and decides which keys to include —
    /// typically all active signing keys for the registration, including keys
    /// in a rotation grace period. The library never prescribes which keys to
    /// include.
    /// </remarks>
    public BuildJwksDocumentDelegate? BuildJwksDocumentAsync { get; set; }


    /// <summary>
    /// Whether <see cref="Validate"/> has been called successfully on this group.
    /// </summary>
    public bool IsValidated { get; private set; }


    /// <summary>
    /// Validates that the required delegates on this group are set.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when one or more required delegates are missing.
    /// </exception>
    public void Validate()
    {
        var missing = new List<string>();

        if(SigningKeyResolver is null) { missing.Add(nameof(SigningKeyResolver)); }
        if(VerificationKeyResolver is null) { missing.Add(nameof(VerificationKeyResolver)); }

        if(missing.Count > 0)
        {
            var sb = new StringBuilder(
                "AuthorizationServerCryptography is missing required delegates: ");
            sb.AppendJoin(", ", missing);
            sb.Append('.');
            throw new InvalidOperationException(sb.ToString());
        }

        IsValidated = true;
    }
}
