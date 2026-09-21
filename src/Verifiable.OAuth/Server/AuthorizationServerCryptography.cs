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
public sealed class AuthorizationServerCryptography: WiringComponent
{
    /// <summary>
    /// Resolves a private signing key by identifier. Required.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ServerSigningKeyResolverDelegate? SigningKeyResolver
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Resolves a private decryption key by identifier. Required when
    /// <see cref="WellKnownCapabilityIdentifiers.VcVerifiablePresentation"/> is enabled
    /// for any registration, otherwise optional.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ServerDecryptionKeyResolverDelegate? DecryptionKeyResolver
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Resolves a public verification key by identifier. Required.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ServerVerificationKeyResolverDelegate? VerificationKeyResolver
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Selects which <see cref="Verifiable.Cryptography.KeyId"/> to sign with at a given library call site.
    /// Optional. When <see langword="null"/>, the library calls
    /// <see cref="ClientRecord.GetDefaultSigningKeyId"/> which returns the
    /// first entry in the registration's <c>SigningKeys[usage].Current</c> list.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Applications set this delegate to implement per-caller key binding,
    /// algorithm-specific selection across multi-algorithm deployments, or any
    /// other selection policy that depends on request context. The delegate
    /// receives the full per-request context bag so it can read caller identity,
    /// tenant-scoped attributes, and whatever else the skin chose to surface.
    /// </para>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// </remarks>
    public SelectSigningKeyDelegate? SelectSigningKey
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Builds the <see cref="Verifiable.JCose.JwksDocument"/> to serve at the JWKS endpoint.
    /// Required when <see cref="WellKnownCapabilityIdentifiers.OAuthJwksEndpoint"/> is enabled
    /// for any registration, otherwise optional.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The implementation receives the resolved <see cref="ClientRecord"/>
    /// and the per-request context bag, and decides which keys to include —
    /// typically all active signing keys for the registration, including keys
    /// in a rotation grace period. The library never prescribes which keys to
    /// include.
    /// </para>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// </remarks>
    public BuildJwksDocumentDelegate? BuildJwksDocumentAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Validates that the required delegates on this group are set.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when one or more required delegates are missing.
    /// </exception>
    public void Validate()
    {
        IsValidated = false;
        var missing = new List<string>();

        if(SigningKeyResolver is null) { missing.Add(nameof(SigningKeyResolver)); }
        if(VerificationKeyResolver is null) { missing.Add(nameof(VerificationKeyResolver)); }

        if(missing.Count > 0)
        {
            var sb = new StringBuilder(
                "AuthorizationServerCryptography is missing required delegates: ");
            _ = sb.AppendJoin(", ", missing);
            _ = sb.Append('.');
            throw new InvalidOperationException(sb.ToString());
        }

        IsValidated = true;
    }
}
