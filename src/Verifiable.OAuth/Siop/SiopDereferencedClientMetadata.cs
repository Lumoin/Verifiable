using System.Diagnostics;

namespace Verifiable.OAuth.Siop;

/// <summary>
/// The result of dereferencing a Relying Party's <c>client_metadata_uri</c> (§7.3),
/// supplied to <see cref="SiopRequestValidation.Validate"/> as data so the Self-Issued OP
/// performs the network act outside the transport-agnostic library, per
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-10.3">SIOPv2 §10.3</see>.
/// </summary>
/// <remarks>
/// §10.3 <c>invalid_client_metadata_uri</c>: "the <c>client_metadata_uri</c> in the
/// Authorization Request returns an error or contains invalid data." That failure — the
/// fetch erroring, or the body not parsing into a valid RP parameter Object — is conveyed
/// by <see cref="IsResolved"/> being <see langword="false"/>, since this primitive never
/// dereferences the URI itself.
/// </remarks>
[DebuggerDisplay("SiopDereferencedClientMetadata IsResolved={IsResolved}")]
public sealed record SiopDereferencedClientMetadata
{
    /// <summary>
    /// Whether dereferencing <c>client_metadata_uri</c> succeeded and yielded a valid RP
    /// parameter Object. <see langword="false"/> when the fetch returned an error or the
    /// body was invalid (§10.3 <c>invalid_client_metadata_uri</c>), in which case
    /// <see cref="Metadata"/> is <see langword="null"/>.
    /// </summary>
    public required bool IsResolved { get; init; }

    /// <summary>
    /// The RP metadata parsed from the <c>client_metadata_uri</c> body when
    /// <see cref="IsResolved"/> is <see langword="true"/>; <see langword="null"/> when the
    /// dereference failed.
    /// </summary>
    public SiopRelyingPartyMetadata? Metadata { get; init; }


    /// <summary>
    /// A dereference that succeeded with the given RP metadata.
    /// </summary>
    /// <param name="metadata">The RP metadata parsed from the dereferenced body.</param>
    /// <returns>A resolved dereference outcome.</returns>
    public static SiopDereferencedClientMetadata Resolved(SiopRelyingPartyMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        return new SiopDereferencedClientMetadata
        {
            IsResolved = true,
            Metadata = metadata
        };
    }


    /// <summary>
    /// A dereference that failed — the fetch errored or the body was invalid (§10.3
    /// <c>invalid_client_metadata_uri</c>).
    /// </summary>
    /// <returns>A failed dereference outcome.</returns>
    public static SiopDereferencedClientMetadata Failed()
    {
        return new SiopDereferencedClientMetadata
        {
            IsResolved = false
        };
    }
}
