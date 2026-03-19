using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.OAuth.Pkce;

namespace Verifiable.OAuth.Oid4Vp.States;

/// <summary>
/// The JAR has been fetched. The flow is waiting for the <c>direct_post.jwt</c>
/// authorization response.
/// </summary>
/// <remarks>
/// Transitions to <see cref="ResponseReceivedState"/> when the authorization response is posted.
/// </remarks>
[DebuggerDisplay("JarServed FlowId={FlowId} FetchedAt={FetchedAt}")]
public sealed record JarServedState: OAuthFlowState
{
    /// <summary>The UTC instant at which the JAR was first fetched.</summary>
    public required DateTimeOffset FetchedAt { get; init; }

    /// <summary>Carried forward from <see cref="JarReadyState"/>.</summary>
    public required PkceParameters Pkce { get; init; }

    /// <summary>Carried forward from <see cref="JarReadyState"/>.</summary>
    public required TransactionNonce Nonce { get; init; }

    /// <summary>Carried forward from <see cref="JarReadyState"/>.</summary>
    public required KeyId DecryptionKeyId { get; init; }
}
