using System.Diagnostics;
using Verifiable.OAuth.Oid4Vp;

namespace Verifiable.OAuth.Oid4Vp.Wallet.States;

/// <summary>
/// The JAR JWT has been fetched from <c>request_uri</c> and its claims parsed into a
/// typed <see cref="AuthorizationRequestObject"/>. Structural and <c>typ</c> validation
/// has passed; signature verification is the caller's responsibility before producing
/// this input.
/// </summary>
/// <remarks>
/// <para>
/// Transitions to <see cref="DcqlEvaluated"/> after the DCQL query carried in
/// <see cref="Request"/> is evaluated against the held credentials.
/// </para>
/// <para>
/// The Wallet must verify the JAR signature against the Verifier's published key before
/// accepting any claims. Structural parsing and signature verification are deliberately
/// separated so the Wallet can reject unsigned or wrongly-signed JARs before touching
/// credential state.
/// </para>
/// </remarks>
[DebuggerDisplay("JarParsed FlowId={FlowId} ClientId={Request.ClientId}")]
public sealed record JarParsed: OAuthFlowState
{
    /// <summary>
    /// The typed Authorization Request Object parsed from the fetched JAR JWT.
    /// Contains the DCQL query, <c>response_uri</c>, nonce, and Verifier client metadata.
    /// </summary>
    public required AuthorizationRequestObject Request { get; init; }
}
