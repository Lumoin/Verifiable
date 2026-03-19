using System.Diagnostics;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.OAuth.Oid4Vp;

namespace Verifiable.OAuth.Oid4Vp.Wallet.States;

/// <summary>
/// The DCQL query carried in the JAR has been evaluated against the Wallet's held
/// credentials. At least one satisfying match has been found.
/// </summary>
/// <remarks>
/// Transitions to <see cref="PresentationBuilt"/> after the Wallet (or the user, for
/// interactive flows) selects the minimum required disclosures from the matching
/// credential and assembles the VP token payload.
/// </remarks>
[DebuggerDisplay("DcqlEvaluated FlowId={FlowId} MatchCount={MatchedCredentialIds.Count}")]
public sealed record DcqlEvaluated: OAuthFlowState
{
    /// <summary>
    /// The Authorization Request that produced the DCQL query.
    /// Carried forward so <c>response_uri</c>, nonce, and client metadata remain
    /// accessible during presentation building and response encryption.
    /// </summary>
    public required AuthorizationRequestObject Request { get; init; }

    /// <summary>
    /// The prepared DCQL query, ready for disclosure strategy computation.
    /// </summary>
    public required PreparedDcqlQuery PreparedQuery { get; init; }

    /// <summary>
    /// The identifiers of held credentials that satisfy the DCQL query, keyed by
    /// DCQL credential query identifier. The Wallet uses this to retrieve the
    /// credential material for disclosure selection.
    /// </summary>
    public required IReadOnlyDictionary<string, string> MatchedCredentialIds { get; init; }
}
