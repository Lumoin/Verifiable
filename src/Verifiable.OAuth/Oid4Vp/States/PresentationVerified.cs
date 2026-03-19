using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp.States;

/// <summary>
/// The direct_post.jwt has been decrypted and the vp_token verified successfully.
/// Terminal success state.
/// </summary>
/// <remarks>
/// No further transitions are defined from this state. The PDA halts when it enters here
/// and <c>PushdownAutomaton.IsAccepted</c> returns <see langword="true"/>.
/// </remarks>
[DebuggerDisplay("PresentationVerified FlowId={FlowId} VerifiedAt={VerifiedAt}")]
public sealed record PresentationVerified: OAuthFlowState
{
    /// <summary>
    /// The verified and extracted claims, keyed by DCQL credential query identifier.
    /// </summary>
    public required IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> Claims { get; init; }

    /// <summary>The UTC instant at which verification completed.</summary>
    public required DateTimeOffset VerifiedAt { get; init; }
}
