using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp.States;

/// <summary>
/// The <c>direct_post.jwt</c> has been decrypted and the vp_token verified successfully.
/// Terminal success state.
/// </summary>
/// <remarks>
/// <para>
/// No further transitions are defined from this state. The PDA halts when it enters here
/// and <c>PushdownAutomaton.IsAccepted</c> returns <see langword="true"/>.
/// </para>
/// <para>
/// In the same-device flow the Verifier's HTTP response to the Wallet's POST must include
/// a <c>redirect_uri</c> JSON field per OID4VP 1.0 §8.2. The application reads
/// <see cref="RedirectUri"/> from this state and writes it into the HTTP 200 response body
/// so the Wallet can follow the redirect to resume the user's browser session.
/// In the cross-device flow <see cref="RedirectUri"/> is <see langword="null"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("PresentationVerified FlowId={FlowId} VerifiedAt={VerifiedAt}")]
public sealed record PresentationVerifiedState: OAuthFlowState
{
    /// <summary>
    /// The verified and extracted claims, keyed by DCQL credential query identifier.
    /// </summary>
    public required IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> Claims { get; init; }

    /// <summary>The UTC instant at which verification completed.</summary>
    public required DateTimeOffset VerifiedAt { get; init; }

    /// <summary>
    /// The URI to which the Wallet should redirect the user's browser session after
    /// POSTing the Authorization Response, per OID4VP 1.0 §8.2. Present in the
    /// same-device flow only; <see langword="null"/> in the cross-device flow.
    /// </summary>
    /// <remarks>
    /// The application reads this value from the verified state and writes it into the
    /// HTTP 200 response body as <c>{"redirect_uri":"..."}</c>. The Wallet receives this
    /// URI in the POST response body, feeds a <c>RedirectReceived</c> input to its PDA,
    /// and follows the redirect.
    /// </remarks>
    public Uri? RedirectUri { get; init; }
}
