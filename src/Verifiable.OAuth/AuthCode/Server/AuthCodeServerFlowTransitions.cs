using Verifiable.Core.Automata;
using Verifiable.OAuth.AuthCode.Server.States;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.AuthCode.Server;

/// <summary>
/// The transition function for the server-side Authorization Code flow PDA.
/// </summary>
/// <remarks>
/// <para>
/// The delegate returned by <see cref="Create"/> is the <c>δ</c> function in
/// <c>PushdownAutomaton&lt;OAuthFlowState, OAuthFlowInput, AuthCodeServerStackSymbol&gt;</c>.
/// It is a pure dispatch table — no I/O, no randomness, no time reads occur here.
/// All effectful values arrive pre-computed inside the input records.
/// </para>
/// <para>
/// Security invariants enforced structurally:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       PKCE downgrade defense
///       (<see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.8">RFC 9700 §4.8</see>):
///       <see cref="ParRequestReceivedState.CodeChallenge"/> is carried forward to
///       <see cref="ServerCodeIssuedState"/> so the token endpoint handler can verify
///       <c>SHA256(code_verifier) == CodeChallenge</c> before constructing
///       <see cref="ServerTokenExchangeSucceeded"/>.
///     </description>
///   </item>
///   <item>
///     <description>
///       Token bytes never stored: <see cref="ServerTokenIssuedState"/> carries only
///       per-token audit metadata in
///       <see cref="ServerTokenIssuedState.IssuedTokens"/> — the signed token
///       compact JWS strings are returned to the client in the HTTP response and
///       never enter the PDA state.
///     </description>
///   </item>
///   <item>
///     <description>
///       Terminal state guard: transitions out of <see cref="ServerTokenIssuedState"/>
///       or <see cref="ServerFlowFailedState"/> return <see langword="null"/>, halting the PDA.
///     </description>
///   </item>
/// </list>
/// </remarks>
public static class AuthCodeServerFlowTransitions
{
    /// <summary>Creates the transition delegate for the server-side Authorization Code flow PDA.</summary>
    public static TransitionDelegate<OAuthFlowState, OAuthFlowInput, AuthCodeServerStackSymbol> Create() =>
        static (state, input, stackTop, cancellationToken) =>
        {
            cancellationToken.ThrowIfCancellationRequested();

            TransitionResult<OAuthFlowState, AuthCodeServerStackSymbol>? result =
                (state, input) switch
                {
                    //ServerFail is accepted from any non-terminal state.
                    (not (ServerTokenIssuedState or ServerFlowFailedState), ServerFail fail) =>
                        Transition(
                            new ServerFlowFailedState
                            {
                                FlowId = state.FlowId,
                                ExpectedIssuer = state.ExpectedIssuer,
                                EnteredAt = fail.FailedAt,
                                ExpiresAt = state.ExpiresAt,
                                Kind = FlowKind.AuthCodeServer,
                                ErrorCode = fail.ErrorCode,
                                Reason = fail.Reason,
                                FailedAt = fail.FailedAt
                            },
                            StackAction<AuthCodeServerStackSymbol>.None,
                            "Fail"),

                    //Initial sentinel + ServerParValidated → ParRequestReceived.
                    (ServerFlowFailedState { FlowId: "" }, ServerParValidated par) =>
                        Transition(
                            new ParRequestReceivedState
                            {
                                FlowId = par.FlowId,
                                ExpectedIssuer = par.ExpectedIssuer,
                                EnteredAt = par.ReceivedAt,
                                ExpiresAt = par.ExpiresAt,
                                Kind = FlowKind.AuthCodeServer,
                                RequestUri = par.RequestUri,
                                CodeChallenge = par.CodeChallenge,
                                RedirectUri = par.RedirectUri,
                                Scope = par.Scope,
                                ClientId = par.ClientId,
                                Nonce = par.Nonce
                            },
                            StackAction<AuthCodeServerStackSymbol>.None,
                            "ParRequestReceived"),

                    //Initial sentinel + ServerDirectAuthorizeCompleted → ServerCodeIssued.
                    //Direct authorization completes in one step — the subject is already
                    //authenticated when the authorize request arrives.
                    (ServerFlowFailedState { FlowId: "" }, ServerDirectAuthorizeCompleted direct) =>
                        Transition(
                            new ServerCodeIssuedState
                            {
                                FlowId = direct.FlowId,
                                ExpectedIssuer = direct.ExpectedIssuer,
                                EnteredAt = direct.CompletedAt,
                                ExpiresAt = direct.ExpiresAt,
                                Kind = FlowKind.AuthCodeServer,
                                CodeHash = direct.CodeHash,
                                RedirectUri = direct.RedirectUri,
                                CodeChallenge = direct.CodeChallenge,
                                Scope = direct.Scope,
                                SubjectId = direct.SubjectId,
                                AuthTime = direct.AuthTime,
                                ClientId = direct.ClientId,
                                Nonce = direct.Nonce
                            },
                            StackAction<AuthCodeServerStackSymbol>.None,
                            "ServerCodeIssued"),

                    //ParRequestReceived + ServerAuthorizeCompleted → ServerCodeIssued.
                    (ParRequestReceivedState received, ServerAuthorizeCompleted auth) =>
                        Transition(
                            new ServerCodeIssuedState
                            {
                                FlowId = received.FlowId,
                                ExpectedIssuer = received.ExpectedIssuer,
                                EnteredAt = auth.CompletedAt,
                                ExpiresAt = received.ExpiresAt,
                                Kind = FlowKind.AuthCodeServer,
                                CodeHash = auth.CodeHash,
                                RedirectUri = received.RedirectUri,
                                CodeChallenge = received.CodeChallenge,
                                Scope = auth.Scope,
                                SubjectId = auth.SubjectId,
                                AuthTime = auth.AuthTime,
                                ClientId = received.ClientId,
                                Nonce = received.Nonce
                            },
                            StackAction<AuthCodeServerStackSymbol>.None,
                            "ServerCodeIssued"),

                    //ServerCodeIssued + ServerTokenExchangeSucceeded → ServerTokenIssued.
                    //The token exchange input carries the per-token audit set and the
                    //response-wide IssuedAt and ExpiresAt timestamps the endpoint
                    //computed before composing the response.
                    (ServerCodeIssuedState issued, ServerTokenExchangeSucceeded token) =>
                        Transition(
                            new ServerTokenIssuedState
                            {
                                FlowId = issued.FlowId,
                                ExpectedIssuer = issued.ExpectedIssuer,
                                EnteredAt = token.IssuedAt,
                                ExpiresAt = token.ExpiresAt,
                                Kind = FlowKind.AuthCodeServer,
                                IssuedTokens = token.IssuedTokens,
                                SubjectId = issued.SubjectId,
                                Scope = issued.Scope,
                                IssuedAt = token.IssuedAt
                            },
                            StackAction<AuthCodeServerStackSymbol>.None,
                            "ServerTokenIssued"),

                    //Terminal states produce no transition — the PDA halts.
                    (ServerTokenIssuedState, _) => null,
                    (ServerFlowFailedState, _) => null,

                    //Any other combination is undefined — the PDA halts.
                    _ => null
                };

            return ValueTask.FromResult<TransitionResult<OAuthFlowState, AuthCodeServerStackSymbol>?>(result);
        };


    private static TransitionResult<OAuthFlowState, AuthCodeServerStackSymbol> Transition(
        OAuthFlowState nextState,
        StackAction<AuthCodeServerStackSymbol> stackAction,
        string label) =>
        new(nextState, stackAction, label);
}
