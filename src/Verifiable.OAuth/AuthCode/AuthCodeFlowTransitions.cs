using System.Threading.Tasks;
using Verifiable.Core.Automata;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode.States;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// The transition function for the OAuth 2.0 Authorization Code flow PDA.
/// </summary>
/// <remarks>
/// <para>
/// The delegate returned by <see cref="Create"/> is <c>δ</c> in
/// <c>PushdownAutomaton&lt;OAuthFlowState, OAuthFlowInput, AuthCodeStackSymbol&gt;</c>.
/// It is a pure dispatch table: no I/O, randomness, or time reads occur inside the
/// transition function. All effectful values arrive pre-computed inside the input records.
/// </para>
/// <para>
/// Security invariants enforced structurally:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       Mix-up defense
///       (<see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC 9700 §4.4</see>):
///       the <see cref="CodeReceived.IssuerId"/> in the redirect must be validated against
///       <see cref="OAuthFlowState.ExpectedIssuer"/> by the caller before constructing
///       <see cref="CodeReceived"/>. The transition function carries the validated value
///       into <see cref="AuthorizationCodeReceived.IssuerId"/>.
///     </description>
///   </item>
///   <item>
///     <description>
///       PKCE downgrade defense
///       (<see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.8">RFC 9700 §4.8</see>):
///       <see cref="Verifiable.OAuth.Pkce.PkceParameters"/> is forwarded to
///       <see cref="AuthorizationCodeReceived"/> so the token exchange can confirm a
///       <c>code_challenge</c> was present in the original request.
///     </description>
///   </item>
/// </list>
/// </remarks>
public static class AuthCodeFlowTransitions
{
    /// <summary>
    /// Creates the transition delegate for the Authorization Code flow PDA.
    /// </summary>
    /// <returns>
    /// A <see cref="TransitionDelegate{TState,TInput,TStackSymbol}"/> suitable for
    /// constructing a
    /// <c>PushdownAutomaton&lt;OAuthFlowState, OAuthFlowInput, AuthCodeStackSymbol&gt;</c>.
    /// </returns>
    public static TransitionDelegate<OAuthFlowState, OAuthFlowInput, AuthCodeStackSymbol> Create() =>
        static (state, input, stackTop, cancellationToken) =>
        {
            cancellationToken.ThrowIfCancellationRequested();

            TransitionResult<OAuthFlowState, AuthCodeStackSymbol>? result = (state, input) switch
            {
                (not (TokenReceived or FlowFailed), Fail fail) =>
                    Transition(
                        new FlowFailed
                        {
                            FlowId = state.FlowId,
                            ExpectedIssuer = state.ExpectedIssuer,
                            EnteredAt = fail.FailedAt,
                            ExpiresAt = state.ExpiresAt,
                            Reason = fail.Reason,
                            FailedAt = fail.FailedAt
                        },
                        StackAction<AuthCodeStackSymbol>.None,
                        "Fail"),

                (_, Initiate init) =>
                    Transition(
                        new PkceGenerated
                        {
                            FlowId = init.FlowId,
                            ExpectedIssuer = init.ExpectedIssuer,
                            EnteredAt = init.InitiatedAt,
                            ExpiresAt = init.InitialExpiresAt,
                            Pkce = init.Pkce,
                            RedirectUri = init.RedirectUri,
                            Scopes = init.Scopes
                        },
                        StackAction<AuthCodeStackSymbol>.None,
                        "Initiate"),

                (PkceGenerated pkce, ParBodyComposed composed) =>
                    Transition(
                        new ParRequestReady
                        {
                            FlowId = pkce.FlowId,
                            ExpectedIssuer = pkce.ExpectedIssuer,
                            EnteredAt = composed.ComposedAt,
                            ExpiresAt = pkce.ExpiresAt,
                            Pkce = pkce.Pkce,
                            RedirectUri = pkce.RedirectUri,
                            Scopes = pkce.Scopes,
                            EncodedBody = composed.EncodedBody
                        },
                        StackAction<AuthCodeStackSymbol>.None,
                        "BuildParRequest"),

                (ParRequestReady ready, ParSucceeded par) =>
                    Transition(
                        new ParCompleted
                        {
                            FlowId = ready.FlowId,
                            ExpectedIssuer = ready.ExpectedIssuer,
                            EnteredAt = par.ReceivedAt,
                            ExpiresAt = par.ReceivedAt.AddSeconds(par.Par.ExpiresIn),
                            Pkce = ready.Pkce,
                            RedirectUri = ready.RedirectUri,
                            Scopes = ready.Scopes,
                            Par = par.Par
                        },
                        StackAction<AuthCodeStackSymbol>.None,
                        "ParCompleted"),

                (ParCompleted completed, CodeReceived code) =>
                    Transition(
                        new AuthorizationCodeReceived
                        {
                            FlowId = completed.FlowId,
                            ExpectedIssuer = completed.ExpectedIssuer,
                            EnteredAt = code.ReceivedAt,
                            ExpiresAt = completed.ExpiresAt,
                            Code = code.Code,
                            State = code.State,
                            IssuerId = code.IssuerId,
                            Pkce = completed.Pkce,
                            RedirectUri = completed.RedirectUri
                        },
                        StackAction<AuthCodeStackSymbol>.None,
                        "CodeReceived"),

                (AuthorizationCodeReceived codeState, TokenExchangeSucceeded token) =>
                    Transition(
                        new TokenReceived
                        {
                            FlowId = codeState.FlowId,
                            ExpectedIssuer = codeState.ExpectedIssuer,
                            EnteredAt = token.ReceivedAt,
                            ExpiresAt = codeState.ExpiresAt,
                            AccessToken = token.AccessToken,
                            TokenType = token.TokenType,
                            ExpiresIn = token.ExpiresIn,
                            RefreshToken = token.RefreshToken,
                            Scope = token.Scope,
                            ReceivedAt = token.ReceivedAt
                        },
                        StackAction<AuthCodeStackSymbol>.None,
                        "TokenReceived"),

                (TokenReceived, _) => null,
                (FlowFailed, _) => null,

                _ => null
            };

            return ValueTask.FromResult(result);
        };


    private static TransitionResult<OAuthFlowState, AuthCodeStackSymbol>? Transition(
        OAuthFlowState nextState,
        StackAction<AuthCodeStackSymbol> stackAction,
        string label) =>
        new(nextState, stackAction, label);
}
