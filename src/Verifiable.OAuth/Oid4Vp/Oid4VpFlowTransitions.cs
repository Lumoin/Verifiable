using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Core.Automata;
using Verifiable.Core.Dcql;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp.States;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// The transition function for the OID4VP authorization flow PDA.
/// </summary>
/// <remarks>
/// <para>
/// The delegate returned by <see cref="Create"/> is <c>δ</c> in
/// <c>PushdownAutomaton&lt;OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol&gt;</c>.
/// It is a pure dispatch table: given the current state and input, it produces the next
/// state and stack action. No I/O, randomness, or time reads occur inside the transition
/// function. All effectful values arrive pre-computed inside the input records.
/// </para>
/// <para>
/// RFC 9700 invariants enforced structurally:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       Mix-up defense
///       (<see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC 9700 §4.4</see>):
///       <see cref="OAuthFlowState.ExpectedIssuer"/> is set at initiation and carried through
///       all states. The application layer constructing inputs must match any received
///       <c>iss</c> against this value before building the input.
///     </description>
///   </item>
///   <item>
///     <description>
///       PKCE downgrade defense
///       (<see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.8">RFC 9700 §4.8</see>):
///       <see cref="Verifiable.OAuth.Pkce.PkceParameters"/> is forwarded to
///       <see cref="ResponseReceived"/> so the token exchange step can confirm a
///       <c>code_challenge</c> was present before accepting a <c>code_verifier</c>.
///     </description>
///   </item>
///   <item>
///     <description>
///       Terminal state guard: transitions out of <see cref="PresentationVerified"/> or
///       <see cref="FlowFailed"/> return <see langword="null"/>, halting the PDA.
///     </description>
///   </item>
/// </list>
/// </remarks>
public static class Oid4VpFlowTransitions
{
    /// <summary>
    /// Creates the transition delegate for the OID4VP authorization flow PDA.
    /// </summary>
    /// <returns>
    /// A <see cref="TransitionDelegate{TState,TInput,TStackSymbol}"/> suitable for
    /// constructing a
    /// <c>PushdownAutomaton&lt;OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol&gt;</c>.
    /// </returns>
    public static TransitionDelegate<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> Create() =>
        static (state, input, stackTop, cancellationToken) =>
        {
            cancellationToken.ThrowIfCancellationRequested();

            TransitionResult<OAuthFlowState, Oid4VpStackSymbol>? result = (state, input) switch
            {
                //A Fail input is accepted from any non-terminal state.
                (not (PresentationVerified or FlowFailed), Fail fail) =>
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
                        StackAction<Oid4VpStackSymbol>.None,
                        "Fail"),

                //Initiate → PkceGenerated.
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
                        StackAction<Oid4VpStackSymbol>.None,
                        "Initiate"),

                //PkceGenerated + ParBodyComposed → ParRequestReady.
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
                        StackAction<Oid4VpStackSymbol>.None,
                        "BuildParRequest"),

                //ParRequestReady + ParSucceeded → ParCompleted (first DB sync point).
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
                            Par = par.Par,
                            Nonce = par.Nonce,
                            Query = par.Query,
                            EncryptionKeyPair = par.EncryptionKeyPair
                        },
                        StackAction<Oid4VpStackSymbol>.None,
                        "ParCompleted"),

                //ParCompleted + JarSigned → JarReady.
                (ParCompleted completed, JarSigned jar) =>
                    Transition(
                        new JarReady
                        {
                            FlowId = completed.FlowId,
                            ExpectedIssuer = completed.ExpectedIssuer,
                            EnteredAt = completed.EnteredAt,
                            ExpiresAt = completed.ExpiresAt,
                            Jar = jar.Jar,
                            Pkce = completed.Pkce,
                            Nonce = completed.Nonce,
                            EncryptionKeyPair = completed.EncryptionKeyPair
                        },
                        StackAction<Oid4VpStackSymbol>.None,
                        "JarReady"),

                //JarReady + JarFetched → JarServed.
                (JarReady jarReady, JarFetched fetched) =>
                    Transition(
                        new JarServed
                        {
                            FlowId = jarReady.FlowId,
                            ExpectedIssuer = jarReady.ExpectedIssuer,
                            EnteredAt = fetched.FetchedAt,
                            ExpiresAt = jarReady.ExpiresAt,
                            FetchedAt = fetched.FetchedAt,
                            Pkce = jarReady.Pkce,
                            Nonce = jarReady.Nonce,
                            EncryptionKeyPair = jarReady.EncryptionKeyPair
                        },
                        StackAction<Oid4VpStackSymbol>.None,
                        "JarServed"),

                //JarServed + ResponsePosted → ResponseReceived (second DB sync point).
                (JarServed served, ResponsePosted posted) =>
                    Transition(
                        new ResponseReceived
                        {
                            FlowId = served.FlowId,
                            ExpectedIssuer = served.ExpectedIssuer,
                            EnteredAt = posted.ReceivedAt,
                            ExpiresAt = served.ExpiresAt,
                            EncryptedResponseJwt = posted.EncryptedResponseJwt,
                            ReceivedAt = posted.ReceivedAt,
                            EncryptionKeyPair = served.EncryptionKeyPair,
                            Nonce = served.Nonce,
                            Pkce = served.Pkce
                        },
                        StackAction<Oid4VpStackSymbol>.None,
                        "ResponseReceived"),

                //ResponseReceived + VerificationSucceeded → PresentationVerified (terminal success).
                (ResponseReceived received, VerificationSucceeded verified) =>
                    Transition(
                        new PresentationVerified
                        {
                            FlowId = received.FlowId,
                            ExpectedIssuer = received.ExpectedIssuer,
                            EnteredAt = verified.VerifiedAt,
                            ExpiresAt = received.ExpiresAt,
                            Claims = verified.Claims,
                            VerifiedAt = verified.VerifiedAt
                        },
                        StackAction<Oid4VpStackSymbol>.None,
                        "PresentationVerified"),

                //Terminal states produce no transition; the PDA halts.
                (PresentationVerified, _) => null,
                (FlowFailed, _) => null,

                //Any other combination is undefined — the PDA halts.
                _ => null
            };

            return ValueTask.FromResult(result);
        };


    private static TransitionResult<OAuthFlowState, Oid4VpStackSymbol> Transition(
        OAuthFlowState nextState,
        StackAction<Oid4VpStackSymbol> stackAction,
        string label) =>
        new(nextState, stackAction, label);
}
