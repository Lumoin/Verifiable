using Verifiable.Core.Automata;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// The transition function for the OID4VP authorization flow PDA.
/// </summary>
/// <remarks>
/// <para>
/// The delegate returned by <see cref="Create"/> is <c>δ</c> in
/// <c>PushdownAutomaton&lt;OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol&gt;</c>.
/// It is a pure dispatch table: no I/O, randomness, or time reads occur inside the
/// transition function. All effectful values arrive pre-computed inside the input records.
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
///       all states.
///     </description>
///   </item>
///   <item>
///     <description>
///       PKCE downgrade defense
///       (<see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.8">RFC 9700 §4.8</see>):
///       <see cref="Verifiable.OAuth.Pkce.PkceParameters"/> is forwarded to
///       <see cref="ResponseReceivedState"/>.
///     </description>
///   </item>
///   <item>
///     <description>
///       Terminal state guard: transitions out of <see cref="PresentationVerifiedState"/> or
///       <see cref="FlowFailed"/> return <see langword="null"/>, halting the PDA.
///     </description>
///   </item>
/// </list>
/// </remarks>
public static class Oid4VpFlowTransitions
{
    /// <summary>Creates the transition delegate for the OID4VP authorization flow PDA.</summary>
    public static TransitionDelegate<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> Create() =>
        static (state, input, stackTop, cancellationToken) =>
        {
            cancellationToken.ThrowIfCancellationRequested();

            TransitionResult<OAuthFlowState, Oid4VpStackSymbol>? result = (state, input) switch
            {
                (not (PresentationVerifiedState or FlowFailed), Fail fail) =>
                    Transition(
                        new FlowFailed
                        {
                            FlowId = state.FlowId,
                            ExpectedIssuer = state.ExpectedIssuer,
                            EnteredAt = fail.FailedAt,
                            ExpiresAt = state.ExpiresAt,
                            Kind = FlowKind.Oid4VpVerifier,
                            Reason = fail.Reason,
                            FailedAt = fail.FailedAt
                        },
                        StackAction<Oid4VpStackSymbol>.None,
                        "Fail"),

                (_, Initiate init) =>
                    Transition(
                        new PkceGeneratedState
                        {
                            FlowId = init.FlowId,
                            ExpectedIssuer = init.ExpectedIssuer,
                            EnteredAt = init.InitiatedAt,
                            ExpiresAt = init.InitialExpiresAt,
                            Kind = FlowKind.Oid4VpVerifier,
                            Pkce = init.Pkce,
                            RedirectUri = init.RedirectUri,
                            Scopes = init.Scopes
                        },
                        StackAction<Oid4VpStackSymbol>.None,
                        "Initiate"),

                (PkceGeneratedState pkce, ParBodyComposed composed) =>
                    Transition(
                        new ParRequestReadyState
                        {
                            FlowId = pkce.FlowId,
                            ExpectedIssuer = pkce.ExpectedIssuer,
                            EnteredAt = composed.ComposedAt,
                            ExpiresAt = pkce.ExpiresAt,
                            Kind = FlowKind.Oid4VpVerifier,
                            Pkce = pkce.Pkce,
                            RedirectUri = pkce.RedirectUri,
                            Scopes = pkce.Scopes,
                            EncodedBody = composed.EncodedBody
                        },
                        StackAction<Oid4VpStackSymbol>.None,
                        "BuildParRequest"),

                (ParRequestReadyState ready, ParSucceeded par) =>
                    Transition(
                        new Oid4Vp.States.ParCompletedState
                        {
                            FlowId = ready.FlowId,
                            ExpectedIssuer = ready.ExpectedIssuer,
                            EnteredAt = par.ReceivedAt,
                            ExpiresAt = par.ReceivedAt.AddSeconds(par.Par.ExpiresIn),
                            Kind = FlowKind.Oid4VpVerifier,
                            Pkce = ready.Pkce,
                            RedirectUri = ready.RedirectUri,
                            Scopes = ready.Scopes,
                            Par = par.Par,
                            Nonce = par.Nonce,
                            Query = par.Query,
                            DecryptionKeyId = par.DecryptionKeyId
                        },
                        StackAction<Oid4VpStackSymbol>.None,
                        "ParCompleted"),

                (Oid4Vp.States.ParCompletedState completed, JarSigned jar) =>
                    Transition(
                        new JarReadyState
                        {
                            FlowId = completed.FlowId,
                            ExpectedIssuer = completed.ExpectedIssuer,
                            EnteredAt = completed.EnteredAt,
                            ExpiresAt = completed.ExpiresAt,
                            Kind = FlowKind.Oid4VpVerifier,
                            Jar = jar.Jar,
                            Pkce = completed.Pkce,
                            Nonce = completed.Nonce,
                            DecryptionKeyId = completed.DecryptionKeyId
                        },
                        StackAction<Oid4VpStackSymbol>.None,
                        "JarReady"),

                (JarReadyState jarReady, JarFetched fetched) =>
                    Transition(
                        new JarServedState
                        {
                            FlowId = jarReady.FlowId,
                            ExpectedIssuer = jarReady.ExpectedIssuer,
                            EnteredAt = fetched.FetchedAt,
                            ExpiresAt = jarReady.ExpiresAt,
                            Kind = FlowKind.Oid4VpVerifier,
                            FetchedAt = fetched.FetchedAt,
                            Pkce = jarReady.Pkce,
                            Nonce = jarReady.Nonce,
                            DecryptionKeyId = jarReady.DecryptionKeyId
                        },
                        StackAction<Oid4VpStackSymbol>.None,
                        "JarServed"),

                (JarServedState served, ResponsePosted posted) =>
                    Transition(
                        new ResponseReceivedState
                        {
                            FlowId = served.FlowId,
                            ExpectedIssuer = served.ExpectedIssuer,
                            EnteredAt = posted.ReceivedAt,
                            ExpiresAt = served.ExpiresAt,
                            Kind = FlowKind.Oid4VpVerifier,
                            EncryptedResponseJwt = posted.EncryptedResponseJwt,
                            ReceivedAt = posted.ReceivedAt,
                            DecryptionKeyId = served.DecryptionKeyId,
                            Nonce = served.Nonce,
                            Pkce = served.Pkce
                        },
                        StackAction<Oid4VpStackSymbol>.None,
                        "ResponseReceived"),

                (ResponseReceivedState received, VerificationSucceeded verified) =>
                    Transition(
                        new PresentationVerifiedState
                        {
                            FlowId = received.FlowId,
                            ExpectedIssuer = received.ExpectedIssuer,
                            EnteredAt = verified.VerifiedAt,
                            ExpiresAt = received.ExpiresAt,
                            Kind = FlowKind.Oid4VpVerifier,
                            Claims = verified.Claims,
                            VerifiedAt = verified.VerifiedAt,
                            RedirectUri = verified.RedirectUri
                        },
                        StackAction<Oid4VpStackSymbol>.None,
                        "PresentationVerified"),

                (PresentationVerifiedState, _) => null,
                (FlowFailed, _) => null,
                _ => null
            };

            return ValueTask.FromResult<TransitionResult<OAuthFlowState, Oid4VpStackSymbol>?>(result);
        };


    private static TransitionResult<OAuthFlowState, Oid4VpStackSymbol> Transition(
        OAuthFlowState nextState,
        StackAction<Oid4VpStackSymbol> stackAction,
        string label) =>
        new(nextState, stackAction, label);
}
