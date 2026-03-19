using Verifiable.Core.Automata;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// The transition function for the server-side OID4VP Verifier flow PDA.
/// </summary>
/// <remarks>
/// <para>
/// Models the Verifier's HTTP endpoint sequence per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0</see>
/// and
/// <see href="https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html">HAIP 1.0</see>.
/// Each transition corresponds to one HTTP boundary crossing.
/// </para>
/// <para>
/// Transitions:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       Sentinel + <see cref="ServerParReceived"/> -> <see cref="VerifierParReceivedState"/>.
///       The PAR endpoint validated the request and returned <c>request_uri</c>.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="VerifierParReceivedState"/> + <see cref="ServerJarSigned"/> ->
///       <see cref="VerifierJarServedState"/>.
///       The JAR request endpoint signed and served the JAR.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="VerifierJarServedState"/> + <see cref="ResponsePosted"/> ->
///       <see cref="VerifierResponseReceivedState"/>.
///       The direct_post endpoint received the encrypted Authorization Response.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="VerifierResponseReceivedState"/> + <see cref="VerificationSucceeded"/> ->
///       <see cref="PresentationVerifiedState"/>. Terminal success.
///     </description>
///   </item>
///   <item>
///     <description>
///       Any non-terminal state + <see cref="Fail"/> -> <see cref="VerifierFlowFailedState"/>.
///       Terminal failure.
///     </description>
///   </item>
/// </list>
/// </remarks>
public static class Oid4VpVerifierFlowTransitions
{
    /// <summary>
    /// Creates the transition delegate for the server-side OID4VP Verifier flow PDA.
    /// </summary>
    public static TransitionDelegate<OAuthFlowState, OAuthFlowInput, Oid4VpVerifierStackSymbol> Create() =>
        static (state, input, stackTop, cancellationToken) =>
        {
            cancellationToken.ThrowIfCancellationRequested();

            TransitionResult<OAuthFlowState, Oid4VpVerifierStackSymbol>? result =
                (state, input) switch
                {
                    //Any non-terminal state + Fail -> VerifierFlowFailed.
                    (not (PresentationVerifiedState or VerifierFlowFailedState), Fail fail) =>
                        Transition(
                            new VerifierFlowFailedState
                            {
                                FlowId = state.FlowId,
                                ExpectedIssuer = state.ExpectedIssuer,
                                EnteredAt = fail.FailedAt,
                                ExpiresAt = state.ExpiresAt,
                                Kind = FlowKind.Oid4VpVerifierServer,
                                Reason = fail.Reason,
                                FailedAt = fail.FailedAt
                            },
                            StackAction<Oid4VpVerifierStackSymbol>.None,
                            "Fail"),

                    //Sentinel + ServerParReceived -> VerifierParReceived.
                    //The PAR endpoint validated the request and sent request_uri to the
                    //Wallet. JAR signing is deferred to the JAR request endpoint per
                    //OID4VP 1.0 §5.2.
                    (VerifierFlowFailedState { FlowId: "" }, ServerParReceived par) =>
                        Transition(
                            new VerifierParReceivedState
                            {
                                FlowId = par.FlowId,
                                ExpectedIssuer = state.ExpectedIssuer,
                                EnteredAt = par.ReceivedAt,
                                ExpiresAt = par.ReceivedAt.AddSeconds(par.Par.ExpiresIn),
                                Kind = FlowKind.Oid4VpVerifierServer,
                                Par = par.Par,
                                Nonce = par.Nonce,
                                Query = par.Query,
                                DecryptionKeyId = par.DecryptionKeyId,
                                SigningKeyId = par.SigningKeyId,
                                AllowedEncAlgorithms = par.AllowedEncAlgorithms
                            },
                            StackAction<Oid4VpVerifierStackSymbol>.None,
                            "VerifierParReceived"),

                    //VerifierParReceived + ServerJarSigned -> VerifierJarServed.
                    //The JAR request endpoint signed and served the JAR in a single
                    //HTTP request per OID4VP 1.0 §5.4.
                    (VerifierParReceivedState received, ServerJarSigned signed) =>
                        Transition(
                            new VerifierJarServedState
                            {
                                FlowId = received.FlowId,
                                ExpectedIssuer = received.ExpectedIssuer,
                                EnteredAt = signed.ServedAt,
                                ExpiresAt = received.ExpiresAt,
                                Kind = FlowKind.Oid4VpVerifierServer,
                                ServedAt = signed.ServedAt,
                                Nonce = received.Nonce,
                                DecryptionKeyId = received.DecryptionKeyId,
                                AllowedEncAlgorithms = received.AllowedEncAlgorithms
                            },
                            StackAction<Oid4VpVerifierStackSymbol>.None,
                            "VerifierJarServed"),

                    //VerifierJarServed + ResponsePosted -> VerifierResponseReceived.
                    //The Wallet POSTed the encrypted Authorization Response to /cb.
                    (VerifierJarServedState served, ResponsePosted posted) =>
                        Transition(
                            new VerifierResponseReceivedState
                            {
                                FlowId = served.FlowId,
                                ExpectedIssuer = served.ExpectedIssuer,
                                EnteredAt = posted.ReceivedAt,
                                ExpiresAt = served.ExpiresAt,
                                Kind = FlowKind.Oid4VpVerifierServer,
                                EncryptedResponseJwt = posted.EncryptedResponseJwt,
                                ReceivedAt = posted.ReceivedAt,
                                DecryptionKeyId = served.DecryptionKeyId,
                                Nonce = served.Nonce,
                                AllowedEncAlgorithms = served.AllowedEncAlgorithms
                            },
                            StackAction<Oid4VpVerifierStackSymbol>.None,
                            "VerifierResponseReceived"),

                    //VerifierResponseReceived + VerificationSucceeded -> PresentationVerified.
                    //Terminal success: VP token decrypted and verified per OID4VP 1.0 §8.2.
                    (VerifierResponseReceivedState received, VerificationSucceeded verified) =>
                        Transition(
                            new PresentationVerifiedState
                            {
                                FlowId = received.FlowId,
                                ExpectedIssuer = received.ExpectedIssuer,
                                EnteredAt = verified.VerifiedAt,
                                ExpiresAt = received.ExpiresAt,
                                Kind = FlowKind.Oid4VpVerifierServer,
                                Claims = verified.Claims,
                                VerifiedAt = verified.VerifiedAt,
                                RedirectUri = verified.RedirectUri
                            },
                            StackAction<Oid4VpVerifierStackSymbol>.None,
                            "PresentationVerified"),

                    //Terminal states — PDA halts.
                    (PresentationVerifiedState, _) => null,
                    (VerifierFlowFailedState, _) => null,

                    _ => null
                };

            return ValueTask.FromResult<TransitionResult<OAuthFlowState, Oid4VpVerifierStackSymbol>?>(result);
        };


    private static TransitionResult<OAuthFlowState, Oid4VpVerifierStackSymbol> Transition(
        OAuthFlowState nextState,
        StackAction<Oid4VpVerifierStackSymbol> stackAction,
        string label) =>
        new(nextState, stackAction, label);
}
