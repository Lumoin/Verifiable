using System.Threading.Tasks;
using Verifiable.Foundation.Automata;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Oid4Vp.Wallet.States;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// The transition function for the Wallet-side OID4VP presentation flow PDA.
/// </summary>
/// <remarks>
/// <para>
/// The delegate returned by <see cref="Create"/> is <c>δ</c> in
/// <c>PushdownAutomaton&lt;FlowState, FlowInput, WalletFlowStackSymbol&gt;</c>.
/// It is a pure dispatch table: no I/O, randomness, or time reads occur inside the
/// transition function. All effectful values arrive pre-computed inside the input records.
/// </para>
/// <para>
/// The Wallet flow transitions:
/// </para>
/// <list type="bullet">
///   <item><description><c>RequestUriReceived</c> + <see cref="JarReceived"/> → <see cref="JarParsed"/> (request_uri_method=get path)</description></item>
///   <item><description><c>RequestUriReceived</c> + <see cref="WalletPostSent"/> → <see cref="WalletNonceSent"/> (request_uri_method=post path, OID4VP 1.0 §5.10)</description></item>
///   <item><description><c>WalletNonceSent</c> + <see cref="JarReceived"/> → <see cref="JarParsed"/> (continuation of the POST path)</description></item>
///   <item><description><c>JarParsed</c> + <see cref="DcqlMatched"/> → <see cref="DcqlEvaluated"/></description></item>
///   <item><description><c>DcqlEvaluated</c> + <see cref="PresentationSelected"/> → <see cref="PresentationBuilt"/></description></item>
///   <item><description><c>PresentationBuilt</c> + <see cref="ResponsePostedByWallet"/> → <see cref="ResponseSent"/> (cross-device terminal)</description></item>
///   <item><description>[Same-device only] <c>ResponseSent</c> + <see cref="RedirectReceived"/> → <see cref="BrowserRedirectIssued"/> (same-device terminal)</description></item>
///   <item><description>Any non-terminal state + <see cref="Fail"/> → <see cref="FlowFailed"/></description></item>
///   <item><description>Terminal states + any input → halt</description></item>
/// </list>
/// </remarks>
public static class WalletFlowTransitions
{
    /// <summary>Creates the transition delegate for the Wallet-side OID4VP presentation flow PDA.</summary>
    public static TransitionDelegate<FlowState, FlowInput, WalletFlowStackSymbol> Create() =>
        (state, input, _, _) =>
        {
            TransitionResult<FlowState, WalletFlowStackSymbol>? result = (state, input) switch
            {
                (RequestUriReceived received, JarReceived jar) =>
                    Transition(
                        new JarParsed
                        {
                            FlowId = received.FlowId,
                            ExpectedIssuer = received.ExpectedIssuer,
                            EnteredAt = jar.FetchedAt,
                            ExpiresAt = received.ExpiresAt,
                            Kind = FlowKind.Wallet,
                            Request = jar.Request
                        },
                        StackAction<WalletFlowStackSymbol>.None,
                        "JarParsed"),

                (RequestUriReceived received, WalletPostSent posted) =>
                    Transition(
                        new WalletNonceSent
                        {
                            FlowId = received.FlowId,
                            ExpectedIssuer = received.ExpectedIssuer,
                            EnteredAt = posted.SentAt,
                            ExpiresAt = received.ExpiresAt,
                            Kind = FlowKind.Wallet,
                            RequestUri = posted.RequestUri,
                            WalletNonce = posted.WalletNonce
                        },
                        StackAction<WalletFlowStackSymbol>.None,
                        "WalletNonceSent"),

                (WalletNonceSent sent, JarReceived jar) =>
                    Transition(
                        new JarParsed
                        {
                            FlowId = sent.FlowId,
                            ExpectedIssuer = sent.ExpectedIssuer,
                            EnteredAt = jar.FetchedAt,
                            ExpiresAt = sent.ExpiresAt,
                            Kind = FlowKind.Wallet,
                            Request = jar.Request
                        },
                        StackAction<WalletFlowStackSymbol>.None,
                        "JarParsed"),

                (JarParsed parsed, DcqlMatched matched) =>
                    Transition(
                        new DcqlEvaluated
                        {
                            FlowId = parsed.FlowId,
                            ExpectedIssuer = parsed.ExpectedIssuer,
                            EnteredAt = matched.EvaluatedAt,
                            ExpiresAt = parsed.ExpiresAt,
                            Kind = FlowKind.Wallet,
                            Request = parsed.Request,
                            PreparedQuery = matched.PreparedQuery,
                            MatchedPresentationsByQueryId = matched.MatchedPresentationsByQueryId
                        },
                        StackAction<WalletFlowStackSymbol>.None,
                        "DcqlEvaluated"),

                (DcqlEvaluated evaluated, PresentationSelected selected) =>
                    Transition(
                        new PresentationBuilt
                        {
                            FlowId = evaluated.FlowId,
                            ExpectedIssuer = evaluated.ExpectedIssuer,
                            EnteredAt = selected.SelectedAt,
                            ExpiresAt = evaluated.ExpiresAt,
                            Kind = FlowKind.Wallet,
                            Request = evaluated.Request,
                            VpTokenJson = selected.VpTokenJson
                        },
                        StackAction<WalletFlowStackSymbol>.None,
                        "PresentationBuilt"),

                (PresentationBuilt built, ResponsePostedByWallet posted) =>
                    Transition(
                        new ResponseSent
                        {
                            FlowId = built.FlowId,
                            ExpectedIssuer = built.ExpectedIssuer,
                            EnteredAt = posted.SentAt,
                            ExpiresAt = built.ExpiresAt,
                            Kind = FlowKind.Wallet,
                            ResponseUri = posted.ResponseUri,
                            State = posted.State,
                            SentAt = posted.SentAt
                        },
                        StackAction<WalletFlowStackSymbol>.None,
                        "ResponseSent"),

                (ResponseSent sent, RedirectReceived redirect) =>
                    Transition(
                        new BrowserRedirectIssued
                        {
                            FlowId = sent.FlowId,
                            ExpectedIssuer = sent.ExpectedIssuer,
                            EnteredAt = redirect.ReceivedAt,
                            ExpiresAt = sent.ExpiresAt,
                            Kind = FlowKind.Wallet,
                            RedirectUri = redirect.RedirectUri,
                            State = sent.State,
                            RedirectIssuedAt = redirect.ReceivedAt
                        },
                        StackAction<WalletFlowStackSymbol>.None,
                        "BrowserRedirectIssued"),

                (not (ResponseSent or BrowserRedirectIssued or FlowFailed), Fail fail) =>
                    Transition(
                        new FlowFailed
                        {
                            FlowId = state.FlowId,
                            ExpectedIssuer = state.ExpectedIssuer,
                            EnteredAt = fail.FailedAt,
                            ExpiresAt = state.ExpiresAt,
                            Kind = FlowKind.Wallet,
                            Reason = fail.Reason,
                            FailedAt = fail.FailedAt
                        },
                        StackAction<WalletFlowStackSymbol>.None,
                        "FlowFailed"),

                (ResponseSent, _) => null,
                (BrowserRedirectIssued, _) => null,
                (FlowFailed, _) => null,
                _ => null
            };

            return ValueTask.FromResult<TransitionResult<FlowState, WalletFlowStackSymbol>?>(result);
        };


    private static TransitionResult<FlowState, WalletFlowStackSymbol> Transition(
        FlowState nextState,
        StackAction<WalletFlowStackSymbol> stackAction,
        string label) =>
        new(nextState, stackAction, label);
}
