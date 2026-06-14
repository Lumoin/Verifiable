using Verifiable.Foundation.Automata;
using Verifiable.Cryptography;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Siop.Server.States;

namespace Verifiable.OAuth.Siop.Server;

/// <summary>
/// The transition function for the server-side SIOPv2 Relying Party flow PDA. Each transition is
/// one HTTP boundary crossing per the
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html">SIOPv2</see>
/// (Self-Issued OpenID Provider v2) RP role: request preparation, then receipt and §11.1
/// validation of the Wallet's Self-Issued ID Token.
/// </summary>
/// <remarks>
/// <para>Transitions:</para>
/// <list type="bullet">
///   <item><description>
///     Sentinel + <see cref="SiopRequestPrepared"/> -> <see cref="SiopRequestPreparedState"/>.
///     The RP fixed the transaction (nonce, client_id) and minted the request handle.
///   </description></item>
///   <item><description>
///     <see cref="SiopRequestPreparedState"/> + <see cref="SelfIssuedAuthenticationVerified"/> ->
///     <see cref="SelfIssuedAuthenticationVerifiedState"/>. Terminal success: the response
///     endpoint validated the <c>id_token</c> against the transaction.
///   </description></item>
///   <item><description>
///     Any non-terminal state + <see cref="SiopFlowFailed"/> -> <see cref="SiopVerifierFlowFailedState"/>.
///     Terminal failure.
///   </description></item>
/// </list>
/// </remarks>
public static class SiopVerifierFlowTransitions
{
    /// <summary>Creates the transition delegate for the server-side SIOP RP flow PDA.</summary>
    public static TransitionDelegate<FlowState, FlowInput, SiopVerifierStackSymbol> Create() =>
        static (state, input, stackTop, cancellationToken) =>
        {
            cancellationToken.ThrowIfCancellationRequested();

            TransitionResult<FlowState, SiopVerifierStackSymbol>? result =
                (state, input) switch
                {
                    //Any non-terminal state + SiopFlowFailed -> SiopVerifierFlowFailed.
                    (not (SelfIssuedAuthenticationVerifiedState or SiopVerifierFlowFailedState), SiopFlowFailed fail) =>
                        Transition(
                            new SiopVerifierFlowFailedState
                            {
                                FlowId = state.FlowId,
                                ExpectedIssuer = state.ExpectedIssuer,
                                EnteredAt = fail.FailedAt,
                                ExpiresAt = state.ExpiresAt,
                                Kind = FlowKind.SiopVerifierServer,
                                Reason = fail.Reason,
                                FailedAt = fail.FailedAt
                            },
                            StackAction<SiopVerifierStackSymbol>.None,
                            "SiopVerifierFlowFailed"),

                    //Sentinel (empty FlowId failed state) + SiopRequestPrepared -> SiopRequestPrepared.
                    (SiopVerifierFlowFailedState { FlowId: "" }, SiopRequestPrepared prepared) =>
                        Transition(
                            new SiopRequestPreparedState
                            {
                                FlowId = prepared.FlowId,
                                ExpectedIssuer = state.ExpectedIssuer,
                                EnteredAt = prepared.PreparedAt,
                                ExpiresAt = prepared.ExpiresAt,
                                Kind = FlowKind.SiopVerifierServer,
                                ClientId = prepared.ClientId,
                                Nonce = prepared.Nonce,
                                IdTokenType = prepared.IdTokenType,
                                AllowedAlgorithms = prepared.AllowedAlgorithms,
                                RequestHandle = prepared.RequestHandle,
                                SigningKeyId = prepared.SigningKeyId,
                                DecryptionKeyId = prepared.DecryptionKeyId,
                                AllowedEncAlgorithms = prepared.AllowedEncAlgorithms,
                                UseStaticDiscoveryAudience = prepared.UseStaticDiscoveryAudience,
                                RequestObjectAdditionalHeaderClaims = prepared.RequestObjectAdditionalHeaderClaims
                            },
                            StackAction<SiopVerifierStackSymbol>.None,
                            "SiopRequestPrepared"),

                    //SiopRequestPrepared + SiopRequestObjectSigned -> SiopRequestObjectServed.
                    //The §9 request-object endpoint signed and served the Request Object in a single
                    //HTTP request (the by-reference request_uri path). Signing is an EFFECT run by
                    //the executor; this transition only records the served checkpoint. The
                    //transaction-forwarding fields are carried so the response endpoint validates
                    //against them exactly as it does from SiopRequestPreparedState on the by-value
                    //path. The by-reference parallel of OID4VP's VerifierParReceived + ServerJarSigned.
                    (SiopRequestPreparedState prepared, SiopRequestObjectSigned signed) =>
                        Transition(
                            new SiopRequestObjectServedState
                            {
                                FlowId = prepared.FlowId,
                                ExpectedIssuer = prepared.ExpectedIssuer,
                                EnteredAt = signed.ServedAt,
                                ExpiresAt = prepared.ExpiresAt,
                                Kind = FlowKind.SiopVerifierServer,
                                ServedAt = signed.ServedAt,
                                RequestHandle = prepared.RequestHandle,
                                ClientId = prepared.ClientId,
                                Nonce = prepared.Nonce,
                                IdTokenType = prepared.IdTokenType,
                                AllowedAlgorithms = prepared.AllowedAlgorithms,
                                DecryptionKeyId = prepared.DecryptionKeyId,
                                AllowedEncAlgorithms = prepared.AllowedEncAlgorithms
                            },
                            StackAction<SiopVerifierStackSymbol>.None,
                            "SiopRequestObjectServed"),

                    //SiopRequestPrepared + SiopResponsePosted -> SiopResponseReceived.
                    //A durable received-but-unverified checkpoint; the new state declares the
                    //ValidateSelfIssuedIdToken action the executor runs to produce the verdict.
                    //This is the same-device (by-value) path where the RP never served a Request
                    //Object at a request_uri.
                    (SiopRequestPreparedState prepared, SiopResponsePosted posted) =>
                        Transition(
                            new SiopResponseReceivedState
                            {
                                FlowId = prepared.FlowId,
                                ExpectedIssuer = prepared.ExpectedIssuer,
                                EnteredAt = posted.ReceivedAt,
                                ExpiresAt = prepared.ExpiresAt,
                                Kind = FlowKind.SiopVerifierServer,
                                IdToken = posted.IdToken,
                                ExpectedAudience = prepared.ClientId,
                                ExpectedNonce = prepared.Nonce,
                                AllowedAlgorithms = prepared.AllowedAlgorithms,
                                ReceivedAt = posted.ReceivedAt
                            },
                            StackAction<SiopVerifierStackSymbol>.None,
                            "SiopResponseReceived"),

                    //SiopRequestObjectServed + SiopResponsePosted -> SiopResponseReceived.
                    //The by-reference (request_uri) path: the Wallet fetched and verified the signed
                    //§9 Request Object, then POSTed its Self-Issued ID Token. Sibling of the by-value
                    //transition above — same successor state, same checkpoint semantics — differing
                    //only in the predecessor, exactly as OID4VP's direct_post accepts from both
                    //VerifierJarServed and VerifierParReceived.
                    (SiopRequestObjectServedState served, SiopResponsePosted posted) =>
                        Transition(
                            new SiopResponseReceivedState
                            {
                                FlowId = served.FlowId,
                                ExpectedIssuer = served.ExpectedIssuer,
                                EnteredAt = posted.ReceivedAt,
                                ExpiresAt = served.ExpiresAt,
                                Kind = FlowKind.SiopVerifierServer,
                                IdToken = posted.IdToken,
                                ExpectedAudience = served.ClientId,
                                ExpectedNonce = served.Nonce,
                                AllowedAlgorithms = served.AllowedAlgorithms,
                                ReceivedAt = posted.ReceivedAt
                            },
                            StackAction<SiopVerifierStackSymbol>.None,
                            "SiopResponseReceived"),

                    //SiopRequestPrepared + SiopCombinedResponsePosted -> SiopCombinedResponseReceived.
                    //SIOPv2 §12: the Wallet answered with BOTH an id_token AND a vp_token in one
                    //Authorization Response. A durable received-but-unverified checkpoint; the new
                    //state declares the ValidateCombinedSiopResponse action the executor runs to
                    //produce the verdict. Same-device (by-value) path. The combined sibling of the
                    //id_token-only SiopResponsePosted transition above.
                    (SiopRequestPreparedState prepared, SiopCombinedResponsePosted posted) =>
                        Transition(
                            new SiopCombinedResponseReceivedState
                            {
                                FlowId = prepared.FlowId,
                                ExpectedIssuer = prepared.ExpectedIssuer,
                                EnteredAt = posted.ReceivedAt,
                                ExpiresAt = prepared.ExpiresAt,
                                Kind = FlowKind.SiopVerifierServer,
                                IdToken = posted.IdToken,
                                VpToken = posted.VpToken,
                                ExpectedAudience = prepared.ClientId,
                                ExpectedNonce = prepared.Nonce,
                                AllowedAlgorithms = prepared.AllowedAlgorithms,
                                ReceivedAt = posted.ReceivedAt
                            },
                            StackAction<SiopVerifierStackSymbol>.None,
                            "SiopCombinedResponseReceived"),

                    //SiopRequestObjectServed + SiopCombinedResponsePosted -> SiopCombinedResponseReceived.
                    //The by-reference (request_uri) path of the §12 combined response — sibling of the
                    //by-value transition above, same successor state, differing only in predecessor,
                    //exactly as the id_token-only SiopResponsePosted transitions do.
                    (SiopRequestObjectServedState served, SiopCombinedResponsePosted posted) =>
                        Transition(
                            new SiopCombinedResponseReceivedState
                            {
                                FlowId = served.FlowId,
                                ExpectedIssuer = served.ExpectedIssuer,
                                EnteredAt = posted.ReceivedAt,
                                ExpiresAt = served.ExpiresAt,
                                Kind = FlowKind.SiopVerifierServer,
                                IdToken = posted.IdToken,
                                VpToken = posted.VpToken,
                                ExpectedAudience = served.ClientId,
                                ExpectedNonce = served.Nonce,
                                AllowedAlgorithms = served.AllowedAlgorithms,
                                ReceivedAt = posted.ReceivedAt
                            },
                            StackAction<SiopVerifierStackSymbol>.None,
                            "SiopCombinedResponseReceived"),

                    //SiopRequestPrepared + SiopEncryptedResponsePosted -> SiopEncryptedResponseReceived.
                    //The Wallet returned the id_token as a compact JWE encrypted to the RP's
                    //advertised encryption key. A durable received-but-undecrypted checkpoint; the new
                    //state declares the DecryptSiopResponse action the executor runs to decrypt (with
                    //the enc allow-list check) and then validate the recovered inner id_token. The
                    //same-device (by-value) path. The encrypted sibling of the SiopResponsePosted
                    //transition above; the SIOP parallel of OID4VP's VerifierResponseReceived.
                    (SiopRequestPreparedState { DecryptionKeyId: { } prepKeyId, AllowedEncAlgorithms: { } prepEnc } prepared,
                        SiopEncryptedResponsePosted encryptedPosted) =>
                        Transition(
                            new SiopEncryptedResponseReceivedState
                            {
                                FlowId = prepared.FlowId,
                                ExpectedIssuer = prepared.ExpectedIssuer,
                                EnteredAt = encryptedPosted.ReceivedAt,
                                ExpiresAt = prepared.ExpiresAt,
                                Kind = FlowKind.SiopVerifierServer,
                                EncryptedIdToken = encryptedPosted.EncryptedIdToken,
                                ExpectedAudience = prepared.ClientId,
                                ExpectedNonce = prepared.Nonce,
                                AllowedAlgorithms = prepared.AllowedAlgorithms,
                                DecryptionKeyId = new KeyId(prepKeyId),
                                AllowedEncAlgorithms = prepEnc,
                                ReceivedAt = encryptedPosted.ReceivedAt
                            },
                            StackAction<SiopVerifierStackSymbol>.None,
                            "SiopEncryptedResponseReceived"),

                    //SiopRequestObjectServed + SiopEncryptedResponsePosted -> SiopEncryptedResponseReceived.
                    //The by-reference (request_uri) path of the encrypted response — sibling of the
                    //by-value transition above, same successor state, differing only in predecessor,
                    //exactly as the bare-JWS SiopResponsePosted transitions do.
                    (SiopRequestObjectServedState { DecryptionKeyId: { } servedKeyId, AllowedEncAlgorithms: { } servedEnc } served,
                        SiopEncryptedResponsePosted encryptedPosted) =>
                        Transition(
                            new SiopEncryptedResponseReceivedState
                            {
                                FlowId = served.FlowId,
                                ExpectedIssuer = served.ExpectedIssuer,
                                EnteredAt = encryptedPosted.ReceivedAt,
                                ExpiresAt = served.ExpiresAt,
                                Kind = FlowKind.SiopVerifierServer,
                                EncryptedIdToken = encryptedPosted.EncryptedIdToken,
                                ExpectedAudience = served.ClientId,
                                ExpectedNonce = served.Nonce,
                                AllowedAlgorithms = served.AllowedAlgorithms,
                                DecryptionKeyId = new KeyId(servedKeyId),
                                AllowedEncAlgorithms = servedEnc,
                                ReceivedAt = encryptedPosted.ReceivedAt
                            },
                            StackAction<SiopVerifierStackSymbol>.None,
                            "SiopEncryptedResponseReceived"),

                    //SiopResponseReceived + SelfIssuedAuthenticationVerified -> terminal success.
                    //The §11.1 validation action ran in the executor (outside the pure transition)
                    //and emitted the verdict.
                    (SiopResponseReceivedState received, SelfIssuedAuthenticationVerified verified) =>
                        Transition(
                            new SelfIssuedAuthenticationVerifiedState
                            {
                                FlowId = received.FlowId,
                                ExpectedIssuer = received.ExpectedIssuer,
                                EnteredAt = verified.VerifiedAt,
                                ExpiresAt = received.ExpiresAt,
                                Kind = FlowKind.SiopVerifierServer,
                                Subject = verified.Subject,
                                SubjectSyntaxType = verified.SubjectSyntaxType,
                                Nonce = verified.Nonce,
                                VerifiedAt = verified.VerifiedAt
                            },
                            StackAction<SiopVerifierStackSymbol>.None,
                            "SelfIssuedAuthenticationVerified"),

                    //SiopEncryptedResponseReceived + SelfIssuedAuthenticationVerified -> terminal
                    //success. The DecryptSiopResponse action decrypted the JWE (enforcing the enc
                    //allow-list) and ran the §11.1 validation on the recovered inner id_token in the
                    //executor (outside the pure transition), emitting the verdict. The encrypted
                    //sibling of the bare-JWS success transition above.
                    (SiopEncryptedResponseReceivedState received, SelfIssuedAuthenticationVerified verified) =>
                        Transition(
                            new SelfIssuedAuthenticationVerifiedState
                            {
                                FlowId = received.FlowId,
                                ExpectedIssuer = received.ExpectedIssuer,
                                EnteredAt = verified.VerifiedAt,
                                ExpiresAt = received.ExpiresAt,
                                Kind = FlowKind.SiopVerifierServer,
                                Subject = verified.Subject,
                                SubjectSyntaxType = verified.SubjectSyntaxType,
                                Nonce = verified.Nonce,
                                VerifiedAt = verified.VerifiedAt
                            },
                            StackAction<SiopVerifierStackSymbol>.None,
                            "SelfIssuedAuthenticationVerified"),

                    //SiopCombinedResponseReceived + SelfIssuedAuthenticationVerified -> terminal
                    //success. The §11.1 id_token validation, the vp_token presentation verification,
                    //and the §12 binding checks all ran in the executor (outside the pure transition)
                    //and emitted the verdict carrying the authenticated SIOP subject. The combined
                    //sibling of the id_token-only success transition above.
                    (SiopCombinedResponseReceivedState received, SelfIssuedAuthenticationVerified verified) =>
                        Transition(
                            new SelfIssuedAuthenticationVerifiedState
                            {
                                FlowId = received.FlowId,
                                ExpectedIssuer = received.ExpectedIssuer,
                                EnteredAt = verified.VerifiedAt,
                                ExpiresAt = received.ExpiresAt,
                                Kind = FlowKind.SiopVerifierServer,
                                Subject = verified.Subject,
                                SubjectSyntaxType = verified.SubjectSyntaxType,
                                Nonce = verified.Nonce,
                                VerifiedAt = verified.VerifiedAt
                            },
                            StackAction<SiopVerifierStackSymbol>.None,
                            "SelfIssuedAuthenticationVerified"),

                    //Terminal states — PDA halts.
                    (SelfIssuedAuthenticationVerifiedState, _) => null,
                    (SiopVerifierFlowFailedState, _) => null,

                    _ => null
                };

            return ValueTask.FromResult<TransitionResult<FlowState, SiopVerifierStackSymbol>?>(result);
        };


    private static TransitionResult<FlowState, SiopVerifierStackSymbol> Transition(
        FlowState nextState,
        StackAction<SiopVerifierStackSymbol> stackAction,
        string label) =>
        new(nextState, stackAction, label);
}
