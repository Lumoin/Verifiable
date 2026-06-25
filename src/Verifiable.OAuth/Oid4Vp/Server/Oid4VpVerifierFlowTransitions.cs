using System.Linq;
using Verifiable.Foundation.Automata;
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
    public static TransitionDelegate<FlowState, FlowInput, Oid4VpVerifierStackSymbol> Create() =>
        static (state, input, stackTop, cancellationToken) =>
        {
            cancellationToken.ThrowIfCancellationRequested();

            TransitionResult<FlowState, Oid4VpVerifierStackSymbol>? result =
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
                                ParHandle = par.ParHandle,
                                Nonce = par.Nonce,
                                Query = par.Query,
                                DecryptionKeyId = par.DecryptionKeyId,
                                SigningKeyId = par.SigningKeyId,
                                AllowedEncAlgorithms = par.AllowedEncAlgorithms,
                                TransactionData = par.TransactionData,
                                JarAdditionalHeaderClaims = par.JarAdditionalHeaderClaims,
                                ResponseMode = par.ResponseMode
                            },
                            StackAction<Oid4VpVerifierStackSymbol>.None,
                            "VerifierParReceived"),

                    //VerifierParReceived + ServerJarSigned -> VerifierJarServed.
                    //The JAR request endpoint signed and served the JAR in a single
                    //HTTP request per OID4VP 1.0 §5.4 (request_uri_method=get path).
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
                                ParHandle = received.ParHandle,
                                Nonce = received.Nonce,
                                DecryptionKeyId = received.DecryptionKeyId,
                                AllowedEncAlgorithms = received.AllowedEncAlgorithms,
                                CredentialQueries = received.Query.Query.Credentials!.ToList(),
                                TransactionData = received.TransactionData
                            },
                            StackAction<Oid4VpVerifierStackSymbol>.None,
                            "VerifierJarServed"),

                    //VerifierParReceived + ServerWalletPostReceived -> VerifierWalletPostReceived.
                    //The Wallet POSTed to request_uri with wallet_nonce per
                    //OID4VP 1.0 §5.10 (request_uri_method=post path). The Verifier
                    //records the wallet_nonce so the subsequent JAR-signing step
                    //can echo it.
                    (VerifierParReceivedState received, ServerWalletPostReceived posted) =>
                        BuildWalletPostReceivedTransition(received, posted),

                    //VerifierWalletPostReceived + ServerJarSigned -> VerifierJarServed.
                    //Continuation of the POST path: the JAR-signing action just
                    //emitted a JAR carrying the wallet_nonce echo.
                    (VerifierWalletPostReceivedState postReceived, ServerJarSigned signed) =>
                        Transition(
                            new VerifierJarServedState
                            {
                                FlowId = postReceived.FlowId,
                                ExpectedIssuer = postReceived.ExpectedIssuer,
                                EnteredAt = signed.ServedAt,
                                ExpiresAt = postReceived.ExpiresAt,
                                Kind = FlowKind.Oid4VpVerifierServer,
                                ServedAt = signed.ServedAt,
                                ParHandle = postReceived.ParHandle,
                                Nonce = postReceived.Nonce,
                                DecryptionKeyId = postReceived.DecryptionKeyId,
                                AllowedEncAlgorithms = postReceived.AllowedEncAlgorithms,
                                CredentialQueries = postReceived.Query.Query.Credentials!.ToList(),
                                TransactionData = postReceived.TransactionData
                            },
                            StackAction<Oid4VpVerifierStackSymbol>.None,
                            "VerifierJarServed"),

                    //VerifierJarServed + ResponsePosted -> VerifierResponseReceived.
                    //The Wallet POSTed the encrypted Authorization Response to the
                    //response_uri carried in the JAR.
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
                                AllowedEncAlgorithms = served.AllowedEncAlgorithms,
                                CredentialQueries = served.CredentialQueries,
                                TransactionData = served.TransactionData
                            },
                            StackAction<Oid4VpVerifierStackSymbol>.None,
                            "VerifierResponseReceived"),

                    //VerifierJarServed + ResponsePostedUnencrypted ->
                    //VerifierUnencryptedResponseReceived. The Wallet POSTed the
                    //plaintext vp_token (response_mode=direct_post) per
                    //OID4VP 1.0 §8.2. Sibling to the encrypted path above; the
                    //two transitions share the same predecessor state and
                    //differ only in input type, so the dispatcher matches on
                    //whichever arrived on the wire.
                    (VerifierJarServedState served, ResponsePostedUnencrypted unencrypted) =>
                        Transition(
                            new VerifierUnencryptedResponseReceivedState
                            {
                                FlowId = served.FlowId,
                                ExpectedIssuer = served.ExpectedIssuer,
                                EnteredAt = unencrypted.ReceivedAt,
                                ExpiresAt = served.ExpiresAt,
                                Kind = FlowKind.Oid4VpVerifierServer,
                                VpTokenJson = unencrypted.VpTokenJson,
                                ReceivedAt = unencrypted.ReceivedAt,
                                Nonce = served.Nonce,
                                CredentialQueries = served.CredentialQueries,
                                TransactionData = served.TransactionData
                            },
                            StackAction<Oid4VpVerifierStackSymbol>.None,
                            "VerifierUnencryptedResponseReceived"),

                    //OID4VP 1.0 §5.9.3 redirect_uri prefix: the Verifier sends
                    //the Authorization Request inline (no JAR), so the PDA
                    //moves directly from VerifierParReceived to a response-
                    //received state when the wallet POSTs to response_uri.
                    //CredentialQueryIds are derived from the same DCQL the
                    //inline request carries, available on VerifierParReceived.
                    (VerifierParReceivedState received, ResponsePosted posted) =>
                        Transition(
                            new VerifierResponseReceivedState
                            {
                                FlowId = received.FlowId,
                                ExpectedIssuer = received.ExpectedIssuer,
                                EnteredAt = posted.ReceivedAt,
                                ExpiresAt = received.ExpiresAt,
                                Kind = FlowKind.Oid4VpVerifierServer,
                                EncryptedResponseJwt = posted.EncryptedResponseJwt,
                                ReceivedAt = posted.ReceivedAt,
                                DecryptionKeyId = received.DecryptionKeyId,
                                Nonce = received.Nonce,
                                AllowedEncAlgorithms = received.AllowedEncAlgorithms,
                                CredentialQueries = received.Query.Query.Credentials!.ToList(),
                                TransactionData = received.TransactionData
                            },
                            StackAction<Oid4VpVerifierStackSymbol>.None,
                            "VerifierResponseReceived"),

                    //Same as above, plaintext direct_post variant.
                    (VerifierParReceivedState received, ResponsePostedUnencrypted unencrypted) =>
                        Transition(
                            new VerifierUnencryptedResponseReceivedState
                            {
                                FlowId = received.FlowId,
                                ExpectedIssuer = received.ExpectedIssuer,
                                EnteredAt = unencrypted.ReceivedAt,
                                ExpiresAt = received.ExpiresAt,
                                Kind = FlowKind.Oid4VpVerifierServer,
                                VpTokenJson = unencrypted.VpTokenJson,
                                ReceivedAt = unencrypted.ReceivedAt,
                                Nonce = received.Nonce,
                                CredentialQueries = received.Query.Query.Credentials!.ToList(),
                                TransactionData = received.TransactionData
                            },
                            StackAction<Oid4VpVerifierStackSymbol>.None,
                            "VerifierUnencryptedResponseReceived"),

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
                                CredentialStatuses = verified.CredentialStatuses,
                                VerifiedAt = verified.VerifiedAt,
                                RedirectUri = verified.RedirectUri
                            },
                            StackAction<Oid4VpVerifierStackSymbol>.None,
                            "PresentationVerified"),

                    //VerifierUnencryptedResponseReceived + VerificationSucceeded
                    //-> PresentationVerified. Terminal success for the
                    //unencrypted-direct_post path.
                    (VerifierUnencryptedResponseReceivedState unencryptedReceived, VerificationSucceeded verified) =>
                        Transition(
                            new PresentationVerifiedState
                            {
                                FlowId = unencryptedReceived.FlowId,
                                ExpectedIssuer = unencryptedReceived.ExpectedIssuer,
                                EnteredAt = verified.VerifiedAt,
                                ExpiresAt = unencryptedReceived.ExpiresAt,
                                Kind = FlowKind.Oid4VpVerifierServer,
                                Claims = verified.Claims,
                                CredentialStatuses = verified.CredentialStatuses,
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

            return ValueTask.FromResult<TransitionResult<FlowState, Oid4VpVerifierStackSymbol>?>(result);
        };


    private static TransitionResult<FlowState, Oid4VpVerifierStackSymbol> Transition(
        FlowState nextState,
        StackAction<Oid4VpVerifierStackSymbol> stackAction,
        string label) =>
        new(nextState, stackAction, label);


    /// <summary>
    /// Builds the <see cref="VerifierWalletPostReceivedState"/> for the
    /// <see cref="VerifierParReceivedState"/> + <see cref="ServerWalletPostReceived"/>
    /// transition. Parses the wallet_metadata blob — once, on the boundary —
    /// to extract the encryption JWKS sub-object and any
    /// <c>authorization_encrypted_response_enc</c> hint so downstream states
    /// carry typed fields rather than the raw JSON blob.
    /// </summary>
    private static TransitionResult<FlowState, Oid4VpVerifierStackSymbol> BuildWalletPostReceivedTransition(
        VerifierParReceivedState received,
        ServerWalletPostReceived posted)
    {
        (string? walletJwksJson, string? jarEnc) =
            ParseWalletMetadata(posted.WalletMetadataJson);

        return Transition(
            new VerifierWalletPostReceivedState
            {
                FlowId = received.FlowId,
                ExpectedIssuer = received.ExpectedIssuer,
                EnteredAt = posted.ReceivedAt,
                ExpiresAt = received.ExpiresAt,
                Kind = FlowKind.Oid4VpVerifierServer,
                Par = received.Par,
                ParHandle = received.ParHandle,
                Nonce = received.Nonce,
                Query = received.Query,
                DecryptionKeyId = received.DecryptionKeyId,
                SigningKeyId = received.SigningKeyId,
                AllowedEncAlgorithms = received.AllowedEncAlgorithms,
                WalletNonce = posted.WalletNonce,
                WalletMetadataJson = posted.WalletMetadataJson,
                WalletEncryptionJwksJson = walletJwksJson,
                JarEncryptionEnc = jarEnc,
                TransactionData = received.TransactionData,
                JarAdditionalHeaderClaims = received.JarAdditionalHeaderClaims
            },
            StackAction<Oid4VpVerifierStackSymbol>.None,
            "VerifierWalletPostReceived");
    }


    private static (string? WalletEncryptionJwksJson, string? JarEncryptionEnc) ParseWalletMetadata(
        string? walletMetadataJson) =>
        WalletMetadataReader.ParseForJarEncryption(walletMetadataJson);
}
