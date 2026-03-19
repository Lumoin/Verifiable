using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Validation;

/// <summary>
/// All validation <see cref="ClaimId"/> instances for OAuth 2.0, OID4VP, and related
/// protocol checks. Codes 700–999 (300 total).
/// </summary>
/// <remarks>
/// <para>
/// Sub-ranges:
/// </para>
/// <list type="bullet">
///   <item><description>700–719: Callback parameter presence.</description></item>
///   <item><description>720–739: Callback flow and CSRF checks.</description></item>
///   <item><description>740–759: PKCE checks.</description></item>
///   <item><description>760–779: JAR (JWT-Secured Authorization Request) validation.</description></item>
///   <item><description>780–799: DPoP proof validation.</description></item>
///   <item><description>800–819: JWT registered claims (iss, sub, aud, exp, nbf, iat, jti).</description></item>
///   <item><description>820–839: ID Token and OIDC-specific checks.</description></item>
///   <item><description>840–859: Token lifetime and scope checks.</description></item>
///   <item><description>860–879: Outbound request pre-send checks.</description></item>
///   <item><description>880–899: Client ID prefix and redirect URI validation.</description></item>
///   <item><description>900–909: JWE decryption checks.</description></item>
///   <item><description>910–929: KB-JWT checks.</description></item>
///   <item><description>930–949: Credential verification.</description></item>
///   <item><description>950–969: VP token structure.</description></item>
///   <item><description>970–999: Reserved for OID4VCI, Federation, CIBA, device authorization.</description></item>
/// </list>
/// </remarks>
public static class ValidationClaimIds
{

    /// <summary>
    /// The <c>code</c> parameter is present in the callback.
    /// Required per <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>.
    /// </summary>
    public static ClaimId CallbackCodePresent { get; } = ClaimId.Create(700, "CallbackCodePresent");

    /// <summary>
    /// The <c>state</c> parameter is present in the callback.
    /// Required for CSRF defense per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.7">RFC 9700 §4.7</see>.
    /// </summary>
    public static ClaimId CallbackStatePresent { get; } = ClaimId.Create(701, "CallbackStatePresent");

    /// <summary>
    /// The <c>iss</c> parameter is present in the callback.
    /// Required for mix-up attack defense per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9207">RFC 9207</see>.
    /// </summary>
    public static ClaimId CallbackIssPresent { get; } = ClaimId.Create(702, "CallbackIssPresent");



    /// <summary>
    /// The <c>iss</c> value in the callback matches the expected authorization server issuer.
    /// Failure indicates a potential mix-up attack per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC 9700 §4.4</see>.
    /// </summary>
    public static ClaimId IssuerMatchesExpected { get; } = ClaimId.Create(720, "IssuerMatchesExpected");

    /// <summary>
    /// The <c>state</c> value in the callback matches an active flow state.
    /// Failure indicates a CSRF attempt per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.7">RFC 9700 §4.7</see>.
    /// </summary>
    public static ClaimId StateMatchesActiveFlow { get; } = ClaimId.Create(721, "StateMatchesActiveFlow");

    /// <summary>
    /// The flow state has not expired at the time of the callback.
    /// </summary>
    public static ClaimId FlowStateNotExpired { get; } = ClaimId.Create(722, "FlowStateNotExpired");



    /// <summary>
    /// The PAR request body contains a <c>code_challenge</c> parameter.
    /// Its absence would allow PKCE downgrade per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.8">RFC 9700 §4.8</see>.
    /// </summary>
    public static ClaimId ParBodyContainsCodeChallenge { get; } = ClaimId.Create(740, "ParBodyContainsCodeChallenge");

    /// <summary>
    /// The token request body contains a <c>code_verifier</c> parameter.
    /// Its absence when a <c>code_challenge</c> was registered indicates an injection attempt per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.5">RFC 9700 §4.5</see>.
    /// </summary>
    public static ClaimId TokenRequestContainsCodeVerifier { get; } = ClaimId.Create(741, "TokenRequestContainsCodeVerifier");

    /// <summary>
    /// The <c>code_challenge_method</c> parameter value is <c>S256</c>.
    /// The plain method must not be used per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1">RFC 9700 §2.1.1</see>.
    /// </summary>
    public static ClaimId CodeChallengeMethodIsS256 { get; } = ClaimId.Create(742, "CodeChallengeMethodIsS256");

    /// <summary>
    /// The <c>code_verifier</c> hash matches the stored <c>code_challenge</c>.
    /// </summary>
    public static ClaimId CodeVerifierMatchesChallenge { get; } = ClaimId.Create(743, "CodeVerifierMatchesChallenge");



    /// <summary>
    /// The JAR <c>typ</c> header is <c>oauth-authz-req+jwt</c> per OID4VP 1.0 §5.
    /// </summary>
    public static ClaimId JarTypIsOAuthAuthzReqJwt { get; } = ClaimId.Create(760, "JarTypIsOAuthAuthzReqJwt");

    /// <summary>
    /// The JAR signature is cryptographically valid.
    /// </summary>
    public static ClaimId JarSignatureValid { get; } = ClaimId.Create(761, "JarSignatureValid");

    /// <summary>
    /// The JAR <c>exp</c> has not passed.
    /// </summary>
    public static ClaimId JarNotExpired { get; } = ClaimId.Create(762, "JarNotExpired");

    /// <summary>
    /// The JAR <c>iat</c> is valid (not in the future, not too old).
    /// </summary>
    public static ClaimId JarIatValid { get; } = ClaimId.Create(763, "JarIatValid");

    /// <summary>
    /// The JAR lifetime (exp - nbf/iat) does not exceed the maximum.
    /// FAPI 2.0 / HAIP 1.0 require ≤ 60 seconds.
    /// </summary>
    public static ClaimId JarLifetimeWithinMaximum { get; } = ClaimId.Create(764, "JarLifetimeWithinMaximum");

    /// <summary>
    /// The JAR does not contain <c>request</c> or <c>request_uri</c> parameters inside the
    /// request object per JAR §10.8.
    /// </summary>
    public static ClaimId JarNoNestedRequestOrRequestUri { get; } = ClaimId.Create(765, "JarNoNestedRequestOrRequestUri");



    /// <summary>
    /// The DPoP proof JWT is present in the request.
    /// </summary>
    public static ClaimId DpopProofPresent { get; } = ClaimId.Create(780, "DpopProofPresent");

    /// <summary>
    /// The DPoP <c>htm</c> claim matches the HTTP method of the request.
    /// </summary>
    public static ClaimId DpopHtmMatchesMethod { get; } = ClaimId.Create(781, "DpopHtmMatchesMethod");

    /// <summary>
    /// The DPoP <c>htu</c> claim matches the HTTP URI of the request.
    /// </summary>
    public static ClaimId DpopHtuMatchesUri { get; } = ClaimId.Create(782, "DpopHtuMatchesUri");

    /// <summary>
    /// The DPoP <c>iat</c> is within acceptable bounds.
    /// </summary>
    public static ClaimId DpopIatValid { get; } = ClaimId.Create(783, "DpopIatValid");

    /// <summary>
    /// The DPoP <c>jti</c> has not been seen before (replay prevention).
    /// </summary>
    public static ClaimId DpopJtiNotReplayed { get; } = ClaimId.Create(784, "DpopJtiNotReplayed");

    /// <summary>
    /// The DPoP proof signature is cryptographically valid.
    /// </summary>
    public static ClaimId DpopSignatureValid { get; } = ClaimId.Create(785, "DpopSignatureValid");



    /// <summary>
    /// The <c>iss</c> claim is present and non-empty.
    /// </summary>
    public static ClaimId IssPresent { get; } = ClaimId.Create(800, "IssPresent");

    /// <summary>
    /// The <c>iss</c> value matches the expected issuer identifier.
    /// </summary>
    public static ClaimId IssMatchesExpected { get; } = ClaimId.Create(801, "IssMatchesExpected");

    /// <summary>
    /// The <c>sub</c> claim is present and non-empty.
    /// </summary>
    public static ClaimId SubPresent { get; } = ClaimId.Create(802, "SubPresent");

    /// <summary>
    /// The <c>aud</c> claim is present.
    /// </summary>
    public static ClaimId AudPresent { get; } = ClaimId.Create(803, "AudPresent");

    /// <summary>
    /// The <c>aud</c> value contains the expected client identifier.
    /// </summary>
    public static ClaimId AudContainsExpectedClient { get; } = ClaimId.Create(804, "AudContainsExpectedClient");

    /// <summary>
    /// The <c>exp</c> claim is present.
    /// </summary>
    public static ClaimId ExpPresent { get; } = ClaimId.Create(805, "ExpPresent");

    /// <summary>
    /// The token has not expired.
    /// </summary>
    public static ClaimId TokenNotExpired { get; } = ClaimId.Create(806, "TokenNotExpired");

    /// <summary>
    /// The <c>nbf</c> claim is present.
    /// </summary>
    public static ClaimId NbfPresent { get; } = ClaimId.Create(807, "NbfPresent");

    /// <summary>
    /// The current time is at or after <c>nbf</c>.
    /// </summary>
    public static ClaimId TokenNotBeforeValid { get; } = ClaimId.Create(808, "TokenNotBeforeValid");

    /// <summary>
    /// The <c>iat</c> claim is present.
    /// </summary>
    public static ClaimId IatPresent { get; } = ClaimId.Create(809, "IatPresent");

    /// <summary>
    /// The <c>iat</c> value is not in the future beyond clock skew tolerance.
    /// </summary>
    public static ClaimId IatNotInFuture { get; } = ClaimId.Create(810, "IatNotInFuture");

    /// <summary>
    /// The <c>jti</c> claim is present.
    /// </summary>
    public static ClaimId JtiPresent { get; } = ClaimId.Create(811, "JtiPresent");

    /// <summary>
    /// The <c>jti</c> value has not been seen before (replay prevention).
    /// </summary>
    public static ClaimId JtiNotReplayed { get; } = ClaimId.Create(812, "JtiNotReplayed");



    /// <summary>
    /// The <c>nonce</c> claim is present in the ID Token.
    /// </summary>
    public static ClaimId NoncePresentInIdToken { get; } = ClaimId.Create(820, "NoncePresentInIdToken");

    /// <summary>
    /// The <c>nonce</c> value matches the nonce sent in the authorization request.
    /// </summary>
    public static ClaimId NonceMatchesRequest { get; } = ClaimId.Create(821, "NonceMatchesRequest");

    /// <summary>
    /// The <c>auth_time</c> satisfies the maximum authentication age constraint.
    /// </summary>
    public static ClaimId AuthTimeSatisfiesMaxAge { get; } = ClaimId.Create(822, "AuthTimeSatisfiesMaxAge");

    /// <summary>
    /// The <c>acr</c> satisfies the requested <c>acr_values</c> constraint.
    /// </summary>
    public static ClaimId AcrSatisfiesRequest { get; } = ClaimId.Create(823, "AcrSatisfiesRequest");



    /// <summary>
    /// The token lifetime (exp - nbf/iat) does not exceed the maximum.
    /// </summary>
    public static ClaimId TokenLifetimeWithinMaximum { get; } = ClaimId.Create(840, "TokenLifetimeWithinMaximum");

    /// <summary>
    /// The <c>scope</c> parameter or claim is present and non-empty.
    /// </summary>
    public static ClaimId ScopePresent { get; } = ClaimId.Create(841, "ScopePresent");

    /// <summary>
    /// The <c>scope</c> contains <c>openid</c>.
    /// </summary>
    public static ClaimId ScopeContainsOpenId { get; } = ClaimId.Create(842, "ScopeContainsOpenId");

    /// <summary>
    /// The granted <c>scope</c> does not include values that were not requested.
    /// </summary>
    public static ClaimId ScopeDoesNotExceedRequested { get; } = ClaimId.Create(843, "ScopeDoesNotExceedRequested");



    /// <summary>
    /// The request contains a <c>state</c> parameter for CSRF protection.
    /// </summary>
    public static ClaimId RequestContainsState { get; } = ClaimId.Create(860, "RequestContainsState");

    /// <summary>
    /// The request contains a <c>redirect_uri</c>.
    /// </summary>
    public static ClaimId RequestContainsRedirectUri { get; } = ClaimId.Create(861, "RequestContainsRedirectUri");

    /// <summary>
    /// The request contains a <c>code_challenge</c>.
    /// </summary>
    public static ClaimId RequestContainsCodeChallenge { get; } = ClaimId.Create(862, "RequestContainsCodeChallenge");

    /// <summary>
    /// The <c>code_challenge_method</c> is <c>S256</c>.
    /// </summary>
    public static ClaimId RequestCodeChallengeMethodIsS256 { get; } = ClaimId.Create(863, "RequestCodeChallengeMethodIsS256");



    /// <summary>
    /// The client identifier prefix is recognized (<c>did:</c>, <c>x509_san_dns:</c>,
    /// <c>redirect_uri:</c>, <c>openid_federation:</c>).
    /// </summary>
    public static ClaimId ClientIdPrefixRecognized { get; } = ClaimId.Create(880, "ClientIdPrefixRecognized");

    /// <summary>
    /// The <c>redirect_uri</c> scheme is HTTPS (or <c>http</c> for localhost).
    /// </summary>
    public static ClaimId RedirectUriSchemeValid { get; } = ClaimId.Create(881, "RedirectUriSchemeValid");

    /// <summary>
    /// The <c>redirect_uri</c> does not contain a fragment component.
    /// </summary>
    public static ClaimId RedirectUriNoFragment { get; } = ClaimId.Create(882, "RedirectUriNoFragment");

    /// <summary>
    /// The <c>redirect_uri</c> matches a registered redirect URI for the client.
    /// </summary>
    public static ClaimId RedirectUriMatchesRegistered { get; } = ClaimId.Create(883, "RedirectUriMatchesRegistered");



    /// <summary>
    /// The JWE <c>enc</c> header is one of the algorithms the Verifier advertised.
    /// </summary>
    public static ClaimId JweEncAlgorithmAllowed { get; } = ClaimId.Create(900, "JweEncAlgorithmAllowed");

    /// <summary>
    /// The JWE decrypted successfully.
    /// </summary>
    public static ClaimId JweDecryptionSucceeded { get; } = ClaimId.Create(901, "JweDecryptionSucceeded");



    /// <summary>
    /// The KB-JWT signature is cryptographically valid.
    /// Conformance test: <c>VP1FinalVerifierInvalidKbJwtSignature</c>.
    /// </summary>
    public static ClaimId KbJwtSignatureValid { get; } = ClaimId.Create(910, "KbJwtSignatureValid");

    /// <summary>
    /// The KB-JWT <c>nonce</c> matches the nonce from the authorization request.
    /// Conformance test: <c>VP1FinalVerifierInvalidKbJwtNonce</c>.
    /// </summary>
    public static ClaimId KbJwtNonceMatchesRequest { get; } = ClaimId.Create(911, "KbJwtNonceMatchesRequest");

    /// <summary>
    /// The KB-JWT <c>aud</c> matches the Verifier's <c>client_id</c>.
    /// Conformance test: <c>VP1FinalVerifierInvalidKbJwtAud</c>.
    /// </summary>
    public static ClaimId KbJwtAudMatchesClientId { get; } = ClaimId.Create(912, "KbJwtAudMatchesClientId");

    /// <summary>
    /// The KB-JWT <c>iat</c> is not in the future beyond clock skew tolerance.
    /// Conformance test: <c>VP1FinalVerifierKbJwtIatInFuture</c>.
    /// </summary>
    public static ClaimId KbJwtIatNotInFuture { get; } = ClaimId.Create(913, "KbJwtIatNotInFuture");

    /// <summary>
    /// The KB-JWT <c>iat</c> is not too far in the past.
    /// Conformance test: <c>VP1FinalVerifierKbJwtIatInPast</c>.
    /// </summary>
    public static ClaimId KbJwtIatNotTooOld { get; } = ClaimId.Create(914, "KbJwtIatNotTooOld");



    /// <summary>
    /// The issuer's signature on the credential is cryptographically valid.
    /// Conformance test: <c>VP1FinalVerifierInvalidCredentialSignature</c>.
    /// </summary>
    public static ClaimId CredentialSignatureValid { get; } = ClaimId.Create(930, "CredentialSignatureValid");

    /// <summary>
    /// The <c>sd_hash</c> in the KB-JWT matches the hash of the presented disclosures.
    /// Conformance test: <c>VP1FinalVerifierInvalidSdHash</c>.
    /// </summary>
    public static ClaimId SdHashMatchesPresentation { get; } = ClaimId.Create(931, "SdHashMatchesPresentation");

    /// <summary>
    /// The session transcript for mdoc presentations is correctly computed.
    /// Conformance test: <c>VP1FinalVerifierInvalidSessionTranscript</c>.
    /// </summary>
    public static ClaimId SessionTranscriptValid { get; } = ClaimId.Create(932, "SessionTranscriptValid");

    /// <summary>
    /// The credential's <c>vct</c> matches a type accepted by the DCQL query.
    /// </summary>
    public static ClaimId CredentialTypeMatchesQuery { get; } = ClaimId.Create(933, "CredentialTypeMatchesQuery");



    /// <summary>
    /// The VP token contains all credential entries requested by the DCQL query.
    /// </summary>
    public static ClaimId VpTokenContainsRequestedCredentials { get; } = ClaimId.Create(950, "VpTokenContainsRequestedCredentials");

    /// <summary>
    /// The <c>state</c> parameter in the direct_post body matches the flow's
    /// external correlation token.
    /// </summary>
    public static ClaimId DirectPostStateMatchesFlow { get; } = ClaimId.Create(951, "DirectPostStateMatchesFlow");
}
