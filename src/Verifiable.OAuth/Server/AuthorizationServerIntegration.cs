using System.Diagnostics;
using System.Text;
using Verifiable.Core;
using Verifiable.OAuth.Server.Keys;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Groups the integration delegates by which the Authorization Server asks the
/// application to resolve request data and read or write persistent state.
/// </summary>
/// <remarks>
/// <para>
/// Every delegate on this group has the same shape: <em>the library has a question,
/// the application supplies an answer</em>. None of the delegates perform protocol
/// logic — that lives entirely inside <see cref="EndpointServer"/>. They only
/// answer questions that depend on the application's deployment choices: which
/// signal identifies a tenant, where flow state is persisted, what URLs endpoints
/// are exposed at, and so on.
/// </para>
/// <para>
/// Wire all required delegates at construction time. <see cref="Validate"/> reports
/// any missing delegate by name in a single error message rather than failing
/// piecemeal at request time.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthorizationServerIntegration Validated={IsValidated}")]
public sealed class AuthorizationServerIntegration: ServerIntegration
{
    /// <summary>
    /// The cryptographic-material delegate group (signing, verification, decryption, JWKS
    /// assembly) the OAuth/OpenID endpoints and token producers use.
    /// </summary>
    public AuthorizationServerCryptography Cryptography { get; set; } = new();

    /// <summary>
    /// The encoding, decoding, hashing, and JWT-serialization delegate group the OAuth/OpenID
    /// endpoints use.
    /// </summary>
    public AuthorizationServerCodecs Codecs { get; set; } = new();

    /// <summary>
    /// The token producers that compose the response of a token-issuing endpoint.
    /// </summary>
    public TokenProducerSet TokenProducers { get; set; } = TokenProducerSet.Empty;

    /// <summary>
    /// The composed claim-contribution issuer that emits the additional claims merged into
    /// token payloads.
    /// </summary>
    public Verifiable.Core.Assessment.ClaimIssuer<ClaimContributionTarget>? ClaimIssuer { get; set; }

    /// <summary>
    /// Drives effectful work between pure PDA transitions for OAuth flows that emit
    /// <see cref="OAuthAction"/> values (e.g. the OID4VP Verifier flow).
    /// </summary>
    public OAuthActionExecutor? ActionExecutor { get; set; }

    /// <summary>
    /// The timing policy applied across all OAuth artifact-issuance and timing-claim
    /// validation sites. Defaults to <see cref="TimingPolicy.Default"/>.
    /// </summary>
    public TimingPolicy Timings { get; set; } = TimingPolicy.Default;


    /// <summary>
    /// Loads a <see cref="ClientRecord"/> by tenant identifier. Required.
    /// </summary>
    public LoadRegistrationDelegate? LoadClientRegistrationAsync
    {
        get => LoadRegistrationAsync;
        set => LoadRegistrationAsync = value;
    }

    /// <summary>
    /// Resolves the authorization server's issuer URI (the <c>iss</c> claim and
    /// the base URL advertised in discovery). Optional. When
    /// <see langword="null"/>, the library uses <see cref="DefaultIssuerResolver"/>
    /// which reads <see cref="ClientRecord.IssuerUri"/> first and falls
    /// back to <see cref="ExchangeContextServerExtensions.Issuer"/> on the request
    /// context.
    /// </summary>
    //ResolveIssuerAsync is the host-generic base seam (ResolveServerIssuerDelegate over
    //IRegistrationRecord); the OAuth wiring adapts its ClientRecord resolver to it.

    /// <summary>
    /// Maps the authenticated end-user identifier to the subject identifier
    /// emitted in tokens for a registration — public (identity) or pairwise
    /// (per-sector hash) per OIDC Core §8. Wire to
    /// <see cref="DefaultSubjectIdentifierResolver.PublicAsync"/> for the
    /// identity default.
    /// </summary>
    /// <remarks>
    /// A structural slot the UserInfo wiring resolves the subject identifier
    /// through.
    /// </remarks>
    public ResolveSubjectIdentifierDelegate? ResolveSubjectIdentifierAsync { get; set; }

    /// <summary>
    /// Fetches and validates Client ID Metadata Documents for CIMD clients.
    /// Optional.
    /// </summary>
    public ResolveClientMetadataDelegate? ResolveClientMetadataAsync { get; set; }

    /// <summary>
    /// Parses an incoming RFC 7591 client metadata document body into a typed
    /// <see cref="Client.ClientMetadata"/>. Required when
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthDynamicClientRegistration"/> is
    /// advertised — the default JSON implementation lives in
    /// <c>Verifiable.OAuth.Json</c> and is wired by the application.
    /// </summary>
    public ParseClientMetadataServerDelegate? ParseClientMetadataAsync { get; set; }

    /// <summary>
    /// Validates a bearer token presented at an RFC 7592 management endpoint.
    /// Required when
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthDynamicClientRegistration"/> is
    /// advertised — the application implements the constant-time comparison
    /// against its persisted form.
    /// </summary>
    public ValidateRegistrationAccessTokenDelegate? ValidateRegistrationAccessTokenAsync { get; set; }

    /// <summary>
    /// Contributes additional fields to the discovery document
    /// (<c>/.well-known/openid-configuration</c> and equivalents). Optional.
    /// </summary>
    /// <remarks>
    /// The library's discovery endpoint emits its base OAuth 2.0 and OIDC fields
    /// first, then merges the contributed fields over the top. Applications use
    /// this delegate to advertise OIDC, FAPI, OID4VP, OID4VCI, OpenID Federation
    /// or deployment-specific capability fields without replacing the discovery
    /// endpoint.
    /// </remarks>
    public ContributeDiscoveryFieldsDelegate? ContributeDiscoveryFieldsAsync { get; set; }

    /// <summary>
    /// Contributes the per-entity-type metadata blocks, authority hints, and
    /// extension claims that populate the entity's own OpenID Federation 1.0
    /// Entity Configuration JWT at <c>/.well-known/openid-federation</c>.
    /// Optional.
    /// </summary>
    /// <remarks>
    /// Required only for registrations carrying
    /// <see cref="Federation.WellKnownFederationCapabilityIdentifiers.PublishEntityConfiguration"/>.
    /// The library emits the EC's structural claims (<c>iss</c>, <c>sub</c>,
    /// <c>iat</c>, <c>exp</c>, <c>jwks</c>) on its own; this delegate supplies
    /// the per-entity-type metadata blocks and federation extension claims.
    /// </remarks>
    public ContributeFederationMetadataDelegate? ContributeFederationMetadataAsync { get; set; }

    /// <summary>
    /// Resolves the Subordinate Statement body the issuing entity asserts
    /// about a queried subject. Optional.
    /// </summary>
    /// <remarks>
    /// Required only for registrations carrying
    /// <see cref="Federation.WellKnownFederationCapabilityIdentifiers.PublishSubordinateStatement"/>.
    /// The library emits the SS's structural claims and signs the result;
    /// this delegate supplies the subject's <c>jwks</c> plus any per-subject
    /// metadata-policy / metadata / constraints / extension claims.
    /// Return <see langword="null"/> when the queried subject is not a
    /// known subordinate — the endpoint then responds 404.
    /// </remarks>
    public ResolveSubordinateStatementDelegate? ResolveSubordinateStatementAsync { get; set; }

    /// <summary>
    /// Resolves the immediate subordinates the issuing entity lists at its
    /// <c>federation_list_endpoint</c>. Optional.
    /// </summary>
    /// <remarks>
    /// Required only for registrations carrying
    /// <see cref="Federation.WellKnownFederationCapabilityIdentifiers.ListSubordinates"/>.
    /// The library matches the request, parses the optional
    /// <c>entity_type</c> filter, and serialises the returned identifiers
    /// as the unsigned JSON array OpenID Federation 1.0 §8.2 mandates; this
    /// delegate supplies the membership list itself. Returning an empty
    /// list is valid — the endpoint then responds with an empty JSON array.
    /// </remarks>
    public ResolveSubordinateListDelegate? ResolveSubordinateListAsync { get; set; }

    /// <summary>
    /// Resolves a subject's effective metadata, trust chain, and trust marks
    /// for the <c>federation_resolve_endpoint</c>. Optional.
    /// </summary>
    /// <remarks>
    /// Required only for registrations carrying
    /// <see cref="Federation.WellKnownFederationCapabilityIdentifiers.ResolveTrustChain"/>.
    /// The library matches the request, parses the <c>sub</c> / <c>anchor</c>
    /// / <c>type</c> parameters, assembles the OpenID Federation 1.0 §8.3
    /// Resolve Response from the returned contribution, and signs it with the
    /// resolver's federation signing key; this delegate supplies the
    /// resolution result. Return <see langword="null"/> when the subject
    /// cannot be resolved — the endpoint then responds 404.
    /// </remarks>
    public ResolveSubjectTrustChainDelegate? ResolveSubjectTrustChainAsync { get; set; }

    /// <summary>
    /// Processes a Relying Party's explicit client registration request at the
    /// <c>federation_registration_endpoint</c>. Optional.
    /// </summary>
    /// <remarks>
    /// Required only for registrations carrying
    /// <see cref="Federation.WellKnownFederationCapabilityIdentifiers.RegisterClientsExplicitly"/>.
    /// The library hands the RP's posted Entity Configuration (raw compact
    /// JWS) to this delegate, assembles the OpenID Federation 1.0 §12.2
    /// Explicit Registration Response from the returned contribution, and
    /// signs it with the OP's federation signing key. Return
    /// <see langword="null"/> when the RP cannot be registered — the endpoint
    /// then responds 400.
    /// </remarks>
    public ResolveExplicitRegistrationDelegate? ResolveExplicitRegistrationAsync { get; set; }

    /// <summary>
    /// Resolves the entity's historical (rotated and revoked) Federation
    /// Entity Keys for the <c>federation_historical_keys_endpoint</c>.
    /// Optional.
    /// </summary>
    /// <remarks>
    /// Required only for registrations carrying
    /// <see cref="Federation.WellKnownFederationCapabilityIdentifiers.PublishHistoricalKeys"/>.
    /// The library matches the request, assembles the OpenID Federation 1.0
    /// §8.7.3 Historical Keys payload (<c>iss</c>, <c>iat</c>, <c>keys</c>)
    /// from the returned contribution, and signs it with the entity's
    /// federation signing key; this delegate supplies the historical
    /// <c>keys</c> array itself. Return <see langword="null"/> when the entity
    /// has no historical keys to publish — the endpoint then responds 404.
    /// </remarks>
    public ResolveHistoricalKeysDelegate? ResolveHistoricalKeysAsync { get; set; }

    /// <summary>
    /// Resolves the Trust Mark JWT the issuing entity serves at its
    /// <c>federation_trust_mark_endpoint</c>. Optional.
    /// </summary>
    /// <remarks>
    /// Required only for registrations carrying
    /// <see cref="Federation.WellKnownFederationCapabilityIdentifiers.PublishTrustMark"/>.
    /// The library matches the request, parses the <c>trust_mark_type</c> and
    /// <c>sub</c> parameters, and serves the returned compact JWS verbatim as
    /// OpenID Federation 1.0 §8.6 mandates (<c>application/trust-mark+jwt</c>);
    /// the library signs nothing — the Trust Mark was signed when it was issued.
    /// This delegate supplies the Trust Mark JWT itself. Return
    /// <see langword="null"/> when the entity has no Trust Mark of the queried
    /// type for the queried subject — the endpoint then responds 404.
    /// </remarks>
    public Federation.ResolveTrustMarkDelegate? ResolveTrustMarkAsync { get; set; }

    /// <summary>
    /// Resolves the entities holding a given Trust Mark type the issuing entity
    /// lists at its <c>federation_trust_mark_list_endpoint</c>. Optional.
    /// </summary>
    /// <remarks>
    /// Required only for registrations carrying
    /// <see cref="Federation.WellKnownFederationCapabilityIdentifiers.PublishTrustMarkedList"/>.
    /// The library matches the request, parses the REQUIRED <c>trust_mark_type</c>
    /// and the OPTIONAL <c>sub</c> filter, and serialises the returned identifiers
    /// as the unsigned JSON array OpenID Federation 1.0 §8.5 mandates; this
    /// delegate supplies the membership list itself. Returning an empty list is
    /// valid — the endpoint then responds with an empty JSON array. Return
    /// <see langword="null"/> when the issuer does not know the queried Trust Mark
    /// type — the endpoint then responds 404.
    /// </remarks>
    public Federation.ResolveTrustMarkedListDelegate? ResolveTrustMarkedListAsync { get; set; }

    /// <summary>
    /// Resolves the status of a Trust Mark the issuing entity reports at its
    /// <c>federation_trust_mark_status_endpoint</c>. Optional.
    /// </summary>
    /// <remarks>
    /// Required only for registrations carrying
    /// <see cref="Federation.WellKnownFederationCapabilityIdentifiers.PublishTrustMarkStatus"/>.
    /// The library matches the POST request, reads the <c>trust_mark</c> form
    /// parameter, assembles the OpenID Federation 1.0 §8.4 status payload
    /// (<c>iss</c>, <c>iat</c>, <c>trust_mark</c>, <c>status</c>) from the
    /// returned status string, and signs it with the entity's federation signing
    /// key; this delegate supplies the status string itself. Return
    /// <see langword="null"/> when the issuer does not know the queried Trust
    /// Mark — the endpoint then responds 404.
    /// </remarks>
    public Federation.ResolveTrustMarkStatusDelegate? ResolveTrustMarkStatusAsync { get; set; }

    /// <summary>
    /// Gates the federation endpoints on OpenID Federation 1.0 §8.8 client
    /// authentication. Optional.
    /// </summary>
    /// <remarks>
    /// When set, the library invokes this at the start of each federation
    /// endpoint it serves (fetch, list, resolve, trust mark, trust marked
    /// listing, trust mark status, historical keys), before producing the
    /// response. Client authentication is not used by default; a deployment that
    /// declares <c>*_auth_methods</c> on an endpoint (§8.8.1) wires this delegate
    /// to require it. The delegate resolves the requester's Federation Entity
    /// Key, verifies the client authentication JWT, and validates its claims via
    /// <see cref="Federation.FederationClientAuthentication.Validate"/>; returning
    /// a failed result rejects the request with HTTP 401 <c>invalid_client</c>,
    /// and <see langword="null"/> means client authentication is not required at
    /// that endpoint so the request proceeds.
    /// </remarks>
    public Federation.AuthenticateFederationClientDelegate? AuthenticateFederationClientAsync { get; set; }

    /// <summary>
    /// Parses an OpenID AuthZEN Authorization API 1.0 Access Evaluation
    /// request JSON body into the neutral information model. Required when
    /// <see cref="WellKnownCapabilityIdentifiers.AuthZenAuthorizationApi"/> is
    /// advertised — the default JSON implementation lives in
    /// <c>Verifiable.OAuth.Json</c> and is wired by the application.
    /// </summary>
    public ParseAccessEvaluationRequestDelegate? ParseAccessEvaluationRequestAsync { get; set; }

    /// <summary>
    /// Parses an OpenID AuthZEN Authorization API 1.0 Access Evaluations API
    /// (batch) request JSON body into the neutral information model. Required
    /// for the <c>access_evaluations_endpoint</c> when
    /// <see cref="WellKnownCapabilityIdentifiers.AuthZenAuthorizationApi"/> is
    /// advertised — the default JSON implementation lives in
    /// <c>Verifiable.OAuth.Json</c> and is wired by the application. The
    /// single-evaluation PDP seam <see cref="EvaluateAccessAsync"/> is reused
    /// for each resolved item.
    /// </summary>
    public ParseAccessEvaluationsRequestDelegate? ParseAccessEvaluationsRequestAsync { get; set; }

    /// <summary>
    /// The Policy Decision Point seam — evaluates a parsed AuthZEN Access
    /// Evaluation request and returns the decision. Required when
    /// <see cref="WellKnownCapabilityIdentifiers.AuthZenAuthorizationApi"/> is
    /// advertised. The library owns the wire; this delegate owns the policy.
    /// </summary>
    public EvaluateAccessDelegate? EvaluateAccessAsync { get; set; }

    /// <summary>
    /// Parses an OpenID AuthZEN Authorization API 1.0 Search API request JSON
    /// body into the neutral information model. Required for any search
    /// endpoint that is wired. The default JSON implementation lives in
    /// <c>Verifiable.OAuth.Json</c> and is wired by the application.
    /// </summary>
    public ParseAccessSearchRequestDelegate? ParseAccessSearchRequestAsync { get; set; }

    /// <summary>
    /// The Subject Search seam (§7). Optional — wiring it activates and
    /// advertises the <c>search_subject_endpoint</c>. The library owns the
    /// wire; this delegate owns enumeration and paging.
    /// </summary>
    public SearchSubjectsDelegate? SearchSubjectsAsync { get; set; }

    /// <summary>
    /// The Resource Search seam (§7). Optional — wiring it activates and
    /// advertises the <c>search_resource_endpoint</c>.
    /// </summary>
    public SearchResourcesDelegate? SearchResourcesAsync { get; set; }

    /// <summary>
    /// The Action Search seam (§7). Optional — wiring it activates and
    /// advertises the <c>search_action_endpoint</c>.
    /// </summary>
    public SearchActionsDelegate? SearchActionsAsync { get; set; }

    /// <summary>
    /// Contributes application-supplied values (currently <c>capabilities</c>)
    /// to the AuthZEN §9.1 PDP metadata document. Optional.
    /// </summary>
    public ContributeAuthZenMetadataDelegate? ContributeAuthZenMetadataAsync { get; set; }

    /// <summary>
    /// Signs the assembled AuthZEN §9.1 PDP metadata as a <c>signed_metadata</c>
    /// JWT. Optional — when set, the returned JWT is embedded in the metadata
    /// document. The application owns the signing key and algorithm.
    /// </summary>
    public SignAuthZenMetadataDelegate? SignAuthZenMetadataAsync { get; set; }

    /// <summary>
    /// Contributes application-supplied values (delivery methods, critical subject
    /// members, authorization schemes, default subjects) to the Shared Signals
    /// Transmitter Configuration Metadata document (SSF 1.0 §7.1). Optional.
    /// </summary>
    public ContributeSsfTransmitterMetadataDelegate? ContributeSsfTransmitterMetadataAsync { get; set; }

    /// <summary>
    /// Contributes application-supplied values (authorization servers, scopes,
    /// bearer methods, human-readable fields, feature booleans) to the OAuth 2.0
    /// Protected Resource Metadata document (RFC 9728 §2). Optional.
    /// </summary>
    public ContributeProtectedResourceMetadataDelegate? ContributeProtectedResourceMetadataAsync { get; set; }

    /// <summary>
    /// Signs the assembled RFC 9728 Protected Resource Metadata as a
    /// <c>signed_metadata</c> JWT (§2.2). Optional — when set, the returned JWT
    /// is embedded in the metadata document. The application owns the signing
    /// key, the algorithm, and the spec-required <c>iss</c> claim.
    /// </summary>
    public SignProtectedResourceMetadataDelegate? SignProtectedResourceMetadataAsync { get; set; }

    /// <summary>
    /// Parses a Create Stream request body (SSF §8.1.1.1). Wire the shipped
    /// default with <c>UseDefaultSsfJsonParsing</c>.
    /// </summary>
    public Ssf.ParseSsfStreamCreateRequestDelegate? ParseSsfStreamCreateRequestAsync { get; set; }

    /// <summary>
    /// Parses an Update/Replace Stream request body (SSF §8.1.1.3/§8.1.1.4).
    /// Wire the shipped default with <c>UseDefaultSsfJsonParsing</c>.
    /// </summary>
    public Ssf.ParseSsfStreamUpdateRequestDelegate? ParseSsfStreamUpdateRequestAsync { get; set; }

    /// <summary>
    /// The Transmitter's stream store: create (SSF §8.1.1.1). Optional — wiring it
    /// (with the create parser) activates and advertises the Configuration Endpoint.
    /// </summary>
    public Ssf.CreateSsfStreamDelegate? CreateSsfStreamAsync { get; set; }

    /// <summary>The Transmitter's stream store: read one or all (SSF §8.1.1.2). Optional.</summary>
    public Ssf.ReadSsfStreamsDelegate? ReadSsfStreamsAsync { get; set; }

    /// <summary>The Transmitter's stream store: PATCH update (SSF §8.1.1.3). Optional.</summary>
    public Ssf.UpdateSsfStreamDelegate? UpdateSsfStreamAsync { get; set; }

    /// <summary>The Transmitter's stream store: PUT replace (SSF §8.1.1.4). Optional.</summary>
    public Ssf.ReplaceSsfStreamDelegate? ReplaceSsfStreamAsync { get; set; }

    /// <summary>The Transmitter's stream store: delete (SSF §8.1.1.5). Optional.</summary>
    public Ssf.DeleteSsfStreamDelegate? DeleteSsfStreamAsync { get; set; }

    /// <summary>Parses a Stream Status update body (SSF §8.1.2.2). Wire via <c>UseDefaultSsfJsonParsing</c>.</summary>
    public Ssf.ParseSsfStreamStatusDelegate? ParseSsfStreamStatusAsync { get; set; }

    /// <summary>Parses an Add Subject body (SSF §8.1.3.2). Wire via <c>UseDefaultSsfJsonParsing</c>.</summary>
    public Ssf.ParseSsfAddSubjectRequestDelegate? ParseSsfAddSubjectRequestAsync { get; set; }

    /// <summary>Parses a Remove Subject body (SSF §8.1.3.3). Wire via <c>UseDefaultSsfJsonParsing</c>.</summary>
    public Ssf.ParseSsfRemoveSubjectRequestDelegate? ParseSsfRemoveSubjectRequestAsync { get; set; }

    /// <summary>Parses a Trigger Verification body (SSF §8.1.4.2). Wire via <c>UseDefaultSsfJsonParsing</c>.</summary>
    public Ssf.ParseSsfVerificationRequestDelegate? ParseSsfVerificationRequestAsync { get; set; }

    /// <summary>The Transmitter's stream store: read status (SSF §8.1.2.1). Optional.</summary>
    public Ssf.ReadSsfStreamStatusDelegate? ReadSsfStreamStatusAsync { get; set; }

    /// <summary>The Transmitter's stream store: update status (SSF §8.1.2.2). Optional.</summary>
    public Ssf.UpdateSsfStreamStatusDelegate? UpdateSsfStreamStatusAsync { get; set; }

    /// <summary>The Transmitter's stream store: add a subject (SSF §8.1.3.2). Optional.</summary>
    public Ssf.AddSsfSubjectDelegate? AddSsfSubjectAsync { get; set; }

    /// <summary>The Transmitter's stream store: remove a subject (SSF §8.1.3.3). Optional.</summary>
    public Ssf.RemoveSsfSubjectDelegate? RemoveSsfSubjectAsync { get; set; }

    /// <summary>The Transmitter's verification trigger (SSF §8.1.4.2). Optional.</summary>
    public Ssf.TriggerSsfVerificationDelegate? TriggerSsfVerificationAsync { get; set; }

    /// <summary>
    /// Authorizes stream-management requests (Bearer token + <c>ssf.read</c>/<c>ssf.manage</c>
    /// scope per CAEP Interoperability Profile §2.7.3). Optional — unset leaves the
    /// stream-management endpoints unauthenticated.
    /// </summary>
    public Ssf.AuthorizeSsfRequestDelegate? AuthorizeSsfRequestAsync { get; set; }

    /// <summary>
    /// Authenticates a confidential client for the <c>client_credentials</c> grant
    /// (RFC 6749 §4.4). The grant endpoint activates only when this seam is wired —
    /// the application owns credential storage and the authentication method.
    /// </summary>
    public ValidateClientCredentialsDelegate? ValidateClientCredentialsAsync { get; set; }

    /// <summary>
    /// Validates a Token Exchange <c>subject_token</c> (RFC 8693 §2.1) and returns its accepted
    /// claims, or rejects it. The grant activates only when the
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthTokenExchange"/> capability is allowed and
    /// BOTH this seam and <see cref="AuthorizeTokenExchangeAsync"/> are wired — an advertised
    /// token-exchange grant with no validation seam would mint tokens for any subject-token string
    /// (fail-closed, the §3.2.1-style materialization the other grants use). The application is the
    /// trust authority: it owns which issuers and keys it accepts, and any remote key fetch is its
    /// concern (the library takes no <c>System.Net.*</c> dependency).
    /// </summary>
    public ValidateTokenExchangeTokenDelegate? ValidateTokenExchangeTokenAsync { get; set; }

    /// <summary>
    /// Decides whether a validated Token Exchange <c>subject_token</c> may be exchanged for the
    /// requested target and shapes the issued token (RFC 8693 §2.1). The grant activates only when
    /// the <see cref="WellKnownCapabilityIdentifiers.OAuthTokenExchange"/> capability is allowed and
    /// BOTH this seam and <see cref="ValidateTokenExchangeTokenAsync"/> are wired — an advertised
    /// grant that cannot make the impersonation policy decision would be a fail-open authorization
    /// boundary (fail-closed, the §3.2.1-style materialization). The application owns the policy
    /// "which entities are permitted to impersonate other entities" (§2.1); a <see langword="null"/>
    /// return denies the exchange and the endpoint answers <c>invalid_target</c> (§2.2.2).
    /// </summary>
    public AuthorizeTokenExchangeDelegate? AuthorizeTokenExchangeAsync { get; set; }

    /// <summary>
    /// Validates a JWT Bearer authorization-grant <c>assertion</c> (RFC 7523 §2.1/§3.1) and returns
    /// the token shape to issue, or rejects it. The grant activates only when the
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthJwtBearer"/> capability is allowed and this seam
    /// is wired — an advertised jwt-bearer grant with no validation seam would mint tokens for any
    /// assertion string (fail-closed, the §3.2.1-style materialization the other grants use). The
    /// application is the trust authority: it owns which issuers and keys it accepts, performs the full
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 §3</see> processing —
    /// signature (rule 9), trusted <c>iss</c> (rule 1), the <c>aud</c>-names-this-AS check (rule 3,
    /// which only the application can make), and the <c>exp</c>/<c>nbf</c> window (rules 4–5) — and any
    /// remote JWKS fetch is its concern (the library takes no <c>System.Net.*</c> dependency). A
    /// <see langword="null"/> return refuses the grant; the endpoint answers <c>invalid_grant</c> (§3.1).
    /// Client authentication is OPTIONAL for this grant (§3.1): when the request carries client
    /// credentials the endpoint validates them through <see cref="ValidateClientCredentialsAsync"/>, but
    /// the grant does not require that seam — the assertion is the grant.
    /// </summary>
    public ValidateJwtBearerAssertionDelegate? ValidateJwtBearerAssertionAsync { get; set; }

    /// <summary>
    /// Revokes a token at the RFC 7009 revocation endpoint on behalf of an
    /// authenticated client. The endpoint activates only when the
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthTokenRevocation"/> capability
    /// is allowed and BOTH this seam and <see cref="ValidateClientCredentialsAsync"/>
    /// are wired — a revocation endpoint that cannot authenticate the client or
    /// cannot revoke would be a silent no-op that misleads clients into believing a
    /// token was killed. The application owns the token store and the
    /// refresh-to-access cascade.
    /// </summary>
    public RevokeTokenDelegate? RevokeTokenAsync { get; set; }

    /// <summary>
    /// Introspects a token at the RFC 7662 introspection endpoint on behalf of an
    /// authenticated protected resource. The endpoint activates only when the
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthTokenIntrospection"/> capability
    /// is allowed and BOTH this seam and <see cref="ValidateClientCredentialsAsync"/>
    /// are wired — an introspection endpoint that cannot authenticate the caller would
    /// leak token state to anyone, and one that cannot read the token store could only
    /// answer <c>active:false</c>, misleading a resource into rejecting live tokens. The
    /// application owns the token store; the library owns the wire shape and the
    /// inactive-discloses-nothing rule.
    /// </summary>
    public IntrospectTokenDelegate? IntrospectTokenAsync { get; set; }

    /// <summary>
    /// Mints a fresh OID4VCI 1.0 §7 <c>c_nonce</c>. The Nonce Endpoint activates only when the
    /// <see cref="WellKnownCapabilityIdentifiers.Oid4VciNonceEndpoint"/> capability is allowed
    /// and this seam is wired — an advertised Nonce Endpoint that cannot mint a challenge would
    /// break every key-bound Credential Request. The application owns the nonce store so it can
    /// validate the nonce later at the Credential Endpoint.
    /// </summary>
    public IssueCredentialNonceDelegate? IssueCredentialNonceAsync { get; set; }

    /// <summary>
    /// Validates an OID4VCI 1.0 §6 Pre-Authorized Code grant. The grant activates only when
    /// the <see cref="WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant"/> capability
    /// is allowed and this seam is wired — an advertised grant with no code-validation seam would
    /// mint access tokens for any code string (fail-closed). The application owns the
    /// pre-authorized code store, so it resolves the subject and distinguishes the §6.3 error
    /// cases the library cannot.
    /// </summary>
    public ValidatePreAuthorizedCodeDelegate? ValidatePreAuthorizedCodeAsync { get; set; }

    /// <summary>
    /// Parses an OID4VCI 1.0 §8.2 Credential Request body into the neutral
    /// <see cref="Oid4Vci.CredentialRequest"/>. Required when
    /// <see cref="WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint"/> is advertised —
    /// the default JSON implementation lives in <c>Verifiable.OAuth.Json</c> and is wired by
    /// the application.
    /// </summary>
    public ParseCredentialRequestDelegate? ParseCredentialRequestAsync { get; set; }

    /// <summary>
    /// Parses an RFC 9396 <c>authorization_details</c> request parameter into the neutral
    /// <see cref="AuthorizationDetail"/> list. Required when the server processes
    /// <c>authorization_details</c> (RFC 9396 §2; OID4VCI 1.0 §5.1.1 / §6.1.1) — a request
    /// carrying the parameter while this seam is unwired is refused with
    /// <c>invalid_authorization_details</c> (the server does not support the parameter). The
    /// default JSON implementation lives in <c>Verifiable.OAuth.Json</c> and is wired by the
    /// application.
    /// </summary>
    public ParseAuthorizationDetailListDelegate? ParseAuthorizationDetailsAsync { get; set; }

    /// <summary>
    /// The RFC 9396 authorization details <c>type</c> → handler registry the AS dispatches
    /// every parsed authorization details object through (§5/§7 multi-type dispatch). Created
    /// pre-populated with the built-in <c>openid_credential</c> handler
    /// (<see cref="Oid4Vci.OpenIdCredentialAuthorizationDetailHandler"/>); a deployment registers
    /// further handlers to support additional types. Its
    /// <see cref="AuthorizationDetailTypeRegistry.RegisteredTypes"/> is what the AS metadata
    /// advertises as <c>authorization_details_types_supported</c> (§10).
    /// </summary>
    public AuthorizationDetailTypeRegistry AuthorizationDetailTypes { get; } =
        CreateDefaultAuthorizationDetailTypeRegistry();

    /// <summary>
    /// Decides an <c>openid_credential</c> authorization details request at the token endpoint
    /// and mints the OID4VCI 1.0 §6.2 <c>credential_identifiers</c> per granted configuration.
    /// Required when the server processes <c>authorization_details</c>; a token request whose
    /// grant carries authorization details while this seam is unwired is refused with
    /// <c>invalid_authorization_details</c> (fail-closed — the library cannot mint Credential
    /// Dataset identifiers). The application owns the configuration catalog and dataset store.
    /// </summary>
    public ResolveCredentialAuthorizationDelegate? ResolveCredentialAuthorizationAsync { get; set; }

    /// <summary>
    /// Issues an OID4VCI 1.0 §8 Credential. The Credential Endpoint activates only when the
    /// <see cref="WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint"/> capability is
    /// allowed and BOTH this seam and <see cref="ParseCredentialRequestAsync"/> are wired — an
    /// advertised Credential Endpoint that cannot parse the request or cannot mint would be a
    /// fail-open authorization boundary. The application owns proof verification (its
    /// <c>c_nonce</c> store), the supported Credential Configurations, and the signing key; the
    /// library owns bearer-token validation and the wire shape.
    /// </summary>
    public IssueCredentialDelegate? IssueCredentialAsync { get; set; }

    /// <summary>
    /// Resolves what a §8 Credential Request's <c>jwt</c> key proof(s) must satisfy (the expected
    /// <c>c_nonce</c>, the acceptable proof-signing algorithms, the <c>iat</c> window). Wiring this
    /// seam OPTS IN to library-side Appendix F.4 proof validation at the Credential Endpoint: the
    /// library validates each proof with <see cref="Oid4Vci.CredentialProofValidator"/> BEFORE
    /// <see cref="IssueCredentialAsync"/> is consulted, mapping a failure to the §8.3.1.2
    /// <c>invalid_proof</c> / <c>invalid_nonce</c> error. When this seam is unwired the endpoint
    /// validates no proofs and hands the whole §F.4 check to <see cref="IssueCredentialAsync"/> (the
    /// established default), so every Credential Endpoint deployment that does not set it is
    /// unchanged. The application owns the <c>c_nonce</c> store and its single-use retirement
    /// either way.
    /// </summary>
    public ResolveCredentialProofExpectationDelegate? ResolveCredentialProofExpectationAsync { get; set; }

    /// <summary>
    /// Encrypts an OID4VCI 1.0 §10 (Deferred) Credential Response to the Wallet-supplied key.
    /// Optional — when unwired, a request carrying <c>credential_response_encryption</c> is
    /// refused with <c>invalid_encryption_parameters</c> (fail-closed: §8.3 forbids answering
    /// such a request in clear).
    /// </summary>
    public EncryptCredentialResponseDelegate? EncryptCredentialResponseAsync { get; set; }

    /// <summary>
    /// Decrypts an OID4VCI 1.0 §10 encrypted Credential Request with the Issuer's key from
    /// <c>credential_request_encryption.jwks</c>. Optional — when unwired, a compact-JWE
    /// request body is refused with <c>invalid_credential_request</c>.
    /// </summary>
    public DecryptCredentialRequestDelegate? DecryptCredentialRequestAsync { get; set; }

    /// <summary>
    /// Resolves an OID4VCI 1.0 §9 Deferred Credential Request from the application's
    /// deferred-transaction store. The Deferred Credential Endpoint activates only when the
    /// <see cref="WellKnownCapabilityIdentifiers.Oid4VciDeferredCredentialEndpoint"/> capability
    /// is allowed and this seam is wired — fail-closed: an advertised endpoint without the
    /// store could only refuse every <c>transaction_id</c>.
    /// </summary>
    public ResolveDeferredCredentialDelegate? ResolveDeferredCredentialAsync { get; set; }

    /// <summary>
    /// Processes an OID4VCI 1.0 §11.1 Notification Request. The Notification Endpoint activates
    /// only when the <see cref="WellKnownCapabilityIdentifiers.Oid4VciNotificationEndpoint"/>
    /// capability is allowed and this seam is wired — fail-closed: an advertised endpoint
    /// without the <c>notification_id</c> store could only reject every notification.
    /// </summary>
    public ProcessCredentialNotificationDelegate? ProcessCredentialNotificationAsync { get; set; }

    /// <summary>
    /// Resolves an OID4VCI 1.0 §4.1.3 by-reference Credential Offer from the application's offer
    /// store. The Credential Offer Endpoint activates only when the
    /// <see cref="WellKnownCapabilityIdentifiers.Oid4VciCredentialOfferEndpoint"/> capability is
    /// allowed and this seam is wired — fail-closed: only the application's offer store, keyed by
    /// the id the <c>credential_offer_uri</c> carries, can produce the offer the Wallet fetches.
    /// </summary>
    public ResolveCredentialOfferDelegate? ResolveCredentialOfferAsync { get; set; }

    /// <summary>
    /// Contributes the application-owned values of the OID4VCI 1.0 §12.2 Credential Issuer
    /// Metadata document (<c>credential_configurations_supported</c> and the optional
    /// <c>authorization_servers</c> / <c>display</c> / <c>batch_credential_issuance</c>). The
    /// Credential Issuer Metadata endpoint activates only when the
    /// <see cref="WellKnownCapabilityIdentifiers.Oid4VciCredentialIssuerMetadata"/> capability is
    /// allowed and this seam is wired — the document's REQUIRED
    /// <c>credential_configurations_supported</c> is application data the library cannot derive.
    /// </summary>
    public ContributeCredentialIssuerMetadataDelegate? ContributeCredentialIssuerMetadataAsync { get; set; }

    /// <summary>
    /// Signs the assembled OID4VCI 1.0 §12.2.3 Credential Issuer Metadata as a
    /// <c>signed_metadata</c> JWT. Optional — when set, the returned JWT is embedded in the
    /// document. The application owns the signing key, the algorithm, and the §12.2.3
    /// structural claims (<c>typ</c>, <c>sub</c>, <c>iat</c>).
    /// </summary>
    public SignCredentialIssuerMetadataDelegate? SignCredentialIssuerMetadataAsync { get; set; }

    /// <summary>
    /// Parses a Global Token Revocation request body
    /// (draft-parecki-oauth-global-token-revocation §3) into the neutral
    /// <see cref="Logout.GlobalTokenRevocationRequest"/>. Required when
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthGlobalTokenRevocation"/> is
    /// advertised — the default JSON implementation lives in
    /// <c>Verifiable.OAuth.Json</c> and is wired by the application.
    /// </summary>
    public ParseGlobalTokenRevocationRequestDelegate? ParseGlobalTokenRevocationRequestAsync { get; set; }

    /// <summary>
    /// Revokes all of a subject's tokens for a Global Token Revocation command
    /// (draft-parecki-oauth-global-token-revocation §3). The endpoint activates
    /// only when the <see cref="WellKnownCapabilityIdentifiers.OAuthGlobalTokenRevocation"/>
    /// capability is allowed and the parse seam, this seam, and
    /// <see cref="ValidateClientCredentialsAsync"/> are all wired (fail-closed —
    /// an unauthenticated or no-op global revocation would be dangerous). The
    /// application owns the fan-out (revoke the subject's grants, optionally emit a
    /// CAEP <c>session-revoked</c> signal); the library owns the wire.
    /// </summary>
    public RevokeSubjectTokensDelegate? RevokeSubjectTokensAsync { get; set; }

    /// <summary>
    /// Terminates the End-User's authentication session for an RP-Initiated Logout
    /// (OIDC RP-Initiated Logout 1.0). The <c>end_session_endpoint</c> activates only
    /// when the <see cref="WellKnownCapabilityIdentifiers.OidcRpInitiatedLogout"/>
    /// capability is allowed and this seam plus the verification-key resolver are wired
    /// (the endpoint must verify the <c>id_token_hint</c>). The application owns the
    /// session store and the cascade.
    /// </summary>
    public TerminateSessionDelegate? TerminateSessionAsync { get; set; }

    /// <summary>
    /// Terminates a session identified only by a <c>logout_hint</c> — the sessionless
    /// RP-Initiated Logout path (OIDC RP-Initiated Logout 1.0 §3), taken when the request
    /// carries a <c>logout_hint</c> but no <c>id_token_hint</c>. Optional: when unset the
    /// <c>end_session_endpoint</c> still requires an <c>id_token_hint</c>; wiring it enables
    /// the sessionless branch. The application resolves the opaque hint to a session.
    /// </summary>
    public TerminateSessionByHintDelegate? TerminateSessionByHintAsync { get; set; }

    /// <summary>
    /// Fans a terminated session out to registered RPs as an OIDC Back-Channel Logout
    /// (OIDC Back-Channel Logout 1.0). Optional: when unset the OP performs no back-channel
    /// fan-out and does not advertise <c>backchannel_logout_supported</c>; wiring it activates
    /// the fan-out the end-session endpoint runs after <see cref="TerminateSessionAsync"/>. The
    /// application owns the session→RP list, builds each Logout Token, and delivers it.
    /// </summary>
    public DeliverBackChannelLogoutDelegate? DeliverBackChannelLogoutAsync { get; set; }

    /// <summary>
    /// Classifies a raw token string into a typed
    /// <see cref="Verifiable.JCose.JoseTokenShape"/> by structural inspection.
    /// Optional.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Required only when token-aware matchers are registered (introspection,
    /// revocation, userinfo, OID4VCI proof endpoints). Endpoints whose
    /// matchers do not consume tokens (PAR, JAR, direct_post, JWKS, discovery)
    /// run without this delegate set.
    /// </para>
    /// <para>
    /// Applications typically wire
    /// <see cref="Verifiable.JCose.JoseTokenClassifier.ClassifyAsync"/> as
    /// the implementation, supplying their Base64Url decoder, JOSE header
    /// deserializer, and memory pool. Deployments that issue non-JOSE token
    /// shapes (paseto, biscuit, macaroon) supply their own classifier or
    /// wrap the JCose default with a pre-classification step that
    /// recognizes their shapes first.
    /// </para>
    /// </remarks>
    public ClassifyTokenDelegate? ClassifyTokenAsync { get; set; }

    /// <summary>
    /// Resolves the per-request policy values for the loaded registration and
    /// populates them on the <see cref="ExchangeContext"/> at dispatch entry.
    /// Required.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The dispatcher invokes this delegate once per request after the
    /// registration is loaded but before any matcher executes. Matchers,
    /// validators, and token producers downstream consult policy via the
    /// typed extensions in <see cref="PolicyExchangeContextExtensions"/>.
    /// </para>
    /// <para>
    /// Wire to <see cref="PolicyProfiles.DefaultResolvePolicyAsync"/> for the
    /// library's named-profile dispatch (<c>strict</c>, <c>haip</c>,
    /// <c>rfc6749</c>), or supply a custom delegate for bespoke policy.
    /// </para>
    /// </remarks>
    //ResolvePolicyAsync is the host-generic base seam (ResolveServerPolicyDelegate over
    //IRegistrationRecord); the OAuth wiring adapts its ClientRecord resolver to it.

    /// <summary>
    /// Resolves the <c>aud</c> claim audience(s) for an RFC 9068 access token
    /// at issuance time. Optional — when <see langword="null"/>, the library's
    /// default <see cref="Rfc9068AccessTokenProducer.DefaultResolveAccessTokenAudienceAsync"/>
    /// runs (reads from <see cref="ClientRecord.ScopeToAudience"/>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The producer consults the active
    /// <see cref="AccessTokenAudPolicy"/> from the resolved policy and uses
    /// the audience(s) this delegate returns to populate the <c>aud</c> claim
    /// per <see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.2">RFC 9068 §2.2</see>.
    /// </para>
    /// </remarks>
    public ResolveAccessTokenAudienceDelegate? ResolveAccessTokenAudienceAsync { get; set; }


    /// <summary>
    /// Validates inbound DPoP proofs at the token endpoint per RFC 9449 §4.3.
    /// Library default backing: <see cref="Verifiable.OAuth.Dpop.DpopProofValidator.ValidateAsync"/>
    /// adapted to the <see cref="Verifiable.OAuth.Dpop.ValidateDpopProofDelegate"/>
    /// shape. Required when any registration's <see cref="PolicyProfile"/>
    /// requires DPoP (HAIP 1.0, FAPI 2.0).
    /// </summary>
    public Verifiable.OAuth.Dpop.ValidateDpopProofDelegate? ValidateDpopProofAsync { get; set; }


    /// <summary>
    /// Issues a fresh DPoP nonce on a 401 <c>use_dpop_nonce</c> challenge or
    /// any other condition where the AS wants the client to refresh its
    /// nonce. Library default backing:
    /// <see cref="Verifiable.OAuth.Dpop.DefaultDpopNonceIssuance.IssueAsync"/>.
    /// </summary>
    public Verifiable.OAuth.Dpop.IssueDpopNonceDelegate? IssueDpopNonceAsync { get; set; }


    /// <summary>
    /// Validates a presented DPoP nonce. Library default backing:
    /// <see cref="Verifiable.OAuth.Dpop.DefaultDpopNonceValidation.ValidateAsync"/>.
    /// Issuance and validation must agree on the wire format.
    /// </summary>
    public Verifiable.OAuth.Dpop.ValidateDpopNonceDelegate? ValidateDpopNonceAsync { get; set; }


    /// <summary>
    /// Loads the HMAC key material for a kid chosen by
    /// <see cref="SelectHmacKeyAsync"/> at issuance or extracted from the
    /// wire artefact at validation. Library default backing:
    /// <see cref="Keys.InProcessKeySet.ResolveMaterial"/> wrapped as the
    /// delegate. Multi-instance deployments wire a Vault/KMS-backed
    /// implementation per the same contract.
    /// </summary>
    public ResolveServerHmacKeyDelegate? ResolveServerHmacKeyAsync { get; set; }


    /// <summary>
    /// Returns the current HMAC <see cref="Keys.KeySet"/> for the given
    /// tenant. Issuance feeds this into <see cref="SelectHmacKeyAsync"/>;
    /// validation reads it to check slot membership
    /// (<see cref="Keys.KeySet.IsKidValidForVerification"/>) before
    /// accepting a presented kid; JWKS publication reads it via
    /// <c>Publishable()</c> when the application's
    /// <see cref="AuthorizationServerCryptography.BuildJwksDocumentAsync"/>
    /// opts to publish HMAC keys as <c>kty=oct</c> JWKs per RFC 7518 §6.4
    /// (typically for HS256 access-token verifiers in a private federation,
    /// not for DPoP nonce keys which are server-internal).
    /// </summary>
    public GetHmacKeySetDelegate? GetHmacKeySetAsync { get; set; }


    /// <summary>
    /// Selects which kid to use for a given HMAC operation. When
    /// <see langword="null"/>, the library uses the kid of the first entry
    /// in the keyset's <see cref="Keys.KeySet.Current"/> list.
    /// </summary>
    public SelectHmacKeyDelegate? SelectHmacKeyAsync { get; set; }


    /// <summary>
    /// Resolves the OpenID Connect claim set for an authenticated subject.
    /// Consumed by <see cref="Oidc10IdTokenProducer"/> during ID Token
    /// issuance and by the UserInfo endpoint per OIDC Core §5.3. Required
    /// when the application's <see cref="TokenProducer"/> list includes
    /// <see cref="TokenProducer.Oidc10IdToken"/> or when the UserInfo
    /// endpoint is registered.
    /// </summary>
    public ResolveOidcClaimsDelegate? ResolveOidcClaimsAsync { get; set; }


    /// <summary>
    /// Application seam making the authorization decision at the authorization endpoint
    /// after authentication and the library's own checks. The application may permit or
    /// deny on any requested/established fact — an unsatisfied <c>acr</c> (RFC 9470 §5
    /// step-up), resource-owner consent, or deployment policy — and the library maps a
    /// denial to its OAuth error. See <see cref="EvaluateAuthorizationRequestDelegate"/>
    /// for the contract. Unset means the authorization server applies no additional
    /// decision at this point (the achieved <c>acr</c> is still conveyed in the issued
    /// tokens, and the resource server's step-up challenge remains the backstop). The
    /// temporal <c>max_age</c> recency requirement is enforced by the library directly (it
    /// needs no deployment semantics) and does not go through this seam.
    /// </summary>
    public EvaluateAuthorizationRequestDelegate? EvaluateAuthorizationRequestAsync { get; set; }


    /// <summary>
    /// Validates that the required delegates on this group are set.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when one or more required delegates are missing.
    /// </exception>
    public override void Validate()
    {
        var missing = new List<string>();

        CollectMissingHostSeams(missing);
        if(ResolveSubjectIdentifierAsync is null) { missing.Add(nameof(ResolveSubjectIdentifierAsync)); }

        if(missing.Count > 0)
        {
            var sb = new StringBuilder(
                "AuthorizationServerIntegration is missing required delegates: ");
            sb.AppendJoin(", ", missing);
            sb.Append('.');
            throw new InvalidOperationException(sb.ToString());
        }

        IsValidated = true;
    }


    /// <summary>
    /// Creates the authorization details <c>type</c> registry every integration starts with,
    /// carrying the built-in <c>openid_credential</c> handler so the OID4VCI 1.0 §5.1.1 profile
    /// works without further wiring.
    /// </summary>
    private static AuthorizationDetailTypeRegistry CreateDefaultAuthorizationDetailTypeRegistry()
    {
        AuthorizationDetailTypeRegistry registry = new();
        registry.Register(Oid4Vci.OpenIdCredentialAuthorizationDetailHandler.Handler);

        return registry;
    }


    private readonly EventSubject eventSubject = new();

    /// <summary>
    /// The instance-scoped event stream for client registration lifecycle events.
    /// </summary>
    public IObservable<ClientRegistrationEvent> Events => eventSubject;


    /// <summary>Emits a <see cref="ClientRegistered"/> event.</summary>
    public void RegisterClient(
        ClientRecord registration,
        RegistrationAccessToken accessToken,
        ExchangeContext context,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(timeProvider);

        eventSubject.Emit(new ClientRegistered
        {
            ClientId = registration.ClientId,
            TenantId = registration.TenantId,
            OccurredAt = timeProvider.GetUtcNow(),
            Context = context,
            Registration = registration,
            AccessToken = accessToken
        });
    }


    /// <summary>Emits a <see cref="ClientUpdated"/> event.</summary>
    public void UpdateClient(
        ClientRecord previous,
        ClientRecord current,
        ExchangeContext context,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(timeProvider);

        eventSubject.Emit(new ClientUpdated
        {
            ClientId = current.ClientId,
            TenantId = current.TenantId,
            OccurredAt = timeProvider.GetUtcNow(),
            Context = context,
            Previous = previous,
            Current = current
        });
    }


    /// <summary>Emits a <see cref="ClientDeregistered"/> event.</summary>
    public void DeregisterClient(
        ClientRecord registration,
        string reason,
        ExchangeContext context,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(timeProvider);

        eventSubject.Emit(new ClientDeregistered
        {
            ClientId = registration.ClientId,
            TenantId = registration.TenantId,
            OccurredAt = timeProvider.GetUtcNow(),
            Context = context,
            Reason = reason
        });
    }


    /// <summary>Emits a <see cref="CapabilityGranted"/> event.</summary>
    public void GrantCapability(
        ClientRecord registration,
        CapabilityIdentifier capability,
        ExchangeContext context,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(timeProvider);

        eventSubject.Emit(new CapabilityGranted
        {
            ClientId = registration.ClientId,
            TenantId = registration.TenantId,
            OccurredAt = timeProvider.GetUtcNow(),
            Context = context,
            Capability = capability
        });
    }


    /// <summary>Emits a <see cref="CapabilityRevoked"/> event.</summary>
    public void RevokeCapability(
        ClientRecord registration,
        CapabilityIdentifier capability,
        string reason,
        ExchangeContext context,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(timeProvider);

        eventSubject.Emit(new CapabilityRevoked
        {
            ClientId = registration.ClientId,
            TenantId = registration.TenantId,
            OccurredAt = timeProvider.GetUtcNow(),
            Context = context,
            Capability = capability,
            Reason = reason
        });
    }


    //Instance-scoped copy-on-write event subject. Each integration has its own.
    private sealed class EventSubject: IObservable<ClientRegistrationEvent>
    {
        private volatile IObserver<ClientRegistrationEvent>[] observers = [];
        private readonly object gate = new();


        public IDisposable Subscribe(IObserver<ClientRegistrationEvent> observer)
        {
            ArgumentNullException.ThrowIfNull(observer);

            lock(gate)
            {
                IObserver<ClientRegistrationEvent>[] current = observers;
                IObserver<ClientRegistrationEvent>[] updated =
                    new IObserver<ClientRegistrationEvent>[current.Length + 1];
                current.CopyTo(updated, 0);
                updated[current.Length] = observer;
                observers = updated;
            }

            return new Subscription(this, observer);
        }


        public void Emit(ClientRegistrationEvent value)
        {
            IObserver<ClientRegistrationEvent>[] current = observers;
            foreach(IObserver<ClientRegistrationEvent> observer in current)
            {
                observer.OnNext(value);
            }
        }


        private void Remove(IObserver<ClientRegistrationEvent> observer)
        {
            lock(gate)
            {
                IObserver<ClientRegistrationEvent>[] current = observers;
                int index = Array.IndexOf(current, observer);
                if(index < 0)
                {
                    return;
                }

                IObserver<ClientRegistrationEvent>[] updated =
                    new IObserver<ClientRegistrationEvent>[current.Length - 1];
                Array.Copy(current, 0, updated, 0, index);
                Array.Copy(current, index + 1, updated, index, current.Length - index - 1);
                observers = updated;
            }
        }


        private sealed class Subscription(
            EventSubject subject,
            IObserver<ClientRegistrationEvent> observer): IDisposable
        {
            private bool disposed;

            public void Dispose()
            {
                if(!disposed)
                {
                    subject.Remove(observer);
                    disposed = true;
                }
            }
        }
    }
}
