using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Server;

namespace Verifiable.Vcalm;

/// <summary>
/// The W3C VCALM 1.0 family integration: the protocol seams the VCALM issuer and verifier endpoints
/// resolve through, registered on a neutral <see cref="EndpointServer"/> via
/// <see cref="EndpointServer.AddIntegration{T}"/> and reached by the endpoints with
/// <see cref="EndpointServerVcalmExtensions.Vcalm(EndpointServer)"/>.
/// </summary>
/// <remarks>
/// <para>
/// Every delegate on this integration has the same shape as the host-generic seams it derives from:
/// the library has a question, the application supplies an answer. The parse seams keep
/// <c>System.Text.Json</c> behind the serialization firewall (their defaults live in
/// <c>Verifiable.Json</c>); the cryptographic seams carry the deployment's Data Integrity
/// primitives; the storage seams own the issued-credential and issued-challenge stores. None of the
/// VCALM members live on the OAuth integration — the two families are siblings on the shared host.
/// </para>
/// <para>
/// A request that reaches a VCALM endpoint when no <see cref="VcalmIntegration"/> is registered
/// fails cleanly: <see cref="EndpointServer.GetIntegration{T}"/> throws an
/// <see cref="System.InvalidOperationException"/> naming the missing integration, exactly as an
/// unwired OAuth seam fails.
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmIntegration")]
public sealed class VcalmIntegration: ServerIntegration
{
    /// <summary>
    /// The maximum request-body size, in bytes, the VCALM 1.0 endpoints accept before answering
    /// HTTP 413. Defaults to the §2.4 RECOMMENDED 10 MB baseline.
    /// </summary>
    public long VcalmMaxRequestBytes { get; set; } = 10L * 1024 * 1024;

    /// <summary>
    /// The default lifetime a §3.6.3 exchange is created with when the create request omits
    /// <c>expires</c> — the PDA expiry boundary past which the exchange (and any challenge bound to it,
    /// §3.6.2) ceases to be valid. Defaults to 15 minutes; a deployment with longer-running mediated
    /// exchanges raises it. An explicit <c>expires</c> in the create body overrides it.
    /// </summary>
    public TimeSpan VcalmExchangeDefaultLifetime { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Parses a VCALM 1.0 §3.3.1 <c>/credentials/verify</c> request body into the neutral
    /// <see cref="VcalmVerifyCredentialRequest"/>. Required when the
    /// <see cref="WellKnownVcalmCapabilities.VcalmVerifier"/> capability is allowed — the verifier
    /// endpoint cannot read its body without it. The default JSON implementation lives in
    /// <c>Verifiable.Json</c> and is wired by the application (serialization firewall).
    /// </summary>
    public ParseVcalmVerifyCredentialDelegate? ParseVcalmVerifyCredentialAsync { get; set; }

    /// <summary>
    /// Parses a VCALM 1.0 §3.3.2 <c>/presentations/verify</c> request body into the neutral
    /// <see cref="VcalmVerifyPresentationRequest"/>. Required when the
    /// <see cref="WellKnownVcalmCapabilities.VcalmVerifier"/> capability is allowed. The default JSON
    /// implementation lives in <c>Verifiable.Json</c>.
    /// </summary>
    public ParseVcalmVerifyPresentationDelegate? ParseVcalmVerifyPresentationAsync { get; set; }

    /// <summary>
    /// The application-supplied Data Integrity verification seams the VCALM 1.0 §3.3.1 / §3.3.2
    /// verifier composes over the Core <c>VerifyAsync</c> surface — the canonicalizer, the DID
    /// resolver, the proof-value codec, the serializers, and the digest function. Optional: when
    /// unwired, the verifier reports every embedded-proof step as unverifiable rather than asserting
    /// it verified (fail-closed). The library does not hardcode the cryptosuite / canonicalization
    /// choice.
    /// </summary>
    public VcalmCredentialVerification? VcalmCredentialVerification { get; set; }

    /// <summary>
    /// Persists a challenge the VCALM 1.0 §3.3.3 <c>/challenges</c> endpoint minted, so a later
    /// §3.3.2 call can gate the presentation's <c>options.challenge</c> against issued challenges.
    /// Optional — when both this and <see cref="ConsumeVcalmChallengeAsync"/> are unwired, the
    /// §3.3.3 endpoint still mints and returns a challenge but the instance does not track issuance.
    /// </summary>
    public PersistVcalmChallengeDelegate? PersistVcalmChallengeAsync { get; set; }

    /// <summary>
    /// Consumes a challenge presented on a VCALM 1.0 §3.3.2 call: returns whether the instance
    /// issued it (§3.3.3 issuance gating). Optional — when unwired, a presented challenge is matched
    /// against the presentation proof only, not gated on issuance.
    /// </summary>
    public ConsumeVcalmChallengeDelegate? ConsumeVcalmChallengeAsync { get; set; }

    /// <summary>
    /// Parses a VCALM 1.0 §3.2.1 <c>/credentials/issue</c> request body into the neutral
    /// <see cref="VcalmIssueCredentialRequest"/>. Required when the
    /// <see cref="WellKnownVcalmCapabilities.VcalmIssuer"/> capability is allowed — the issuer
    /// endpoint cannot read its body without it. The default JSON implementation lives in
    /// <c>Verifiable.Json</c> and is wired by the application (serialization firewall).
    /// </summary>
    public ParseVcalmIssueCredentialDelegate? ParseVcalmIssueCredentialAsync { get; set; }

    /// <summary>
    /// The application-supplied Data Integrity signing seams the VCALM 1.0 §3.2.1 issuer composes
    /// over the Core <c>SignAsync</c> surface — the configured issuer identity, the one-or-more proof
    /// descriptors (signing key, cryptosuite, canonicalizer, codec, serializers, digest), the
    /// existing-proof handling, and the memory pool. Required when the
    /// <see cref="WellKnownVcalmCapabilities.VcalmIssuer"/> capability is allowed — without it the
    /// §3.2.1 endpoint cannot secure a credential (fail-closed; the route does not materialize).
    /// </summary>
    public VcalmCredentialIssuance? VcalmCredentialIssuance { get; set; }

    /// <summary>
    /// Resolves the §3.2.1 issuance configuration for the tenant the current request was dispatched to,
    /// so a single host serves many tenants each securing credentials under its own issuer identity and
    /// signing key — the multi-tenant counterpart of the single, server-global
    /// <see cref="VcalmCredentialIssuance"/>. When wired it SUPERSEDES <see cref="VcalmCredentialIssuance"/>
    /// for the §3.2.1 issuer endpoint; when null, the endpoint reads the flat
    /// <see cref="VcalmCredentialIssuance"/>. A deployment wires exactly one of the two: the flat value
    /// for a single issuer, this resolver for per-tenant issuers. The application keys its per-tenant
    /// store off <c>context.TenantId</c>, exactly as the issued-credential and challenge stores do.
    /// </summary>
    public ResolveVcalmCredentialIssuanceDelegate? ResolveVcalmCredentialIssuanceAsync { get; set; }

    /// <summary>
    /// The §3.2.1 issuance configuration in effect for the current request: the per-tenant
    /// <see cref="ResolveVcalmCredentialIssuanceAsync"/> when wired, otherwise the single, server-global
    /// <see cref="VcalmCredentialIssuance"/>. The issuer endpoint resolves issuance through this so the
    /// single-tenant and multi-tenant wirings share one code path.
    /// </summary>
    /// <param name="context">The per-request context bag, carrying the resolved tenant identity.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The issuance configuration for the request's tenant, or <see langword="null"/> when none is configured.</returns>
    public ValueTask<VcalmCredentialIssuance?> ResolveEffectiveCredentialIssuanceAsync(
        ExchangeContext context,
        CancellationToken cancellationToken) =>
        ResolveVcalmCredentialIssuanceAsync is { } resolve
            ? resolve(context, cancellationToken)
            : ValueTask.FromResult(VcalmCredentialIssuance);

    /// <summary>
    /// Persists a credential the VCALM 1.0 §3.2.1 endpoint secured, keyed by its <c>credentialId</c>,
    /// so the §3.2.2 / §3.2.3 retrieval / deletion interfaces can reach it. Optional — when unwired
    /// the issuer is stateless and the §3.2.2 / §3.2.3 MAY interfaces do not materialize.
    /// </summary>
    public StoreVcalmIssuedCredentialDelegate? StoreVcalmIssuedCredentialAsync { get; set; }

    /// <summary>
    /// Loads a stored issued credential by id for the §3.2.2 <c>GET /credentials/{id}</c> endpoint.
    /// Optional — when unwired the §3.2.2 retrieval interface does not materialize.
    /// </summary>
    public LoadVcalmIssuedCredentialDelegate? LoadVcalmIssuedCredentialAsync { get; set; }

    /// <summary>
    /// Soft-deletes a stored issued credential by id for the §3.2.3 <c>DELETE /credentials/{id}</c>
    /// endpoint. Optional — when unwired the §3.2.3 deletion interface does not materialize. B.3
    /// (deletion semantics: partial vs complete, status side-effects) is the application's concern
    /// behind this seam.
    /// </summary>
    public DeleteVcalmIssuedCredentialDelegate? DeleteVcalmIssuedCredentialAsync { get; set; }

    /// <summary>
    /// Parses a VCALM 1.0 §C.3 <c>/credentials/status</c> request body into the neutral
    /// <see cref="VcalmUpdateStatusRequest"/>. Required when the
    /// <see cref="WellKnownVcalmCapabilities.VcalmStatus"/> capability is allowed — the §C.3 endpoint
    /// cannot read its body without it. The default JSON implementation lives in
    /// <c>Verifiable.Json</c> and is wired by the application (serialization firewall).
    /// </summary>
    public ParseVcalmUpdateStatusDelegate? ParseVcalmUpdateStatusAsync { get; set; }

    /// <summary>
    /// Applies a §C.3 status update behind the application's storage boundary (load the status-list
    /// credential, set / clear the bit, re-secure and persist). Required when the
    /// <see cref="WellKnownVcalmCapabilities.VcalmStatus"/> capability is allowed — the §1.3 binding
    /// §C.3 endpoint cannot mutate a status without it (fail-closed; the route does not materialize).
    /// </summary>
    public UpdateVcalmCredentialStatusDelegate? UpdateVcalmCredentialStatusAsync { get; set; }

    /// <summary>
    /// Parses a VCALM 1.0 §C.1 <c>/status-lists</c> request body into the neutral
    /// <see cref="VcalmCreateStatusListRequest"/>. Required for the §C.1 MAY endpoint to materialize.
    /// The default JSON implementation lives in <c>Verifiable.Json</c>.
    /// </summary>
    public ParseVcalmCreateStatusListDelegate? ParseVcalmCreateStatusListAsync { get; set; }

    /// <summary>
    /// The application-supplied Data Integrity signing configuration the §C.1
    /// <c>POST /status-lists</c> endpoint composes to secure a NEW status-list credential. §C.1: "the
    /// status list credential typically uses the same securing mechanism … as the verifiable
    /// credentials it will be linked to." Reuse the issuer service's
    /// <see cref="VcalmCredentialIssuance"/> value here, or supply a distinct one for a stand-alone
    /// status service. Required for the §C.1 MAY endpoint to materialize.
    /// </summary>
    public VcalmCredentialIssuance? VcalmStatusListIssuance { get; set; }

    /// <summary>
    /// Resolves the §C.1 status-list signing configuration for the tenant the current request was
    /// dispatched to, so a single host serves many tenants each securing their status lists under their
    /// own issuer identity and key — the multi-tenant counterpart of the single, server-global
    /// <see cref="VcalmStatusListIssuance"/>. When wired it SUPERSEDES <see cref="VcalmStatusListIssuance"/>
    /// for the §C.1 endpoint; when null, the endpoint reads the flat value.
    /// </summary>
    public ResolveVcalmCredentialIssuanceDelegate? ResolveVcalmStatusListIssuanceAsync { get; set; }

    /// <summary>
    /// The §C.1 status-list signing configuration in effect for the current request: the per-tenant
    /// <see cref="ResolveVcalmStatusListIssuanceAsync"/> when wired, otherwise the single, server-global
    /// <see cref="VcalmStatusListIssuance"/>.
    /// </summary>
    /// <param name="context">The per-request context bag, carrying the resolved tenant identity.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The status-list issuance for the request's tenant, or <see langword="null"/> when none.</returns>
    public ValueTask<VcalmCredentialIssuance?> ResolveEffectiveStatusListIssuanceAsync(
        ExchangeContext context,
        CancellationToken cancellationToken) =>
        ResolveVcalmStatusListIssuanceAsync is { } resolve
            ? resolve(context, cancellationToken)
            : ValueTask.FromResult(VcalmStatusListIssuance);

    /// <summary>
    /// The number of entries a NEW §C.1 status list holds. Defaults to the W3C Bitstring Status List
    /// §3.2 herd-privacy minimum (131072). A larger value is permitted; a smaller one is rejected by
    /// the codec.
    /// </summary>
    public int VcalmStatusListEntryCount { get; set; } = Verifiable.Core.StatusList.BitstringStatusListCodec.MinimumEntries;

    /// <summary>
    /// Persists a status-list credential the §C.1 endpoint secured, keyed by its <c>id</c>, so the
    /// §C.2 <c>GET /status-lists/{id}</c> interface can retrieve it. Optional — when unwired the §C.1
    /// endpoint still secures and returns the list but the instance does not retain it.
    /// </summary>
    public StoreVcalmStatusListDelegate? StoreVcalmStatusListAsync { get; set; }

    /// <summary>
    /// Loads a stored status-list credential by id for the §C.2 <c>GET /status-lists/{id}</c>
    /// endpoint. Optional — when unwired the §C.2 retrieval interface does not materialize. §C.2 is
    /// "typically publicly accessible without authentication" (the §C privacy guidance prefers
    /// holders carrying the list over verifiers phoning home).
    /// </summary>
    public LoadVcalmStatusListDelegate? LoadVcalmStatusListAsync { get; set; }

    /// <summary>
    /// Resolves the decoded W3C Bitstring Status List a verified credential's
    /// <see cref="Core.StatusList.BitstringStatusListEntry"/> points at, so the §3.3.1 / §3.3.2
    /// verifier can read the status bit and classify a revoked / suspended status as a §3.8.1
    /// WARNING. Optional — when unwired (or when it returns <see langword="null"/>) a credential's
    /// status is left unresolved and no status warning is emitted (an undeterminable status is not
    /// asserted as revoked). Carried on the verifier-facing surface because the verifier composes it;
    /// the §C privacy guidance prefers the holder supplying the list over a verifier fetch.
    /// </summary>
    public ResolveVcalmStatusListDelegate? ResolveVcalmStatusListAsync { get; set; }

    /// <summary>
    /// Parses a VCALM 1.0 §3.5.1 <c>/credentials/derive</c> request body into the neutral
    /// <see cref="VcalmDeriveCredentialRequest"/>. Required when the
    /// <see cref="WellKnownVcalmCapabilities.VcalmHolder"/> capability is allowed — the §3.5.1 endpoint
    /// cannot read its body without it. The default JSON implementation lives in <c>Verifiable.Json</c>
    /// and is wired by the application (serialization firewall).
    /// </summary>
    public ParseVcalmDeriveCredentialDelegate? ParseVcalmDeriveCredentialAsync { get; set; }

    /// <summary>
    /// The application-supplied ecdsa-sd-2023 selective-disclosure derive seams the VCALM 1.0 §3.5.1
    /// holder endpoint composes over the Core <c>DeriveProofAsync</c> surface — the canonicalizer, the
    /// statement partitioner, the JSON-LD fragment selector, the base / derived proof codecs, the
    /// serializers, the base64url codec, and the memory pool. Required when the
    /// <see cref="WellKnownVcalmCapabilities.VcalmHolder"/> capability is allowed — without it the
    /// §3.5.1 endpoint cannot derive a credential (fail-closed; the route does not materialize). The
    /// library does not hardcode the cryptosuite / canonicalization choice.
    /// </summary>
    public VcalmCredentialDerivation? VcalmCredentialDerivation { get; set; }

    /// <summary>
    /// Resolves the §3.5.1 derive configuration for the tenant the current request was dispatched to, so
    /// a single host serves many holder tenants each deriving under their own keys — the multi-tenant
    /// counterpart of the single, server-global <see cref="VcalmCredentialDerivation"/>. When wired it
    /// SUPERSEDES <see cref="VcalmCredentialDerivation"/> for the §3.5.1 endpoint.
    /// </summary>
    public ResolveVcalmCredentialDerivationDelegate? ResolveVcalmCredentialDerivationAsync { get; set; }

    /// <summary>
    /// The §3.5.1 derive configuration in effect for the current request: the per-tenant
    /// <see cref="ResolveVcalmCredentialDerivationAsync"/> when wired, otherwise the single,
    /// server-global <see cref="VcalmCredentialDerivation"/>.
    /// </summary>
    /// <param name="context">The per-request context bag, carrying the resolved tenant identity.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The derive configuration for the request's tenant, or <see langword="null"/> when none.</returns>
    public ValueTask<VcalmCredentialDerivation?> ResolveEffectiveCredentialDerivationAsync(
        ExchangeContext context,
        CancellationToken cancellationToken) =>
        ResolveVcalmCredentialDerivationAsync is { } resolve
            ? resolve(context, cancellationToken)
            : ValueTask.FromResult(VcalmCredentialDerivation);

    /// <summary>
    /// Parses a VCALM 1.0 §3.5.2 <c>/presentations</c> request body into the neutral
    /// <see cref="VcalmCreatePresentationRequest"/>. Required when the
    /// <see cref="WellKnownVcalmCapabilities.VcalmHolder"/> capability is allowed — the §3.5.2 endpoint
    /// cannot read its body without it. The default JSON implementation lives in <c>Verifiable.Json</c>.
    /// </summary>
    public ParseVcalmCreatePresentationDelegate? ParseVcalmCreatePresentationAsync { get; set; }

    /// <summary>
    /// The application-supplied presentation Data Integrity signing seams the VCALM 1.0 §3.5.2 holder
    /// endpoint composes over the Core <c>SignAsync</c> surface — the holder signing key, the default
    /// verification method, the cryptosuite, the canonicalizer, the proof-value codec, the serializers,
    /// the digest, and the memory pool. Required when the
    /// <see cref="WellKnownVcalmCapabilities.VcalmHolder"/> capability is allowed — without it the
    /// §3.5.2 endpoint cannot secure a presentation (fail-closed; the route does not materialize).
    /// </summary>
    public VcalmPresentationSigning? VcalmPresentationSigning { get; set; }

    /// <summary>
    /// Resolves the §3.5.2 presentation-signing configuration for the tenant the current request was
    /// dispatched to, so a single host serves many holder tenants each signing presentations under
    /// their own key — the multi-tenant counterpart of the single, server-global
    /// <see cref="VcalmPresentationSigning"/>. When wired it SUPERSEDES <see cref="VcalmPresentationSigning"/>
    /// for the §3.5.2 endpoint.
    /// </summary>
    public ResolveVcalmPresentationSigningDelegate? ResolveVcalmPresentationSigningAsync { get; set; }

    /// <summary>
    /// The §3.5.2 presentation-signing configuration in effect for the current request: the per-tenant
    /// <see cref="ResolveVcalmPresentationSigningAsync"/> when wired, otherwise the single, server-global
    /// <see cref="VcalmPresentationSigning"/>.
    /// </summary>
    /// <param name="context">The per-request context bag, carrying the resolved tenant identity.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The presentation-signing configuration for the request's tenant, or <see langword="null"/> when none.</returns>
    public ValueTask<VcalmPresentationSigning?> ResolveEffectivePresentationSigningAsync(
        ExchangeContext context,
        CancellationToken cancellationToken) =>
        ResolveVcalmPresentationSigningAsync is { } resolve
            ? resolve(context, cancellationToken)
            : ValueTask.FromResult(VcalmPresentationSigning);

    /// <summary>
    /// Persists a presentation the VCALM 1.0 §3.5.2 endpoint secured, keyed by its id, so the §3.5.3 /
    /// §3.5.4 / §3.5.5 listing / retrieval / deletion interfaces can reach it. Optional — when unwired
    /// the holder is stateless and the §3.5.3 / §3.5.4 / §3.5.5 MAY interfaces do not materialize.
    /// </summary>
    public StoreVcalmPresentationDelegate? StoreVcalmPresentationAsync { get; set; }

    /// <summary>
    /// Lists the stored presentations the §3.5.3 <c>GET /presentations</c> endpoint returns. Optional —
    /// when unwired the §3.5.3 listing interface does not materialize.
    /// </summary>
    public ListVcalmPresentationsDelegate? ListVcalmPresentationsAsync { get; set; }

    /// <summary>
    /// Loads a stored presentation by id for the §3.5.4 <c>GET /presentations/{id}</c> endpoint.
    /// Optional — when unwired the §3.5.4 retrieval interface does not materialize.
    /// </summary>
    public LoadVcalmPresentationDelegate? LoadVcalmPresentationAsync { get; set; }

    /// <summary>
    /// Soft-deletes a stored presentation by id for the §3.5.5 <c>DELETE /presentations/{id}</c>
    /// endpoint. Optional — when unwired the §3.5.5 deletion interface does not materialize. B.3
    /// (deletion semantics) is the application's concern behind this seam.
    /// </summary>
    public DeleteVcalmPresentationDelegate? DeleteVcalmPresentationAsync { get; set; }

    /// <summary>
    /// Parses a VCALM 1.0 §3.6.3 <c>POST /workflows/{localWorkflowId}/exchanges</c> create-exchange
    /// request body into the neutral <see cref="VcalmCreateExchangeRequest"/>. Required when the
    /// <see cref="WellKnownVcalmCapabilities.VcalmExchange"/> capability is allowed — the create-exchange
    /// endpoint cannot read its body without it. The default JSON implementation lives in
    /// <c>Verifiable.Json</c> and is wired by the application (serialization firewall).
    /// </summary>
    public ParseVcalmCreateExchangeDelegate? ParseVcalmCreateExchangeAsync { get; set; }

    /// <summary>
    /// Parses a VCALM 1.0 §3.6.5 vcapi protocol message body into the neutral
    /// <see cref="VcalmExchangeMessage"/>. Required when the
    /// <see cref="WellKnownVcalmCapabilities.VcalmExchange"/> capability is allowed — the §1.3 conforming
    /// §3.6.5 participate endpoint cannot read its body without it. The default JSON implementation
    /// lives in <c>Verifiable.Json</c>.
    /// </summary>
    public ParseVcalmExchangeMessageDelegate? ParseVcalmExchangeMessageAsync { get; set; }

    /// <summary>
    /// Resolves a §3.6 exchange's <c>{localExchangeId}</c> to the internal flow id its PDA
    /// <c>FlowState</c> is persisted under, for the stateless §3.6.4 protocols and §3.6.6 state reads.
    /// Required when the <see cref="WellKnownVcalmCapabilities.VcalmExchange"/> capability is allowed —
    /// without it the engine cannot find an exchange's persisted state (fail-closed; the §3.6 routes do
    /// not materialize). The §3.6 view is rendered from the loaded <c>FlowState</c>, so the application
    /// keeps only the exchange-id → flow-id index, not a separate exchange store. A
    /// <see langword="null"/> result is the §3.6 404 (unknown exchange).
    /// </summary>
    public ResolveVcalmExchangeFlowIdDelegate? ResolveVcalmExchangeFlowIdAsync { get; set; }

    /// <summary>
    /// The application-supplied Data Integrity verification seams the §3.6.5 exchange engine composes
    /// to verify a <c>verifiablePresentation</c> a holder presents during a vcapi step (the same
    /// <see cref="VcalmCredentialVerification"/> shape the §3.3.2 verifier uses). Optional — when
    /// unwired (or when set to the verifier-role value) the engine reuses
    /// <see cref="VcalmCredentialVerification"/>; an exchange role co-hosted with a verifier role
    /// shares the one configuration. When neither is wired the engine cannot verify a presented
    /// presentation and rejects the step (fail-closed).
    /// </summary>
    public VcalmCredentialVerification? VcalmExchangeVerification { get; set; }

    /// <summary>
    /// The §3.6.5 verification configuration the exchange engine uses, preferring the dedicated
    /// <see cref="VcalmExchangeVerification"/> and falling back to the shared
    /// <see cref="VcalmCredentialVerification"/> the §3.3.2 verifier composes. The exchange engine and
    /// the verifier verify presentations the same way (against the bound challenge / domain), so a
    /// deployment that wires only the verifier-role configuration gets exchange verification for free.
    /// </summary>
    public VcalmCredentialVerification? EffectiveExchangeVerification =>
        VcalmExchangeVerification ?? VcalmCredentialVerification;

    /// <summary>
    /// Decides the engine's next §3.6.5 vcapi move for an exchange — the application's step logic.
    /// Required when the <see cref="WellKnownVcalmCapabilities.VcalmExchange"/> capability is allowed —
    /// the engine ships no built-in workflow, so without it the §3.6.5 participate endpoint cannot
    /// decide what to ask of or offer the client (fail-closed; the route does not materialize). The
    /// V-5c workflow surface layers an admin-authored step graph behind this seam.
    /// </summary>
    public ResolveVcalmExchangeStepDelegate? ResolveVcalmExchangeStepAsync { get; set; }

    /// <summary>
    /// The §3.6.1 credential-template evaluation seam — the registry the workflow surface (V-5c)
    /// consumes to turn an issue request's template + exchange variables into a credential body.
    /// Defaults to a registry with the two built-in evaluators wired: <c>jsonata</c> backed by the
    /// minimal in-repo JSONata engine in <c>Verifiable.JsonPointer</c>, and a <c>literal</c>
    /// pass-through. A deployment registers the full JSONata engine from <c>Lumoin.Veritas</c> for
    /// <c>jsonata</c> through <see cref="VcalmTemplateEvaluatorRegistry.Register"/> to supersede the
    /// minimal one as the production evaluator. The seam carries the neutral JSON model, not
    /// <c>System.Text.Json</c> (serialization firewall).
    /// </summary>
    public VcalmTemplateEvaluatorRegistry VcalmTemplateEvaluators { get; set; } = new();

    /// <summary>
    /// Parses a VCALM 1.0 §3.6.1 <c>POST /workflows</c> create-workflow request body into the neutral
    /// <see cref="VcalmWorkflowConfiguration"/>. Required when the
    /// <see cref="WellKnownVcalmCapabilities.VcalmAdministration"/> capability is allowed — the create
    /// endpoint cannot read its body without it. The default JSON implementation lives in
    /// <c>Verifiable.Json</c> and is wired by the application (serialization firewall).
    /// </summary>
    public ParseVcalmCreateWorkflowDelegate? ParseVcalmCreateWorkflowAsync { get; set; }

    /// <summary>
    /// Persists a §3.6.1 workflow configuration the <c>POST /workflows</c> endpoint accepted, keyed by
    /// its <c>{localWorkflowId}</c>. Required when the
    /// <see cref="WellKnownVcalmCapabilities.VcalmAdministration"/> capability is allowed — without it
    /// the §3.6.1 create endpoint cannot retain the workflow (fail-closed; the route does not
    /// materialize). The application owns the workflow store behind this seam.
    /// </summary>
    public StoreVcalmWorkflowDelegate? StoreVcalmWorkflowAsync { get; set; }

    /// <summary>
    /// Loads a §3.6.1 workflow configuration by its <c>{localWorkflowId}</c> for the §3.6.2
    /// <c>GET /workflows/{localWorkflowId}</c> read. Required when the
    /// <see cref="WellKnownVcalmCapabilities.VcalmAdministration"/> capability is allowed — without it
    /// the §3.6.2 read cannot find a workflow (fail-closed; the route does not materialize). A
    /// <see langword="null"/> result is the §3.6.2 404 (unknown workflow).
    /// </summary>
    public LoadVcalmWorkflowDelegate? LoadVcalmWorkflowAsync { get; set; }

    /// <summary>
    /// Resolves the §3.6.1 workflow configuration an exchange runs on, given the exchange's
    /// <c>{localExchangeId}</c>, so the §3.6.5 engine DRIVES its step decisions off the admin-authored
    /// step graph. Optional — when wired, the exchange engine's default step logic reads the step graph
    /// (the V-5c workflow surface); when unwired, the engine falls back to the explicit
    /// <see cref="ResolveVcalmExchangeStepAsync"/> seam. A deployment may wire BOTH: the explicit seam
    /// is a per-deployment override of the config-derived default.
    /// </summary>
    public ResolveVcalmWorkflowForExchangeDelegate? ResolveVcalmWorkflowForExchangeAsync { get; set; }

    /// <summary>
    /// The application-supplied Data Integrity signing configuration the §3.6 exchange engine composes
    /// to MINT a credential for a step's <c>issueRequests</c> (the issuance-in-exchange direction): the
    /// engine evaluates the named <c>credentialTemplate</c> against the exchange variables through
    /// <see cref="VcalmTemplateEvaluators"/>, signs the produced credential here, and offers it back
    /// over vcapi as a <c>verifiablePresentation</c>. Reuse the issuer service's
    /// <see cref="VcalmCredentialIssuance"/> value here, or supply a distinct one. Optional — when
    /// unwired, a step with <c>issueRequests</c> cannot mint and the engine rejects the step
    /// (fail-closed: an exchange that cannot honour its workflow's issuance step does not complete it).
    /// </summary>
    public VcalmCredentialIssuance? VcalmExchangeIssuance { get; set; }

    /// <summary>
    /// Resolves the §3.6 issuance-in-exchange signing configuration for the tenant the current request
    /// was dispatched to, so a single host serves many tenants each minting exchange credentials under
    /// their own issuer identity and key — the multi-tenant counterpart of the dedicated, server-global
    /// <see cref="VcalmExchangeIssuance"/>. When wired it SUPERSEDES <see cref="VcalmExchangeIssuance"/>
    /// for the §3.6 engine; when null, the engine reads the flat value, then the issuer fallback.
    /// </summary>
    public ResolveVcalmCredentialIssuanceDelegate? ResolveVcalmExchangeIssuanceAsync { get; set; }

    /// <summary>
    /// The §3.6 issuance-in-exchange signing configuration in effect for the current request, preferring
    /// the per-tenant <see cref="ResolveVcalmExchangeIssuanceAsync"/>, then the dedicated flat
    /// <see cref="VcalmExchangeIssuance"/>, then falling back to the issuer-role
    /// <see cref="ResolveEffectiveCredentialIssuanceAsync"/> (itself per-tenant or flat). An exchange
    /// role co-hosted with an issuer role shares the one signing configuration; a stand-alone workflow
    /// service wires the dedicated value or resolver.
    /// </summary>
    /// <param name="context">The per-request context bag, carrying the resolved tenant identity.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The exchange issuance for the request's tenant, or <see langword="null"/> when none resolves.</returns>
    public async ValueTask<VcalmCredentialIssuance?> ResolveEffectiveExchangeIssuanceAsync(
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        if(ResolveVcalmExchangeIssuanceAsync is { } resolve)
        {
            VcalmCredentialIssuance? perTenant = await resolve(context, cancellationToken).ConfigureAwait(false);
            if(perTenant is not null)
            {
                return perTenant;
            }
        }

        return VcalmExchangeIssuance
            ?? await ResolveEffectiveCredentialIssuanceAsync(context, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Parses a VCALM 1.0 §3.6.7 <c>POST /callbacks/{localCallbackId}</c> request body into the neutral
    /// <see cref="VcalmCallbackRequest"/>. Required when the
    /// <see cref="WellKnownVcalmCapabilities.VcalmAdministration"/> capability is allowed (the §3.6.7
    /// callback endpoint is part of the workflow service). The default JSON implementation lives in
    /// <c>Verifiable.Json</c>.
    /// </summary>
    public ParseVcalmCallbackDelegate? ParseVcalmCallbackAsync { get; set; }

    /// <summary>
    /// Delivers a §3.6.7 step callback by POSTing the engine-composed <c>{event{data{exchangeId}}}</c>
    /// body to the step's <c>callback.url</c>. The library carries no <c>System.Net.*</c> — the
    /// outbound HTTP POST is the application's, behind this seam. Optional — when unwired, a step that
    /// names a callback does not fire it.
    /// </summary>
    public DeliverVcalmCallbackDelegate? DeliverVcalmCallbackAsync { get; set; }

    /// <summary>
    /// Adapts a verbatim JSON fragment to the neutral <see cref="JsonPointer.Jsonata.JsonataValue"/>
    /// model the §3.6 exchange engine feeds to the credential-template evaluation (the exchange's
    /// <c>variables.results</c> and an issue request's per-request <c>variables</c>). The default JSON
    /// implementation lives in <c>Verifiable.Json</c> (serialization firewall). Optional — when unwired,
    /// an <c>issueRequests</c> template is evaluated against an empty variable context, so a constant
    /// (literal) credential body still renders but a variable-referencing template navigates to nothing.
    /// </summary>
    public ParseVcalmTemplateInputDelegate? ParseVcalmTemplateInputAsync { get; set; }

    /// <summary>
    /// Resolves the §3.7.4 protocols map for a §3.7.1 interaction id — the protocol identifier →
    /// initiation URL pairs the coordinator advertises for the interaction. Required when the
    /// <see cref="WellKnownVcalmCapabilities.VcalmCoordinator"/> capability is allowed — without it the
    /// §3.7.4 interaction-protocols-response endpoint cannot answer (fail-closed; the route does not
    /// materialize). A <see langword="null"/> result is the §3.7.4 404 (unknown interaction). The §3.7.6
    /// vcapi entry in the resolved map addresses a §3.6 exchange's §3.6.5 participate URL — the
    /// coordinator points at the §3.6 engine rather than re-implementing it.
    /// </summary>
    public ResolveVcalmInteractionProtocolsDelegate? ResolveVcalmInteractionProtocolsAsync { get; set; }

    /// <summary>
    /// Parses a §3.7.5 inviteRequest body into the neutral <see cref="VcalmInviteRequest"/>. Required
    /// when the <see cref="WellKnownVcalmCapabilities.VcalmCoordinator"/> capability is allowed — the
    /// §3.7.5 endpoint cannot read its body without it. The default JSON implementation lives in
    /// <c>Verifiable.Json</c> and is wired by the application (serialization firewall).
    /// </summary>
    public ParseVcalmInviteRequestDelegate? ParseVcalmInviteRequestAsync { get; set; }

    /// <summary>
    /// Records a §3.7.5 inviteRequest the coordinator accepted, keyed by the <c>{localInviteId}</c> path
    /// segment. Optional — when unwired the §3.7.5 endpoint still validates and accepts the invitation
    /// (200) but the coordinator does not retain it. The application owns the invite store behind this
    /// seam.
    /// </summary>
    public StoreVcalmInviteRequestDelegate? StoreVcalmInviteRequestAsync { get; set; }
}
