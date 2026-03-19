using System.Diagnostics;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Configuration and I/O delegates for the Authorization Server handlers.
/// </summary>
/// <remarks>
/// <para>
/// All I/O is supplied via delegates. Construct with property initializers and
/// call <see cref="Validate"/> once at application startup before the HTTP server
/// begins accepting requests.
/// </para>
/// <para>
/// The <see cref="ActionExecutor"/> drives all effectful work between pure PDA
/// transitions — JAR signing, JWE decryption, token issuance. The library provides
/// pre-wired executors for standard profiles such as
/// <see cref="Verifiable.OAuth.Oid4Vp.HaipOid4VpVerifierExecutor"/>. Custom profiles
/// supply their own executor or extend the default one.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthorizationServerOptions Validated={IsValidated}")]
public sealed class AuthorizationServerOptions
{
    /// <summary>
    /// Extracts the <see cref="TenantId"/> from the inbound request. Required.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The dispatcher invokes this delegate at the start of every request, before
    /// any other delegate. The implementation reads whatever signal identifies the
    /// tenant in this deployment — path segment, subdomain, Host header,
    /// client-certificate subject/SAN, a claim in an upstream JWT, or a combination.
    /// </para>
    /// <para>
    /// The resolved <see cref="TenantId"/> is placed on the <see cref="RequestContext"/>
    /// via <see cref="RequestContextExtensions.SetTenantId"/> and threaded through every
    /// storage-bounded delegate (<see cref="LoadClientRegistrationAsync"/>,
    /// <see cref="SaveFlowStateAsync"/>, <see cref="LoadFlowStateAsync"/>,
    /// <see cref="ResolveCorrelationKeyAsync"/>) so the storage layer can enforce
    /// per-tenant isolation by keying records on <c>(tenantId, *)</c> compounds.
    /// </para>
    /// <para>
    /// Returning <see langword="null"/> indicates the request carries no identifiable
    /// tenant; the dispatcher responds with <c>400 invalid_request</c> without invoking
    /// any further delegates.
    /// </para>
    /// </remarks>
    public ExtractTenantIdDelegate? ExtractTenantIdAsync { get; set; }


    /// <summary>
    /// Loads a <see cref="ClientRegistration"/> by client identifier or endpoint segment.
    /// Required.
    /// </summary>
    public LoadClientRegistrationDelegate? LoadClientRegistrationAsync { get; set; }

    /// <summary>
    /// Saves the flow state under the internal <c>flowId</c>. Required.
    /// The key is always the stable internal flow identifier — never an
    /// external handle. The application may pattern-match on the state to
    /// build secondary indexes (e.g., code → flowId).
    /// </summary>
    public SaveServerFlowStateDelegate? SaveFlowStateAsync { get; set; }

    /// <summary>
    /// Loads an <see cref="OAuthFlowState"/> and step count by the internal
    /// <c>flowId</c>. Required. The key has already been resolved from any
    /// external handle by <see cref="ResolveCorrelationKeyAsync"/>.
    /// </summary>
    public LoadServerFlowStateDelegate? LoadFlowStateAsync { get; set; }

    /// <summary>
    /// Resolves an external correlation handle (request_uri token, authorization
    /// code, device_code, etc.) to the stable internal <c>flowId</c> used as the
    /// primary persistence key. Required for flows where the external handle
    /// differs from the <c>flowId</c> (Auth Code with PAR, Device Authorization).
    /// Optional for flows where the external handle is the <c>flowId</c>.
    /// When <see langword="null"/>, the external handle is used directly.
    /// </summary>
    public ResolveCorrelationKeyDelegate? ResolveCorrelationKeyAsync { get; set; }

    /// <summary>
    /// Resolves a private signing key by identifier. Required.
    /// </summary>
    public ServerSigningKeyResolverDelegate? SigningKeyResolver { get; set; }

    /// <summary>
    /// Resolves a private decryption key by identifier. Required when
    /// <see cref="ServerCapabilityName.VerifiablePresentation"/> is enabled.
    /// </summary>
    public ServerDecryptionKeyResolverDelegate? DecryptionKeyResolver { get; set; }

    /// <summary>
    /// Resolves a public key by identifier for verification and JWKS. Required.
    /// </summary>
    public ServerVerificationKeyResolverDelegate? VerificationKeyResolver { get; set; }

    /// <summary>
    /// Selects which <see cref="KeyId"/> to sign with at a given library call
    /// site. Optional. When <see langword="null"/>, the library calls
    /// <see cref="ClientRegistration.GetDefaultSigningKeyId"/> which returns the
    /// first entry in the registration's <c>SigningKeys[usage].Current</c> list.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Applications set this delegate to implement per-caller key binding,
    /// algorithm-specific selection across multi-algorithm deployments, or
    /// any other selection policy that depends on request context. The delegate
    /// receives the full per-request context bag so it can read caller identity,
    /// tenant-scoped attributes, and whatever else the ASP.NET skin chose to
    /// surface.
    /// </para>
    /// <para>
    /// Implementations are expected to return a <see cref="KeyId"/> present in
    /// the registration's <see cref="SigningKeySet.Current"/> list for the
    /// requested usage; returning an identifier outside that list indicates a
    /// misconfigured selection policy.
    /// </para>
    /// </remarks>
    public SelectSigningKeyDelegate? SelectSigningKey { get; set; }

    /// <summary>
    /// Resolves the authorization server's issuer URI (the <c>iss</c> claim
    /// and the base URL advertised in discovery). Optional. When
    /// <see langword="null"/>, the library uses <see cref="DefaultIssuerResolver"/>
    /// which reads <see cref="ClientRegistration.IssuerUri"/> first and falls
    /// back to <see cref="RequestContextExtensions.Issuer"/> on the request
    /// context.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is a cross-cutting resolver — a single-value lookup used by every
    /// endpoint that needs to name the authorization server: the discovery
    /// endpoint, the token endpoint, and future endpoints such as OID4VP JAR
    /// signing. Applications set this delegate to implement per-request,
    /// per-region, or dynamic issuer resolution without reimplementing each
    /// consumer.
    /// </para>
    /// <para>
    /// Contrast with per-token-type issuance hooks (not yet present as of the
    /// time this was written) which assemble coupled claim sets for a single
    /// token type. Issuer is emitted on every token and in metadata documents
    /// regardless of token type, so it lives outside those hooks.
    /// </para>
    /// </remarks>
    public ResolveIssuerDelegate? ResolveIssuerAsync { get; set; }

    /// <summary>
    /// The token producers that compose the response of a token-issuing endpoint.
    /// Optional. When <see langword="null"/>, the library defaults to
    /// <c>[TokenProducer.Rfc9068AccessToken]</c> — single access-token output identical to
    /// the pre-producer-pipeline behaviour.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each entry is a <see cref="TokenProducer"/> bundle: a name, a target response
    /// field, a required capability, an applicability predicate, and a build delegate
    /// returning a <c>(JwtHeader, JwtPayload)</c> pair. The library's token endpoint
    /// walks the list, filters by <see cref="TokenProducer.RequiredCapability"/> and
    /// <see cref="TokenProducer.IsApplicable"/>, calls each producer's
    /// <see cref="TokenProducer.BuildAsync"/>, runs any matching
    /// <see cref="ClaimContributors"/> over the produced payload, signs via
    /// <see cref="JCose.JwtSigningExtensions.SignAsync"/>, and composes the JSON
    /// response from the collected tokens keyed by
    /// <see cref="TokenProducer.ResponseField"/>.
    /// </para>
    /// <para>
    /// Library-shipped producers: <see cref="TokenProducer.Rfc9068AccessToken"/>,
    /// <see cref="TokenProducer.Oidc10IdToken"/>. Applications add their own
    /// (logout tokens, refresh tokens, deployment-specific tokens) via extension
    /// blocks on <see cref="TokenProducer"/>.
    /// </para>
    /// </remarks>
    public IReadOnlyList<TokenProducer>? TokenProducers { get; set; }

    /// <summary>
    /// Claim contributors that decorate token payloads with additional claims during
    /// the token-endpoint pipeline. Optional. When <see langword="null"/>, no
    /// contributors run and producers emit only their base claim set.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each contributor's <see cref="ClaimContributor.IsApplicable"/> receives the
    /// <see cref="TokenProducer"/> currently being processed, so contributors target
    /// specific token types — Verified Claims contributing to the ID token, tenancy
    /// claims contributing to the access token, ACR/AMR contributing to the ID token
    /// based on the flow's authentication events, and so on.
    /// </para>
    /// <para>
    /// Contributors run in list order after the producer's
    /// <see cref="TokenProducer.BuildAsync"/> returns; later contributors overwrite
    /// earlier values for the same claim name.
    /// </para>
    /// </remarks>
    public IReadOnlyList<ClaimContributor>? ClaimContributors { get; set; }

    /// <summary>
    /// Contributes additional fields to the discovery document
    /// (<c>/.well-known/openid-configuration</c> and equivalents). Optional.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The library's discovery endpoint emits its base OAuth 2.0 and OIDC fields first,
    /// then merges the contributed fields over the top. Applications use this delegate
    /// to advertise OIDC-, FAPI-, OID4VP-, OID4VCI-, OpenID Federation-, or
    /// deployment-specific capability fields without replacing the discovery endpoint.
    /// </para>
    /// </remarks>
    public ContributeDiscoveryFieldsDelegate? ContributeDiscoveryFieldsAsync { get; set; }

    /// <summary>
    /// Serializes a <see cref="JwtHeader"/> to UTF-8 JSON bytes. Required.
    /// </summary>
    /// <remarks>
    /// Wire to the application's chosen JSON library. The library does not import
    /// any JSON serialization library; the application decides whether
    /// <c>System.Text.Json</c>, <c>Utf8Json</c>, or another library is used, and
    /// supplies a delegate that calls it.
    /// </remarks>
    public JwtHeaderSerializer? JwtHeaderSerializer { get; set; }

    /// <summary>
    /// Serializes a <see cref="JwtPayload"/> to UTF-8 JSON bytes. Required.
    /// </summary>
    /// <remarks>
    /// Wire to the application's chosen JSON library. See
    /// <see cref="JwtHeaderSerializer"/> for the rationale.
    /// </remarks>
    public JwtPayloadSerializer? JwtPayloadSerializer { get; set; }

    /// <summary>
    /// Builds the <see cref="JwksDocument"/> to serve at the JWKS endpoint. Required
    /// when <see cref="ServerCapabilityName.JwksEndpoint"/> is enabled.
    /// </summary>
    /// <remarks>
    /// Receives the <see cref="ClientRegistration"/> and the full per-request context
    /// bag. The implementation decides which keys to include — typically all active
    /// signing keys for the registration, including keys in a rotation grace period.
    /// The context bag carries whatever the ASP.NET skin chose to surface (tenant ID,
    /// caller IP, billing tier) so the delegate can make per-call decisions.
    /// </remarks>
    public BuildJwksDocumentDelegate? BuildJwksDocumentAsync { get; set; }

    /// <summary>
    /// Context-sensitive capability check. When <see langword="null"/>, falls back
    /// to <see cref="ClientRegistration.IsCapabilityAllowed"/>. Optional.
    /// </summary>
    public IsCapabilityAllowedDelegate? IsCapabilityAllowedAsync { get; set; }

    /// <summary>
    /// Fetches and validates CIMD documents for CIMD clients. Optional.
    /// </summary>
    public ResolveClientMetadataDelegate? ResolveClientMetadataAsync { get; set; }

    /// <summary>
    /// Drives effectful work between pure PDA transitions — JAR signing, JWE
    /// decryption, token issuance. Required.
    /// </summary>
    /// <remarks>
    /// Use <see cref="Verifiable.OAuth.Oid4Vp.HaipOid4VpVerifierExecutor.Create"/> for
    /// the HAIP 1.0 OID4VP Verifier server flow, or supply a custom executor for
    /// other profiles and flow types.
    /// </remarks>
    public OAuthActionExecutor? ActionExecutor { get; set; }

    /// <summary>
    /// Base64url encoder delegate. Required. Used for PKCE code challenge computation,
    /// correlation key encoding, and any other place where the server produces
    /// Base64url-encoded values.
    /// </summary>
    /// <remarks>
    /// Wire from the library's coder registry at startup:
    /// <c>options.Encoder = DefaultCoderSelector.SelectEncoder(WellKnownKeyFormats.PublicKeyJwk);</c>
    /// </remarks>
    public EncodeDelegate? Encoder { get; set; }

    /// <summary>
    /// Base64url decoder delegate. Required. Used for JWE header parsing, JWKS
    /// key coordinate decoding, and any other place where the server consumes
    /// Base64url-encoded values.
    /// </summary>
    /// <remarks>
    /// Wire from the library's coder registry at startup:
    /// <c>options.Decoder = DefaultCoderSelector.SelectDecoder(WellKnownKeyFormats.PublicKeyJwk);</c>
    /// </remarks>
    public DecodeDelegate? Decoder { get; set; }

    /// <summary>
    /// Resolves a <see cref="HashFunctionDelegate"/> by algorithm name. Required.
    /// Called at request time to obtain the hash function for PKCE S256 verification,
    /// authorization code hashing, and any other digest computation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Wire from the library's hash function registry at startup:
    /// <c>options.HashFunctionSelector = DefaultHashFunctionSelector.Select;</c>
    /// </para>
    /// <para>
    /// The selector pattern allows the same server to use different hash algorithms
    /// for different purposes — SHA-256 for PKCE per RFC 7636 §4.2, SHA-512 for
    /// token binding, or post-quantum hash functions when specifications adopt them.
    /// The selector resolves from whatever backends the application registered at
    /// startup via <see cref="CryptoLibrary.InitializeProviders"/>.
    /// </para>
    /// </remarks>
    public HashFunctionSelector? HashFunctionSelector { get; set; }

    /// <summary>
    /// The time source used for expiry, state timestamps, and event timestamps.
    /// Defaults to <see cref="System.TimeProvider.System"/>. Override in tests with
    /// <c>FakeTimeProvider</c>.
    /// </summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;

    /// <summary>
    /// The endpoint builders that define which protocol flows the server supports.
    /// Each builder produces <see cref="ServerEndpoint"/> records for registrations
    /// that have the required capabilities.
    /// </summary>
    /// <remarks>
    /// <para>
    /// There are no "built-in" flows. Every flow — Auth Code, OID4VP, JWKS,
    /// Discovery, Federation, CIBA — is a module registered here. The application
    /// chooses which modules to include at startup.
    /// </para>
    /// <para>
    /// Library-provided modules: <c>AuthCodeEndpoints.Builder</c>,
    /// <c>Oid4VpEndpoints.Builder</c>, <c>MetadataEndpoints.Builder</c>.
    /// Application-provided modules use the same delegate shape and are treated
    /// identically.
    /// </para>
    /// <para>
    /// Example:
    /// </para>
    /// <code>
    /// options.EndpointBuilders =
    /// [
    ///     AuthCodeEndpoints.Builder,
    ///     Oid4VpEndpoints.Builder,
    ///     MetadataEndpoints.Builder,
    ///     MyCustomFlow.Builder
    /// ];
    /// </code>
    /// </remarks>
    public IReadOnlyList<EndpointBuilderDelegate>? EndpointBuilders { get; set; }

    /// <summary>Whether <see cref="Validate"/> has been called successfully.</summary>
    public bool IsValidated { get; private set; }


    /// <summary>
    /// Validates that all required delegates are set.
    /// </summary>
    /// <remarks>
    /// <see cref="ActionExecutor"/> is intentionally not required here — it is only
    /// needed when a flow produces <see cref="OAuthAction"/> values that require
    /// effectful work between PDA transitions, such as the OID4VP Verifier flow.
    /// The Authorization Code server flow does not use it. The dispatcher guards
    /// <c>if(options.ActionExecutor is not null)</c> before calling it.
    /// <see cref="SelectSigningKey"/> is also optional — when unset the library
    /// uses <see cref="ClientRegistration.GetDefaultSigningKeyId"/>.
    /// <see cref="ResolveIssuerAsync"/> is optional — when unset the library
    /// uses <see cref="DefaultIssuerResolver"/>.
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// Thrown when one or more required delegates are missing.
    /// </exception>
    public void Validate()
    {
        var missing = new List<string>();

        if(ExtractTenantIdAsync is null) { missing.Add(nameof(ExtractTenantIdAsync)); }
        if(LoadClientRegistrationAsync is null) { missing.Add(nameof(LoadClientRegistrationAsync)); }
        if(SaveFlowStateAsync is null) { missing.Add(nameof(SaveFlowStateAsync)); }
        if(LoadFlowStateAsync is null) { missing.Add(nameof(LoadFlowStateAsync)); }
        if(SigningKeyResolver is null) { missing.Add(nameof(SigningKeyResolver)); }
        if(VerificationKeyResolver is null) { missing.Add(nameof(VerificationKeyResolver)); }
        if(Encoder is null) { missing.Add(nameof(Encoder)); }
        if(Decoder is null) { missing.Add(nameof(Decoder)); }
        if(HashFunctionSelector is null) { missing.Add(nameof(HashFunctionSelector)); }
        if(JwtHeaderSerializer is null) { missing.Add(nameof(JwtHeaderSerializer)); }
        if(JwtPayloadSerializer is null) { missing.Add(nameof(JwtPayloadSerializer)); }
        if(EndpointBuilders is null || EndpointBuilders.Count == 0)
        {
            missing.Add(nameof(EndpointBuilders));
        }

        if(missing.Count > 0)
        {
            var sb = new StringBuilder(
                "AuthorizationServerOptions is missing required delegates: ");
            sb.AppendJoin(", ", missing);
            sb.Append('.');
            throw new InvalidOperationException(sb.ToString());
        }

        IsValidated = true;
    }


    /// <summary>
    /// Evaluates whether the given client registration is allowed to use a capability.
    /// Uses <see cref="IsCapabilityAllowedAsync"/> when set, otherwise falls back to
    /// <see cref="ClientRegistration.IsCapabilityAllowed"/>.
    /// </summary>
    public ValueTask<bool> CheckCapabilityAsync(
        ClientRegistration registration,
        ServerCapabilityName capability,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        if(IsCapabilityAllowedAsync is not null)
        {
            return IsCapabilityAllowedAsync(registration, capability, context, cancellationToken);
        }

        return ValueTask.FromResult(registration.IsCapabilityAllowed(capability));
    }
}
