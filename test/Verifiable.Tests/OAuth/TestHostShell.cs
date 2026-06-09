using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.Model.SelectiveDisclosure.Strategy;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.Server.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Oidc;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Audit;
using Verifiable.OAuth.Server.Keys;
using Verifiable.OAuth.Server.States;
using Verifiable.Core.Assessment;
using Verifiable.OAuth.Validation;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.Server.Metadata;
using Verifiable.OAuth.Server.Registration;
namespace Verifiable.Tests.OAuth;

/// <summary>
/// An in-memory test host that mirrors what a production ASP.NET application does
/// at startup: creates an <see cref="AuthorizationServer"/> instance, wires all I/O
/// delegates to in-memory stores, subscribes to events, and registers clients.
/// </summary>
/// <remarks>
/// <para>
/// This is the test equivalent of <c>Program.cs</c>. In production the host is
/// ASP.NET with Kestrel, Dapper, PostgreSQL, and whatever other infrastructure
/// the deployment requires. Here the host is a plain class with
/// <see cref="ConcurrentDictionary{TKey,TValue}"/> stores. The
/// <see cref="AuthorizationServer"/> underneath is identical in both cases.
/// </para>
/// <para>
/// The host is responsible for infrastructure concerns only: key material storage,
/// flow state persistence, client registration routing, issuer trust resolution,
/// and HTTP dispatch. It never contains protocol logic, cryptographic verification,
/// or flow state machine knowledge — those belong to the library. The host provides
/// delegates that connect the library to external storage and trust frameworks.
/// </para>
/// <para>
/// Every test suite uses this — Auth Code PKCE, OID4VP, Federation, attack
/// mitigation — differing only in which capabilities each registered client has.
/// All algorithms are registered: P-256, P-384, P-521, Ed25519, secp256k1,
/// RSA-2048, ML-DSA-44/65/87. The key type used per client is determined at
/// registration time.
/// </para>
/// <para>
/// The host does NOT contain client actions. Browser redirect simulation lives
/// in <see cref="TestBrowser"/>. OAuth client logic lives in
/// <see cref="AuthCodeClient"/>. Wallet logic lives in <see cref="TestWallet"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("TestHostShell Clients={Default.Registrations.Count} Flows={Default.FlowStates.Count}")]
internal sealed class TestHostShell: IAsyncDisposable
{
    //All per-host state lives on the Default HostedAuthorizationServer.
    //Property accessors below mirror the historical field names so methods
    //on TestHostShell continue to compile unchanged. Multi-host tests get
    //additional hosts via Hosts (TODO follow-up).
    private HostedAuthorizationServer Default { get; }

    //Property aliases — same names the integration-delegate lambdas in the
    //constructor close over. Each access goes to the Default host's state.
    private ConcurrentDictionary<string, ClientRecord> Registrations => Default.Registrations;
    private ConcurrentDictionary<string, (OAuthFlowState State, int StepCount)> FlowStates => Default.FlowStates;
    private ConcurrentDictionary<string, string> RequestUriTokenIndex => Default.RequestUriTokenIndex;
    private ConcurrentDictionary<string, string> CodeIndex => Default.CodeIndex;
    private ConcurrentDictionary<string, string> JtiIndex => Default.JtiIndex;
    private ConcurrentDictionary<string, string> AccessTokenIndex => Default.AccessTokenIndex;
    private ConcurrentDictionary<string, string> RefreshTokenIndex => Default.RefreshTokenIndex;
    private ConcurrentDictionary<KeyId, PrivateKeyMemory> SigningKeys => Default.SigningKeys;
    private ConcurrentDictionary<KeyId, PublicKeyMemory> VerificationKeys => Default.VerificationKeys;
    private ConcurrentDictionary<KeyId, PrivateKeyMemory> DecryptionKeys => Default.DecryptionKeys;
    private ConcurrentDictionary<string, string> RegistrationAccessTokens => Default.RegistrationAccessTokens;

    private List<IDisposable> DpopOwnedDisposables { get; } = [];
    private InProcessKeySet? DpopHmacKeySet { get; set; }
    private bool Disposed { get; set; }

    private global::Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServer? KestrelServer
    {
        get => Default.KestrelServer;
        set => Default.KestrelServer = value;
    }
    private Uri? HttpBaseAddress
    {
        get => Default.HttpBaseAddress;
        set => Default.HttpBaseAddress = value;
    }
    private System.Net.Http.HttpClient? SharedHttpClient
    {
        get => Default.SharedHttpClient;
        set => Default.SharedHttpClient = value;
    }

    /// <summary>Base64Url encoder shared by tests with the host's own wiring.</summary>
    public static EncodeDelegate Base64UrlEncoder => TestSetup.Base64UrlEncoder;

    /// <summary>Base64Url decoder shared by tests with the host's own wiring.</summary>
    public static DecodeDelegate Base64UrlDecoder => TestSetup.Base64UrlDecoder;

    /// <summary>The memory pool used by the host for sensitive allocations.</summary>
    public static MemoryPool<byte> MemoryPool => SensitiveMemoryPool<byte>.Shared;

    /// <summary>
    /// Constant tenant segment used by dynamic-registration tests. The
    /// global RFC 7591 POST has no segment in the URL, so the test transport
    /// supplies this value to <see cref="RegistrationEndpoints.HandleCreateAsync"/>.
    /// All dynamically-registered clients in tests share this tenant.
    /// </summary>
    private const string DynamicRegistrationTenant = "dynamic-clients";

    /// <summary>
    /// The AS's issuer URI for dynamic-registration tests. Returned by
    /// <see cref="GlobalRegistrationEndpoint"/> for the host root and used as
    /// <see cref="ClientRegistration.AuthorizationServerIssuer"/> on the
    /// resulting registration.
    /// </summary>
    public Uri IssuerUri { get; } = new($"https://issuer.test/{DynamicRegistrationTenant}");

    /// <summary>
    /// The global RFC 7591 §3 registration endpoint URL. Used by
    /// dynamic-registration tests as the value of
    /// <see cref="RegisterClientOptions.RegistrationEndpoint"/>.
    /// </summary>
    public Uri GlobalRegistrationEndpoint { get; } =
        new("https://verifier.example.com/connect/register");


    /// <summary>The authorization server instance. All tests dispatch through this.</summary>
    public AuthorizationServer Server => Default.Server;

    /// <summary>The current registration routing table.</summary>
    public IReadOnlyDictionary<string, ClientRecord> RegistrationStore => Registrations;

    /// <summary>The server-side flow state store.</summary>
    public IReadOnlyDictionary<string, (OAuthFlowState State, int StepCount)> FlowStore => FlowStates;

    /// <summary>The time provider injected at construction.</summary>
    public TimeProvider Time { get; }

    /// <summary>
    /// Issuer trust store mapping issuer identifiers to their public keys.
    /// The verifier uses this to verify credential issuer signatures.
    /// </summary>
    private Dictionary<string, PublicKeyMemory> IssuerTrustStore { get; } = [];

    /// <summary>
    /// Per-subject OIDC claim store. The fixture's
    /// <see cref="AuthorizationServerIntegration.ResolveOidcClaimsAsync"/>
    /// lambda reads from this dictionary so tests can seed claim sets and
    /// drive flows that consume them.
    /// </summary>
    public Dictionary<string, OidcClaims> SubjectClaims { get; } =
        new(StringComparer.Ordinal);


    /// <summary>
    /// Registers a trusted issuer's public key for credential signature verification.
    /// </summary>
    /// <param name="issuerId">The issuer identifier (the <c>iss</c> claim value).</param>
    /// <param name="issuerPublicKey">The issuer's public key.</param>
    public void RegisterIssuerTrust(string issuerId, PublicKeyMemory issuerPublicKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuerId);
        ArgumentNullException.ThrowIfNull(issuerPublicKey);

        IssuerTrustStore[issuerId] = issuerPublicKey;
    }


    /// <summary>
    /// Seeds an entry in <see cref="SubjectClaims"/> for OIDC tests. Default
    /// values populate the standard profile/email shape; pass <c>null</c> to
    /// omit a sub-record.
    /// </summary>
    public OidcClaims SeedTestSubject(
        string subject = "test-subject",
        string? name = "Test User",
        string? email = "test@example.com",
        bool emailVerified = true,
        string? acr = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);

        OidcClaims claims = new()
        {
            Subject = subject,
            Profile = name is null ? null : new ProfileClaims { Name = name },
            Email = email is null ? null : new EmailClaims
            {
                Email = email,
                EmailVerified = emailVerified
            },
            AuthContext = acr is null ? null : new AuthenticationContext { Acr = acr }
        };
        SubjectClaims[subject] = claims;
        return claims;
    }


    /// <summary>
    /// Creates a fully wired test application with in-memory stores and all
    /// cryptographic algorithms registered.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The constructor mirrors production startup: all codec, hash, signing,
    /// verification, and key agreement functions are registered via
    /// <see cref="TestSetup.Setup"/> (the <c>[ModuleInitializer]</c>) before this
    /// constructor runs. The server options resolve delegates from those registries,
    /// exactly as a production application would.
    /// </para>
    /// </remarks>
    /// <param name="timeProvider">
    /// Time provider for all timestamps. Pass <c>FakeTimeProvider</c> in tests.
    /// </param>
    /// <param name="resolveIssuerKey">
    /// Delegate that resolves an issuer's public key from its identifier.
    /// When <see langword="null"/>, the default resolver reads from
    /// <see cref="IssuerTrustStore"/>.
    /// </param>
    /// <param name="vpValidator">
    /// VP token validator. When <see langword="null"/>, HAIP 1.0 SD-JWT rules are used.
    /// </param>
    public TestHostShell(
        TimeProvider timeProvider,
        ResolveIssuerKeyDelegate? resolveIssuerKey = null,
        ClaimIssuer<ValidationContext>? vpValidator = null,
        MdocVpVerificationSeams? mdocSeams = null,
        SdCwtVpVerificationSeams? sdCwtSeams = null,
        CommitmentReuseDetectionSeam? saltReuseSeam = null)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);

        Time = timeProvider;

        //Shell-level dependencies reused by every host the shell builds —
        //AddHost picks up the same trust anchor and VP validator unless the
        //caller overrides them per host.
        ResolveIssuerKeyShared = resolveIssuerKey ?? ResolveIssuerKey;
        VpValidatorShared = vpValidator ?? new ClaimIssuer<ValidationContext>(
            "vp-haip10-verifier",
            ValidationProfiles.Haip10SdJwtRules(),
            timeProvider);
        MdocSeamsShared = mdocSeams;
        SdCwtSeamsShared = sdCwtSeams;
        SaltReuseSeamShared = saltReuseSeam;

        Default = HostedAuthorizationServer.Build(
            name: "default",
            timeProvider: timeProvider,
            subjectClaims: SubjectClaims,
            resolveIssuerKey: ResolveIssuerKeyShared,
            vpValidator: VpValidatorShared,
            mdocSeams: MdocSeamsShared,
            sdCwtSeams: SdCwtSeamsShared,
            saltReuseSeam: SaltReuseSeamShared);
        HostsByName["default"] = Default;
    }


    //Shell-level dependencies kept for AddHost so secondary hosts wire the
    //same trust anchor and VP validator the Default host received.
    private ResolveIssuerKeyDelegate ResolveIssuerKeyShared { get; }
    private ClaimIssuer<ValidationContext> VpValidatorShared { get; }
    private MdocVpVerificationSeams? MdocSeamsShared { get; }
    private SdCwtVpVerificationSeams? SdCwtSeamsShared { get; }
    private CommitmentReuseDetectionSeam? SaltReuseSeamShared { get; }

    //Multi-host orchestration. The Default entry is added in the constructor;
    //AddHost creates further independent hosts (different roles in a multi-
    //party flow — Verifier + Federation Anchor, etc.).
    private Dictionary<string, HostedAuthorizationServer> HostsByName { get; } =
        new(StringComparer.Ordinal);


    /// <summary>All hosts owned by this shell, keyed by role name.</summary>
    public IReadOnlyDictionary<string, HostedAuthorizationServer> Hosts => HostsByName;


    /// <summary>
    /// Looks up a previously added host by name. Throws if no host with the
    /// given name exists.
    /// </summary>
    public HostedAuthorizationServer Host(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        if(!HostsByName.TryGetValue(name, out HostedAuthorizationServer? host))
        {
            throw new KeyNotFoundException(
                $"No host named '{name}' is registered with this TestHostShell.");
        }

        return host;
    }


    /// <summary>
    /// Adds a new <see cref="HostedAuthorizationServer"/> to this shell with
    /// its own independent state. The new host shares the shell-level
    /// <see cref="IssuerTrustStore"/>, <see cref="SubjectClaims"/>, and VP
    /// validator with the Default host so trust and claim seeding stay
    /// centralised on the orchestrator.
    /// </summary>
    public HostedAuthorizationServer AddHost(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        if(HostsByName.ContainsKey(name))
        {
            throw new InvalidOperationException(
                $"A host named '{name}' is already registered.");
        }

        HostedAuthorizationServer host = HostedAuthorizationServer.Build(
            name: name,
            timeProvider: Time,
            subjectClaims: SubjectClaims,
            resolveIssuerKey: ResolveIssuerKeyShared,
            vpValidator: VpValidatorShared,
            mdocSeams: MdocSeamsShared,
            sdCwtSeams: SdCwtSeamsShared);
        HostsByName[name] = host;

        return host;
    }


    /// <summary>
    /// Registers a client with the specified capabilities and fresh P-256 key material.
    /// </summary>
    /// <param name="clientId">The OAuth client identifier.</param>
    /// <param name="baseUri">The base URI for the client's endpoints.</param>
    /// <param name="capabilities">
    /// The capabilities this client is allowed to use. Determines which endpoints
    /// are active.
    /// </param>
    public VerifierKeyMaterial RegisterClient(
        string clientId,
        Uri baseUri,
        ImmutableHashSet<CapabilityIdentifier> capabilities,
        PolicyProfile? profile = null) =>
        RegisterClientOnHost("default", clientId, baseUri, capabilities, profile);


    /// <summary>
    /// Registers a client on the named host. Multi-host topologies (e.g.
    /// verifier + federation anchor) call this overload to put each
    /// registration on the right host's per-host dictionaries.
    /// </summary>
    public VerifierKeyMaterial RegisterClientOnHost(
        string hostName,
        string clientId,
        Uri baseUri,
        ImmutableHashSet<CapabilityIdentifier> capabilities,
        PolicyProfile? profile = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostName);
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentNullException.ThrowIfNull(baseUri);
        ArgumentNullException.ThrowIfNull(capabilities);

        HostedAuthorizationServer host = Host(hostName);

        string segment = Guid.NewGuid().ToString("N")[..8];
        KeyId signingKeyId = new($"urn:uuid:{Guid.NewGuid()}");
        KeyId encryptionKeyId = new($"urn:uuid:{Guid.NewGuid()}");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signingKeyPair =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> exchangeKeyPair =
            TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();

        host.SigningKeys[signingKeyId] = signingKeyPair.PrivateKey;
        host.VerificationKeys[signingKeyId] = signingKeyPair.PublicKey;
        host.DecryptionKeys[encryptionKeyId] = exchangeKeyPair.PrivateKey;

        VerifierClientMetadata? clientMetadata = capabilities.Contains(
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation)
            ? BuildClientMetadata(clientId, exchangeKeyPair.PublicKey, encryptionKeyId)
            : null;

        Uri responseUri = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.Oid4VpDirectPost, segment));

        //OID4VP verifier registrations resolve to the dedicated verifier policy
        //profile (presentation timing axes only), not the FAPI 2.0 token-endpoint
        //default. Non-verifier registrations created via this helper keep the
        //library default (Fapi20).
        //An explicit profile wins; otherwise OID4VP verifier registrations resolve to
        //the dedicated verifier profile and everything else takes the library default.
        PolicyProfile? policyProfile = profile ?? (capabilities.Contains(
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation)
            ? PolicyProfile.Oid4VpVerifier
            : null);

        ClientRecord registration = new()
        {
            ClientId = clientId,
            TenantId = segment,
            IssuerUri = new Uri($"https://issuer.test/{segment}"),
            Profile = policyProfile,
            AllowedCapabilities = capabilities,
            AllowedRedirectUris = ImmutableHashSet.Create(
                new Uri("https://client.example.com/callback")),
            AllowedScopes = ImmutableHashSet.Create(WellKnownScopes.OpenId),
            SigningKeys = ImmutableDictionary<KeyUsageContext, SigningKeySet>.Empty
                .Add(KeyUsageContext.JarSigning, new SigningKeySet { Current = [signingKeyId] }),
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty,
            ResponseUri = responseUri,
            ClientMetadata = clientMetadata
        };

        //Index by both segment and clientId for lookup.
        host.Registrations[segment] = registration;
        host.Registrations[clientId] = registration;

        //Emit event so observers (routing table, caches) are notified.
        host.Server.RegisterClient(
            registration,
            new RegistrationAccessToken(Guid.NewGuid().ToString("N")),
            new ExchangeContext());

        //Dispose the exchange public key — only the private key is retained.
        //The signing public key is retained in VerificationKeys for JAR verification.
        exchangeKeyPair.PublicKey.Dispose();

        return new VerifierKeyMaterial(
            registration,
            signingKeyPair.PublicKey,
            signingKeyPair.PrivateKey,
            exchangeKeyPair.PrivateKey,
            encryptionKeyId,
            signingKeyId);
    }


    /// <summary>
    /// Registers a client with externally provided signing key material.
    /// Use this overload to test JWKS output for any algorithm — P-256, P-384,
    /// P-521, Ed25519, secp256k1, RSA-2048, ML-DSA-44, ML-DSA-65, ML-DSA-87.
    /// </summary>
    /// <param name="clientId">The client identifier.</param>
    /// <param name="signingKeyPair">
    /// The signing key pair. Ownership transfers to the host — both keys are
    /// stored in the key stores and disposed when the host is disposed.
    /// </param>
    /// <param name="capabilities">
    /// The capabilities this client is allowed to use.
    /// </param>
    /// <returns>The registered <see cref="ClientRecord"/>.</returns>
    /// <summary>
    /// Registers a client with the supplied signing key in the
    /// <see cref="KeyUsageContext.JarSigning"/> slot, so JAR-bearing AuthCode
    /// or OID4VP flows can be parameterised across signature algorithms.
    /// </summary>
    public VerifierKeyMaterial RegisterJarSigningClient(
        string clientId,
        Uri baseUri,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signingKeyPair,
        ImmutableHashSet<CapabilityIdentifier> capabilities)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentNullException.ThrowIfNull(baseUri);
        ArgumentNullException.ThrowIfNull(signingKeyPair);
        ArgumentNullException.ThrowIfNull(capabilities);

        string segment = Guid.NewGuid().ToString("N")[..8];
        KeyId signingKeyId = new($"urn:uuid:{Guid.NewGuid()}");

        SigningKeys[signingKeyId] = signingKeyPair.PrivateKey;
        VerificationKeys[signingKeyId] = signingKeyPair.PublicKey;

        //P-256 exchange keypair satisfies VerifierKeyMaterial's required
        //DecryptionPrivateKey slot. JAR-signing-only tests do not exercise
        //response encryption, but the type's invariant still applies.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> exchangeKeyPair =
            TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        KeyId encryptionKeyId = new($"urn:uuid:{Guid.NewGuid()}");
        DecryptionKeys[encryptionKeyId] = exchangeKeyPair.PrivateKey;

        //When the registered capabilities include OID4VP presentation, the
        //wallet needs the verifier's encryption JWK off the JAR's
        //client_metadata claim to encrypt the direct_post.jwt response.
        //Auth Code-only registrations skip metadata. BuildClientMetadata
        //freezes the JWK into a JSON dictionary so the public key buffer
        //is disposed unconditionally afterward.
        VerifierClientMetadata? clientMetadata = capabilities.Contains(
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation)
            ? BuildClientMetadata(clientId, exchangeKeyPair.PublicKey, encryptionKeyId)
            : null;
        exchangeKeyPair.PublicKey.Dispose();

        ClientRecord registration = new()
        {
            ClientId = clientId,
            TenantId = segment,
            IssuerUri = new Uri($"https://issuer.test/{segment}"),
            AllowedCapabilities = capabilities,
            AllowedRedirectUris = ImmutableHashSet.Create(
                new Uri("https://client.example.com/callback")),
            AllowedScopes = ImmutableHashSet.Create(WellKnownScopes.OpenId),
            SigningKeys = ImmutableDictionary<KeyUsageContext, SigningKeySet>.Empty
                .Add(KeyUsageContext.JarSigning, new SigningKeySet { Current = [signingKeyId] }),
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty,
            ResponseUri = new Uri(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.Oid4VpDirectPost, segment)),
            ClientMetadata = clientMetadata
        };

        Registrations[segment] = registration;
        Registrations[clientId] = registration;

        Server.RegisterClient(
            registration,
            new RegistrationAccessToken(Guid.NewGuid().ToString("N")),
            new ExchangeContext());

        return new VerifierKeyMaterial(
            registration,
            signingKeyPair.PublicKey,
            signingKeyPair.PrivateKey,
            decryptionPrivateKey: exchangeKeyPair.PrivateKey,
            encryptionKeyId: encryptionKeyId,
            signingKeyId: signingKeyId);
    }


    public ClientRecord RegisterSigningClient(
        string clientId,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signingKeyPair,
        ImmutableHashSet<CapabilityIdentifier> capabilities)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentNullException.ThrowIfNull(signingKeyPair);
        ArgumentNullException.ThrowIfNull(capabilities);

        string segment = Guid.NewGuid().ToString("N")[..8];
        KeyId signingKeyId = new($"urn:uuid:{Guid.NewGuid()}");

        SigningKeys[signingKeyId] = signingKeyPair.PrivateKey;
        VerificationKeys[signingKeyId] = signingKeyPair.PublicKey;

        ClientRecord registration = new()
        {
            ClientId = clientId,
            TenantId = segment,
            IssuerUri = new Uri($"https://issuer.test/{segment}"),
            AllowedCapabilities = capabilities,
            AllowedRedirectUris = ImmutableHashSet.Create(
                new Uri("https://client.example.com/callback")),
            AllowedScopes = ImmutableHashSet.Create(WellKnownScopes.OpenId),
            SigningKeys = ImmutableDictionary<KeyUsageContext, SigningKeySet>.Empty
                .Add(KeyUsageContext.AccessTokenIssuance, new SigningKeySet { Current = [signingKeyId] }),
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty
        };

        Registrations[segment] = registration;
        Registrations[clientId] = registration;

        Server.RegisterClient(
            registration,
            new RegistrationAccessToken(Guid.NewGuid().ToString("N")),
            new ExchangeContext());

        return registration;
    }


    /// <summary>
    /// Registers a federation-participating client. Builds the baseline
    /// OID4VP / OAuth registration via <see cref="RegisterClient"/>, then
    /// upgrades the resulting <see cref="ClientRecord"/> to also publish an
    /// OpenID Federation 1.0 Entity Configuration at
    /// <c>/.well-known/openid-federation</c>: adds
    /// <see cref="Verifiable.OAuth.Federation.WellKnownFederationCapabilityIdentifiers.PublishEntityConfiguration"/>
    /// to <see cref="ClientRecord.AllowedCapabilities"/>, sets
    /// <see cref="ClientRecord.FederationEntityId"/>, and stores
    /// <paramref name="federationSigningKeyPair"/> under
    /// <see cref="KeyUsageContext.FederationEntitySignature"/> on the
    /// registration's <see cref="ClientRecord.SigningKeys"/> inventory.
    /// </summary>
    /// <remarks>
    /// The federation signing key is independent of the OID4VP JAR-signing
    /// key generated by <see cref="RegisterClient"/> — different artifacts
    /// (Entity Configuration vs JAR), different purposes, different rotation
    /// lifecycles. Federation chain validation reads the federation key
    /// from <c>chain[N].jwks</c>; JAR signature verification reads the JAR
    /// signing key from the verifier's <c>metadata.openid_relying_party.jwks</c>
    /// effective metadata claim.
    /// </remarks>
    public VerifierKeyMaterial RegisterFederationCapableClient(
        string clientId,
        Uri baseUri,
        Uri federationEntityId,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationSigningKeyPair,
        ImmutableHashSet<CapabilityIdentifier> baseCapabilities) =>
        RegisterFederationCapableClientOnHost(
            "default", clientId, baseUri, federationEntityId, federationSigningKeyPair, baseCapabilities);


    /// <summary>
    /// Registers a federation-capable client on the named host. Used by
    /// multi-host federation topologies (Verifier + Anchor) where each
    /// federation entity lives on its own Kestrel.
    /// </summary>
    public VerifierKeyMaterial RegisterFederationCapableClientOnHost(
        string hostName,
        string clientId,
        Uri baseUri,
        Uri federationEntityId,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationSigningKeyPair,
        ImmutableHashSet<CapabilityIdentifier> baseCapabilities)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostName);
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentNullException.ThrowIfNull(baseUri);
        ArgumentNullException.ThrowIfNull(federationEntityId);
        ArgumentNullException.ThrowIfNull(federationSigningKeyPair);
        ArgumentNullException.ThrowIfNull(baseCapabilities);

        HostedAuthorizationServer host = Host(hostName);

        //Build the baseline registration (OID4VP / OAuth capabilities,
        //JAR signing key, encryption keys, optional client_metadata).
        VerifierKeyMaterial baseKeys = RegisterClientOnHost(hostName, clientId, baseUri, baseCapabilities);

        //Store the federation signing key material on the host so the
        //federation endpoint's SigningKeyResolver / VerificationKeyResolver
        //find it.
        KeyId federationSigningKeyId = new($"urn:uuid:{Guid.NewGuid()}");
        host.SigningKeys[federationSigningKeyId] = federationSigningKeyPair.PrivateKey;
        host.VerificationKeys[federationSigningKeyId] = federationSigningKeyPair.PublicKey;

        ClientRecord baseline = baseKeys.Registration;
        ClientRecord federated = baseline with
        {
            AllowedCapabilities = baseline.AllowedCapabilities.Add(
                Verifiable.OAuth.Federation.WellKnownFederationCapabilityIdentifiers.PublishEntityConfiguration),
            FederationEntityId = federationEntityId,
            SigningKeys = ImmutableDictionary
                .CreateRange<KeyUsageContext, SigningKeySet>(baseline.SigningKeys)
                .Add(KeyUsageContext.FederationEntitySignature,
                    new SigningKeySet { Current = [federationSigningKeyId] })
        };

        string segment = baseline.TenantId.Value;
        host.Registrations[segment] = federated;
        host.Registrations[baseline.ClientId] = federated;

        //Emit the update event so registration-observers re-sync against
        //the federation-bearing record.
        host.Server.RegisterClient(
            federated,
            new RegistrationAccessToken(Guid.NewGuid().ToString("N")),
            new ExchangeContext());

        //Re-point baseKeys' Registration to the federation-bearing record so
        //test code that reaches through baseKeys.Registration sees the same
        //ClientRecord the dispatcher resolves. Key material is unchanged;
        //ownership stays with baseKeys.
        baseKeys.Registration = federated;

        return baseKeys;
    }


    /// <summary>
    /// Constructs an <see cref="OAuthClient"/> over a fresh
    /// <see cref="OAuthClientInfrastructure"/> and the matching
    /// <see cref="ClientRegistration"/> for the registered tenant. Returns
    /// both because every protocol-method call threads the registration
    /// alongside the client.
    /// </summary>
    /// <param name="record">The server-side registration record.</param>
    /// <param name="redirectUri">The client's redirect URI.</param>
    /// <param name="issuerUri">The expected issuer URI for callback validation.</param>
    public (OAuthClient Client, ClientRegistration Registration, Dictionary<string, OAuthFlowState> ClientFlowStore)
        CreateInProcessOAuthClientAndRegistration(
            ClientRecord record,
            string redirectUri,
            string issuerUri,
            PolicyProfile? profile = null)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentException.ThrowIfNullOrWhiteSpace(redirectUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(issuerUri);

        InProcessTransport transport = new(
            Server, record, record.TenantId, issuerUri);

        Dictionary<string, OAuthFlowState> clientFlowStore = [];

        string segment = record.TenantId.Value;
        Uri baseUri = new("https://verifier.example.com");

        Uri parEndpoint = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodePar, segment));
        Uri authEndpoint = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment));
        Uri tokenEndpoint = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));
        Uri issuerUriValue = new(issuerUri);

        AuthorizationServerMetadata metadata = new()
        {
            Issuer = issuerUriValue,
            PushedAuthorizationRequestEndpoint = parEndpoint,
            AuthorizationEndpoint = authEndpoint,
            TokenEndpoint = tokenEndpoint
        };

        OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create(
            sendFormPostAsync: (endpoint, fields, headers, _, ct) =>
                transport.SendAsync(endpoint, fields, headers, ct),
            saveStateAsync: (state, _, ct) =>
            {
                clientFlowStore[state.FlowId] = state;
                return ValueTask.CompletedTask;
            },
            loadStateAsync: (flowId, _, ct) =>
                ValueTask.FromResult(clientFlowStore.GetValueOrDefault(flowId)),
            loadStateByRequestUriAsync: (requestUri, _, ct) =>
            {
                foreach(OAuthFlowState state in clientFlowStore.Values)
                {
                    if(state is Verifiable.OAuth.AuthCode.States.ParCompletedState pc
                        && string.Equals(
                            pc.Par.RequestUri.ToString(), requestUri, StringComparison.Ordinal))
                    {
                        return ValueTask.FromResult<OAuthFlowState?>(state);
                    }
                }

                return ValueTask.FromResult<OAuthFlowState?>(null);
            },
            parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
            parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
            parseAuthorizationServerMetadataAsync: (body, ct) =>
                throw new NotImplementedException("Test host pre-resolves metadata; the parser is not exercised."),
            parseRegistrationResponseAsync: (body, ct) =>
                throw new NotImplementedException("Phase 2 does not exercise dynamic registration."),
            resolveAuthorizationServerMetadataAsync: (issuer, context, ct) =>
                ValueTask.FromResult(metadata),
            resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            timeProvider: Time);

        ClientRegistration registration = new()
        {
            ClientId = new ClientId(record.ClientId),
            AuthorizationServerIssuer = issuerUriValue,
            RedirectUris = [new Uri(redirectUri)],
            AuthenticationMethod = ClientAuthenticationMethod.None,
            Profile = profile ?? PolicyProfile.Haip10
        };

        return (new OAuthClient(infrastructure), registration, clientFlowStore);
    }


    /// <summary>
    /// HTTP-backed counterpart to <see cref="CreateInProcessOAuthClientAndRegistration"/>.
    /// Starts the in-process Kestrel listener if not already running and
    /// wires the <see cref="OAuthClient"/> with <see cref="HttpClientTransport"/>
    /// transport delegates against a real <see cref="System.Net.Http.HttpClient"/>.
    /// </summary>
    /// <remarks>
    /// The issuer URI on the supplied <paramref name="record"/> is rewritten
    /// in-place to point at the Kestrel base address. This aligns the AS's
    /// DPoP-htu computation (which uses <c>IssuerUri.Authority</c>) with
    /// the client's actual outbound URL. Test isolation is preserved because
    /// each <see cref="TestHostShell"/> binds its own ephemeral port.
    /// </remarks>
    public async ValueTask<(OAuthClient Client, ClientRegistration Registration, Dictionary<string, OAuthFlowState> ClientFlowStore)>
        CreateOAuthClientAndRegistrationAsync(
            ClientRecord record,
            string redirectUri,
            PolicyProfile? profile = null,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentException.ThrowIfNullOrWhiteSpace(redirectUri);

        await StartHttpHostAsync(cancellationToken).ConfigureAwait(false);

        ClientRecord alignedRecord = AlignRegistrationIssuerToHttpBase(record);

        Dictionary<string, OAuthFlowState> clientFlowStore = [];

        string segment = alignedRecord.TenantId.Value;
        Uri baseUri = HttpBaseAddress!;
        Uri parEndpoint = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodePar, segment));
        Uri authEndpoint = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment));
        Uri tokenEndpoint = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));
        Uri issuerUriValue = alignedRecord.IssuerUri!;

        AuthorizationServerMetadata metadata = new()
        {
            Issuer = issuerUriValue,
            PushedAuthorizationRequestEndpoint = parEndpoint,
            AuthorizationEndpoint = authEndpoint,
            TokenEndpoint = tokenEndpoint
        };

        System.Net.Http.HttpClient httpClient = SharedHttpClient!;

        OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create(
            sendFormPostAsync: (endpoint, fields, headers, _, ct) =>
                HttpClientTransport.SendFormPostAsync(httpClient, endpoint, fields, headers, ct),
            saveStateAsync: (state, _, ct) =>
            {
                clientFlowStore[state.FlowId] = state;
                return ValueTask.CompletedTask;
            },
            loadStateAsync: (flowId, _, ct) =>
                ValueTask.FromResult(clientFlowStore.GetValueOrDefault(flowId)),
            loadStateByRequestUriAsync: (requestUri, _, ct) =>
            {
                foreach(OAuthFlowState state in clientFlowStore.Values)
                {
                    if(state is Verifiable.OAuth.AuthCode.States.ParCompletedState pc
                        && string.Equals(
                            pc.Par.RequestUri.ToString(), requestUri, StringComparison.Ordinal))
                    {
                        return ValueTask.FromResult<OAuthFlowState?>(state);
                    }
                }

                return ValueTask.FromResult<OAuthFlowState?>(null);
            },
            parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
            parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
            parseAuthorizationServerMetadataAsync: (body, ct) =>
                throw new NotImplementedException("Test host pre-resolves metadata; the parser is not exercised."),
            parseRegistrationResponseAsync: (body, ct) =>
                throw new NotImplementedException("HTTP-backed factory does not exercise dynamic registration parse."),
            resolveAuthorizationServerMetadataAsync: (issuer, context, ct) =>
                ValueTask.FromResult(metadata),
            resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            timeProvider: Time);

        ClientRegistration registration = new()
        {
            ClientId = new ClientId(alignedRecord.ClientId),
            AuthorizationServerIssuer = issuerUriValue,
            RedirectUris = [new Uri(redirectUri)],
            AuthenticationMethod = ClientAuthenticationMethod.None,
            Profile = profile ?? PolicyProfile.Haip10
        };

        return (new OAuthClient(infrastructure), registration, clientFlowStore);
    }


    /// <summary>
    /// HTTP-backed OID4VP wallet factory. Starts the in-process Kestrel,
    /// aligns the verifier's registration issuer to the Kestrel base, and
    /// returns an <see cref="Oid4VpWalletClient"/> whose
    /// <see cref="OAuthClientInfrastructure.SendFormPostAsync"/> goes through
    /// <see cref="HttpClientTransport"/> to the real wire. The wallet's
    /// direct_post call therefore reaches the verifier via the Kestrel
    /// listener instead of an in-process dispatch.
    /// </summary>
    /// <remarks>
    /// Returns the wallet client only — the JAR-fetch GET is the wallet
    /// caller's responsibility (it is not an OAuth-spec operation; a real
    /// wallet uses its own <see cref="System.Net.Http.HttpClient"/>). Tests
    /// fetch the JAR via <c>app.Host("default").SharedHttpClient!.GetAsync(requestUri)</c>.
    /// </remarks>
    public async ValueTask<Oid4VpWalletClient> CreateHttpBackedOid4VpWalletClientAsync(
        VerifierKeyMaterial verifierKeys,
        string storedSdJwt,
        PrivateKeyMemory holderKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verifierKeys);
        ArgumentException.ThrowIfNullOrWhiteSpace(storedSdJwt);
        ArgumentNullException.ThrowIfNull(holderKey);

        OAuthClientInfrastructure infrastructure = await BuildHttpBackedOAuthClientInfrastructureAsync(
            verifierKeys, cancellationToken).ConfigureAwait(false);

        HttpClient walletHttpClient = Host("default").SharedHttpClient!;
        Oid4VpWalletConfiguration config =
            BuildSlimOid4VpWalletConfiguration(
                BuildSdJwtProduceDelegate(storedSdJwt, holderKey),
                PinnedVerifierKeyResolver(verifierKeys.SigningPublicKey)) with
            {
                SendFormPost = (endpoint, fields, headers, _, ct) =>
                    HttpClientTransport.SendFormPostAsync(
                        walletHttpClient, endpoint, fields, headers, ct)
            };

        return new Oid4VpWalletClient(infrastructure, config);
    }


    /// <summary>
    /// HTTP-backed OID4VP wallet factory for multi-credential presentations.
    /// Each entry in <paramref name="credentialsByQueryId"/> is matched
    /// against the DCQL query's <see cref="CredentialQuery.Id"/> at present
    /// time; queries without a matching entry surface as a clear "no
    /// candidates" error from the wallet client.
    /// </summary>
    public async ValueTask<Oid4VpWalletClient> CreateHttpBackedOid4VpWalletClientAsync(
        VerifierKeyMaterial verifierKeys,
        IReadOnlyDictionary<string, string> credentialsByQueryId,
        PrivateKeyMemory holderKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verifierKeys);
        ArgumentNullException.ThrowIfNull(credentialsByQueryId);
        ArgumentNullException.ThrowIfNull(holderKey);

        OAuthClientInfrastructure infrastructure = await BuildHttpBackedOAuthClientInfrastructureAsync(
            verifierKeys, cancellationToken).ConfigureAwait(false);

        HttpClient walletHttpClient = Host("default").SharedHttpClient!;
        Oid4VpWalletConfiguration config =
            BuildSlimOid4VpWalletConfiguration(
                BuildSdJwtProduceDelegate(credentialsByQueryId, holderKey),
                PinnedVerifierKeyResolver(verifierKeys.SigningPublicKey)) with
            {
                SendFormPost = (endpoint, fields, headers, _, ct) =>
                    HttpClientTransport.SendFormPostAsync(
                        walletHttpClient, endpoint, fields, headers, ct)
            };

        return new Oid4VpWalletClient(infrastructure, config);
    }


    /// <summary>
    /// HTTP-backed OID4VP wallet factory wired with an explicit presentation
    /// drop-out and an explicit client-id-scheme key resolver — the
    /// resolution-by-scheme counterpart to the pinned-key overloads above. Used
    /// by flows that must resolve the verifier's JAR-signing key off the wire
    /// (e.g. x509_san_dns from the JAR's <c>x5c</c>) over real HTTP, including the
    /// §5.10 <c>request_uri_method=post</c> + encrypted-JAR path.
    /// </summary>
    public async ValueTask<Oid4VpWalletClient> CreateHttpBackedOid4VpWalletClientAsync(
        VerifierKeyMaterial verifierKeys,
        ProduceVpTokenPresentationsDelegate produceVpTokenPresentations,
        ResolveClientIdSigningKeyAsyncDelegate verifierSigningKeyResolver,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verifierKeys);
        ArgumentNullException.ThrowIfNull(produceVpTokenPresentations);
        ArgumentNullException.ThrowIfNull(verifierSigningKeyResolver);

        OAuthClientInfrastructure infrastructure = await BuildHttpBackedOAuthClientInfrastructureAsync(
            verifierKeys, cancellationToken).ConfigureAwait(false);

        HttpClient walletHttpClient = Host("default").SharedHttpClient!;
        Oid4VpWalletConfiguration config =
            BuildSlimOid4VpWalletConfiguration(produceVpTokenPresentations, verifierSigningKeyResolver) with
            {
                SendFormPost = GuardedHttpClientTransport.BuildGuardedFormPost(walletHttpClient)
            };

        return new Oid4VpWalletClient(infrastructure, config);
    }


    private async ValueTask<OAuthClientInfrastructure> BuildHttpBackedOAuthClientInfrastructureAsync(
        VerifierKeyMaterial verifierKeys,
        CancellationToken cancellationToken)
    {
        //Use the OAuth-client factory to get HTTP-backed infrastructure. The
        //redirect_uri is irrelevant to the OID4VP path — the wallet client
        //only uses the infrastructure's SendFormPostAsync transport — but the
        //OAuth ClientRegistration record requires one.
        (OAuthClient oauthClient, _, _) = await CreateOAuthClientAndRegistrationAsync(
            verifierKeys.Registration,
            redirectUri: "https://wallet.example.com/cb",
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return oauthClient.Infrastructure;
    }


    /// <summary>
    /// The outbound-fetch policy for wallet sends against this fixture's loopback
    /// Kestrel listener: the secure default relaxed for plain-<c>http</c> loopback
    /// targets, because the test deployment's transport endpoint genuinely is a
    /// local listener. The relaxation is the deployment's explicit, principled
    /// per-call choice — production wallets keep
    /// <see cref="Verifiable.Core.OutboundFetch.OutboundFetchPolicy.SecureDefault"/>,
    /// under which an authorization request pointing the wallet at a private or
    /// loopback address is denied before any network contact.
    /// </summary>
    public static Verifiable.Core.OutboundFetch.OutboundFetchPolicy LoopbackOutboundFetchPolicy { get; } =
        Verifiable.Core.OutboundFetch.OutboundFetchPolicy.SecureDefault with
        {
            AllowedSchemes = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "http", "https" },
            BlockPrivateAndLoopback = false
        };


    /// <summary>
    /// A trivial <see cref="ResolveClientIdSigningKeyAsyncDelegate"/> that returns
    /// the supplied pre-registered/known verifier signing key regardless of the
    /// <c>client_id</c> scheme — the "pinned key" case expressed as a resolver.
    /// Hands the wallet a fresh owned copy on each call because the wallet
    /// disposes the resolved key after verifying the JAR.
    /// </summary>
    internal static ResolveClientIdSigningKeyAsyncDelegate PinnedVerifierKeyResolver(
        PublicKeyMemory verifierSigningKey)
    {
        ArgumentNullException.ThrowIfNull(verifierSigningKey);

        return (context, clientId, jarHeader, cancellationToken) =>
        {
            ReadOnlySpan<byte> keyBytes = verifierSigningKey.AsReadOnlySpan();
            IMemoryOwner<byte> owner = MemoryPool.Rent(keyBytes.Length);
            keyBytes.CopyTo(owner.Memory.Span);

            return ValueTask.FromResult(new PublicKeyMemory(owner, verifierSigningKey.Tag));
        };
    }


    /// <summary>
    /// Builds the format-agnostic <see cref="Oid4VpWalletConfiguration"/> wired
    /// to the project's standard delegate stack (BouncyCastle ECDH-ES + AES-GCM,
    /// the default ConcatKdf, the JSON (de)serialisers) plus the supplied
    /// presentation drop-out. Credential-format machinery lives behind
    /// <paramref name="produceVpTokenPresentations"/> — see
    /// <see cref="BuildSdJwtProduceDelegate(string, PrivateKeyMemory)"/>.
    /// </summary>
    internal static Oid4VpWalletConfiguration BuildSlimOid4VpWalletConfiguration(
        ProduceVpTokenPresentationsDelegate produceVpTokenPresentations,
        ResolveClientIdSigningKeyAsyncDelegate verifierSigningKeyResolver)
    {
        ArgumentNullException.ThrowIfNull(produceVpTokenPresentations);
        ArgumentNullException.ThrowIfNull(verifierSigningKeyResolver);

        return new Oid4VpWalletConfiguration
        {
            ProduceVpTokenPresentations = produceVpTokenPresentations,
            VerifierSigningKeyResolver = verifierSigningKeyResolver,
            WalletCapabilities = Oid4VpWalletCapabilities.HaipDefault,
            Base64UrlDecoder = TestSetup.Base64UrlDecoder,
            JwtHeaderSerializer = header => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions),
            JwtPayloadSerializer = payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions),
            JarHeaderDeserializer = bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            JarPayloadDeserializer = bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            DcqlQueryDeserializer = json => JsonSerializer.Deserialize<DcqlQuery>(
                json, TestSetup.DefaultSerializationOptions)!,
            ClientMetadataDeserializer = json => JsonSerializer.Deserialize<VerifierClientMetadata>(
                json, TestSetup.DefaultSerializationOptions)!,
            TagToEpkCrvConverter = CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            KeyAgreementEncrypt = BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
            KeyDerivation = ConcatKdf.DefaultKeyDerivationDelegate,
            AeadEncrypt = BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            //Decrypt delegates for OID4VP 1.0 §5.10 JAR-encryption support.
            //Wallet flows that don't opt into JAR encryption ignore these.
            KeyAgreementDecrypt = BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
            AeadDecrypt = BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
            MemoryPool = MemoryPool
        };
    }


    //SD-JWT VC mandatory claims — always disclosed, the lattice bottom.
    private static readonly CredentialPath SdJwtIssPath = CredentialPath.FromJsonPointer("/iss");
    private static readonly CredentialPath SdJwtVctPath = CredentialPath.FromJsonPointer("/vct");


    /// <summary>
    /// Builds the SD-JWT VC presentation drop-out (single stored credential,
    /// presented for every credential query). The worked example of wiring the
    /// Core disclosure engine: it parses the stored SD-JWT, runs
    /// <see cref="DcqlEvaluator"/>-style path resolution + <see cref="DisclosureComputation{TCredential}"/>
    /// to pick the minimal disclosure set the DCQL query asks for, then builds
    /// the KB-JWT presentation bound to the request.
    /// </summary>
    internal static ProduceVpTokenPresentationsDelegate BuildSdJwtProduceDelegate(
        string storedSdJwt, PrivateKeyMemory holderKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(storedSdJwt);
        ArgumentNullException.ThrowIfNull(holderKey);

        return BuildSdJwtProduceDelegateCore(_ => storedSdJwt, holderKey);
    }


    /// <summary>
    /// Multi-credential variant: each credential query resolves to the entry in
    /// <paramref name="credentialsByQueryId"/> whose key matches the query id.
    /// </summary>
    internal static ProduceVpTokenPresentationsDelegate BuildSdJwtProduceDelegate(
        IReadOnlyDictionary<string, string> credentialsByQueryId, PrivateKeyMemory holderKey)
    {
        ArgumentNullException.ThrowIfNull(credentialsByQueryId);
        ArgumentNullException.ThrowIfNull(holderKey);

        return BuildSdJwtProduceDelegateCore(
            queryId => credentialsByQueryId.TryGetValue(queryId, out string? stored)
                ? stored
                : throw new InvalidOperationException(
                    $"No stored SD-JWT VC for credential query '{queryId}'."),
            holderKey);
    }


    /// <summary>
    /// Over-disclosing SD-JWT VC wallet (test affordance): reveals every
    /// disclosure regardless of the DCQL query, to exercise the verifier's
    /// no-over-disclosure enforcement.
    /// </summary>
    internal static ProduceVpTokenPresentationsDelegate BuildSdJwtProduceDelegateRevealingAll(
        string storedSdJwt, PrivateKeyMemory holderKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(storedSdJwt);
        ArgumentNullException.ThrowIfNull(holderKey);

        return BuildSdJwtProduceDelegateCore(_ => storedSdJwt, holderKey, minimalDisclosure: false);
    }


    private static ProduceVpTokenPresentationsDelegate BuildSdJwtProduceDelegateCore(
        Func<string, string> resolveStoredSdJwt, PrivateKeyMemory holderKey, bool minimalDisclosure = true)
    {
        JwtHeaderSerializer headerSerializer = header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);
        JwtPayloadSerializer payloadSerializer = payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);

        return async (context, cancellationToken) =>
        {
            Dictionary<string, string> presentations = new(StringComparer.Ordinal);

            foreach(CredentialQuery query in context.Request.DcqlQuery!.Credentials!)
            {
                string queryId = query.Id
                    ?? throw new InvalidOperationException("DCQL credential query is missing the 'id' field.");

                using SdToken<string> token = SdJwtSerializer.ParseToken(
                    resolveStoredSdJwt(queryId), TestSetup.Base64UrlDecoder, MemoryPool, TestSalts.TestSaltTag);

                HashSet<string> selectedClaimNames;
                if(minimalDisclosure)
                {
                    //--- The one engine path every flow runs: DcqlDisclosure drives
                    //DcqlEvaluator.Evaluate -> ToDisclosureMatch -> ComputeAsync over the
                    //parsed token via SdTokenDcqlAdapter. iss/vct are the always-visible
                    //mandatory paths (lattice bottom); the engine's SelectedPaths is the
                    //minimal disclosure set. ---
                    DisclosureStrategyGraph<SdToken<string>> graph = (await DcqlDisclosure.ComputeStrategyAsync(
                        query,
                        token,
                        SdTokenDcqlAdapter.CreateMetadataExtractor<string>(DcqlCredentialFormats.SdJwt),
                        SdTokenDcqlAdapter.ClaimExtractor<string>,
                        mandatoryPaths: new HashSet<CredentialPath> { SdJwtIssPath, SdJwtVctPath },
                        cancellationToken: cancellationToken).ConfigureAwait(false)).Graph;

                    selectedClaimNames = graph.Decisions[0].SelectedPaths
                        .Select(path => path.ToString().TrimStart('/'))
                        .ToHashSet(StringComparer.Ordinal);
                }
                else
                {
                    //Over-disclosing wallet: reveal every object-property disclosure
                    //the credential carries, ignoring the query.
                    selectedClaimNames = token.Disclosures
                        .Where(disclosure => disclosure.ClaimName is not null)
                        .Select(disclosure => disclosure.ClaimName!)
                        .ToHashSet(StringComparer.Ordinal);
                }

                using SdToken<string> selected = token.SelectDisclosures(
                    disclosure => disclosure.ClaimName is not null
                        && selectedClaimNames.Contains(disclosure.ClaimName),
                    MemoryPool);

                //--- Format build: KB-JWT bound to client_id / nonce / transaction_data. ---
                byte[] hashInputBytes = Encoding.UTF8.GetBytes(
                    SdJwtSerializer.GetSdJwtForHashing(selected, TestSetup.Base64UrlEncoder));

                IReadOnlyList<string>? transactionDataHashes = null;
                if(context.Request.TransactionData is { Count: > 0 } transactionData)
                {
                    transactionDataHashes = await TransactionDataHasher.ComputeSha256Async(
                        transactionData, context.Base64UrlEncoder, context.MemoryPool, cancellationToken)
                        .ConfigureAwait(false);
                }

                string compactKbJwt = await KbJwtIssuance.IssueAsync(
                    hashInputBytes, holderKey, context.Request.Nonce, context.Request.ClientId, context.Now,
                    context.Base64UrlEncoder, headerSerializer, payloadSerializer, context.MemoryPool,
                    cancellationToken, transactionDataHashes).ConfigureAwait(false);

                using SdToken<string> tokenWithKb = selected.WithKeyBinding(compactKbJwt, MemoryPool);
                presentations[queryId] = SdJwtSerializer.SerializeToken(tokenWithKb, TestSetup.Base64UrlEncoder);
            }

            return new Oid4VpPresentationSet { PresentationsByQueryId = presentations };
        };
    }


    /// <summary>
    /// Re-issues the supplied <see cref="ClientRecord"/> with its external
    /// URLs (<see cref="ClientRecord.IssuerUri"/> and, when set,
    /// <see cref="ClientRecord.ResponseUri"/>) swapped to point at the
    /// Kestrel base address while preserving each URL's path. The in-memory
    /// registration dictionary is updated to match so the AS resolves the
    /// same record on subsequent dispatch.
    /// </summary>
    /// <remarks>
    /// OID4VP JAR signing reads <c>response_uri</c> directly off
    /// <see cref="ClientRecord.ResponseUri"/>, so wallet HTTP POSTs miss the
    /// Kestrel unless ResponseUri is aligned as well. AuthCode-only flows do
    /// not consult ResponseUri; the alignment is a no-op for those.
    /// </remarks>
    private ClientRecord AlignRegistrationIssuerToHttpBase(ClientRecord record) =>
        AlignRegistrationToHostHttpBase("default", record);


    /// <summary>
    /// Host-aware variant: aligns the registration's external URLs to the
    /// named host's Kestrel base. Used for multi-host federation
    /// topologies where each entity lives on its own listener — the
    /// anchor's registration aligns to anchor.HttpBaseAddress, the
    /// verifier's to default.HttpBaseAddress.
    /// </summary>
    internal ClientRecord AlignRegistrationToHostHttpBase(string hostName, ClientRecord record)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostName);
        ArgumentNullException.ThrowIfNull(record);

        HostedAuthorizationServer host = Host(hostName);
        if(host.HttpBaseAddress is null)
        {
            throw new InvalidOperationException(
                $"HTTP host '{hostName}' must be started before aligning registration issuer.");
        }
        if(record.IssuerUri is null)
        {
            return record;
        }

        Uri httpAlignedIssuer = new(host.HttpBaseAddress, record.IssuerUri.AbsolutePath);
        Uri? httpAlignedResponseUri = record.ResponseUri is null
            ? null
            : new Uri(host.HttpBaseAddress, record.ResponseUri.AbsolutePath);

        ClientRecord aligned = record with
        {
            IssuerUri = httpAlignedIssuer,
            ResponseUri = httpAlignedResponseUri ?? record.ResponseUri
        };
        host.Registrations[aligned.TenantId.Value] = aligned;
        host.Registrations[aligned.ClientId] = aligned;

        return aligned;
    }


    /// <summary>
    /// Constructs an <see cref="OAuthClient"/> with the full dynamic-registration
    /// + AuthCode transport wired but without any pre-existing
    /// <see cref="ClientRegistration"/>. Used by the canonical phase 4 test
    /// that registers dynamically and then drives an AuthCode flow against
    /// the freshly-issued registration.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The infrastructure wires three transports:
    /// </para>
    /// <list type="bullet">
    ///   <item><description>
    ///     <c>SendJsonPostAsync</c> — dispatches the RFC 7591 §3 POST to
    ///     <see cref="RegistrationEndpoints.HandleCreateAsync"/> with the
    ///     <see cref="DynamicRegistrationTenant"/> as the tenant identifier.
    ///   </description></item>
    ///   <item><description>
    ///     <c>SendFormPostAsync</c> — dispatches PAR / token / revocation
    ///     calls via a tenant-lookup transport that reads the segment from
    ///     the URL and resolves the <see cref="ClientRecord"/> from
    ///     <see cref="Registrations"/>.
    ///   </description></item>
    ///   <item><description>
    ///     <c>ResolveAuthorizationServerMetadataAsync</c> — returns AS
    ///     metadata whose endpoints point at the test verifier's hostnames
    ///     for the configured tenant segment.
    ///   </description></item>
    /// </list>
    /// </remarks>
    public OAuthClient CreateOAuthClientWithoutRegistration()
    {
        Dictionary<string, OAuthFlowState> clientFlowStore = [];

        Uri baseUri = new("https://verifier.example.com");
        Uri parEndpoint = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodePar, DynamicRegistrationTenant));
        Uri authEndpoint = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, DynamicRegistrationTenant));
        Uri tokenEndpoint = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, DynamicRegistrationTenant));

        AuthorizationServerMetadata metadata = new()
        {
            Issuer = IssuerUri,
            PushedAuthorizationRequestEndpoint = parEndpoint,
            AuthorizationEndpoint = authEndpoint,
            TokenEndpoint = tokenEndpoint
        };

        LookupTransport transport = new(Server, Registrations, IssuerUri.OriginalString);

        OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create(
            sendFormPostAsync: (endpoint, fields, headers, _, ct) =>
                transport.SendAsync(endpoint, fields, headers, ct),
            saveStateAsync: (state, _, ct) =>
            {
                clientFlowStore[state.FlowId] = state;
                return ValueTask.CompletedTask;
            },
            loadStateAsync: (flowId, _, ct) =>
                ValueTask.FromResult(clientFlowStore.GetValueOrDefault(flowId)),
            loadStateByRequestUriAsync: (requestUri, _, ct) =>
            {
                foreach(OAuthFlowState state in clientFlowStore.Values)
                {
                    if(state is Verifiable.OAuth.AuthCode.States.ParCompletedState pc
                        && string.Equals(
                            pc.Par.RequestUri.ToString(), requestUri, StringComparison.Ordinal))
                    {
                        return ValueTask.FromResult<OAuthFlowState?>(state);
                    }
                }

                return ValueTask.FromResult<OAuthFlowState?>(null);
            },
            parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
            parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
            parseAuthorizationServerMetadataAsync: (body, ct) =>
                throw new NotImplementedException("Test host pre-resolves metadata; the parser is not exercised."),
            parseRegistrationResponseAsync: (body, ct) => ParseRegistrationResponseJson(body),
            resolveAuthorizationServerMetadataAsync: (issuer, context, ct) =>
                ValueTask.FromResult(metadata),
            resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            timeProvider: Time,
            sendJsonPostAsync: async (endpoint, jsonBody, headers, context, cancellationToken) =>
            {
                //Headers and exchange context are unused for the global registration
                //POST — RFC 7591 §3 is unauthenticated and the test host is single-tenant.
                _ = headers;
                _ = context;
                TenantId tenantId = new(DynamicRegistrationTenant);
                ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
                    WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                    WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
                    WellKnownCapabilityIdentifiers.OAuthDynamicClientRegistration);

                ServerHttpResponse response = await RegistrationEndpoints.HandleCreateAsync(
                    tenantId,
                    jsonBody,
                    capabilities,
                    new ExchangeContext(),
                    Server,
                    cancellationToken).ConfigureAwait(false);

                return new HttpResponseData
                {
                    Body = response.Body ?? string.Empty,
                    StatusCode = response.StatusCode
                };
            },
            sendJsonGetAsync: (endpoint, headers, _, ct) =>
                DispatchManagementAsync(endpoint, headers, WellKnownHttpMethods.Get, jsonBody: null, ct),
            sendJsonPutAsync: (endpoint, jsonBody, headers, _, ct) =>
                DispatchManagementAsync(endpoint, headers, WellKnownHttpMethods.Put, jsonBody: jsonBody, ct),
            sendJsonDeleteAsync: (endpoint, headers, _, ct) =>
                DispatchManagementAsync(endpoint, headers, WellKnownHttpMethods.Delete, jsonBody: null, ct),
            parseClientMetadataAsync: ParseClientMetadataJson);

        return new OAuthClient(infrastructure);
    }


    /// <summary>
    /// Test-transport dispatcher for the three RFC 7592 management methods.
    /// Resolves the registration by tenant segment from the URL path, builds
    /// an <see cref="IncomingRequest"/> carrying the Authorization header
    /// (and the request body for PUT), then dispatches via
    /// <see cref="AuthorizationServer.DispatchAsync"/>.
    /// </summary>
    private async ValueTask<HttpResponseData> DispatchManagementAsync(
        Uri endpoint,
        OutgoingHeaders headers,
        string method,
        string? jsonBody,
        CancellationToken cancellationToken)
    {
        string path = endpoint.IsAbsoluteUri ? endpoint.AbsolutePath : endpoint.OriginalString;

        string segment = LookupTransport.ExtractTenantSegmentForTests(path);
        if(!Registrations.TryGetValue(segment, out ClientRecord? registration))
        {
            return new HttpResponseData
            {
                StatusCode = 404,
                Body = $"No registration found for segment '{segment}'."
            };
        }

        Dictionary<string, string[]> headerDict = new(StringComparer.OrdinalIgnoreCase);
        foreach(KeyValuePair<string, string> pair in headers.Values)
        {
            headerDict[pair.Key] = [pair.Value];
        }
        RequestHeaders requestHeaders = new(headerDict);

        RequestBody body = jsonBody is null
            ? RequestBody.None
            : new RequestBody
            {
                Bytes = Encoding.UTF8.GetBytes(jsonBody),
                ContentType = WellKnownMediaTypes.Application.Json
            };

        IncomingRequest request = new(
            Path: path,
            Method: method,
            Fields: new RequestFields(new Dictionary<string, string>(0)),
            Headers: requestHeaders,
            RouteValues: RouteValues.Empty)
        {
            Body = body
        };

        ExchangeContext context = new();
        context.SetTenantId(segment);
        context.SetIssuer(IssuerUri);
        context.SetRegistration(registration);

        ServerHttpResponse response = await Server.DispatchAsync(
            request, context, cancellationToken).ConfigureAwait(false);

        return new HttpResponseData
        {
            Body = response.Body ?? string.Empty,
            StatusCode = response.StatusCode
        };
    }


    /// <summary>
    /// Minimal client-side <see cref="ClientMetadata"/> parser used by the
    /// test transport. Reads only the fields the canonical lifecycle test
    /// exercises (<c>client_id</c>, <c>redirect_uris</c>, <c>scope</c>,
    /// <c>client_name</c>); production wiring uses
    /// <c>Verifiable.OAuth.Json</c>.
    /// </summary>
    private static ValueTask<ClientMetadata> ParseClientMetadataJson(string body, CancellationToken cancellationToken)
    {
        _ = cancellationToken;
        using JsonDocument doc = JsonDocument.Parse(body);
        JsonElement root = doc.RootElement;

        List<Uri> redirectUris = [];
        if(root.TryGetProperty("redirect_uris", out JsonElement uris))
        {
            foreach(JsonElement el in uris.EnumerateArray())
            {
                string? s = el.GetString();
                if(s is not null)
                {
                    redirectUris.Add(new Uri(s));
                }
            }
        }

        string? clientName = root.TryGetProperty("client_name", out JsonElement nm) ? nm.GetString() : null;
        string? scope = root.TryGetProperty("scope", out JsonElement sc) ? sc.GetString() : null;

        return ValueTask.FromResult(new ClientMetadata
        {
            ClientName = clientName,
            RedirectUris = redirectUris,
            Scope = scope
        });
    }


    private static ValueTask<RegistrationResponse> ParseRegistrationResponseJson(string body)
    {
        using JsonDocument doc = JsonDocument.Parse(body);
        JsonElement root = doc.RootElement;

        string clientIdValue = root.GetProperty("client_id").GetString()
            ?? throw new FormatException("RFC 7591 §3.2.1 response missing client_id.");

        RegistrationAccessToken? token = null;
        if(root.TryGetProperty("registration_access_token", out JsonElement tokElem)
            && tokElem.GetString() is string tokenValue)
        {
            token = new RegistrationAccessToken(tokenValue);
        }

        Uri? mgmtUri = null;
        if(root.TryGetProperty("registration_client_uri", out JsonElement mgmtElem)
            && mgmtElem.GetString() is string mgmtValue
            && Uri.TryCreate(mgmtValue, UriKind.RelativeOrAbsolute, out Uri? parsedMgmt))
        {
            mgmtUri = parsedMgmt;
        }

        DateTimeOffset? issuedAt = null;
        if(root.TryGetProperty("client_id_issued_at", out JsonElement issuedElem)
            && issuedElem.TryGetInt64(out long unixIssued))
        {
            issuedAt = DateTimeOffset.FromUnixTimeSeconds(unixIssued);
        }

        ClientMetadata metadata = new()
        {
            ClientName = root.TryGetProperty("client_name", out JsonElement nm) ? nm.GetString() : null,
            Scope = root.TryGetProperty("scope", out JsonElement sc) ? sc.GetString() : null
        };

        return ValueTask.FromResult(new RegistrationResponse
        {
            ClientId = new ClientId(clientIdValue),
            Metadata = metadata,
            AccessToken = token,
            ManagementUri = mgmtUri,
            IssuedAt = issuedAt
        });
    }


    /// <summary>
    /// Creates a <see cref="TestWallet"/> for OID4VP flows.
    /// </summary>
    /// <param name="expectedVerifierClientId">
    /// The Verifier client identifier the Wallet expects in every JAR.
    /// </param>
    /// <param name="credentials">
    /// Map from credential identifier to serialized SD-JWT string.
    /// </param>
    /// <param name="holderPrivateKey">
    /// The holder's private key for KB-JWT signing.
    /// </param>
    public TestWallet CreateWallet(
        string expectedVerifierClientId,
        Dictionary<string, string> credentials,
        PrivateKeyMemory holderPrivateKey)
    {
        return new TestWallet(expectedVerifierClientId, credentials, holderPrivateKey, Time);
    }


    /// <summary>
    /// Resolves the endpoint chain for a registration in the supplied
    /// per-request context. Tests that don't have a meaningful context to
    /// thread (structural inspection, capability listing, no actual request
    /// in flight) construct a fresh empty <see cref="ExchangeContext"/> at
    /// the call site.
    /// </summary>
    public ValueTask<EndpointChain> GetEndpointsAsync(ClientRecord registration, ExchangeContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        //Phase 9h chunk 8 — AuthorizationServer no longer exposes a public
        //GetEndpointsAsync. Tests inspect the chain directly via the proper
        //BuildForRequestAsync entry point; the context must carry the active
        //server so capability resolution and URL resolution can reach the
        //integration delegates.
        context.SetServer(Server);
        return EndpointChain.BuildForRequestAsync(registration, context, CancellationToken.None);
    }


    /// <summary>
    /// Returns the current server-side flow state. Resolves external handles
    /// (request_uri tokens, codes) through the secondary indexes, so tests
    /// can look up state using whatever handle they have.
    /// </summary>
    public (OAuthFlowState State, int StepCount) GetFlowState(string key)
    {
        if(FlowStates.TryGetValue(key, out var entry))
        {
            return entry;
        }

        if(RequestUriTokenIndex.TryGetValue(key, out string? flowId)
            && FlowStates.TryGetValue(flowId, out entry))
        {
            return entry;
        }

        if(CodeIndex.TryGetValue(key, out flowId)
            && FlowStates.TryGetValue(flowId, out entry))
        {
            return entry;
        }

        throw new KeyNotFoundException($"No flow found for key '{key}'.");
    }


    /// <summary>
    /// OID4VP PAR — creates a new Verifiable Presentation flow.
    /// Returns the request URI (for QR code) and the per-flow handle (for
    /// subsequent JAR and direct_post steps). The internal flow identifier
    /// never leaves this method.
    /// </summary>
    public Task<(Uri RequestUri, string ParHandle)> HandleParAsync(
        VerifierKeyMaterial keyMaterial,
        TransactionNonce nonce,
        PreparedDcqlQuery dcqlQuery,
        CancellationToken cancellationToken) =>
        HandleParAsync(keyMaterial, nonce, dcqlQuery,
            transactionData: null, jarAdditionalHeaderClaims: null, cancellationToken);


    /// <summary>
    /// OID4VP PAR with optional <c>transaction_data</c> descriptors bound into
    /// the JAR per OID4VP 1.0 §8.4. When <paramref name="transactionData"/> is
    /// non-null the executor sets
    /// <see cref="Verifiable.OAuth.Validation.ValidationContext.ExpectedTransactionDataHashes"/>
    /// at verification time and the HAIP profile's
    /// <c>CheckKbJwtTransactionDataHashes</c> enforces the round-trip.
    /// </summary>
    public Task<(Uri RequestUri, string ParHandle)> HandleParAsync(
        VerifierKeyMaterial keyMaterial,
        TransactionNonce nonce,
        PreparedDcqlQuery dcqlQuery,
        IReadOnlyList<string>? transactionData,
        CancellationToken cancellationToken) =>
        HandleParAsync(keyMaterial, nonce, dcqlQuery,
            transactionData, jarAdditionalHeaderClaims: null, cancellationToken);


    /// <summary>
    /// OID4VP PAR with optional <paramref name="jarAdditionalHeaderClaims"/> —
    /// the federation <c>trust_chain</c>, the <c>x5c</c> certificate chain,
    /// or the <c>jwt</c> attestation depending on the client_id prefix per
    /// OID4VP 1.0 §5.9.3. The executor merges these into the JAR header at
    /// signing time.
    /// </summary>
    public Task<(Uri RequestUri, string ParHandle)> HandleParAsync(
        VerifierKeyMaterial keyMaterial,
        TransactionNonce nonce,
        PreparedDcqlQuery dcqlQuery,
        IReadOnlyList<string>? transactionData,
        JwtHeader? jarAdditionalHeaderClaims,
        CancellationToken cancellationToken) =>
        HandleParAsync(keyMaterial, nonce, dcqlQuery, transactionData,
            jarAdditionalHeaderClaims, responseMode: null, cancellationToken);


    /// <summary>
    /// OID4VP PAR with an explicit <c>response_mode</c> override on the
    /// JAR — typically <see cref="WellKnownResponseModes.DirectPost"/> for
    /// the plaintext direct_post path per OID4VP 1.0 §8.2. Defaults to
    /// <see cref="WellKnownResponseModes.DirectPostJwt"/> (HAIP 1.0 §5.1)
    /// when null.
    /// </summary>
    public async Task<(Uri RequestUri, string ParHandle)> HandleParAsync(
        VerifierKeyMaterial keyMaterial,
        TransactionNonce nonce,
        PreparedDcqlQuery dcqlQuery,
        IReadOnlyList<string>? transactionData,
        JwtHeader? jarAdditionalHeaderClaims,
        string? responseMode,
        CancellationToken cancellationToken)
    {
        ExchangeContext context = new();
        context.SetTenantId(keyMaterial.Registration.TenantId);
        context.SetTransactionNonce(nonce);
        context.SetPreparedQuery(dcqlQuery);
        context.SetDecryptionKeyId(keyMaterial.EncryptionKeyId);

        if(transactionData is { Count: > 0 })
        {
            context.SetTransactionData(transactionData);
        }

        if(jarAdditionalHeaderClaims is { Count: > 0 })
        {
            context.SetJarAdditionalHeaderClaims(jarAdditionalHeaderClaims);
        }

        if(!string.IsNullOrWhiteSpace(responseMode))
        {
            context.SetOid4VpResponseMode(responseMode);
        }

        //OID4VP PAR is invoked internally by the verifier app — not from a
        //wire HTTP request. The matcher reads context (TransactionNonce,
        //PreparedQuery, DecryptionKeyId) and ignores path and fields.
        //IncomingRequest is constructed for protocol-uniformity but its
        //Path is the canonical /par template substituted with the segment;
        //a real verifier deployment that exposed this endpoint internally
        //would do the same.
        string segment = keyMaterial.Registration.TenantId.Value;
        string parPath = TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodePar, segment);

        IncomingRequest request = new(
            Path: parPath,
            Method: "POST",
            Fields: new RequestFields(),
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty);

        ServerHttpResponse response = await Server.DispatchAsync(
            request, context, cancellationToken).ConfigureAwait(false);

        //RFC 9126 §2.2: a successful PAR response is HTTP 201 Created (accept any 2xx).
        if(!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"PAR failed with status {response.StatusCode}: {response.Body}");
        }

        //The library placed the per-flow handle on context before invoking
        //ResolveEndpointUriAsync; it is still on context after dispatch returns.
        string parHandle = context.ParHandle
            ?? throw new InvalidOperationException("ParHandle not set after PAR.");
        Uri requestUri = context.GeneratedRequestUri
            ?? throw new InvalidOperationException("GeneratedRequestUri not set after PAR.");

        return (requestUri, parHandle);
    }


    /// <summary>
    /// OID4VP JAR request — fetches the signed JAR for a continuing flow.
    /// The <paramref name="externalToken"/> is the opaque token from
    /// <see cref="HandleParAsync"/>, not the internal flow identifier.
    /// </summary>
    public async Task<string> HandleJarRequestAsync(
        VerifierKeyMaterial keyMaterial,
        string externalToken,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(externalToken);

        ExchangeContext context = new();
        context.SetTenantId(keyMaterial.Registration.TenantId);
        context.SetCorrelationKey(externalToken);

        //JAR Request matches on context.CorrelationKey — the verifier app's
        //URL routing layer extracted the {flowId} segment from the JAR URL
        //and placed it on context before dispatching.
        string segment = keyMaterial.Registration.TenantId.Value;
        string jarPath = TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.Oid4VpJarRequest, segment)
            .Replace("{flowId}", externalToken, StringComparison.Ordinal);

        IncomingRequest request = new(
            Path: jarPath,
            Method: "GET",
            Fields: new RequestFields(),
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty);

        ServerHttpResponse response = await Server.DispatchAsync(
            request, context, cancellationToken).ConfigureAwait(false);

        if(response.StatusCode != 200)
        {
            throw new InvalidOperationException(
                $"JAR request failed with status {response.StatusCode}: {response.Body}");
        }

        return context.Jar
            ?? throw new InvalidOperationException("JAR not set in context after dispatch.");
    }


    /// <summary>
    /// OID4VP JAR request via the POST path — <c>request_uri_method=post</c>
    /// per OID4VP 1.0 §5.10. The Wallet sends <c>wallet_nonce</c> in the form
    /// body; the Verifier echoes it as the JAR's <c>wallet_nonce</c> claim.
    /// </summary>
    public async Task<string> HandleJarRequestPostAsync(
        VerifierKeyMaterial keyMaterial,
        string externalToken,
        string walletNonce,
        string? walletMetadataJson,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(externalToken);
        ArgumentException.ThrowIfNullOrWhiteSpace(walletNonce);

        ExchangeContext context = new();
        context.SetTenantId(keyMaterial.Registration.TenantId);
        context.SetCorrelationKey(externalToken);

        string segment = keyMaterial.Registration.TenantId.Value;
        string jarPath = TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.Oid4VpJarRequest, segment)
            .Replace("{flowId}", externalToken, StringComparison.Ordinal);

        RequestFields fields = new()
        {
            [Oid4VpAuthorizationRequestParameterNames.WalletNonce] = walletNonce
        };

        if(walletMetadataJson is not null)
        {
            fields[Oid4VpAuthorizationRequestParameterNames.WalletMetadata] = walletMetadataJson;
        }

        IncomingRequest request = new(
            Path: jarPath,
            Method: "POST",
            Fields: fields,
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty);

        ServerHttpResponse response = await Server.DispatchAsync(
            request, context, cancellationToken).ConfigureAwait(false);

        if(response.StatusCode != 200)
        {
            throw new InvalidOperationException(
                $"JAR POST request failed with status {response.StatusCode}: {response.Body}");
        }

        return context.Jar
            ?? throw new InvalidOperationException("JAR not set in context after POST dispatch.");
    }


    /// <summary>
    /// OID4VP direct_post — posts the encrypted VP token response.
    /// The <paramref name="externalToken"/> is the opaque token from
    /// <see cref="HandleParAsync"/>, not the internal flow identifier.
    /// </summary>
    public async Task<PresentationVerifiedState> HandleDirectPostAsync(
        VerifierKeyMaterial keyMaterial,
        string externalToken,
        string compactJwe,
        Uri? redirectUri,
        CancellationToken cancellationToken)
    {
        ExchangeContext context = new();
        context.SetTenantId(keyMaterial.Registration.TenantId);

        if(redirectUri is not null)
        {
            context.SetOid4VpRedirectUri(redirectUri);
        }

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.Response] = compactJwe,
            [OAuthRequestParameterNames.State] = externalToken
        };

        string segment = keyMaterial.Registration.TenantId.Value;
        string directPostPath = TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.Oid4VpDirectPost, segment);

        IncomingRequest request = new(
            Path: directPostPath,
            Method: "POST",
            Fields: fields,
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty);

        ServerHttpResponse response = await Server.DispatchAsync(
            request, context, cancellationToken).ConfigureAwait(false);

        if(response.StatusCode != 200)
        {
            throw new InvalidOperationException(
                $"direct_post failed with status {response.StatusCode}: {response.Body}");
        }

        return (PresentationVerifiedState)GetFlowState(externalToken).State;
    }


    /// <summary>
    /// Dispatches a pre-built <see cref="IncomingRequest"/> for the given
    /// segment. Used by tests that need to verify negative-path behaviour
    /// (404 after deregistration, malformed requests, etc.) — the request
    /// shape is the test's responsibility.
    /// </summary>
    public async ValueTask<ServerHttpResponse> DispatchBySegmentAsync(
        string segment,
        IncomingRequest request,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        context.SetTenantId(segment);
        return await Server.DispatchAsync(request, context, cancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Test-side convenience: dispatches a request at the URL the
    /// application's
    /// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>
    /// resolves for <paramref name="endpointName"/> and
    /// <paramref name="segment"/>, builds the <see cref="IncomingRequest"/>
    /// from that URL's <see cref="Uri.AbsolutePath"/> plus the supplied HTTP
    /// method and fields, and dispatches. Tests pass
    /// <see cref="WellKnownEndpointNames"/> constants directly.
    /// </summary>
    /// <remarks>
    /// Routing through <c>ResolveEndpointUriAsync</c> means tests exercise
    /// the same URL-resolution path the production AS uses. The
    /// <see cref="ResolveEndpointUriAsync"/> lambda wired in this fixture is
    /// the single test-side source of URL shape; changes to URL shape happen
    /// there, not in every test.
    /// </remarks>
    public async ValueTask<ServerHttpResponse> DispatchAtEndpointAsync(
        string segment,
        string endpointName,
        string httpMethod,
        RequestFields fields,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);
        ArgumentException.ThrowIfNullOrWhiteSpace(endpointName);
        ArgumentException.ThrowIfNullOrWhiteSpace(httpMethod);
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(context);

        //The fixture's URL-shape choice lives in ComposeEndpointPath /
        //ResolveEndpointUriAsync — both call the same EndpointPathSuffix
        //helper. ComposeEndpointPath is the synchronous form; we use it
        //here so DispatchAtEndpointAsync works for unknown segments
        //(negative-path tests verifying 404 behaviour for unregistered
        //tenants). The dispatcher's own AuthorizationServer.DispatchAsync
        //invokes Integration.ResolveEndpointUriAsync at chain-build time
        //for the happy path, so the lambda is end-to-end exercised
        //regardless of whether this helper calls it explicitly.
        string path = ComposeEndpointPath(endpointName, segment);

        IncomingRequest request = new(
            Path: path,
            Method: httpMethod,
            Fields: fields,
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty);

        context.SetTenantId(segment);
        return await Server.DispatchAsync(request, context, cancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Dispatches a request carrying a JSON body to the named endpoint — the
    /// body-bearing form of
    /// <see cref="DispatchAtEndpointAsync(string, string, string, RequestFields, ExchangeContext, CancellationToken)"/>
    /// for endpoints that read <c>IncomingRequest.Body</c> (AuthZEN, SSF, Global
    /// Token Revocation). A <see langword="null"/> <paramref name="jsonBody"/>
    /// dispatches with no body.
    /// </summary>
    public async ValueTask<ServerHttpResponse> DispatchAtEndpointAsync(
        string segment,
        string endpointName,
        string httpMethod,
        RequestFields fields,
        string? jsonBody,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);
        ArgumentException.ThrowIfNullOrWhiteSpace(endpointName);
        ArgumentException.ThrowIfNullOrWhiteSpace(httpMethod);
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(context);

        string path = ComposeEndpointPath(endpointName, segment);

        RequestBody body = jsonBody is null
            ? RequestBody.None
            : new RequestBody
            {
                Bytes = Encoding.UTF8.GetBytes(jsonBody),
                ContentType = WellKnownMediaTypes.Application.Json
            };

        IncomingRequest request = new(
            Path: path,
            Method: httpMethod,
            Fields: fields,
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty)
        {
            Body = body
        };

        context.SetTenantId(segment);
        return await Server.DispatchAsync(request, context, cancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Deregisters a client by endpoint segment and emits a
    /// <see cref="ClientDeregistered"/> event.
    /// </summary>
    public void DeregisterClient(string segment, string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        if(!Registrations.TryGetValue(segment, out ClientRecord? registration))
        {
            return;
        }

        Server.DeregisterClient(registration, reason, new ExchangeContext());
    }


    /// <summary>
    /// Rotates the signing key for a registered client, emits a
    /// <see cref="ClientUpdated"/> event, and returns the new key material.
    /// </summary>
    /// <remarks>
    /// The old signing key remains in the key store so in-flight flows that were
    /// signed with it can still be verified.
    /// </remarks>
    public VerifierKeyMaterial RotateSigningKey(string segment)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);

        if(!Registrations.TryGetValue(segment, out ClientRecord? previous))
        {
            throw new InvalidOperationException(
                $"No registration found for segment '{segment}'.");
        }

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> newSigningKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> newExchangeKeys =
            TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();

        KeyId newSigningKeyId = new($"urn:uuid:{Guid.NewGuid()}");
        KeyId newEncryptionKeyId = new($"urn:uuid:{Guid.NewGuid()}");

        SigningKeys[newSigningKeyId] = newSigningKeys.PrivateKey;
        VerificationKeys[newSigningKeyId] = newSigningKeys.PublicKey;
        DecryptionKeys[newEncryptionKeyId] = newExchangeKeys.PrivateKey;

        string jwksJson = EphemeralEncryptionKeyPair.CreatePublicKeyJwks(
            newExchangeKeys.PublicKey,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared);

        newExchangeKeys.PublicKey.Dispose();

        VerifierClientMetadata newMetadata =
            HaipProfile.CreateVerifierClientMetadata(previous.ClientId, jwksJson);

        ImmutableDictionary<KeyUsageContext, SigningKeySet>.Builder signingKeysBuilder =
            ImmutableDictionary.CreateBuilder<KeyUsageContext, SigningKeySet>();
        foreach(KeyValuePair<KeyUsageContext, SigningKeySet> entry in previous.SigningKeys)
        {
            signingKeysBuilder[entry.Key] = entry.Value;
        }
        signingKeysBuilder[KeyUsageContext.JarSigning] =
            new SigningKeySet { Current = [newSigningKeyId] };

        ClientRecord updated = previous with
        {
            SigningKeys = signingKeysBuilder.ToImmutable(),
            ClientMetadata = newMetadata
        };

        //Update the routing table directly — the observer also handles this
        //via the ClientUpdated event, but explicit update ensures consistency.
        Registrations[segment] = updated;

        Server.UpdateClient(previous, updated, new ExchangeContext());

        return new VerifierKeyMaterial(
            updated,
            newSigningKeys.PublicKey,
            newSigningKeys.PrivateKey,
            newExchangeKeys.PrivateKey,
            newEncryptionKeyId,
            newSigningKeyId);
    }


    /// <summary>
    /// Generates a fresh P-256 signing key pair, stores it under a new <see cref="KeyId"/>,
    /// and returns that identifier. Does not modify any registration — the caller
    /// decides which rotation slot the new key enters and calls
    /// <see cref="UpdateSigningKeys"/> to apply the change.
    /// </summary>
    /// <remarks>
    /// Used by rotation tests that need fine-grained control over which slot a new
    /// key lands in (Incoming, Current, Retiring, Historical). The more coarse
    /// <see cref="RotateSigningKey"/> allocates and installs in a single step.
    /// </remarks>
    public KeyId AllocateSigningKey()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> fresh =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        KeyId newKeyId = new($"urn:uuid:{Guid.NewGuid()}");
        SigningKeys[newKeyId] = fresh.PrivateKey;
        VerificationKeys[newKeyId] = fresh.PublicKey;

        return newKeyId;
    }


    /// <summary>
    /// Replaces the <see cref="ClientRecord.SigningKeys"/> map for the given
    /// segment, then re-publishes the updated registration through the server's
    /// <see cref="AuthorizationServer.UpdateClient"/> so a <c>ClientUpdated</c>
    /// event is emitted. Used by rotation tests to inject Incoming, Retiring,
    /// and Historical slot configurations without going through the full
    /// <see cref="RotateSigningKey"/> path.
    /// </summary>
    /// <param name="segment">The endpoint segment identifying the registration to update.</param>
    /// <param name="signingKeys">The complete <see cref="SigningKeySet"/> map replacing the current one.</param>
    public void UpdateSigningKeys(
        string segment,
        IReadOnlyDictionary<KeyUsageContext, SigningKeySet> signingKeys)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);
        ArgumentNullException.ThrowIfNull(signingKeys);

        if(!Registrations.TryGetValue(segment, out ClientRecord? previous))
        {
            throw new InvalidOperationException(
                $"No registration found for segment '{segment}'.");
        }

        ClientRecord updated = previous with
        {
            SigningKeys = signingKeys.ToImmutableDictionary()
        };

        Registrations[segment] = updated;
        Server.UpdateClient(previous, updated, new ExchangeContext());
    }


    /// <summary>
    /// Registers a client whose policy profile requires DPoP — HAIP 1.0 by
    /// default. Allows AuthorizationCode + PushedAuthorization capabilities so
    /// the canonical token-endpoint DPoP enforcement path is reachable.
    /// </summary>
    public VerifierKeyMaterial RegisterDpopClient(
        string clientId,
        Uri baseUri,
        PolicyProfile? profile = null,
        ImmutableHashSet<CapabilityIdentifier>? capabilities = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentNullException.ThrowIfNull(baseUri);

        capabilities ??= ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
            WellKnownCapabilityIdentifiers.OidcUserInfo,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint);

        string segment = Guid.NewGuid().ToString("N")[..8];
        KeyId signingKeyId = new($"urn:uuid:{Guid.NewGuid()}");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signingKeyPair =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        SigningKeys[signingKeyId] = signingKeyPair.PrivateKey;
        VerificationKeys[signingKeyId] = signingKeyPair.PublicKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> exchangeKeyPair =
            TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        KeyId encryptionKeyId = new($"urn:uuid:{Guid.NewGuid()}");
        DecryptionKeys[encryptionKeyId] = exchangeKeyPair.PrivateKey;
        exchangeKeyPair.PublicKey.Dispose();

        ClientRecord registration = new()
        {
            ClientId = clientId,
            TenantId = segment,
            IssuerUri = new Uri($"https://issuer.test/{segment}"),
            AllowedCapabilities = capabilities,
            AllowedRedirectUris = ImmutableHashSet.Create(
                new Uri("https://client.example.com/callback")),
            AllowedPostLogoutRedirectUris = ImmutableHashSet.Create(
                new Uri("https://client.example.com/post-logout")),
            AllowedScopes = ImmutableHashSet.Create(
                WellKnownScopes.OpenId,
                WellKnownScopes.Profile,
                WellKnownScopes.Email,
                WellKnownScopes.Address,
                WellKnownScopes.Phone),
            SigningKeys = ImmutableDictionary<KeyUsageContext, SigningKeySet>.Empty
                .Add(KeyUsageContext.AccessTokenIssuance,
                    new SigningKeySet { Current = [signingKeyId] })
                .Add(KeyUsageContext.IdTokenIssuance,
                    new SigningKeySet { Current = [signingKeyId] }),
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty,
            //FAPI 2.0 / HAIP require a resolved aud on access tokens. Map the
            //openid scope to a deterministic resource-server identifier so the
            //RFC 9068 producer has an audience to embed.
            ScopeToAudience = new Dictionary<string, IReadOnlyList<string>>
            {
                [WellKnownScopes.OpenId] = new[] { "https://rs.example.com" }
            },
            Profile = profile ?? PolicyProfile.Haip10
        };

        Registrations[segment] = registration;
        Registrations[clientId] = registration;

        Server.RegisterClient(
            registration,
            new RegistrationAccessToken(Guid.NewGuid().ToString("N")),
            new ExchangeContext());

        return new VerifierKeyMaterial(
            registration,
            signingKeyPair.PublicKey,
            signingKeyPair.PrivateKey,
            decryptionPrivateKey: exchangeKeyPair.PrivateKey,
            encryptionKeyId: encryptionKeyId,
            signingKeyId: signingKeyId);
    }


    /// <summary>
    /// Registers an OIDC Back-Channel Logout relying party: a DPoP/auth-code client
    /// (RP-Initiated + Back-Channel Logout capable, <see cref="PolicyProfile.Rfc6749WithPkce"/>)
    /// whose <see cref="ClientRecord.BackchannelLogoutUri"/> is set to
    /// <paramref name="backchannelLogoutUri"/> — the receiver endpoint the OP POSTs this
    /// RP's <c>logout_token</c> to during federated logout
    /// (<see href="https://openid.net/specs/openid-connect-backchannel-1_0.html#BCRegistration">OIDC Back-Channel Logout 1.0 §2.2</see>).
    /// </summary>
    /// <remarks>
    /// Builds the baseline registration via <see cref="RegisterDpopClient"/>, then
    /// re-stores it with <see cref="ClientRecord.BackchannelLogoutUri"/> populated — the
    /// same register-then-upgrade pattern <see cref="RegisterFederationCapableClient"/>
    /// uses, because the routing dictionaries are host-internal.
    /// </remarks>
    /// <param name="clientId">The OAuth client identifier.</param>
    /// <param name="baseUri">The base URI for the client's endpoints.</param>
    /// <param name="backchannelLogoutUri">The RP's back-channel logout receiver URI.</param>
    /// <param name="capabilities">The capabilities this RP is allowed to use.</param>
    /// <returns>The RP's key material, with <see cref="VerifierKeyMaterial.Registration"/> pointing at the upgraded record.</returns>
    public VerifierKeyMaterial RegisterBackChannelLogoutClient(
        string clientId,
        Uri baseUri,
        Uri backchannelLogoutUri,
        ImmutableHashSet<CapabilityIdentifier> capabilities)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentNullException.ThrowIfNull(baseUri);
        ArgumentNullException.ThrowIfNull(backchannelLogoutUri);
        ArgumentNullException.ThrowIfNull(capabilities);

        VerifierKeyMaterial material = RegisterDpopClient(
            clientId, baseUri, PolicyProfile.Rfc6749WithPkce, capabilities);

        ClientRecord updated = material.Registration with
        {
            BackchannelLogoutUri = backchannelLogoutUri
        };

        string segment = updated.TenantId.Value;
        Registrations[segment] = updated;
        Registrations[clientId] = updated;
        Server.RegisterClient(
            updated,
            new RegistrationAccessToken(Guid.NewGuid().ToString("N")),
            new ExchangeContext());
        material.Registration = updated;

        return material;
    }


    /// <summary>
    /// Wires up the AS-side DPoP delegates on the server's integration:
    /// HMAC-key byte-loader, HMAC keyset accessor, nonce issuance, nonce
    /// validation, and proof validation. Returns the in-process HMAC
    /// keyset so tests can drive slot transitions. Idempotent — repeat
    /// calls reuse the existing keyset.
    /// </summary>
    public InProcessKeySet EnableDpop(string initialKid = "test-hmac-1")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(initialKid);

        if(DpopHmacKeySet is not null)
        {
            return DpopHmacKeySet;
        }

        SymmetricKey hmacMaterial = CreateFreshHmacKey(initialKid);
        KeyId initialKidValue = new(initialKid);
        DpopHmacKeySet = new InProcessKeySet();
        DpopHmacKeySet.AddCurrent(initialKidValue, hmacMaterial);

        Server.Integration.ResolveServerHmacKeyAsync = (kid, tenantId, ctx, ct) =>
            ValueTask.FromResult(DpopHmacKeySet!.ResolveMaterial(kid));
        Server.Integration.GetHmacKeySetAsync = (tenantId, ctx, ct) =>
            ValueTask.FromResult(DpopHmacKeySet!.Snapshot());
        Server.Integration.ValidateDpopProofAsync = (request, ct) =>
            DpopProofValidator.ValidateAsync(
                request,
                MicrosoftCryptographicFunctions.VerifyP256Async,
                DpopTestSupport.Parser,
                Base64UrlEncoder,
                Base64UrlDecoder,
                Time,
                MemoryPool,
                iatSkew: WellKnownDpopValues.DefaultIatSkew,
                cancellationToken: ct);
        Server.Integration.IssueDpopNonceAsync = (audience, tenantId, ctx, ct) =>
            DefaultDpopNonceIssuance.IssueAsync(
                audience,
                tenantId,
                ctx,
                Server.Integration.GetHmacKeySetAsync!,
                Server.Integration.SelectHmacKeyAsync,
                Server.Integration.ResolveServerHmacKeyAsync!,
                Time,
                Base64UrlEncoder,
                System.Security.Cryptography.RandomNumberGenerator.Fill,
                MemoryPool,
                ct);
        Server.Integration.ValidateDpopNonceAsync = (presented, audience, tenantId, ctx, ct) =>
            DefaultDpopNonceValidation.ValidateAsync(
                presented,
                audience,
                tenantId,
                ctx,
                Server.Integration.GetHmacKeySetAsync!,
                Server.Integration.ResolveServerHmacKeyAsync!,
                Time,
                WellKnownDpopValues.DefaultNonceValidityWindow,
                Base64UrlDecoder,
                MemoryPool,
                ct);

        return DpopHmacKeySet;
    }


    /// <summary>
    /// Convenience for tests: rotate the DPoP HMAC key by adding a new
    /// Incoming key, promoting it to Current, and retiring the previous
    /// Current keys. Returns the new key's kid. <see cref="EnableDpop"/>
    /// must have been called first.
    /// </summary>
    public KeyId RotateDpopHmacKey(string newKid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(newKid);
        if(DpopHmacKeySet is null)
        {
            throw new InvalidOperationException(
                "EnableDpop must be called before RotateDpopHmacKey.");
        }

        SymmetricKey newMaterial = CreateFreshHmacKey(newKid);
        KeyId newKid_ = new(newKid);

        DpopHmacKeySet.AddIncoming(newKid_, newMaterial);
        DpopHmacKeySet.PromoteIncomingToCurrent(newKid_);

        KeySet snap = DpopHmacKeySet.Snapshot();
        foreach(KeyId old in snap.Current)
        {
            if(!old.Equals(newKid_))
            {
                DpopHmacKeySet.RetireCurrent(old);
            }
        }

        return newKid_;
    }


    /// <summary>
    /// Adds a key to the DPoP HMAC <c>Incoming</c> slot without promoting.
    /// Used by slot-transition rotation tests.
    /// </summary>
    public KeyId AddIncomingDpopHmacKey(string kid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(kid);
        if(DpopHmacKeySet is null)
        {
            throw new InvalidOperationException(
                "EnableDpop must be called before AddIncomingDpopHmacKey.");
        }

        SymmetricKey material = CreateFreshHmacKey(kid);
        KeyId kidValue = new(kid);
        DpopHmacKeySet.AddIncoming(kidValue, material);
        return kidValue;
    }


    /// <summary>Promotes a kid from <c>Incoming</c> to <c>Current</c>.</summary>
    public void PromoteIncomingDpopHmacKey(KeyId kid) =>
        DpopHmacKeySet!.PromoteIncomingToCurrent(kid);


    /// <summary>Moves a kid from <c>Current</c> to <c>Retiring</c>.</summary>
    public void RetireCurrentDpopHmacKey(KeyId kid) =>
        DpopHmacKeySet!.RetireCurrent(kid);


    /// <summary>Archives a kid from <c>Retiring</c> to <c>Historical</c>.</summary>
    public void ArchiveRetiringDpopHmacKey(KeyId kid) =>
        DpopHmacKeySet!.ArchiveRetiring(kid);


    /// <summary>
    /// Mints a fresh 256-bit HMAC-SHA-256 key and wires it for the bound
    /// HMAC delegates registered globally by <see cref="TestSetup"/>.
    /// Records the key for lifetime cleanup at host disposal.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "SymmetricKeyMemory ownership transfers to SymmetricKey; SymmetricKey itself is tracked in DpopOwnedDisposables and disposed when the host is disposed.")]
    private SymmetricKey CreateFreshHmacKey(string id)
    {
        IMemoryOwner<byte> owner = SensitiveMemoryPool<byte>.Shared.Rent(32);
        SymmetricKeyMemory material;
        try
        {
            RandomNumberGenerator.Fill(owner.Memory.Span[..32]);
            material = new SymmetricKeyMemory(owner, CryptoTags.HmacSha256Key);
        }
        catch
        {
            owner.Dispose();
            throw;
        }

        SymmetricKey key = new(
            material,
            id,
            MicrosoftHmacFunctions.ComputeHmacAsync,
            MicrosoftHmacFunctions.VerifyHmacAsync);
        DpopOwnedDisposables.Add(key);
        return key;
    }


    /// <summary>
    /// Builds a DPoP-enabled <see cref="OAuthClient"/> + matching
    /// <see cref="ClientRegistration"/> for the supplied server registration,
    /// generates a fresh P-256 DPoP key, wires the client-side cache, and
    /// returns the components a test needs to drive a full DPoP-bound
    /// AuthCode round-trip.
    /// </summary>
    public DpopClientFixture CreateInProcessDpopEnabledOAuthClient(
        ClientRecord record,
        string redirectUri,
        string issuerUri)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentException.ThrowIfNullOrWhiteSpace(redirectUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(issuerUri);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> dpopKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);
        InMemoryDpopNonceCache nonceCache = new();

        InProcessTransport transport = new(Server, record, record.TenantId, issuerUri);
        Dictionary<string, OAuthFlowState> clientFlowStore = [];

        string segment = record.TenantId.Value;
        Uri issuerUriValue = new(issuerUri);
        //RFC 9449 §4.2 — the htu claim is the URL of the inbound request. The
        //AS-side enforcement composes htu from the issuer authority + request
        //path (it has no direct access to the externally-visible URL); pin the
        //client-side endpoint URLs to the same authority so both sides agree.
        Uri baseUri = new(issuerUriValue.GetLeftPart(UriPartial.Authority));
        Uri parEndpoint = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodePar, segment));
        Uri authEndpoint = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment));
        Uri tokenEndpoint = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

        AuthorizationServerMetadata metadata = new()
        {
            Issuer = issuerUriValue,
            PushedAuthorizationRequestEndpoint = parEndpoint,
            AuthorizationEndpoint = authEndpoint,
            TokenEndpoint = tokenEndpoint
        };

        OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create(
            sendFormPostAsync: (endpoint, fields, headers, _, ct) =>
                transport.SendAsync(endpoint, fields, headers, ct),
            saveStateAsync: (state, _, ct) =>
            {
                clientFlowStore[state.FlowId] = state;
                return ValueTask.CompletedTask;
            },
            loadStateAsync: (flowId, _, ct) =>
                ValueTask.FromResult(clientFlowStore.GetValueOrDefault(flowId)),
            loadStateByRequestUriAsync: (requestUri, _, ct) =>
            {
                foreach(OAuthFlowState state in clientFlowStore.Values)
                {
                    if(state is Verifiable.OAuth.AuthCode.States.ParCompletedState pc
                        && string.Equals(
                            pc.Par.RequestUri.ToString(), requestUri, StringComparison.Ordinal))
                    {
                        return ValueTask.FromResult<OAuthFlowState?>(state);
                    }
                }

                return ValueTask.FromResult<OAuthFlowState?>(null);
            },
            parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
            parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
            parseAuthorizationServerMetadataAsync: (body, ct) =>
                throw new NotImplementedException("Test host pre-resolves metadata; the parser is not exercised."),
            parseRegistrationResponseAsync: (body, ct) =>
                throw new NotImplementedException("DPoP gate test does not exercise dynamic registration."),
            resolveAuthorizationServerMetadataAsync: (issuer, context, ct) =>
                ValueTask.FromResult(metadata),
            resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
            base64UrlEncoder: Base64UrlEncoder,
            timeProvider: Time,
            constructDpopProofAsync: (claims, key, ct) => DpopProofConstruction.BuildAsync(
                claims,
                key,
                Base64UrlEncoder,
                DpopTestSupport.Serializer,
                MicrosoftCryptographicFunctions.SignP256Async,
                MemoryPool,
                ct),
            dpopKey: dpopKey,
            lookupDpopNonce: nonceCache.Lookup,
            storeDpopNonce: nonceCache.Store);

        ClientRegistration registration = new()
        {
            ClientId = new ClientId(record.ClientId),
            AuthorizationServerIssuer = issuerUriValue,
            RedirectUris = [new Uri(redirectUri)],
            AuthenticationMethod = ClientAuthenticationMethod.None,
            Profile = PolicyProfile.Haip10
        };

        return new DpopClientFixture(
            new OAuthClient(infrastructure),
            registration,
            dpopKey,
            nonceCache,
            dpopKeys.PublicKey,
            dpopKeys.PrivateKey,
            clientFlowStore);
    }


    /// <summary>
    /// HTTP-backed counterpart to <see cref="CreateInProcessDpopEnabledOAuthClient"/>.
    /// Starts the in-process Kestrel listener if not already running, aligns
    /// the registration's <see cref="ClientRecord.IssuerUri"/> to the
    /// Kestrel base address (so DPoP htu comparison agrees on both sides),
    /// and wires the <see cref="OAuthClient"/> with
    /// <see cref="HttpClientTransport"/>.
    /// </summary>
    public async ValueTask<DpopClientFixture> CreateDpopEnabledOAuthClientAsync(
        ClientRecord record,
        string redirectUri,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentException.ThrowIfNullOrWhiteSpace(redirectUri);

        await StartHttpHostAsync(cancellationToken).ConfigureAwait(false);

        ClientRecord alignedRecord = AlignRegistrationIssuerToHttpBase(record);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> dpopKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);
        InMemoryDpopNonceCache nonceCache = new();

        Dictionary<string, OAuthFlowState> clientFlowStore = [];

        string segment = alignedRecord.TenantId.Value;
        Uri baseUri = HttpBaseAddress!;
        Uri parEndpoint = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodePar, segment));
        Uri authEndpoint = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment));
        Uri tokenEndpoint = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));
        Uri issuerUriValue = alignedRecord.IssuerUri!;

        AuthorizationServerMetadata metadata = new()
        {
            Issuer = issuerUriValue,
            PushedAuthorizationRequestEndpoint = parEndpoint,
            AuthorizationEndpoint = authEndpoint,
            TokenEndpoint = tokenEndpoint
        };

        System.Net.Http.HttpClient httpClient = SharedHttpClient!;

        OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create(
            sendFormPostAsync: (endpoint, fields, headers, _, ct) =>
                HttpClientTransport.SendFormPostAsync(httpClient, endpoint, fields, headers, ct),
            saveStateAsync: (state, _, ct) =>
            {
                clientFlowStore[state.FlowId] = state;
                return ValueTask.CompletedTask;
            },
            loadStateAsync: (flowId, _, ct) =>
                ValueTask.FromResult(clientFlowStore.GetValueOrDefault(flowId)),
            loadStateByRequestUriAsync: (requestUri, _, ct) =>
            {
                foreach(OAuthFlowState state in clientFlowStore.Values)
                {
                    if(state is Verifiable.OAuth.AuthCode.States.ParCompletedState pc
                        && string.Equals(
                            pc.Par.RequestUri.ToString(), requestUri, StringComparison.Ordinal))
                    {
                        return ValueTask.FromResult<OAuthFlowState?>(state);
                    }
                }

                return ValueTask.FromResult<OAuthFlowState?>(null);
            },
            parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
            parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
            parseAuthorizationServerMetadataAsync: (body, ct) =>
                throw new NotImplementedException("Test host pre-resolves metadata; the parser is not exercised."),
            parseRegistrationResponseAsync: (body, ct) =>
                throw new NotImplementedException("HTTP-backed DPoP factory does not exercise dynamic registration parse."),
            resolveAuthorizationServerMetadataAsync: (issuer, context, ct) =>
                ValueTask.FromResult(metadata),
            resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
            base64UrlEncoder: Base64UrlEncoder,
            timeProvider: Time,
            constructDpopProofAsync: (claims, key, ct) => DpopProofConstruction.BuildAsync(
                claims,
                key,
                Base64UrlEncoder,
                DpopTestSupport.Serializer,
                MicrosoftCryptographicFunctions.SignP256Async,
                MemoryPool,
                ct),
            dpopKey: dpopKey,
            lookupDpopNonce: nonceCache.Lookup,
            storeDpopNonce: nonceCache.Store);

        ClientRegistration registration = new()
        {
            ClientId = new ClientId(alignedRecord.ClientId),
            AuthorizationServerIssuer = issuerUriValue,
            RedirectUris = [new Uri(redirectUri)],
            AuthenticationMethod = ClientAuthenticationMethod.None,
            Profile = PolicyProfile.Haip10
        };

        return new DpopClientFixture(
            new OAuthClient(infrastructure),
            registration,
            dpopKey,
            nonceCache,
            dpopKeys.PublicKey,
            dpopKeys.PrivateKey,
            clientFlowStore);
    }


    /// <summary>
    /// Returns the RFC 7800 confirmation method recorded against the flow
    /// that issued <paramref name="accessToken"/>, or <see langword="null"/>
    /// when the token is unknown or the issuing state did not carry a
    /// binding. Diagnostic accessor — wire-level tests should read
    /// <c>cnf</c> from the JWT and <c>token_type</c> from the response
    /// body rather than calling this helper.
    /// </summary>
    public ConfirmationMethod? GetConfirmationForAccessToken(string accessToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);
        if(!AccessTokenIndex.TryGetValue(accessToken, out string? flowId))
        {
            return null;
        }
        if(!FlowStates.TryGetValue(flowId, out var entry))
        {
            return null;
        }
        return entry.State is ServerTokenIssuedState issued ? issued.Confirmation : null;
    }


    /// <summary>
    /// Starts an in-process Kestrel listener bound to localhost on an
    /// OS-assigned ephemeral port and maps inbound HTTP requests to
    /// <see cref="AuthorizationServer.DispatchAsync"/> via
    /// <see cref="AuthorizationServerHttpApplication"/>.
    /// Idempotent — repeat calls return without re-binding.
    /// </summary>
    /// <remarks>
    /// Invoked automatically by the HTTP-backed
    /// <see cref="CreateOAuthClientAndRegistrationAsync"/> /
    /// <see cref="CreateDpopEnabledOAuthClientAsync"/> factories the first
    /// time they're called. Tests that hold a <see cref="TestHostShell"/>
    /// across multiple HTTP-backed flow drives reuse the same listener.
    /// </remarks>
    public Task StartHttpHostAsync(CancellationToken cancellationToken = default) =>
        StartHttpHostAsync("default", cancellationToken);


    /// <summary>
    /// Starts an in-process Kestrel listener for the named host. Multi-host
    /// federation topologies (verifier + anchor) start each host's listener
    /// independently so each gets its own ephemeral port and authority.
    /// Idempotent per host — repeat calls return without re-binding.
    /// </summary>
    public async Task StartHttpHostAsync(string hostName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostName);

        HostedAuthorizationServer host = Host(hostName);
        if(host.KestrelServer is not null)
        {
            return;
        }

        global::Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions kestrelOptions = new();
        //Kestrel's ListenLocalhost(0) rejects dynamic port (it binds both
        //IPv4 + IPv6 loopback and can't reconcile a single OS-assigned port
        //across two sockets). Listen on IPv4 loopback with an ephemeral
        //port; the dispatched URL uses 127.0.0.1 explicitly.
        kestrelOptions.Listen(System.Net.IPAddress.Loopback, port: 0);

        global::Microsoft.AspNetCore.Server.Kestrel.Transport.Sockets.SocketTransportOptions socketOptions = new();
        global::Microsoft.AspNetCore.Server.Kestrel.Transport.Sockets.SocketTransportFactory socketFactory = new(
            global::Microsoft.Extensions.Options.Options.Create(socketOptions),
            global::Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance);

        global::Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServer kestrel = new(
            global::Microsoft.Extensions.Options.Options.Create(kestrelOptions),
            socketFactory,
            global::Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance);

        AuthorizationServerHttpApplication app = new(host.Server);
        await kestrel.StartAsync(app, cancellationToken).ConfigureAwait(false);

        global::Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature? addresses =
            kestrel.Features.Get<global::Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>();
        if(addresses is null || addresses.Addresses.Count == 0)
        {
            throw new InvalidOperationException(
                $"Kestrel for host '{hostName}' started but no server addresses were exposed via IServerAddressesFeature.");
        }

        host.KestrelServer = kestrel;
        host.HttpBaseAddress = new Uri(addresses.Addresses.First());
        host.SharedHttpClient = new System.Net.Http.HttpClient { BaseAddress = host.HttpBaseAddress };
    }


    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if(Disposed)
        {
            return;
        }

        Disposed = true;

        //Iterate every host so multi-host topologies (Verifier + Federation
        //Anchor + ...) tear down their Kestrel listeners, HttpClients, and
        //per-host key material cleanly. Single-host tests still hit Default
        //via the same loop.
        foreach(HostedAuthorizationServer host in HostsByName.Values)
        {
            host.SharedHttpClient?.Dispose();
            host.SharedHttpClient = null;

            if(host.KestrelServer is not null)
            {
                await host.KestrelServer.StopAsync(CancellationToken.None).ConfigureAwait(false);
                host.KestrelServer.Dispose();
                host.KestrelServer = null;
            }

            host.Server.Dispose();

            foreach(PrivateKeyMemory key in host.SigningKeys.Values)
            {
                key.Dispose();
            }

            foreach(PublicKeyMemory key in host.VerificationKeys.Values)
            {
                key.Dispose();
            }

            foreach(PrivateKeyMemory key in host.DecryptionKeys.Values)
            {
                key.Dispose();
            }
        }

        foreach(IDisposable owned in DpopOwnedDisposables)
        {
            owned.Dispose();
        }
    }


    /// <summary>
    /// Composes the absolute path for a
    /// <see cref="WellKnownEndpointNames"/> role at a given tenant segment,
    /// using the same path scheme the
    /// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>
    /// lambda this fixture wires produces. Use this from synchronous test
    /// code (registration construction, expected-URL builders) that needs
    /// the path without going through the async resolver.
    /// </summary>
    /// <remarks>
    /// Both this helper and the resolver lambda call
    /// <see cref="EndpointPathSuffix"/> so the two stay in sync. The
    /// <c>/connect/{segment}/&lt;suffix&gt;</c> scheme is the test
    /// fixture's URL-shape choice and lives in one place.
    /// </remarks>
    public static string ComposeEndpointPath(string endpointName, string segment)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(endpointName);
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);

        //RFC 9728 §3: the protected-resource well-known suffix is INSERTED
        //between the host and the resource identifier's path — for the
        //fixture's https://issuer.test/{segment} identity that is
        // /.well-known/oauth-protected-resource/{segment}, not a suffix
        //appended under the tenant path like the other endpoints. The host
        //part is the deployment's logical→transport mapping; the path
        //carries through verbatim so the §3.3 resource-match invariant holds.
        if(endpointName == WellKnownEndpointNames.ProtectedResourceMetadata)
        {
            return $"/.well-known/oauth-protected-resource/{segment}";
        }

        string suffix = EndpointPathSuffix(endpointName)
            ?? throw new ArgumentException(
                $"No fixture path mapping registered for endpoint role '{endpointName}'.",
                nameof(endpointName));

        return $"/connect/{segment}/{suffix}";
    }


    /// <summary>
    /// <see cref="Uri"/>-returning companion to
    /// <see cref="ComposeEndpointPath"/>. Resolves the absolute URL against
    /// <paramref name="baseUri"/>; the host part comes from
    /// <paramref name="baseUri"/>'s authority.
    /// </summary>
    public static Uri ComposeEndpointUri(Uri baseUri, string segment, string endpointName)
    {
        ArgumentNullException.ThrowIfNull(baseUri);
        return new Uri(baseUri, ComposeEndpointPath(endpointName, segment));
    }


    //Shared suffix dispatch — read by ResolveEndpointUriAsync and by the
    //synchronous Compose* helpers. The fixture's URL-shape contract lives
    //here in one place. New endpoint roles get added to both
    //WellKnownEndpointNames (in the library) and to this switch (in this
    //fixture).
    internal static string? EndpointPathSuffix(string endpointName)
    {
        if(endpointName == WellKnownEndpointNames.AuthCodePar) { return "par"; }
        if(endpointName == WellKnownEndpointNames.AuthCodeJarPar) { return "par"; }
        if(endpointName == WellKnownEndpointNames.AuthCodeAuthorize) { return "authorize"; }
        if(endpointName == WellKnownEndpointNames.AuthCodeAuthorizeJarByValue) { return "authorize"; }
        if(endpointName == WellKnownEndpointNames.AuthCodeDirectAuthorize) { return "authorize"; }
        if(endpointName == WellKnownEndpointNames.AuthCodeRequestObjectConflict) { return "authorize"; }
        if(endpointName == WellKnownEndpointNames.AuthCodeToken) { return "token"; }
        if(endpointName == WellKnownEndpointNames.AuthCodeRefreshToken) { return "token"; }
        if(endpointName == WellKnownEndpointNames.ClientCredentialsToken) { return "token"; }
        if(endpointName == WellKnownEndpointNames.AuthCodeRevoke) { return "revoke"; }
        if(endpointName == WellKnownEndpointNames.AuthCodeIntrospect) { return "introspect"; }
        if(endpointName == WellKnownEndpointNames.GlobalTokenRevocation) { return "global_token_revocation"; }
        if(endpointName == WellKnownEndpointNames.EndSession) { return "end_session"; }
        if(endpointName == WellKnownEndpointNames.Oid4VpPar) { return "par"; }
        if(endpointName == WellKnownEndpointNames.Oid4VpJarRequest) { return "jar"; }
        if(endpointName == WellKnownEndpointNames.Oid4VpDirectPost) { return "cb"; }
        if(endpointName == WellKnownEndpointNames.MetadataJwks) { return "jwks"; }
        if(endpointName == WellKnownEndpointNames.MetadataDiscovery) { return ".well-known/openid-configuration"; }
        if(endpointName == WellKnownEndpointNames.FederationEntityConfiguration) { return ".well-known/openid-federation"; }
        if(endpointName == WellKnownEndpointNames.FederationFetch) { return "federation_fetch"; }
        if(endpointName == WellKnownEndpointNames.FederationList) { return "federation_list"; }
        if(endpointName == WellKnownEndpointNames.FederationResolve) { return "federation_resolve"; }
        if(endpointName == WellKnownEndpointNames.FederationRegistration) { return "federation_registration"; }
        if(endpointName == WellKnownEndpointNames.FederationHistoricalKeys) { return "federation_historical_keys"; }
        if(endpointName == WellKnownEndpointNames.RegistrationRegister) { return "register"; }
        if(endpointName == WellKnownEndpointNames.UserInfo) { return "userinfo"; }
        if(endpointName == WellKnownEndpointNames.AuthZenAccessEvaluation) { return "access/v1/evaluation"; }
        if(endpointName == WellKnownEndpointNames.AuthZenAccessEvaluations) { return "access/v1/evaluations"; }
        if(endpointName == WellKnownEndpointNames.AuthZenSearchSubject) { return "access/v1/search/subject"; }
        if(endpointName == WellKnownEndpointNames.AuthZenSearchResource) { return "access/v1/search/resource"; }
        if(endpointName == WellKnownEndpointNames.AuthZenSearchAction) { return "access/v1/search/action"; }
        if(endpointName == WellKnownEndpointNames.AuthZenConfiguration) { return ".well-known/authzen-configuration"; }
        if(endpointName == WellKnownEndpointNames.SsfConfiguration) { return ".well-known/ssf-configuration"; }
        //The five stream-management roles share the single Configuration
        //Endpoint URL (SSF §8.1.1); the HTTP method disambiguates.
        if(endpointName == WellKnownEndpointNames.SsfStreamCreate) { return "ssf/stream"; }
        if(endpointName == WellKnownEndpointNames.SsfStreamRead) { return "ssf/stream"; }
        if(endpointName == WellKnownEndpointNames.SsfStreamUpdate) { return "ssf/stream"; }
        if(endpointName == WellKnownEndpointNames.SsfStreamReplace) { return "ssf/stream"; }
        if(endpointName == WellKnownEndpointNames.SsfStreamDelete) { return "ssf/stream"; }
        if(endpointName == WellKnownEndpointNames.SsfStatusRead) { return "ssf/status"; }
        if(endpointName == WellKnownEndpointNames.SsfStatusUpdate) { return "ssf/status"; }
        if(endpointName == WellKnownEndpointNames.SsfSubjectAdd) { return "ssf/subjects/add"; }
        if(endpointName == WellKnownEndpointNames.SsfSubjectRemove) { return "ssf/subjects/remove"; }
        if(endpointName == WellKnownEndpointNames.SsfVerification) { return "ssf/verify"; }

        return null;
    }


    private static VerifierClientMetadata BuildClientMetadata(
        string clientId,
        PublicKeyMemory exchangePublicKey,
        KeyId encryptionKeyId)
    {
        string jwksJson = EphemeralEncryptionKeyPair.CreatePublicKeyJwks(
            exchangePublicKey,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared);

        return HaipProfile.CreateVerifierClientMetadata(clientId, jwksJson);
    }


    /// <summary>
    /// Resolves the JWK <c>kty</c> and <c>crv</c> parameters from a key's
    /// <see cref="Tag"/>. Algorithm-agile — supports EC, OKP, RSA, and
    /// post-quantum key types.
    /// </summary>
    /// <summary>
    /// Extracts the opaque token from an Auth Code <c>request_uri</c> URN.
    /// The URN form is <c>urn:ietf:params:oauth:request_uri:{token}</c> per
    /// RFC 9126 §2.2 with the <c>urn:ietf:params:oauth:request_uri</c> prefix
    /// reserved for OAuth Authorization Code flows.
    /// </summary>
    /// <remarks>
    /// OID4VP no longer needs URL parsing on the host side — the per-flow
    /// handle is carried as a first-class field on the state record
    /// (<see cref="Verifiable.OAuth.Oid4Vp.Server.States.VerifierParReceivedState.ParHandle"/>)
    /// and indexed directly. This helper is therefore Auth Code only.
    /// </remarks>
    internal static string ExtractRequestUriToken(Uri requestUri)
    {
        string value = requestUri.ToString();

        const string urnPrefix = "urn:ietf:params:oauth:request_uri:";
        if(value.StartsWith(urnPrefix, StringComparison.Ordinal))
        {
            return value[urnPrefix.Length..];
        }

        return value;
    }


    /// <summary>
    /// In-process transport that routes the client's HTTP-shaped requests to the
    /// server's <see cref="AuthorizationServer.DispatchAsync"/>. Models the role
    /// of an HTTP layer plus structural router collapsed into one in-memory
    /// class. No closures — all dependencies are constructor parameters.
    /// </summary>
    [DebuggerDisplay("InProcessTransport Segment={segment}")]
    private sealed class InProcessTransport(
        AuthorizationServer server,
        ClientRecord registration,
        string segment,
        string issuerUri)
    {
        public async ValueTask<HttpResponseData> SendAsync(
            Uri endpoint,
            IReadOnlyDictionary<string, string> fields,
            OutgoingHeaders headers,
            CancellationToken cancellationToken)
        {
            //The OAuth client's transport contract is form-POST: it speaks
            //URLs and form fields. The matcher chain reads everything it
            //needs from the IncomingRequest envelope; capability narrowing
            //and method filtering happen inside the matchers themselves.
            RequestFields serverFields = new(fields);

            IncomingRequest request = new(
                Path: endpoint.AbsolutePath,
                Method: "POST",
                Fields: serverFields,
                Headers: BuildIncomingHeaders(headers),
                RouteValues: RouteValues.Empty);

            ExchangeContext context = new();
            context.SetTenantId(segment);
            context.SetIssuer(new Uri(issuerUri));
            context.SetRegistration(registration);

            ServerHttpResponse response = await server.DispatchAsync(
                request, context, cancellationToken).ConfigureAwait(false);

            return new HttpResponseData
            {
                Body = response.Body ?? string.Empty,
                StatusCode = response.StatusCode,
                Headers = BuildResponseHeaders(response.Headers)
            };
        }
    }


    /// <summary>
    /// Builds a <see cref="RequestHeaders"/> view over the client-side
    /// <see cref="OutgoingHeaders"/>. The in-process transport forwards every
    /// outgoing header so AS-side matchers (DPoP, RFC 9421 signing) see what
    /// production deployments see over the wire.
    /// </summary>
    private static RequestHeaders BuildIncomingHeaders(OutgoingHeaders headers)
    {
        if(headers.Values.Count == 0)
        {
            return RequestHeaders.Empty;
        }

        Dictionary<string, string[]> incoming = new(headers.Values.Count, StringComparer.OrdinalIgnoreCase);
        foreach(KeyValuePair<string, string> pair in headers.Values)
        {
            incoming[pair.Key] = [pair.Value];
        }
        return new RequestHeaders(incoming);
    }


    /// <summary>
    /// Promotes server-side <see cref="ServerHttpResponse.Headers"/> into the
    /// client-side <see cref="ResponseHeaders"/> shape. RFC 9449 §8.1 carries
    /// fresh nonces in <c>DPoP-Nonce</c> on a 400 challenge; the client's
    /// retry loop reads them via this surface.
    /// </summary>
    private static ResponseHeaders BuildResponseHeaders(ImmutableDictionary<string, string> headers)
    {
        if(headers.IsEmpty)
        {
            return ResponseHeaders.Empty;
        }

        return new ResponseHeaders { Values = headers };
    }


    /// <summary>
    /// Resolves an issuer's public key from the trust store.
    /// </summary>
    private PublicKeyMemory? ResolveIssuerKey(string issuerId)
    {
        return IssuerTrustStore.GetValueOrDefault(issuerId);
    }


    /// <summary>
    /// In-process transport that resolves the <see cref="ClientRecord"/> from
    /// the host's registration dictionary at dispatch time, rather than
    /// binding to a fixed registration at construction. Used by the dynamic-
    /// registration path where the registration does not exist at client-
    /// construction time.
    /// </summary>
    [DebuggerDisplay("LookupTransport")]
    private sealed class LookupTransport(
        AuthorizationServer server,
        ConcurrentDictionary<string, ClientRecord> registrations,
        string issuerUri)
    {
        public async ValueTask<HttpResponseData> SendAsync(
            Uri endpoint,
            IReadOnlyDictionary<string, string> fields,
            OutgoingHeaders headers,
            CancellationToken cancellationToken)
        {
            string segment = ExtractTenantSegment(endpoint.AbsolutePath);
            if(!registrations.TryGetValue(segment, out ClientRecord? registration))
            {
                return new HttpResponseData
                {
                    StatusCode = 404,
                    Body = $"No registration found for segment '{segment}'."
                };
            }

            RequestFields serverFields = new(fields);

            IncomingRequest request = new(
                Path: endpoint.AbsolutePath,
                Method: "POST",
                Fields: serverFields,
                Headers: BuildIncomingHeaders(headers),
                RouteValues: RouteValues.Empty);

            ExchangeContext context = new();
            context.SetTenantId(segment);
            context.SetIssuer(new Uri(issuerUri));
            context.SetRegistration(registration);

            ServerHttpResponse response = await server.DispatchAsync(
                request, context, cancellationToken).ConfigureAwait(false);

            return new HttpResponseData
            {
                Body = response.Body ?? string.Empty,
                StatusCode = response.StatusCode,
                Headers = BuildResponseHeaders(response.Headers)
            };
        }


        private static string ExtractTenantSegment(string path) =>
            ExtractTenantSegmentForTests(path);


        internal static string ExtractTenantSegmentForTests(string path)
        {
            //Test paths follow /connect/{segment}/<endpoint>. Anything else
            //returns an empty segment which will fail the registration
            //lookup and surface a 404.
            const string prefix = "/connect/";
            if(!path.StartsWith(prefix, StringComparison.Ordinal))
            {
                return string.Empty;
            }
            int start = prefix.Length;
            int end = path.IndexOf('/', start);
            return end < 0 ? path[start..] : path[start..end];
        }
    }


}
