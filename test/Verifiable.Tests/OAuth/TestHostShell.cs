using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.Model.SelectiveDisclosure.Strategy;
using Verifiable.Core.OutboundFetch;
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
using Verifiable.OAuth.Siop.Server;
using Verifiable.Core.Assessment;
using Verifiable.OAuth.Validation;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.Server.Metadata;
using Verifiable.OAuth.Server.Registration;
using Verifiable.Server;
using Verifiable.Server.Pipeline;
using Verifiable.Vcalm;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// An in-memory test host that mirrors what a production ASP.NET application does
/// at startup: creates an <see cref="AuthorizationServer"/> instance, wires all I/O
/// delegates to in-memory stores, subscribes to events, and registers clients.
/// </summary>
/// <remarks>
/// <para>
/// This is the test equivalent of <c>Program.cs</c>. In production the host is
/// ASP.NET with Kestrel, a database, and whatever other infrastructure
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
    /// <summary>
    /// All per-host state lives on this instance. The property aliases below mirror the historical
    /// field names so methods on <see cref="TestHostShell"/> continue to compile unchanged after that
    /// state moved onto <see cref="HostedAuthorizationServer"/>. Multi-host tests reach additional
    /// hosts through <see cref="Hosts"/>.
    /// </summary>
    private HostedAuthorizationServer Default { get; }

    /// <summary>The <see cref="Default"/> host's client registrations, keyed by both tenant segment and client id.</summary>
    private ConcurrentDictionary<string, ClientRecord> Registrations => Default.Registrations;

    /// <summary>The <see cref="Default"/> host's flow-state store, keyed by flow id.</summary>
    private ConcurrentDictionary<string, (FlowState State, int StepCount)> FlowStates => Default.FlowStates;

    /// <summary>The <see cref="Default"/> host's request_uri / per-flow handle secondary index.</summary>
    private ConcurrentDictionary<string, string> RequestUriTokenIndex => Default.RequestUriTokenIndex;

    /// <summary>The <see cref="Default"/> host's authorization-code secondary index.</summary>
    private ConcurrentDictionary<string, string> CodeIndex => Default.CodeIndex;

    /// <summary>The <see cref="Default"/> host's DPoP <c>jti</c> replay index.</summary>
    private ConcurrentDictionary<string, string> JtiIndex => Default.JtiIndex;

    /// <summary>The <see cref="Default"/> host's access-token secondary index.</summary>
    private ConcurrentDictionary<string, string> AccessTokenIndex => Default.AccessTokenIndex;

    /// <summary>The <see cref="Default"/> host's refresh-token secondary index.</summary>
    private ConcurrentDictionary<string, string> RefreshTokenIndex => Default.RefreshTokenIndex;

    /// <summary>The <see cref="Default"/> host's token/JAR signing key store.</summary>
    private ConcurrentDictionary<KeyId, PrivateKeyMemory> SigningKeys => Default.SigningKeys;

    /// <summary>The <see cref="Default"/> host's signature verification key store.</summary>
    private ConcurrentDictionary<KeyId, PublicKeyMemory> VerificationKeys => Default.VerificationKeys;

    /// <summary>The <see cref="Default"/> host's response-encryption decryption key store.</summary>
    private ConcurrentDictionary<KeyId, PrivateKeyMemory> DecryptionKeys => Default.DecryptionKeys;

    /// <summary>The <see cref="Default"/> host's RFC 7592 registration access token store.</summary>
    private ConcurrentDictionary<string, string> RegistrationAccessTokens => Default.RegistrationAccessTokens;

    /// <summary>Disposable DPoP-related resources owned by this shell, released on <see cref="DisposeAsync"/>.</summary>
    private List<IDisposable> DpopOwnedDisposables { get; } = [];

    /// <summary>
    /// Disposable transport resources (pinned <see cref="System.Net.Http.HttpClient"/> instances)
    /// <see cref="WireCimdMaterialization"/> owns, released on <see cref="DisposeAsync"/>.
    /// </summary>
    private List<IDisposable> TransportOwnedDisposables { get; } = [];

    /// <summary>The DPoP HMAC confirmation key set shared by tests that need symmetric DPoP proofs.</summary>
    private InProcessKeySet? DpopHmacKeySet { get; set; }

    /// <summary>Guards <see cref="DisposeAsync"/> against running its teardown more than once.</summary>
    private bool Disposed { get; set; }

    /// <summary>The <see cref="Default"/> host's HTTPS <see cref="WebApplication"/> instance, set once <see cref="StartHttpHostAsync"/> runs.</summary>
    private global::Microsoft.AspNetCore.Builder.WebApplication? HttpHost
    {
        get => Default.HttpHost;
        set => Default.HttpHost = value;
    }

    /// <summary>The <see cref="Default"/> host's loopback base address once it is serving HTTPS.</summary>
    private Uri? HttpBaseAddress
    {
        get => Default.HttpBaseAddress;
        set => Default.HttpBaseAddress = value;
    }

    /// <summary>The <see cref="Default"/> host's shared <see cref="System.Net.Http.HttpClient"/> for real-wire tests.</summary>
    private System.Net.Http.HttpClient? SharedHttpClient
    {
        get => Default.SharedHttpClient;
        set => Default.SharedHttpClient = value;
    }

    /// <summary>
    /// The shared self-signed leaf certificate an HTTPS host this shell starts presents unless the
    /// host was added with its own distinct certificate (<see cref="AddHost(string, bool)"/>) — minted
    /// lazily on first use via <see cref="LoopbackTls.CreateServerCertificate"/> and shared
    /// thereafter, since its SAN covers both <c>127.0.0.1</c> and <c>localhost</c> and every host
    /// binds loopback. Wire-level tests that build their own <see cref="System.Net.Http.HttpClient"/>
    /// pin to this exact certificate via <see cref="LoopbackTls.CreatePinnedHandler"/> rather than
    /// trusting a CA. <see cref="HostCertificate"/> answers which certificate a NAMED host actually
    /// presents, covering both the shared and the distinct-certificate cases.
    /// </summary>
    internal X509Certificate2 ServerCertificate => serverCertificate ??= LoopbackTls.CreateServerCertificate("oauth-loopback-test-host");

    private X509Certificate2? serverCertificate;

    /// <summary>
    /// The per-host certificates for hosts added with <c>useDistinctCertificate: true</c> on
    /// <see cref="AddHost(string, bool)"/>, keyed by host name. Hosts absent from this map present
    /// the shared <see cref="ServerCertificate"/>; <see cref="HostCertificate"/> is the one
    /// selection authority both listener bootstrap and client pinning read.
    /// </summary>
    private Dictionary<string, X509Certificate2> DistinctHostCertificates { get; } =
        new(StringComparer.Ordinal);


    /// <summary>
    /// The certificate the named host's HTTPS listener presents: the host's own distinct
    /// certificate when it was added with <c>useDistinctCertificate: true</c> on
    /// <see cref="AddHost(string, bool)"/>, otherwise the shared <see cref="ServerCertificate"/>.
    /// A test-side client dialing several hosts with distinct TLS identities pins each host's
    /// exact certificate via
    /// <see cref="LoopbackTls.CreatePinnedHandler(IReadOnlyCollection{X509Certificate2})"/>.
    /// </summary>
    /// <param name="hostName">The host's role name as registered via <see cref="AddHost(string, bool)"/>.</param>
    internal X509Certificate2 HostCertificate(string hostName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostName);

        //Validates the host exists so a mistyped name fails with the host-lookup
        //error instead of silently answering the shared certificate.
        _ = Host(hostName);

        return DistinctHostCertificates.TryGetValue(hostName, out X509Certificate2? certificate)
            ? certificate
            : ServerCertificate;
    }

    /// <summary>Base64Url encoder shared by tests with the host's own wiring.</summary>
    public static EncodeDelegate Base64UrlEncoder => TestSetup.Base64UrlEncoder;

    /// <summary>Base64Url decoder shared by tests with the host's own wiring.</summary>
    public static DecodeDelegate Base64UrlDecoder => TestSetup.Base64UrlDecoder;

    /// <summary>The memory pool used by the host for sensitive allocations.</summary>
    public static MemoryPool<byte> MemoryPool => BaseMemoryPool.Shared;

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
    public EndpointServer Server => Default.Server;

    /// <summary>The current registration routing table.</summary>
    public IReadOnlyDictionary<string, ClientRecord> RegistrationStore => Registrations;

    /// <summary>The server-side flow state store.</summary>
    public IReadOnlyDictionary<string, (FlowState State, int StepCount)> FlowStore => FlowStates;

    /// <summary>The time provider injected at construction.</summary>
    public TimeProvider Time { get; }

    /// <summary>
    /// Issuer trust store mapping issuer identifiers to their public keys.
    /// The verifier uses this to verify credential issuer signatures.
    /// </summary>
    private Dictionary<string, PublicKeyMemory> IssuerTrustStore { get; } = [];

    /// <summary>
    /// SIOPv2 §11.1 DID trust map for Self-Issued ID Tokens of the Decentralized Identifier
    /// Subject Syntax Type, keyed by the DID Document verification-method id (the JOSE header
    /// <c>kid</c>) and falling back to the bare DID. The SIOP validator's
    /// <see cref="Verifiable.OAuth.Siop.ResolveDidVerificationKeyDelegate"/> reads from this map,
    /// the DID-subject parallel of <see cref="IssuerTrustStore"/>.
    /// </summary>
    private Dictionary<string, PublicKeyMemory> SiopDidTrustStore { get; } =
        new(StringComparer.Ordinal);

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
    /// Registers a SIOPv2 Self-Issued OP's DID verification key for the Decentralized Identifier
    /// Subject Syntax Type. The key is indexed under both the verification-method id
    /// (<paramref name="keyId"/>, the JOSE header <c>kid</c>) and the bare <paramref name="did"/>,
    /// so the resolver matches whether or not the token carries a <c>kid</c>.
    /// </summary>
    /// <param name="did">The Self-Issued OP's DID — the <c>iss</c>/<c>sub</c> claim value.</param>
    /// <param name="keyId">The DID Document verification-method id (the header <c>kid</c>).</param>
    /// <param name="verificationKey">The DID's public verification key.</param>
    public void RegisterSiopDidTrust(string did, string keyId, PublicKeyMemory verificationKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(did);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        ArgumentNullException.ThrowIfNull(verificationKey);

        SiopDidTrustStore[keyId] = verificationKey;
        SiopDidTrustStore[did] = verificationKey;
    }


    /// <summary>
    /// The SIOPv2 §11.1 DID resolution seam shared into every host this shell builds. It selects
    /// the verification key by the JOSE header <c>kid</c> when present (the verification-method id),
    /// falling back to the bare DID, and hands back a fresh owned copy because the validator
    /// disposes the resolved key after signature verification.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The resolved key's ownership transfers to the SIOP validator, which disposes it under a using statement after signature verification; disposing here would close the buffer before the caller reads it. This mirrors PinnedVerifierKeyResolver.")]
    private ValueTask<PublicKeyMemory?> ResolveSiopDidKey(
        string did, string? keyId, CancellationToken cancellationToken)
    {
        PublicKeyMemory? trusted = keyId is not null && SiopDidTrustStore.TryGetValue(keyId, out PublicKeyMemory? byKid)
            ? byKid
            : SiopDidTrustStore.GetValueOrDefault(did);
        if(trusted is null)
        {
            return ValueTask.FromResult<PublicKeyMemory?>(null);
        }

        //Hand back a fresh owned copy so the validator can dispose the resolved key after use
        //without disturbing the shell's retained trust-store entry.
        ReadOnlySpan<byte> keyBytes = trusted.AsReadOnlySpan();
        IMemoryOwner<byte> owner = MemoryPool.Rent(keyBytes.Length);
        keyBytes.CopyTo(owner.Memory.Span);

        return ValueTask.FromResult<PublicKeyMemory?>(new PublicKeyMemory(owner, trusted.Tag));
    }


    /// <summary>
    /// Registers a fresh P-256 exchange keypair as a Relying Party encryption key on the named host:
    /// the private half lands in the host's decryption-key store under a new key id (so the SIOP
    /// executor's <c>DecryptionKeyResolver</c> resolves it), and the public half is returned to the
    /// caller — a SIOP test wallet encrypts the Self-Issued ID Token JWE to it. The caller owns and
    /// disposes the returned public key.
    /// </summary>
    public (KeyId EncryptionKeyId, PublicKeyMemory EncryptionPublicKey) RegisterRpEncryptionKey(
        string hostName = "default")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostName);

        HostedAuthorizationServer host = Host(hostName);

        KeyId encryptionKeyId = new($"urn:uuid:{Guid.NewGuid()}");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> exchangeKeyPair =
            TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();

        host.DecryptionKeys[encryptionKeyId] = exchangeKeyPair.PrivateKey;

        return (encryptionKeyId, exchangeKeyPair.PublicKey);
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
        CommitmentReuseDetectionSeam? saltReuseSeam = null,
        Verifiable.Core.StatusList.ResolveVerifiedStatusListTokenDelegate? resolveVerifiedStatusListToken = null)
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
        StatusListResolverShared = resolveVerifiedStatusListToken;

        Default = HostedAuthorizationServer.Build(
            name: "default",
            timeProvider: timeProvider,
            subjectClaims: SubjectClaims,
            resolveIssuerKey: ResolveIssuerKeyShared,
            vpValidator: VpValidatorShared,
            mdocSeams: MdocSeamsShared,
            sdCwtSeams: SdCwtSeamsShared,
            saltReuseSeam: SaltReuseSeamShared,
            resolveDidVerificationKey: ResolveSiopDidKey,
            resolveVerifiedStatusListToken: StatusListResolverShared);
        HostsByName["default"] = Default;
    }


    /// <summary>
    /// Shell-level trust-anchor lookup, kept for <see cref="AddHost"/> so secondary hosts wire the
    /// same trust anchor the <see cref="Default"/> host received.
    /// </summary>
    private ResolveIssuerKeyDelegate ResolveIssuerKeyShared { get; }

    /// <summary>Shell-level VP-token validator, kept for <see cref="AddHost"/> alongside <see cref="ResolveIssuerKeyShared"/>.</summary>
    private ClaimIssuer<ValidationContext> VpValidatorShared { get; }

    /// <summary>Shell-level mdoc VP verification seams, or <see langword="null"/> when the shell was not built with mdoc support.</summary>
    private MdocVpVerificationSeams? MdocSeamsShared { get; }

    /// <summary>Shell-level SD-CWT VP verification seams, or <see langword="null"/> when the shell was not built with SD-CWT support.</summary>
    private SdCwtVpVerificationSeams? SdCwtSeamsShared { get; }

    /// <summary>Shell-level commitment-reuse detection seam, or <see langword="null"/> when the shell was not built with one.</summary>
    private CommitmentReuseDetectionSeam? SaltReuseSeamShared { get; }

    /// <summary>Shell-level status-list token resolver, or <see langword="null"/> when status-list resolution is not wired.</summary>
    private Verifiable.Core.StatusList.ResolveVerifiedStatusListTokenDelegate? StatusListResolverShared { get; }

    /// <summary>
    /// Multi-host orchestration store, keyed by role name. The <c>"default"</c> entry is added by the
    /// constructor; <see cref="AddHost"/> creates further independent hosts (different roles in a
    /// multi-party flow — Verifier + Federation Anchor, etc.).
    /// </summary>
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
    /// <param name="name">The host's role name (e.g. "anchor", "as2").</param>
    /// <param name="useDistinctCertificate">
    /// When <see langword="true"/>, mints the host its own leaf certificate via
    /// <see cref="LoopbackTls.CreateServerCertificate"/> so the host is a distinct TLS identity —
    /// distinct trust domains in a multi-party topology present distinct certificates. When
    /// <see langword="false"/>, the host presents the shared <see cref="ServerCertificate"/>.
    /// <see cref="HostCertificate"/> answers the effective certificate either way.
    /// </param>
    public HostedAuthorizationServer AddHost(string name, bool useDistinctCertificate = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        if(HostsByName.ContainsKey(name))
        {
            throw new InvalidOperationException(
                $"A host named '{name}' is already registered.");
        }

        if(useDistinctCertificate)
        {
            DistinctHostCertificates[name] = LoopbackTls.CreateServerCertificate($"oauth-loopback-{name}");
        }

        HostedAuthorizationServer host = HostedAuthorizationServer.Build(
            name: name,
            timeProvider: Time,
            subjectClaims: SubjectClaims,
            resolveIssuerKey: ResolveIssuerKeyShared,
            vpValidator: VpValidatorShared,
            mdocSeams: MdocSeamsShared,
            sdCwtSeams: SdCwtSeamsShared,
            resolveDidVerificationKey: ResolveSiopDidKey,
            resolveVerifiedStatusListToken: StatusListResolverShared);
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
    /// Registers a Client ID Metadata Document (CIMD) stub client on the <c>"default"</c> host: a
    /// <see cref="ClientRecord"/> whose <see cref="ClientRecord.ClientId"/> equals
    /// <paramref name="documentUri"/>'s <see cref="Uri.OriginalString"/> and whose
    /// <see cref="ClientRecord.ClientMetadataUri"/> is <paramref name="documentUri"/> itself, per
    /// draft-ietf-oauth-client-id-metadata-document-02 §4 (CIMD-013/014/015/016 — the document's
    /// <c>client_id</c> must match the Client Identifier URL, which must match the URL fetched).
    /// Carries <see cref="WellKnownCapabilityIdentifiers.OAuthClientIdMetadataDocument"/> among
    /// <paramref name="capabilities"/> (added when the caller omits it) and an EMPTY
    /// <see cref="ClientRecord.AllowedRedirectUris"/> — the fetched document supplies redirect URIs
    /// at materialization time (§4.2), never the stub. AS-owned facets (capabilities, scopes,
    /// signing keys, profile) mirror <see cref="RegisterSigningClient"/>; client-data-dependent
    /// facets (redirect URIs, auth method, JWKS, display) are left for
    /// <see cref="ClientIdMetadataMaterialization"/> to overlay from the fetched document.
    /// </summary>
    public ClientRecord RegisterCimdStubClient(
        Uri documentUri,
        ImmutableHashSet<CapabilityIdentifier> capabilities,
        PolicyProfile? profile = null) =>
        RegisterCimdStubClientOnHost("default", documentUri, capabilities, profile);


    /// <summary>
    /// Host-aware variant of <see cref="RegisterCimdStubClient"/>, for multi-host CIMD topologies
    /// (a document host distinct from the AS host is the common case; a multi-AS-host topology also
    /// reaches this overload directly).
    /// </summary>
    public ClientRecord RegisterCimdStubClientOnHost(
        string hostName,
        Uri documentUri,
        ImmutableHashSet<CapabilityIdentifier> capabilities,
        PolicyProfile? profile = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostName);
        ArgumentNullException.ThrowIfNull(documentUri);
        ArgumentNullException.ThrowIfNull(capabilities);

        HostedAuthorizationServer host = Host(hostName);

        if(!capabilities.Contains(WellKnownCapabilityIdentifiers.OAuthClientIdMetadataDocument))
        {
            capabilities = capabilities.Add(WellKnownCapabilityIdentifiers.OAuthClientIdMetadataDocument);
        }

        string segment = Guid.NewGuid().ToString("N")[..8];
        KeyId signingKeyId = new($"urn:uuid:{Guid.NewGuid()}");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signingKeyPair =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        host.SigningKeys[signingKeyId] = signingKeyPair.PrivateKey;
        host.VerificationKeys[signingKeyId] = signingKeyPair.PublicKey;

        ClientRecord registration = new()
        {
            ClientId = documentUri.OriginalString,
            TenantId = segment,
            IssuerUri = new Uri($"https://issuer.test/{segment}"),
            Profile = profile,
            AllowedCapabilities = capabilities,
            AllowedRedirectUris = ImmutableHashSet<Uri>.Empty,
            AllowedScopes = ImmutableHashSet.Create(WellKnownScopes.OpenId),
            SigningKeys = ImmutableDictionary<KeyUsageContext, SigningKeySet>.Empty
                .Add(KeyUsageContext.AccessTokenIssuance, new SigningKeySet { Current = [signingKeyId] }),
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty,
            ClientMetadataUri = documentUri
        };

        host.Registrations[segment] = registration;
        host.Registrations[registration.ClientId] = registration;

        host.Server.RegisterClient(
            registration,
            new RegistrationAccessToken(Guid.NewGuid().ToString("N")),
            new ExchangeContext());

        return registration;
    }


    /// <summary>
    /// Wires CIMD materialization onto the named host:
    /// <see cref="AuthorizationServerIntegration.MaterializeRegistrationAsync"/> to
    /// <see cref="ClientIdMetadataMaterialization.Build"/>'s factory output, and
    /// <see cref="AuthorizationServerIntegration.ResolveClientMetadataAsync"/> to
    /// <see cref="ClientIdMetadataDocuments.BuildResolving"/> over a transport built from
    /// <see cref="LoopbackTls.CreateSingleHopPinnedHttpClient(X509Certificate2)"/> (auto-redirect
    /// disabled per the <see cref="Verifiable.Core.OutboundFetch.OutboundTransportDelegate"/>
    /// contract) and <see cref="GuardedHttpClientTransport.BuildSingleHopTransport"/>, pinned to
    /// <paramref name="documentHostCertificate"/> — the CIMD document host's OWN certificate,
    /// distinct from this AS host's <see cref="ServerCertificate"/> when the document is served by a
    /// separate loopback listener.
    /// </summary>
    /// <remarks>
    /// The resolved delegate sets <see cref="LoopbackOutboundFetchPolicy"/> on the live per-request
    /// <see cref="ExchangeContext"/> immediately before delegating to the built resolver — the same
    /// context <see cref="AuthorizationServerHttpApplication.ProcessRequestAsync"/> constructs fresh
    /// per inbound request, so the guarded fetch the resolver drives is permitted to dial another
    /// loopback listener exactly as <see cref="LoopbackOutboundFetchPolicy"/>'s own remarks describe
    /// (the test deployment's document host genuinely is another loopback listener). Owns the pinned
    /// <see cref="System.Net.Http.HttpClient"/>, released on <see cref="DisposeAsync"/>.
    /// </remarks>
    public void WireCimdMaterialization(
        string hostName,
        X509Certificate2 documentHostCertificate,
        ClientIdMetadataDocumentResolverOptions? options = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostName);
        ArgumentNullException.ThrowIfNull(documentHostCertificate);

        HostedAuthorizationServer host = Host(hostName);

        System.Net.Http.HttpClient documentHttpClient =
            LoopbackTls.CreateSingleHopPinnedHttpClient(documentHostCertificate);
        TransportOwnedDisposables.Add(documentHttpClient);

        Verifiable.Core.OutboundFetch.OutboundTransportDelegate transport =
            GuardedHttpClientTransport.BuildSingleHopTransport(documentHttpClient);
        ResolveClientMetadataDelegate resolve = ClientIdMetadataDocuments.BuildResolving(
            transport, options ?? new ClientIdMetadataDocumentResolverOptions(), Time);

        AuthorizationServerIntegration oauth = host.Server.OAuth();
        oauth.MaterializeRegistrationAsync = ClientIdMetadataMaterialization.Build();
        oauth.ResolveClientMetadataAsync = (clientMetadataUri, context, cancellationToken) =>
        {
            context.SetOutboundFetchPolicy(LoopbackOutboundFetchPolicy);

            return resolve(clientMetadataUri, context, cancellationToken);
        };
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
    public (OAuthClient Client, ClientRegistration Registration, Dictionary<string, FlowState> ClientFlowStore)
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

        Dictionary<string, FlowState> clientFlowStore = [];

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
                foreach(FlowState state in clientFlowStore.Values)
                {
                    if(state is Verifiable.OAuth.AuthCode.States.ParCompletedState pc
                        && string.Equals(
                            pc.Par.RequestUri.ToString(), requestUri, StringComparison.Ordinal))
                    {
                        return ValueTask.FromResult<FlowState?>(state);
                    }
                }

                return ValueTask.FromResult<FlowState?>(null);
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
    public async ValueTask<(OAuthClient Client, ClientRegistration Registration, Dictionary<string, FlowState> ClientFlowStore)>
        CreateOAuthClientAndRegistrationAsync(
            ClientRecord record,
            string redirectUri,
            PolicyProfile? profile = null,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentException.ThrowIfNullOrWhiteSpace(redirectUri);

        await StartHttpHostAsync(cancellationToken: cancellationToken).ConfigureAwait(false);

        ClientRecord alignedRecord = AlignRegistrationIssuerToHttpBase(record);

        Dictionary<string, FlowState> clientFlowStore = [];

        string segment = alignedRecord.TenantId.Value;
        Uri baseUri = HttpBaseAddress!;
        Uri parEndpoint = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodePar, segment));
        Uri authEndpoint = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment));
        Uri tokenEndpoint = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));
        Uri revocationEndpoint = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeRevoke, segment));
        Uri issuerUriValue = alignedRecord.IssuerUri!;

        AuthorizationServerMetadata metadata = new()
        {
            Issuer = issuerUriValue,
            PushedAuthorizationRequestEndpoint = parEndpoint,
            AuthorizationEndpoint = authEndpoint,
            TokenEndpoint = tokenEndpoint,
            RevocationEndpoint = revocationEndpoint
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
                foreach(FlowState state in clientFlowStore.Values)
                {
                    if(state is Verifiable.OAuth.AuthCode.States.ParCompletedState pc
                        && string.Equals(
                            pc.Par.RequestUri.ToString(), requestUri, StringComparison.Ordinal))
                    {
                        return ValueTask.FromResult<FlowState?>(state);
                    }
                }

                return ValueTask.FromResult<FlowState?>(null);
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
            verifierKeys, cancellationToken: cancellationToken).ConfigureAwait(false);

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
            verifierKeys, cancellationToken: cancellationToken).ConfigureAwait(false);

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
            verifierKeys, cancellationToken: cancellationToken).ConfigureAwait(false);

        HttpClient walletHttpClient = Host("default").SharedHttpClient!;
        Oid4VpWalletConfiguration config =
            BuildSlimOid4VpWalletConfiguration(produceVpTokenPresentations, verifierSigningKeyResolver) with
            {
                SendFormPost = GuardedHttpClientTransport.BuildGuardedFormPost(walletHttpClient)
            };

        return new Oid4VpWalletClient(infrastructure, config);
    }


    /// <summary>
    /// Registers <paramref name="verifierKeys"/>' client via the OAuth-client factory and returns the
    /// resulting HTTP-backed <see cref="OAuthClientInfrastructure"/> so wallet clients can send through
    /// its <c>SendFormPostAsync</c> transport.
    /// </summary>
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
    /// HTTPS listener: the secure default relaxed for loopback targets, because
    /// the test deployment's transport endpoint genuinely is a local listener.
    /// The scheme stays <c>https</c>-only — every loopback test host serves TLS —
    /// so only <see cref="Verifiable.Core.OutboundFetch.OutboundFetchPolicy.BlockPrivateAndLoopback"/>
    /// is relaxed, a deployment's explicit, principled per-call choice. Production
    /// wallets keep <see cref="Verifiable.Core.OutboundFetch.OutboundFetchPolicy.SecureDefault"/>,
    /// under which an authorization request pointing the wallet at a private or
    /// loopback address is denied before any network contact.
    /// </summary>
    public static Verifiable.Core.OutboundFetch.OutboundFetchPolicy LoopbackOutboundFetchPolicy { get; } =
        Verifiable.Core.OutboundFetch.OutboundFetchPolicy.SecureDefault with
        {
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


    /// <summary>
    /// The SD-JWT VC mandatory <c>iss</c> claim path — always disclosed, the lattice bottom every
    /// disclosure computation in this file treats as non-selectable.
    /// </summary>
    private static CredentialPath SdJwtIssPath { get; } = CredentialPath.FromJsonPointer("/iss");

    /// <summary>
    /// The SD-JWT VC mandatory <c>vct</c> claim path — always disclosed, the lattice bottom every
    /// disclosure computation in this file treats as non-selectable.
    /// </summary>
    private static CredentialPath SdJwtVctPath { get; } = CredentialPath.FromJsonPointer("/vct");


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


    /// <summary>
    /// Shared implementation behind the <c>BuildSdJwtProduceDelegate*</c> overloads: parses the stored
    /// SD-JWT resolved by <paramref name="resolveStoredSdJwt"/>, computes the disclosure set (minimal
    /// unless <paramref name="minimalDisclosure"/> is <see langword="false"/>), and builds the bound
    /// KB-JWT presentation.
    /// </summary>
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
                    //The one engine path every flow runs: DcqlDisclosure drives
                    //DcqlEvaluator.Evaluate -> ToDisclosureMatch -> ComputeAsync over the
                    //parsed token via SdTokenDcqlAdapter. iss/vct are the always-visible
                    //mandatory paths (lattice bottom); the engine's SelectedPaths is the
                    //minimal disclosure set.
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

                //Format build: KB-JWT bound to client_id / nonce / transaction_data.
                string sdJwtForHashing = SdJwtSerializer.GetSdJwtForHashing(selected, TestSetup.Base64UrlEncoder);
                using IMemoryOwner<byte> hashInputOwner = MemoryPool.Rent(Encoding.UTF8.GetByteCount(sdJwtForHashing));
                int hashInputLength = Encoding.UTF8.GetBytes(sdJwtForHashing, hashInputOwner.Memory.Span);
                ReadOnlyMemory<byte> hashInputBytes = hashInputOwner.Memory[..hashInputLength];

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
                    transactionDataHashes, cancellationToken: cancellationToken).ConfigureAwait(false);

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
    /// HTTPS host's base address while preserving each URL's path. The
    /// in-memory registration dictionary is updated to match so the AS
    /// resolves the same record on subsequent dispatch.
    /// </summary>
    /// <remarks>
    /// OID4VP JAR signing reads <c>response_uri</c> directly off
    /// <see cref="ClientRecord.ResponseUri"/>, so wallet HTTP POSTs miss the
    /// host unless ResponseUri is aligned as well. AuthCode-only flows do
    /// not consult ResponseUri; the alignment is a no-op for those.
    /// </remarks>
    private ClientRecord AlignRegistrationIssuerToHttpBase(ClientRecord record) =>
        AlignRegistrationToHostHttpBase("default", record);


    /// <summary>
    /// Host-aware variant: aligns the registration's external URLs to the
    /// named host's HTTPS base. Used for multi-host federation
    /// topologies where each entity lives on its own listener — the
    /// anchor's registration aligns to anchor.HttpBaseAddress, the
    /// verifier's to default.HttpBaseAddress.
    /// </summary>
    /// <remarks>
    /// The registration's issuer authority now equals the wire authority — both are the same
    /// <c>https://127.0.0.1:{port}</c> host — so <see cref="DefaultIssuerResolver"/>'s RFC 9207 §2 /
    /// RFC 8414 §2 https-shape gate and the RFC 9449 §4.2 <c>htu</c> comparison are satisfied by
    /// construction, with no application-supplied <see cref="AuthorizationServerIntegration.ResolveIssuerAsync"/>
    /// override needed.
    /// </remarks>
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
        Dictionary<string, FlowState> clientFlowStore = [];

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
                foreach(FlowState state in clientFlowStore.Values)
                {
                    if(state is Verifiable.OAuth.AuthCode.States.ParCompletedState pc
                        && string.Equals(
                            pc.Par.RequestUri.ToString(), requestUri, StringComparison.Ordinal))
                    {
                        return ValueTask.FromResult<FlowState?>(state);
                    }
                }

                return ValueTask.FromResult<FlowState?>(null);
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
                    cancellationToken: cancellationToken).ConfigureAwait(false);

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
            request, context, cancellationToken: cancellationToken).ConfigureAwait(false);

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


    /// <summary>Parses an RFC 7591 §3.2.1 dynamic-registration JSON response body into a <see cref="RegistrationResponse"/>.</summary>
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
    public (FlowState State, int StepCount) GetFlowState(string key)
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
            request, context, cancellationToken: cancellationToken).ConfigureAwait(false);

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
    /// SIOPv2 request preparation — creates a new Relying-Party flow. Sets the transaction
    /// inputs (nonce, client_id, accepted algorithms) on the context bag and dispatches the
    /// preparation endpoint, mirroring <see cref="HandleParAsync"/>. Returns the per-flow request
    /// handle the Wallet echoes as <c>state</c> on its Self-Issued ID Token response. The internal
    /// flow identifier never leaves this method.
    /// </summary>
    public async Task<string> HandleSiopRequestPreparationAsync(
        VerifierKeyMaterial keyMaterial,
        string nonce,
        string clientId,
        IReadOnlyList<string> allowedAlgorithms,
        CancellationToken cancellationToken)
    {
        (string requestHandle, _) = await HandleSiopRequestPreparationAsync(
            keyMaterial, nonce, clientId, allowedAlgorithms,
            useStaticDiscoveryAudience: false, cancellationToken: cancellationToken).ConfigureAwait(false);

        return requestHandle;
    }


    /// <summary>
    /// SIOPv2 request preparation that also exposes the by-reference <c>request_uri</c> the
    /// preparation endpoint composed, and lets the caller toggle the §9.1 static-discovery
    /// <c>aud</c>. Returns both the per-flow request handle (echoed as <c>state</c>) and the
    /// <c>request_uri</c> the Wallet GETs to fetch the signed §9 Request Object.
    /// </summary>
    public Task<(string RequestHandle, Uri RequestUri)> HandleSiopRequestPreparationAsync(
        VerifierKeyMaterial keyMaterial,
        string nonce,
        string clientId,
        IReadOnlyList<string> allowedAlgorithms,
        bool useStaticDiscoveryAudience,
        CancellationToken cancellationToken) =>
        HandleSiopRequestPreparationAsync(
            keyMaterial, nonce, clientId, allowedAlgorithms, useStaticDiscoveryAudience,
            encryptionKeyId: null, allowedEncAlgorithms: null, cancellationToken);


    /// <summary>
    /// SIOPv2 request preparation that also advertises the Relying Party's encryption key id and
    /// accepted content-encryption algorithms, so the Wallet may return the Self-Issued ID Token as a
    /// compact JWE encrypted to the RP's public encryption key. The encrypted-response analogue of the
    /// bare-JWS preparation above.
    /// </summary>
    public Task<(string RequestHandle, Uri RequestUri)> HandleSiopRequestPreparationAsync(
        VerifierKeyMaterial keyMaterial,
        string nonce,
        string clientId,
        IReadOnlyList<string> allowedAlgorithms,
        bool useStaticDiscoveryAudience,
        string? encryptionKeyId,
        IReadOnlyList<string>? allowedEncAlgorithms,
        CancellationToken cancellationToken) =>
        HandleSiopRequestPreparationAsync(
            keyMaterial, nonce, clientId, allowedAlgorithms, useStaticDiscoveryAudience,
            encryptionKeyId, allowedEncAlgorithms, requestObjectAdditionalHeaderClaims: null,
            cancellationToken);


    /// <summary>
    /// SIOPv2 request preparation that also sets the additional §9 Request Object JOSE header claims —
    /// the client-id-prefix material (<c>x5c</c>, <c>trust_chain</c>, <c>jwt</c>, <c>kid</c>) the
    /// wallet resolves the RP signing key from through the shared client-id trust fabric. The SIOP
    /// parallel of how the OID4VP PAR helper threads <c>jarAdditionalHeaderClaims</c>.
    /// </summary>
    public async Task<(string RequestHandle, Uri RequestUri)> HandleSiopRequestPreparationAsync(
        VerifierKeyMaterial keyMaterial,
        string nonce,
        string clientId,
        IReadOnlyList<string> allowedAlgorithms,
        bool useStaticDiscoveryAudience,
        string? encryptionKeyId,
        IReadOnlyList<string>? allowedEncAlgorithms,
        JwtHeader? requestObjectAdditionalHeaderClaims,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(keyMaterial);
        ArgumentException.ThrowIfNullOrWhiteSpace(nonce);
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentNullException.ThrowIfNull(allowedAlgorithms);

        ExchangeContext context = new();
        context.SetTenantId(keyMaterial.Registration.TenantId);
        context.SetSiopNonce(nonce);
        context.SetSiopClientId(clientId);
        context.SetSiopAllowedAlgorithms(allowedAlgorithms);
        context.SetSiopUseStaticDiscoveryAudience(useStaticDiscoveryAudience);

        if(encryptionKeyId is not null)
        {
            context.SetSiopEncryptionKeyId(encryptionKeyId);
        }

        if(allowedEncAlgorithms is not null)
        {
            context.SetSiopAllowedEncAlgorithms(allowedEncAlgorithms);
        }

        if(requestObjectAdditionalHeaderClaims is not null)
        {
            context.SetSiopRequestObjectAdditionalHeaderClaims(requestObjectAdditionalHeaderClaims);
        }

        //The preparation endpoint is invoked internally by the RP app — not from a wire HTTP
        //request. The matcher reads context (the siop.nonce slot) and ignores path and fields.
        //IncomingRequest is constructed for protocol-uniformity; its Path is the canonical
        ///siop_request template substituted with the segment.
        string segment = keyMaterial.Registration.TenantId.Value;
        string preparationPath = TestHostShell.ComposeEndpointPath(
            WellKnownEndpointNames.SiopRequestObject, segment);

        IncomingRequest request = new(
            Path: preparationPath,
            Method: "POST",
            Fields: new RequestFields(),
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty);

        ServerHttpResponse response = await Server.DispatchAsync(
            request, context, cancellationToken: cancellationToken).ConfigureAwait(false);

        if(!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"SIOP request preparation failed with status {response.StatusCode}: {response.Body}");
        }

        //The library placed the per-flow request handle and the composed request_uri on context
        //before dispatch returned.
        string requestHandle = context.SiopRequestHandle
            ?? throw new InvalidOperationException("SiopRequestHandle not set after preparation.");
        Uri requestUri = context.SiopGeneratedRequestUri
            ?? throw new InvalidOperationException("SiopGeneratedRequestUri not set after preparation.");

        return (requestHandle, requestUri);
    }


    /// <summary>
    /// SIOPv2 §9 Request Object fetch — the by-reference GET against the <c>request_uri</c>. The
    /// <paramref name="externalToken"/> is the per-flow request handle from
    /// <see cref="HandleSiopRequestPreparationAsync(VerifierKeyMaterial, string, string, IReadOnlyList{string}, bool, CancellationToken)"/>.
    /// Returns the signed compact §9 Request Object the RP served. Mirrors
    /// <see cref="HandleJarRequestAsync"/>.
    /// </summary>
    public async Task<string> HandleSiopRequestObjectAsync(
        VerifierKeyMaterial keyMaterial,
        string externalToken,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(keyMaterial);
        ArgumentException.ThrowIfNullOrWhiteSpace(externalToken);

        ExchangeContext context = new();
        context.SetTenantId(keyMaterial.Registration.TenantId);
        context.SetCorrelationKey(externalToken);

        //The request-object endpoint matches on context.CorrelationKey — the RP app's URL routing
        //layer extracted the {handle} segment from the request_uri and placed it on context before
        //dispatching, the same skin behaviour as the OID4VP JAR-fetch endpoint.
        string segment = keyMaterial.Registration.TenantId.Value;
        string requestObjectPath = TestHostShell.ComposeEndpointPath(
            WellKnownEndpointNames.SiopRequestObjectByReference, segment) + "/" + externalToken;

        IncomingRequest request = new(
            Path: requestObjectPath,
            Method: "GET",
            Fields: new RequestFields(),
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty);

        ServerHttpResponse response = await Server.DispatchAsync(
            request, context, cancellationToken: cancellationToken).ConfigureAwait(false);

        if(response.StatusCode != 200)
        {
            throw new InvalidOperationException(
                $"SIOP §9 Request Object request failed with status {response.StatusCode}: {response.Body}");
        }

        return context.SiopRequestObject
            ?? throw new InvalidOperationException(
                "SiopRequestObject not set in context after request-object dispatch.");
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
            request, context, cancellationToken: cancellationToken).ConfigureAwait(false);

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
            request, context, cancellationToken: cancellationToken).ConfigureAwait(false);

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
            request, context, cancellationToken: cancellationToken).ConfigureAwait(false);

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
    public ValueTask<ServerHttpResponse> DispatchAtEndpointAsync(
        string segment,
        string endpointName,
        string httpMethod,
        RequestFields fields,
        ExchangeContext context,
        CancellationToken cancellationToken)
        => DispatchAtEndpointAsync(
            segment, endpointName, httpMethod, fields, RequestHeaders.Empty, context, cancellationToken);


    /// <summary>
    /// Header-carrying form of
    /// <see cref="DispatchAtEndpointAsync(string, string, string, RequestFields, ExchangeContext, CancellationToken)"/>
    /// for tests that exercise header-driven policy — for example a
    /// <c>ResolveCapabilitiesAsync</c> that attenuates capabilities by the caller's
    /// <c>X-Forwarded-For</c>. The no-headers form delegates here with
    /// <see cref="RequestHeaders.Empty"/>.
    /// </summary>
    public async ValueTask<ServerHttpResponse> DispatchAtEndpointAsync(
        string segment,
        string endpointName,
        string httpMethod,
        RequestFields fields,
        RequestHeaders headers,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);
        ArgumentException.ThrowIfNullOrWhiteSpace(endpointName);
        ArgumentException.ThrowIfNullOrWhiteSpace(httpMethod);
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(headers);
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
            Headers: headers,
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
    /// Dispatches a request carrying a body with an explicit content type and raw bytes — the
    /// content-type-controlling form used to exercise the §2.4 <c>application/json</c> MUST and the
    /// §2.4 / B.4 payload-size 413 (a non-JSON content type, or a body over the cap, must be
    /// rejected before parsing). An empty <paramref name="contentType"/> dispatches with no body.
    /// </summary>
    public async ValueTask<ServerHttpResponse> DispatchWithBodyAsync(
        string segment,
        string endpointName,
        string httpMethod,
        ReadOnlyMemory<byte> bodyBytes,
        string contentType,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);
        ArgumentException.ThrowIfNullOrWhiteSpace(endpointName);
        ArgumentException.ThrowIfNullOrWhiteSpace(httpMethod);
        ArgumentNullException.ThrowIfNull(contentType);
        ArgumentNullException.ThrowIfNull(context);

        string path = ComposeEndpointPath(endpointName, segment);

        RequestBody body = contentType.Length == 0
            ? RequestBody.None
            : new RequestBody
            {
                Bytes = bodyBytes,
                ContentType = contentType
            };

        IncomingRequest request = new(
            Path: path,
            Method: httpMethod,
            Fields: new RequestFields(),
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
    /// Dispatches a VCALM 1.0 §3.2.2 / §3.2.3 <c>{GET|DELETE} /credentials/{id}</c> request: the
    /// issuer's <c>/credentials</c> collection path (resolved from
    /// <see cref="WellKnownVcalmEndpointNames.VcalmGetCredential"/>) plus the URL-escaped credential id as
    /// the trailing path segment. The §3.2.2 / §3.2.3 matchers extract the id from this trailing
    /// segment. The id is passed RAW (the path is escaped here) so callers test with urn / data-URL
    /// ids verbatim.
    /// </summary>
    public async ValueTask<ServerHttpResponse> DispatchVcalmCredentialByIdAsync(
        string segment,
        string httpMethod,
        string credentialId,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);
        ArgumentException.ThrowIfNullOrWhiteSpace(httpMethod);
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialId);
        ArgumentNullException.ThrowIfNull(context);

        //The collection path the §3.2.2 / §3.2.3 endpoints resolve to, plus the escaped id segment.
        string collectionPath = ComposeEndpointPath(WellKnownVcalmEndpointNames.VcalmGetCredential, segment);
        string path = $"{collectionPath}/{Uri.EscapeDataString(credentialId)}";

        IncomingRequest request = new(
            Path: path,
            Method: httpMethod,
            Fields: new RequestFields(),
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty);

        context.SetTenantId(segment);
        return await Server.DispatchAsync(request, context, cancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Dispatches a VCALM 1.0 §C.2 <c>GET /status-lists/{id}</c> request: the status service's
    /// <c>/status-lists</c> collection path (resolved from
    /// <see cref="WellKnownVcalmEndpointNames.VcalmGetStatusList"/>) plus the URL-escaped status-list
    /// id as the trailing path segment. The §C.2 matcher extracts the id from this trailing segment.
    /// The id is passed RAW (the path is escaped here) so callers test with urn / URL ids verbatim.
    /// </summary>
    public async ValueTask<ServerHttpResponse> DispatchVcalmStatusListByIdAsync(
        string segment,
        string statusListId,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);
        ArgumentException.ThrowIfNullOrWhiteSpace(statusListId);
        ArgumentNullException.ThrowIfNull(context);

        string collectionPath = ComposeEndpointPath(WellKnownVcalmEndpointNames.VcalmGetStatusList, segment);
        string path = $"{collectionPath}/{Uri.EscapeDataString(statusListId)}";

        IncomingRequest request = new(
            Path: path,
            Method: "GET",
            Fields: new RequestFields(),
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty);

        context.SetTenantId(segment);
        return await Server.DispatchAsync(request, context, cancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Dispatches a VCALM 1.0 §3.5.4 / §3.5.5 <c>{GET|DELETE} /presentations/{id}</c> request: the
    /// holder's <c>/presentations</c> collection path (resolved from
    /// <see cref="WellKnownVcalmEndpointNames.VcalmGetPresentation"/>) plus the URL-escaped presentation
    /// id as the trailing path segment. The §3.5.4 / §3.5.5 matchers extract the id from this trailing
    /// segment. The id is passed RAW (the path is escaped here) so callers test with urn ids verbatim.
    /// </summary>
    public async ValueTask<ServerHttpResponse> DispatchVcalmPresentationByIdAsync(
        string segment,
        string httpMethod,
        string presentationId,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);
        ArgumentException.ThrowIfNullOrWhiteSpace(httpMethod);
        ArgumentException.ThrowIfNullOrWhiteSpace(presentationId);
        ArgumentNullException.ThrowIfNull(context);

        string collectionPath = ComposeEndpointPath(WellKnownVcalmEndpointNames.VcalmGetPresentation, segment);
        string path = $"{collectionPath}/{Uri.EscapeDataString(presentationId)}";

        IncomingRequest request = new(
            Path: path,
            Method: httpMethod,
            Fields: new RequestFields(),
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty);

        context.SetTenantId(segment);
        return await Server.DispatchAsync(request, context, cancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Dispatches a VCALM 1.0 §3.6.5 <c>POST /exchanges/{id}</c> participate or §3.6.6
    /// <c>GET /exchanges/{id}</c> get-state request: the exchange engine's <c>/exchanges</c> collection
    /// path (resolved from <see cref="WellKnownVcalmEndpointNames.VcalmParticipateInExchange"/>) plus the
    /// URL-escaped exchange id as the trailing path segment. The §3.6.5 / §3.6.6 matchers extract the id
    /// from this trailing segment. A <see langword="null"/> <paramref name="jsonBody"/> dispatches with
    /// no body (the §3.6.6 GET); a non-null body is the §3.6.5 vcapi message.
    /// </summary>
    public async ValueTask<ServerHttpResponse> DispatchVcalmExchangeByIdAsync(
        string segment,
        string httpMethod,
        string exchangeId,
        string? jsonBody,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);
        ArgumentException.ThrowIfNullOrWhiteSpace(httpMethod);
        ArgumentException.ThrowIfNullOrWhiteSpace(exchangeId);
        ArgumentNullException.ThrowIfNull(context);

        string collectionPath = ComposeEndpointPath(WellKnownVcalmEndpointNames.VcalmParticipateInExchange, segment);
        string path = $"{collectionPath}/{Uri.EscapeDataString(exchangeId)}";

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
            Fields: new RequestFields(),
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
    /// Dispatches a VCALM 1.0 §3.6.4 <c>GET /exchanges/{id}/protocols</c> get-exchange-protocols
    /// request: the exchange engine's <c>/exchanges</c> collection path plus the URL-escaped exchange id
    /// and the <c>/protocols</c> sub-resource as the trailing path. The §3.6.4 matcher extracts the id
    /// from between the collection path and the <c>/protocols</c> segment.
    /// </summary>
    public async ValueTask<ServerHttpResponse> DispatchVcalmExchangeProtocolsAsync(
        string segment,
        string exchangeId,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);
        ArgumentException.ThrowIfNullOrWhiteSpace(exchangeId);
        ArgumentNullException.ThrowIfNull(context);

        string collectionPath = ComposeEndpointPath(WellKnownVcalmEndpointNames.VcalmGetExchangeProtocols, segment);
        string path = $"{collectionPath}/{Uri.EscapeDataString(exchangeId)}/protocols";

        IncomingRequest request = new(
            Path: path,
            Method: "GET",
            Fields: new RequestFields(),
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty);

        context.SetTenantId(segment);
        return await Server.DispatchAsync(request, context, cancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Dispatches a VCALM 1.0 §3.6.2 <c>GET /workflows/{localWorkflowId}</c> request: the administration
    /// surface's <c>/workflows</c> collection path (resolved from
    /// <see cref="WellKnownVcalmEndpointNames.VcalmGetWorkflow"/>) plus the URL-escaped workflow id as the
    /// trailing path segment. The §3.6.2 matcher extracts the id from the trailing segment.
    /// </summary>
    public async ValueTask<ServerHttpResponse> DispatchVcalmWorkflowByIdAsync(
        string segment,
        string workflowId,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);
        ArgumentException.ThrowIfNullOrWhiteSpace(workflowId);
        ArgumentNullException.ThrowIfNull(context);

        string collectionPath = ComposeEndpointPath(WellKnownVcalmEndpointNames.VcalmGetWorkflow, segment);
        string path = $"{collectionPath}/{Uri.EscapeDataString(workflowId)}";

        IncomingRequest request = new(
            Path: path,
            Method: "GET",
            Fields: new RequestFields(),
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty);

        context.SetTenantId(segment);
        return await Server.DispatchAsync(request, context, cancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Dispatches a VCALM 1.0 §3.6.7 <c>POST /callbacks/{localCallbackId}</c> request: the administration
    /// surface's <c>/callbacks</c> collection path (resolved from
    /// <see cref="WellKnownVcalmEndpointNames.VcalmExchangeStepCallback"/>) plus the URL-escaped callback
    /// id as the trailing path segment, carrying the <c>{event{data{exchangeId}}}</c> body.
    /// </summary>
    public async ValueTask<ServerHttpResponse> DispatchVcalmCallbackAsync(
        string segment,
        string callbackId,
        string? jsonBody,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);
        ArgumentException.ThrowIfNullOrWhiteSpace(callbackId);
        ArgumentNullException.ThrowIfNull(context);

        string collectionPath = ComposeEndpointPath(WellKnownVcalmEndpointNames.VcalmExchangeStepCallback, segment);
        string path = $"{collectionPath}/{Uri.EscapeDataString(callbackId)}";

        RequestBody body = jsonBody is null
            ? RequestBody.None
            : new RequestBody
            {
                Bytes = Encoding.UTF8.GetBytes(jsonBody),
                ContentType = WellKnownMediaTypes.Application.Json
            };

        IncomingRequest request = new(
            Path: path,
            Method: "POST",
            Fields: new RequestFields(),
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
    /// Dispatches a VCALM 1.0 §3.7.4 <c>GET /interactions/{localInteractionId}</c> interaction-protocols
    /// request: the coordinator's <c>/interactions</c> collection path (resolved from
    /// <see cref="WellKnownVcalmEndpointNames.VcalmInteractionProtocols"/>) plus the URL-escaped
    /// interaction id as the trailing path segment, carrying the given <paramref name="acceptHeader"/>
    /// so the §3.7.4 content negotiation can choose the <c>application/json</c> map or the
    /// <c>text/html</c> human-directing fallback. A <see langword="null"/> <paramref name="acceptHeader"/>
    /// dispatches with no Accept header (the §3.7.4 unrecognized-Accept text/html branch).
    /// </summary>
    public async ValueTask<ServerHttpResponse> DispatchVcalmInteractionProtocolsAsync(
        string segment,
        string interactionId,
        string? acceptHeader,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);
        ArgumentException.ThrowIfNullOrWhiteSpace(interactionId);
        ArgumentNullException.ThrowIfNull(context);

        string collectionPath = ComposeEndpointPath(WellKnownVcalmEndpointNames.VcalmInteractionProtocols, segment);
        string path = $"{collectionPath}/{Uri.EscapeDataString(interactionId)}";

        RequestHeaders headers = acceptHeader is null
            ? RequestHeaders.Empty
            : new RequestHeaders(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["Accept"] = [acceptHeader]
            });

        IncomingRequest request = new(
            Path: path,
            Method: "GET",
            Fields: new RequestFields(),
            Headers: headers,
            RouteValues: RouteValues.Empty);

        context.SetTenantId(segment);
        return await Server.DispatchAsync(request, context, cancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Dispatches a VCALM 1.0 §3.7.5 <c>POST /{localInviteId}/invite-request/response</c> inviteRequest:
    /// the coordinator's invite base path (resolved from
    /// <see cref="WellKnownVcalmEndpointNames.VcalmInviteRequest"/>) plus the URL-escaped invite id and
    /// the fixed <c>invite-request/response</c> sub-resource as the trailing path, carrying the
    /// <c>{url, purpose, referenceId?}</c> body.
    /// </summary>
    public async ValueTask<ServerHttpResponse> DispatchVcalmInviteRequestAsync(
        string segment,
        string inviteId,
        string? jsonBody,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);
        ArgumentException.ThrowIfNullOrWhiteSpace(inviteId);
        ArgumentNullException.ThrowIfNull(context);

        string basePath = ComposeEndpointPath(WellKnownVcalmEndpointNames.VcalmInviteRequest, segment);
        string path = $"{basePath}/{Uri.EscapeDataString(inviteId)}/invite-request/response";

        RequestBody body = jsonBody is null
            ? RequestBody.None
            : new RequestBody
            {
                Bytes = Encoding.UTF8.GetBytes(jsonBody),
                ContentType = WellKnownMediaTypes.Application.Json
            };

        IncomingRequest request = new(
            Path: path,
            Method: "POST",
            Fields: new RequestFields(),
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
    /// Header- and body-carrying form of <see cref="DispatchAtEndpointAsync(string, string, string, RequestFields, string, ExchangeContext, CancellationToken)"/>
    /// — for protected endpoints that read both an <c>Authorization</c> bearer header and a
    /// JSON <c>IncomingRequest.Body</c> (the OID4VCI 1.0 §8 Credential Endpoint). A
    /// <see langword="null"/> <paramref name="jsonBody"/> dispatches with no body.
    /// </summary>
    public async ValueTask<ServerHttpResponse> DispatchAtEndpointAsync(
        string segment,
        string endpointName,
        string httpMethod,
        RequestFields fields,
        RequestHeaders headers,
        string? jsonBody,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);
        ArgumentException.ThrowIfNullOrWhiteSpace(endpointName);
        ArgumentException.ThrowIfNullOrWhiteSpace(httpMethod);
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(headers);
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
            Headers: headers,
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
            BaseMemoryPool.Shared);

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
        ImmutableHashSet<CapabilityIdentifier>? capabilities = null) =>
        RegisterDpopClientOnHost("default", clientId, baseUri, profile, capabilities);


    /// <summary>
    /// Registers a DPoP/token-issuing client on the named host. Multi-host
    /// topologies (e.g. a Credential Issuer beside the default Verifier) call
    /// this overload to put the registration and its key material on the right
    /// host's per-host dictionaries.
    /// </summary>
    public VerifierKeyMaterial RegisterDpopClientOnHost(
        string hostName,
        string clientId,
        Uri baseUri,
        PolicyProfile? profile = null,
        ImmutableHashSet<CapabilityIdentifier>? capabilities = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostName);
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentNullException.ThrowIfNull(baseUri);

        HostedAuthorizationServer host = Host(hostName);

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

        host.SigningKeys[signingKeyId] = signingKeyPair.PrivateKey;
        host.VerificationKeys[signingKeyId] = signingKeyPair.PublicKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> exchangeKeyPair =
            TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        KeyId encryptionKeyId = new($"urn:uuid:{Guid.NewGuid()}");
        host.DecryptionKeys[encryptionKeyId] = exchangeKeyPair.PrivateKey;
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

        host.Registrations[segment] = registration;
        host.Registrations[clientId] = registration;

        host.Server.RegisterClient(
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
    /// Re-registers <paramref name="material"/>'s client with an explicit
    /// <see cref="WellKnownTokenTypes.AccessToken"/> lifetime on
    /// <see cref="ClientRecord.TokenLifetimes"/>. Credential-issuing flows that mint a plain
    /// bearer Access Token use this to stay within the OID4VCI 1.0 §13.10 long-lived threshold:
    /// "Long-lived Access Tokens giving access to Credentials MUST not be issued unless
    /// sender-constrained." Updates the per-host registration table and re-emits the registration
    /// event so the routing table re-syncs against the lifetime-bearing record.
    /// </summary>
    public void SetAccessTokenLifetime(VerifierKeyMaterial material, TimeSpan lifetime, string hostName = "default")
    {
        ArgumentNullException.ThrowIfNull(material);
        ArgumentException.ThrowIfNullOrWhiteSpace(hostName);

        HostedAuthorizationServer host = Host(hostName);

        //Read the live record from the per-host table — other helpers (e.g. UpdateSigningKeys)
        //may have re-registered the client without updating material.Registration, so the dict is
        //the source of truth for the current key/scope/lifetime set.
        string segment = material.Registration.TenantId.Value;
        if(!host.Registrations.TryGetValue(segment, out ClientRecord? previous))
        {
            throw new InvalidOperationException(
                $"No registration found for segment '{segment}'.");
        }

        ImmutableDictionary<string, TimeSpan> lifetimes = previous.TokenLifetimes
            .ToImmutableDictionary(StringComparer.Ordinal)
            .SetItem(WellKnownTokenTypes.AccessToken, lifetime);

        ClientRecord updated = previous with
        {
            TokenLifetimes = lifetimes
        };

        host.Registrations[segment] = updated;
        host.Registrations[updated.ClientId] = updated;

        host.Server.UpdateClient(previous, updated, new ExchangeContext());

        material.Registration = updated;
    }


    /// <summary>
    /// Re-registers <paramref name="material"/>'s client with the RFC 9396 §10
    /// <c>authorization_details_types</c> allowlist set to
    /// <paramref name="allowedTypes"/> on <see cref="ClientRecord.AllowedAuthorizationDetailsTypes"/>.
    /// Drives the per-client gate that refuses an authorization details object whose <c>type</c>
    /// is outside the registered set. Uses the same register-then-upgrade pattern as
    /// <see cref="SetAccessTokenLifetime"/>, because the routing dictionaries are host-internal.
    /// </summary>
    public void SetAllowedAuthorizationDetailsTypes(
        VerifierKeyMaterial material,
        ImmutableHashSet<string> allowedTypes,
        string hostName = "default")
    {
        ArgumentNullException.ThrowIfNull(material);
        ArgumentNullException.ThrowIfNull(allowedTypes);
        ArgumentException.ThrowIfNullOrWhiteSpace(hostName);

        HostedAuthorizationServer host = Host(hostName);

        string segment = material.Registration.TenantId.Value;
        if(!host.Registrations.TryGetValue(segment, out ClientRecord? previous))
        {
            throw new InvalidOperationException(
                $"No registration found for segment '{segment}'.");
        }

        ClientRecord updated = previous with
        {
            AllowedAuthorizationDetailsTypes = allowedTypes
        };

        host.Registrations[segment] = updated;
        host.Registrations[updated.ClientId] = updated;

        host.Server.UpdateClient(previous, updated, new ExchangeContext());

        material.Registration = updated;
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

        Server.OAuth().ResolveServerHmacKeyAsync = (kid, tenantId, ctx, ct) =>
            ValueTask.FromResult(DpopHmacKeySet!.ResolveMaterial(kid));
        Server.OAuth().GetHmacKeySetAsync = (tenantId, ctx, ct) =>
            ValueTask.FromResult(DpopHmacKeySet!.Snapshot());
        Server.OAuth().ValidateDpopProofAsync = (request, ct) =>
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
        Server.OAuth().IssueDpopNonceAsync = (audience, tenantId, ctx, ct) =>
            DefaultDpopNonceIssuance.IssueAsync(
                audience,
                tenantId,
                ctx,
                Server.OAuth().GetHmacKeySetAsync!,
                Server.OAuth().SelectHmacKeyAsync,
                Server.OAuth().ResolveServerHmacKeyAsync!,
                Time,
                Base64UrlEncoder,
                System.Security.Cryptography.RandomNumberGenerator.Fill,
                MemoryPool,
                ct);
        Server.OAuth().ValidateDpopNonceAsync = (presented, audience, tenantId, ctx, ct) =>
            DefaultDpopNonceValidation.ValidateAsync(
                presented,
                audience,
                tenantId,
                ctx,
                Server.OAuth().GetHmacKeySetAsync!,
                Server.OAuth().ResolveServerHmacKeyAsync!,
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
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(32);
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
        Dictionary<string, FlowState> clientFlowStore = [];

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
                foreach(FlowState state in clientFlowStore.Values)
                {
                    if(state is Verifiable.OAuth.AuthCode.States.ParCompletedState pc
                        && string.Equals(
                            pc.Par.RequestUri.ToString(), requestUri, StringComparison.Ordinal))
                    {
                        return ValueTask.FromResult<FlowState?>(state);
                    }
                }

                return ValueTask.FromResult<FlowState?>(null);
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

        await StartHttpHostAsync(cancellationToken: cancellationToken).ConfigureAwait(false);

        ClientRecord alignedRecord = AlignRegistrationIssuerToHttpBase(record);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> dpopKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);
        InMemoryDpopNonceCache nonceCache = new();

        Dictionary<string, FlowState> clientFlowStore = [];

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
                foreach(FlowState state in clientFlowStore.Values)
                {
                    if(state is Verifiable.OAuth.AuthCode.States.ParCompletedState pc
                        && string.Equals(
                            pc.Par.RequestUri.ToString(), requestUri, StringComparison.Ordinal))
                    {
                        return ValueTask.FromResult<FlowState?>(state);
                    }
                }

                return ValueTask.FromResult<FlowState?>(null);
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
    /// Starts an in-process HTTPS listener bound to loopback on an
    /// OS-assigned ephemeral port and maps inbound requests to
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
    /// Starts an in-process HTTPS listener for the named host. Multi-host
    /// federation topologies (verifier + anchor) start each host's listener
    /// independently so each gets its own ephemeral port and authority.
    /// Idempotent per host — repeat calls return without re-binding.
    /// </summary>
    public async Task StartHttpHostAsync(string hostName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostName);

        HostedAuthorizationServer host = Host(hostName);
        if(host.HttpHost is not null)
        {
            return;
        }

        X509Certificate2 hostCertificate = HostCertificate(hostName);

        global::Microsoft.AspNetCore.Builder.WebApplicationBuilder builder =
            global::Microsoft.AspNetCore.Builder.WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();

        //Kestrel's ListenLocalhost(0) rejects dynamic port (it binds both IPv4 + IPv6 loopback and
        //can't reconcile a single OS-assigned port across two sockets). Listen on IPv4 loopback with
        //an ephemeral port, presenting the host's certificate (its own distinct one when added with
        //useDistinctCertificate: true, the shell's shared one otherwise); the dispatched URL uses
        //127.0.0.1 explicitly. A single explicit HTTPS Listen call — no UseUrls — so there is no
        //plaintext fallback on this host at all.
        builder.WebHost.ConfigureKestrel(options =>
            options.Listen(System.Net.IPAddress.Loopback, port: 0,
                listenOptions => listenOptions.UseHttps(hostCertificate)));

        global::Microsoft.AspNetCore.Builder.WebApplication app = builder.Build();

        AuthorizationServerHttpApplication application = new(host.Server);
        app.Run(application.ProcessRequestAsync);

        await app.StartAsync(cancellationToken).ConfigureAwait(false);

        global::Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature addresses =
            app.Services.GetRequiredService<global::Microsoft.AspNetCore.Hosting.Server.IServer>()
                .Features.Get<global::Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>()
            ?? throw new InvalidOperationException(
                $"HTTPS host '{hostName}' started but no server addresses were exposed via IServerAddressesFeature.");
        string boundAddress = addresses.Addresses.FirstOrDefault()
            ?? throw new InvalidOperationException($"HTTPS host '{hostName}' bound no address.");

        host.HttpHost = app;
        host.HttpBaseAddress = new Uri(boundAddress);
        host.SharedHttpClient = LoopbackTls.CreatePinnedHttpClient(hostCertificate, host.HttpBaseAddress);
    }


    /// <summary>
    /// Starts an in-process HTTPS listener for the W3C VCALM 1.0 conformance bridge (chunk V-6a):
    /// the same ephemeral-port loopback bootstrap as <see cref="StartHttpHostAsync(string, CancellationToken)"/>,
    /// but mounting <see cref="Verifiable.Tests.Vcalm.VcalmConformanceHttpApplication"/> so the VCALM
    /// issuer / verifier interfaces are served at the STABLE, suite-expected flat paths
    /// (<c>/credentials/issue</c>, <c>/credentials/verify</c>, <c>/presentations/verify</c>) over real
    /// HTTPS behind an OAuth2 client-credentials bearer gate, with the AS token endpoint reachable at
    /// <c>/token</c>. The external <c>vc-api-issuer-test-suite</c> / <c>vc-api-verifier-test-suite</c>
    /// JS suites POST to those flat paths; this is the in-repo bridge the suites would later be pointed
    /// at (V-6b). Idempotent per host. The supplied <paramref name="registration"/> is the conformance
    /// tenant whose VCALM endpoints the skin fronts.
    /// </summary>
    public async Task StartVcalmConformanceHostAsync(
        string hostName, ClientRecord registration, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostName);
        ArgumentNullException.ThrowIfNull(registration);

        HostedAuthorizationServer host = Host(hostName);
        if(host.HttpHost is not null)
        {
            return;
        }

        X509Certificate2 hostCertificate = HostCertificate(hostName);

        global::Microsoft.AspNetCore.Builder.WebApplicationBuilder builder =
            global::Microsoft.AspNetCore.Builder.WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();

        builder.WebHost.ConfigureKestrel(options =>
            options.Listen(System.Net.IPAddress.Loopback, port: 0,
                listenOptions => listenOptions.UseHttps(hostCertificate)));

        global::Microsoft.AspNetCore.Builder.WebApplication app = builder.Build();

        Verifiable.Tests.Vcalm.VcalmConformanceHttpApplication application = new(host.Server, registration);
        app.Run(application.ProcessRequestAsync);

        await app.StartAsync(cancellationToken).ConfigureAwait(false);

        global::Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature addresses =
            app.Services.GetRequiredService<global::Microsoft.AspNetCore.Hosting.Server.IServer>()
                .Features.Get<global::Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>()
            ?? throw new InvalidOperationException(
                $"HTTPS host for VCALM conformance host '{hostName}' started but no server addresses were exposed.");
        string boundAddress = addresses.Addresses.FirstOrDefault()
            ?? throw new InvalidOperationException(
                $"HTTPS host for VCALM conformance host '{hostName}' bound no address.");

        host.HttpHost = app;
        host.HttpBaseAddress = new Uri(boundAddress);
        host.SharedHttpClient = LoopbackTls.CreatePinnedHttpClient(hostCertificate, host.HttpBaseAddress);
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

            if(host.HttpHost is not null)
            {
                await host.HttpHost.StopAsync(CancellationToken.None).ConfigureAwait(false);
                await host.HttpHost.DisposeAsync().ConfigureAwait(false);
                host.HttpHost = null;
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

        foreach(IDisposable owned in TransportOwnedDisposables)
        {
            owned.Dispose();
        }

        foreach(X509Certificate2 certificate in DistinctHostCertificates.Values)
        {
            certificate.Dispose();
        }

        serverCertificate?.Dispose();
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

        //OID4VCI §12.2.2: the Credential Issuer Metadata path is likewise formed by INSERTING
        // /.well-known/openid-credential-issuer between the host and the issuer's path component.
        if(endpointName == WellKnownEndpointNames.Oid4VciCredentialIssuerMetadata)
        {
            return $"/.well-known/openid-credential-issuer/{segment}";
        }

        //RFC 8414 §3: the authorization server metadata path is formed by INSERTING
        // /.well-known/oauth-authorization-server between the host and the issuer's
        //path component — for the fixture's https://issuer.test/{segment} identity
        //that is /.well-known/oauth-authorization-server/{segment}. This is the §3
        //default location, served alongside the appended openid-configuration mount.
        if(endpointName == WellKnownEndpointNames.MetadataOAuthAuthorizationServer)
        {
            return $"/.well-known/oauth-authorization-server/{segment}";
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


    /// <summary>
    /// Shared suffix dispatch — read by <c>ResolveEndpointUriAsync</c> and by the synchronous
    /// <c>Compose*</c> helpers. The fixture's URL-shape contract lives here in one place. New endpoint
    /// roles get added to both <see cref="WellKnownEndpointNames"/> (in the library) and to this switch
    /// (in this fixture). Returns <see langword="null"/> for an endpoint name this fixture does not serve.
    /// </summary>
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
        if(endpointName == WellKnownEndpointNames.TokenExchangeToken) { return "token"; }
        if(endpointName == WellKnownEndpointNames.JwtBearerToken) { return "token"; }
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
        if(endpointName == WellKnownEndpointNames.FederationTrustMark) { return "federation_trust_mark"; }
        if(endpointName == WellKnownEndpointNames.FederationTrustMarkList) { return "federation_trust_mark_list"; }
        if(endpointName == WellKnownEndpointNames.FederationTrustMarkStatus) { return "federation_trust_mark_status"; }
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
        if(endpointName == WellKnownEndpointNames.Oid4VciNonce) { return "nonce"; }
        if(endpointName == WellKnownEndpointNames.Oid4VciPreAuthorizedToken) { return "token"; }
        if(endpointName == WellKnownEndpointNames.Oid4VciCredential) { return "credential"; }
        if(endpointName == WellKnownEndpointNames.Oid4VciDeferredCredential) { return "deferred_credential"; }
        if(endpointName == WellKnownEndpointNames.Oid4VciNotification) { return "notification"; }
        if(endpointName == WellKnownEndpointNames.Oid4VciCredentialOffer) { return "credential_offer"; }
        if(endpointName == WellKnownEndpointNames.SiopRequestObject) { return "siop_request"; }
        if(endpointName == WellKnownEndpointNames.SiopRequestObjectByReference) { return "siop_request_object"; }
        if(endpointName == WellKnownEndpointNames.SiopResponse) { return "siop_response"; }
        //VCALM 1.0 §3.3 verifier paths (the instance pathing per §2.3 is deployment-chosen; the
        //host skin scopes them under the tenant segment like the other service endpoints).
        if(endpointName == WellKnownVcalmEndpointNames.VcalmCredentialsVerify) { return "vcalm/credentials/verify"; }
        if(endpointName == WellKnownVcalmEndpointNames.VcalmPresentationsVerify) { return "vcalm/presentations/verify"; }
        if(endpointName == WellKnownVcalmEndpointNames.VcalmCreateChallenge) { return "vcalm/challenges"; }
        //VCALM 1.0 §3.2 issuer paths. The §3.2.2 / §3.2.3 endpoints resolve to the /credentials
        //collection path; the matcher accepts collection/{id} and extracts the trailing id segment.
        if(endpointName == WellKnownVcalmEndpointNames.VcalmCredentialsIssue) { return "vcalm/credentials/issue"; }
        if(endpointName == WellKnownVcalmEndpointNames.VcalmGetCredential) { return "vcalm/credentials"; }
        if(endpointName == WellKnownVcalmEndpointNames.VcalmDeleteCredential) { return "vcalm/credentials"; }
        //VCALM 1.0 Appendix C status paths. The §C.2 endpoint resolves to the /status-lists
        //collection path; the matcher accepts collection/{id} and extracts the trailing id segment.
        if(endpointName == WellKnownVcalmEndpointNames.VcalmCredentialsStatus) { return "vcalm/credentials/status"; }
        if(endpointName == WellKnownVcalmEndpointNames.VcalmCreateStatusList) { return "vcalm/status-lists"; }
        if(endpointName == WellKnownVcalmEndpointNames.VcalmGetStatusList) { return "vcalm/status-lists"; }
        //VCALM 1.0 §3.5 holder presentation paths. The §3.5.2 POST and §3.5.3 GET share the
        ///presentations collection path (the matchers split by method); the §3.5.4 / §3.5.5 endpoints
        //resolve to the same collection path and the matcher extracts the trailing id segment.
        if(endpointName == WellKnownVcalmEndpointNames.VcalmCredentialsDerive) { return "vcalm/credentials/derive"; }
        if(endpointName == WellKnownVcalmEndpointNames.VcalmCreatePresentation) { return "vcalm/presentations"; }
        if(endpointName == WellKnownVcalmEndpointNames.VcalmGetPresentations) { return "vcalm/presentations"; }
        if(endpointName == WellKnownVcalmEndpointNames.VcalmGetPresentation) { return "vcalm/presentations"; }
        if(endpointName == WellKnownVcalmEndpointNames.VcalmDeletePresentation) { return "vcalm/presentations"; }
        //VCALM 1.0 §3.6 workflows-and-exchanges paths. The §3.6.3 create POSTs to the /exchanges
        //collection path; the §3.6.4 / §3.6.5 / §3.6.6 endpoints resolve to the same collection path
        //and the matchers extract the trailing {localExchangeId} (+ "/protocols" for §3.6.4) segment.
        if(endpointName == WellKnownVcalmEndpointNames.VcalmCreateExchange) { return "vcalm/exchanges"; }
        if(endpointName == WellKnownVcalmEndpointNames.VcalmGetExchangeProtocols) { return "vcalm/exchanges"; }
        if(endpointName == WellKnownVcalmEndpointNames.VcalmParticipateInExchange) { return "vcalm/exchanges"; }
        if(endpointName == WellKnownVcalmEndpointNames.VcalmGetExchangeState) { return "vcalm/exchanges"; }

        //VCALM 1.0 §3.6.1 / §3.6.2 administration + §3.6.7 callbacks
        if(endpointName == WellKnownVcalmEndpointNames.VcalmCreateWorkflow) { return "vcalm/workflows"; }
        if(endpointName == WellKnownVcalmEndpointNames.VcalmGetWorkflow) { return "vcalm/workflows"; }
        if(endpointName == WellKnownVcalmEndpointNames.VcalmExchangeStepCallback) { return "vcalm/callbacks"; }

        //VCALM 1.0 §3.7 initiating-interactions (coordinator-hosted). The §3.7.4 endpoint resolves to
        //the /interactions collection path and the matcher extracts the trailing {localInteractionId};
        //the §3.7.5 inviteRequest endpoint resolves to its base path and the matcher reads the
        //{localInviteId}/invite-request/response tail.
        if(endpointName == WellKnownVcalmEndpointNames.VcalmInteractionProtocols) { return "vcalm/interactions"; }
        if(endpointName == WellKnownVcalmEndpointNames.VcalmInviteRequest) { return "vcalm/invites"; }

        return null;
    }


    /// <summary>
    /// Builds an OID4VP verifier's <c>client_metadata</c> claim by publishing
    /// <paramref name="exchangePublicKey"/> as a JWK under <paramref name="encryptionKeyId"/>, so the
    /// wallet can encrypt its <c>direct_post.jwt</c> response to it.
    /// </summary>
    private static VerifierClientMetadata BuildClientMetadata(
        string clientId,
        PublicKeyMemory exchangePublicKey,
        KeyId encryptionKeyId)
    {
        string jwksJson = EphemeralEncryptionKeyPair.CreatePublicKeyJwks(
            exchangePublicKey,
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared);

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
    /// server's <see cref="EndpointServer.DispatchAsync"/>. Models the role
    /// of an HTTP layer plus structural router collapsed into one in-memory
    /// class. No closures — all dependencies are constructor parameters.
    /// </summary>
    [DebuggerDisplay("InProcessTransport Segment={segment}")]
    private sealed class InProcessTransport(
        EndpointServer server,
        ClientRecord registration,
        string segment,
        string issuerUri)
    {
        /// <summary>
        /// Routes <paramref name="endpoint"/>/<paramref name="fields"/>/<paramref name="headers"/> to
        /// the constructor-bound <see cref="EndpointServer.DispatchAsync"/> for the constructor-bound
        /// tenant and registration, mapping the resulting <see cref="ServerHttpResponse"/> onto
        /// <see cref="HttpResponseData"/>.
        /// </summary>
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
                request, context, cancellationToken: cancellationToken).ConfigureAwait(false);

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
        EndpointServer server,
        ConcurrentDictionary<string, ClientRecord> registrations,
        string issuerUri)
    {
        /// <summary>
        /// Resolves the <see cref="ClientRecord"/> for <paramref name="endpoint"/>'s tenant segment at
        /// dispatch time and routes to the constructor-bound <see cref="EndpointServer.DispatchAsync"/>,
        /// returning a 404 <see cref="HttpResponseData"/> when no registration is found for the segment.
        /// </summary>
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
                request, context, cancellationToken: cancellationToken).ConfigureAwait(false);

            return new HttpResponseData
            {
                Body = response.Body ?? string.Empty,
                StatusCode = response.StatusCode,
                Headers = BuildResponseHeaders(response.Headers)
            };
        }


        /// <summary>Extracts the tenant segment from <paramref name="path"/>. Delegates to <see cref="ExtractTenantSegmentForTests"/>.</summary>
        private static string ExtractTenantSegment(string path) =>
            ExtractTenantSegmentForTests(path);


        /// <summary>
        /// Extracts the tenant segment from a test path shaped <c>/connect/{segment}/&lt;endpoint&gt;</c>.
        /// Any other shape returns an empty segment, which fails the registration lookup and surfaces a 404.
        /// </summary>
        internal static string ExtractTenantSegmentForTests(string path)
        {
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
