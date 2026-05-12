using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Oid4Vp.Wallet;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Long-lived configuration and I/O delegates shared by every protocol call
/// an <see cref="OAuthClient"/> drives, across every
/// <see cref="ClientRegistration"/> that client serves. The
/// <em>infrastructure</em> half of the registration-versus-infrastructure
/// separation: things that vary with the deployment (transport, time,
/// serializer, parser, memory pool) live here; things that vary with the
/// peer AS or flow live on <see cref="ClientRegistration"/>.
/// </summary>
/// <remarks>
/// <para>
/// One <see cref="OAuthClientInfrastructure"/> serves many registrations.
/// The application constructs the infrastructure once at startup, validating
/// every delegate is wired, then constructs an <see cref="OAuthClient"/>
/// around it. Protocol methods on the client take a
/// <see cref="ClientRegistration"/> as their first parameter and read
/// per-AS state from the registration.
/// </para>
/// <para>
/// All I/O — storage, HTTP transport, time, parsing, validation, encoding —
/// is supplied via delegates. The flow handlers perform no I/O themselves;
/// they call the delegates on this infrastructure instance and return shaped
/// results.
/// </para>
/// <para>
/// Construct via <see cref="Create"/> to validate every mandatory delegate
/// at construction time. The same instance is safe to share across
/// concurrent requests — fields are <see langword="private init"/> after
/// construction and the delegates are expected to be reentrant.
/// </para>
/// </remarks>
[DebuggerDisplay("OAuthClientInfrastructure")]
public sealed class OAuthClientInfrastructure
{
    private OAuthClientInfrastructure() { }


    /// <summary>
    /// UTC time source. Defaults to <see cref="TimeProvider.System"/>.
    /// Inject <c>FakeTimeProvider</c> in tests for deterministic time control.
    /// </summary>
    public TimeProvider TimeProvider { get; private init; } = TimeProvider.System;

    /// <summary>
    /// Memory pool used for sensitive allocations (PKCE verifiers, nonces,
    /// JAR payload buffers). Defaults to
    /// <see cref="SensitiveMemoryPool{T}.Shared"/>.
    /// </summary>
    public MemoryPool<byte> MemoryPool { get; private init; } = null!;

    /// <summary>
    /// Base64url encoder without padding. Required for PKCE verifier and
    /// challenge encoding per RFC 7636 §4.1–4.2.
    /// </summary>
    public EncodeDelegate Base64UrlEncoder { get; private init; } = null!;


    //Transport.

    /// <summary>
    /// Sends an HTTP POST with a form-encoded body and returns the full HTTP
    /// response. Used for PAR, token exchange, refresh, revocation, and
    /// dynamic-registration management requests.
    /// </summary>
    public SendFormPostDelegate SendFormPostAsync { get; private init; } = null!;

    /// <summary>
    /// Sends an HTTP POST with a JSON body — used by RFC 7591 §3 dynamic
    /// client registration. <see langword="null"/> when the application does
    /// not register clients dynamically; required when
    /// <see cref="OAuthDynamicRegistrationClient.RegisterAsync"/> is called.
    /// The in-process test transport wires this delegate to
    /// <see cref="Verifiable.OAuth.Server.Registration.RegistrationEndpoints.HandleCreateAsync"/>;
    /// production deployments wire it to their HTTP transport.
    /// </summary>
    public SendJsonPostDelegate? SendJsonPostAsync { get; private init; }


    //Flow state storage.

    /// <summary>Persists a flow state to durable storage at each state transition point.</summary>
    public SaveFlowStateDelegate SaveStateAsync { get; private init; } = null!;

    /// <summary>Loads a flow state from durable storage by flow identifier.</summary>
    public LoadFlowStateDelegate LoadStateAsync { get; private init; } = null!;

    /// <summary>Loads a flow state from durable storage by PAR <c>request_uri</c>.</summary>
    public LoadFlowStateByRequestUriDelegate LoadStateByRequestUriAsync { get; private init; } = null!;


    //Wire response parsers.

    /// <summary>Parses a PAR endpoint response.</summary>
    public ParseParResponseDelegate ParseParResponseAsync { get; private init; } = null!;

    /// <summary>Parses a token endpoint response.</summary>
    public ParseTokenResponseDelegate ParseTokenResponseAsync { get; private init; } = null!;

    /// <summary>Parses an AS metadata document body into a typed record.</summary>
    public ParseAuthorizationServerMetadataDelegate ParseAuthorizationServerMetadataAsync { get; private init; } = null!;

    /// <summary>Parses an RFC 7591 §3.2.1 registration response body.</summary>
    public ParseRegistrationResponseDelegate ParseRegistrationResponseAsync { get; private init; } = null!;


    //Discovery resolvers.

    /// <summary>
    /// Resolves an AS issuer URL into its
    /// <see cref="AuthorizationServerMetadata"/>. Invoked per-call by
    /// protocol methods that need an endpoint URL or capability list. The
    /// implementation typically fetches and caches per the application's
    /// caching policy.
    /// </summary>
    public ResolveAuthorizationServerMetadataDelegate ResolveAuthorizationServerMetadataAsync { get; private init; } = null!;


    //Profile resolvers.

    /// <summary>
    /// Resolves the callback validator <see cref="Verifiable.Core.Assessment.ClaimIssuer{TInput}"/>
    /// for a registration based on its profile. Wire
    /// <see cref="ClientPolicyProfiles.DefaultResolveCallbackValidator"/> for
    /// the library defaults.
    /// </summary>
    public ResolveCallbackValidatorDelegate ResolveCallbackValidator { get; private init; } = null!;


    //Wallet integration.

    /// <summary>
    /// The wallet-side configuration that backs the OID4VP Wallet
    /// convenience surface on <see cref="OAuthClient"/>. When
    /// <see langword="null"/>, the convenience surface is unavailable and
    /// applications wanting OID4VP Wallet flows construct
    /// <see cref="Oid4VpWalletClient{TCredential}"/> directly.
    /// </summary>
    public Oid4VpWalletConfiguration<SdJwtVcCredential>? DefaultSdJwtVcWalletConfiguration { get; init; }


    /// <summary>
    /// Constructs a fully validated <see cref="OAuthClientInfrastructure"/>.
    /// Every mandatory delegate is checked for non-null at construction so
    /// missing wiring fails fast at startup, not at first protocol call.
    /// </summary>
    public static OAuthClientInfrastructure Create(
        SendFormPostDelegate sendFormPostAsync,
        SaveFlowStateDelegate saveStateAsync,
        LoadFlowStateDelegate loadStateAsync,
        LoadFlowStateByRequestUriDelegate loadStateByRequestUriAsync,
        ParseParResponseDelegate parseParResponseAsync,
        ParseTokenResponseDelegate parseTokenResponseAsync,
        ParseAuthorizationServerMetadataDelegate parseAuthorizationServerMetadataAsync,
        ParseRegistrationResponseDelegate parseRegistrationResponseAsync,
        ResolveAuthorizationServerMetadataDelegate resolveAuthorizationServerMetadataAsync,
        ResolveCallbackValidatorDelegate resolveCallbackValidator,
        EncodeDelegate base64UrlEncoder,
        TimeProvider? timeProvider = null,
        MemoryPool<byte>? memoryPool = null,
        Oid4VpWalletConfiguration<SdJwtVcCredential>? defaultSdJwtVcWalletConfiguration = null,
        SendJsonPostDelegate? sendJsonPostAsync = null)
    {
        ArgumentNullException.ThrowIfNull(sendFormPostAsync);
        ArgumentNullException.ThrowIfNull(saveStateAsync);
        ArgumentNullException.ThrowIfNull(loadStateAsync);
        ArgumentNullException.ThrowIfNull(loadStateByRequestUriAsync);
        ArgumentNullException.ThrowIfNull(parseParResponseAsync);
        ArgumentNullException.ThrowIfNull(parseTokenResponseAsync);
        ArgumentNullException.ThrowIfNull(parseAuthorizationServerMetadataAsync);
        ArgumentNullException.ThrowIfNull(parseRegistrationResponseAsync);
        ArgumentNullException.ThrowIfNull(resolveAuthorizationServerMetadataAsync);
        ArgumentNullException.ThrowIfNull(resolveCallbackValidator);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);

        return new OAuthClientInfrastructure
        {
            SendFormPostAsync = sendFormPostAsync,
            SaveStateAsync = saveStateAsync,
            LoadStateAsync = loadStateAsync,
            LoadStateByRequestUriAsync = loadStateByRequestUriAsync,
            ParseParResponseAsync = parseParResponseAsync,
            ParseTokenResponseAsync = parseTokenResponseAsync,
            ParseAuthorizationServerMetadataAsync = parseAuthorizationServerMetadataAsync,
            ParseRegistrationResponseAsync = parseRegistrationResponseAsync,
            ResolveAuthorizationServerMetadataAsync = resolveAuthorizationServerMetadataAsync,
            ResolveCallbackValidator = resolveCallbackValidator,
            Base64UrlEncoder = base64UrlEncoder,
            TimeProvider = timeProvider ?? TimeProvider.System,
            MemoryPool = memoryPool ?? SensitiveMemoryPool<byte>.Shared,
            DefaultSdJwtVcWalletConfiguration = defaultSdJwtVcWalletConfiguration,
            SendJsonPostAsync = sendJsonPostAsync
        };
    }
}
