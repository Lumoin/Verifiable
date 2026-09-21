using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Text.Json;
using System.Threading.Channels;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.Model.SelectiveDisclosure.Strategy;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.Server.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Oidc;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Audit;
using Verifiable.OAuth.Server.Metadata;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.Server.Registration;
using Verifiable.OAuth.Server.States;
using Verifiable.OAuth.Siop.Server;
using Verifiable.OAuth.Siop.Server.States;
using Verifiable.OAuth.Validation;
using Verifiable.Server.Pipeline;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Vcalm;
using Verifiable.Vcalm.Exchange;

namespace Verifiable.Tests.OAuth;

/// <summary>The five points <see cref="HostedAuthorizationServer.EnterGrantOrderGateAsync"/> reports for its per-grant ordering gate.</summary>
internal enum GrantOrderEventKind
{
    /// <summary>A request joined the FIFO queue for its (tenant, grant key).</summary>
    Enqueued,

    /// <summary>A request was let through to the library.</summary>
    Admitted,

    /// <summary>A request's response was written (or it faulted) and its turn passed to the next waiter.</summary>
    Released,

    /// <summary>A queued request left the FIFO queue through its own cancellation, without ever being admitted.</summary>
    Left,

    /// <summary>The entry for a (tenant, grant key) was removed because nobody held or waited for it any longer.</summary>
    Retired
}


/// <summary>
/// One observation of <see cref="HostedAuthorizationServer.EnterGrantOrderGateAsync"/>'s per-grant
/// ordering gate, in the order it occurred. <see cref="Sequence"/> is allocated and this
/// observation is written to the channel under the same single lock
/// (<see cref="HostedAuthorizationServer.EmitGrantOrderObservation"/>), so the channel's read order
/// IS the sequence order, across every key the host serves.
/// </summary>
/// <param name="Kind">
/// Which point of the gate this observation reports: <see cref="GrantOrderEventKind.Enqueued"/>
/// establishes the request's own FIFO chain position for its key;
/// <see cref="GrantOrderEventKind.Admitted"/> that the library runs for it from that point;
/// <see cref="GrantOrderEventKind.Released"/> that its turn has passed to the next waiter (always
/// before that waiter's own <see cref="GrantOrderEventKind.Admitted"/>);
/// <see cref="GrantOrderEventKind.Left"/> that a queued request departed through its own
/// cancellation, never admitted; <see cref="GrantOrderEventKind.Retired"/> that the key's entry was
/// removed because nobody holds or waits for it any longer.
/// </param>
/// <param name="TenantId">The tenant half of the gate's key.</param>
/// <param name="GrantKey">The grant half of the gate's key.</param>
/// <param name="Sequence">This observation's position in the host's single monotonic sequence.</param>
internal readonly record struct GrantOrderObservation(
    GrantOrderEventKind Kind,
    TenantId TenantId,
    string GrantKey,
    long Sequence);


/// <summary>
/// Per-host state for a single test-fixture <c>AuthorizationServer</c>
/// deployment: registrations, key stores, flow-handle indexes, and the
/// associated HTTPS host + HttpClient when the host is serving requests.
/// </summary>
/// <remarks>
/// <para>
/// One <see cref="TestHostShell"/> may own multiple <see cref="HostedAuthorizationServer"/>
/// instances — typically one per deployment role in a multi-party flow
/// (Verifier, Federation Anchor, Resource Server, OAuth client, etc.).
/// Each hosted server is wired independently, has its own state, and binds
/// its own Kestrel port; the shell is the orchestrator, not a participant.
/// </para>
/// <para>
/// Production parallel: this object stands in for the constellation of
/// dependency-injected services and configuration that a real
/// <c>WebApplication</c> would wire together for a single
/// <c>AuthorizationServer</c> instance.
/// </para>
/// </remarks>
[DebuggerDisplay("HostedAuthorizationServer Name={Name} Clients={Registrations.Count} HasHttp={HttpHost != null}")]
internal sealed class HostedAuthorizationServer: IClientRegistrationStore
{
    /// <summary>Records named server faults observed by the real HTTP skin.</summary>
    public ConcurrentQueue<Exception> HttpFaults { get; } = new();


    /// <summary>Transfers captured faults to the owning assertion so teardown preserves its result.</summary>
    public Exception[] ConsumeHttpFaults()
    {
        List<Exception> faults = [];
        while(HttpFaults.TryDequeue(out Exception? fault))
        {
            faults.Add(fault);
        }

        return [.. faults];
    }


    /// <summary>The fixture hook marking listener arrival before server admission, awaited by the request path.</summary>
    public Func<Task>? RequestArriving { get; set; }


    /// <summary>Whether the listener deliberately permits unvalidated wiring for admission tests.</summary>
    public bool IsUnvalidatedListenerAllowed { get; set; }


    /// <summary>
    /// Whether <see cref="AuthorizationServerHttpApplication.ProcessRequestAsync"/> holds an
    /// inbound request the ordering matrix (<see cref="ResolveOrderingKey"/>) can place behind
    /// other requests of the SAME (tenant, grant key) before dispatching it to the library. This is
    /// the application's own coordination — the last paragraph of
    /// <see cref="Verifiable.OAuth.Server.LoadGrantFlowStatesDelegate"/>'s
    /// documentation — demonstrated by this test host; the library runs no ordering protocol of its
    /// own. Settable so a test can force a concurrency window this gate would otherwise close — the
    /// one stated exception to this codebase's get-only-property rule, mirroring
    /// <see cref="IsUnvalidatedListenerAllowed"/>. Defaults to <see langword="true"/>.
    /// </summary>
    public bool IsOrderingRequestsPerGrant { get; set; } = true;


    /// <summary>
    /// An optional Kestrel connection middleware installed before TLS on this host's next
    /// <see cref="TestHostShell.StartHttpHostAsync(string, CancellationToken)"/> bind, letting one test
    /// hold the raw loopback connection deterministically (e.g. on a closed gate) to prove a deadline
    /// defect without depending on real network timing. <see langword="null"/> installs nothing.
    /// </summary>
    public Func<global::Microsoft.AspNetCore.Connections.ConnectionContext, Func<Task>, Task>? ConnectionMiddleware { get; set; }


    /// <summary>Creates a fresh unvalidated server over construction wiring for admission tests.</summary>
    public void UseUnvalidatedServer()
    {
        EndpointServer source = Server;
        Server = new EndpointServer
        {
            Integration = source.Integration,
            Configuration = source.Configuration,
            TimeProvider = source.TimeProvider,
            ActionExecutor = source.ActionExecutor
        };
        Server.AddIntegration(source.OAuth());
        Server.AddIntegration(source.Vcalm());
        source.Dispose();
    }


    /// <summary>The backend and operation observed for each request in a storage alteration proof.</summary>
    public ConcurrentQueue<(ExchangeContext Context, string Backend, string Operation)> StorageObservations { get; } = new();


    /// <summary>Copies persisted flows and their indexes during the serving host's drained alteration.</summary>
    /// <param name="destination">The independent backend receiving retained flow records.</param>
    public void MigrateFlowStorageTo(HostedAuthorizationServer destination)
    {
        foreach(var entry in FlowStates)
        {
            destination.FlowStates[entry.Key] = entry.Value;
        }
        foreach(var entry in ClaimedFlowSteps)
        {
            destination.ClaimedFlowSteps[entry.Key] = entry.Value;
        }
        foreach(var entry in RequestUriTokenIndex)
        {
            destination.RequestUriTokenIndex[entry.Key] = entry.Value;
        }
        foreach(var entry in CodeIndex)
        {
            destination.CodeIndex[entry.Key] = entry.Value;
        }
        foreach(var entry in JtiIndex)
        {
            destination.JtiIndex[entry.Key] = entry.Value;
        }
        foreach(var entry in AccessTokenIndex)
        {
            destination.AccessTokenIndex[entry.Key] = entry.Value;
        }
        foreach(var entry in RefreshTokenIndex)
        {
            destination.RefreshTokenIndex[entry.Key] = entry.Value;
        }
        foreach(var entry in GrantIndex)
        {
            destination.GrantIndex[entry.Key] = new ConcurrentDictionary<string, byte>(entry.Value);
        }
    }


    /// <summary>Installs one backend's full storage bundle with per-request observation.</summary>
    /// <param name="candidate">The candidate integration receiving the storage operations.</param>
    /// <param name="backend">The independent backend supplying every operation.</param>
    public void InstallObservedStorage(AuthorizationServerIntegration candidate, HostedAuthorizationServer backend)
    {
        AuthorizationServerIntegration source = backend.Server.OAuth();
        LoadServerFlowStateDelegate load = source.LoadFlowStateAsync!;
        SaveServerFlowStateDelegate save = source.SaveFlowStateAsync!;
        ClaimServerFlowStateDelegate claim = source.ClaimFlowStateAsync!;
        DeleteServerFlowStateDelegate delete = source.DeleteFlowStateAsync!;
        ResolveCorrelationKeyDelegate correlate = source.ResolveCorrelationKeyAsync!;
        LoadGrantFlowStatesDelegate loadGrant = source.LoadGrantFlowStatesAsync!;
        candidate.LoadGrantFlowStatesAsync = (tenant, grantFlowId, ctx, ct) =>
        {
            StorageObservations.Enqueue((ctx, backend.Name, "load-grant"));

            return loadGrant(tenant, grantFlowId, ctx, ct);
        };
        candidate.LoadFlowStateAsync = (tenant, key, ctx, ct) =>
        {
            StorageObservations.Enqueue((ctx, backend.Name, "load"));

            return load(tenant, key, ctx, ct);
        };
        candidate.SaveFlowStateAsync = (tenant, key, state, step, ctx, ct) =>
        {
            StorageObservations.Enqueue((ctx, backend.Name, "save"));

            return save(tenant, key, state, step, ctx, ct);
        };
        candidate.ClaimFlowStateAsync = (tenant, key, step, ctx, ct) =>
        {
            StorageObservations.Enqueue((ctx, backend.Name, "claim"));

            return claim(tenant, key, step, ctx, ct);
        };
        candidate.DeleteFlowStateAsync = (tenant, key, ctx, ct) =>
        {
            StorageObservations.Enqueue((ctx, backend.Name, "delete"));

            return delete(tenant, key, ctx, ct);
        };
        candidate.ResolveCorrelationKeyAsync = (tenant, kind, key, ctx, ct) =>
        {
            StorageObservations.Enqueue((ctx, backend.Name, "correlate"));

            return correlate(tenant, kind, key, ctx, ct);
        };
    }


    /// <summary>
    /// Asserts that NO flow-state store operation of ANY kind — <c>correlate</c>, <c>load</c>,
    /// <c>save</c>, <c>claim</c>, <c>delete</c>, and <c>load-grant</c> alike — was recorded on
    /// <see cref="StorageObservations"/> since <paramref name="before"/>.
    /// </summary>
    /// <remarks>
    /// <see cref="InstallObservedStorage"/>'s observation identifies a record only by (context,
    /// backend name, operation) — never by the stored <c>FlowState.Kind</c> or the correlation
    /// key — so a <c>save</c>/<c>claim</c> the authentication stores (a client assertion's
    /// <c>jti</c>, a DPoP proof's <c>jti</c>, a nonce) legitimately make cannot be told apart, by
    /// this instrumentation, from one the GRANT store makes; both travel through the same
    /// <c>SaveFlowStateAsync</c>/<c>ClaimFlowStateAsync</c> delegates
    /// (<see cref="JtiReplayGuard.ConsultAsync"/> is the shared caller for both). A caller uses
    /// this assertion only for a shape that is refused before
    /// <see cref="JtiReplayGuard.ConsultAsync"/> is ever reached at all (a Basic-secret mismatch,
    /// no credentials, an absent-or-server-nonce-challenged DPoP proof, or a signature failure —
    /// none of which consults any <c>jti</c> store) — never for one that legitimately touches the
    /// authentication stores — so the EXACT expected count for every operation, including the
    /// authentication stores, is zero for these shapes.
    /// </remarks>
    /// <param name="before">The <see cref="StorageObservations"/> count captured before the request under test.</param>
    /// <param name="context">Describes the refusal under test, for the assertion failure message.</param>
    public void AssertNoFlowStateStoreOperationTouched(int before, string context)
    {
        var ops = StorageObservations.Skip(before).Select(entry => entry.Operation).ToList();
        Assert.IsEmpty(ops,
            $"{context} must touch no flow-state store operation of any kind (correlate/load/save/claim/delete/load-grant); observed: {string.Join(", ", ops)}.");
    }


    /// <summary>The host's role name (e.g. "verifier", "anchor", "resource-server").</summary>
    public string Name { get; }


    /// <summary>The wired authorization server. All HTTP and in-process dispatch routes through this.</summary>
    /// <remarks>
    /// Two-phase init: the host is constructed empty so the
    /// <see cref="AuthorizationServerIntegration"/> delegates can close over
    /// <see cref="Registrations"/> / <see cref="FlowStates"/> / etc. before the
    /// <see cref="EndpointServer"/> itself is built; <see cref="Build"/>
    /// assigns the wired server here.
    /// </remarks>
    public EndpointServer Server { get; internal set; } = null!;


    //Per-host stores. Every AuthorizationServer integration delegate that
    //carries cross-request state closes over these dictionaries — registration
    //routing, flow persistence, secondary indexes for token/handle lookups,
    //and the key material backing the cryptography resolvers.

    public ConcurrentDictionary<string, ClientRecord> Registrations { get; } = new();
    public ConcurrentDictionary<string, (FlowState State, int StepCount)> FlowStates { get; } = new();

    /// <summary>
    /// Backs <see cref="ServerIntegration.ClaimFlowStateAsync"/>: a claim on
    /// <c>(flowId, expectedStepCount)</c> succeeds for exactly one caller because
    /// <see cref="ConcurrentDictionary{TKey,TValue}.TryAdd"/> is itself the atomic operation —
    /// no read-modify-write over <see cref="FlowStates"/> is needed, so the claim never touches
    /// (and cannot race with) the state or step count <see cref="FlowStates"/> holds.
    /// </summary>
    public ConcurrentDictionary<(string FlowId, int StepCount), byte> ClaimedFlowSteps { get; } = new();
    public ConcurrentDictionary<string, string> RequestUriTokenIndex { get; } = new();
    public ConcurrentDictionary<string, string> CodeIndex { get; } = new();
    public ConcurrentDictionary<string, string> JtiIndex { get; } = new();
    public ConcurrentDictionary<string, string> AccessTokenIndex { get; } = new();
    public ConcurrentDictionary<string, string> RefreshTokenIndex { get; } = new();

    /// <summary>
    /// Backs <see cref="AuthorizationServerIntegration.LoadGrantFlowStatesAsync"/>: every grant
    /// key (a saved <see cref="ServerTokenIssuedState"/> or <see cref="ServerRefreshTokenIssuedState"/>'s
    /// own <c>GrantFlowId ?? FlowId</c>) maps to the flow ids saved under it. Maintained wherever
    /// <see cref="ServerIntegration.SaveFlowStateAsync"/> indexes one of those two state types, and
    /// cleaned on <see cref="ServerIntegration.DeleteFlowStateAsync"/>.
    /// </summary>
    public ConcurrentDictionary<string, ConcurrentDictionary<string, byte>> GrantIndex { get; } = new();
    public ConcurrentDictionary<KeyId, PrivateKeyMemory> SigningKeys { get; } = new();
    public ConcurrentDictionary<KeyId, PublicKeyMemory> VerificationKeys { get; } = new();
    public ConcurrentDictionary<KeyId, PrivateKeyMemory> DecryptionKeys { get; } = new();
    public ConcurrentDictionary<string, string> RegistrationAccessTokens { get; } = new();


    //HTTPS host state — populated when StartHttpHostAsync runs against this host.

    public global::Microsoft.AspNetCore.Builder.WebApplication? HttpHost { get; set; }
    public Uri? HttpBaseAddress { get; set; }
    public System.Net.Http.HttpClient? SharedHttpClient { get; set; }


    /// <summary>
    /// The <see cref="RegistrationObserver"/> subscription onto <see cref="Server"/>'s event stream,
    /// held so <see cref="TestHostShell.DisposeAsync"/> can release it alongside this host's other state.
    /// </summary>
    internal IDisposable? EventSubscription { get; set; }


    internal HostedAuthorizationServer(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        Name = name;
    }


    /// <summary>
    /// The grant key a saved grant record indexes under: its own <c>GrantFlowId</c> when set, its
    /// own <paramref name="flowId"/> otherwise.
    /// </summary>
    private static string GrantKeyOf(FlowState state, string flowId) =>
        state switch
        {
            ServerTokenIssuedState issued => issued.GrantFlowId ?? flowId,
            ServerRefreshTokenIssuedState refresh => refresh.GrantFlowId ?? flowId,
            _ => flowId
        };


    /// <summary>
    /// The grant key <see cref="FlowStates"/>'s own record for <paramref name="flowId"/> belongs
    /// to, computed the same way <see cref="GrantKeyOf"/> computes it for a save: its own
    /// <c>GrantFlowId</c> when the record carries one, <paramref name="flowId"/> itself otherwise
    /// or when no record is stored under it. Lets a test resolve a grant's key from any one flow
    /// id inside it without duplicating <see cref="GrantKeyOf"/>'s switch.
    /// </summary>
    /// <param name="flowId">A flow id belonging to the grant whose key is wanted.</param>
    public string ResolveGrantKey(string flowId) =>
        FlowStates.TryGetValue(flowId, out var entry) ? GrantKeyOf(entry.State, flowId) : flowId;


    /// <summary>
    /// Adds one record directly to what <see cref="AuthorizationServerIntegration.LoadGrantFlowStatesAsync"/>
    /// returns for <paramref name="grantFlowId"/>, without going through
    /// <see cref="ServerIntegration.SaveFlowStateAsync"/>. Lets a test simulate a store fault that
    /// returns another client's record under the same grant key.
    /// </summary>
    /// <param name="grantFlowId">The grant key the injected record should be returned under.</param>
    /// <param name="flowId">The injected record's own flow id.</param>
    /// <param name="state">The injected record.</param>
    /// <param name="stepCount">The injected record's step count.</param>
    public void InjectForeignGrantRecord(string grantFlowId, string flowId, FlowState state, int stepCount)
    {
        FlowStates[flowId] = (state, stepCount);
        _ = GrantIndex.GetOrAdd(grantFlowId, static _ => new ConcurrentDictionary<string, byte>())
            .TryAdd(flowId, 0);
    }


    /// <summary>
    /// Which requests <see cref="EnterGrantOrderGateAsync"/> can place into a grant, and which it
    /// cannot. The host only LOOKS UP an already-issued wire handle against its own indexes; it
    /// validates nothing, so a malformed or unknown handle here is UNORDERED exactly like a request
    /// shape this matrix does not cover at all — both reach the library exactly as they would with
    /// <see cref="IsOrderingRequestsPerGrant"/> off, for the library itself to answer.
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    ///   <item><description>
    ///   Token endpoint, <c>grant_type=refresh_token</c>: the wire <c>refresh_token</c> resolves
    ///   through <see cref="RefreshTokenIndex"/> to its record's flow id, whose grant key
    ///   (<see cref="ResolveGrantKey"/>) is the ordering key. An unknown token is unordered.
    ///   </description></item>
    ///   <item><description>
    ///   Token endpoint, <c>grant_type=authorization_code</c>: the wire <c>code</c> is hashed
    ///   EXACTLY as <c>AuthCodeEndpoints.ComputeDigestBase64Url</c> hashes it at issuance
    ///   (<see cref="HashAuthorizationCode"/>) and resolved through <see cref="CodeIndex"/> to the
    ///   flow id that IS the grant key before any token exists. An unknown code is unordered.
    ///   </description></item>
    ///   <item><description>
    ///   The revocation endpoint: a presented <c>token</c> known to <see cref="RefreshTokenIndex"/>
    ///   or <see cref="AccessTokenIndex"/> resolves to its grant; any other token is unordered.
    ///   </description></item>
    ///   <item><description>
    ///   Everything else is UNORDERED here: the pushed and direct authorization requests (pre-grant),
    ///   client credentials, the JWT bearer grant, the pre-authorized code grant, and a token
    ///   exchange (it creates its grant inside the library). An application that needs those
    ///   coordinated uses its own correlation or versioned writes.
    ///   </description></item>
    ///   <item><description>
    ///   The gate's key is (tenant, grant key) even though this host's stores ignore the tenant — a
    ///   request whose tenant this host never resolved
    ///   (<see cref="ExchangeContextExtensions.extension(ExchangeContext).TenantId"/> unset) is
    ///   unordered.
    ///   </description></item>
    ///   <item><description>
    ///   A resolved flow id whose record <see cref="FlowStates"/> does not hold is UNORDERED: the
    ///   record can be gone because a revocation deleted it and this host's
    ///   <see cref="ServerIntegration.DeleteFlowStateAsync"/> wiring cleans up
    ///   <see cref="RefreshTokenIndex"/> but not <see cref="AccessTokenIndex"/> on delete, or because
    ///   the request's own index read landed just before a concurrent deletion of that same record.
    ///   The library answers such a request exactly as it answers any other unordered one.
    ///   </description></item>
    ///   <item><description>
    ///   This lookup is a PRE-AUTHENTICATION read of an unauthenticated wire value: a holder of any
    ///   known handle — refresh token, authorization code, or access token — can queue behind the
    ///   grant it resolves to, whether or not that holder could authenticate as the grant's own
    ///   client. An application copying this host's gate bounds its own per-key queue depth and
    ///   wait; this test host bounds neither.
    ///   </description></item>
    /// </list>
    /// </remarks>
    /// <param name="request">The inbound request, before it reaches the library.</param>
    /// <param name="context">The per-request exchange context, carrying the resolved tenant.</param>
    internal (TenantId TenantId, string GrantKey)? ResolveOrderingKey(IncomingRequest request, ExchangeContext context)
    {
        if(context.TenantId is not { } tenantId)
        {
            return null;
        }

        bool isTokenEndpoint = string.Equals(request.Method, "POST", StringComparison.Ordinal)
            && request.Path.EndsWith("/" + TokenEndpointPathSuffix, StringComparison.Ordinal);
        if(isTokenEndpoint && request.Fields.TryGetValue(OAuthRequestParameterNames.GrantType, out string? grantType))
        {
            return grantType switch
            {
                _ when string.Equals(grantType, WellKnownGrantTypes.RefreshToken, StringComparison.Ordinal)
                    && request.Fields.TryGetValue(OAuthRequestParameterNames.RefreshToken, out string? refreshToken)
                    && RefreshTokenIndex.TryGetValue(refreshToken, out string? refreshFlowId)
                    && FlowStates.ContainsKey(refreshFlowId)
                    => (tenantId, ResolveGrantKey(refreshFlowId)),

                _ when string.Equals(grantType, WellKnownGrantTypes.AuthorizationCode, StringComparison.Ordinal)
                    && request.Fields.TryGetValue(OAuthRequestParameterNames.Code, out string? code)
                    && HashAuthorizationCode(code) is { } codeHash
                    && CodeIndex.TryGetValue(codeHash, out string? codeFlowId)
                    && FlowStates.ContainsKey(codeFlowId)
                    => (tenantId, ResolveGrantKey(codeFlowId)),

                _ => null
            };
        }

        bool isRevocationEndpoint = string.Equals(request.Method, "POST", StringComparison.Ordinal)
            && request.Path.EndsWith("/" + RevocationEndpointPathSuffix, StringComparison.Ordinal);
        if(isRevocationEndpoint && request.Fields.TryGetValue(OAuthRequestParameterNames.Token, out string? presentedToken))
        {
            return true switch
            {
                _ when RefreshTokenIndex.TryGetValue(presentedToken, out string? revokedRefreshFlowId)
                    && FlowStates.ContainsKey(revokedRefreshFlowId)
                    => (tenantId, ResolveGrantKey(revokedRefreshFlowId)),

                _ when AccessTokenIndex.TryGetValue(presentedToken, out string? revokedAccessFlowId)
                    && FlowStates.ContainsKey(revokedAccessFlowId)
                    => (tenantId, ResolveGrantKey(revokedAccessFlowId)),

                _ => null
            };
        }

        return null;
    }


    /// <summary>The token endpoint's fixture path suffix, shared with <see cref="TestHostShell.EndpointPathSuffix"/>.</summary>
    private static string TokenEndpointPathSuffix { get; } =
        TestHostShell.EndpointPathSuffix(WellKnownEndpointNames.AuthCodeToken)!;


    /// <summary>The revocation endpoint's fixture path suffix, shared with <see cref="TestHostShell.EndpointPathSuffix"/>.</summary>
    private static string RevocationEndpointPathSuffix { get; } =
        TestHostShell.EndpointPathSuffix(WellKnownEndpointNames.AuthCodeRevoke)!;


    /// <summary>
    /// Hashes <paramref name="code"/> exactly as <c>AuthCodeEndpoints.ComputeDigestBase64Url</c>
    /// hashes an authorization code at issuance and at redemption: a SHA-256 digest of its ASCII
    /// bytes, base64url-encoded, through this host's OWN wired
    /// <see cref="AuthorizationServerCodecs.Encoder"/> and
    /// <see cref="AuthorizationServerIntegration.MemoryPool"/> — never a fixture-private codec or
    /// pool — so a test that alters either on <see cref="Server"/> is hashed the same way the
    /// library itself would hash it. Returns <see langword="null"/>, without hashing, for a
    /// <paramref name="code"/> outside
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.11">RFC 6749 Appendix A.11</see>'s
    /// <c>code = 1*VSCHAR</c> grammar (<c>VSCHAR = %x20-7E</c>): the library applies this same
    /// precondition before ever hashing a presented code, because <see cref="System.Text.Encoding.ASCII"/>
    /// folds a byte outside plain ASCII rather than rejecting it.
    /// </summary>
    /// <param name="code">The wire authorization code to hash.</param>
    private string? HashAuthorizationCode(string code)
    {
        foreach(char c in code)
        {
            if(c is < (char)0x20 or > (char)0x7E)
            {
                return null;
            }
        }

        AuthorizationServerIntegration oauth = Server.OAuth();
        int byteCount = System.Text.Encoding.ASCII.GetByteCount(code);
        using IMemoryOwner<byte> owner = oauth.MemoryPool!.Rent(byteCount);
        Span<byte> codeBytes = owner.Memory.Span[..byteCount];
        _ = System.Text.Encoding.ASCII.GetBytes(code, codeBytes);

        using DigestValue digest = CryptographicKeyEvents.ComputeDigest(
            codeBytes, WellKnownHashAlgorithms.Sha256SizeBytes, CryptoTags.Sha256Digest, oauth.MemoryPool!);

        return oauth.Codecs.Encoder!(digest.AsReadOnlySpan());
    }


    /// <summary>
    /// The keyed FIFO queue backing <see cref="EnterGrantOrderGateAsync"/>: one entry per (tenant,
    /// grant key) currently enqueued or admitted, retired the instant nobody holds or waits for it.
    /// </summary>
    private ConcurrentDictionary<(TenantId TenantId, string GrantKey), GrantOrderGateEntry> GrantOrderGates { get; } = new();


    /// <summary>
    /// The monotonic counter every <see cref="GrantOrderObservation"/> reads its own sequence from.
    /// Written only under <see cref="GrantOrderEmissionLock"/>, so a plain increment (never
    /// <see cref="Interlocked.Increment(ref long)"/>) is sufficient.
    /// </summary>
    private long _grantOrderSequence;


    /// <summary>
    /// Serializes <see cref="EmitGrantOrderObservation"/>'s sequence allocation and channel write
    /// into one atomic step, so the channel's read order is always the sequence order. A distinct
    /// lock, never <c>lock(entry)</c>: an emission this lock protects may run while an entry's own
    /// lock is already held (<see cref="EnterGrantOrderGateAsync"/>'s Enqueued emission), so this
    /// lock is always taken INSIDE an entry's lock, never the reverse.
    /// </summary>
    private object GrantOrderEmissionLock { get; } = new();


    /// <summary>
    /// The Enqueued / Admitted / Released / Left / Retired observations
    /// <see cref="EnterGrantOrderGateAsync"/> and <see cref="RetireGrantOrderGateIfIdle"/> emit, in
    /// the order they occur. A test awaits <c>GrantOrderObservations.Reader.ReadAsync</c> — no
    /// polling.
    /// </summary>
    public Channel<GrantOrderObservation> GrantOrderObservations { get; } = Channel.CreateUnbounded<GrantOrderObservation>();


    /// <summary>
    /// Waits <paramref name="grantKey"/>'s FIFO turn for <paramref name="tenantId"/>, admits this
    /// caller, and returns a ticket whose <see cref="IAsyncDisposable.DisposeAsync"/> releases the
    /// next waiter — call it from a <c>finally</c> so an exception releases the gate exactly as a
    /// normal response does. Awaited with <paramref name="cancellationToken"/>: a cancelled waiter
    /// leaves the queue without ever being admitted, and its slot passes its turn on ONLY when the
    /// turn before it has passed, so the requests still queued behind it are never admitted ahead
    /// of whoever it was itself waiting for. The entry for the key is retired the instant nobody
    /// holds or waits for it, so two requests for the same key never find two separate gates.
    /// </summary>
    /// <param name="tenantId">The tenant half of the gate's key.</param>
    /// <param name="grantKey">The grant half of the gate's key, from <see cref="ResolveOrderingKey"/>.</param>
    /// <param name="cancellationToken">The presenting request's own cancellation token.</param>
    public async ValueTask<IAsyncDisposable> EnterGrantOrderGateAsync(
        TenantId tenantId, string grantKey, CancellationToken cancellationToken)
    {
        (TenantId, string) key = (tenantId, grantKey);
        TaskCompletionSource myTurn = new(TaskCreationOptions.RunContinuationsAsynchronously);
        GrantOrderGateEntry entry;
        Task waitFor;
        while(true)
        {
            entry = GrantOrderGates.GetOrAdd(key, static _ => new GrantOrderGateEntry());
            lock(entry)
            {
                if(entry.IsRetired)
                {
                    continue;
                }

                entry.Waiters++;
                waitFor = entry.Tail;
                entry.Tail = myTurn.Task;

                //Taken inside the entry lock, never the reverse: this observation's sequence is
                //therefore this request's own chain position, exactly as entry.Tail was just set.
                EmitGrantOrderObservation(GrantOrderEventKind.Enqueued, tenantId, grantKey);
            }

            break;
        }

        try
        {
            await waitFor.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch(OperationCanceledException)
        {
            //This waiter leaves without ever being admitted. Its own turn (myTurn) is not resolved
            //here directly — it is chained onto waitFor's own completion, so whoever this waiter
            //was itself chained after (waitFor) must complete FIRST, and only then does myTurn
            //complete and the next FIFO waiter proceed. A waiter admitted while an earlier holder
            //still holds its turn is exactly the corruption this chaining prevents.
            _ = waitFor.ContinueWith(
                static (_, state) => ((TaskCompletionSource)state!).TrySetResult(),
                myTurn,
                CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);

            RetireGrantOrderGateIfIdle(key, entry);
            EmitGrantOrderObservation(GrantOrderEventKind.Left, tenantId, grantKey);

            throw;
        }

        EmitGrantOrderObservation(GrantOrderEventKind.Admitted, tenantId, grantKey);

        return new GrantOrderGateTicket(this, key, entry, myTurn);
    }


    /// <summary>
    /// Whether a per-grant ordering gate entry currently exists for (<paramref name="tenantId"/>,
    /// <paramref name="grantKey"/>) — a test's way of confirming an idle entry was retired rather
    /// than left behind.
    /// </summary>
    /// <param name="tenantId">The tenant half of the gate's key.</param>
    /// <param name="grantKey">The grant half of the gate's key.</param>
    public bool HasGrantOrderGateEntry(TenantId tenantId, string grantKey) =>
        GrantOrderGates.ContainsKey((tenantId, grantKey));


    /// <summary>
    /// Writes one gate observation. The next sequence number is allocated and the channel write
    /// performed under <see cref="GrantOrderEmissionLock"/> as a single atomic step, so the
    /// channel's read order is always the sequence order across every key.
    /// </summary>
    /// <param name="kind">Which point of the gate this observation reports.</param>
    /// <param name="tenantId">The tenant half of the gate's key.</param>
    /// <param name="grantKey">The grant half of the gate's key.</param>
    private void EmitGrantOrderObservation(GrantOrderEventKind kind, TenantId tenantId, string grantKey)
    {
        lock(GrantOrderEmissionLock)
        {
            long sequence = ++_grantOrderSequence;
            _ = GrantOrderObservations.Writer.TryWrite(new GrantOrderObservation(kind, tenantId, grantKey, sequence));
        }
    }


    /// <summary>
    /// Decrements <paramref name="entry"/>'s waiter count and, when it reaches zero, atomically
    /// retires the entry so the next arrival for <paramref name="key"/> starts a fresh gate rather
    /// than joining a chain nothing will ever advance, and emits
    /// <see cref="GrantOrderEventKind.Retired"/>. <see cref="GrantOrderGateEntry.Waiters"/> is
    /// changed only under this entry's own lock by every participant currently enqueued or
    /// admitted, so a count of zero means nobody holds or waits for it — a straggling arrival that
    /// fetched this same entry just before the removal is caught by
    /// <see cref="EnterGrantOrderGateAsync"/>'s own <c>IsRetired</c> re-fetch loop.
    /// </summary>
    /// <param name="key">The (tenant, grant key) pair this entry is filed under.</param>
    /// <param name="entry">The entry this caller was enqueued on or admitted from.</param>
    private void RetireGrantOrderGateIfIdle((TenantId, string) key, GrantOrderGateEntry entry)
    {
        lock(entry)
        {
            entry.Waiters--;
            if(entry.Waiters == 0)
            {
                entry.IsRetired = true;
                if(GrantOrderGates.TryRemove(new KeyValuePair<(TenantId, string), GrantOrderGateEntry>(key, entry)))
                {
                    EmitGrantOrderObservation(GrantOrderEventKind.Retired, key.Item1, key.Item2);
                }
            }
        }
    }


    /// <summary>
    /// One <see cref="EnterGrantOrderGateAsync"/> key's FIFO chain. Every property is read and
    /// written only under <c>lock(this)</c>.
    /// </summary>
    private sealed class GrantOrderGateEntry
    {
        /// <summary>
        /// The most recently enqueued waiter's own completion signal, so the next arrival awaits
        /// it. A settable property, not a naked field, because it is mutable chain state written
        /// only under this entry's own lock.
        /// </summary>
        public Task Tail { get; set; } = Task.CompletedTask;

        /// <summary>
        /// The count of participants currently enqueued or admitted for this key. A settable
        /// property, not a naked field, because it is mutable chain state written only under this
        /// entry's own lock.
        /// </summary>
        public int Waiters { get; set; }

        /// <summary>
        /// Whether a release already removed this entry from <see cref="GrantOrderGates"/>, so a
        /// straggling arrival that fetched this SAME entry just before the removal knows to fetch a
        /// fresh one instead of joining a chain nothing will ever advance. A settable property, not
        /// a naked field, because it is mutable chain state written only under this entry's own
        /// lock.
        /// </summary>
        public bool IsRetired { get; set; }
    }


    /// <summary>
    /// The disposable ticket <see cref="EnterGrantOrderGateAsync"/> returns: releases exactly once,
    /// idempotently, so a caller may safely dispose it from both a normal path and a <c>finally</c>.
    /// </summary>
    /// <param name="host">The host whose <see cref="GrantOrderObservations"/> this ticket's release reports to.</param>
    /// <param name="key">The (tenant, grant key) pair this ticket was admitted under.</param>
    /// <param name="entry">The FIFO entry this ticket was admitted from.</param>
    /// <param name="myTurn">This ticket's own completion signal, resolved on release so the next waiter proceeds.</param>
    private sealed class GrantOrderGateTicket(
        HostedAuthorizationServer host,
        (TenantId, string) key,
        GrantOrderGateEntry entry,
        TaskCompletionSource myTurn): IAsyncDisposable
    {
        /// <summary>
        /// 0 until released. A field, not a property: <see cref="Interlocked.Exchange(ref int, int)"/>
        /// requires a genuine <see langword="ref"/>-addressable storage location.
        /// </summary>
        private int _isReleased;


        /// <summary>
        /// Emits <see cref="GrantOrderEventKind.Released"/>, resolves this ticket's own completion
        /// signal so the next FIFO waiter for its key proceeds, and retires its entry when nobody
        /// holds or waits for it any longer. Idempotent: a second call does nothing.
        /// </summary>
        public ValueTask DisposeAsync()
        {
            if(Interlocked.Exchange(ref _isReleased, 1) == 0)
            {
                host.EmitGrantOrderObservation(GrantOrderEventKind.Released, key.Item1, key.Item2);
                _ = myTurn.TrySetResult();
                host.RetireGrantOrderGateIfIdle(key, entry);
            }

            return ValueTask.CompletedTask;
        }
    }


    /// <summary>
    /// Constructs a fully wired <see cref="HostedAuthorizationServer"/> whose
    /// <see cref="Server"/> integration delegates close over the new host's
    /// own dictionaries. Every host built by this method is independent —
    /// flow states, registrations, and key material live exclusively on the
    /// returned instance.
    /// </summary>
    /// <param name="name">Host role name; used for diagnostics.</param>
    /// <param name="timeProvider">Time provider for all timestamps.</param>
    /// <param name="subjectClaims">
    /// Shared (shell-level) subject claim store. The
    /// <see cref="AuthorizationServerIntegration.ResolveOidcClaimsAsync"/>
    /// delegate reads from this dictionary so claim seeding stays at the
    /// orchestrator level rather than being host-private.
    /// </param>
    /// <param name="resolveIssuerKey">
    /// Trust-anchor lookup for credential issuer verification. Shared by all
    /// hosts built from the same shell so issuer trust is a single source of
    /// truth.
    /// </param>
    /// <param name="vpValidator">VP token validator (HAIP 1.0 SD-JWT rules by default).</param>
    /// <param name="mdocSeams">Optional mdoc VP verification seams; <see langword="null"/> uses the shipped defaults.</param>
    /// <param name="sdCwtSeams">Optional SD-CWT VP verification seams; <see langword="null"/> uses the shipped defaults.</param>
    /// <param name="saltReuseSeam">Optional commitment/salt reuse detector shared across presentations; <see langword="null"/> disables the check.</param>
    /// <param name="timings">Optional timing policy for issued tokens and objects; <see langword="null"/> uses the shipped defaults.</param>
    /// <param name="resolveDidVerificationKey">
    /// SIOPv2 §11.1 DID resolution seam for Self-Issued ID Tokens of the Decentralized
    /// Identifier Subject Syntax Type. Shared from the shell so the DID trust map is a single
    /// source of truth, mirroring <paramref name="resolveIssuerKey"/>. When
    /// <see langword="null"/> the SIOP validator fails closed on a DID subject.
    /// </param>
    /// <param name="resolveVerifiedStatusListToken">
    /// Optional resolver that returns an already-verified status list token for a credential's
    /// <c>status</c> claim. <see langword="null"/> uses the shipped default resolution.
    /// </param>
    /// <param name="parseX5c">
    /// Optional parser for a <c>dc+sd-jwt</c> issuer JWS's <c>x5c</c> header, feeding the <c>aki</c>
    /// arm of <paramref name="resolveTrustedAuthorityEvidence"/>. <see langword="null"/> when the
    /// host's SD-JWT credentials carry no certificate chain.
    /// </param>
    /// <param name="resolveTrustedAuthorityEvidence">
    /// Optional OID4VP 1.0 §6.1.1 trust-evidence resolver for <c>dc+sd-jwt</c> credentials, wired to
    /// e.g. <see cref="TrustedAuthorityEvidenceResolution.Build"/>. <see langword="null"/> surfaces no
    /// evidence, so a <c>trusted_authorities</c> constraint on a <c>dc+sd-jwt</c> query fails closed.
    /// </param>
    /// <param name="credentialStatusPolicy">
    /// Optional relying-party verdict over a presentation's surfaced credential-status outcomes, threaded to
    /// both <see cref="HaipOid4VpVerifierExecutor.Create"/> and <see cref="SiopVerifierExecutor.Register"/>.
    /// <see langword="null"/> uses <see cref="Verifiable.Core.StatusList.CredentialStatusPolicies.Surface"/>
    /// (the shipped default).
    /// </param>
    /// <param name="statusListFreshnessPolicy">
    /// Optional Section 8.3 step 4.b freshness policy, threaded to both seats. <see langword="null"/> skips
    /// the check (the shipped default).
    /// </param>
    /// <param name="statusListCachingBounds">
    /// Optional Section 11.5 refresh-interval bounds, threaded to both seats. <see langword="null"/> leaves
    /// the resolved token's <c>ttl</c> unclamped (the shipped default).
    /// </param>
    /// <param name="unsupportedStatusMechanisms">
    /// What both seats do with a credential whose <c>status</c> claim names only status mechanisms the
    /// library does not evaluate. Defaults to
    /// <see cref="Verifiable.Core.StatusList.UnsupportedStatusMechanismDisposition.Refuse"/>, the shipped
    /// default.
    /// </param>
    /// <param name="vpTokenCredentialQueryId">
    /// The <see cref="CredentialQueryId"/> the SIOPv2 §12 combined-response seat publishes its
    /// <c>vp_token</c> under, threaded to <see cref="SiopVerifierExecutor.Register"/>.
    /// <see langword="null"/> leaves <see cref="SiopVerifierExecutor.SiopCombinedResponseCredentialQueryId"/>
    /// as the default.
    /// </param>
    public static HostedAuthorizationServer Build(
        string name,
        TimeProvider timeProvider,
        Dictionary<string, OidcClaims> subjectClaims,
        ResolveIssuerKeyDelegate resolveIssuerKey,
        ClaimIssuer<ValidationContext> vpValidator,
        MdocVpVerificationSeams? mdocSeams = null,
        SdCwtVpVerificationSeams? sdCwtSeams = null,
        CommitmentReuseDetectionSeam? saltReuseSeam = null,
        TimingPolicy? timings = null,
        Verifiable.OAuth.Siop.ResolveDidVerificationKeyDelegate? resolveDidVerificationKey = null,
        Verifiable.Core.StatusList.ResolveVerifiedStatusListTokenDelegate? resolveVerifiedStatusListToken = null,
        Verifiable.Cryptography.Pki.ParseX5cDelegate? parseX5c = null,
        ResolveTrustedAuthorityEvidenceDelegate? resolveTrustedAuthorityEvidence = null,
        Verifiable.Core.StatusList.CredentialStatusPolicy? credentialStatusPolicy = null,
        Verifiable.Core.StatusList.StatusListFreshnessPolicy? statusListFreshnessPolicy = null,
        Verifiable.Core.StatusList.StatusListCachingBounds? statusListCachingBounds = null,
        Verifiable.Core.StatusList.UnsupportedStatusMechanismDisposition unsupportedStatusMechanisms =
            Verifiable.Core.StatusList.UnsupportedStatusMechanismDisposition.Refuse,
        CredentialQueryId? vpTokenCredentialQueryId = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(subjectClaims);
        ArgumentNullException.ThrowIfNull(resolveIssuerKey);
        ArgumentNullException.ThrowIfNull(vpValidator);

        HostedAuthorizationServer host = new(name);

        AuthorizationServerIntegration integration = new()
        {
            MemoryPool = BaseMemoryPool.Shared,

            ExtractTenantIdAsync = (ctx, ct) =>
                ValueTask.FromResult(ctx.TenantId),

            ResolveOidcClaimsAsync = (subject, scope, tenantId, ctx, ct) =>
                ValueTask.FromResult(
                    subjectClaims.TryGetValue(subject, out OidcClaims? claims)
                        ? claims : null),

            LoadClientRegistrationAsync = (tenantId, ctx, ct) =>
            {
                lock(host.RegistrationGate)
                {

                    return ValueTask.FromResult<IRegistrationRecord?>(
                        host.Registrations.TryGetValue(tenantId, out ClientRecord? reg) ? reg : null);
                }
            },
            ClientRegistrationStore = host,

            DeleteFlowStateAsync = (tenantId, flowId, ctx, ct) =>
            {
                //Replay and reuse revoke the claimed live refresh record and its token index.
                //Retired rotation records retain their indexes for reuse detection.
                if(host.FlowStates.TryRemove(flowId, out var removed))
                {
                    if(removed.State is ServerRefreshTokenIssuedState removedRefresh)
                    {
                        _ = host.RefreshTokenIndex.TryRemove(removedRefresh.RefreshToken, out _);
                    }

                    if(removed.State is ServerTokenIssuedState or ServerRefreshTokenIssuedState
                        && host.GrantIndex.TryGetValue(GrantKeyOf(removed.State, flowId), out var grantFlowIds))
                    {
                        _ = grantFlowIds.TryRemove(flowId, out _);
                    }
                }

                //A real backend ties a claim entry's lifetime to its flow record's; this
                //in-memory fixture only ever adds to ClaimedFlowSteps (see its own /// above), so
                //a deleted flow's claim entries are evicted here to bound the dictionary's growth
                //across a long-running test process.
                foreach((string FlowId, int StepCount) key in host.ClaimedFlowSteps.Keys)
                {
                    if(string.Equals(key.FlowId, flowId, StringComparison.Ordinal))
                    {
                        _ = host.ClaimedFlowSteps.TryRemove(key, out _);
                    }
                }

                return ValueTask.CompletedTask;
            },

            SaveFlowStateAsync = (tenantId, flowId, state, stepCount, ctx, ct) =>
            {
                host.FlowStates[flowId] = (state, stepCount);

                //Build secondary indexes from the state so that continuing
                //endpoints can resolve external handles back to the flowId.
                //This mirrors SQL indexed columns on the same row.
                //Single-tenant fixture: tenantId is accepted to match the delegate
                //signature but not used in the keying. Multi-tenant tests would key
                //by (tenantId, flowId) compounds.
                switch(state)
                {
                    case ParRequestReceivedState par:
                    {
                        string token = TestHostShell.ExtractRequestUriToken(par.RequestUri);
                        if(!string.IsNullOrWhiteSpace(token))
                        {
                            host.RequestUriTokenIndex[token] = flowId;
                        }

                        break;
                    }
                    case ServerCodeIssuedState codeIssued:
                    {
                        host.CodeIndex[codeIssued.CodeHash] = flowId;
                        break;
                    }
                    case VerifierParReceivedState vpPar:
                    {
                        //The OID4VP PAR endpoint stamps the per-flow handle directly on
                        //the state. No URL parsing — the handle is first-class.
                        if(!string.IsNullOrWhiteSpace(vpPar.ParHandle))
                        {
                            host.RequestUriTokenIndex[vpPar.ParHandle] = flowId;
                        }

                        break;
                    }
                    case SiopRequestPreparedState siopPrepared:
                    {
                        //The SIOP preparation endpoint stamps the per-flow request handle
                        //directly on the state. Index it so the response endpoint's state echo
                        //resolves back to the flowId through ResolveCorrelationKeyAsync — the
                        //same RequestUriTokenIndex path the OID4VP handle uses.
                        if(!string.IsNullOrWhiteSpace(siopPrepared.RequestHandle))
                        {
                            host.RequestUriTokenIndex[siopPrepared.RequestHandle] = flowId;
                        }

                        break;
                    }
                    case SiopRequestObjectServedState siopServed:
                    {
                        //The by-reference §9 path advances past SiopRequestPreparedState to the
                        //served state. Keep the per-flow handle indexed so both the request_uri GET
                        //(CorrelationKey) and the subsequent id_token POST (state echo) resolve back
                        //to the flowId — the parallel of VerifierJarServedState carrying ParHandle.
                        if(!string.IsNullOrWhiteSpace(siopServed.RequestHandle))
                        {
                            host.RequestUriTokenIndex[siopServed.RequestHandle] = flowId;
                        }

                        break;
                    }
                    case VcalmExchangePendingState exchangePending:
                    {
                        //VCALM §3.6: index the exchange id -> flowId so the §3.6.5 participate POST's
                        //{localExchangeId} resolves back to the flow id (ResolveCorrelationKeyAsync) and
                        //the stateless §3.6.4 / §3.6.6 reads resolve it (ResolveVcalmExchangeFlowIdAsync).
                        //The same RequestUriTokenIndex path the OID4VP / SIOP handles use.
                        if(!string.IsNullOrWhiteSpace(exchangePending.ExchangeId))
                        {
                            host.RequestUriTokenIndex[exchangePending.ExchangeId] = flowId;
                        }

                        break;
                    }
                    case VcalmExchangeActiveState exchangeActive:
                    {
                        //Keep the index live across the §3.6.5 advance so a subsequent participate POST
                        //and a §3.6.6 read still resolve to the flow id.
                        if(!string.IsNullOrWhiteSpace(exchangeActive.ExchangeId))
                        {
                            host.RequestUriTokenIndex[exchangeActive.ExchangeId] = flowId;
                        }

                        break;
                    }
                    case VcalmExchangeCompleteState exchangeComplete:
                    {
                        if(!string.IsNullOrWhiteSpace(exchangeComplete.ExchangeId))
                        {
                            host.RequestUriTokenIndex[exchangeComplete.ExchangeId] = flowId;
                        }

                        break;
                    }
                    case VcalmExchangeInvalidState { ExchangeId.Length: > 0 } exchangeInvalid:
                    {
                        host.RequestUriTokenIndex[exchangeInvalid.ExchangeId] = flowId;
                        break;
                    }
                    case JtiSeenState jti:
                    {
                        //RFC 9449 §11.1 replay defense. The index key is the state's own
                        //JtiSeenState.CorrelationKey (JtiReplayGuard.CorrelationKey composed
                        //once, never re-derived here) so the guard's post-save self-check
                        //resolves exactly what was just saved. Presence in the dictionary is
                        //the replay signal.
                        host.JtiIndex[jti.CorrelationKey] = flowId;
                        break;
                    }
                    case ServerTokenIssuedState issuedGrant:
                    {
                        //Capture access_token → flowId so test code can recover the
                        //Confirmation binding for a known access token. The
                        //IssuedTokenSet carries the live JWS strings on the request
                        //context (they are never persisted onto state).
                        string? accessToken = ctx.IssuedTokens?.AccessToken;
                        if(!string.IsNullOrEmpty(accessToken))
                        {
                            host.AccessTokenIndex[accessToken] = flowId;
                        }

                        _ = host.GrantIndex.GetOrAdd(GrantKeyOf(issuedGrant, flowId), static _ => new())
                            .TryAdd(flowId, 0);

                        break;
                    }
                    case ServerRefreshTokenIssuedState refresh:
                    {
                        //Refresh tokens index by their wire string. Rotation
                        //replaces the entry on every refresh-grant call.
                        host.RefreshTokenIndex[refresh.RefreshToken] = flowId;

                        _ = host.GrantIndex.GetOrAdd(GrantKeyOf(refresh, flowId), static _ => new())
                            .TryAdd(flowId, 0);

                        break;
                    }
                    case VerifierJarServedState:
                    case SiopResponseReceivedState:
                    case SiopEncryptedResponseReceivedState:
                    case SiopCombinedResponseReceivedState:
                    case SelfIssuedAuthenticationVerifiedState:
                    case Verifiable.OAuth.Oid4Vp.Wallet.States.DcqlEvaluated:
                    case Verifiable.OAuth.Oid4Vp.Wallet.States.JarParsed:
                    case Verifiable.OAuth.Oid4Vp.States.PresentationVerifiedState:
                    case VerifierWalletPostReceivedState:
                    case VerifierWalletErrorReceivedState:
                    case VerifierResponseReceivedState:
                    case VerifierUnencryptedResponseReceivedState:
                    case Verifiable.OAuth.AuthCode.States.TokenReceivedState:
                    case Verifiable.OAuth.AuthCode.States.PkceGeneratedState:
                    case Verifiable.OAuth.AuthCode.States.ParCompletedState:
                    case SiopVerifierFlowFailedState:
                    case VerifierFlowFailedState:
                    case Verifiable.OAuth.AuthCode.States.ParRequestReadyState:
                    case Verifiable.OAuth.AuthCode.States.AuthorizationCodeReceivedState:
                    case Verifiable.OAuth.Oid4Vp.Wallet.States.WalletNonceSent:
                    case Verifiable.OAuth.Oid4Vp.Wallet.States.ResponseSent:
                    case Verifiable.OAuth.Oid4Vp.Wallet.States.RequestUriReceived:
                    case Verifiable.OAuth.Oid4Vp.Wallet.States.PresentationBuilt:
                    case Verifiable.OAuth.Oid4Vp.Wallet.States.BrowserRedirectIssued:
                    case Verifiable.OAuth.Oid4Vp.States.ResponseReceivedState:
                    case Verifiable.OAuth.Oid4Vp.States.ParCompletedState:
                    case Verifiable.OAuth.Oid4Vp.States.JarServedState:
                    case Verifiable.OAuth.Oid4Vp.States.JarReadyState:
                    case ServerFlowFailedState:
                    {
                        //Carries no externally-visible correlation handle this secondary-index build
                        //keys on; an explicit no-op arm preserving this switch's original silent
                        //fall-through for every other flow state.
                        break;
                    }
                }

                return ValueTask.CompletedTask;
            },

            //The (FlowState?) cast is load-bearing: ValueTask.FromResult<TResult> infers TResult from
            //the ternary's own natural type, and a bare null branch here has no type of its own to
            //unify with the other branch's (FlowState, int) — the cast is what makes it (FlowState?, int).
            LoadFlowStateAsync = (tenantId, flowId, ctx, ct) =>
                ValueTask.FromResult(
                    host.FlowStates.TryGetValue(flowId, out var entry)
                        ? (entry.State, entry.StepCount)
                        : (null, 0)),

            //Reads every flow id GrantIndex has ever recorded under this grant key whose record
            //still exists — a rotated-out or deleted flow id simply misses the TryGetValue below
            //and is left out, exactly as a deleted row would drop out of a SQL grant-key query.
            LoadGrantFlowStatesAsync = (tenantId, grantFlowId, ctx, ct) =>
            {
                List<(string FlowId, FlowState State, int StepCount)> records = [];
                if(host.GrantIndex.TryGetValue(grantFlowId, out var flowIds))
                {
                    foreach(string candidateFlowId in flowIds.Keys)
                    {
                        if(host.FlowStates.TryGetValue(candidateFlowId, out var entry))
                        {
                            records.Add((candidateFlowId, entry.State, entry.StepCount));
                        }
                    }
                }

                return ValueTask.FromResult<IReadOnlyList<(string FlowId, FlowState State, int StepCount)>>(records);
            },

            //The atomic claim selects one caller. Checking the stored version afterward also
            //rejects a stale request whose flow was deleted and whose claim entry was evicted.
            ClaimFlowStateAsync = (tenantId, flowId, expectedStepCount, ctx, ct) =>
                ValueTask.FromResult(
                    host.ClaimedFlowSteps.TryAdd((flowId, expectedStepCount), 0)
                    && host.FlowStates.TryGetValue(flowId, out var entry)
                    && entry.StepCount == expectedStepCount),

            ResolveCorrelationKeyAsync = (tenantId, flowKind, externalHandle, ctx, ct) =>
            {
                //DPoP replay lookup is keyed specifically by flow kind: the AS
                //pre-composes "{issuer}:{jti}" and asks under FlowKind.JtiReplay.
                //Other flows fall through to the general secondary indexes.
                if(flowKind == FlowKind.JtiReplay)
                {
                    return ValueTask.FromResult<string?>(
                        host.JtiIndex.TryGetValue(externalHandle, out string? jtiFlowId)
                            ? jtiFlowId : null);
                }

                //Refresh-token grant — the endpoint Kind is FlowKind.RefreshToken
                //and the external handle is the opaque refresh-token string.
                if(flowKind == FlowKind.RefreshToken)
                {
                    return ValueTask.FromResult<string?>(
                        host.RefreshTokenIndex.TryGetValue(externalHandle, out string? refreshFlowId)
                            ? refreshFlowId : null);
                }

                //Try each secondary index. The application knows which handle
                //types exist — this mirrors a SQL query with OR conditions.
                if(host.RequestUriTokenIndex.TryGetValue(externalHandle, out string? flowId))
                {
                    return ValueTask.FromResult<string?>(flowId);
                }

                if(host.CodeIndex.TryGetValue(externalHandle, out flowId))
                {
                    return ValueTask.FromResult<string?>(flowId);
                }

                //Not found in any index.
                return ValueTask.FromResult<string?>(null);
            },

            //URL composition for the discovery document and any token claims that
            //embed endpoint URLs. The library never composes paths; it asks here.
            //Test fixture serves a /connect/{segment}/<suffix> path family rooted
            //at the registered issuer, the request issuer, or this host's bound listener
            //for a dynamically registered client. The listener address is host-owned.
            //Deployments may use subdomains, header routing, or another scheme.
            ResolveEndpointUriAsync = (endpointKey, registration, ctx, ct) =>
            {
                Uri? baseUri = ((ClientRecord)registration).IssuerUri ?? ctx.Issuer ?? host.HttpBaseAddress;
                if(baseUri is null)
                {
                    return ValueTask.FromResult<Uri?>(null);
                }

                string authority = baseUri.GetLeftPart(UriPartial.Authority);
                string segment = registration.TenantId.Value;

                //Per-flow OID4VP request_uri: incorporate the per-flow handle the
                //library placed on the context. The URL shape is the deployment's
                //choice; this fixture uses /connect/{segment}/request/{handle}.
                if(string.Equals(endpointKey, Oid4VpEndpointKeys.RequestUri, StringComparison.Ordinal))
                {
                    string? handle = ctx.ParHandle;
                    if(string.IsNullOrWhiteSpace(handle))
                    {
                        return ValueTask.FromResult<Uri?>(null);
                    }

                    return ValueTask.FromResult<Uri?>(
                        new Uri($"{authority}/connect/{segment}/request/{handle}"));
                }

                //Per-flow SIOPv2 §9 request_uri — the same per-flow shape as the OID4VP request_uri,
                //incorporating the SIOP request handle the preparation endpoint placed on the
                //context. This fixture uses /connect/{segment}/siop_request_object/{handle}.
                if(string.Equals(endpointKey, SiopVerifierEndpointKeys.RequestUri, StringComparison.Ordinal))
                {
                    string? handle = ctx.SiopRequestHandle;
                    if(string.IsNullOrWhiteSpace(handle))
                    {
                        return ValueTask.FromResult<Uri?>(null);
                    }

                    return ValueTask.FromResult<Uri?>(
                        new Uri($"{authority}/connect/{segment}/siop_request_object/{handle}"));
                }

                //VCALM §3.6 vcapi participation URL — the per-exchange URL the §3.6.4 protocols response
                //and the §3.6.3 create Location header carry. The exchange engine stamped the exchange
                //id on the context before asking, so the fixture appends it to the /exchanges collection
                //path: /connect/{segment}/vcalm/exchanges/{exchangeId}.
                if(string.Equals(endpointKey, WellKnownVcalmEndpointNames.VcalmParticipateInExchange, StringComparison.Ordinal)
                    && ctx.VcalmExchangeId is { } vcalmExchangeId)
                {
                    return ValueTask.FromResult<Uri?>(
                        new Uri($"{authority}/connect/{segment}/vcalm/exchanges/{vcalmExchangeId}"));
                }

                //RFC 9728 §3: the protected-resource metadata path is formed by
                //INSERTION between host and the identifier's path, not by the
                //fixture's /connect/{segment}/<suffix> scheme — delegate to
                //ComposeEndpointPath, which owns that special case.
                if(string.Equals(endpointKey, WellKnownEndpointNames.ProtectedResourceMetadata, StringComparison.Ordinal))
                {
                    return ValueTask.FromResult<Uri?>(
                        new Uri($"{authority}{TestHostShell.ComposeEndpointPath(endpointKey, segment)}"));
                }

                //OID4VCI §12.2.2 Credential Issuer Metadata — same INSERTION shape as the
                //RFC 9728 protected-resource metadata above; ComposeEndpointPath owns the case.
                if(string.Equals(endpointKey, WellKnownEndpointNames.Oid4VciCredentialIssuerMetadata, StringComparison.Ordinal))
                {
                    return ValueTask.FromResult<Uri?>(
                        new Uri($"{authority}{TestHostShell.ComposeEndpointPath(endpointKey, segment)}"));
                }

                //RFC 8414 §3 Authorization Server Metadata — the §3 default well-known
                //location formed by the same INSERTION shape between host and the issuer's
                //path component; ComposeEndpointPath owns the case.
                if(string.Equals(endpointKey, WellKnownEndpointNames.MetadataOAuthAuthorizationServer, StringComparison.Ordinal))
                {
                    return ValueTask.FromResult<Uri?>(
                        new Uri($"{authority}{TestHostShell.ComposeEndpointPath(endpointKey, segment)}"));
                }

                //The library asks for endpoint URLs solely through this delegate; the
                //path-suffix dispatch lives in a private static helper
                //(EndpointPathSuffix) shared with ComposeEndpointPath /
                //ComposeEndpointUri — fixture code that needs concrete URIs
                //synchronously calls the same source-of-truth.
                string? suffix = TestHostShell.EndpointPathSuffix(endpointKey);
                if(suffix is null)
                {
                    return ValueTask.FromResult<Uri?>(null);
                }

                return ValueTask.FromResult<Uri?>(
                    new Uri($"{authority}/connect/{segment}/{suffix}"));
            },

            //Per-request policy resolution. The default dispatches on
            //ClientRecord.Profile across the three shipped profiles;
            //an unset Profile falls back to PolicyProfile.Fapi20
            //(FAPI 2.0 / HAIP-aligned).
            ResolvePolicyAsync = (registration, ctx, ct) =>
                PolicyProfiles.DefaultResolvePolicyAsync((ClientRecord)registration, ctx, ct),

            //Per-request capability resolution reads the application's active grants.
            //The registration declares endpoint eligibility; a revoked grant removes
            //reachability through this resolver while preserving that declaration.
            //A tenant without persisted history uses its request-derived eligibility.
            //An empty deletion tombstone keeps an overlapping stored request unreachable.
            //Inspection and public-subject identity use their library defaults.
            ResolveCapabilitiesAsync = (registration, _, _) =>
            {
                lock(host.RegistrationGate)
                {
                    bool hasCurrent = host.Registrations.TryGetValue(registration.TenantId, out ClientRecord? current);
                    IReadOnlySet<CapabilityIdentifier> granted = hasCurrent switch
                    {
                        true => string.Equals(current!.ClientId, registration.ClientId, StringComparison.Ordinal)
                            && host.GrantedCapabilities.TryGetValue(registration.TenantId, out ImmutableHashSet<CapabilityIdentifier>? capabilities)
                                ? capabilities : ImmutableHashSet<CapabilityIdentifier>.Empty,
                        false => host.GrantedCapabilities.ContainsKey(registration.TenantId)
                            ? ImmutableHashSet<CapabilityIdentifier>.Empty : registration.AllowedCapabilities
                    };

                    return ValueTask.FromResult(granted);
                }
            },
            InspectAsync = DefaultInspector.NoOpAsync,
            ResolveSubjectIdentifierAsync = DefaultSubjectIdentifierResolver.PublicAsync,
            GenerateIdentifierAsync = DefaultIdentifierGenerator.For(timeProvider, TestEntropy.NewCounterStream(), BaseMemoryPool.Shared),

            //Dynamic registration delegates. The parser uses JsonDocument to
            //read the few fields the canonical test exercises directly into a
            //ClientMetadata record; no default ParseClientMetadataServerDelegate
            //is shipped, so production deployments wire their own full JSON
            //layer instead.
            ParseClientMetadataAsync = (body, ct) =>
            {
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
                Uri? clientUri = root.TryGetProperty("client_uri", out JsonElement uri) && uri.GetString() is string uriText
                    ? new Uri(uriText) : null;
                string? scope = root.TryGetProperty("scope", out JsonElement sc) ? sc.GetString() : null;
                ClientAuthenticationMethod? authMethod = null;
                if(root.TryGetProperty("token_endpoint_auth_method", out JsonElement am)
                    && am.GetString() is string authMethodStr
                    && ClientAuthenticationMethodNames.TryParse(authMethodStr, out ClientAuthenticationMethod parsed))
                {
                    authMethod = parsed;
                }

                //RFC 9396 §10/§14.5 authorization_details_types — an absent member leaves this
                //null (the client registered no restriction); a present array becomes the allowlist.
                List<string>? authorizationDetailsTypes = null;
                if(root.TryGetProperty(
                    AuthorizationDetailsParameterNames.AuthorizationDetailsTypes, out JsonElement adt))
                {
                    authorizationDetailsTypes = [];
                    foreach(JsonElement el in adt.EnumerateArray())
                    {
                        if(el.GetString() is string typeValue)
                        {
                            authorizationDetailsTypes.Add(typeValue);
                        }
                    }
                }

                return ValueTask.FromResult(new ClientMetadata
                {
                    ClientId = root.TryGetProperty("client_id", out JsonElement id) ? id.GetString() : null,
                    RedirectUris = redirectUris,
                    ClientName = clientName,
                    ClientUri = clientUri,
                    Scope = scope,
                    TokenEndpointAuthMethod = authMethod,
                    AuthorizationDetailsTypes = authorizationDetailsTypes,
                    LogoUri = root.TryGetProperty("logo_uri", out JsonElement parsedLogoUri) ? new Uri(parsedLogoUri.GetString()!) : null,
                    TokenEndpointAuthSigningAlg = root.TryGetProperty("token_endpoint_auth_signing_alg", out JsonElement parsedTokenEndpointAuthSigningAlg) ? parsedTokenEndpointAuthSigningAlg.GetString() : null,
                    JwksUri = root.TryGetProperty("jwks_uri", out JsonElement parsedJwksUri) ? new Uri(parsedJwksUri.GetString()!) : null,
                    Jwks = root.TryGetProperty("jwks", out JsonElement parsedJwks) ? parsedJwks.GetRawText() : null,
                    SoftwareStatement = root.TryGetProperty("software_statement", out JsonElement parsedSoftwareStatement) ? parsedSoftwareStatement.GetString() : null,
                    ApplicationType = root.TryGetProperty("application_type", out JsonElement parsedApplicationType) ? parsedApplicationType.GetString() : null,
                    IdTokenSignedResponseAlg = root.TryGetProperty("id_token_signed_response_alg", out JsonElement parsedIdTokenSignedResponseAlg) ? parsedIdTokenSignedResponseAlg.GetString() : null,
                    RequestObjectSigningAlg = root.TryGetProperty("request_object_signing_alg", out JsonElement parsedRequestObjectSigningAlg) ? parsedRequestObjectSigningAlg.GetString() : null,
                    RequestObjectEncryptionAlg = root.TryGetProperty("request_object_encryption_alg", out JsonElement parsedRequestObjectEncryptionAlg) ? parsedRequestObjectEncryptionAlg.GetString() : null,
                    BackchannelLogoutUri = root.TryGetProperty("backchannel_logout_uri", out JsonElement parsedBackchannelLogoutUri) ? new Uri(parsedBackchannelLogoutUri.GetString()!) : null,
                    FrontchannelLogoutUri = root.TryGetProperty("frontchannel_logout_uri", out JsonElement parsedFrontchannelLogoutUri) ? new Uri(parsedFrontchannelLogoutUri.GetString()!) : null,
                    BackchannelLogoutSessionRequired = root.TryGetProperty("backchannel_logout_session_required", out JsonElement parsedBackchannelLogoutSessionRequired) && parsedBackchannelLogoutSessionRequired.GetBoolean(),
                    FrontchannelLogoutSessionRequired = root.TryGetProperty("frontchannel_logout_session_required", out JsonElement parsedFrontchannelLogoutSessionRequired) && parsedFrontchannelLogoutSessionRequired.GetBoolean(),
                    GrantTypes = root.TryGetProperty("grant_types", out JsonElement parsedGrantTypes) ? parsedGrantTypes.EnumerateArray().Select(value => GrantTypeNames.TryParse(value.GetString()!, out GrantType parsed) ? parsed : throw new InvalidOperationException("Invalid grant type.")).ToArray() : [],
                    ResponseTypes = root.TryGetProperty("response_types", out JsonElement parsedResponseTypes) ? parsedResponseTypes.EnumerateArray().Select(value => ResponseTypeNames.TryParse(value.GetString()!, out ResponseType parsed) ? parsed : throw new InvalidOperationException("Invalid response type.")).ToArray() : [],
                    PostLogoutRedirectUris = root.TryGetProperty("post_logout_redirect_uris", out JsonElement parsedPostLogoutRedirectUris) ? parsedPostLogoutRedirectUris.EnumerateArray().Select(value => new Uri(value.GetString()!)).ToArray() : [],
                    AuthorizationGrantProfilesSupported = root.TryGetProperty("authorization_grant_profiles_supported", out JsonElement parsedAuthorizationGrantProfilesSupported) ? parsedAuthorizationGrantProfilesSupported.EnumerateArray().Select(value => value.GetString()!).ToArray() : null
                });
            },

            //Bearer-token validation for RFC 7592 management calls. Test wiring stores the
            //plaintext token (a production deployment would store a hash instead) but the
            //comparison itself uses the library's constant-time helper — an ordinal compare
            //exits on the first differing character, letting a network attacker recover the
            //token incrementally by timing.
            ValidateRegistrationAccessTokenAsync = (tenantId, clientId, presented, _, _) =>
            {
                lock(host.RegistrationGate)
                {

                    return ValueTask.FromResult(
                        host.Registrations.TryGetValue(tenantId, out ClientRecord? registered)
                        && string.Equals(registered.ClientId, clientId, StringComparison.Ordinal)
                        && host.RegistrationAccessTokens.TryGetValue(clientId, out string? stored)
                        && FixedTimeComparison.AreEqual(stored, presented));
                }
            }
        };

        AuthorizationServerCryptography cryptography = new()
        {
            SigningKeyResolver = (keyId, tenantId, ctx, ct) =>
                ValueTask.FromResult(
                    host.SigningKeys.TryGetValue(keyId, out PrivateKeyMemory? key)
                        ? key : null),

            VerificationKeyResolver = (keyId, tenantId, ctx, ct) =>
                ValueTask.FromResult(
                    host.VerificationKeys.TryGetValue(keyId, out PublicKeyMemory? key)
                        ? key : null),

            DecryptionKeyResolver = (keyId, ctx, ct) =>
                ValueTask.FromResult(
                    host.DecryptionKeys.TryGetValue(keyId, out PrivateKeyMemory? key)
                        ? key : null),

            BuildJwksDocumentAsync = (registration, ctx, ct) =>
            {
                List<JsonWebKey> jwks = [];

                //OAuth /jwks publishes OAuth/OIDC token-signing keys and JAR
                //signing keys. Federation entity-signing keys live behind
                //the federation EC's own jwks claim (served at
                // /.well-known/openid-federation), so skip them here. A real
                //deployment with separate JWKS endpoints would scope
                //similarly per usage-context.
                foreach(KeyValuePair<KeyUsageContext, SigningKeySet> entry in registration.SigningKeys)
                {
                    if(entry.Key == KeyUsageContext.FederationEntitySignature)
                    {
                        continue;
                    }

                    foreach(KeyId publishedKeyId in entry.Value.PublishedKeys)
                    {
                        if(!host.VerificationKeys.TryGetValue(publishedKeyId, out PublicKeyMemory? publicKey))
                        {
                            continue;
                        }

                        JsonWebKey jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
                            publicKey.Tag.Get<CryptoAlgorithm>(),
                            publicKey.Tag.Get<Purpose>(),
                            publicKey.AsReadOnlySpan(),
                            TestSetup.Base64UrlEncoder);
                        jwk.Kid = publishedKeyId.Value;
                        jwk.Use = WellKnownJwkValues.UseSig;

                        jwks.Add(jwk);
                    }
                }

                return ValueTask.FromResult(new JwksDocument { Keys = [.. jwks] });
            }
        };

        AuthorizationServerCodecs codecs = new()
        {
            Encoder = TestSetup.Base64UrlEncoder,
            Decoder = TestSetup.Base64UrlDecoder,
            ComputeDigest = MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,

            //The library signs access tokens via the registered token producers.
            //TestHostShell supplies the two JSON serialization delegates; tests
            //that need non-standard signing assign their own producers per test.
            JwtHeaderSerializer = static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)header,
                TestSetup.DefaultSerializationOptions),
            JwtPayloadSerializer = static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)payload,
                TestSetup.DefaultSerializationOptions),

            //Deserializers required by JAR-bearing matchers (AuthCode JAR-PAR
            //and AuthCode JAR-by-value direct Authorize). Other in-dispatch
            //consumers may follow; the slots are wired here once.
            JwtHeaderDeserializer = static bytes =>
                JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                    bytes, TestSetup.DefaultSerializationOptions)
                ?? throw new FormatException("Header JSON parsed to null."),
            JwtPayloadDeserializer = static bytes =>
                JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                    bytes, TestSetup.DefaultSerializationOptions)
                ?? throw new FormatException("Payload JSON parsed to null."),

            //OID4VP §5.9.3 redirect_uri prefix path serialises the JAR
            //inline; the dcql_query and client_metadata claims need their
            //own wire-form serialisers since that path bypasses the
            //executor's delegate-injected ones.
            DcqlQuerySerializer = static query =>
                JsonSerializer.Serialize(query, TestSetup.DefaultSerializationOptions),
            ClientMetadataSerializer = static metadata =>
                JsonSerializer.Serialize(metadata, TestSetup.DefaultSerializationOptions)
        };

        //The shared action executor holds the handlers of every stateful flow this host runs.
        //The HAIP executor seeds it with the OID4VP verifier handlers (SignJar, DecryptResponse);
        //SiopVerifierExecutor.Register then contributes the SIOPv2 ValidateSelfIssuedIdToken handler
        //onto the SAME instance, so a single registry serves both flows.
        OAuthActionExecutor executor = HaipOid4VpVerifierExecutor.Create(
            headerSerializer: header => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)header,
                TestSetup.DefaultSerializationOptions),
            payloadSerializer: payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)payload,
                TestSetup.DefaultSerializationOptions),
            dcqlQuerySerializer: q =>
                JsonSerializer.Serialize(q, TestSetup.DefaultSerializationOptions),
            clientMetadataSerializer: m =>
                JsonSerializer.Serialize(m, TestSetup.DefaultSerializationOptions),
            decoder: TestSetup.Base64UrlDecoder,
            encoder: TestSetup.Base64UrlEncoder,
            resolveIssuerKey: resolveIssuerKey,
            parseSdJwtToken: static s => SdJwtSerializer.ParseToken(
                s, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared, TestSalts.TestSaltTag),
            computeSdJwtHashInput: static t => SdJwtSerializer.GetSdJwtForHashing(
                t, TestSetup.Base64UrlEncoder),
            computeDigest: MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            vpValidators: BuildVpValidators(vpValidator, mdocSeams, sdCwtSeams, timeProvider),
            keyAgreementDecryptDelegate:
                BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
            keyDerivationDelegate: ConcatKdf.DefaultKeyDerivationDelegate,
            aeadDecryptDelegate: BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
            pool: BaseMemoryPool.Shared,
            keyAgreementEncryptDelegate:
                BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
            aeadEncryptDelegate: BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            tagToEpkCrvConverter: CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            mdocSeams: mdocSeams,
            sdCwtSeams: sdCwtSeams,
            saltReuseSeam: saltReuseSeam,
            //Wire the Core disclosure engine behind the verifier's assessment seam:
            //run DcqlDisclosure over the disclosed claims and read graph.Satisfied
            //(DCQL satisfaction) and disclosed-minus-selected (over-disclosure).
            assessDisclosure: static async (assessContext, cancellationToken) =>
            {
                DcqlDisclosureResult<IReadOnlyDictionary<CredentialPath, object?>> result =
                    await DcqlDisclosure.ComputeStrategyAsync(
                        assessContext.CredentialQuery,
                        assessContext.Credential.Disclosed,
                        //Supply the verified trust evidence and the credential's own declared
                        //type so DcqlEvaluator can enforce trusted_authorities and
                        //meta.vct_values fail-closed; with neither, a credential with no
                        //evidence at all does not match (OpenID for Verifiable Presentations
                        //1.0 §6.4.2 MUST NOT).
                        DisclosedClaimsDcqlAdapter.CreateMetadataExtractor(
                            assessContext.CredentialQuery.Format!,
                            credentialType: assessContext.Credential.CredentialType,
                            additionalTypes: assessContext.Credential.AdditionalTypes,
                            trustedAuthorityEvidence: assessContext.Credential.TrustedAuthorityEvidence),
                        DisclosedClaimsDcqlAdapter.ClaimExtractor,
                        new FakeTimeProvider(TestClock.CanonicalEpoch),
                        cancellationToken: cancellationToken).ConfigureAwait(false);

                //Satisfaction is result.Satisfied — the DCQL match verdict (format / type /
                //trusted_authorities / claim values) ANDed with lattice disclosure adequacy.
                //Over-disclosure is any SELECTIVELY disclosable path the engine did not select as
                //appropriate. OpenID for Verifiable Presentations 1.0 Section 6.4 governs only
                //what the wallet chooses to send, so a claim the credential carries
                //unconditionally — vct, iss, any claim the Issuer left plain — is never counted.
                DisclosureStrategyGraph<IReadOnlyDictionary<CredentialPath, object?>> graph = result.Graph;
                bool satisfied = result.Satisfied;
                bool overDisclosed = false;
                if(graph.Decisions.Count > 0)
                {
                    IReadOnlySet<CredentialPath> selected = graph.Decisions[0].SelectedPaths;
                    foreach(CredentialPath disclosedPath in assessContext.Credential.Disclosed.Keys)
                    {
                        if(!selected.Contains(disclosedPath)
                            && !assessContext.Credential.UnconditionallyDisclosed.Contains(disclosedPath))
                        {
                            overDisclosed = true;
                            break;
                        }
                    }
                }
                else
                {
                    //No decision -> the query's required claims were not met.
                    foreach(CredentialPath disclosedPath in assessContext.Credential.Disclosed.Keys)
                    {
                        if(!assessContext.Credential.UnconditionallyDisclosed.Contains(disclosedPath))
                        {
                            overDisclosed = true;
                            break;
                        }
                    }
                }

                return new Oid4VpDisclosureAssessment
                {
                    Satisfied = satisfied,
                    OverDisclosed = overDisclosed
                };
            },
            resolveVerifiedStatusListToken: resolveVerifiedStatusListToken,
            parseX5c: parseX5c,
            resolveTrustedAuthorityEvidence: resolveTrustedAuthorityEvidence,
            credentialStatusPolicy: credentialStatusPolicy,
            statusListFreshnessPolicy: statusListFreshnessPolicy,
            statusListCachingBounds: statusListCachingBounds,
            unsupportedStatusMechanisms: unsupportedStatusMechanisms);

        //SIOPv2 RP flow's §11.1 ValidateSelfIssuedIdToken handler AND the §12 combined-response
        //ValidateCombinedSiopResponse handler, contributed onto the shared executor alongside the
        //OID4VP handlers above. The §12 handler reuses the SAME vp_token-verification seams the
        //OID4VP executor was wired with — the shared issuer-key lookup, the SD-JWT parser, the
        //hash-input function, and the digest function — so combined responses validate their
        //vp_token through the identical SdJwtVpTokenVerification pipeline.
        SiopVerifierExecutor.Register(
            executor,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            headerSerializer: header => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)header,
                TestSetup.DefaultSerializationOptions),
            payloadSerializer: payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)payload,
                TestSetup.DefaultSerializationOptions),
            pool: BaseMemoryPool.Shared,
            timeProvider: timeProvider,
            resolveDidVerificationKey: resolveDidVerificationKey,
            resolveIssuerKey: resolveIssuerKey,
            parseSdJwtToken: static s => SdJwtSerializer.ParseToken(
                s, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared, TestSalts.TestSaltTag),
            computeSdJwtHashInput: static t => SdJwtSerializer.GetSdJwtForHashing(
                t, TestSetup.Base64UrlEncoder),
            computeDigest: MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            saltReuseSeam: saltReuseSeam,
            resolveVerifiedStatusListToken: resolveVerifiedStatusListToken,
            credentialStatusPolicy: credentialStatusPolicy,
            statusListFreshnessPolicy: statusListFreshnessPolicy,
            statusListCachingBounds: statusListCachingBounds,
            unsupportedStatusMechanisms: unsupportedStatusMechanisms,
            vpTokenCredentialQueryId: vpTokenCredentialQueryId);

        //The OAuth family configuration the endpoints read — cryptography, codecs,
        //timings, token producers, the claim issuer, and the OAuth action executor —
        //lives on the family integration, reached through server.OAuth().
        integration.Cryptography = cryptography;
        integration.Codecs = codecs;
        integration.Timings = timings ?? TimingPolicy.Default;
        integration.TokenProducers = new TokenProducerSet(
        [
            TokenProducer.Rfc9068AccessToken,
            TokenProducer.Oidc10IdToken
        ]);
        integration.ClaimIssuer = ContributionProfiles.StandardClaimIssuer(timeProvider);

        //The shared executor (built above) holds the OID4VP verifier handlers
        //(SignJar, DecryptResponse) AND the SIOPv2 ValidateSelfIssuedIdToken handler.
        //Auth Code flows do not produce actions and ignore the executor.
        integration.ActionExecutor = executor;

        host.Server = new EndpointServer
        {
            Integration = integration,
            TimeProvider = timeProvider,

            //The fold pipeline is configured up-front via the neutral ServerConfiguration
            //(endpoint builders only). TestHostShell wires the library-shipped endpoint
            //builders; tests that need a different builder set apply a new configuration
            //via Server.ApplyConfiguration before dispatching.
            Configuration = new Verifiable.Server.ServerConfiguration
            {
                EndpointBuilders = new EndpointBuilderSet(
                [
                    AuthCodeEndpoints.Builder,
                    Oid4VpEndpoints.Builder,
                    MetadataEndpoints.Builder,
                    RegistrationEndpoints.Builder,
                    UserInfoEndpoints.Builder,
                    Verifiable.OAuth.Federation.FederationEndpoints.Builder,
                    Verifiable.OAuth.AuthZen.AuthZenEndpoints.Builder,
                    Verifiable.OAuth.Ssf.SsfTransmitterEndpoints.Builder,
                    Verifiable.OAuth.ProtectedResource.ProtectedResourceMetadataEndpoints.Builder,
                    Verifiable.OAuth.Logout.GlobalTokenRevocationEndpoints.Builder,
                    Verifiable.OAuth.Logout.EndSessionEndpoints.Builder,
                    Verifiable.OAuth.Oid4Vci.Oid4VciEndpoints.Builder,
                    SiopVerifierEndpoints.Builder,
                    Verifiable.Vcalm.VcalmVerifierEndpoints.Builder,
                    Verifiable.Vcalm.VcalmIssuerEndpoints.Builder,
                    Verifiable.Vcalm.VcalmStatusEndpoints.Builder,
                    Verifiable.Vcalm.VcalmHolderEndpoints.Builder,
                    Verifiable.Vcalm.Exchange.VcalmExchangeEndpoints.Builder,
                    Verifiable.Vcalm.VcalmWorkflowEndpoints.Builder,
                    Verifiable.Vcalm.VcalmInteractionEndpoints.Builder
                ])
            },

            //The neutral host drives the PDA's effectful loop through this delegate.
            //It bridges the host-generic PdaAction to the OAuth executor, which owns
            //the OID4VP / SIOP action handlers. Auth Code flows produce no actions.
            ActionExecutor = (action, ctx, ct) =>
                ctx.RequestServer!.OAuth().ActionExecutor!.ExecuteAsync((OAuthAction)action, ctx, ct)
        };

        //Register the OAuth family integration so endpoints reach it via server.OAuth().
        host.Server.AddIntegration(integration);

        //Register the W3C VCALM family integration so the VCALM issuer / verifier endpoints reach
        //their seams via server.Vcalm(). Tests configure the VCALM seams (parsers, Data Integrity
        //verification / issuance, challenge and credential stores, request-size cap) on this
        //instance through app.Server.Vcalm() after construction.
        host.Server.AddIntegration(new Verifiable.Vcalm.VcalmIntegration());


        host.Server.Validate();

        //Subscribe to apply capability signals to the state consulted by dispatch.
        host.EventSubscription = host.Server.Events.Subscribe(new RegistrationObserver(host));

        return host;
    }


    /// <summary>
    /// Builds the format-keyed VP-token validator map the OID4VP executor
    /// dispatches through. SD-JWT is always present; the mso_mdoc validator
    /// (HAIP 1.0 mdoc rules) is added only when the host was built with mdoc
    /// verification seams, mirroring a deployment that opts into mdoc support.
    /// </summary>
    private static Dictionary<string, ClaimIssuer<ValidationContext>> BuildVpValidators(
        ClaimIssuer<ValidationContext> sdJwtValidator,
        MdocVpVerificationSeams? mdocSeams,
        SdCwtVpVerificationSeams? sdCwtSeams,
        TimeProvider timeProvider)
    {
        var validators = new Dictionary<string, ClaimIssuer<ValidationContext>>(StringComparer.Ordinal)
        {
            [DcqlCredentialFormats.SdJwt] = sdJwtValidator
        };

        if(mdocSeams is not null)
        {
            validators[DcqlCredentialFormats.MsoMdoc] = new ClaimIssuer<ValidationContext>(
                "vp-haip10-mdoc-verifier",
                ValidationProfiles.Haip10MdocRules(),
                timeProvider);
        }

        if(sdCwtSeams is not null)
        {
            validators[DcqlCredentialFormats.SdCwt] = new ClaimIssuer<ValidationContext>(
                "vp-haip10-sd-cwt-verifier",
                ValidationProfiles.Haip10SdCwtRules(),
                timeProvider);
        }

        return validators;
    }


    /// <summary>The lock shared by registration persistence, routing loads and capability effects.</summary>
    private object RegistrationGate { get; } = new();


    /// <summary>The active grants and empty deletion tombstones that distinguish persisted tenants from request-derived registrations.</summary>
    private Dictionary<string, ImmutableHashSet<CapabilityIdentifier>> GrantedCapabilities { get; } = [];


    /// <summary>A deterministic pre-commit create hook for storage-failure wire assertions.</summary>
    public Func<ClientRecord, CancellationToken, ValueTask>? BeforeRegistrationCreateAsync { get; set; }


    /// <summary>A deterministic pre-commit update hook so concurrent requests can share one loaded revision.</summary>
    public Func<ClientRecord, CancellationToken, ValueTask>? BeforeRegistrationUpdateAsync { get; set; }


    /// <summary>Atomically commits the registration, both routing indexes and its test credential.</summary>
    public async ValueTask CreateAsync(ClientRecord registration, RegistrationAccessToken accessToken,
        ExchangeContext context, CancellationToken cancellationToken)
    {
        if(BeforeRegistrationCreateAsync is { } before)
        {
            await before(registration, cancellationToken).ConfigureAwait(false);
        }

        lock(RegistrationGate)
        {
            if(Registrations.ContainsKey(registration.TenantId) || Registrations.ContainsKey(registration.ClientId))
            {
                throw new InvalidOperationException("The registration already exists.");
            }

            Registrations[registration.TenantId] = registration;
            Registrations[registration.ClientId] = registration;
            GrantedCapabilities[registration.TenantId] = registration.AllowedCapabilities;
            RegistrationAccessTokens[registration.ClientId] = accessToken.Value;
        }
    }


    /// <summary>Atomically refuses stale revisions or commits the next record through both routing indexes.</summary>
    public async ValueTask<bool> TryUpdateAsync(ClientRecord registration, long expectedRevision,
        ExchangeContext context, CancellationToken cancellationToken)
    {
        if(BeforeRegistrationUpdateAsync is { } before)
        {
            await before(registration, cancellationToken).ConfigureAwait(false);
        }

        lock(RegistrationGate)
        {
            if(!Registrations.TryGetValue(registration.TenantId, out ClientRecord? current)
                || !string.Equals(current.ClientId, registration.ClientId, StringComparison.Ordinal)
                || current.Revision != expectedRevision
                || registration.Revision != checked(expectedRevision + 1))
            {

                return false;
            }

            Registrations[registration.TenantId] = registration;
            Registrations[registration.ClientId] = registration;
            ImmutableHashSet<CapabilityIdentifier> granted = GrantedCapabilities.GetValueOrDefault(registration.TenantId)
                ?? ImmutableHashSet<CapabilityIdentifier>.Empty;
            GrantedCapabilities[registration.TenantId] = granted.Intersect(registration.AllowedCapabilities)
                .Union(registration.AllowedCapabilities.Except(current.AllowedCapabilities));

            return true;
        }
    }


    /// <summary>A deterministic pre-commit deletion hook for overlapping management requests.</summary>
    public Func<ClientRecord, CancellationToken, ValueTask>? BeforeRegistrationDeleteAsync { get; set; }


    /// <summary>Removes only the expected identity and revision and returns the final record under the index lock.</summary>
    public async ValueTask<ClientRecord?> DeleteAsync(ClientRecord registration, long expectedRevision,
        ExchangeContext context, CancellationToken cancellationToken)
    {
        if(BeforeRegistrationDeleteAsync is { } before)
        {
            await before(registration, cancellationToken).ConfigureAwait(false);
        }

        lock(RegistrationGate)
        {
            if(!Registrations.TryGetValue(registration.TenantId, out ClientRecord? current)
                || !string.Equals(current.ClientId, registration.ClientId, StringComparison.Ordinal)
                || current.Revision != expectedRevision)
            {

                return null;
            }

            _ = checked(current.Revision + 1);
            _ = Registrations.TryRemove(registration.TenantId, out _);
            _ = Registrations.TryRemove(registration.ClientId, out _);
            _ = RegistrationAccessTokens.TryRemove(registration.ClientId, out _);
            GrantedCapabilities[registration.TenantId] = ImmutableHashSet<CapabilityIdentifier>.Empty;

            return current;
        }
    }


    /// <summary>Commits fixture registration data and then awaits its immutable notification.</summary>
    public async Task RegisterClientAsync(ClientRecord registration, RegistrationAccessToken accessToken, ExchangeContext context, CancellationToken cancellationToken = default)
    {
        await CreateAsync(registration, accessToken, context, cancellationToken).ConfigureAwait(false);
        await Server.RegisterClientAsync(registration, context).ConfigureAwait(false);
    }


    /// <summary>Commits a fixture metadata or key replacement before awaiting its next revision.</summary>
    public async Task<ClientRecord> UpdateClientAsync(ClientRecord previous, ClientRecord current, ExchangeContext context, CancellationToken cancellationToken = default)
    {
        current = current with { Revision = checked(previous.Revision + 1) };
        bool isCommitted = await TryUpdateAsync(current, previous.Revision, context, cancellationToken).ConfigureAwait(false);
        if(!isCommitted)
        {
            throw new InvalidOperationException("The fixture registration revision changed.");
        }

        await Server.UpdateClientAsync(previous, current, context).ConfigureAwait(false);

        return current;
    }


    /// <summary>Commits fixture deletion before awaiting the final registration projection.</summary>
    public async Task DeregisterClientAsync(ClientRecord registration, string reason, ExchangeContext context, CancellationToken cancellationToken = default)
    {
        ClientRecord deleted = await DeleteAsync(registration, registration.Revision, context, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("The fixture registration revision changed.");
        await Server.DeregisterClientAsync(deleted, reason, context).ConfigureAwait(false);
    }


    /// <summary>Applies grant and revoke signals to synchronized registration and resolver state.</summary>
    private void ApplyCapability(ClientRegistrationEvent value)
    {
        lock(RegistrationGate)
        {
            if(!Registrations.TryGetValue(value.TenantId, out ClientRecord? current)
                || !string.Equals(current.ClientId, value.ClientId, StringComparison.Ordinal)
                || current.Revision != value.Revision)
            {

                return;
            }

            ImmutableHashSet<CapabilityIdentifier> granted = GrantedCapabilities.GetValueOrDefault(value.TenantId)
                ?? ImmutableHashSet<CapabilityIdentifier>.Empty;
            ImmutableHashSet<CapabilityIdentifier> capabilities = value switch
            {
                CapabilityGranted grant => granted.Add(grant.Capability),
                CapabilityRevoked revoke => granted.Remove(revoke.Capability),
                _ => granted
            };
            if(ReferenceEquals(capabilities, granted))
            {

                return;
            }

            ClientRecord updated = current with
            {
                Revision = checked(current.Revision + 1),
                AllowedCapabilities = value switch
                {
                    CapabilityGranted grant => current.AllowedCapabilities.Add(grant.Capability),
                    _ => current.AllowedCapabilities
                }
            };
            Registrations[updated.TenantId] = updated;
            Registrations[updated.ClientId] = updated;
            GrantedCapabilities[updated.TenantId] = capabilities;
        }
    }


    /// <summary>The application's effect handler for capability grant and revoke notifications.</summary>
    private sealed class RegistrationObserver(HostedAuthorizationServer host): IObserver<ClientRegistrationEvent>
    {
        /// <summary>Applies capability signals; registration persistence belongs to the required store.</summary>
        public void OnNext(ClientRegistrationEvent value)
        {
            host.ApplyCapability(value);
        }


        /// <summary>The stream does not terminate on an optional observer's exception.</summary>
        public void OnError(Exception error)
        {
        }


        /// <summary>The stream has the lifetime of its owning integration.</summary>
        public void OnCompleted()
        {
        }
    }
}
