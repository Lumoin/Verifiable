using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.Server.States;
using Verifiable.OAuth.Siop;
using Verifiable.OAuth.Siop.Server.States;
using Verifiable.OAuth.Siop.Wallet;
using Verifiable.Server;
using Verifiable.Server.Routing;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Proves the <see cref="JtiReplayGuard"/> store self-check over the guard directly: a store
/// wired for other correlation kinds but that cannot resolve what it recorded under
/// <see cref="FlowKind.JtiReplay"/> is treated as unavailable under every policy, a store that
/// answers a foreign flow id is as defective as one that answers nothing, a correctly wired store
/// records a first use and refuses the repeat, <see cref="JtiReplayPolicy.Disabled"/> never touches
/// the store, and an oversized <c>jti</c> is refused before any store access. These exercise
/// RFC 7523 §3 rule 7's "maintaining the set of used jti values" and RFC 9449 §11.1's memory-exhaustion
/// rule over the guard, independently of any wire path.
/// </summary>
[TestClass]
internal sealed class JtiReplayGuardStoreProofTests
{
    /// <summary>The tenant every consultation in this class is scoped to.</summary>
    private static TenantId Tenant { get; } = new("tenant-a");

    /// <summary>The issuer a <c>jti</c> is presented under in the single-issuer cases.</summary>
    private const string Issuer = "https://issuer.example.com/";

    /// <summary>A second issuer, distinct from <see cref="Issuer"/>, for the issuer-isolation case.</summary>
    private const string OtherIssuer = "https://other-issuer.example.com/";

    /// <summary>A representative <c>jti</c> value within the guard's length bound.</summary>
    private const string Jti = "a-unique-jti-value";

    /// <summary>The per-test fake clock; anchored to the canonical epoch so timestamps are deterministic.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The ambient test context supplying the cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// RFC 7523 §3 rule 7: "The authorization server MAY ensure that JWTs are not replayed by
    /// maintaining the set of used "jti" values for the length of time for which the JWT would be
    /// considered valid based on the applicable "exp" instant." A store wired for other correlation
    /// kinds but that never resolves what it saved under <see cref="FlowKind.JtiReplay"/> cannot
    /// maintain that set; under <see cref="JtiReplayPolicy.Required"/> the guard fails closed with
    /// <see cref="JtiReplayOutcome.StoreUnavailable"/> rather than answer a silent first use.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523">RFC 7523, Section 3</see>.
    /// </summary>
    [TestMethod]
    public async Task HalfWiredStoreFailsClosedUnderRequired()
    {
        InMemoryJtiStore store = new(JtiStoreBehavior.NeverResolvesJtiReplay);
        using EndpointServer server = BuildServer(store);
        ExchangeContext context = BuildContext(JtiReplayPolicy.Required);

        JtiReplayOutcome outcome = await ConsultAsync(server, context, Issuer, Jti).ConfigureAwait(false);

        Assert.AreEqual(JtiReplayOutcome.StoreUnavailable, outcome,
            "RFC 7523 §3 rule 7: a store that cannot resolve what it recorded must fail closed under Required.");
        Assert.AreEqual(1, store.SaveCallCount,
            "The guard must attempt to record the first use before proving the store.");
    }


    /// <summary>
    /// RFC 7523 §3 rule 7: "The authorization server MAY ensure that JWTs are not replayed by
    /// maintaining the set of used "jti" values for the length of time for which the JWT would be
    /// considered valid based on the applicable "exp" instant." A wired store that cannot resolve what
    /// it recorded is neither "present" nor "absent" but defective; under
    /// <see cref="JtiReplayPolicy.OptionalIfStorePresent"/> — which tolerates a store's absence, not
    /// its malfunction — the guard answers <see cref="JtiReplayOutcome.StoreUnavailable"/> exactly as
    /// under Required. <see href="https://www.rfc-editor.org/rfc/rfc7523">RFC 7523, Section 3</see>.
    /// </summary>
    [TestMethod]
    public async Task HalfWiredStoreFailsClosedUnderOptionalIfStorePresent()
    {
        InMemoryJtiStore store = new(JtiStoreBehavior.NeverResolvesJtiReplay);
        using EndpointServer server = BuildServer(store);
        ExchangeContext context = BuildContext(JtiReplayPolicy.OptionalIfStorePresent);

        JtiReplayOutcome outcome = await ConsultAsync(server, context, Issuer, Jti).ConfigureAwait(false);

        Assert.AreEqual(JtiReplayOutcome.StoreUnavailable, outcome,
            "RFC 7523 §3 rule 7: OptionalIfStorePresent tolerates a store's absence, not its malfunction — a defective store fails closed.");
    }


    /// <summary>
    /// RFC 7523 §3 rule 7: "The authorization server MAY ensure that JWTs are not replayed by
    /// maintaining the set of used "jti" values for the length of time for which the JWT would be
    /// considered valid based on the applicable "exp" instant." The self-check compares the resolved
    /// value to the flow id just saved: a store that resolves a stale or foreign id has not maintained
    /// the set and is as defective as one that resolves nothing, so the guard answers
    /// <see cref="JtiReplayOutcome.StoreUnavailable"/> under both policies.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523">RFC 7523, Section 3</see>.
    /// </summary>
    [TestMethod]
    [DataRow(JtiReplayPolicy.Required)]
    [DataRow(JtiReplayPolicy.OptionalIfStorePresent)]
    public async Task StoreResolvingForeignFlowIdFailsClosed(JtiReplayPolicy policy)
    {
        InMemoryJtiStore store = new(JtiStoreBehavior.ResolvesForeignFlowId);
        using EndpointServer server = BuildServer(store);
        ExchangeContext context = BuildContext(policy);

        JtiReplayOutcome outcome = await ConsultAsync(server, context, Issuer, Jti).ConfigureAwait(false);

        Assert.AreEqual(JtiReplayOutcome.StoreUnavailable, outcome,
            "RFC 7523 §3 rule 7: equality with the saved flow id, not mere presence — a foreign resolved id fails the self-check.");
    }


    /// <summary>
    /// RFC 7523 §3 rule 7: "The authorization server MAY ensure that JWTs are not replayed by
    /// maintaining the set of used "jti" values for the length of time for which the JWT would be
    /// considered valid based on the applicable "exp" instant." A correctly wired store records the
    /// first consultation as <see cref="JtiReplayOutcome.FirstUse"/> and, on the same
    /// <c>(issuer, jti)</c>, refuses the second as <see cref="JtiReplayOutcome.Replayed"/>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523">RFC 7523, Section 3</see>.
    /// </summary>
    [TestMethod]
    public async Task CorrectStoreRecordsFirstUseThenRefusesReplay()
    {
        InMemoryJtiStore store = new(JtiStoreBehavior.ResolvesWhatItSaved);
        using EndpointServer server = BuildServer(store);
        ExchangeContext context = BuildContext(JtiReplayPolicy.Required);

        JtiReplayOutcome first = await ConsultAsync(server, context, Issuer, Jti).ConfigureAwait(false);
        JtiReplayOutcome second = await ConsultAsync(server, context, Issuer, Jti).ConfigureAwait(false);

        Assert.AreEqual(JtiReplayOutcome.FirstUse, first,
            "RFC 7523 §3 rule 7: the first use of a jti is accepted and recorded.");
        Assert.AreEqual(JtiReplayOutcome.Replayed, second,
            "RFC 7523 §3 rule 7: the same jti under the same issuer is refused as a replay.");
    }


    /// <summary>
    /// RFC 7523 §3 rule 7: "The authorization server MAY ensure that JWTs are not replayed by
    /// maintaining the set of used "jti" values for the length of time for which the JWT would be
    /// considered valid based on the applicable "exp" instant." The set is keyed by <c>(issuer, jti)</c>
    /// so independent issuers are isolated: the same <c>jti</c> value presented under a second issuer is
    /// a first use, not a false replay. <see href="https://www.rfc-editor.org/rfc/rfc7523">RFC 7523, Section 3</see>.
    /// </summary>
    [TestMethod]
    public async Task CorrectStoreIsolatesIssuers()
    {
        InMemoryJtiStore store = new(JtiStoreBehavior.ResolvesWhatItSaved);
        using EndpointServer server = BuildServer(store);
        ExchangeContext context = BuildContext(JtiReplayPolicy.Required);

        JtiReplayOutcome firstIssuer = await ConsultAsync(server, context, Issuer, Jti).ConfigureAwait(false);
        JtiReplayOutcome secondIssuer = await ConsultAsync(server, context, OtherIssuer, Jti).ConfigureAwait(false);

        Assert.AreEqual(JtiReplayOutcome.FirstUse, firstIssuer,
            "RFC 7523 §3 rule 7: the first issuer's jti is a first use.");
        Assert.AreEqual(JtiReplayOutcome.FirstUse, secondIssuer,
            "RFC 7523 §3 rule 7: the (issuer, jti) key isolates issuers — the same jti under another issuer is not a replay.");
    }


    /// <summary>
    /// RFC 7523 §3 rule 7: "The authorization server MAY ensure that JWTs are not replayed by
    /// maintaining the set of used "jti" values ...". <see cref="JtiReplayPolicy.Disabled"/> is the
    /// deployment that declines that MAY; the guard returns <see cref="JtiReplayOutcome.FirstUse"/>
    /// without a single read or write against the store.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523">RFC 7523, Section 3</see>.
    /// </summary>
    [TestMethod]
    public async Task DisabledPolicyNeverTouchesTheStore()
    {
        InMemoryJtiStore store = new(JtiStoreBehavior.ResolvesWhatItSaved);
        using EndpointServer server = BuildServer(store);
        ExchangeContext context = BuildContext(JtiReplayPolicy.Disabled);

        JtiReplayOutcome outcome = await ConsultAsync(server, context, Issuer, Jti).ConfigureAwait(false);

        Assert.AreEqual(JtiReplayOutcome.FirstUse, outcome,
            "RFC 7523 §3 rule 7: Disabled declines the MAY and proceeds.");
        Assert.AreEqual(0, store.ResolveCallCount,
            "Disabled must not read the store.");
        Assert.AreEqual(0, store.SaveCallCount,
            "Disabled must not write the store.");
    }


    /// <summary>
    /// RFC 9449 §11.1: "In order to guard against memory exhaustion attacks, a server that is tracking
    /// jti values should reject DPoP proof JWTs with unnecessarily large jti values or store only a hash
    /// thereof." A <c>jti</c> longer than <see cref="JtiReplayGuard.MaxJtiLength"/> is refused with
    /// <see cref="JtiReplayOutcome.Unacceptable"/> before any store is read or written, under every
    /// policy that consults the store at all.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449">RFC 9449, Section 11.1</see>.
    /// </summary>
    [TestMethod]
    [DataRow(JtiReplayPolicy.Required)]
    [DataRow(JtiReplayPolicy.OptionalIfStorePresent)]
    public async Task OversizedJtiIsUnacceptableBeforeAnyStoreAccess(JtiReplayPolicy policy)
    {
        InMemoryJtiStore store = new(JtiStoreBehavior.ResolvesWhatItSaved);
        using EndpointServer server = BuildServer(store);
        ExchangeContext context = BuildContext(policy);
        string oversizedJti = new('j', JtiReplayGuard.MaxJtiLength + 1);

        JtiReplayOutcome outcome = await ConsultAsync(server, context, Issuer, oversizedJti).ConfigureAwait(false);

        Assert.AreEqual(JtiReplayOutcome.Unacceptable, outcome,
            "RFC 9449 §11.1: an unnecessarily large jti is refused before it can be tracked.");
        Assert.AreEqual(0, store.ResolveCallCount,
            "RFC 9449 §11.1: the oversized jti must never reach the store's resolver.");
        Assert.AreEqual(0, store.SaveCallCount,
            "RFC 9449 §11.1: the oversized jti must never reach the store's writer.");
    }


    /// <summary>
    /// RFC 9449 §11.1: "In order to guard against memory exhaustion attacks, a server that is tracking
    /// jti values should reject DPoP proof JWTs with unnecessarily large jti values or store only a hash
    /// thereof." A <c>jti</c> of exactly <see cref="JtiReplayGuard.MaxJtiLength"/> is within the bound
    /// and is tracked as a first use — the refusal is strictly for lengths beyond the bound.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449">RFC 9449, Section 11.1</see>.
    /// </summary>
    [TestMethod]
    public async Task JtiAtMaxLengthIsAccepted()
    {
        InMemoryJtiStore store = new(JtiStoreBehavior.ResolvesWhatItSaved);
        using EndpointServer server = BuildServer(store);
        ExchangeContext context = BuildContext(JtiReplayPolicy.Required);
        string boundaryJti = new('j', JtiReplayGuard.MaxJtiLength);

        JtiReplayOutcome outcome = await ConsultAsync(server, context, Issuer, boundaryJti).ConfigureAwait(false);

        Assert.AreEqual(JtiReplayOutcome.FirstUse, outcome,
            "RFC 9449 §11.1: a jti of exactly MaxJtiLength is within the bound and is accepted.");
    }


    /// <summary>
    /// RFC 7523 §3 rule 7 keys the used-<c>jti</c> set by <c>(issuer, jti)</c>; the guard composes that
    /// key once through <see cref="JtiReplayGuard.CorrelationKey"/>, and the flow state a host indexes
    /// under composes its own key through the same function via
    /// <see cref="JtiSeenState.CorrelationKey"/>, so the two never diverge.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523">RFC 7523, Section 3</see>.
    /// </summary>
    [TestMethod]
    public void CorrelationKeyMatchesJtiSeenStateCorrelationKey()
    {
        string guardKey = JtiReplayGuard.CorrelationKey(Issuer, Jti);
        JtiSeenState state = new()
        {
            FlowId = "flow-id",
            ExpectedIssuer = Issuer,
            EnteredAt = TimeProvider.GetUtcNow(),
            ExpiresAt = TimeProvider.GetUtcNow().AddMinutes(5),
            Kind = FlowKind.JtiReplay,
            Issuer = Issuer,
            Jti = Jti,
            SeenAt = TimeProvider.GetUtcNow()
        };

        Assert.AreEqual(guardKey, state.CorrelationKey,
            "The state's CorrelationKey must equal JtiReplayGuard.CorrelationKey(issuer, jti) — one composition, one home.");
    }


    /// <summary>
    /// Consults the guard for the given <paramref name="issuer"/>/<paramref name="jti"/> with a
    /// five-minute recording window off the fake clock, carrying the test's cancellation token.
    /// </summary>
    /// <param name="server">The minimal server carrying the wired store and clock.</param>
    /// <param name="context">The exchange context carrying the resolved policy.</param>
    /// <param name="issuer">The issuer the <c>jti</c> is presented under.</param>
    /// <param name="jti">The presented <c>jti</c> value.</param>
    private ValueTask<JtiReplayOutcome> ConsultAsync(
        EndpointServer server,
        ExchangeContext context,
        string issuer,
        string jti)
    {
        DateTimeOffset expiresAt = TimeProvider.GetUtcNow().AddMinutes(5);

        return JtiReplayGuard.ConsultAsync(
            server, context, Tenant, issuer, jti, expiresAt, TestContext.CancellationToken);
    }


    /// <summary>
    /// Builds a minimal <see cref="EndpointServer"/> that registers an
    /// <see cref="AuthorizationServerIntegration"/> whose replay-store delegates are the given
    /// <paramref name="store"/>, with the fake clock as its time source. Only the store delegates and
    /// the clock are exercised by <see cref="JtiReplayGuard.ConsultAsync"/>.
    /// </summary>
    /// <param name="store">The in-memory store whose delegates back the integration.</param>
    private EndpointServer BuildServer(InMemoryJtiStore store)
    {
        AuthorizationServerIntegration integration = new()
        {
            SaveFlowStateAsync = store.SaveAsync,
            ResolveCorrelationKeyAsync = store.ResolveAsync,
            GenerateIdentifierAsync = DefaultIdentifierGenerator.For(TimeProvider, TestEntropy.NewCounterStream(), BaseMemoryPool.Shared),
            MemoryPool = BaseMemoryPool.Shared
        };

        EndpointServer server = new()
        {
            Integration = integration,
            Configuration = ServerConfiguration.Empty,
            TimeProvider = TimeProvider
        };
        server.AddIntegration(integration);

        return server;
    }


    /// <summary>
    /// Builds an <see cref="ExchangeContext"/> carrying the given <paramref name="policy"/> as its
    /// resolved <c>jti</c> replay policy.
    /// </summary>
    /// <param name="policy">The replay policy the consultation runs under.</param>
    private static ExchangeContext BuildContext(JtiReplayPolicy policy)
    {
        ExchangeContext context = new();
        context.SetJtiReplayPolicy(policy);

        return context;
    }


    /// <summary>
    /// How the test store answers its resolver after a save, modelling a correctly wired store, a store
    /// wired for other correlation kinds but never for <see cref="FlowKind.JtiReplay"/>, and a store that
    /// resolves a foreign flow id.
    /// </summary>
    private enum JtiStoreBehavior
    {
        /// <summary>The store resolves exactly the flow id it saved under the correlation key.</summary>
        ResolvesWhatItSaved,

        /// <summary>Saves succeed, but the resolver never answers under <see cref="FlowKind.JtiReplay"/>.</summary>
        NeverResolvesJtiReplay,

        /// <summary>Saves succeed, but the resolver answers a flow id unrelated to what was saved.</summary>
        ResolvesForeignFlowId
    }


    /// <summary>
    /// A pooled-allocation-free in-memory <c>jti</c> correlation store standing in for a host's
    /// flow-state store, mirroring <c>HostedAuthorizationServer</c>'s save/resolve wiring under
    /// <see cref="FlowKind.JtiReplay"/> and counting its calls so a policy that must not touch the store
    /// can be proved to have left it untouched.
    /// </summary>
    private sealed class InMemoryJtiStore
    {
        /// <summary>The flow id the foreign-answer behaviour resolves instead of the saved key.</summary>
        private const string ForeignFlowId = "a-foreign-unrelated-flow-id";

        /// <summary>The <c>(issuer, jti)</c> key to saved-flow-id index, keyed ordinally.</summary>
        private Dictionary<string, string> JtiIndex { get; } = new(StringComparer.Ordinal);

        /// <summary>The resolver behaviour this store exhibits after a save.</summary>
        private JtiStoreBehavior Behavior { get; }

        /// <summary>Constructs a store exhibiting the given <paramref name="behavior"/>.</summary>
        /// <param name="behavior">How the resolver answers after a save.</param>
        public InMemoryJtiStore(JtiStoreBehavior behavior)
        {
            this.Behavior = behavior;
        }

        /// <summary>The number of times <see cref="SaveAsync"/> has been invoked.</summary>
        public int SaveCallCount { get; private set; }

        /// <summary>The number of times <see cref="ResolveAsync"/> has been invoked.</summary>
        public int ResolveCallCount { get; private set; }

        /// <summary>
        /// Records a <see cref="JtiSeenState"/> under its own <see cref="JtiSeenState.CorrelationKey"/>,
        /// as a host's save switch does. The stored value is the saved flow id under
        /// <see cref="JtiStoreBehavior.ResolvesWhatItSaved"/>, or an unrelated id under
        /// <see cref="JtiStoreBehavior.ResolvesForeignFlowId"/>.
        /// </summary>
        /// <param name="tenantId">The tenant the state is scoped to; accepted to match the delegate shape.</param>
        /// <param name="correlationKey">The key the state is saved under (also the saved flow id).</param>
        /// <param name="state">The flow state being saved.</param>
        /// <param name="stepCount">The step count; accepted to match the delegate shape.</param>
        /// <param name="context">The request context; accepted to match the delegate shape.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public ValueTask SaveAsync(
            TenantId tenantId,
            string correlationKey,
            FlowState state,
            int stepCount,
            ExchangeContext context,
            CancellationToken cancellationToken)
        {
            SaveCallCount++;
            if(state is JtiSeenState jti)
            {
                JtiIndex[jti.CorrelationKey] = Behavior switch
                {
                    JtiStoreBehavior.ResolvesForeignFlowId => ForeignFlowId,
                    _ => correlationKey
                };
            }

            return ValueTask.CompletedTask;
        }

        /// <summary>
        /// Resolves an external handle under <see cref="FlowKind.JtiReplay"/> to the saved flow id, or
        /// answers <see langword="null"/> when the behaviour never resolves that flow kind or the key was
        /// never saved.
        /// </summary>
        /// <param name="tenantId">The tenant; accepted to match the delegate shape.</param>
        /// <param name="flowKind">The flow kind; only <see cref="FlowKind.JtiReplay"/> is answered.</param>
        /// <param name="externalHandle">The correlation key to resolve.</param>
        /// <param name="context">The request context; accepted to match the delegate shape.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public ValueTask<string?> ResolveAsync(
            TenantId tenantId,
            FlowKind flowKind,
            string externalHandle,
            ExchangeContext context,
            CancellationToken cancellationToken)
        {
            ResolveCallCount++;
            bool isJtiReplayResolvable =
                flowKind == FlowKind.JtiReplay
                && Behavior != JtiStoreBehavior.NeverResolvesJtiReplay;
            if(isJtiReplayResolvable)
            {
                return ValueTask.FromResult<string?>(
                    JtiIndex.TryGetValue(externalHandle, out string? id) ? id : null);
            }

            return ValueTask.FromResult<string?>(null);
        }
    }
}


/// <summary>
/// Proves the <see cref="JtiReplayGuard"/> store self-check over the real dispatch wire on the SIOP
/// nonce-replay consumer: with a store that saves but cannot resolve what it recorded under
/// <see cref="FlowKind.JtiReplay"/>, the very first Self-Issued ID Token presentation fails closed
/// (SIOPv2 §11.2), and with a correctly wired store the second presentation of the same
/// <c>(client_id, nonce)</c> is still refused as a replay. The other <c>jti</c> consumers (the JAR
/// request object, the JWT Bearer / ID-JAG redemption, the <c>private_key_jwt</c> assertion, and the
/// DPoP proof at the token endpoint) consult the same guard and map its
/// <see cref="JtiReplayOutcome.StoreUnavailable"/> to their own malformed-input refusal; the guard
/// half of that contract is proved in <see cref="JtiReplayGuardStoreProofTests"/>.
/// </summary>
[TestClass]
internal sealed class JtiReplayGuardSiopWireProofTests
{
    /// <summary>The ambient test context supplying the cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The per-test fake clock; anchored to the canonical epoch so timestamps are deterministic.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The pool the Self-Issued ID Token issuance borrows its buffers from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The Relying Party client identifier, also the expected SIOP <c>aud</c>.</summary>
    private const string RelyingPartyClientId = "https://rp.example.com";

    /// <summary>The per-transaction nonce the RP issues and the ID Token echoes.</summary>
    private const string SiopNonce = "n-siop-store-proof-01";

    /// <summary>The RP's base URI used at registration.</summary>
    private static Uri RelyingPartyBaseUri { get; } = new("https://rp.example.com");

    /// <summary>The SIOP Self-Issued OP capability the RP registration advertises.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> SiopCapabilities { get; } =
        ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.SiopSelfIssuedOp);

    /// <summary>The signing algorithms the RP accepts on a Self-Issued ID Token.</summary>
    private static string[] AllowedSiopAlgorithms { get; } = [WellKnownJwaValues.Es256];

    /// <summary>Serializes a JWT header to UTF-8 through the project's test serialization options.</summary>
    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    /// <summary>Serializes a JWT payload to UTF-8 through the project's test serialization options.</summary>
    private static JwtPayloadSerializer PayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);


    /// <summary>
    /// SIOPv2 §11.2 replay defense over the real dispatch wire: the RP MUST reject a Self-Issued ID
    /// Token whose <c>nonce</c> cannot be proved unused. With a store that saves but never resolves
    /// what it recorded under <see cref="FlowKind.JtiReplay"/>, the guard answers
    /// <see cref="JtiReplayOutcome.StoreUnavailable"/> and the SIOP verifier fails the very FIRST
    /// presentation closed — the silent no-op the half-wiring would otherwise produce is caught.
    /// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-11.2">SIOPv2 §11.2</see>.
    /// </summary>
    [TestMethod]
    public async Task SiopNonceFailsClosedWhenStoreCannotProveItself()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial rpKeys = host.RegisterClient(
            RelyingPartyClientId, RelyingPartyBaseUri, SiopCapabilities);
        string tenant = rpKeys.Registration.TenantId.Value;

        HalfWireJtiReplayStore(host.Server);

        (PublicKeyMemory siopPublic, PrivateKeyMemory siopPrivate) = CreateSiopKeys();
        using(siopPublic)
        using(siopPrivate)
        {
            string idToken = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
                siopPrivate, siopPublic, RelyingPartyClientId, SiopNonce,
                issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
                TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

            string handle = await host.HandleSiopRequestPreparationAsync(
                rpKeys, SiopNonce, RelyingPartyClientId, AllowedSiopAlgorithms,
                TestContext.CancellationToken).ConfigureAwait(false);

            ServerHttpResponse response = await PostIdTokenAsync(host, tenant, idToken, handle)
                .ConfigureAwait(false);

            Assert.AreNotEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);
            Assert.IsInstanceOfType<SiopVerifierFlowFailedState>(
                host.GetFlowState(handle).State,
                "SIOPv2 §11.2: a store that cannot prove it recorded the nonce must fail the first presentation closed.");
        }
    }


    /// <summary>
    /// SIOPv2 §11.2 replay defense over the real dispatch wire with a correctly wired store: the FIRST
    /// presentation of a <c>(client_id, nonce)</c> verifies and the SECOND is refused as a replay. This
    /// pins that the guard's store self-check did not weaken the correct-store refusal proved by
    /// <c>SiopNonceReplayTests.ReplayedNonceUnderSameClientIdReachesFailedStateSecondTime</c>.
    /// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-11.2">SIOPv2 §11.2</see>.
    /// </summary>
    [TestMethod]
    public async Task SiopNonceReplayStillRefusedWithCorrectStore()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial rpKeys = host.RegisterClient(
            RelyingPartyClientId, RelyingPartyBaseUri, SiopCapabilities);
        string tenant = rpKeys.Registration.TenantId.Value;

        (PublicKeyMemory siopPublic, PrivateKeyMemory siopPrivate) = CreateSiopKeys();
        using(siopPublic)
        using(siopPrivate)
        {
            string idToken = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
                siopPrivate, siopPublic, RelyingPartyClientId, SiopNonce,
                issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
                TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

            string firstHandle = await host.HandleSiopRequestPreparationAsync(
                rpKeys, SiopNonce, RelyingPartyClientId, AllowedSiopAlgorithms,
                TestContext.CancellationToken).ConfigureAwait(false);
            ServerHttpResponse first = await PostIdTokenAsync(host, tenant, idToken, firstHandle)
                .ConfigureAwait(false);

            Assert.AreEqual((int)HttpStatusCode.OK, first.StatusCode, first.Body);
            Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(
                host.GetFlowState(firstHandle).State,
                "SIOPv2 §11.2: the first use of a nonce verifies against a correct store.");

            string secondHandle = await host.HandleSiopRequestPreparationAsync(
                rpKeys, SiopNonce, RelyingPartyClientId, AllowedSiopAlgorithms,
                TestContext.CancellationToken).ConfigureAwait(false);
            ServerHttpResponse second = await PostIdTokenAsync(host, tenant, idToken, secondHandle)
                .ConfigureAwait(false);

            Assert.AreNotEqual((int)HttpStatusCode.OK, second.StatusCode, second.Body);
            Assert.IsInstanceOfType<SiopVerifierFlowFailedState>(
                host.GetFlowState(secondHandle).State,
                "SIOPv2 §11.2: the same (client_id, nonce) is refused as a replay against a correct store.");
        }
    }


    /// <summary>
    /// Rewires the host's replay store so it saves normally but never resolves anything under
    /// <see cref="FlowKind.JtiReplay"/>, while every other correlation kind (the SIOP request handle
    /// among them) still resolves through the host's real resolver. This is the half-wired store the
    /// guard's post-save self-check must catch.
    /// </summary>
    /// <param name="server">The hosted server whose OAuth integration resolver is wrapped.</param>
    private static void HalfWireJtiReplayStore(EndpointServer server)
    {
        ResolveCorrelationKeyDelegate original = server.OAuth().ResolveCorrelationKeyAsync!;
        server.OAuth().ResolveCorrelationKeyAsync = (tenantId, flowKind, externalHandle, ctx, ct) =>
            flowKind == FlowKind.JtiReplay
                ? ValueTask.FromResult<string?>(null)
                : original(tenantId, flowKind, externalHandle, ctx, ct);
    }


    /// <summary>
    /// Mints a fresh P-256 key pair for the Self-Issued OP. The caller owns both halves and disposes
    /// them.
    /// </summary>
    private static (PublicKeyMemory Public, PrivateKeyMemory Private) CreateSiopKeys()
    {
        var siopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        return (siopKeys.PublicKey, siopKeys.PrivateKey);
    }


    /// <summary>
    /// POSTs a Self-Issued ID Token to the SIOP response endpoint for the flow identified by
    /// <paramref name="requestHandle"/>, mirroring the dispatch path <c>SiopNonceReplayTests</c> uses.
    /// </summary>
    /// <param name="host">The hosted test server.</param>
    /// <param name="tenant">The RP tenant segment.</param>
    /// <param name="idToken">The compact Self-Issued ID Token.</param>
    /// <param name="requestHandle">The per-flow request handle echoed as <c>state</c>.</param>
    private async Task<ServerHttpResponse> PostIdTokenAsync(
        TestHostShell host,
        string tenant,
        string idToken,
        string requestHandle) =>
        await host.DispatchAtEndpointAsync(
            tenant,
            WellKnownEndpointNames.SiopResponse,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.IdToken] = idToken,
                [OAuthRequestParameterNames.State] = requestHandle
            },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
}
