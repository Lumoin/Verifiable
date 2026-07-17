using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Foundation.Automata;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for the pure PDA transition function <see cref="CtapAuthenticatorTransitions"/>, driven
/// directly through a <see cref="PushdownAutomaton{TState, TInput, TStackSymbol}"/> without going
/// through <see cref="CtapAuthenticatorSimulator"/>'s wire framing or CBOR codecs.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorTransitionsTests
{
    /// <summary>The MSTest-injected context; supplies <see cref="TestContext.CancellationToken"/> to every async call below.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Builds a fresh automaton over the transitions under test, seeded with the given AAGUID, or with
    /// <paramref name="initialState"/> directly when the test needs a state shape
    /// <see cref="CtapAuthenticatorState.Initial(Guid, DateTimeOffset, IReadOnlyList{string}?, int, MemoryPool{byte}?)"/>
    /// alone cannot produce (e.g. a pre-set PIN).
    /// </summary>
    private static PushdownAutomaton<CtapAuthenticatorState, CtapAuthenticatorInput, CtapAuthenticatorStackSymbol> BuildAutomaton(
        Guid aaguid, IReadOnlyList<string>? supportedExtensions = null, CtapAuthenticatorState? initialState = null) =>
        new(
            runId: "transitions-test",
            initialState: initialState ?? CtapAuthenticatorState.Initial(aaguid, TestClock.CanonicalEpoch, supportedExtensions),
            initialStackSymbol: CtapAuthenticatorStackSymbol.Session,
            transition: CtapAuthenticatorTransitions.Create(),
            acceptPredicate: static _ => true);


    /// <summary>Builds a fixed-content <see cref="DigestValue"/> standing in for a stored PIN hash, without a full <c>setPIN</c> round trip.</summary>
    private static DigestValue BuildFixedDigest(byte seed, int length, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(length);
        for(int i = 0; i < length; i++)
        {
            owner.Memory.Span[i] = (byte)(seed + i);
        }

        return new DigestValue(owner, CryptoTags.Sha256Digest);
    }


    /// <summary>
    /// <see cref="GetInfoRequested"/> produces a <see cref="GetInfoResponseReady"/> intent carrying
    /// the state's own AAGUID, the FIDO_2_3 version, and <c>options.rk = true</c> (wave 2: this
    /// authenticator can create discoverable credentials).
    /// </summary>
    [TestMethod]
    public async Task GetInfoRequestedProducesGetInfoResponseReadyWithStateAaguid()
    {
        Guid aaguid = Guid.NewGuid();
        var automaton = BuildAutomaton(aaguid);

        bool stepped = await automaton.StepAsync(new GetInfoRequested(), TestContext.CancellationToken);

        Assert.IsTrue(stepped);
        Assert.IsInstanceOfType<GetInfoResponseReady>(automaton.CurrentState.ResponseIntent);
        var intent = (GetInfoResponseReady)automaton.CurrentState.ResponseIntent!;
        Assert.AreEqual(aaguid, intent.Response.Aaguid);
        Assert.HasCount(1, intent.Response.Versions);
        Assert.AreEqual(WellKnownCtapVersions.Fido23, intent.Response.Versions[0]);
        Assert.IsNotNull(intent.Response.Options);
        Assert.IsTrue(intent.Response.Options!.ResidentKey);
        Assert.IsNull(intent.Response.Options!.Platform);
        Assert.AreSame(NullAction.Instance, automaton.CurrentState.NextAction);
    }


    /// <summary>A configured <c>SupportedExtensions</c> personalization threads into the response's <c>Extensions</c> member.</summary>
    [TestMethod]
    public async Task GetInfoRequestedIncludesConfiguredSupportedExtensions()
    {
        string[] extensions = ["hmac-secret", "credProtect"];
        var automaton = BuildAutomaton(Guid.NewGuid(), extensions);

        await automaton.StepAsync(new GetInfoRequested(), TestContext.CancellationToken);

        var intent = (GetInfoResponseReady)automaton.CurrentState.ResponseIntent!;
        CollectionAssert.AreEqual(extensions, new List<string>(intent.Response.Extensions!));
    }


    /// <summary>
    /// A default-constructed automaton (no <c>supportedExtensions</c> personalization supplied)
    /// advertises exactly <c>["credProtect", "hmac-secret", "hmac-secret-mc", "largeBlobKey",
    /// "minPinLength"]</c>, correctly cased, per <see cref="CtapAuthenticatorState.DefaultSupportedExtensions"/>
    /// (contract R1).
    /// </summary>
    [TestMethod]
    public async Task GetInfoRequestedDefaultsToRealSupportedExtensions()
    {
        var automaton = BuildAutomaton(Guid.NewGuid());

        await automaton.StepAsync(new GetInfoRequested(), TestContext.CancellationToken);

        var intent = (GetInfoResponseReady)automaton.CurrentState.ResponseIntent!;
        CollectionAssert.AreEqual(
            new List<string>
            {
                WellKnownWebAuthnExtensionIdentifiers.CredProtect,
                WellKnownWebAuthnExtensionIdentifiers.HmacSecret,
                WellKnownWebAuthnExtensionIdentifiers.HmacSecretMc,
                WellKnownWebAuthnExtensionIdentifiers.LargeBlobKey,
                WellKnownWebAuthnExtensionIdentifiers.MinPinLength
            },
            new List<string>(intent.Response.Extensions!));
    }


    /// <summary>
    /// <c>authenticatorGetInfo</c> now advertises <c>clientPin:false</c> (no PIN can be set yet, but
    /// CTAP 2.3 §9 item 2 requires the boolean present once FIDO_2_3 is claimed),
    /// <c>pinUvAuthToken:true</c> (§9 item 5), and <c>pinUvAuthProtocols:[2, 1]</c> (§9 item 6:
    /// protocol 2 MUST be included and is listed first, this authenticator's preference) — CTAP wave-a's
    /// getInfo flips, decision 5.
    /// </summary>
    [TestMethod]
    public async Task GetInfoRequestedAdvertisesClientPinFlips()
    {
        var automaton = BuildAutomaton(Guid.NewGuid());

        await automaton.StepAsync(new GetInfoRequested(), TestContext.CancellationToken);

        var intent = (GetInfoResponseReady)automaton.CurrentState.ResponseIntent!;
        Assert.IsNotNull(intent.Response.Options);
        Assert.IsFalse(intent.Response.Options!.ClientPin);
        Assert.IsTrue(intent.Response.Options.PinUvAuthToken);
        Assert.IsNotNull(intent.Response.PinUvAuthProtocols);
        CollectionAssert.AreEqual(new List<int> { 2, 1 }, new List<int>(intent.Response.PinUvAuthProtocols!));
    }


    /// <summary>
    /// <c>makeCredUvNotRqd</c> is DERIVED as the logical negation of <c>alwaysUv</c> (CTAP 2.3, line
    /// 4951's MUST) — <see langword="true"/> while <c>alwaysUv</c> is disabled (closing ledger row
    /// 4929's "Authenticators SHOULD include this option with the value true" for that state,
    /// independent of whether a PIN has been set), <see langword="false"/> once <c>toggleAlwaysUv</c>
    /// has enabled <c>alwaysUv</c>. <c>authnrCfg</c>, <c>credMgmt</c>, and <c>setMinPINLength</c> are
    /// advertised <see langword="true"/> unconditionally; <c>minPINLength</c>, <c>forcePINChange</c>,
    /// <c>authenticatorConfigCommands</c>, and <c>maxRPIDsForSetMinPINLength</c> are always present;
    /// <c>remainingDiscoverableCredentials</c> is always present and, for a freshly constructed
    /// authenticator with an empty credential store, equals the state's own
    /// <see cref="CtapAuthenticatorState.ResidentCredentialCapacity"/> exactly (nothing has been minted
    /// yet to reduce it) — proven for BOTH <c>alwaysUv</c> states, since <c>credMgmt</c>'s surface is
    /// orthogonal to the config surface.
    /// </summary>
    [TestMethod]
    [DataRow(false, DisplayName = "alwaysUv disabled")]
    [DataRow(true, DisplayName = "alwaysUv enabled")]
    public async Task GetInfoRequestedAdvertisesMakeCredUvNotRqdDerivedFromAlwaysUv(bool isAlwaysUvEnabled)
    {
        Guid aaguid = Guid.NewGuid();
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapAuthenticatorState initialState = CtapAuthenticatorState.Initial(aaguid, TestClock.CanonicalEpoch, keyAgreementPool: pool) with
        {
            IsAlwaysUvEnabled = isAlwaysUvEnabled
        };

        var automaton = BuildAutomaton(aaguid, initialState: initialState);

        await automaton.StepAsync(new GetInfoRequested(), TestContext.CancellationToken);

        var intent = (GetInfoResponseReady)automaton.CurrentState.ResponseIntent!;
        Assert.IsNotNull(intent.Response.Options);
        Assert.AreEqual(isAlwaysUvEnabled, intent.Response.Options!.AlwaysUv);
        Assert.AreEqual(!isAlwaysUvEnabled, intent.Response.Options.MakeCredUvNotRqd);
        Assert.IsTrue(intent.Response.Options.AuthnrCfg);
        Assert.IsTrue(intent.Response.Options.CredMgmt);
        Assert.IsTrue(intent.Response.Options.SetMinPinLength);
        Assert.AreEqual(4, intent.Response.MinPinLength);
        Assert.IsFalse(intent.Response.ForcePinChange);
        Assert.AreEqual(CtapAuthenticatorState.MaxRpIdsForSetMinPinLengthCapacity, intent.Response.MaxRpIdsForSetMinPinLength);
        Assert.AreEqual(initialState.ResidentCredentialCapacity, intent.Response.RemainingDiscoverableCredentials);
        CollectionAssert.AreEqual(new List<int> { 2, 3 }, new List<int>(intent.Response.AuthenticatorConfigCommands!));
    }


    /// <summary>
    /// A default-constructed (non-enterprise-attestation-seeded) authenticator reports <c>ep</c> ABSENT
    /// (CTAP 2.3 lines 4744-4746: "the Enterprise Attestation feature is NOT supported") and
    /// <c>authenticatorConfigCommands</c> stays <c>[2, 3]</c> (R1: the default profile's observable wire
    /// behavior is byte-identical to a pre-waveep authenticator) — the regression-fence half of R2's
    /// single-predicate proof, its capable+enabled sibling is
    /// <see cref="GetInfoRequestedAdvertisesEpTriStateAndConditionalConfigCommandsForCapableAuthenticator"/>.
    /// </summary>
    [TestMethod]
    public async Task GetInfoRequestedAdvertisesEpAbsentForNonCapableAuthenticator()
    {
        Guid aaguid = Guid.NewGuid();
        var automaton = BuildAutomaton(aaguid);

        await automaton.StepAsync(new GetInfoRequested(), TestContext.CancellationToken);

        var intent = (GetInfoResponseReady)automaton.CurrentState.ResponseIntent!;
        Assert.IsNotNull(intent.Response.Options);
        Assert.IsNull(intent.Response.Options!.Ep, "ep must be absent for a non-capable authenticator.");
        CollectionAssert.AreEqual(new List<int> { 2, 3 }, new List<int>(intent.Response.AuthenticatorConfigCommands!));
    }


    /// <summary>
    /// An enterprise-attestation-CAPABLE authenticator (R1: a provisioning record seeded on
    /// <see cref="CtapAuthenticatorState.Initial"/>) reports <c>ep</c> present with the CURRENT
    /// <see cref="CtapAuthenticatorState.IsEnterpriseAttestationEnabled"/> value — never a second stored
    /// flag (R2, trap 15: <c>capable ? enabled : null</c>) — and <c>authenticatorConfigCommands</c>
    /// widens to the ascending <c>[1, 2, 3]</c> (trap 6), for BOTH the enabled and disabled states.
    /// </summary>
    [TestMethod]
    [DataRow(false, DisplayName = "capable, disabled")]
    [DataRow(true, DisplayName = "capable, enabled")]
    public async Task GetInfoRequestedAdvertisesEpTriStateAndConditionalConfigCommandsForCapableAuthenticator(bool isEnterpriseAttestationEnabled)
    {
        Guid aaguid = Guid.NewGuid();
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapEnterpriseAttestationProvisioning provisioning = CtapWaveEpFixtures.BuildProvisioning(pool);
        CtapAuthenticatorState initialState = CtapAuthenticatorState.Initial(
            aaguid, TestClock.CanonicalEpoch, keyAgreementPool: pool, enterpriseAttestationProvisioning: provisioning) with
        {
            IsEnterpriseAttestationEnabled = isEnterpriseAttestationEnabled
        };

        var automaton = BuildAutomaton(aaguid, initialState: initialState);

        await automaton.StepAsync(new GetInfoRequested(), TestContext.CancellationToken);

        var intent = (GetInfoResponseReady)automaton.CurrentState.ResponseIntent!;
        Assert.IsNotNull(intent.Response.Options);
        Assert.IsNotNull(intent.Response.Options!.Ep, "ep must be present for a capable authenticator.");
        Assert.AreEqual(isEnterpriseAttestationEnabled, intent.Response.Options.Ep!.Value);
        CollectionAssert.AreEqual(new List<int> { 1, 2, 3 }, new List<int>(intent.Response.AuthenticatorConfigCommands!));

        provisioning.Dispose();
    }


    /// <summary>
    /// <c>remainingDiscoverableCredentials</c> tracks the LIVE resident credential count: three resident
    /// credentials placed directly into <see cref="CtapAuthenticatorState.CredentialsByCredentialId"/>
    /// drop the reported value to exactly <c>capacity - 3</c>, the same
    /// <see cref="CtapAuthenticatorState.ResidentCredentialCapacity"/>-minus-count computation the
    /// empty-store case above already proves (R9's single-source-of-truth choice). Proven once, not
    /// crossed with <c>alwaysUv</c> again — the empty-store test above already establishes that
    /// <c>credMgmt</c>'s surface is orthogonal to the config surface.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the credential ID, user handle, and private key carriers transfers to the CtapCredentialRecord inserted into the state's credential store; every record built here is disposed explicitly once the assertion completes.")]
    public async Task GetInfoRequestedAdvertisesRemainingDiscoverableCredentialsDerivedFromResidentCredentialCount()
    {
        Guid aaguid = Guid.NewGuid();
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapAuthenticatorState initialState = CtapAuthenticatorState.Initial(aaguid, TestClock.CanonicalEpoch, keyAgreementPool: pool);

        const int residentCredentialCount = 3;
        ImmutableDictionary<string, CtapCredentialRecord> populated = initialState.CredentialsByCredentialId;
        CtapCredentialSigningBackend backend = CtapCredentialSigningBackend.CreateEs256Default();
        for(int i = 0; i < residentCredentialCount; i++)
        {
            CtapCredentialKeyPair keyPair = await backend.GenerateCredentialKeyPair(
                WellKnownCoseAlgorithms.Es256, pool, TestContext.CancellationToken);
            CredentialId credentialId = CredentialId.Create(BuildFixedIdentifierBytes(0x50, i), pool);
            UserHandle userId = UserHandle.Create(BuildFixedIdentifierBytes(0x60, i), pool);
            CtapCredentialRecord record = new(
                credentialId, "example.com", userId, "alice", "Alice Example", WellKnownCoseAlgorithms.Es256,
                IsResident: true, keyPair.PrivateKey, SignCount: 0, CreationSequence: (ulong)i, PublicKey: keyPair.PublicKey, CredProtectLevel: 1,
                CredRandomWithUV: BuildFixedOwner(0x70, i, pool), CredRandomWithoutUV: BuildFixedOwner(0x80, i, pool));

            populated = populated.SetItem(Convert.ToHexStringLower(credentialId.AsReadOnlySpan()), record);
        }

        initialState = initialState with { CredentialsByCredentialId = populated };
        var automaton = BuildAutomaton(aaguid, initialState: initialState);

        await automaton.StepAsync(new GetInfoRequested(), TestContext.CancellationToken);

        var intent = (GetInfoResponseReady)automaton.CurrentState.ResponseIntent!;
        Assert.AreEqual(
            initialState.ResidentCredentialCapacity - residentCredentialCount,
            intent.Response.RemainingDiscoverableCredentials);

        foreach(CtapCredentialRecord record in populated.Values)
        {
            record.Dispose();
        }
    }


    /// <summary>Builds a 16-byte identifier with a fixed, iteration-distinguishable pattern seeded by <paramref name="seed"/>.</summary>
    private static byte[] BuildFixedIdentifierBytes(byte seed, int iteration)
    {
        byte[] bytes = new byte[16];
        for(int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = (byte)(seed + iteration + i);
        }

        return bytes;
    }


    /// <summary>
    /// Builds a 32-byte pooled <see cref="IMemoryOwner{T}"/> with a fixed, iteration-distinguishable
    /// content pattern, standing in for a minted <c>hmac-secret</c> CredRandom value without a full
    /// <c>authenticatorMakeCredential</c> round trip.
    /// </summary>
    private static IMemoryOwner<byte> BuildFixedOwner(byte seed, int iteration, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(32);
        for(int i = 0; i < 32; i++)
        {
            owner.Memory.Span[i] = (byte)(seed + iteration + i);
        }

        return owner;
    }


    /// <summary><see cref="UnsupportedCtapCommandReceived"/> produces an <see cref="UnsupportedCommandResponse"/> intent carrying the rejected command byte.</summary>
    [TestMethod]
    public async Task UnsupportedCommandProducesUnsupportedCommandResponse()
    {
        var automaton = BuildAutomaton(Guid.NewGuid());

        bool stepped = await automaton.StepAsync(new UnsupportedCtapCommandReceived(0xFF), TestContext.CancellationToken);

        Assert.IsTrue(stepped);
        Assert.IsInstanceOfType<UnsupportedCommandResponse>(automaton.CurrentState.ResponseIntent);
        var intent = (UnsupportedCommandResponse)automaton.CurrentState.ResponseIntent!;
        Assert.AreEqual((byte)0xFF, intent.CommandByte);
        Assert.AreSame(NullAction.Instance, automaton.CurrentState.NextAction);
    }


    /// <summary>Successive commands each overwrite <c>ResponseIntent</c> with the latest command's result; the AAGUID never changes.</summary>
    [TestMethod]
    public async Task SuccessiveCommandsPreserveAaguidAcrossSteps()
    {
        Guid aaguid = Guid.NewGuid();
        var automaton = BuildAutomaton(aaguid);

        await automaton.StepAsync(new UnsupportedCtapCommandReceived(0x99), TestContext.CancellationToken);
        Assert.IsInstanceOfType<UnsupportedCommandResponse>(automaton.CurrentState.ResponseIntent);

        await automaton.StepAsync(new GetInfoRequested(), TestContext.CancellationToken);

        Assert.IsInstanceOfType<GetInfoResponseReady>(automaton.CurrentState.ResponseIntent);
        Assert.AreEqual(aaguid, automaton.CurrentState.Aaguid);
    }
}
