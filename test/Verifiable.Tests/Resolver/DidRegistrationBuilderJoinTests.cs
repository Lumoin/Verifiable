using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Foundation.Automata;
using Verifiable.Tests.TestDataProviders;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests the builder join (registration matrix J1): a <see cref="BeginCreate"/> carrying key material is
/// dispatched through <see cref="DidRegistrationBuilders"/> to the per-method document builder
/// (<see cref="KeyDidBuilder"/>/<see cref="WebDidBuilder"/>) and completes the real registration PDA with a
/// standards-shaped document. This proves the join end-to-end (the builders consume key material; the PDA carries
/// a create request; the registry method handler bridges the two).
/// </summary>
[TestClass]
internal sealed class DidRegistrationBuilderJoinTests
{
    /// <summary>The test context.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>A create supplying key material for did:key builds and completes with a standard did:key document.</summary>
    [TestMethod]
    public async Task CreateThroughKeyBuilderCompletesWithStandardDocument()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signing = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> exchange = TestKeyMaterialProvider.CreateX25519KeyMaterial();
        using PublicKeyMemory signingPublic = signing.PublicKey;
        using PrivateKeyMemory signingPrivate = signing.PrivateKey;
        using PublicKeyMemory exchangePublic = exchange.PublicKey;
        using PrivateKeyMemory exchangePrivate = exchange.PrivateKey;

        PushdownAutomaton<RegistrationFlowState, RegistrationInput, string> pda = CreateRegistrarAutomaton();

        await pda.StepAsync(
            new BeginCreate("key", Document: null, Keys: StandardKeyInputs(signingPublic, exchangePublic)),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pda.IsAccepted);
        var completed = (RegistrationCompleted)pda.CurrentState;
        Assert.IsNotNull(completed.Document);
        Assert.AreEqual(completed.Document!.Id!.Id, completed.Did, "The completed DID must equal the built document's id.");
        Assert.StartsWith(KeyDidMethod.Prefix, completed.Did);
        AssertStandardDocument(completed.Document!);
    }


    /// <summary>A create for did:web reads the host from the method-specific domain option and builds a did:web document.</summary>
    [TestMethod]
    public async Task CreateThroughWebBuilderUsesDomainOption()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signing = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> exchange = TestKeyMaterialProvider.CreateX25519KeyMaterial();
        using PublicKeyMemory signingPublic = signing.PublicKey;
        using PrivateKeyMemory signingPrivate = signing.PrivateKey;
        using PublicKeyMemory exchangePublic = exchange.PublicKey;
        using PrivateKeyMemory exchangePrivate = exchange.PrivateKey;

        PushdownAutomaton<RegistrationFlowState, RegistrationInput, string> pda = CreateRegistrarAutomaton();

        var options = new Dictionary<string, object?>
        {
            [WellKnownDidRegistrationValues.WebDomainOption] = "example.com"
        };

        await pda.StepAsync(
            new BeginCreate("web", Document: null, Keys: StandardKeyInputs(signingPublic, exchangePublic), Options: options),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pda.IsAccepted);
        var completed = (RegistrationCompleted)pda.CurrentState;
        Assert.IsNotNull(completed.Document);
        Assert.AreEqual("did:web:example.com", completed.Did);
        AssertStandardDocument(completed.Document!);
    }


    /// <summary>The did:web representation option maps to the builder's named parameter (jsonWithoutContext ⇒ no @context).</summary>
    [TestMethod]
    public async Task CreateThroughWebBuilderHonorsRepresentationOption()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signing = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> exchange = TestKeyMaterialProvider.CreateX25519KeyMaterial();
        using PublicKeyMemory signingPublic = signing.PublicKey;
        using PrivateKeyMemory signingPrivate = signing.PrivateKey;
        using PublicKeyMemory exchangePublic = exchange.PublicKey;
        using PrivateKeyMemory exchangePrivate = exchange.PrivateKey;

        PushdownAutomaton<RegistrationFlowState, RegistrationInput, string> pda = CreateRegistrarAutomaton();

        var options = new Dictionary<string, object?>
        {
            [WellKnownDidRegistrationValues.WebDomainOption] = "example.com",
            [WellKnownDidRegistrationValues.WebRepresentationOption] = WellKnownDidRegistrationValues.RepresentationJsonWithoutContext
        };

        await pda.StepAsync(
            new BeginCreate("web", Document: null, Keys: StandardKeyInputs(signingPublic, exchangePublic), Options: options),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pda.IsAccepted);
        var completed = (RegistrationCompleted)pda.CurrentState;
        Assert.IsNull(completed.Document!.Context, "The jsonWithoutContext representation must omit @context.");
    }


    /// <summary>The did:web didCoreVersion + additionalContexts options map to the builder's @context array.</summary>
    [TestMethod]
    public async Task CreateThroughWebBuilderMapsContextOptions()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signing = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> exchange = TestKeyMaterialProvider.CreateX25519KeyMaterial();
        using PublicKeyMemory signingPublic = signing.PublicKey;
        using PrivateKeyMemory signingPrivate = signing.PrivateKey;
        using PublicKeyMemory exchangePublic = exchange.PublicKey;
        using PrivateKeyMemory exchangePrivate = exchange.PrivateKey;

        PushdownAutomaton<RegistrationFlowState, RegistrationInput, string> pda = CreateRegistrarAutomaton();

        var options = new Dictionary<string, object?>
        {
            [WellKnownDidRegistrationValues.WebDomainOption] = "example.com",
            [WellKnownDidRegistrationValues.WebRepresentationOption] = WellKnownDidRegistrationValues.RepresentationJsonLd,
            [WellKnownDidRegistrationValues.WebDidCoreVersionOption] = Context.DidCore11,
            [WellKnownDidRegistrationValues.WebAdditionalContextsOption] = new[] { "https://example.com/custom" }
        };

        await pda.StepAsync(
            new BeginCreate("web", Document: null, Keys: StandardKeyInputs(signingPublic, exchangePublic), Options: options),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pda.IsAccepted);
        var completed = (RegistrationCompleted)pda.CurrentState;
        Assert.IsNotNull(completed.Document!.Context);
        Assert.AreEqual(Context.DidCore11, completed.Document!.Context!.Contexts![0]);
        Assert.AreEqual("https://example.com/custom", completed.Document!.Context!.Contexts![1]);
    }


    /// <summary>A create naming a method with no registered builder fails closed.</summary>
    [TestMethod]
    public async Task UnknownMethodFailsClosed()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signing = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> exchange = TestKeyMaterialProvider.CreateX25519KeyMaterial();
        using PublicKeyMemory signingPublic = signing.PublicKey;
        using PrivateKeyMemory signingPrivate = signing.PrivateKey;
        using PublicKeyMemory exchangePublic = exchange.PublicKey;
        using PrivateKeyMemory exchangePrivate = exchange.PrivateKey;

        PushdownAutomaton<RegistrationFlowState, RegistrationInput, string> pda = CreateRegistrarAutomaton();

        await pda.StepAsync(
            new BeginCreate("bogus", Document: null, Keys: StandardKeyInputs(signingPublic, exchangePublic)),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<RegistrationFailed>(pda.CurrentState);
    }


    /// <summary>A create supplying a pre-built document completes directly, without dispatching to a builder.</summary>
    [TestMethod]
    public async Task PreBuiltDocumentCompletesWithoutBuilder()
    {
        PushdownAutomaton<RegistrationFlowState, RegistrationInput, string> pda = CreateRegistrarAutomaton();

        var prebuilt = new DidDocument { Id = (GenericDidMethod)"did:key:zPrebuilt" };

        await pda.StepAsync(
            new BeginCreate("key", Document: prebuilt),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pda.IsAccepted);
        var completed = (RegistrationCompleted)pda.CurrentState;
        Assert.AreEqual("did:key:zPrebuilt", completed.Did);
        Assert.AreSame(prebuilt, completed.Document);
    }


    /// <summary>An update with <c>setDidDocument</c> completes through the real handler with the supplied document.</summary>
    [TestMethod]
    public async Task UpdateSetThroughRealHandlerReplacesDocument()
    {
        PushdownAutomaton<RegistrationFlowState, RegistrationInput, string> pda = CreateRegistrarAutomaton();

        var replacement = new DidDocument
        {
            Id = (GenericDidMethod)"did:web:example.com",
            VerificationMethod = [new VerificationMethod { Id = "#key-2", Controller = "did:web:example.com" }]
        };

        await pda.StepAsync(
            new BeginUpdate("did:web:example.com", [new DidDocumentOperationStep(WellKnownDidRegistrationValues.SetDidDocument, replacement)]),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pda.IsAccepted);
        var completed = (RegistrationCompleted)pda.CurrentState;
        Assert.AreSame(replacement, completed.Document);
    }


    /// <summary>An update with <c>addToDidDocument</c> merges the payload into the supplied current document.</summary>
    [TestMethod]
    public async Task UpdateAddThroughRealHandlerMergesDocument()
    {
        PushdownAutomaton<RegistrationFlowState, RegistrationInput, string> pda = CreateRegistrarAutomaton();

        var current = new DidDocument
        {
            Id = (GenericDidMethod)"did:web:example.com",
            VerificationMethod = [new VerificationMethod { Id = "#key-1", Controller = "did:web:example.com" }]
        };

        var additions = new DidDocument
        {
            Id = (GenericDidMethod)"did:web:example.com",
            VerificationMethod = [new VerificationMethod { Id = "#key-2", Controller = "did:web:example.com" }]
        };

        await pda.StepAsync(
            new BeginUpdate("did:web:example.com", [new DidDocumentOperationStep(WellKnownDidRegistrationValues.AddToDidDocument, additions)], current),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pda.IsAccepted);
        var completed = (RegistrationCompleted)pda.CurrentState;
        Assert.HasCount(2, completed.Document!.VerificationMethod!);
    }


    /// <summary>An update with <c>removeFromDidDocument</c> prunes the named entries from the supplied current document.</summary>
    [TestMethod]
    public async Task UpdateRemoveThroughRealHandlerPrunesDocument()
    {
        PushdownAutomaton<RegistrationFlowState, RegistrationInput, string> pda = CreateRegistrarAutomaton();

        var current = new DidDocument
        {
            Id = (GenericDidMethod)"did:web:example.com",
            VerificationMethod =
            [
                new VerificationMethod { Id = "#key-1", Controller = "did:web:example.com" },
                new VerificationMethod { Id = "#key-2", Controller = "did:web:example.com" }
            ]
        };

        var removals = new DidDocument
        {
            Id = (GenericDidMethod)"did:web:example.com",
            VerificationMethod = [new VerificationMethod { Id = "#key-1", Controller = "did:web:example.com" }]
        };

        await pda.StepAsync(
            new BeginUpdate("did:web:example.com", [new DidDocumentOperationStep(WellKnownDidRegistrationValues.RemoveFromDidDocument, removals)], current),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pda.IsAccepted);
        var completed = (RegistrationCompleted)pda.CurrentState;
        Assert.HasCount(1, completed.Document!.VerificationMethod!);
        Assert.AreEqual("#key-2", completed.Document!.VerificationMethod![0].Id);
    }


    /// <summary>An <c>addToDidDocument</c> update without the current document fails closed.</summary>
    [TestMethod]
    public async Task UpdateAddWithoutCurrentDocumentFailsClosed()
    {
        PushdownAutomaton<RegistrationFlowState, RegistrationInput, string> pda = CreateRegistrarAutomaton();

        var additions = new DidDocument { Id = (GenericDidMethod)"did:web:example.com" };

        await pda.StepAsync(
            new BeginUpdate("did:web:example.com", [new DidDocumentOperationStep(WellKnownDidRegistrationValues.AddToDidDocument, additions)]),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<RegistrationFailed>(pda.CurrentState);
    }


    /// <summary>An update naming the deactivate operation (which is not a document transform) fails closed.</summary>
    [TestMethod]
    public async Task UpdateWithDeactivateOperationFailsClosed()
    {
        PushdownAutomaton<RegistrationFlowState, RegistrationInput, string> pda = CreateRegistrarAutomaton();

        var document = new DidDocument { Id = (GenericDidMethod)"did:web:example.com" };

        await pda.StepAsync(
            new BeginUpdate("did:web:example.com", [new DidDocumentOperationStep(WellKnownDidRegistrationValues.DeactivateOperation, document)]),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<RegistrationFailed>(pda.CurrentState);
    }


    /// <summary>An update carrying no <c>didDocumentOperation</c> steps fails closed.</summary>
    [TestMethod]
    public async Task UpdateWithoutOperationsFailsClosed()
    {
        PushdownAutomaton<RegistrationFlowState, RegistrationInput, string> pda = CreateRegistrarAutomaton();

        await pda.StepAsync(
            new BeginUpdate("did:web:example.com", []),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<RegistrationFailed>(pda.CurrentState);
    }


    /// <summary>
    /// A multi-operation update (<c>removeFromDidDocument</c> then <c>addToDidDocument</c>) applies the steps in order
    /// against the supplied current document, rotating a verification method.
    /// </summary>
    [TestMethod]
    public async Task UpdateMultiOperationThroughRealHandlerRotatesKey()
    {
        PushdownAutomaton<RegistrationFlowState, RegistrationInput, string> pda = CreateRegistrarAutomaton();

        var current = new DidDocument
        {
            Id = (GenericDidMethod)"did:web:example.com",
            VerificationMethod = [new VerificationMethod { Id = "#key-1", Controller = "did:web:example.com" }]
        };

        var removal = new DidDocument
        {
            Id = (GenericDidMethod)"did:web:example.com",
            VerificationMethod = [new VerificationMethod { Id = "#key-1", Controller = "did:web:example.com" }]
        };

        var addition = new DidDocument
        {
            Id = (GenericDidMethod)"did:web:example.com",
            VerificationMethod = [new VerificationMethod { Id = "#key-2", Controller = "did:web:example.com" }]
        };

        await pda.StepAsync(
            new BeginUpdate(
                "did:web:example.com",
                [
                    new DidDocumentOperationStep(WellKnownDidRegistrationValues.RemoveFromDidDocument, removal),
                    new DidDocumentOperationStep(WellKnownDidRegistrationValues.AddToDidDocument, addition)
                ],
                current),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pda.IsAccepted);
        var completed = (RegistrationCompleted)pda.CurrentState;
        Assert.HasCount(1, completed.Document!.VerificationMethod!);
        Assert.AreEqual("#key-2", completed.Document!.VerificationMethod![0].Id, "The remove-then-add rotates #key-1 out and #key-2 in.");
    }


    /// <summary>A deactivate completes through the real handler with the DID and no document.</summary>
    [TestMethod]
    public async Task DeactivateThroughRealHandlerCompletesWithNoDocument()
    {
        PushdownAutomaton<RegistrationFlowState, RegistrationInput, string> pda = CreateRegistrarAutomaton();

        await pda.StepAsync(
            new BeginDeactivate("did:web:example.com"),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pda.IsAccepted);
        var completed = (RegistrationCompleted)pda.CurrentState;
        Assert.AreEqual("did:web:example.com", completed.Did);
        Assert.IsNull(completed.Document, "A deactivated DID resolves to no document.");
    }


    /// <summary>An update of a generative method's DID (did:key, registered generative) fails closed — such DIDs are immutable.</summary>
    [TestMethod]
    public async Task UpdateOfGenerativeMethodFailsClosed()
    {
        PushdownAutomaton<RegistrationFlowState, RegistrationInput, string> pda = CreateRegistrarAutomaton();

        var document = new DidDocument { Id = (GenericDidMethod)"did:key:z6MkExample" };

        await pda.StepAsync(
            new BeginUpdate(
                "did:key:z6MkExample",
                [new DidDocumentOperationStep(WellKnownDidRegistrationValues.SetDidDocument, document)]),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<RegistrationFailed>(pda.CurrentState, "A did:key DID is immutable; update must fail closed.");
    }


    /// <summary>A deactivate of a generative method's DID (did:key, registered generative) fails closed — such DIDs are immutable.</summary>
    [TestMethod]
    public async Task DeactivateOfGenerativeMethodFailsClosed()
    {
        PushdownAutomaton<RegistrationFlowState, RegistrationInput, string> pda = CreateRegistrarAutomaton();

        await pda.StepAsync(
            new BeginDeactivate("did:key:z6MkExample"),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<RegistrationFailed>(pda.CurrentState, "A did:key DID is immutable; deactivate must fail closed.");
    }


    /// <summary>
    /// A multi-operation update is observable on the registration PDA's trace: stepping it emits one
    /// <see cref="TraceEntry{TState, TInput}"/> labelled <c>BeginUpdate</c> with
    /// <see cref="TraceOutcome.Transitioned"/> — the event-log record a trace consumer (a LogReplayer) accumulates for
    /// the operation — and the traced step leaves the PDA in the completed, key-rotated state.
    /// </summary>
    [TestMethod]
    public async Task MultiOperationUpdateEmitsTraceEntry()
    {
        var entries = new List<TraceEntry<RegistrationFlowState, RegistrationInput>>();
        var observer = new TraceObserver<TraceEntry<RegistrationFlowState, RegistrationInput>>(entries);

        var current = new DidDocument
        {
            Id = (GenericDidMethod)"did:web:example.com",
            VerificationMethod = [new VerificationMethod { Id = "#key-1", Controller = "did:web:example.com" }]
        };

        var removal = new DidDocument
        {
            Id = (GenericDidMethod)"did:web:example.com",
            VerificationMethod = [new VerificationMethod { Id = "#key-1", Controller = "did:web:example.com" }]
        };

        var addition = new DidDocument
        {
            Id = (GenericDidMethod)"did:web:example.com",
            VerificationMethod = [new VerificationMethod { Id = "#key-2", Controller = "did:web:example.com" }]
        };

        PushdownAutomaton<RegistrationFlowState, RegistrationInput, string> pda = CreateRegistrarAutomaton();

        using(pda.Subscribe(observer))
        {
            await pda.StepAsync(
                new BeginUpdate(
                    "did:web:example.com",
                    [
                        new DidDocumentOperationStep(WellKnownDidRegistrationValues.RemoveFromDidDocument, removal),
                        new DidDocumentOperationStep(WellKnownDidRegistrationValues.AddToDidDocument, addition)
                    ],
                    current),
                TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.HasCount(1, entries);
        Assert.AreEqual("BeginUpdate", entries[0].Label, "The update step is recorded on the trace as BeginUpdate.");
        Assert.AreEqual(TraceOutcome.Transitioned, entries[0].Outcome);

        var completed = (RegistrationCompleted)pda.CurrentState;
        Assert.AreEqual("#key-2", completed.Document!.VerificationMethod![0].Id, "The traced update rotated #key-1 out and #key-2 in.");
    }


    /// <summary>Builds a registration PDA wired to the default builder registry's method handler.</summary>
    /// <returns>The configured registration automaton.</returns>
    private static PushdownAutomaton<RegistrationFlowState, RegistrationInput, string> CreateRegistrarAutomaton()
    {
        return DidRegistrationTransitions.CreateAutomaton(
            "builder-join",
            DidRegistrationBuilders.CreateDefault().CreateMethodHandler());
    }


    /// <summary>A signing Ed25519 verification method followed by a key-agreement X25519 verification method.</summary>
    /// <param name="signingKey">The Ed25519 signing public key.</param>
    /// <param name="exchangeKey">The X25519 key-agreement public key.</param>
    /// <returns>The ordered key-material inputs.</returns>
    private static IReadOnlyList<KeyMaterialInput> StandardKeyInputs(PublicKeyMemory signingKey, PublicKeyMemory exchangeKey)
    {
        return
        [
            new KeyMaterialInput { PublicKey = signingKey, VerificationMethodType = JsonWebKey2020VerificationMethodTypeInfo.Instance },
            new KeyMaterialInput { PublicKey = exchangeKey, VerificationMethodType = X25519KeyAgreementKey2020VerificationMethodTypeInfo.Instance }
        ];
    }


    /// <summary>
    /// Asserts the standard shape the shared construction guarantees: two verification methods both controlled by
    /// the DID, the signing key in all four signing relationships, and the exchange key in <c>keyAgreement</c>.
    /// </summary>
    /// <param name="document">The built DID document.</param>
    private static void AssertStandardDocument(DidDocument document)
    {
        string did = document.Id!.ToString()!;

        Assert.IsNotNull(document.VerificationMethod);
        Assert.HasCount(2, document.VerificationMethod!);
        foreach(VerificationMethod verificationMethod in document.VerificationMethod!)
        {
            Assert.AreEqual(did, verificationMethod.Controller, "Every verification method's controller MUST be the DID.");
        }

        Assert.HasCount(1, document.Authentication!);
        Assert.HasCount(1, document.AssertionMethod!);
        Assert.HasCount(1, document.CapabilityInvocation!);
        Assert.HasCount(1, document.CapabilityDelegation!);
        Assert.HasCount(1, document.KeyAgreement!);
    }


    /// <summary>Collects the registration PDA's emitted trace entries for assertion.</summary>
    /// <typeparam name="T">The trace entry type.</typeparam>
    /// <param name="entries">The list each emitted entry is appended to.</param>
    private sealed class TraceObserver<T>(List<T> entries) : IObserver<T>
    {
        /// <summary>Records an emitted trace entry.</summary>
        /// <param name="value">The emitted trace entry.</param>
        public void OnNext(T value) => entries.Add(value);

        /// <summary>Unused: the trace stream does not surface errors to this observer.</summary>
        /// <param name="error">The error.</param>
        public void OnError(Exception error) { }

        /// <summary>Unused: the test does not assert on stream completion.</summary>
        public void OnCompleted() { }
    }
}
