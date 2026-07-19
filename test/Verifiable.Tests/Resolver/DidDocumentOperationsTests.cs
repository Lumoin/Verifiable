using System;
using System.Linq;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Resolvers;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Conformance vectors for <see cref="DidDocumentOperations.Apply"/>: the pure document algebra behind a DIF
/// DID Registration <c>update</c> — <c>setDidDocument</c> (replace), <c>addToDidDocument</c> (union by identity),
/// and <c>removeFromDidDocument</c> (difference by identity) — plus the fail-closed guards.
/// </summary>
[TestClass]
internal sealed class DidDocumentOperationsTests
{
    /// <summary>The DID the documents under test identify.</summary>
    private const string Did = "did:web:example.com";

    /// <summary>The expected verification-method ids after a two-key union.</summary>
    private static readonly string[] ExpectedKeyOneAndTwo = ["#key-1", "#key-2"];

    /// <summary>The expected service ids after a two-service union.</summary>
    private static readonly string[] ExpectedServiceOneAndTwo = [Did + "#svc-1", Did + "#svc-2"];

    /// <summary>The expected controllers after a two-controller union.</summary>
    private static readonly string[] ExpectedControllerAAndB = ["did:web:controller-a", "did:web:controller-b"];

    /// <summary>The expected alsoKnownAs values after a two-value union.</summary>
    private static readonly string[] ExpectedAkaAAndB = ["did:web:aka-a", "did:web:aka-b"];


    /// <summary><c>setDidDocument</c> returns the supplied document wholesale, ignoring the current document.</summary>
    [TestMethod]
    public void SetReplacesDocumentWholesale()
    {
        DidDocument current = DocumentWith(Method("#key-1"));
        DidDocument replacement = DocumentWith(Method("#key-2"));

        DidDocument result = DidDocumentOperations.Apply(current, WellKnownDidRegistrationValues.SetDidDocument, replacement);

        Assert.AreSame(replacement, result, "setDidDocument must return the supplied document.");
        Assert.HasCount(1, result.VerificationMethod!);
        Assert.AreEqual("#key-2", result.VerificationMethod![0].Id);
    }


    /// <summary><c>setDidDocument</c> tolerates a null current document (there is nothing to merge into).</summary>
    [TestMethod]
    public void SetToleratesNullCurrent()
    {
        DidDocument replacement = DocumentWith(Method("#key-1"));

        DidDocument result = DidDocumentOperations.Apply(current: null, WellKnownDidRegistrationValues.SetDidDocument, replacement);

        Assert.AreSame(replacement, result);
    }


    /// <summary><c>addToDidDocument</c> unions verification methods by id and preserves the current id and context.</summary>
    [TestMethod]
    public void AddUnionsVerificationMethodsPreservingIdentity()
    {
        DidDocument current = DocumentWith(Method("#key-1"));
        current.Context = new Context { Contexts = [Context.DidCore11] };
        DidDocument additions = DocumentWith(Method("#key-2"));
        additions.Id = (GenericDidMethod)"did:web:other.example";

        DidDocument result = DidDocumentOperations.Apply(current, WellKnownDidRegistrationValues.AddToDidDocument, additions);

        Assert.AreEqual(Did, result.Id!.Id, "Add preserves the current document's id, not the payload's.");
        Assert.AreEqual(Context.DidCore11, result.Context!.Contexts![0], "Add preserves the current document's @context.");
        Assert.HasCount(2, result.VerificationMethod!);
        Assert.AreSequenceEqual(ExpectedKeyOneAndTwo, result.VerificationMethod!.Select(static method => method.Id).ToArray(), SequenceOrder.InAnyOrder);
    }


    /// <summary><c>addToDidDocument</c> is idempotent by id: re-adding an existing entry keeps the current one.</summary>
    [TestMethod]
    public void AddIsIdempotentById()
    {
        VerificationMethod existing = Method("#key-1");
        DidDocument current = DocumentWith(existing);
        DidDocument additions = DocumentWith(Method("#key-1"));

        DidDocument result = DidDocumentOperations.Apply(current, WellKnownDidRegistrationValues.AddToDidDocument, additions);

        Assert.HasCount(1, result.VerificationMethod!);
        Assert.AreSame(existing, result.VerificationMethod![0], "A duplicate id keeps the current entry, not the addition.");
    }


    /// <summary><c>addToDidDocument</c> unions relationships, services, controllers and alsoKnownAs by their identities.</summary>
    [TestMethod]
    public void AddUnionsAllArrayMembers()
    {
        var current = new DidDocument
        {
            Id = (GenericDidMethod)Did,
            Authentication = [new AuthenticationMethod("#key-1")],
            Service = [ServiceWith("#svc-1")],
            Controller = [new Controller("did:web:controller-a")],
            AlsoKnownAs = ["did:web:aka-a"]
        };

        var additions = new DidDocument
        {
            Id = (GenericDidMethod)Did,
            Authentication = [new AuthenticationMethod("#key-1"), new AuthenticationMethod("#key-2")],
            Service = [ServiceWith("#svc-2")],
            Controller = [new Controller("did:web:controller-b")],
            AlsoKnownAs = ["did:web:aka-a", "did:web:aka-b"]
        };

        DidDocument result = DidDocumentOperations.Apply(current, WellKnownDidRegistrationValues.AddToDidDocument, additions);

        Assert.AreSequenceEqual(ExpectedKeyOneAndTwo, result.Authentication!.Select(static reference => reference.Id).ToArray(), SequenceOrder.InAnyOrder);
        Assert.AreSequenceEqual(ExpectedServiceOneAndTwo, result.Service!.Select(static service => service.Id!.ToString()).ToArray(), SequenceOrder.InAnyOrder);
        Assert.AreSequenceEqual(ExpectedControllerAAndB, result.Controller!.Select(static controller => controller.Did).ToArray(), SequenceOrder.InAnyOrder);
        Assert.AreSequenceEqual(ExpectedAkaAAndB, result.AlsoKnownAs!, SequenceOrder.InAnyOrder);
    }


    /// <summary><c>removeFromDidDocument</c> drops the entries whose identity appears in the payload.</summary>
    [TestMethod]
    public void RemoveDropsEntriesById()
    {
        DidDocument current = DocumentWith(Method("#key-1"), Method("#key-2"));
        DidDocument removals = DocumentWith(Method("#key-1"));

        DidDocument result = DidDocumentOperations.Apply(current, WellKnownDidRegistrationValues.RemoveFromDidDocument, removals);

        Assert.HasCount(1, result.VerificationMethod!);
        Assert.AreEqual("#key-2", result.VerificationMethod![0].Id);
    }


    /// <summary>A <c>removeFromDidDocument</c> that empties an array makes that member absent (null), not an empty array.</summary>
    [TestMethod]
    public void RemoveEmptyingArrayYieldsNull()
    {
        DidDocument current = DocumentWith(Method("#key-1"));
        DidDocument removals = DocumentWith(Method("#key-1"));

        DidDocument result = DidDocumentOperations.Apply(current, WellKnownDidRegistrationValues.RemoveFromDidDocument, removals);

        Assert.IsNull(result.VerificationMethod, "An array emptied by removal becomes absent.");
        Assert.AreEqual(Did, result.Id!.Id, "Remove preserves the current document's id.");
    }


    /// <summary>A <c>removeFromDidDocument</c> naming an absent entry leaves the array unchanged.</summary>
    [TestMethod]
    public void RemoveOfAbsentEntryIsUnchanged()
    {
        DidDocument current = DocumentWith(Method("#key-1"));
        DidDocument removals = DocumentWith(Method("#key-absent"));

        DidDocument result = DidDocumentOperations.Apply(current, WellKnownDidRegistrationValues.RemoveFromDidDocument, removals);

        Assert.HasCount(1, result.VerificationMethod!);
        Assert.AreEqual("#key-1", result.VerificationMethod![0].Id);
    }


    /// <summary>Add does not mutate either input document.</summary>
    [TestMethod]
    public void ApplyDoesNotMutateInputs()
    {
        DidDocument current = DocumentWith(Method("#key-1"));
        DidDocument additions = DocumentWith(Method("#key-2"));

        _ = DidDocumentOperations.Apply(current, WellKnownDidRegistrationValues.AddToDidDocument, additions);

        Assert.HasCount(1, current.VerificationMethod!, "Apply must not mutate the current document.");
        Assert.HasCount(1, additions.VerificationMethod!, "Apply must not mutate the payload.");
    }


    /// <summary>The <c>deactivate</c> extension is a flow-level operation, not a document transform, and is rejected.</summary>
    [TestMethod]
    public void ApplyRejectsDeactivate()
    {
        DidDocument current = DocumentWith(Method("#key-1"));

        _ = Assert.ThrowsExactly<ArgumentException>(() =>
            DidDocumentOperations.Apply(current, WellKnownDidRegistrationValues.DeactivateOperation, current));
    }


    /// <summary>An unknown or method-specific operation is rejected.</summary>
    [TestMethod]
    public void ApplyRejectsUnknownOperation()
    {
        DidDocument current = DocumentWith(Method("#key-1"));

        _ = Assert.ThrowsExactly<ArgumentException>(() =>
            DidDocumentOperations.Apply(current, "methodSpecificOperation", current));
    }


    /// <summary>Apply requires a payload document.</summary>
    [TestMethod]
    public void ApplyRejectsNullPayload()
    {
        DidDocument current = DocumentWith(Method("#key-1"));

        _ = Assert.ThrowsExactly<ArgumentNullException>(() =>
            DidDocumentOperations.Apply(current, WellKnownDidRegistrationValues.SetDidDocument, payload: null!));
    }


    /// <summary>Add and remove require the current document (they transform it); a null current is rejected.</summary>
    [TestMethod]
    public void AddAndRemoveRequireCurrentDocument()
    {
        DidDocument payload = DocumentWith(Method("#key-1"));

        _ = Assert.ThrowsExactly<ArgumentNullException>(() =>
            DidDocumentOperations.Apply(current: null, WellKnownDidRegistrationValues.AddToDidDocument, payload));

        _ = Assert.ThrowsExactly<ArgumentNullException>(() =>
            DidDocumentOperations.Apply(current: null, WellKnownDidRegistrationValues.RemoveFromDidDocument, payload));
    }


    /// <summary>
    /// A multi-operation update applies its steps in order, threading each result into the next: the DIF example of
    /// <c>removeFromDidDocument</c> then <c>addToDidDocument</c> rotates a verification method.
    /// </summary>
    [TestMethod]
    public void SequenceAppliesStepsInOrder()
    {
        DidDocument current = DocumentWith(Method("#key-1"));
        DidDocument removal = DocumentWith(Method("#key-1"));
        DidDocument addition = DocumentWith(Method("#key-2"));

        DidDocument result = DidDocumentOperations.Apply(
            current,
            [
                new DidDocumentOperationStep(WellKnownDidRegistrationValues.RemoveFromDidDocument, removal),
                new DidDocumentOperationStep(WellKnownDidRegistrationValues.AddToDidDocument, addition)
            ]);

        Assert.HasCount(1, result.VerificationMethod!);
        Assert.AreEqual("#key-2", result.VerificationMethod![0].Id, "remove #key-1 then add #key-2 leaves only #key-2.");
    }


    /// <summary>
    /// A leading <c>setDidDocument</c> step ignores the current document and establishes the running document the
    /// later steps transform, so the sequence needs no current document.
    /// </summary>
    [TestMethod]
    public void SequenceLeadingSetIgnoresCurrent()
    {
        DidDocument replacement = DocumentWith(Method("#key-1"));
        DidDocument addition = DocumentWith(Method("#key-2"));

        DidDocument result = DidDocumentOperations.Apply(
            current: null,
            [
                new DidDocumentOperationStep(WellKnownDidRegistrationValues.SetDidDocument, replacement),
                new DidDocumentOperationStep(WellKnownDidRegistrationValues.AddToDidDocument, addition)
            ]);

        Assert.HasCount(2, result.VerificationMethod!);
        Assert.AreSequenceEqual(ExpectedKeyOneAndTwo, result.VerificationMethod!.Select(static method => method.Id).ToArray(), SequenceOrder.InAnyOrder);
    }


    /// <summary>A sequence with a leading add/remove still requires the current document.</summary>
    [TestMethod]
    public void SequenceLeadingAddRequiresCurrent()
    {
        DidDocument addition = DocumentWith(Method("#key-1"));

        _ = Assert.ThrowsExactly<ArgumentNullException>(() =>
            DidDocumentOperations.Apply(
                current: null,
                [new DidDocumentOperationStep(WellKnownDidRegistrationValues.AddToDidDocument, addition)]));
    }


    /// <summary>An empty operation sequence is rejected (an update has at least one didDocumentOperation).</summary>
    [TestMethod]
    public void SequenceRejectsEmpty()
    {
        DidDocument current = DocumentWith(Method("#key-1"));

        _ = Assert.ThrowsExactly<ArgumentException>(() =>
            DidDocumentOperations.Apply(current, []));
    }


    /// <summary>A null operation sequence is rejected.</summary>
    [TestMethod]
    public void SequenceRejectsNull()
    {
        DidDocument current = DocumentWith(Method("#key-1"));

        _ = Assert.ThrowsExactly<ArgumentNullException>(() =>
            DidDocumentOperations.Apply(current, operations: null!));
    }


    /// <summary>Builds a verification method with the given fragment id, controlled by the document subject.</summary>
    /// <param name="id">The verification method id (a fragment such as <c>#key-1</c>).</param>
    /// <returns>The verification method.</returns>
    private static VerificationMethod Method(string id)
    {
        return new VerificationMethod { Id = id, Controller = Did };
    }


    /// <summary>Builds a service with the given fragment id under the document subject.</summary>
    /// <param name="fragment">The service id fragment (such as <c>#svc-1</c>).</param>
    /// <returns>The service.</returns>
    private static Service ServiceWith(string fragment)
    {
        return new Service
        {
            Id = DidUrl.Parse(Did + fragment),
            Type = "ExampleService",
            ServiceEndpoint = "https://example.com/endpoint"
        };
    }


    /// <summary>Builds a minimal DID document for the test subject carrying the given verification methods.</summary>
    /// <param name="methods">The verification methods to place on the document.</param>
    /// <returns>The DID document.</returns>
    private static DidDocument DocumentWith(params VerificationMethod[] methods)
    {
        return new DidDocument
        {
            Id = (GenericDidMethod)Did,
            VerificationMethod = methods
        };
    }
}
