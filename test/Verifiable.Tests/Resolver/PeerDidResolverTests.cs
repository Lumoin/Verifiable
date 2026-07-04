using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Resolvers;
using Verifiable.Core.Did.Methods.Peer;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="PeerDidResolver"/> covering <c>did:peer:2</c> resolution against the
/// Peer DID Method specification golden vector, the unsupported numalgos, and malformed input.
/// </summary>
[TestClass]
internal sealed class PeerDidResolverTests
{
    //The numalgo 2 golden vector from the Peer DID Method specification (§ Resolving a did:peer:2):
    //purpose V (authentication) key, purpose E (keyAgreement) key, and two DIDCommMessaging services.
    private const string GoldenVectorDid =
        "did:peer:2"
        + ".Vz6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc"
        + ".Ez6LSg8zQom395jKLrGiBNruB9MM6V8PWuf2FpEy4uRFiqQBR"
        + ".SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9kaWRjb21tIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0xIl19fQ"
        + ".SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9hbm90aGVyIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0yIl19fQ";

    //A single purpose-V (authentication) inception key, used by did:key examples.
    private const string SingleAuthenticationKeyDid =
        "did:peer:2.Vz6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc";

    private static readonly ExchangeContext ResolutionContext = new();

    public TestContext TestContext { get; set; } = null!;


    private static DidResolver CreateResolver() =>
        new(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.PeerDidMethodPrefix, PeerDidResolver.Build(BaseMemoryPool.Shared, DeserializeDidDocument))));


    //The did:peer:4 embedded document is deserialized by the JSON layer; Verifiable.Core never parses it.
    private static DidDocument? DeserializeDidDocument(ReadOnlySpan<byte> jsonUtf8)
    {
        try
        {
            return JsonSerializerExtensions.Deserialize<DidDocument>(Encoding.UTF8.GetString(jsonUtf8), TestSetup.DefaultSerializationOptions);
        }
        catch(JsonException)
        {
            return null;
        }
    }


    [TestMethod]
    public async Task ResolvePeer4LongFormProducesContextualizedDocument()
    {
        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(PeerDid4TestVectors.TutorialLongForm, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual(DidResolutionKind.Document, result.Kind);
        var document = result.Document;
        Assert.IsNotNull(document);

        //Contextualized: the root id is the long-form DID, alsoKnownAs gains the short form.
        Assert.AreEqual(PeerDid4TestVectors.TutorialLongForm, document.Id!.Id);
        Assert.IsNotNull(document.AlsoKnownAs);
        Assert.HasCount(1, document.AlsoKnownAs!);
        Assert.AreEqual(PeerDid4TestVectors.TutorialShortForm, document.AlsoKnownAs![0]);

        //Two verification methods, each with controller defaulted to the DID, in document order.
        Assert.IsNotNull(document.VerificationMethod);
        Assert.HasCount(2, document.VerificationMethod!);

        var keyAgreementVm = document.VerificationMethod![0];
        Assert.AreEqual("#6LSqPZfn", keyAgreementVm.Id);
        Assert.AreEqual("X25519KeyAgreementKey2020", keyAgreementVm.Type);
        Assert.AreEqual(PeerDid4TestVectors.TutorialLongForm, keyAgreementVm.Controller);
        Assert.AreEqual("z6LSqPZfn9krvgXma2icTMKf2uVcYhKXsudCmPoUzqGYW24U", ((PublicKeyMultibase)keyAgreementVm.KeyFormat!).Key);

        var signingVm = document.VerificationMethod![1];
        Assert.AreEqual("#6MkrCD1c", signingVm.Id);
        Assert.AreEqual("Ed25519VerificationKey2020", signingVm.Type);
        Assert.AreEqual(PeerDid4TestVectors.TutorialLongForm, signingVm.Controller);

        //Verification relationships are preserved as relative references.
        Assert.AreEqual("#6MkrCD1c", document.Authentication![0].Id);
        Assert.AreEqual("#6LSqPZfn", document.KeyAgreement![0].Id);
        Assert.AreEqual("#6MkrCD1c", document.AssertionMethod![0].Id);
        Assert.AreEqual("#6MkrCD1c", document.CapabilityInvocation![0].Id);
        Assert.AreEqual("#6MkrCD1c", document.CapabilityDelegation![0].Id);

        //The service is preserved.
        Assert.IsNotNull(document.Service);
        Assert.HasCount(1, document.Service!);
        Assert.AreEqual("#didcommmessaging-0", document.Service![0].Id!.ToString());
        Assert.AreEqual("DIDCommMessaging", document.Service![0].Type);
    }


    [TestMethod]
    public async Task ResolvePeer4ShortFormReturnsNotFound()
    {
        //The short form carries no embedded document; it cannot be resolved without the long form.
        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(PeerDid4TestVectors.TutorialShortForm, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.NotFound, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task ResolvePeer4TamperedDocumentReturnsInvalidDid()
    {
        //Altering one character of the encoded document breaks the embedded SHA2-256 hash binding.
        string longForm = PeerDid4TestVectors.TutorialLongForm;
        string tampered = string.Concat(longForm.AsSpan(0, longForm.Length - 1), longForm[^1] == 'z' ? "y" : "z");

        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(tampered, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task ResolvePeer4InvalidHashPortionReturnsInvalidDid()
    {
        //'0', 'O', 'I', 'l' are not in the base58btc alphabet, so the hash portion cannot be decoded.
        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(
            "did:peer:4z0OIl:z2M1k7h4psgp4CmJcnQn2Ljp7Pz7ktsd7oBhMU3dWY5s4fhFNj17qcRTQ",
            ResolutionContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task ResolvePeer4DefaultsControllerOnEmbeddedVerificationMethods()
    {
        //Verification methods embedded directly inside relationships must have their omitted controller
        //defaulted to the DID (spec "Resolving a DID" step 4). The deserializer seam supplies the document
        //shape while the authoritative Tutorial vector drives the real hash and decode.
        var embeddedDocument = new DidDocument
        {
            Authentication = [new AuthenticationMethod(new VerificationMethod { Id = "#key-1", Type = "Multikey" })],
            KeyAgreement = [new KeyAgreementMethod(new VerificationMethod { Id = "#key-2", Type = "Multikey" })]
        };

        var resolver = ResolverReturning(embeddedDocument);
        var result = await resolver.ResolveAsync(PeerDid4TestVectors.TutorialLongForm, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        var document = result.Document;
        Assert.IsNotNull(document);

        var embeddedAuthentication = document.Authentication![0].EmbeddedVerification;
        Assert.IsNotNull(embeddedAuthentication);
        Assert.AreEqual("#key-1", embeddedAuthentication.Id);
        Assert.AreEqual(PeerDid4TestVectors.TutorialLongForm, embeddedAuthentication.Controller);

        var embeddedKeyAgreement = document.KeyAgreement![0].EmbeddedVerification;
        Assert.IsNotNull(embeddedKeyAgreement);
        Assert.AreEqual("#key-2", embeddedKeyAgreement.Id);
        Assert.AreEqual(PeerDid4TestVectors.TutorialLongForm, embeddedKeyAgreement.Controller);
    }


    [TestMethod]
    public async Task ResolvePeer4PreservesExplicitForeignController()
    {
        //An explicit (non-owner) controller is left untouched; only an omitted one is defaulted to the DID.
        var document = new DidDocument
        {
            VerificationMethod =
            [
                new VerificationMethod { Id = "#key-1", Type = "Multikey", Controller = "did:example:other" },
                new VerificationMethod { Id = "#key-2", Type = "Multikey" }
            ]
        };

        var resolver = ResolverReturning(document);
        var result = await resolver.ResolveAsync(PeerDid4TestVectors.TutorialLongForm, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        var resolved = result.Document;
        Assert.IsNotNull(resolved);
        Assert.HasCount(2, resolved.VerificationMethod!);
        Assert.AreEqual("did:example:other", resolved.VerificationMethod![0].Controller);
        Assert.AreEqual(PeerDid4TestVectors.TutorialLongForm, resolved.VerificationMethod![1].Controller);
    }


    [TestMethod]
    public async Task ResolvePeer4AppendsShortFormToExistingAlsoKnownAs()
    {
        //A pre-existing alsoKnownAs is preserved; the short form is appended, not replaced.
        var document = new DidDocument
        {
            AlsoKnownAs = ["did:example:prior"],
            VerificationMethod = [new VerificationMethod { Id = "#key-1", Type = "Multikey" }]
        };

        var resolver = ResolverReturning(document);
        var result = await resolver.ResolveAsync(PeerDid4TestVectors.TutorialLongForm, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        var resolved = result.Document;
        Assert.IsNotNull(resolved);
        Assert.HasCount(2, resolved.AlsoKnownAs!);
        Assert.AreEqual("did:example:prior", resolved.AlsoKnownAs![0]);
        Assert.AreEqual(PeerDid4TestVectors.TutorialShortForm, resolved.AlsoKnownAs![1]);
    }


    [TestMethod]
    public async Task ResolvePeer4NullDeserializerReturnsInvalidDidDocument()
    {
        //A hash-valid long form whose embedded payload is not a DID document (deserializer returns null)
        //surfaces InvalidDidDocument, the sole producer of that error.
        var resolver = ResolverReturning(null);
        var result = await resolver.ResolveAsync(PeerDid4TestVectors.TutorialLongForm, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.InvalidDidDocument, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task ResolvePeer4ThrowingDeserializerFailsClosedAsInvalidDidDocument()
    {
        //A throwing deserializer is a closed InvalidDidDocument failure, not an escaping fault that the
        //DidResolver maps to InternalError.
        var resolver = new DidResolver(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.PeerDidMethodPrefix, PeerDidResolver.Build(BaseMemoryPool.Shared, ThrowingDeserializer))));

        var result = await resolver.ResolveAsync(PeerDid4TestVectors.TutorialLongForm, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.InvalidDidDocument, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task ResolvePeer4EmptyHashOrEncodedPortionReturnsInvalidDid()
    {
        //The long form is "did:peer:4{hash}:{encoded}" with both portions non-empty.
        var resolver = CreateResolver();
        string encodedPart = PeerDid4TestVectors.TutorialLongForm[(PeerDid4TestVectors.TutorialShortForm.Length + 1)..];

        string[] degenerate =
        [
            $"{PeerDid4TestVectors.TutorialShortForm}:",
            $"did:peer:4:{encodedPart}"
        ];

        foreach(string did in degenerate)
        {
            var result = await resolver.ResolveAsync(did, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccessful, did);
            Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error, did);
        }
    }


    private static DidDocument? ThrowingDeserializer(ReadOnlySpan<byte> didDocumentJsonUtf8) =>
        throw new InvalidOperationException("Simulated deserializer failure.");


    //Wires a resolver whose did:peer:4 deserializer returns a fixed document, so a test can exercise the
    //contextualize step on any document shape while the real hash and decode run over the Tutorial vector.
    private static DidResolver ResolverReturning(DidDocument? document) =>
        new(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.PeerDidMethodPrefix,
             PeerDidResolver.Build(BaseMemoryPool.Shared, new ConstantDocumentDeserializer(document).Deserialize))));


    private sealed class ConstantDocumentDeserializer(DidDocument? document)
    {
        public DidDocument? Deserialize(ReadOnlySpan<byte> didDocumentJsonUtf8) => document;
    }


    [TestMethod]
    public async Task ResolveNumalgo2GoldenVectorProducesSpecifiedDocument()
    {
        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(GoldenVectorDid, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual(DidResolutionKind.Document, result.Kind);

        var document = result.Document;
        Assert.IsNotNull(document);

        //The document id is the full DID.
        Assert.AreEqual(GoldenVectorDid, document.Id!.Id);

        //Context is the DID core context followed by the Multikey context, in order.
        Assert.IsNotNull(document.Context);
        Assert.IsNotNull(document.Context!.Contexts);
        Assert.HasCount(2, document.Context.Contexts!);
        Assert.AreEqual(Context.DidCore10, document.Context.Contexts![0]);
        Assert.AreEqual(Context.Multikey10, document.Context.Contexts![1]);

        //Two Multikey verification methods with relative #key-N ids and the full DID as controller;
        //the publicKeyMultibase is the encoded key from the DID string, re-canonicalized identically.
        Assert.IsNotNull(document.VerificationMethod);
        Assert.HasCount(2, document.VerificationMethod!);

        var key1 = document.VerificationMethod![0];
        Assert.AreEqual("#key-1", key1.Id);
        Assert.AreEqual("Multikey", key1.Type);
        Assert.AreEqual(GoldenVectorDid, key1.Controller);
        Assert.AreEqual("z6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc", ((PublicKeyMultibase)key1.KeyFormat!).Key);

        var key2 = document.VerificationMethod![1];
        Assert.AreEqual("#key-2", key2.Id);
        Assert.AreEqual("Multikey", key2.Type);
        Assert.AreEqual(GoldenVectorDid, key2.Controller);
        Assert.AreEqual("z6LSg8zQom395jKLrGiBNruB9MM6V8PWuf2FpEy4uRFiqQBR", ((PublicKeyMultibase)key2.KeyFormat!).Key);

        //V → authentication(#key-1), E → keyAgreement(#key-2); the unused relationships stay absent.
        Assert.IsNotNull(document.Authentication);
        Assert.HasCount(1, document.Authentication!);
        Assert.AreEqual("#key-1", document.Authentication![0].Id);

        Assert.IsNotNull(document.KeyAgreement);
        Assert.HasCount(1, document.KeyAgreement!);
        Assert.AreEqual("#key-2", document.KeyAgreement![0].Id);

        Assert.IsNull(document.AssertionMethod);
        Assert.IsNull(document.CapabilityInvocation);
        Assert.IsNull(document.CapabilityDelegation);

        //Two DIDCommMessaging services with the positional default ids #service and #service-1; the
        //abbreviated keys (t/s/a/r) and the dm type are expanded.
        Assert.IsNotNull(document.Service);
        Assert.HasCount(2, document.Service!);

        var service0 = document.Service![0];
        Assert.AreEqual("#service", service0.Id!.ToString());
        Assert.AreEqual("DIDCommMessaging", service0.Type);
        Assert.IsNotNull(service0.ServiceEndpointMap);
        Assert.AreEqual("http://example.com/didcomm", service0.ServiceEndpointMap!["uri"]);

        var accept0 = (List<string>)service0.ServiceEndpointMap!["accept"];
        Assert.HasCount(1, accept0);
        Assert.AreEqual("didcomm/v2", accept0[0]);

        var routing0 = (List<string>)service0.ServiceEndpointMap!["routingKeys"];
        Assert.HasCount(1, routing0);
        Assert.AreEqual("did:example:123456789abcdefghi#key-1", routing0[0]);

        var service1 = document.Service![1];
        Assert.AreEqual("#service-1", service1.Id!.ToString());
        Assert.AreEqual("DIDCommMessaging", service1.Type);
        Assert.AreEqual("http://example.com/another", service1.ServiceEndpointMap!["uri"]);

        var routing1 = (List<string>)service1.ServiceEndpointMap!["routingKeys"];
        Assert.HasCount(1, routing1);
        Assert.AreEqual("did:example:123456789abcdefghi#key-2", routing1[0]);
    }


    [TestMethod]
    public async Task ResolveNumalgo2SingleAuthenticationKeyMapsOnlyAuthentication()
    {
        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(SingleAuthenticationKeyDid, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        var document = result.Document;
        Assert.IsNotNull(document);

        Assert.IsNotNull(document.VerificationMethod);
        Assert.HasCount(1, document.VerificationMethod!);
        Assert.AreEqual("#key-1", document.VerificationMethod![0].Id);

        Assert.IsNotNull(document.Authentication);
        Assert.HasCount(1, document.Authentication!);
        Assert.AreEqual("#key-1", document.Authentication![0].Id);

        Assert.IsNull(document.KeyAgreement);
        Assert.IsNull(document.Service);
    }


    /// <summary>
    /// Per the Peer DID Method specification (§ Method Specific Identifier) peer DIDs MUST be compared
    /// case-sensitively and MUST NOT be case-normalized. Resolution preserves the identifier's exact case,
    /// and two identifiers differing only in case are distinct values rather than folded together.
    /// </summary>
    [TestMethod]
    public async Task ResolveNumalgo2PreservesCaseAndTreatsCaseVariantsAsDistinct()
    {
        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(GoldenVectorDid, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        var document = result.Document;
        Assert.IsNotNull(document);

        //A case-altered variant of the same DID, keeping the lowercase "did:peer:" method prefix intact so
        //only the method-specific identifier differs by case.
        string caseVariantDid = PeerDidMethod.Prefix + GoldenVectorDid[PeerDidMethod.Prefix.Length..].ToUpperInvariant();

        //The resolved id is the input verbatim (mixed case), NOT the case-folded variant: the resolver does
        //not case-normalize the identifier.
        Assert.AreEqual(GoldenVectorDid, document.Id!.Id);
        Assert.AreNotEqual(caseVariantDid, document.Id!.Id);

        //Identity is value-based and ordinal: the same-cased identifier is equal, but the case-altered
        //variant is a distinct identifier — peer DIDs are compared case-sensitively.
        var original = new PeerDidMethod(GoldenVectorDid);
        var sameCase = new PeerDidMethod(GoldenVectorDid);
        var caseVariant = new PeerDidMethod(caseVariantDid);
        Assert.AreEqual(original, sameCase);
        Assert.AreNotEqual(original, caseVariant);
    }


    [TestMethod]
    public async Task ResolveNumalgo0ReturnsMethodNotSupported()
    {
        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(
            "did:peer:0z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            ResolutionContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.MethodNotSupported, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task ResolveNumalgo1ReturnsMethodNotSupported()
    {
        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(
            "did:peer:1zQmZMygzYqNwU6Uhmewx5Xepf2VLp5S4HLSwwgf2aiKZuwa",
            ResolutionContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.MethodNotSupported, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task ResolveUnknownNumalgoReturnsInvalidDid()
    {
        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(
            "did:peer:9.Vz6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc",
            ResolutionContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task ResolveUnknownPurposeCodeReturnsInvalidDid()
    {
        //Purpose code 'X' is not a key purpose (V/A/E/I/D) and is not the service code 'S'.
        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(
            "did:peer:2.Xz6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc",
            ResolutionContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task ResolveMalformedKeyReturnsInvalidDid()
    {
        //A valid purpose code V followed by a value that is not a decodable multibase key.
        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(
            "did:peer:2.Vnotavalidmultibasekey",
            ResolutionContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task ResolveServiceWithoutTypeReturnsInvalidDid()
    {
        //".Se30" is base64url("{}"): a well-formed but typeless service object, which a peer service
        //block must not be.
        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(
            "did:peer:2.Vz6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc.Se30",
            ResolutionContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task ResolveNumalgo2MapsEveryPurposeCodeToItsRelationship()
    {
        //One key per key-purpose code in DID-string order: A, E, V, I, D. This pins all five mappings
        //(a transposition would otherwise survive a suite that only exercises V and E).
        string did = "did:peer:2"
            + ".A" + AuthenticationKey
            + ".E" + KeyAgreementKey
            + ".V" + AuthenticationKey
            + ".I" + AuthenticationKey
            + ".D" + AuthenticationKey;

        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(did, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        var document = result.Document;
        Assert.IsNotNull(document);
        Assert.HasCount(5, document.VerificationMethod!);

        Assert.AreEqual("#key-1", document.AssertionMethod![0].Id);
        Assert.AreEqual("#key-2", document.KeyAgreement![0].Id);
        Assert.AreEqual("#key-3", document.Authentication![0].Id);
        Assert.AreEqual("#key-4", document.CapabilityInvocation![0].Id);
        Assert.AreEqual("#key-5", document.CapabilityDelegation![0].Id);
    }


    [TestMethod]
    public async Task ResolveServiceWithExplicitIdPreservesItAndDoesNotConsumePositionalSlot()
    {
        string did = "did:peer:2.V" + AuthenticationKey
            + ServiceSegment("{\"t\":\"dm\",\"s\":\"https://example.com/explicit\",\"id\":\"#agent\"}")
            + ServiceSegment("{\"t\":\"dm\",\"s\":\"https://example.com/default\"}");

        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(did, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        var document = result.Document;
        Assert.IsNotNull(document);
        Assert.HasCount(2, document.Service!);

        //The explicit id is preserved verbatim; an id-bearing service must not consume a positional
        //slot, so the following id-less service is still #service (not #service-1).
        Assert.AreEqual("#agent", document.Service![0].Id!.ToString());
        Assert.AreEqual("#service", document.Service![1].Id!.ToString());
    }


    [TestMethod]
    public async Task ResolveServiceWithMalformedIdReturnsInvalidDid()
    {
        //"foo" is neither an absolute DID URL nor a fragment reference, so the service id is malformed.
        string did = "did:peer:2.V" + AuthenticationKey
            + ServiceSegment("{\"t\":\"dm\",\"id\":\"foo\"}");

        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(did, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task ResolveThreeIdlessServicesNumbersThemSequentially()
    {
        string service = "{\"t\":\"dm\",\"s\":\"https://example.com/ep\"}";
        string did = "did:peer:2.V" + AuthenticationKey
            + ServiceSegment(service) + ServiceSegment(service) + ServiceSegment(service);

        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(did, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        var document = result.Document;
        Assert.IsNotNull(document);
        Assert.HasCount(3, document.Service!);
        Assert.AreEqual("#service", document.Service![0].Id!.ToString());
        Assert.AreEqual("#service-1", document.Service![1].Id!.ToString());
        Assert.AreEqual("#service-2", document.Service![2].Id!.ToString());
    }


    [TestMethod]
    public async Task ResolveStringServiceEndpointWithNonDidCommTypePassesTypeThroughVerbatim()
    {
        string did = "did:peer:2.V" + AuthenticationKey
            + ServiceSegment("{\"t\":\"LinkedDomains\",\"s\":\"https://example.com/ep\"}");

        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(did, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        var service = result.Document!.Service![0];

        //A non-dm type is carried verbatim; a string endpoint populates ServiceEndpoint, not the map.
        Assert.AreEqual("LinkedDomains", service.Type);
        Assert.AreEqual("https://example.com/ep", service.ServiceEndpoint);
        Assert.IsNull(service.ServiceEndpointMap);
    }


    [TestMethod]
    public async Task ResolveServiceEndpointDecodesJsonStringEscapes()
    {
        //The uri carries an escaped solidus (\/) and a \uXXXX escape; both must be decoded.
        string did = "did:peer:2.V" + AuthenticationKey
            + ServiceSegment("{\"t\":\"dm\",\"s\":{\"uri\":\"a\\/b\\u0041c\"}}");

        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(did, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        var service = result.Document!.Service![0];
        Assert.AreEqual("a/bAc", service.ServiceEndpointMap!["uri"]);
    }


    [TestMethod]
    public async Task ResolveInterleavedKeysAndServicesNumberCountersIndependently()
    {
        //Key/service interleaving must not let a service advance the key counter or vice versa.
        string service = "{\"t\":\"dm\",\"s\":\"https://example.com/ep\"}";
        string did = "did:peer:2.V" + AuthenticationKey + ServiceSegment(service)
            + ".E" + KeyAgreementKey + ServiceSegment(service);

        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(did, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        var document = result.Document!;
        Assert.HasCount(2, document.VerificationMethod!);
        Assert.AreEqual("#key-1", document.VerificationMethod![0].Id);
        Assert.AreEqual("#key-2", document.VerificationMethod![1].Id);
        Assert.AreEqual("#key-1", document.Authentication![0].Id);
        Assert.AreEqual("#key-2", document.KeyAgreement![0].Id);
        Assert.HasCount(2, document.Service!);
        Assert.AreEqual("#service", document.Service![0].Id!.ToString());
        Assert.AreEqual("#service-1", document.Service![1].Id!.ToString());
    }


    [TestMethod]
    public async Task ResolveUndecodableServiceBase64ReturnsInvalidDid()
    {
        //'!' is outside the base64url alphabet, so the service value cannot be decoded.
        string did = "did:peer:2.V" + AuthenticationKey + ".S!!!";

        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(did, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>
    /// Per the Peer DID Method specification (§ Generating a did:peer:2) each service is encoded
    /// individually as its own base64url <c>.S</c> element; a service MUST NOT be encoded as a JSON list.
    /// A <c>.S</c> element whose bytes decode to a JSON array — even one wrapping an otherwise valid
    /// service object — is not a valid service encoding and must fail closed as an invalid DID.
    /// </summary>
    [TestMethod]
    public async Task ResolveServiceEncodedAsJsonListReturnsInvalidDid()
    {
        //The wrapped object resolves when encoded on its own (see the id-less service tests); wrapping the
        //same object in a JSON array is the specific violation and must be rejected.
        string did = "did:peer:2.V" + AuthenticationKey
            + ServiceSegment("[{\"t\":\"dm\",\"s\":\"https://example.com/ep\"}]");

        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(did, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task ResolveDegenerateElementStructureReturnsInvalidDid()
    {
        //The numalgo-2 ABNF is "did:peer:2" 1*element with element = "." <non-empty body>: zero
        //elements, a trailing dot, and a doubled dot are all syntactically invalid.
        var resolver = CreateResolver();

        string[] degenerate =
        [
            "did:peer:2",
            "did:peer:2.",
            "did:peer:2.." + AuthenticationKey,
            "did:peer:2.V" + AuthenticationKey + "."
        ];

        foreach(string did in degenerate)
        {
            var result = await resolver.ResolveAsync(did, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccessful, did);
            Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error, did);
        }
    }


    //The golden-vector keys, reused as decodable multibase keys when exercising purpose-code mappings:
    //AuthenticationKey is Ed25519 (z6Mk...), KeyAgreementKey is X25519 (z6LS...).
    private const string AuthenticationKey = "z6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc";
    private const string KeyAgreementKey = "z6LSg8zQom395jKLrGiBNruB9MM6V8PWuf2FpEy4uRFiqQBR";


    //Builds a numalgo-2 service element (".S" + base64url-nopad of the service JSON object).
    private static string ServiceSegment(string serviceJson) =>
        ".S" + Base64Url.EncodeToString(Encoding.UTF8.GetBytes(serviceJson));
}
