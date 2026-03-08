using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.Methods;
using Verifiable.Core.Resolvers;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Integration tests for <see cref="DidResolver"/> using realistic method handler registrations.
/// Covers the full dispatch path including <see cref="DidResolutionKind"/> discrimination,
/// <c>?service=</c> query parameter handling, fragment dereferencing, and <c>relativeRef</c> appending.
/// </summary>
[TestClass]
internal sealed class DidResolverIntegrationTests
{
    private const string ExampleDidPrefix = "did:example";

    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task ResolveWebDidReturnsDocumentUrlKind()
    {
        var resolver = CreateWebResolver();
        var result = await resolver.ResolveAsync(
            "did:web:example.com", cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual(DidResolutionKind.DocumentUrl, result.Kind);
        Assert.IsNull(result.Document);
        Assert.AreEqual("https://example.com/.well-known/did.json", result.DocumentUrl);
    }

    [TestMethod]
    public async Task ResolveWebDidWithPathReturnsCorrectUrl()
    {
        var resolver = CreateWebResolver();
        var result = await resolver.ResolveAsync(
            "did:web:example.com:users:alice", cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual(DidResolutionKind.DocumentUrl, result.Kind);
        Assert.AreEqual("https://example.com/users/alice/did.json", result.DocumentUrl);
    }

    [TestMethod]
    public async Task ResolveKeyDidReturnsDocumentKind()
    {
        var resolver = CreateKeyResolver();
        var result = await resolver.ResolveAsync(
            "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual(DidResolutionKind.Document, result.Kind);
        Assert.IsNotNull(result.Document);
        Assert.IsNull(result.DocumentUrl);
    }

    [TestMethod]
    public async Task DereferenceServiceQueryParameterReturnsEndpointUrl()
    {
        var resolver = CreateResolverWithServices(
            "did:example:passport123",
            new Service
            {
                Id = (DidUrl)"did:example:passport123#ProductPassport",
                Type = "ProductPassportService",
                ServiceEndpoint = "https://registry.example.com/passport"
            });

        var result = await resolver.DereferenceAsync(
            "did:example:passport123?service=ProductPassport",
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual("https://registry.example.com/passport", result.ContentStream as string);
    }

    [TestMethod]
    public async Task DereferenceServiceByTypeReturnsEndpointUrl()
    {
        var resolver = CreateResolverWithServices(
            "did:example:passport123",
            new Service
            {
                Id = (DidUrl)"did:example:passport123#passport-svc",
                Type = "ProductPassportService",
                ServiceEndpoint = "https://registry.example.com/passport"
            });

        var result = await resolver.DereferenceAsync(
            "did:example:passport123?service=ProductPassportService",
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual("https://registry.example.com/passport", result.ContentStream as string);
    }

    [TestMethod]
    public async Task DereferenceServiceWithRelativeRefAppendsPath()
    {
        var resolver = CreateResolverWithServices(
            "did:example:passport123",
            new Service
            {
                Id = (DidUrl)"did:example:passport123#ProductPassport",
                Type = "ProductPassportService",
                ServiceEndpoint = "https://registry.example.com/passport"
            });

        var result = await resolver.DereferenceAsync(
            "did:example:passport123?service=ProductPassport&relativeRef=/items/456",
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual("https://registry.example.com/passport/items/456", result.ContentStream as string);
    }

    [TestMethod]
    public async Task DereferenceUnknownServiceReturnsNotFound()
    {
        var resolver = CreateResolverWithServices(
            "did:example:passport123",
            new Service
            {
                Id = (DidUrl)"did:example:passport123#ProductPassport",
                Type = "ProductPassportService",
                ServiceEndpoint = "https://registry.example.com/passport"
            });

        var result = await resolver.DereferenceAsync(
            "did:example:passport123?service=UnknownService",
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.NotFound, result.DereferencingMetadata.Error);
    }

    [TestMethod]
    public async Task DereferenceFragmentResolvesVerificationMethod()
    {
        const string did = "did:example:123";
        const string keyId = "did:example:123#signing-key";

        var document = new DidDocument
        {
            Id = new GenericDidMethod(did),
            VerificationMethod =
            [
                new VerificationMethod { Id = keyId, Type = "Ed25519VerificationKey2020", Controller = did }
            ]
        };

        var resolver = CreateResolverReturning(did, document);

        var result = await resolver.DereferenceAsync(
            $"{did}#signing-key", cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        var method = result.ContentStream as VerificationMethod;
        Assert.IsNotNull(method);
        Assert.AreEqual(keyId, method.Id);
    }

    [TestMethod]
    public async Task DereferenceFragmentResolvesServiceById()
    {
        const string did = "did:example:456";

        var service = new Service
        {
            Id = (DidUrl)$"{did}#svc-1",
            Type = "LinkedDomains",
            ServiceEndpoint = "https://example.com"
        };

        var document = new DidDocument
        {
            Id = new GenericDidMethod(did),
            Service = [service]
        };

        var resolver = CreateResolverReturning(did, document);

        var result = await resolver.DereferenceAsync(
            $"{did}#svc-1", cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        var resolved = result.ContentStream as Service;
        Assert.IsNotNull(resolved);
        Assert.AreEqual("LinkedDomains", resolved.Type);
    }

    [TestMethod]
    public async Task DereferenceBaseDidWithoutFragmentReturnsDocument()
    {
        const string did = "did:example:789";
        var document = new DidDocument { Id = new GenericDidMethod(did) };
        var resolver = CreateResolverReturning(did, document);

        var result = await resolver.DereferenceAsync(
            did, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreSame(document, result.ContentStream);
    }

    [TestMethod]
    public async Task DereferenceDocumentUrlKindResultReturnsNotFound()
    {
        //A method that returns DocumentUrl cannot be dereferenced without a fetch step.
        var resolver = CreateWebResolver();

        var result = await resolver.DereferenceAsync(
            "did:web:example.com#key-1", cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.NotFound, result.DereferencingMetadata.Error);
    }

    //Helper methods at end of test class.

    private static DidResolver CreateWebResolver()
    {
        return new DidResolver(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.WebDidMethodPrefix, WebDidResolver.ResolveAsync)));
    }

    private static DidResolver CreateKeyResolver()
    {
        return new DidResolver(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, ResolveKeyDidAsync)));
    }

    private static DidResolver CreateResolverWithServices(string did, Service service)
    {
        var document = new DidDocument
        {
            Id = new GenericDidMethod(did),
            Service = [service]
        };

        return CreateResolverReturning(did, document);
    }

    private static DidResolver CreateResolverReturning(string did, DidDocument document)
    {
        //A DocumentStub carries the fixed document so the handler can be registered as
        //an instance method group without any closure over local variables.
        var stub = new DocumentStub(document);
        return new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, stub.ResolveAsync)));
    }

    private static ValueTask<DidResolutionResult> ResolveKeyDidAsync(
        string did,
        DidResolutionOptions options,
        CancellationToken cancellationToken)
    {
        //Minimal in-process document derivation used until a full did:key resolver is available.
        var document = new DidDocument { Id = new KeyDidMethod(did) };
        return ValueTask.FromResult(DidResolutionResult.Success(document, DidDocumentMetadata.Empty));
    }

    /// <summary>
    /// Carries a fixed <see cref="DidDocument"/> for test resolver stubs without using closures.
    /// The document is injected at construction and flows to <see cref="ResolveAsync"/>
    /// through the instance rather than through a captured variable.
    /// </summary>
    private sealed class DocumentStub(DidDocument document)
    {
        private DidDocument Document { get; } = document;

        public ValueTask<DidResolutionResult> ResolveAsync(
            string did,
            DidResolutionOptions options,
            CancellationToken cancellationToken)
        {
            return ValueTask.FromResult(
                DidResolutionResult.Success(Document, DidDocumentMetadata.Empty));
        }
    }
}
