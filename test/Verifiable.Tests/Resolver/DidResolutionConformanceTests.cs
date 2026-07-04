using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Resolvers;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Conformance tests for the abstract <c>resolve()</c> and <c>dereference()</c> contracts of
/// <see cref="DidResolver"/> as specified by the W3C DID Resolution algorithms — the metadata
/// shapes, the <c>expandRelativeUrls</c> post-processing, and the failure-result invariants that
/// the method-specific resolver tests do not exercise directly.
/// </summary>
/// <remarks>
/// See <see href="https://www.w3.org/TR/did-resolution/#resolving">DID Resolution §4.4 resolve()</see>
/// and <see href="https://www.w3.org/TR/did-resolution/#dereferencing-algorithm">§5.4 dereference()</see>.
/// </remarks>
[TestClass]
internal sealed class DidResolutionConformanceTests
{
    /// <summary>Prefix used for the test-only DID method dispatched in these tests.</summary>
    private const string ExampleDidPrefix = "did:example";

    /// <summary>The DID subject the test documents are built for.</summary>
    private const string ExampleDid = "did:example:123";

    /// <summary>A default context; this layer does no network I/O.</summary>
    private static readonly ExchangeContext Context = new();

    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task ExpandRelativeUrlsRewritesRelativeVerificationMethodId()
    {
        //DID Resolution §4.4 step 6: a relative verification method id (#fragment) is expanded to
        //an absolute DID URL against the resolved DID.
        var document = new DidDocument
        {
            Id = new GenericDidMethod(ExampleDid),
            VerificationMethod =
            [
                new VerificationMethod { Id = "#key-1", Type = "Multikey", Controller = ExampleDid }
            ]
        };

        var result = await ResolveExpandingAsync(document).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual($"{ExampleDid}#key-1", result.Document!.VerificationMethod![0].Id);
    }

    [TestMethod]
    public async Task ExpandRelativeUrlsRewritesRelativeServiceId()
    {
        var document = new DidDocument
        {
            Id = new GenericDidMethod(ExampleDid),
            Service =
            [
                new Service { Id = (DidUrl)"#svc-1", Type = "LinkedDomains", ServiceEndpoint = "https://example.com" }
            ]
        };

        var result = await ResolveExpandingAsync(document).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual($"{ExampleDid}#svc-1", result.Document!.Service![0].Id!.ToString());
    }

    [TestMethod]
    public async Task ExpandRelativeUrlsRewritesRelativeRelationshipReferences()
    {
        //§4.4 step 6 names the verification relationships alongside services and verification
        //methods; a by-reference relative fragment in a relationship array is expanded too.
        var document = new DidDocument
        {
            Id = new GenericDidMethod(ExampleDid),
            VerificationMethod =
            [
                new VerificationMethod { Id = "#key-1", Type = "Multikey", Controller = ExampleDid }
            ],
            Authentication = [new AuthenticationMethod("#key-1")],
            AssertionMethod = [new AssertionMethod("#key-1")]
        };

        var result = await ResolveExpandingAsync(document).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual($"{ExampleDid}#key-1", result.Document!.Authentication![0].Id);
        Assert.AreEqual($"{ExampleDid}#key-1", result.Document!.AssertionMethod![0].Id);
    }

    [TestMethod]
    public async Task ExpandRelativeUrlsLeavesAbsoluteIdsUnchanged()
    {
        string absoluteVmId = $"{ExampleDid}#key-1";
        var document = new DidDocument
        {
            Id = new GenericDidMethod(ExampleDid),
            VerificationMethod =
            [
                new VerificationMethod { Id = absoluteVmId, Type = "Multikey", Controller = ExampleDid }
            ],
            Authentication = [new AuthenticationMethod(absoluteVmId)]
        };

        var result = await ResolveExpandingAsync(document).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual(absoluteVmId, result.Document!.VerificationMethod![0].Id);
        Assert.AreEqual(absoluteVmId, result.Document!.Authentication![0].Id);
    }

    [TestMethod]
    public async Task WithoutExpandOptionRelativeIdsAreLeftUnchanged()
    {
        var document = new DidDocument
        {
            Id = new GenericDidMethod(ExampleDid),
            VerificationMethod =
            [
                new VerificationMethod { Id = "#key-1", Type = "Multikey", Controller = ExampleDid }
            ],
            Authentication = [new AuthenticationMethod("#key-1")]
        };

        var stub = new DocumentStub(document);
        var resolver = new DidResolver(DidMethodSelectors.FromResolvers((ExampleDidPrefix, stub.ResolveAsync)));

        //No ExpandRelativeUrls option: the document is returned verbatim.
        var result = await resolver.ResolveAsync(
            ExampleDid, Context, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual("#key-1", result.Document!.VerificationMethod![0].Id);
        Assert.AreEqual("#key-1", result.Document!.Authentication![0].Id);
    }

    [TestMethod]
    public async Task ResolveFailureReturnsNullDocumentAndEmptyDocumentMetadata()
    {
        //§4.4: on every failure the didDocument is null and the didDocumentMetadata is empty.
        var resolver = new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, ResolveReturnsNotFoundAsync)));

        var result = await resolver.ResolveAsync(
            ExampleDid, Context, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.IsNull(result.Document);
        Assert.AreSame(DidDocumentMetadata.Empty, result.DocumentMetadata);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.NotFound, result.ResolutionMetadata.Error);
    }

    [TestMethod]
    public async Task DereferenceFailureReturnsNullContentStreamAndMetadata()
    {
        //§5.4: on every failure the contentStream is null and the contentMetadata is empty.
        var resolver = new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, ResolveReturnsNotFoundAsync)));

        var result = await resolver.DereferenceAsync(
            $"{ExampleDid}#key-1", Context, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.IsNull(result.ContentStream);
        Assert.IsNull(result.ContentMetadata);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.NotFound, result.DereferencingMetadata.Error);
    }

    [TestMethod]
    public async Task ResolveSurfacesMethodResolverNotFound()
    {
        //§4.4 step 5: a NOT_FOUND returned by the method's Read operation surfaces unchanged.
        var resolver = new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, ResolveReturnsNotFoundAsync)));

        var result = await resolver.ResolveAsync(
            ExampleDid, Context, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.NotFound, result.ResolutionMetadata.Error);
    }

    [TestMethod]
    public async Task ResolveRejectsDocumentWhoseIdDoesNotMatchTheResolvedDid()
    {
        //§4.4 step 5.3 (MUST): the resolved document's id MUST be string equal to the DID that was
        //resolved. A method resolver that returns a document for a different DID is malformed, so the
        //generic layer fails closed with invalidDidDocument rather than surfacing the wrong document.
        var document = new DidDocument { Id = new GenericDidMethod("did:example:999") };
        var stub = new DocumentStub(document);
        var resolver = new DidResolver(DidMethodSelectors.FromResolvers((ExampleDidPrefix, stub.ResolveAsync)));

        var result = await resolver.ResolveAsync(
            ExampleDid, Context, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.IsNull(result.Document);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.InvalidDidDocument, result.ResolutionMetadata.Error);
    }

    [TestMethod]
    public async Task DereferenceRejectsServiceEndpointThatAlreadyContainsFragment()
    {
        //§5.4.2 step 2.1 (MUST): if the selected service endpoint URL contains a fragment component,
        //raise an error rather than append the DID URL fragment (which would yield two fragments).
        var document = new DidDocument
        {
            Id = new GenericDidMethod(ExampleDid),
            Service =
            [
                new Service { Id = (DidUrl)$"{ExampleDid}#svc-1", Type = "LinkedDomains", ServiceEndpoint = "https://example.com/path#existing" }
            ]
        };

        var stub = new DocumentStub(document);
        var resolver = new DidResolver(DidMethodSelectors.FromResolvers((ExampleDidPrefix, stub.ResolveAsync)));

        var result = await resolver.DereferenceAsync(
            $"{ExampleDid}?service=svc-1#frag", Context, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.InvalidDidDocument, result.DereferencingMetadata.Error);
    }

    //Helper methods at end of test class.

    /// <summary>
    /// Resolves <paramref name="document"/> with the <c>expandRelativeUrls</c> option enabled,
    /// driving the §4.4 step 6 post-processing.
    /// </summary>
    private async Task<DidResolutionResult> ResolveExpandingAsync(DidDocument document)
    {
        var stub = new DocumentStub(document);
        var resolver = new DidResolver(DidMethodSelectors.FromResolvers((ExampleDidPrefix, stub.ResolveAsync)));

        return await resolver.ResolveAsync(
            ExampleDid,
            Context,
            new DidResolutionOptions { ExpandRelativeUrls = true },
            TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Resolves to a NOT_FOUND failure, modelling a DID absent from its registry.</summary>
    private static ValueTask<DidResolutionResult> ResolveReturnsNotFoundAsync(
        string did,
        DidResolutionOptions options,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(DidResolutionResult.Failure(DidResolutionErrors.NotFound));
    }

    /// <summary>
    /// Carries a fixed <see cref="DidDocument"/> for a test resolver stub without using closures.
    /// The document is injected at construction and flows to <see cref="ResolveAsync"/> through the
    /// instance rather than a captured variable.
    /// </summary>
    private sealed class DocumentStub(DidDocument document)
    {
        private DidDocument Document { get; } = document;

        /// <summary>Resolves any DID to the fixed document supplied at construction.</summary>
        public ValueTask<DidResolutionResult> ResolveAsync(
            string did,
            DidResolutionOptions options,
            ExchangeContext context,
            CancellationToken cancellationToken)
        {
            return ValueTask.FromResult(DidResolutionResult.Success(Document, DidDocumentMetadata.Empty));
        }
    }
}
