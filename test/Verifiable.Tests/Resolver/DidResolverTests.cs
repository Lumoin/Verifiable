using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.Methods;
using Verifiable.Core.Resolvers;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="DidResolver"/> covering resolution dispatch, error handling,
/// options propagation, dereferencing, and factory method contracts.
/// </summary>
[TestClass]
internal sealed class DidResolverTests
{
    //Prefix used for test-only DID strings that have no well-known method type.
    private const string ExampleDidPrefix = "did:example";

    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task ResolveInvalidDidSyntaxReturnsInvalidDidError()
    {
        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(
            "not-a-did", cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.IsNotNull(result.ResolutionMetadata.Error);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
        Assert.IsNull(result.Document);
    }

    [TestMethod]
    public async Task ResolveEmptyStringReturnsInvalidDidError()
    {
        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(
            "", cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }

    [TestMethod]
    public async Task ResolveUnsupportedMethodReturnsMethodNotSupportedError()
    {
        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(
            "did:unknown:123", cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.MethodNotSupported, result.ResolutionMetadata.Error);
    }

    [TestMethod]
    public async Task ResolveDispatchesToRegisteredMethodHandler()
    {
        //Each handler returns a distinct ContentType so dispatch is verifiable from the result.
        var resolver = new DidResolver(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.WebDidMethodPrefix, ResolveWebWithContentTypeAsync),
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, ResolveKeyWithContentTypeAsync)));

        var webResult = await resolver.ResolveAsync(
            "did:web:example.com", cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var keyResult = await resolver.ResolveAsync(
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual("application/did+json; method=web", webResult.ResolutionMetadata.ContentType);
        Assert.AreEqual("application/did+json; method=key", keyResult.ResolutionMetadata.ContentType);
    }

    [TestMethod]
    public async Task ResolveDoesNotDispatchToUnregisteredMethodHandler()
    {
        var resolver = new DidResolver(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.WebDidMethodPrefix, ResolveWebWithContentTypeAsync)));

        var keyResult = await resolver.ResolveAsync(
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(keyResult.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.MethodNotSupported, keyResult.ResolutionMetadata.Error);
    }

    [TestMethod]
    public async Task ResolveSuccessfulReturnsDocumentKindAndMetadata()
    {
        var resolver = new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, ResolveWithFixedMetadataAsync)));

        var result = await resolver.ResolveAsync(
            "did:example:123", cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.IsNotNull(result.Document);
        Assert.AreEqual(DidResolutionKind.Document, result.Kind);
        Assert.AreEqual("application/did+json", result.ResolutionMetadata.ContentType);
        Assert.AreEqual("1", result.DocumentMetadata.VersionId);
        Assert.IsNull(result.ResolutionMetadata.Error);
    }

    [TestMethod]
    public async Task ResolveMethodHandlerExceptionReturnsInternalError()
    {
        var resolver = new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, ResolveAlwaysThrowsAsync)));

        var result = await resolver.ResolveAsync(
            "did:example:123", cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.InternalError, result.ResolutionMetadata.Error);
    }

    [TestMethod]
    public async Task ResolveMethodHandlerCancellationPropagates()
    {
        var resolver = new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, ResolveChecksCancellationAsync)));

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync().ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () =>
            await resolver.ResolveAsync(
                "did:example:123", cancellationToken: cts.Token).ConfigureAwait(false)).ConfigureAwait(false);
    }

    [TestMethod]
    public async Task ResolvePassesAcceptOptionToMethodHandler()
    {
        //The handler echoes options.Accept back as ContentType so it is verifiable from the result.
        var resolver = new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, ResolveEchoesAcceptAsync)));

        var options = new DidResolutionOptions { Accept = "application/did+ld+json" };
        var result = await resolver.ResolveAsync(
            "did:example:123", options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual("application/did+ld+json", result.ResolutionMetadata.ContentType);
    }

    [TestMethod]
    public async Task ResolvePassesVersionIdOptionToMethodHandler()
    {
        //The handler echoes options.VersionId back as DocumentMetadata.VersionId so it is verifiable from the result.
        var resolver = new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, ResolveEchoesVersionIdAsync)));

        var options = new DidResolutionOptions { VersionId = "42" };
        var result = await resolver.ResolveAsync(
            "did:example:123", options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual("42", result.DocumentMetadata.VersionId);
    }

    [TestMethod]
    public async Task ResolveNullOptionsDefaultsToEmptyOptions()
    {
        //The handler returns a sentinel ContentType only when Accept is null, confirming
        //that null options are normalized to DidResolutionOptions.Empty before dispatch.
        var resolver = new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, ResolveConfirmsEmptyOptionsAsync)));

        var result = await resolver.ResolveAsync(
            "did:example:123", cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual("options-were-empty", result.ResolutionMetadata.ContentType);
    }

    [TestMethod]
    public async Task ResolveDeactivatedDidReturnsMetadataWithDeactivatedFlag()
    {
        var resolver = new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, ResolveDeactivatedAsync)));

        var result = await resolver.ResolveAsync(
            "did:example:deactivated", cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.DocumentMetadata.Deactivated);
        Assert.IsNull(result.Document);
    }

    [TestMethod]
    public async Task DereferenceInvalidDidUrlReturnsInvalidDidUrlError()
    {
        var resolver = CreateResolver();
        var result = await resolver.DereferenceAsync(
            "not-a-did-url", cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.InvalidDidUrl, result.DereferencingMetadata.Error);
    }

    [TestMethod]
    public async Task DereferenceFragmentOnlyReferenceReturnsInvalidDidUrlError()
    {
        var resolver = CreateResolver();
        var result = await resolver.DereferenceAsync(
            "#key-1", cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.InvalidDidUrl, result.DereferencingMetadata.Error);
    }

    [TestMethod]
    public void DidResolutionResultSuccessFactoryCreatesDocumentKind()
    {
        var doc = CreateTestDocument("did:example:123");
        var metadata = new DidDocumentMetadata { VersionId = "1" };

        var result = DidResolutionResult.Success(doc, metadata, "application/did+json");

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual(DidResolutionKind.Document, result.Kind);
        Assert.IsNotNull(result.Document);
        Assert.IsNull(result.DocumentUrl);
        Assert.AreEqual("application/did+json", result.ResolutionMetadata.ContentType);
        Assert.AreEqual("1", result.DocumentMetadata.VersionId);
    }

    [TestMethod]
    public void DidResolutionResultSuccessUrlFactoryCreatesDocumentUrlKind()
    {
        const string url = "https://example.com/.well-known/did.json";

        var result = DidResolutionResult.SuccessUrl(url);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual(DidResolutionKind.DocumentUrl, result.Kind);
        Assert.IsNull(result.Document);
        Assert.AreEqual(url, result.DocumentUrl);
    }

    [TestMethod]
    public void DidResolutionResultSuccessVerifiedLogFactoryCreatesVerifiedLogKind()
    {
        const string url = "https://example.com/.well-known/did.jsonl";

        var result = DidResolutionResult.SuccessVerifiedLog(url);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual(DidResolutionKind.VerifiedLog, result.Kind);
        Assert.IsNull(result.Document);
        Assert.AreEqual(url, result.DocumentUrl);
    }

    [TestMethod]
    public void DidResolutionResultFailureFactoryCreatesFailedResult()
    {
        var result = DidResolutionResult.Failure(DidResolutionErrors.NotFound);

        Assert.IsFalse(result.IsSuccessful);
        Assert.IsNull(result.Document);
        Assert.IsNull(result.DocumentUrl);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.NotFound, result.ResolutionMetadata.Error);
    }

    [TestMethod]
    public void DidDereferencingResultSuccessFactoryCreatesValidResult()
    {
        var doc = CreateTestDocument("did:example:123");
        var result = DidDereferencingResult.Success(doc, DidDocumentMetadata.Empty, "application/did+json");

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreSame(doc, result.ContentStream);
        Assert.AreEqual("application/did+json", result.DereferencingMetadata.ContentType);
    }

    [TestMethod]
    public void DidDereferencingResultFailureFactoryCreatesFailedResult()
    {
        var result = DidDereferencingResult.Failure(DidResolutionErrors.NotFound);

        Assert.IsFalse(result.IsSuccessful);
        Assert.IsNull(result.ContentStream);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.NotFound, result.DereferencingMetadata.Error);
    }

    [TestMethod]
    public void DidDocumentMetadataEmptyIsConsistentSingleton()
    {
        var empty1 = DidDocumentMetadata.Empty;
        var empty2 = DidDocumentMetadata.Empty;

        Assert.AreSame(empty1, empty2);
        Assert.IsFalse(empty1.Deactivated);
        Assert.IsNull(empty1.Created);
        Assert.IsNull(empty1.VersionId);
    }

    [TestMethod]
    public void DidResolutionOptionsEmptyIsConsistentSingleton()
    {
        var empty1 = DidResolutionOptions.Empty;
        var empty2 = DidResolutionOptions.Empty;

        Assert.AreSame(empty1, empty2);
        Assert.IsNull(empty1.Accept);
    }

    [TestMethod]
    public void DidResolutionKindWellKnownValuesAreDistinct()
    {
        Assert.AreNotEqual(DidResolutionKind.Document, DidResolutionKind.DocumentUrl);
        Assert.AreNotEqual(DidResolutionKind.Document, DidResolutionKind.VerifiedLog);
        Assert.AreNotEqual(DidResolutionKind.DocumentUrl, DidResolutionKind.VerifiedLog);
    }

    [TestMethod]
    public void DidResolutionKindCustomValueRoundTrips()
    {
        var custom = new DidResolutionKind(99);

        Assert.AreEqual(new DidResolutionKind(99), custom);
        Assert.AreNotEqual(DidResolutionKind.Document, custom);
    }

    [TestMethod]
    public void FromResolversThrowsForPrefixWithoutDidScheme()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            DidMethodSelectors.FromResolvers(("web", ResolveExampleDidAsync)));
    }

    [TestMethod]
    public void FromResolversThrowsForNullDelegate()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            DidMethodSelectors.FromResolvers((ExampleDidPrefix, null!)));
    }

    [TestMethod]
    public void FromDereferencersThrowsForPrefixWithoutDidScheme()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            DidMethodSelectors.FromDereferencers(("web", DereferenceExampleDidAsync)));
    }

    [TestMethod]
    public void FromDereferencersThrowsForNullDelegate()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            DidMethodSelectors.FromDereferencers((ExampleDidPrefix, null!)));
    }

    //Helper methods at end of test class.

    private static DidResolver CreateResolver()
    {
        return new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, ResolveExampleDidAsync)));
    }

    private static ValueTask<DidResolutionResult> ResolveExampleDidAsync(
        string did,
        DidResolutionOptions options,
        CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(
            DidResolutionResult.Success(CreateTestDocument(did), DidDocumentMetadata.Empty));
    }

    private static ValueTask<DidResolutionResult> ResolveWebWithContentTypeAsync(
        string did,
        DidResolutionOptions options,
        CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(
            DidResolutionResult.Success(
                CreateTestDocument(did),
                DidDocumentMetadata.Empty,
                "application/did+json; method=web"));
    }

    private static ValueTask<DidResolutionResult> ResolveKeyWithContentTypeAsync(
        string did,
        DidResolutionOptions options,
        CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(
            DidResolutionResult.Success(
                CreateTestDocument(did),
                DidDocumentMetadata.Empty,
                "application/did+json; method=key"));
    }

    private static ValueTask<DidResolutionResult> ResolveWithFixedMetadataAsync(
        string did,
        DidResolutionOptions options,
        CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(
            DidResolutionResult.Success(
                CreateTestDocument(did),
                new DidDocumentMetadata { VersionId = "1" },
                "application/did+json"));
    }

    private static ValueTask<DidResolutionResult> ResolveAlwaysThrowsAsync(
        string did,
        DidResolutionOptions options,
        CancellationToken cancellationToken)
    {
        throw new InvalidOperationException("Simulated failure.");
    }

    private static ValueTask<DidResolutionResult> ResolveChecksCancellationAsync(
        string did,
        DidResolutionOptions options,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(
            DidResolutionResult.Success(CreateTestDocument(did), DidDocumentMetadata.Empty));
    }

    private static ValueTask<DidResolutionResult> ResolveEchoesAcceptAsync(
        string did,
        DidResolutionOptions options,
        CancellationToken cancellationToken)
    {
        //Echo options.Accept back as ContentType so the test can verify it was received correctly.
        return ValueTask.FromResult(
            DidResolutionResult.Success(
                CreateTestDocument(did),
                DidDocumentMetadata.Empty,
                options.Accept));
    }

    private static ValueTask<DidResolutionResult> ResolveEchoesVersionIdAsync(
        string did,
        DidResolutionOptions options,
        CancellationToken cancellationToken)
    {
        //Echo options.VersionId back as DocumentMetadata.VersionId so the test can verify it was received correctly.
        return ValueTask.FromResult(
            DidResolutionResult.Success(
                CreateTestDocument(did),
                new DidDocumentMetadata { VersionId = options.VersionId }));
    }

    private static ValueTask<DidResolutionResult> ResolveConfirmsEmptyOptionsAsync(
        string did,
        DidResolutionOptions options,
        CancellationToken cancellationToken)
    {
        //Return a sentinel ContentType confirming that options were non-null with a null Accept,
        //which is what DidResolutionOptions.Empty produces.
        string sentinel = options.Accept is null ? "options-were-empty" : "options-had-accept";
        return ValueTask.FromResult(
            DidResolutionResult.Success(
                CreateTestDocument(did),
                DidDocumentMetadata.Empty,
                sentinel));
    }

    private static ValueTask<DidResolutionResult> ResolveDeactivatedAsync(
        string did,
        DidResolutionOptions options,
        CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(new DidResolutionResult
        {
            ResolutionMetadata = new DidResolutionMetadata(),
            Document = null,
            DocumentMetadata = new DidDocumentMetadata { Deactivated = true }
        });
    }

    private static ValueTask<DidDereferencingResult> DereferenceExampleDidAsync(
        string baseDid,
        string? path,
        string? query,
        DidDereferencingOptions options,
        CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(
            DidDereferencingResult.Success(CreateTestDocument(baseDid)));
    }

    private static DidDocument CreateTestDocument(string did)
    {
        return new DidDocument { Id = new GenericDidMethod(did) };
    }
}