using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Peer;
using Verifiable.Core.OutboundFetch;
using Verifiable.Core.Resolvers;
using Verifiable.Core.Did.Methods.Web;
using Verifiable.Cryptography;
using Verifiable.Foundation;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="DidResolverComposition"/> — the local-binding composition of the multi-method
/// <see cref="DidResolver"/>. One composed resolver dispatches across the standard methods (synthetic
/// <c>did:key</c>, guarded-fetch <c>did:web</c>, parsed <c>did:peer</c>, URL-computing <c>did:cheqd</c>),
/// an appended extension method, and reports an unregistered method as unsupported.
/// </summary>
[TestClass]
internal sealed class DidResolverCompositionTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;

    private const string KeyDid = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    private const string CheqdDid = "did:cheqd:mainnet:zF7rhDBfUt9d1gJPjx7s1JXfUY7oVWkY";
    private const string AliceWebDid = "did:web:example.com:alice";
    private const string AliceWebUrl = "https://example.com/alice/did.json";
    private const string ExtensionMethodPrefix = "did:example";
    private const string ExtensionUrl = "https://example.test/stub";


    /// <summary>The composed resolver dispatches <c>did:key</c> to a synthesised document.</summary>
    [TestMethod]
    public async Task DispatchesDidKeyToSyntheticDocument()
    {
        DidResolutionResult result = await Resolve(BuildComposedResolver(), KeyDid).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"did:key MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(DidResolutionKind.Document, result.Kind);
        Assert.AreEqual(KeyDid, result.Document?.Id?.ToString());
    }


    /// <summary>The composed resolver dispatches <c>did:web</c> through the guarded fetch to a document.</summary>
    [TestMethod]
    public async Task DispatchesDidWebThroughGuardedFetch()
    {
        DidResolutionResult result = await Resolve(BuildComposedResolver(), AliceWebDid).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"did:web MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(DidResolutionKind.Document, result.Kind);
        Assert.AreEqual(AliceWebDid, result.Document?.Id?.ToString());
    }


    /// <summary>The composed resolver dispatches a minted <c>did:peer:2</c> to its resolved document.</summary>
    [TestMethod]
    public async Task DispatchesDidPeerToResolvedDocument()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> peerKeys = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory peerPublic = peerKeys.PublicKey;
        using PrivateKeyMemory peerPrivate = peerKeys.PrivateKey;
        string peerDid = PeerDidGenerator.GenerateNumalgo2([new PeerDidPurposedKey(peerPublic, PeerDidPurpose.KeyAgreement)], [], Pool);

        DidResolutionResult result = await Resolve(BuildComposedResolver(), peerDid).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"did:peer MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(DidResolutionKind.Document, result.Kind);
        Assert.AreEqual(peerDid, result.Document?.Id?.ToString());
    }


    /// <summary>The composed resolver dispatches <c>did:cheqd</c> to a document URL for the caller to fetch.</summary>
    [TestMethod]
    public async Task DispatchesDidCheqdToDocumentUrl()
    {
        DidResolutionResult result = await Resolve(BuildComposedResolver(), CheqdDid).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"did:cheqd MUST resolve to a URL. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(DidResolutionKind.DocumentUrl, result.Kind);
        Assert.IsNotNull(result.DocumentUrl);
    }


    /// <summary>A method appended through the extension point is dispatched.</summary>
    [TestMethod]
    public async Task DispatchesAppendedExtensionMethod()
    {
        DidResolutionResult result = await Resolve(BuildComposedResolver(), "did:example:123").ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual(DidResolutionKind.DocumentUrl, result.Kind);
        Assert.AreEqual(ExtensionUrl, result.DocumentUrl);
    }


    /// <summary>A method that is not registered is reported as not supported.</summary>
    [TestMethod]
    public async Task ReportsMethodNotSupportedForUnregisteredMethod()
    {
        DidResolutionResult result = await Resolve(BuildComposedResolver(), "did:unregistered:xyz").ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.MethodNotSupported, result.ResolutionMetadata.Error);
    }


    private async Task<DidResolutionResult> Resolve(DidResolver resolver, string did)
    {
        ExchangeContext context = new();
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        return await resolver.ResolveAsync(did, context, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }


    //Composes the resolver wired for the standard methods plus one appended extension method. The did:web
    //transport serves a single document for AliceWebUrl and 404s everything else.
    private static DidResolver BuildComposedResolver()
    {
        string aliceJson = SerializeDocument(AliceWebDid);

        OutboundTransportDelegate webTransport = (request, context, cancellationToken) =>
        {
            bool isAlice = string.Equals(request.Target.AbsoluteUri, AliceWebUrl, StringComparison.Ordinal);

            return ValueTask.FromResult(new OutboundResponse
            {
                StatusCode = isAlice ? 200 : 404,
                Body = isAlice ? new TaggedMemory<byte>(Encoding.UTF8.GetBytes(aliceJson), BufferTags.Json) : TaggedMemory<byte>.Empty
            });
        };

        DidMethodResolverDelegate extension = (did, options, context, cancellationToken) =>
            ValueTask.FromResult(DidResolutionResult.SuccessUrl(ExtensionUrl));

        return DidResolverComposition.Build(
            Pool,
            webTransport,
            new WebDidDocumentDeserializer(DeserializeDocument),
            new PeerDidDocumentDeserializer(DeserializeDocument),
            additionalMethods: [(ExtensionMethodPrefix, extension)]);
    }


    //The JSON layer supplies document deserialization; Verifiable.Core never parses the document itself.
    private static DidDocument? DeserializeDocument(ReadOnlySpan<byte> jsonUtf8)
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


    //Serializes a minimal DID document with the given subject id through the same serializer the
    //resolver's deserializer uses, guaranteeing a faithful round trip. The DID v1 @context is included
    //because a resolved did:web document is a JSON-LD representation the resolver requires to carry it.
    private static string SerializeDocument(string did)
    {
        var document = new DidDocument
        {
            Context = new Verifiable.Core.Model.Common.Context
            {
                Contexts = [Verifiable.Core.Model.Common.Context.DidCore10]
            },
            Id = new GenericDidMethod(did)
        };

        return JsonSerializerExtensions.Serialize(document, TestSetup.DefaultSerializationOptions);
    }
}
