using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Peer;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Builders;

/// <summary>
/// Tests for <see cref="PeerDidGenerator"/> — did:peer generation — verified by round-tripping the
/// generated identifiers back through <see cref="PeerDidResolver"/>. The specification does not
/// canonicalize the encoded JSON, so generate→resolve equivalence (not a fixed output string) is the
/// conformance property; <see cref="PeerDidResolver"/> itself is pinned to the spec golden vector elsewhere.
/// </summary>
[TestClass]
internal sealed class PeerDidGeneratorTests
{
    private const string SigningKey = "z6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc";

    private const string KeyAgreementKey = "z6LSg8zQom395jKLrGiBNruB9MM6V8PWuf2FpEy4uRFiqQBR";

    private static readonly ExchangeContext ResolutionContext = new();

    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task GenerateNumalgo4RoundTripsThroughResolution()
    {
        var inputDocument = NewInputDocument();

        string longForm = PeerDidGenerator.GenerateNumalgo4(inputDocument, SerializeDidDocument, SHA256.HashData, BaseMemoryPool.Shared);
        Assert.IsTrue(longForm.StartsWith("did:peer:4", StringComparison.Ordinal));

        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(longForm, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        var document = result.Document;
        Assert.IsNotNull(document);

        //Long-form resolution presents the long form and defaults the controller to it.
        Assert.AreEqual(longForm, document.Id!.Id);
        Assert.HasCount(1, document.VerificationMethod!);
        Assert.AreEqual("#key-1", document.VerificationMethod![0].Id);
        Assert.AreEqual(longForm, document.VerificationMethod![0].Controller);
        Assert.AreEqual(SigningKey, ((PublicKeyMultibase)document.VerificationMethod![0].KeyFormat!).Key);
        Assert.AreEqual("#key-1", document.Authentication![0].Id);

        //The input had no alsoKnownAs, so contextualization adds exactly the short form.
        Assert.HasCount(1, document.AlsoKnownAs!);
        Assert.AreEqual(ShortFormOf(longForm), document.AlsoKnownAs![0]);
    }


    [TestMethod]
    public async Task GenerateNumalgo4ShortFormResolvesAgainstStoredLongForm()
    {
        string longForm = PeerDidGenerator.GenerateNumalgo4(NewInputDocument(), SerializeDidDocument, SHA256.HashData, BaseMemoryPool.Shared);
        string shortForm = ShortFormOf(longForm);

        //A short form on its own is not resolvable; the standard resolver returns NotFound for it.
        var resolver = CreateResolver();
        var standalone = await resolver.ResolveAsync(shortForm, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(standalone.IsSuccessful);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.NotFound, standalone.ResolutionMetadata.Error);

        //Given the stored long form, the short form resolves and is contextualized with the short-form DID.
        var result = await PeerDidResolver.ResolveShortForm(longForm, BaseMemoryPool.Shared, DeserializeDidDocument, TestContext.CancellationToken);
        Assert.IsTrue(result.IsSuccessful);
        var document = result.Document;
        Assert.IsNotNull(document);
        Assert.AreEqual(shortForm, document.Id!.Id);
        Assert.AreEqual(shortForm, document.VerificationMethod![0].Controller);
        Assert.HasCount(1, document.AlsoKnownAs!);
        Assert.AreEqual(longForm, document.AlsoKnownAs![0]);
    }


    [TestMethod]
    public async Task GenerateNumalgo4RoundTripsEmbeddedMethodsAndService()
    {
        //A richer, DIDComm-shaped document exercising the real serialize/encode/decode path for an embedded
        //verification method, a referenced key, and a service — the embedded-VM path the resolver test only
        //covered via a stub deserializer.
        var inputDocument = new DidDocument
        {
            Context = new Context { Contexts = [Context.DidCore10, Context.Multikey10] },
            VerificationMethod =
            [
                new VerificationMethod { Id = "#key-2", Type = "Multikey", KeyFormat = new PublicKeyMultibase(KeyAgreementKey) }
            ],
            Authentication = [new AuthenticationMethod(new VerificationMethod { Id = "#key-1", Type = "Multikey", KeyFormat = new PublicKeyMultibase(SigningKey) })],
            KeyAgreement = [new KeyAgreementMethod("#key-2")],
            Service = [new Service { Id = DidUrl.ParseFragment("#didcomm"), Type = "DIDCommMessaging", ServiceEndpoint = "https://example.com/didcomm" }]
        };

        string longForm = PeerDidGenerator.GenerateNumalgo4(inputDocument, SerializeDidDocument, SHA256.HashData, BaseMemoryPool.Shared);

        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(longForm, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        var document = result.Document;
        Assert.IsNotNull(document);

        //The embedded authentication method survives the round trip with its controller defaulted.
        var embedded = document.Authentication![0].EmbeddedVerification;
        Assert.IsNotNull(embedded);
        Assert.AreEqual("#key-1", embedded.Id);
        Assert.AreEqual(longForm, embedded.Controller);
        Assert.AreEqual(SigningKey, ((PublicKeyMultibase)embedded.KeyFormat!).Key);

        //The referenced keyAgreement key and its top-level verification method round-trip too.
        Assert.AreEqual("#key-2", document.KeyAgreement![0].Id);
        Assert.HasCount(1, document.VerificationMethod!);
        Assert.AreEqual(longForm, document.VerificationMethod![0].Controller);

        //The service is preserved.
        Assert.AreEqual("#didcomm", document.Service![0].Id!.ToString());
        Assert.AreEqual("DIDCommMessaging", document.Service![0].Type);
    }


    /// <summary>
    /// Per the did:peer:4 specification the input document MUST NOT include a root <c>id</c> — the id is
    /// assigned only when the DID is later resolved. An input document carrying a root id is rejected by the
    /// generator.
    /// </summary>
    [TestMethod]
    public void GenerateNumalgo4RejectsInputDocumentWithRootId()
    {
        var inputDocument = NewInputDocument();
        inputDocument.Id = new GenericDidMethod("did:example:123456789abcdefghi");

        Assert.ThrowsExactly<ArgumentException>(() => PeerDidGenerator.GenerateNumalgo4(
            inputDocument, SerializeDidDocument, SHA256.HashData, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// Per the did:peer:4 specification all identifiers within the input document MUST be relative. A
    /// verification method whose <c>id</c> is an absolute DID URL rather than a fragment reference is
    /// rejected by the generator.
    /// </summary>
    [TestMethod]
    public void GenerateNumalgo4RejectsAbsoluteVerificationMethodIdentifier()
    {
        var inputDocument = new DidDocument
        {
            Context = new Context { Contexts = [Context.DidCore10, Context.Multikey10] },
            VerificationMethod =
            [
                new VerificationMethod { Id = "did:example:123456789abcdefghi#key-1", Type = "Multikey", KeyFormat = new PublicKeyMultibase(SigningKey) }
            ]
        };

        Assert.ThrowsExactly<ArgumentException>(() => PeerDidGenerator.GenerateNumalgo4(
            inputDocument, SerializeDidDocument, SHA256.HashData, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// Per the did:peer:4 specification all references pointing to resources within the input document MUST
    /// be relative. A verification relationship referencing a key by an absolute DID URL is rejected by the
    /// generator.
    /// </summary>
    [TestMethod]
    public void GenerateNumalgo4RejectsAbsoluteVerificationRelationshipReference()
    {
        var inputDocument = new DidDocument
        {
            Context = new Context { Contexts = [Context.DidCore10, Context.Multikey10] },
            VerificationMethod =
            [
                new VerificationMethod { Id = "#key-1", Type = "Multikey", KeyFormat = new PublicKeyMultibase(SigningKey) }
            ]
        };
        inputDocument.WithAuthentication("did:example:123456789abcdefghi#key-1");

        Assert.ThrowsExactly<ArgumentException>(() => PeerDidGenerator.GenerateNumalgo4(
            inputDocument, SerializeDidDocument, SHA256.HashData, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// Per the did:peer:4 specification a verification method's <c>controller</c> MUST be omitted when the
    /// subject owns the method and INCLUDED when another party controls it; an absolute other-party
    /// controller DID is therefore legitimate and MUST NOT be rejected by the relativity rule (which reaches
    /// only the subject's own identifiers and references). Such a document still generates and round-trips,
    /// with the foreign controller preserved verbatim.
    /// </summary>
    [TestMethod]
    public async Task GenerateNumalgo4AcceptsAbsoluteForeignControllerOnVerificationMethod()
    {
        var inputDocument = new DidDocument
        {
            Context = new Context { Contexts = [Context.DidCore10, Context.Multikey10] },
            VerificationMethod =
            [
                new VerificationMethod { Id = "#key-1", Type = "Multikey", Controller = "did:example:other", KeyFormat = new PublicKeyMultibase(SigningKey) }
            ]
        };
        inputDocument.WithAuthentication("#key-1");

        string longForm = PeerDidGenerator.GenerateNumalgo4(inputDocument, SerializeDidDocument, SHA256.HashData, BaseMemoryPool.Shared);
        Assert.IsTrue(longForm.StartsWith("did:peer:4", StringComparison.Ordinal));

        var result = await CreateResolver().ResolveAsync(longForm, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);

        //An explicit foreign controller is a legitimate other-party assertion, preserved verbatim; the
        //relativity rule does not rewrite or reject it.
        Assert.AreEqual("did:example:other", result.Document!.VerificationMethod![0].Controller);
    }


    [TestMethod]
    public void GenerateNumalgo2ProducesSpecGoldenVector()
    {
        //did:peer:2 is a closed, abbreviated format, so generation is asserted byte-for-byte against the
        //specification's golden vector.
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using PublicKeyMemory authenticationKey = DecodeMultibaseKey(SigningKey, pool);
        using PublicKeyMemory keyAgreementKey = DecodeMultibaseKey(KeyAgreementKey, pool);

        string did = PeerDidGenerator.GenerateNumalgo2(
            [
                new PeerDidPurposedKey(authenticationKey, PeerDidPurpose.Authentication),
                new PeerDidPurposedKey(keyAgreementKey, PeerDidPurpose.KeyAgreement)
            ],
            [
                DidCommService("http://example.com/didcomm", "did:example:123456789abcdefghi#key-1"),
                DidCommService("http://example.com/another", "did:example:123456789abcdefghi#key-2")
            ],
            pool);

        Assert.AreEqual(PeerDid2TestVectors.GoldenVector, did);
    }


    [TestMethod]
    public async Task GenerateNumalgo2RoundTripsThroughResolution()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using PublicKeyMemory authenticationKey = DecodeMultibaseKey(SigningKey, pool);
        using PublicKeyMemory keyAgreementKey = DecodeMultibaseKey(KeyAgreementKey, pool);

        string did = PeerDidGenerator.GenerateNumalgo2(
            [
                new PeerDidPurposedKey(authenticationKey, PeerDidPurpose.Authentication),
                new PeerDidPurposedKey(keyAgreementKey, PeerDidPurpose.KeyAgreement)
            ],
            [DidCommService("http://example.com/didcomm", "did:example:123456789abcdefghi#key-1")],
            pool);

        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(did, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        var document = result.Document;
        Assert.IsNotNull(document);
        Assert.HasCount(2, document.VerificationMethod!);
        Assert.AreEqual("#key-1", document.Authentication![0].Id);
        Assert.AreEqual("#key-2", document.KeyAgreement![0].Id);
        Assert.HasCount(1, document.Service!);
        Assert.AreEqual("DIDCommMessaging", document.Service![0].Type);
    }


    [TestMethod]
    public void GenerateNumalgo2RejectsServicesTheClosedFormatCannotExpress()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using PublicKeyMemory key = DecodeMultibaseKey(SigningKey, pool);
        PeerDidPurposedKey[] keys = [new PeerDidPurposedKey(key, PeerDidPurpose.Authentication)];

        //A missing type, multiple types, multiple endpoints, and extension data are all unrepresentable in
        //the abbreviated format and must fail closed rather than be silently truncated.
        Assert.Throws<ArgumentException>(() => PeerDidGenerator.GenerateNumalgo2(
            keys, [new Service { ServiceEndpoint = "https://example.com" }], pool));
        Assert.Throws<ArgumentException>(() => PeerDidGenerator.GenerateNumalgo2(
            keys, [new Service { Types = ["A", "B"], ServiceEndpoint = "https://example.com" }], pool));
        Assert.Throws<ArgumentException>(() => PeerDidGenerator.GenerateNumalgo2(
            keys, [new Service { Type = "DIDCommMessaging", ServiceEndpoints = ["https://example.com"] }], pool));
        Assert.Throws<ArgumentException>(() => PeerDidGenerator.GenerateNumalgo2(
            keys, [new Service { Type = "DIDCommMessaging", ServiceEndpoint = "https://example.com", AdditionalData = new Dictionary<string, object> { ["x"] = "y" } }], pool));
    }


    [TestMethod]
    public async Task GenerateNumalgo2EscapesAndRoundTripsServiceStringValues()
    {
        //A uri carrying a quote, a backslash, and a newline exercises the writer's escaping and the reader's decoding.
        string uri = "https://example.com/a\"b\\c\nd";
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using PublicKeyMemory key = DecodeMultibaseKey(SigningKey, pool);

        string did = PeerDidGenerator.GenerateNumalgo2(
            [new PeerDidPurposedKey(key, PeerDidPurpose.Authentication)],
            [DidCommService(uri, "did:example:123456789abcdefghi#key-1")],
            pool);

        var result = await CreateResolver().ResolveAsync(did, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual(uri, result.Document!.Service![0].ServiceEndpointMap!["uri"]);
    }


    [TestMethod]
    public async Task GenerateNumalgo2RoundTripsStringServiceEndpoint()
    {
        //A non-dm type passes through verbatim and a bare-string endpoint populates ServiceEndpoint, not the map.
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using PublicKeyMemory key = DecodeMultibaseKey(SigningKey, pool);
        var service = new Service { Type = "LinkedDomains", ServiceEndpoint = "https://example.com/ep" };

        string did = PeerDidGenerator.GenerateNumalgo2(
            [new PeerDidPurposedKey(key, PeerDidPurpose.Authentication)],
            [service],
            pool);

        var result = await CreateResolver().ResolveAsync(did, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        var resolved = result.Document!.Service![0];
        Assert.AreEqual("LinkedDomains", resolved.Type);
        Assert.AreEqual("https://example.com/ep", resolved.ServiceEndpoint);
        Assert.IsNull(resolved.ServiceEndpointMap);
    }


    [TestMethod]
    public async Task GenerateNumalgo2MapsEveryPurposeToItsRelationship()
    {
        //One key per purpose, in order, pins all five purpose-code mappings (a transposition would otherwise
        //survive a suite that only generates V and E). No services exercises the key-only path.
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using PublicKeyMemory assertion = DecodeMultibaseKey(SigningKey, pool);
        using PublicKeyMemory keyAgreement = DecodeMultibaseKey(KeyAgreementKey, pool);
        using PublicKeyMemory authentication = DecodeMultibaseKey(SigningKey, pool);
        using PublicKeyMemory invocation = DecodeMultibaseKey(SigningKey, pool);
        using PublicKeyMemory delegation = DecodeMultibaseKey(SigningKey, pool);

        string did = PeerDidGenerator.GenerateNumalgo2(
            [
                new PeerDidPurposedKey(assertion, PeerDidPurpose.AssertionMethod),
                new PeerDidPurposedKey(keyAgreement, PeerDidPurpose.KeyAgreement),
                new PeerDidPurposedKey(authentication, PeerDidPurpose.Authentication),
                new PeerDidPurposedKey(invocation, PeerDidPurpose.CapabilityInvocation),
                new PeerDidPurposedKey(delegation, PeerDidPurpose.CapabilityDelegation)
            ],
            [],
            pool);

        var result = await CreateResolver().ResolveAsync(did, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        var document = result.Document!;
        Assert.AreEqual("#key-1", document.AssertionMethod![0].Id);
        Assert.AreEqual("#key-2", document.KeyAgreement![0].Id);
        Assert.AreEqual("#key-3", document.Authentication![0].Id);
        Assert.AreEqual("#key-4", document.CapabilityInvocation![0].Id);
        Assert.AreEqual("#key-5", document.CapabilityDelegation![0].Id);
    }


    [TestMethod]
    public async Task GenerateNumalgo2EmitsExplicitServiceId()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using PublicKeyMemory key = DecodeMultibaseKey(SigningKey, pool);
        var service = new Service { Id = DidUrl.ParseFragment("#agent"), Type = "DIDCommMessaging", ServiceEndpoint = "https://example.com/ep" };

        string did = PeerDidGenerator.GenerateNumalgo2(
            [new PeerDidPurposedKey(key, PeerDidPurpose.Authentication)],
            [service],
            pool);

        var result = await CreateResolver().ResolveAsync(did, ResolutionContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual("#agent", result.Document!.Service![0].Id!.ToString());
    }


    private static PublicKeyMemory DecodeMultibaseKey(string multibaseKey, MemoryPool<byte> pool)
    {
        var decoded = CryptoFormatConversions.DefaultBase58ToAlgorithmConverter(
            multibaseKey, pool, DefaultCoderSelector.SelectDecoder(typeof(PublicKeyMultibase)));

        return new PublicKeyMemory(decoded.keyMaterial, Tag.Create(decoded.Algorithm).With(decoded.Purpose).With(decoded.Scheme));
    }


    private static Service DidCommService(string uri, string routingKey) => new()
    {
        Type = "DIDCommMessaging",
        ServiceEndpointMap = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["uri"] = uri,
            ["accept"] = new List<string> { "didcomm/v2" },
            ["routingKeys"] = new List<string> { routingKey }
        }
    };


    private static DidDocument NewInputDocument()
    {
        //An input document per the spec: relative ids, no root id, controller omitted (filled on resolution).
        var document = new DidDocument
        {
            Context = new Context { Contexts = [Context.DidCore10, Context.Multikey10] },
            VerificationMethod =
            [
                new VerificationMethod { Id = "#key-1", Type = "Multikey", KeyFormat = new PublicKeyMultibase(SigningKey) }
            ]
        };

        return document.WithAuthentication("#key-1");
    }


    private static string ShortFormOf(string longFormDid) =>
        longFormDid[..longFormDid.IndexOf(':', PeerDidMethod.Prefix.Length)];


    private static DidResolver CreateResolver() =>
        new(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.PeerDidMethodPrefix, PeerDidResolver.Build(BaseMemoryPool.Shared, DeserializeDidDocument))));


    private static string SerializeDidDocument(DidDocument document) =>
        DidDocumentWireFixtures.SerializeDidDocument(document, TestSetup.DefaultSerializationOptions);


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
}
