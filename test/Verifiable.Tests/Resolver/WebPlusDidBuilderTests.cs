using System;
using System.Collections.Immutable;
using System.Text;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Core.Did.Methods.WebPlus;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Foundation;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for the production <see cref="WebPlusDidBuilder"/> — the controller/mint side that builds and
/// self-hashes a did:webplus root document (WP-CTL-1, WP-SH-1) through the SHARED DID construction. The output is
/// cross-checked against the verifier under test (it MUST resolve through the real
/// <see cref="WebPlusDidResolver"/>), proving the builder's self-hash generation is the inverse of the resolver's
/// verification. BLAKE3 is supplied from BouncyCastle as the (here, shared) hash; the firewall is that the
/// builder and resolver are independent code paths whose agreement is the assertion.
/// </summary>
[TestClass]
internal sealed class WebPlusDidBuilderTests
{
    private const int Blake3DigestLength = 32;
    private const string Host = "example.com";
    private const string ValidFrom = "2025-01-01T00:00:00Z";

    /// <summary>The cancellation-token source for the test.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// The <see cref="WebPlusDidDocumentSerializer"/> wired from the production method-polymorphic converter
    /// (which emits the typed did:webplus control fields) plus RFC 8785 JCS canonicalization.
    /// </summary>
    /// <param name="document">The document to serialize.</param>
    /// <returns>The document's JCS canonical bytes tagged as JSON.</returns>
    private static TaggedMemory<byte> Serialize(WebPlusDidDocument document)
    {
        string json = JsonSerializerExtensions.Serialize<DidDocument>(document, TestSetup.DefaultSerializationOptions);

        return new TaggedMemory<byte>(Jcs.CanonicalizeToUtf8Bytes(json), BufferTags.Json);
    }


    /// <summary>Builds the did:webplus root builder wired with the JSON serializer and the BLAKE3 oracle.</summary>
    /// <returns>The builder under test.</returns>
    private static WebPlusDidBuilder CreateBuilder()
    {
        return new WebPlusDidBuilder(
            Serialize,
            BouncyCastleEntropyFunctions.ComputeBlake3DigestAsync,
            CryptoTags.Blake3Digest,
            MultihashHeaders.Blake3.ToArray(),
            Blake3DigestLength,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base58Encoder,
            BaseMemoryPool.Shared);
    }


    /// <summary>
    /// A built root document resolves through the real <see cref="WebPlusDidResolver"/>: its self-hash generation
    /// is the inverse of the resolver's WP-SH/WP-ID-1 verification, so the minted DID round-trips.
    /// </summary>
    [TestMethod]
    public async Task BuiltRootResolvesThroughResolver()
    {
        using PublicKeyMemory publicKey = CreateKey(out PrivateKey privateKey);
        using PrivateKey _ = privateKey;

        WebPlusDidDocument root = await CreateBuilder().BuildRootAsync(
            publicKey, Host, ValidFrom, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(root.SelfHash, "The built root MUST be self-hashed.");
        string did = root.Id!.ToString()!;
        Assert.AreEqual($"did:webplus:{Host}:{root.SelfHash}", did, "The DID's trailing segment MUST be the root self-hash (WP-ID-1).");

        string microledger = Encoding.UTF8.GetString(Serialize(root).Span);
        DidResolutionResult result = await WebPlusTestResolver.ResolveAsync(did, microledger, options: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A built did:webplus root MUST resolve. Error: {result.ResolutionMetadata.Error?.Detail}.");
        Assert.AreEqual(did, result.Document!.Id?.ToString());
        Assert.AreEqual("0", result.DocumentMetadata.VersionId);
    }


    /// <summary>
    /// The built root carries the standard verification method and relationships produced by the shared
    /// construction: one signing verification method controlled by the DID, in the four signing relationships.
    /// </summary>
    [TestMethod]
    public async Task BuiltRootCarriesStandardVerificationMethod()
    {
        using PublicKeyMemory publicKey = CreateKey(out PrivateKey privateKey);
        using PrivateKey _ = privateKey;

        WebPlusDidDocument root = await CreateBuilder().BuildRootAsync(
            publicKey, Host, ValidFrom, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string did = root.Id!.ToString()!;
        Assert.HasCount(1, root.VerificationMethod!);
        Assert.AreEqual(did, root.VerificationMethod![0].Controller, "The verification method's controller MUST be the DID.");
        Assert.HasCount(1, root.Authentication!);
        Assert.HasCount(1, root.AssertionMethod!);
        Assert.HasCount(1, root.CapabilityInvocation!);
        Assert.HasCount(1, root.CapabilityDelegation!);

        //No placeholder may survive into the published document: every self-hash slot is the digest.
        string microledger = Encoding.UTF8.GetString(Serialize(root).Span);
        Assert.DoesNotContain("AAAAAAAA", microledger, "No all-zero MBHash placeholder may remain in the self-hashed document.");
    }


    /// <summary>
    /// The production builder and the INDEPENDENT minter produce the byte-identical self-hashed root for the same
    /// key, host and timestamp: two independent mint code paths agree, the firewall cross-check that pins the
    /// self-hash generation (neither path's correctness rests on the other).
    /// </summary>
    [TestMethod]
    public async Task BuilderAndIndependentMinterAgree()
    {
        using WebPlusController controller = WebPlusController.Create();

        WebPlusMintedDid minted = await WebPlusMinter.MintAsync(Host,
        [
            new WebPlusDocPlan(controller, VersionId: 0, ValidFrom)
        ]).ConfigureAwait(false);

        WebPlusDidDocument built = await CreateBuilder().BuildRootAsync(
            controller.PublicKey, Host, ValidFrom, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(minted.SelfHashes[0], built.SelfHash, "The builder and the independent minter MUST compute the same root self-hash.");
        Assert.AreEqual(minted.Did, built.Id!.ToString(), "The builder and the independent minter MUST derive the same DID.");

        string builtLine = Encoding.UTF8.GetString(Serialize(built).Span);
        Assert.AreEqual(minted.Lines[0], builtLine, "The builder and the independent minter MUST produce byte-identical JCS.");
    }


    /// <summary>Generates a fresh Ed25519 key pair (BouncyCastle), returning the public key and its private key.</summary>
    /// <param name="privateKey">The generated signing key, for the caller to dispose.</param>
    /// <returns>The public key.</returns>
    private static PublicKeyMemory CreateKey(out PrivateKey privateKey)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = BouncyCastleKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
        privateKey = CryptographicKeyFactory.CreatePrivateKey(keys.PrivateKey, "webplus-builder-test", keys.PrivateKey.Tag);

        return keys.PublicKey;
    }
}
