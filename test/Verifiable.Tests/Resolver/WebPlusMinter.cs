using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Digests;
using Verifiable.BouncyCastle;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.WebPlus;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Cryptography;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Mints valid (and deliberately invalid) did:webplus <c>did-documents.jsonl</c> microledgers for the resolver
/// and replay tests by executing the specification's Create/Update construction independently of the verifier
/// under test: build each document with its self-hash slots set to the placeholder, sign the detached-JWS proofs
/// over that placeholder form, then self-hash by replacing every placeholder occurrence with the digest. The
/// verification path under test re-derives every one of those values, so a faithfully minted microledger is the
/// round-trip oracle. The crypto is INDEPENDENT (BouncyCastle Ed25519 + BLAKE3); only the neutral multihash/
/// multibase wire encoding is shared.
/// </summary>
internal static class WebPlusMinter
{
    /// <summary>The BLAKE3-256 digest length in bytes.</summary>
    public const int Blake3DigestLength = 32;


    /// <summary>BLAKE3-256 via BouncyCastle, the independent hash oracle the minter self-hashes with.</summary>
    public static HashFunctionDelegate Blake3 { get; } = (source, destination) =>
    {
        var digest = new Blake3Digest();
        digest.BlockUpdate(source);

        return digest.DoFinal(destination);
    };


    /// <summary>The BLAKE3 multihash code naming the self-hash's hash function.</summary>
    public static ReadOnlyMemory<byte> MultihashCode { get; } = MultihashHeaders.Blake3.ToArray();


    /// <summary>
    /// The minter's independent MBHash of <paramref name="input"/>: hashed with this oracle's own BLAKE3
    /// (<see cref="Blake3"/>), then the neutral multihash/multibase wire encoding (shared with the verifier, not the
    /// verifier's registered digest seam) — so the issuer/verifier hash firewall holds.
    /// </summary>
    /// <param name="input">The bytes to hash.</param>
    /// <returns>The base64url multibase MBHash string.</returns>
    public static string MbHash(ReadOnlySpan<byte> input)
    {
        Span<byte> digest = stackalloc byte[Blake3DigestLength];
        Blake3(input, digest);

        Span<byte> multihashHeader = stackalloc byte[MultihashCode.Length + 1];
        MultihashCode.Span.CopyTo(multihashHeader);
        multihashHeader[MultihashCode.Length] = (byte)Blake3DigestLength;

        return MultibaseSerializer.Encode(digest, multihashHeader, MultibaseAlgorithms.Base64Url, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Mints a microledger for a host (no path), chaining each document to its predecessor: document <c>i</c>'s
    /// <c>updateRules</c> is a <c>key</c> rule over <paramref name="plans"/>[i]'s update key, and document
    /// <c>i</c> (for <c>i &gt; 0</c>) is signed by document <c>i-1</c>'s update key. The first plan mints the root.
    /// </summary>
    /// <param name="host">The DID host (for example <c>example.com</c>).</param>
    /// <param name="plans">The ordered document plans, root first.</param>
    /// <returns>The minted DID, its microledger lines and each document's selfHash.</returns>
    public static async Task<WebPlusMintedDid> MintAsync(string host, IReadOnlyList<WebPlusDocPlan> plans)
    {
        ArgumentNullException.ThrowIfNull(plans);
        if(plans.Count == 0)
        {
            throw new ArgumentException("At least the root plan is required.", nameof(plans));
        }

        string placeholder = WebPlusMbHash.Placeholder(MultihashCode.Span, Blake3DigestLength, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        //The root document's id carries its own selfHash in the trailing segment, so the id is built with the
        //placeholder and resolved once the root selfHash is known. Every later document uses that fixed DID.
        var lines = ImmutableArray.CreateBuilder<string>(plans.Count);
        var selfHashes = ImmutableArray.CreateBuilder<string>(plans.Count);

        string placeholderDid = $"did:webplus:{host}:{placeholder}";
        string rootLine = MintRoot(placeholderDid, plans[0], placeholder);
        string rootSelfHash = ReadSelfHash(rootLine);
        string did = $"did:webplus:{host}:{rootSelfHash}";

        lines.Add(rootLine);
        selfHashes.Add(rootSelfHash);

        string predecessorSelfHash = rootSelfHash;
        for(int i = 1; i < plans.Count; i++)
        {
            string line = await MintNonRoot(did, plans[i], plans[i - 1].UpdateKey!, predecessorSelfHash, placeholder).ConfigureAwait(false);
            string selfHash = ReadSelfHash(line);
            lines.Add(line);
            selfHashes.Add(selfHash);
            predecessorSelfHash = selfHash;
        }

        return new WebPlusMintedDid(did, lines.ToImmutable(), selfHashes.ToImmutable());
    }


    /// <summary>Joins minted lines into a <c>did-documents.jsonl</c> body (newline-delimited JCS documents).</summary>
    /// <param name="lines">The minted document lines, in order.</param>
    /// <returns>The microledger body.</returns>
    public static string ToMicroledger(ImmutableArray<string> lines) => string.Join('\n', lines);


    /// <summary>
    /// Mints the root document: <c>updateRules</c> = <c>key</c> over the plan's update key, no predecessor, no
    /// proofs (a root document MAY omit them). The id's trailing segment, the <c>selfHash</c> field and the
    /// verification method's <c>selfHash</c> query parameter are the self-hash slots.
    /// </summary>
    /// <param name="placeholderDid">The DID with its trailing root-self-hash segment set to the placeholder.</param>
    /// <param name="plan">The root plan.</param>
    /// <param name="placeholder">The MBHash placeholder occupying every self-hash slot before self-hashing.</param>
    /// <returns>The self-hashed root document as its JCS line.</returns>
    private static string MintRoot(string placeholderDid, WebPlusDocPlan plan, string placeholder)
    {
        JsonObject document = BuildDocumentJson(
            plan.IdOverride ?? placeholderDid, plan, placeholder, predecessorSelfHash: null);

        return SelfHash(Jcs.CanonicalizeToUtf8Bytes(document.ToJsonString()), placeholder);
    }


    /// <summary>
    /// Mints a non-root document: it references the fixed DID, chains to its predecessor by
    /// <c>prevDIDDocumentSelfHash</c>, declares its own <c>updateRules</c>, and carries a detached-JWS proof from
    /// <paramref name="signer"/> over the placeholder form. The <c>selfHash</c> field and the verification
    /// method's <c>selfHash</c> query parameter are the self-hash slots.
    /// </summary>
    /// <param name="did">The fixed DID (every document's <c>id</c>).</param>
    /// <param name="plan">The document plan.</param>
    /// <param name="predecessorUpdateKey">The predecessor's update key, the controller authorizing this update unless the plan's <see cref="WebPlusDocPlan.SignerOverride"/> replaces it.</param>
    /// <param name="predecessorSelfHash">The predecessor document's selfHash, referenced as <c>prevDIDDocumentSelfHash</c>.</param>
    /// <param name="placeholder">The MBHash placeholder occupying the self-hash slot before self-hashing.</param>
    /// <returns>The self-hashed, proof-signed non-root document as its JCS line.</returns>
    private static async Task<string> MintNonRoot(string did, WebPlusDocPlan plan, WebPlusController predecessorUpdateKey, string predecessorSelfHash, string placeholder)
    {
        JsonObject unsigned = BuildDocumentJson(
            plan.IdOverride ?? did, plan, placeholder, plan.PrevSelfHashOverride ?? predecessorSelfHash);

        //The proof signs S = JCS(document with proofs removed and self-hash slots = placeholder). At this point
        //the document carries no proofs and its slots are already the placeholder, so S is its JCS as-is. The
        //signer is the predecessor's update key unless a SignerOverride mints a proof from an unauthorized key
        //(the WP-VAL-7e negative).
        WebPlusController signer = plan.SignerOverride ?? predecessorUpdateKey;
        byte[] signingInput = Jcs.CanonicalizeToUtf8Bytes(unsigned.ToJsonString());
        string proof = await BuildProofAsync(signer, signingInput, plan.ProofHeaderMutator, plan.RawProofHeaderMutator).ConfigureAwait(false);

        //The proofs member is an array of the detached-JWS proofs; a ProofsMutator can replace it with a
        //non-array shape (the WP-DM-6 negative).
        JsonArray proofs = new(proof);
        unsigned["proofs"] = plan.ProofsMutator is { } mutateProofs ? mutateProofs(proofs) : proofs;

        return SelfHash(Jcs.CanonicalizeToUtf8Bytes(unsigned.ToJsonString()), placeholder);
    }


    /// <summary>
    /// Builds a did:webplus document as a JSON object: the standard W3C parts (the verification method and its
    /// relationships) are produced through the SHARED library construction
    /// (<see cref="DidBuilderExtensions.CreateVerificationMethod"/> +
    /// <see cref="DidDocumentVerificationExtensions.WithStandardVerificationRelationships"/>) — the same standard
    /// step every DID method builder uses, here with the did:webplus verification-method id format. The
    /// method-specific control fields (<c>selfHash</c>, <c>prevDIDDocumentSelfHash</c>, <c>updateRules</c>,
    /// <c>validFrom</c>, <c>versionId</c>) are then merged in, kept explicit so the minter stays an independent
    /// firewall oracle. A deactivation document carries no verification method (the tombstone).
    /// </summary>
    /// <param name="id">The document's <c>id</c> (the placeholder DID for the root, the fixed DID otherwise).</param>
    /// <param name="plan">The document plan supplying the update key, version and timestamps.</param>
    /// <param name="placeholder">The MBHash placeholder occupying every self-hash slot before self-hashing.</param>
    /// <param name="predecessorSelfHash">The predecessor's selfHash for a non-root document, or <see langword="null"/> for the root.</param>
    /// <returns>The placeholder-form document as a JSON object (without proofs).</returns>
    private static JsonObject BuildDocumentJson(string id, WebPlusDocPlan plan, string placeholder, string? predecessorSelfHash)
    {
        ulong versionId = plan.VersionIdOverride ?? (ulong)plan.VersionId;

        //The standard verification method + relationships come from the shared library construction; a
        //deactivation document publishes no verification method (RECOMMENDED tombstone with no keys).
        DidDocument didDocument = new() { Id = new GenericDidMethod(id) };
        if(!plan.Deactivate && plan.UpdateKey is WebPlusController verificationKey)
        {
            //The did:webplus verification-method id carries the document's selfHash (placeholder here) and
            //versionId as query parameters and a key fragment — the fully-qualified key resource form. A
            //VerificationMethodIdMutator can drop or reorder those query parameters (the WP-VAL-5a negative).
            string verificationMethodId = $"{id}?selfHash={placeholder}&versionId={versionId}#0";
            if(plan.VerificationMethodIdMutator is { } mutateId)
            {
                verificationMethodId = mutateId(verificationMethodId);
            }

            VerificationMethod verificationMethod = DidBuilderExtensions.CreateVerificationMethod(
                verificationKey.PublicKey, MultikeyVerificationMethodTypeInfo.Instance, verificationMethodId, id);
            didDocument.VerificationMethod = [verificationMethod];
            didDocument.WithStandardVerificationRelationships(verificationKey.PublicKey, verificationMethodId);
        }

        JsonObject document = JsonNode.Parse(JsonSerializerExtensions.Serialize(didDocument, TestSetup.DefaultSerializationOptions))!.AsObject();
        document["selfHash"] = placeholder;
        if(predecessorSelfHash is not null)
        {
            document["prevDIDDocumentSelfHash"] = predecessorSelfHash;
        }

        //An UpdateRulesJsonOverride mints a document whose updateRules is a deliberately-degenerate or malformed
        //form (an empty 'all', a non-positive 'atLeast', a multi-discriminator object) that the verifier's strict
        //parser must reject.
        document["updateRules"] = plan.UpdateRulesJsonOverride is { } rulesJson
            ? JsonNode.Parse(rulesJson)
            : BuildUpdateRules(plan);
        document["validFrom"] = plan.ValidFrom;
        document["versionId"] = versionId;

        return document;
    }


    /// <summary>Builds a document's <c>updateRules</c> JSON: the empty object <c>{}</c> when deactivating, else a <c>key</c> rule.</summary>
    /// <param name="plan">The document plan.</param>
    /// <returns>The <c>updateRules</c> value.</returns>
    private static JsonObject BuildUpdateRules(WebPlusDocPlan plan)
    {
        if(plan.Deactivate)
        {
            return new JsonObject();
        }

        return new JsonObject { ["key"] = plan.UpdateKey!.MbPubKey };
    }


    /// <summary>
    /// Self-hashes a placeholder form: hash the placeholder'd JCS bytes to the MBHash digest, then replace every
    /// placeholder occurrence with that digest (length-preserving, so the result stays JCS-canonical).
    /// </summary>
    /// <param name="placeholderedJcs">The JCS bytes with every self-hash slot set to the placeholder.</param>
    /// <param name="placeholder">The MBHash placeholder string.</param>
    /// <returns>The self-hashed document as its JCS line.</returns>
    private static string SelfHash(byte[] placeholderedJcs, string placeholder)
    {
        string selfHash = MbHash(placeholderedJcs);

        return Encoding.UTF8.GetString(placeholderedJcs).Replace(placeholder, selfHash, StringComparison.Ordinal);
    }


    /// <summary>
    /// Builds one did:webplus proof: a detached, unencoded-payload (RFC 7797 <c>b64:false</c>) compact JWS over
    /// the signing input <c>S</c>, with the header <c>{"alg":"Ed25519","kid":"&lt;MBPubKey&gt;","crit":["b64"],"b64":false}</c>.
    /// </summary>
    /// <param name="signer">The controller whose Ed25519 key signs the proof.</param>
    /// <param name="signingInput">The detached payload <c>S</c> the proof signs over.</param>
    /// <param name="headerMutator">An optional transform of the protected header applied BEFORE it is encoded and signed, so the signature stays valid for a deliberately-malformed header (the WP-PRF-2/3 negatives); <see langword="null"/> mints a conformant header.</param>
    /// <param name="rawHeaderMutator">An optional transform of the protected header's JSON text applied AFTER serialization and before encoding, minting a header shape a <see cref="JsonObject"/> cannot express (a repeated top-level member); the signature stays valid over the mutated bytes.</param>
    /// <returns>The compact detached JWS (<c>&lt;header&gt;..&lt;signature&gt;</c>).</returns>
    private static async Task<string> BuildProofAsync(WebPlusController signer, ReadOnlyMemory<byte> signingInput, WebPlusProofHeaderMutator? headerMutator, WebPlusProofHeaderTextMutator? rawHeaderMutator)
    {
        JsonObject header = new()
        {
            ["alg"] = WellKnownWebPlusValues.Ed25519SignatureAlgorithm,
            ["kid"] = signer.MbPubKey,
            ["crit"] = new JsonArray("b64"),
            ["b64"] = false
        };

        //Mutating the header (as a JSON object) before it is encoded keeps the signature valid over the malformed
        //header, so a WP-PRF-2/3 negative exercises only the header-shape rejection, never a signature mismatch.
        if(headerMutator is not null)
        {
            header = headerMutator(header);
        }

        //A raw text mutation, applied after serialization, mints a header a JsonObject cannot represent — for
        //example a repeated top-level member — while keeping the signature valid over the exact mutated bytes.
        string headerText = rawHeaderMutator is not null ? rawHeaderMutator(header.ToJsonString()) : header.ToJsonString();

        //The protected segment is the base64url of the header's UTF-8 bytes, written into a pooled buffer and
        //encoded through the shared encoder delegate (never a raw BCL Base64 call).
        int headerByteCount = Encoding.UTF8.GetByteCount(headerText);
        using IMemoryOwner<byte> headerOwner = BaseMemoryPool.Shared.Rent(headerByteCount);
        Encoding.UTF8.GetBytes(headerText, headerOwner.Memory.Span[..headerByteCount]);
        string protectedSegment = TestSetup.Base64UrlEncoder(headerOwner.Memory.Span[..headerByteCount]);

        //The RFC 7797 unencoded-payload (b64:false) signing input — ASCII(protected) '.' rawPayload(S) — assembled
        //into a pooled buffer by the shared JWS signing-input helper, then signed by the independent Ed25519 key.
        using IMemoryOwner<byte> signingInputOwner = Jws.RentSigningInput(
            protectedSegment, signingInput.Span, base64UrlPayload: false, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared, out int signingInputLength);

        using Signature signature = await signer.SignAsync(signingInputOwner.Memory[..signingInputLength]).ConfigureAwait(false);
        string signatureSegment = TestSetup.Base64UrlEncoder(signature.AsReadOnlyMemory().Span);

        //A detached compact JWS leaves the payload segment empty: <protected>..<signature>.
        return $"{protectedSegment}..{signatureSegment}";
    }


    /// <summary>Reads the <c>selfHash</c> field value out of a minted JCS document line.</summary>
    /// <param name="line">The minted JCS document.</param>
    /// <returns>The document's <c>selfHash</c>.</returns>
    private static string ReadSelfHash(string line)
    {
        JsonObject document = JsonNode.Parse(line)!.AsObject();

        return (string)document["selfHash"]!;
    }
}


/// <summary>
/// A did:webplus controller backed by a freshly generated Ed25519 key: its MBPubKey (base58btc multikey, which
/// equals the did:key method id) used both as an <c>updateRules</c> <c>key</c> value and as a proof <c>kid</c>,
/// and the Ed25519 signing that produces each detached-JWS proof signature.
/// </summary>
internal sealed class WebPlusController: IDisposable
{
    /// <summary>The controller's public key material, used to build the document's verification method (disposed with the controller).</summary>
    public PublicKeyMemory PublicKey { get; }

    /// <summary>The controller's Ed25519 signing key (disposed with the controller).</summary>
    private PrivateKey SigningKey { get; }


    /// <summary>Creates a controller over the given key material and MBPubKey.</summary>
    /// <param name="publicKey">The public key material.</param>
    /// <param name="signingKey">The Ed25519 signing key.</param>
    /// <param name="mbPubKey">The base58btc MBPubKey string.</param>
    private WebPlusController(PublicKeyMemory publicKey, PrivateKey signingKey, string mbPubKey)
    {
        PublicKey = publicKey;
        SigningKey = signingKey;
        MbPubKey = mbPubKey;
    }


    /// <summary>The Ed25519 public key as a base58btc MBPubKey (identical to the <c>did:key</c> method id).</summary>
    public string MbPubKey { get; }


    /// <summary>Generates a new Ed25519 controller key.</summary>
    /// <returns>The new controller.</returns>
    public static WebPlusController Create()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = BouncyCastleKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
        string mbPubKey = MultibaseSerializer.EncodeKey(keys.PublicKey, TestSetup.Base58Encoder);
        PrivateKey signingKey = CryptographicKeyFactory.CreatePrivateKey(keys.PrivateKey, "webplus-test", keys.PrivateKey.Tag);

        return new WebPlusController(keys.PublicKey, signingKey, mbPubKey);
    }


    /// <summary>Signs the given bytes with this controller's Ed25519 key, returning the raw signature carrier.</summary>
    /// <param name="data">The bytes to sign (the RFC 7797 JWS signing input).</param>
    /// <returns>The signature; the caller disposes it and encodes it through the shared encoder delegate.</returns>
    public ValueTask<Signature> SignAsync(ReadOnlyMemory<byte> data)
    {
        return SigningKey.SignAsync(data, BaseMemoryPool.Shared);
    }


    /// <inheritdoc />
    public void Dispose()
    {
        SigningKey.Dispose();
        PublicKey.Dispose();
    }
}


/// <summary>Transforms a did:webplus proof's protected header (as a JSON object) before it is encoded and signed, minting a deliberately-malformed but validly-signed proof (the WP-PRF-2/3 negatives).</summary>
/// <param name="header">The conformant protected header.</param>
/// <returns>The mutated header.</returns>
internal delegate JsonObject WebPlusProofHeaderMutator(JsonObject header);


/// <summary>Transforms a did:webplus proof's protected-header JSON text after serialization, minting a header shape a <see cref="JsonObject"/> cannot express (a repeated top-level member) while keeping the signature valid over the mutated bytes.</summary>
/// <param name="headerJson">The serialized protected header.</param>
/// <returns>The mutated header text.</returns>
internal delegate string WebPlusProofHeaderTextMutator(string headerJson);


/// <summary>Transforms a did:webplus verification method <c>id</c> before self-hashing, dropping or reordering its query parameters (the WP-VAL-5a negative).</summary>
/// <param name="verificationMethodId">The conformant verification method id.</param>
/// <returns>The mutated id.</returns>
internal delegate string WebPlusVerificationMethodIdMutator(string verificationMethodId);


/// <summary>Transforms a did:webplus document's single-element <c>proofs</c> array into the value stored as its <c>proofs</c> member, minting a non-array shape (WP-DM-6) or an empty array (the non-root-carries-no-proof negative).</summary>
/// <param name="proofs">The single-element proofs array the minter built.</param>
/// <returns>The value to store as the document's <c>proofs</c> member.</returns>
internal delegate JsonNode WebPlusProofsMutator(JsonArray proofs);


/// <summary>
/// One did:webplus document to mint: the key governing the next update (this document's <c>updateRules</c>), its
/// <c>versionId</c> and <c>validFrom</c>, and optional overrides used to mint deliberately-invalid documents for
/// the negative validation tests.
/// </summary>
/// <param name="UpdateKey">The controller whose key is this document's <c>updateRules</c> <c>key</c> rule, or <see langword="null"/> when deactivating.</param>
/// <param name="VersionId">This document's <c>versionId</c> (0 for the root; the chain index otherwise).</param>
/// <param name="ValidFrom">This document's <c>validFrom</c> timestamp.</param>
/// <param name="Deactivate">When <see langword="true"/>, <c>updateRules</c> is the empty <c>{}</c> tombstone (no <see cref="UpdateKey"/>).</param>
/// <param name="VersionIdOverride">An explicit <c>versionId</c> overriding <see cref="VersionId"/> (for the WP-VAL-7d negative).</param>
/// <param name="IdOverride">An explicit <c>id</c> overriding the DID (for the WP-VAL-7a negative).</param>
/// <param name="PrevSelfHashOverride">An explicit <c>prevDIDDocumentSelfHash</c> overriding the predecessor's selfHash (for the WP-VAL-7b negative).</param>
/// <param name="ProofHeaderMutator">A transform of the proof's protected header applied before it is encoded and signed, minting a deliberately-malformed but validly-signed proof (for the WP-PRF-2/3 negatives).</param>
/// <param name="SignerOverride">The controller signing this document's proof, replacing the predecessor's update key, so a proof from a key the predecessor's <c>updateRules</c> do not authorize can be minted (for the WP-VAL-7e negative).</param>
/// <param name="VerificationMethodIdMutator">A transform of the verification method <c>id</c> applied before self-hashing, dropping or reordering its <c>selfHash</c>/<c>versionId</c> query parameters (for the WP-VAL-5a negative).</param>
/// <param name="ProofsMutator">A transform of the single-element <c>proofs</c> array into the value stored as the document's <c>proofs</c> member, minting a non-array <c>proofs</c> shape (for the WP-DM-6 negative) or an empty <c>proofs</c> array (for the non-root-carries-no-proof negative).</param>
/// <param name="UpdateRulesJsonOverride">A raw JSON value replacing the document's <c>updateRules</c>, minting a deliberately-degenerate or malformed rule (an empty <c>all</c>, a non-positive <c>atLeast</c>, a multi-discriminator object) the strict parser must reject.</param>
/// <param name="RawProofHeaderMutator">A transform of the proof's protected-header JSON text applied after serialization, minting a header shape a <see cref="JsonObject"/> cannot express (a repeated top-level member) while keeping the signature valid over the mutated bytes.</param>
internal sealed record WebPlusDocPlan(
    WebPlusController? UpdateKey,
    int VersionId,
    string ValidFrom,
    bool Deactivate = false,
    ulong? VersionIdOverride = null,
    string? IdOverride = null,
    string? PrevSelfHashOverride = null,
    WebPlusProofHeaderMutator? ProofHeaderMutator = null,
    WebPlusController? SignerOverride = null,
    WebPlusVerificationMethodIdMutator? VerificationMethodIdMutator = null,
    WebPlusProofsMutator? ProofsMutator = null,
    string? UpdateRulesJsonOverride = null,
    WebPlusProofHeaderTextMutator? RawProofHeaderMutator = null);


/// <summary>A minted did:webplus microledger: the resolved DID, its JCS document lines, and each document's selfHash.</summary>
/// <param name="Did">The resolved <c>did:webplus</c> identifier.</param>
/// <param name="Lines">The <c>did-documents.jsonl</c> lines, in order.</param>
/// <param name="SelfHashes">Each document's <c>selfHash</c>, in order.</param>
internal sealed record WebPlusMintedDid(
    string Did,
    ImmutableArray<string> Lines,
    ImmutableArray<string> SelfHashes);
