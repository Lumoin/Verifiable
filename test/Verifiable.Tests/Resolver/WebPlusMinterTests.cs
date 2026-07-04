using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Verifiable.Core.Resolvers;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests that drive the independent <see cref="WebPlusMinter"/> against the verifier under test: a faithfully
/// minted microledger round-trips through <see cref="Verifiable.Core.Did.Methods.WebPlus.WebPlusDidResolver"/>
/// (proving the minter is a valid oracle), and a microledger with exactly one violated cross-document field is
/// rejected — the isolated WP-VAL-7 negatives a static fixture cannot express (tampering one field of a minted
/// document would break its selfHash). The minter mints each broken document with a valid selfHash and a valid
/// proof, so only the targeted cross-document obligation fails.
/// </summary>
[TestClass]
internal sealed class WebPlusMinterTests
{
    private const string Host = "example.com";
    private const string RootTime = "2025-01-01T00:00:00Z";
    private const string SecondTime = "2025-02-01T00:00:00Z";
    private const string ThirdTime = "2025-03-01T00:00:00Z";

    /// <summary>The cancellation-token source for the test.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>A minted two-document microledger round-trips: it resolves to the latest version through the real resolver.</summary>
    [TestMethod]
    public async Task MintedChainRoundTripsThroughResolver()
    {
        using WebPlusController root = WebPlusController.Create();
        using WebPlusController next = WebPlusController.Create();
        WebPlusMintedDid minted = await WebPlusMinter.MintAsync(Host,
        [
            new WebPlusDocPlan(root, VersionId: 0, RootTime),
            new WebPlusDocPlan(next, VersionId: 1, SecondTime)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(minted).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A faithfully minted did:webplus microledger MUST resolve. Error: {result.ResolutionMetadata.Error?.Detail}.");
        Assert.AreEqual(minted.Did, result.Document!.Id?.ToString());
        Assert.AreEqual("1", result.DocumentMetadata.VersionId);
        Assert.IsFalse(result.DocumentMetadata.Deactivated);
    }


    /// <summary>A minted deactivation (versionId-1 <c>updateRules: {}</c>) resolves as deactivated with no document.</summary>
    [TestMethod]
    public async Task MintedDeactivationResolvesAsDeactivated()
    {
        using WebPlusController root = WebPlusController.Create();
        using WebPlusController next = WebPlusController.Create();
        WebPlusMintedDid minted = await WebPlusMinter.MintAsync(Host,
        [
            new WebPlusDocPlan(root, VersionId: 0, RootTime),
            new WebPlusDocPlan(next, VersionId: 1, SecondTime, Deactivate: true)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(minted).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A minted deactivation MUST resolve with deactivated metadata. Error: {result.ResolutionMetadata.Error?.Detail}.");
        Assert.IsNull(result.Document, "A deactivated DID MUST NOT return a DIDDoc.");
        Assert.IsTrue(result.DocumentMetadata.Deactivated);
        Assert.AreEqual("1", result.DocumentMetadata.VersionId);
    }


    /// <summary>WP-VAL-7a: a non-root document whose <c>id</c> differs from its predecessor's MUST be rejected.</summary>
    [TestMethod]
    public async Task RejectsNonRootIdNotIdenticalToPredecessor()
    {
        using WebPlusController root = WebPlusController.Create();
        using WebPlusController next = WebPlusController.Create();
        WebPlusMintedDid minted = await WebPlusMinter.MintAsync(Host,
        [
            new WebPlusDocPlan(root, VersionId: 0, RootTime),
            new WebPlusDocPlan(next, VersionId: 1, SecondTime, IdOverride: "did:webplus:example.com:uHiCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(minted).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A non-root document whose id differs from its predecessor's MUST be rejected.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>WP-VAL-7c: a non-root <c>validFrom</c> not strictly later than its predecessor's MUST be rejected.</summary>
    [TestMethod]
    public async Task RejectsNonRootValidFromNotStrictlyLater()
    {
        using WebPlusController root = WebPlusController.Create();
        using WebPlusController next = WebPlusController.Create();
        WebPlusMintedDid minted = await WebPlusMinter.MintAsync(Host,
        [
            new WebPlusDocPlan(root, VersionId: 0, SecondTime),
            //versionId-1 validFrom is BEFORE the root's, violating the strictly-later obligation.
            new WebPlusDocPlan(next, VersionId: 1, RootTime)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(minted).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A non-root validFrom not strictly later than its predecessor's MUST be rejected.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>WP-VAL-7d: a non-root <c>versionId</c> not exactly one greater than its predecessor's MUST be rejected.</summary>
    [TestMethod]
    public async Task RejectsNonRootVersionIdNotIncremented()
    {
        using WebPlusController root = WebPlusController.Create();
        using WebPlusController next = WebPlusController.Create();
        WebPlusMintedDid minted = await WebPlusMinter.MintAsync(Host,
        [
            new WebPlusDocPlan(root, VersionId: 0, RootTime),
            //versionId 5 instead of 1: not exactly predecessor + 1.
            new WebPlusDocPlan(next, VersionId: 1, SecondTime, VersionIdOverride: 5)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(minted).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A non-root versionId not exactly predecessor + 1 MUST be rejected.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>WP-VAL-7b: a non-root <c>prevDIDDocumentSelfHash</c> not equal to the predecessor's selfHash MUST be rejected.</summary>
    [TestMethod]
    public async Task RejectsNonRootBrokenPrevSelfHash()
    {
        using WebPlusController root = WebPlusController.Create();
        using WebPlusController next = WebPlusController.Create();
        WebPlusMintedDid minted = await WebPlusMinter.MintAsync(Host,
        [
            new WebPlusDocPlan(root, VersionId: 0, RootTime),
            new WebPlusDocPlan(next, VersionId: 1, SecondTime, PrevSelfHashOverride: "uHiCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(minted).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A non-root prevDIDDocumentSelfHash not equal to the predecessor's selfHash MUST be rejected.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>An update appended after a deactivation MUST be rejected: a tombstoned DID authorizes no further updates.</summary>
    [TestMethod]
    public async Task RejectsUpdateAfterDeactivation()
    {
        using WebPlusController root = WebPlusController.Create();
        using WebPlusController afterDeactivation = WebPlusController.Create();
        using WebPlusController revived = WebPlusController.Create();
        WebPlusMintedDid minted = await WebPlusMinter.MintAsync(Host,
        [
            new WebPlusDocPlan(root, VersionId: 0, RootTime),
            //versionId-1 deactivates (updateRules {}); its update key still signs the (illegitimate) versionId-2.
            new WebPlusDocPlan(afterDeactivation, VersionId: 1, SecondTime, Deactivate: true),
            new WebPlusDocPlan(revived, VersionId: 2, ThirdTime)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(minted).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "An update appended after a deactivation MUST be rejected.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>
    /// WP-PRF-2: a proof whose header sets the RFC 7797 <c>b64</c> to true (claiming an encoded payload) MUST be
    /// rejected. The header is mutated before signing, so the signature is valid over the malformed header and the
    /// only failure is the header-shape rejection.
    /// </summary>
    [TestMethod]
    public async Task RejectsProofHeaderWithB64True()
    {
        using WebPlusController root = WebPlusController.Create();
        using WebPlusController next = WebPlusController.Create();
        WebPlusMintedDid minted = await WebPlusMinter.MintAsync(Host,
        [
            new WebPlusDocPlan(root, VersionId: 0, RootTime),
            new WebPlusDocPlan(next, VersionId: 1, SecondTime, ProofHeaderMutator: WithB64True)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(minted).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A did:webplus proof header that sets 'b64' to true MUST be rejected.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>
    /// WP-PRF-2: a proof whose header omits <c>kid</c> MUST be rejected — the header carries no signing-key name.
    /// The header is mutated before signing, isolating the header-shape rejection from any signature mismatch.
    /// </summary>
    [TestMethod]
    public async Task RejectsProofHeaderMissingKid()
    {
        using WebPlusController root = WebPlusController.Create();
        using WebPlusController next = WebPlusController.Create();
        WebPlusMintedDid minted = await WebPlusMinter.MintAsync(Host,
        [
            new WebPlusDocPlan(root, VersionId: 0, RootTime),
            new WebPlusDocPlan(next, VersionId: 1, SecondTime, ProofHeaderMutator: WithoutKid)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(minted).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A did:webplus proof header without a 'kid' MUST be rejected.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>
    /// WP-PRF-2: a proof whose header omits <c>alg</c> MUST be rejected — the header carries no algorithm name. The
    /// header is mutated before signing, isolating the header-shape rejection from any signature mismatch.
    /// </summary>
    [TestMethod]
    public async Task RejectsProofHeaderMissingAlg()
    {
        using WebPlusController root = WebPlusController.Create();
        using WebPlusController next = WebPlusController.Create();
        WebPlusMintedDid minted = await WebPlusMinter.MintAsync(Host,
        [
            new WebPlusDocPlan(root, VersionId: 0, RootTime),
            new WebPlusDocPlan(next, VersionId: 1, SecondTime, ProofHeaderMutator: WithoutAlg)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(minted).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A did:webplus proof header without an 'alg' MUST be rejected.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>
    /// WP-PRF-2: a proof whose header carries a <c>crit</c> that does not mark <c>b64</c> critical MUST be rejected
    /// (the b64 unencoded-payload extension MUST be marked critical). The header is mutated before signing, so the
    /// signature is valid over the malformed header and the only failure is the missing critical marking.
    /// </summary>
    [TestMethod]
    public async Task RejectsProofHeaderCritMissingB64()
    {
        using WebPlusController root = WebPlusController.Create();
        using WebPlusController next = WebPlusController.Create();
        WebPlusMintedDid minted = await WebPlusMinter.MintAsync(Host,
        [
            new WebPlusDocPlan(root, VersionId: 0, RootTime),
            new WebPlusDocPlan(next, VersionId: 1, SecondTime, ProofHeaderMutator: WithCritNotMarkingB64)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(minted).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A did:webplus proof header whose 'crit' does not mark 'b64' critical MUST be rejected.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>
    /// WP-PRF-2 / RFC 7797 §6: a proof whose header sets <c>b64:false</c> but omits <c>crit</c> entirely MUST be
    /// rejected — an unencoded-payload JWS MUST list <c>b64</c> in <c>crit</c> so a consumer that does not implement
    /// RFC 7797 rejects it rather than mis-verifying the payload as base64url. The header is mutated before signing,
    /// isolating the missing-critical-marking rejection from any signature mismatch.
    /// </summary>
    [TestMethod]
    public async Task RejectsProofHeaderWithCritAbsent()
    {
        using WebPlusController root = WebPlusController.Create();
        using WebPlusController next = WebPlusController.Create();
        WebPlusMintedDid minted = await WebPlusMinter.MintAsync(Host,
        [
            new WebPlusDocPlan(root, VersionId: 0, RootTime),
            new WebPlusDocPlan(next, VersionId: 1, SecondTime, ProofHeaderMutator: WithoutCrit)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(minted).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A did:webplus proof header that omits 'crit' entirely (a b64:false unencoded payload) MUST be rejected.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>
    /// WP-PRF-3: a proof whose header <c>alg</c> names an algorithm different from the Ed25519 key its <c>kid</c>
    /// names MUST be rejected (algorithm confusion). The header is mutated before signing, so the signature is
    /// valid over the malformed header and the only failure is the alg/key mismatch.
    /// </summary>
    [TestMethod]
    public async Task RejectsProofAlgKeyMismatch()
    {
        using WebPlusController root = WebPlusController.Create();
        using WebPlusController next = WebPlusController.Create();
        WebPlusMintedDid minted = await WebPlusMinter.MintAsync(Host,
        [
            new WebPlusDocPlan(root, VersionId: 0, RootTime),
            new WebPlusDocPlan(next, VersionId: 1, SecondTime, ProofHeaderMutator: WithMismatchedAlg)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(minted).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A did:webplus proof whose 'alg' does not match its key's algorithm MUST be rejected.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>
    /// WP-VAL-7e: a valid proof from a key the predecessor's <c>updateRules</c> do not authorize MUST be rejected.
    /// The versionId-1 proof is signed by a freshly generated key rather than the root's update key, so the proof
    /// verifies but does not satisfy the root's <c>key</c> rule.
    /// </summary>
    [TestMethod]
    public async Task RejectsProofFromUnauthorizedKey()
    {
        using WebPlusController root = WebPlusController.Create();
        using WebPlusController next = WebPlusController.Create();
        using WebPlusController unauthorized = WebPlusController.Create();
        WebPlusMintedDid minted = await WebPlusMinter.MintAsync(Host,
        [
            new WebPlusDocPlan(root, VersionId: 0, RootTime),
            new WebPlusDocPlan(next, VersionId: 1, SecondTime, SignerOverride: unauthorized)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(minted).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A valid proof from a key not authorized by the predecessor's updateRules MUST be rejected.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>
    /// WP-VAL-5a: a verification method <c>id</c> that drops the required <c>selfHash</c> query parameter MUST be
    /// rejected — the id no longer carries the document's selfHash and versionId as query parameters in the
    /// specified form. The document is otherwise validly self-hashed and proof-signed, isolating the id-form
    /// rejection.
    /// </summary>
    [TestMethod]
    public async Task RejectsVerificationMethodIdMissingSelfHashQueryParameter()
    {
        using WebPlusController root = WebPlusController.Create();
        using WebPlusController next = WebPlusController.Create();
        WebPlusMintedDid minted = await WebPlusMinter.MintAsync(Host,
        [
            new WebPlusDocPlan(root, VersionId: 0, RootTime),
            new WebPlusDocPlan(next, VersionId: 1, SecondTime, VerificationMethodIdMutator: DropSelfHashQueryParameter)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(minted).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A verification method id missing the required selfHash query parameter MUST be rejected.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>
    /// WP-DM-6: a document whose <c>proofs</c> member is a bare string rather than an array MUST be rejected — the
    /// proofs member, when present, MUST be an array of detached-JWS proofs.
    /// </summary>
    [TestMethod]
    public async Task RejectsNonArrayProofs()
    {
        using WebPlusController root = WebPlusController.Create();
        using WebPlusController next = WebPlusController.Create();
        WebPlusMintedDid minted = await WebPlusMinter.MintAsync(Host,
        [
            new WebPlusDocPlan(root, VersionId: 0, RootTime),
            new WebPlusDocPlan(next, VersionId: 1, SecondTime, ProofsMutator: ToSingleStringProofs)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(minted).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A did:webplus 'proofs' member that is not an array MUST be rejected.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>
    /// The zero-proof-takeover regression (Update Rules): a document whose <c>updateRules</c> is a degenerate,
    /// always-satisfied form — here an empty <c>all</c>, which would otherwise authorize any successor with no
    /// proof at all — MUST be rejected. The strict update-rule parser rejects the degenerate rule, so the whole
    /// microledger is invalid.
    /// </summary>
    [TestMethod]
    public async Task RejectsDocumentWithEmptyAllUpdateRule()
    {
        using WebPlusController root = WebPlusController.Create();
        WebPlusMintedDid minted = await WebPlusMinter.MintAsync(Host,
        [
            new WebPlusDocPlan(root, VersionId: 0, RootTime, UpdateRulesJsonOverride: """{"all":[]}""")
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(minted).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A document whose updateRules is a vacuously-satisfied empty 'all' MUST be rejected.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>
    /// A document whose <c>updateRules</c> is a non-positive <c>atLeast</c> threshold (satisfied by zero proofs)
    /// MUST be rejected — the second half of the zero-proof-takeover regression, the numeric-threshold form.
    /// </summary>
    [TestMethod]
    public async Task RejectsDocumentWithZeroAtLeastThreshold()
    {
        using WebPlusController root = WebPlusController.Create();
        WebPlusMintedDid minted = await WebPlusMinter.MintAsync(Host,
        [
            new WebPlusDocPlan(root, VersionId: 0, RootTime, UpdateRulesJsonOverride: """{"atLeast":0,"of":[{"key":"uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}""")
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(minted).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A document whose updateRules is a non-positive 'atLeast' threshold MUST be rejected.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>
    /// A non-root document that carries no proof MUST be rejected: each non-root DID document contains the proofs
    /// that satisfy the predecessor's <c>updateRules</c> (only the root MAY omit them). The versionId-1 document is
    /// minted with an empty <c>proofs</c> array against a normal <c>key</c> rule, so the missing-proof rejection is
    /// isolated (a defence-in-depth complement to rejecting degenerate rules at parse).
    /// </summary>
    [TestMethod]
    public async Task RejectsNonRootWithoutProofs()
    {
        using WebPlusController root = WebPlusController.Create();
        using WebPlusController next = WebPlusController.Create();
        WebPlusMintedDid minted = await WebPlusMinter.MintAsync(Host,
        [
            new WebPlusDocPlan(root, VersionId: 0, RootTime),
            new WebPlusDocPlan(next, VersionId: 1, SecondTime, ProofsMutator: ToEmptyProofs)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(minted).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A non-root document that carries no proof MUST be rejected.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
        //Assert the explicit at-least-one-proof rejection fires (not the generic updateRules-not-satisfied path),
        //so this guards the explicit check rather than passing on the rule evaluation returning false by chance.
        bool citesMissingProof = result.ResolutionMetadata.Error?.Detail?.Contains("at least one valid proof", StringComparison.Ordinal) ?? false;
        Assert.IsTrue(citesMissingProof, $"The rejection MUST cite the missing proof; detail was '{result.ResolutionMetadata.Error?.Detail}'.");
    }


    /// <summary>
    /// WP-PRF-2: a proof whose protected header repeats a top-level member MUST be rejected — the header is read
    /// first-occurrence while its exact bytes are what the signature covers, so a repeated member is an ambiguous,
    /// smuggling-prone shape. The header is duplicated as raw text (a <see cref="JsonObject"/> cannot repeat a
    /// member) and re-signed, isolating the duplicate-member rejection from any signature mismatch.
    /// </summary>
    [TestMethod]
    public async Task RejectsProofHeaderWithDuplicateMember()
    {
        using WebPlusController root = WebPlusController.Create();
        using WebPlusController next = WebPlusController.Create();
        WebPlusMintedDid minted = await WebPlusMinter.MintAsync(Host,
        [
            new WebPlusDocPlan(root, VersionId: 0, RootTime),
            new WebPlusDocPlan(next, VersionId: 1, SecondTime, RawProofHeaderMutator: DuplicateAlgMember)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(minted).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A did:webplus proof header that repeats a top-level member MUST be rejected.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>Sets the proof header's RFC 7797 <c>b64</c> to <see langword="true"/>, violating the unencoded-payload requirement (WP-PRF-2).</summary>
    /// <param name="header">The proof's protected header.</param>
    /// <returns>The mutated header.</returns>
    private static JsonObject WithB64True(JsonObject header)
    {
        header["b64"] = true;

        return header;
    }


    /// <summary>Removes the <c>kid</c> member so the proof header names no signing key (WP-PRF-2).</summary>
    /// <param name="header">The proof's protected header.</param>
    /// <returns>The mutated header.</returns>
    private static JsonObject WithoutKid(JsonObject header)
    {
        header.Remove("kid");

        return header;
    }


    /// <summary>Removes the <c>alg</c> member so the proof header names no algorithm (WP-PRF-2).</summary>
    /// <param name="header">The proof's protected header.</param>
    /// <returns>The mutated header.</returns>
    private static JsonObject WithoutAlg(JsonObject header)
    {
        header.Remove("alg");

        return header;
    }


    /// <summary>
    /// Replaces <c>crit</c> with a list that does not mark <c>b64</c> critical (it lists a benign extension member
    /// also added to the header), so the b64 unencoded-payload extension is left uncritical (WP-PRF-2).
    /// </summary>
    /// <param name="header">The proof's protected header.</param>
    /// <returns>The mutated header.</returns>
    private static JsonObject WithCritNotMarkingB64(JsonObject header)
    {
        //A crit that lists an extension present in the header but not 'b64': the header no longer marks the
        //RFC 7797 unencoded-payload extension critical.
        header["exp"] = 0;
        header["crit"] = new JsonArray("exp");

        return header;
    }


    /// <summary>Removes the <c>crit</c> member entirely, so a <c>b64:false</c> unencoded-payload proof fails to mark <c>b64</c> critical (WP-PRF-2 / RFC 7797 §6).</summary>
    /// <param name="header">The proof's protected header.</param>
    /// <returns>The mutated header.</returns>
    private static JsonObject WithoutCrit(JsonObject header)
    {
        header.Remove("crit");

        return header;
    }


    /// <summary>Sets the proof header <c>alg</c> to a signature algorithm other than the Ed25519 key's, forcing an algorithm-confusion mismatch (WP-PRF-3).</summary>
    /// <param name="header">The proof's protected header.</param>
    /// <returns>The mutated header.</returns>
    private static JsonObject WithMismatchedAlg(JsonObject header)
    {
        //An ECDSA P-256 algorithm name, which is not the Ed25519 algorithm the proof's kid MBPubKey fixes.
        header["alg"] = "ES256";

        return header;
    }


    /// <summary>
    /// Drops the <c>selfHash</c> query parameter from a verification method <c>id</c>, so it no longer carries the
    /// document's selfHash and versionId as query parameters in the specified form (WP-VAL-5a).
    /// </summary>
    /// <param name="verificationMethodId">The verification method id in its conformant form.</param>
    /// <returns>The verification method id with its <c>selfHash</c> query parameter removed.</returns>
    private static string DropSelfHashQueryParameter(string verificationMethodId)
    {
        int selfHash = verificationMethodId.IndexOf("selfHash=", StringComparison.Ordinal);
        int nextParameter = verificationMethodId.IndexOf('&', selfHash);

        return verificationMethodId.Remove(selfHash, nextParameter - selfHash + 1);
    }


    /// <summary>Replaces the single-element <c>proofs</c> array with the bare proof string, so <c>proofs</c> is not an array (WP-DM-6).</summary>
    /// <param name="proofs">The single-element proofs array the minter built.</param>
    /// <returns>The bare proof string as the <c>proofs</c> member value.</returns>
    private static JsonValue ToSingleStringProofs(JsonArray proofs)
    {
        return JsonValue.Create((string)proofs[0]!)!;
    }


    /// <summary>Replaces the single-element <c>proofs</c> array with an empty array, so a non-root document carries no proof.</summary>
    /// <param name="proofs">The single-element proofs array the minter built (discarded).</param>
    /// <returns>An empty proofs array.</returns>
    private static JsonArray ToEmptyProofs(JsonArray proofs)
    {
        _ = proofs;

        return new JsonArray();
    }


    /// <summary>Duplicates the proof header's <c>alg</c> member as raw text, so the header repeats a top-level member (WP-PRF-2).</summary>
    /// <param name="headerJson">The serialized proof protected header.</param>
    /// <returns>The header text with a repeated <c>alg</c> member.</returns>
    private static string DuplicateAlgMember(string headerJson)
    {
        return headerJson.Replace("\"alg\":\"Ed25519\"", "\"alg\":\"Ed25519\",\"alg\":\"Ed25519\"", StringComparison.Ordinal);
    }


    /// <summary>Resolves a minted microledger through the shared resolver harness.</summary>
    /// <param name="minted">The minted microledger.</param>
    /// <returns>The resolution result.</returns>
    private Task<DidResolutionResult> ResolveAsync(WebPlusMintedDid minted)
    {
        return WebPlusTestResolver.ResolveAsync(minted.Did, WebPlusMinter.ToMicroledger(minted.Lines), options: null, TestContext.CancellationToken);
    }
}
