using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.DidComm;
using Verifiable.Foundation;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Verifies the DIDComm v2.1 §DID Rotation <c>from_prior</c> mint and verify pipeline
/// (<see cref="DidCommFromPriorExtensions"/>) end to end against REAL Ed25519 <c>did:key</c> DIDs
/// resolved through <see cref="Verifiable.Core.Did.Methods.Key.KeyDidResolver"/>: a positive normal
/// rotation (verified through the encrypted authcrypt path — the spec MUST — and the signed path), a
/// positive rotate-to-nothing, and the fail-closed adversarial rejections (tampered signature, bad
/// <c>typ</c>, malformed <c>kid</c>, <c>kid</c> not authorized for authentication, unresolvable prior DID,
/// <c>sub</c>≠<c>from</c>, <c>kid</c> base DID ≠ <c>iss</c>, and the rotate-to-nothing presence violation).
/// The semantic tests run over the anoncrypt path — which authenticates no sender, so the rotation verify
/// is exercised in isolation — and each negative asserts the specific error code, that the rotation is
/// rejected, and that nothing throws.
/// </summary>
[TestClass]
internal sealed class DidCommFromPriorTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private const string MessageId = "1234567890";
    private const string MessageType = "https://example.com/protocols/lets_do_lunch/1.0/proposal";


    /// <summary>
    /// A normal rotation minted by the prior DID and packed authcrypt verifies on unpack: the rotation is
    /// recognized, <c>sub</c> == the message <c>from</c> (the new DID), the prior-DID <c>kid</c> is
    /// authorized for authentication, and <c>PriorDid</c> == <c>iss</c>. This is the spec MUST path — a
    /// rotation message MUST be encrypted (DIDComm v2.1 §DID Rotation).
    /// </summary>
    [TestMethod]
    public async Task NormalRotationAuthcryptVerifies()
    {
        await using var rotation = await RotationFixture.CreateAsync(Pool, TestContext.CancellationToken).ConfigureAwait(false);

        //The new DID (from / sub) is set inside the authcrypt helper to the X25519 sender DID so the
        //authcrypt from↔skid MUST and the from_prior sub==from MUST both hold.
        DidCommMessage message = NewMessage(from: null);
        (DidCommEncryptedUnpackResult result, string newDid) = await rotation.PackAndUnpackAuthcryptRotationAsync(message, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsUnpacked, $"The rotation message MUST unpack. Error: {result.Error}.");
        Assert.AreEqual(DidCommDecryptionError.None, result.Error);
        Assert.IsTrue(result.IsRotation, "A verified from_prior MUST be surfaced as a rotation.");
        Assert.AreEqual(rotation.PriorDid, result.PriorDid, "PriorDid MUST be the from_prior iss.");
        Assert.AreEqual(1516239022L, result.RotationIat, "The from_prior iat (RotationFixture.RotationTime in epoch seconds) MUST be surfaced for app-side pre-rotation ordering.");
        Assert.AreEqual(newDid, result.Message!.From, "The new DID (the message from / the JWT sub) is carried by the recovered plaintext.");
        Assert.IsTrue(rotation.IsPriorKidAuthorizedForAuthentication(), "The prior-DID kid MUST be authorized for authentication.");
    }


    /// <summary>The same normal rotation verifies on the SIGNED unpack path (reference-impl parity — from_prior is verified in every unpack mode).</summary>
    [TestMethod]
    public async Task NormalRotationSignedVerifies()
    {
        await using var rotation = await RotationFixture.CreateAsync(Pool, TestContext.CancellationToken).ConfigureAwait(false);

        DidCommMessage message = NewMessage(rotation.NewDid);
        await rotation.MintFromPriorAsync(message, TestContext.CancellationToken).ConfigureAwait(false);

        DidCommSignedVerificationResult result = await rotation.PackAndUnpackSignedAsync(message, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsVerified, $"The signed rotation message MUST verify. Error: {result.Error}.");
        Assert.IsTrue(result.IsRotation, "A verified from_prior MUST be surfaced as a rotation on the signed path too.");
        Assert.AreEqual(rotation.PriorDid, result.PriorDid);
        Assert.AreEqual(1516239022L, result.RotationIat, "The from_prior iat MUST be surfaced on the signed path too.");
        Assert.AreEqual(rotation.NewDid, result.Message!.From);
    }


    /// <summary>
    /// A nested signed-then-encrypted (anoncrypt(sign)) message whose inner signed JWM carries a from_prior
    /// rotation is VERIFIED, not force-rejected: the inner signature authenticates the new DID and the rotation
    /// is surfaced (the C1/C2 fix threads the from_prior deserializers into the nested signed unpack).
    /// </summary>
    [TestMethod]
    public async Task NestedSignedThenAnoncryptRotationVerifies()
    {
        await using var rotation = await RotationFixture.CreateAsync(Pool, TestContext.CancellationToken).ConfigureAwait(false);

        DidCommMessage message = NewMessage(rotation.NewDid);
        await rotation.MintFromPriorAsync(message, TestContext.CancellationToken).ConfigureAwait(false);

        DidCommEncryptedUnpackResult result = await rotation.PackSignedThenAnoncryptAndUnpackAsync(message, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsUnpacked, $"The nested signed+encrypted rotation MUST unpack. Error: {result.Error}.");
        Assert.AreEqual(DidCommDecryptionError.None, result.Error);
        Assert.IsTrue(result.IsSignedInner, "The inner message is signed.");
        Assert.IsTrue(result.IsSenderAuthenticated, "The verified inner signature authenticates the new DID.");
        Assert.IsTrue(result.IsRotation, "The inner from_prior rotation MUST be verified and surfaced (C1/C2).");
        Assert.AreEqual(rotation.PriorDid, result.PriorDid);
        Assert.AreEqual(1516239022L, result.RotationIat);
        Assert.AreEqual(rotation.NewDid, result.Message!.From);
    }


    /// <summary>
    /// A rotate-to-nothing (ending a relationship) — <c>sub</c> and the message <c>from</c> both omitted —
    /// verifies (DIDComm v2.1 §Ending a Relationship). Carried on the anoncrypt path since a message without
    /// a <c>from</c> cannot use authcrypt.
    /// </summary>
    [TestMethod]
    public async Task RotateToNothingVerifies()
    {
        await using var rotation = await RotationFixture.CreateAsync(Pool, TestContext.CancellationToken).ConfigureAwait(false);

        //Rotate-to-nothing: no `from`, and the JWT omits sub.
        DidCommMessage message = NewMessage(from: null);
        await rotation.MintFromPriorAsync(message, TestContext.CancellationToken).ConfigureAwait(false);

        DidCommEncryptedUnpackResult result = await rotation.PackAndUnpackAnoncryptAsync(message, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsUnpacked, $"A rotate-to-nothing MUST unpack. Error: {result.Error}.");
        Assert.IsTrue(result.IsRotation, "A verified rotate-to-nothing MUST be surfaced as a rotation.");
        Assert.AreEqual(rotation.PriorDid, result.PriorDid);
        Assert.IsNull(result.Message!.From, "Rotate-to-nothing omits the message from.");
    }


    /// <summary>A tampered from_prior signature is rejected by the cryptographic check (fail closed).</summary>
    [TestMethod]
    public async Task TamperedSignatureRejected()
    {
        await using var rotation = await RotationFixture.CreateAsync(Pool, TestContext.CancellationToken).ConfigureAwait(false);

        DidCommMessage message = NewMessage(rotation.NewDid);
        await rotation.MintFromPriorAsync(message, TestContext.CancellationToken).ConfigureAwait(false);

        //Flip the leading character of the compact JWT signature segment (still valid base64url, wrong
        //bytes — a leading-byte flip keeps the decoded signature 64 bytes, unlike a trailing-bit flip).
        message.FromPrior = TamperSignature(message.FromPrior!);

        DidCommEncryptedUnpackResult result = await rotation.PackAndUnpackAnoncryptAsync(message, TestContext.CancellationToken).ConfigureAwait(false);

        AssertRotationRejected(result, DidCommDecryptionError.RotationSignatureInvalid);
    }


    /// <summary>A from_prior JWT whose <c>typ</c> is not <c>JWT</c> is rejected as malformed.</summary>
    [TestMethod]
    public async Task TypNotJwtRejected()
    {
        await using var rotation = await RotationFixture.CreateAsync(Pool, TestContext.CancellationToken).ConfigureAwait(false);

        DidCommMessage message = NewMessage(rotation.NewDid);
        message.FromPrior = await rotation.MintRawFromPriorAsync(
            typ: "JWM", kid: rotation.PriorKid, iss: rotation.PriorDid, sub: rotation.NewDid, TestContext.CancellationToken).ConfigureAwait(false);

        DidCommEncryptedUnpackResult result = await rotation.PackAndUnpackAnoncryptAsync(message, TestContext.CancellationToken).ConfigureAwait(false);

        AssertRotationRejected(result, DidCommDecryptionError.RotationJwtMalformed);
    }


    /// <summary>A from_prior JWT whose <c>kid</c> is not a DID URL with a fragment is rejected as malformed.</summary>
    [TestMethod]
    public async Task KidNotDidUrlWithFragmentRejected()
    {
        await using var rotation = await RotationFixture.CreateAsync(Pool, TestContext.CancellationToken).ConfigureAwait(false);

        DidCommMessage message = NewMessage(rotation.NewDid);

        //kid is the bare prior DID with no fragment.
        message.FromPrior = await rotation.MintRawFromPriorAsync(
            typ: "JWT", kid: rotation.PriorDid, iss: rotation.PriorDid, sub: rotation.NewDid, TestContext.CancellationToken).ConfigureAwait(false);

        DidCommEncryptedUnpackResult result = await rotation.PackAndUnpackAnoncryptAsync(message, TestContext.CancellationToken).ConfigureAwait(false);

        AssertRotationRejected(result, DidCommDecryptionError.RotationJwtMalformed);
    }


    /// <summary>
    /// A from_prior <c>kid</c> that is a well-formed DID URL with a fragment but is NOT in the prior DID's
    /// authentication relationship is rejected (DIDComm v2.1 §DID Rotation: the kid MUST be authorized in
    /// the prior DID's document).
    /// </summary>
    [TestMethod]
    public async Task KidNotInAuthenticationRejected()
    {
        await using var rotation = await RotationFixture.CreateAsync(Pool, TestContext.CancellationToken).ConfigureAwait(false);

        DidCommMessage message = NewMessage(rotation.NewDid);

        //A kid whose base DID is the prior DID (so the kid/iss check passes) but whose fragment names a
        //verification method the resolved prior-DID document does not authorize for authentication.
        string unknownKid = $"{rotation.PriorDid}#not-an-authentication-key";
        message.FromPrior = await rotation.MintRawFromPriorAsync(
            typ: "JWT", kid: unknownKid, iss: rotation.PriorDid, sub: rotation.NewDid, TestContext.CancellationToken).ConfigureAwait(false);

        DidCommEncryptedUnpackResult result = await rotation.PackAndUnpackAnoncryptAsync(message, TestContext.CancellationToken).ConfigureAwait(false);

        AssertRotationRejected(result, DidCommDecryptionError.RotationSignerNotAuthorized);
    }


    /// <summary>A from_prior whose prior DID (<c>iss</c>) cannot be resolved is rejected (fail closed).</summary>
    [TestMethod]
    public async Task PriorDidNotResolvableRejected()
    {
        await using var rotation = await RotationFixture.CreateAsync(Pool, TestContext.CancellationToken).ConfigureAwait(false);

        DidCommMessage message = NewMessage(rotation.NewDid);
        await rotation.MintFromPriorAsync(message, TestContext.CancellationToken).ConfigureAwait(false);

        //Unpack against a resolver that fails every resolution: the prior DID cannot be found. Anoncrypt
        //resolves nothing else, so the failure is unambiguously the prior-DID resolution inside the verify.
        DidCommEncryptedUnpackResult result = await rotation.PackAndUnpackAnoncryptAsync(
            message, TestContext.CancellationToken, useFailingResolver: true).ConfigureAwait(false);

        AssertRotationRejected(result, DidCommDecryptionError.PriorDidResolutionFailed);
    }


    /// <summary>A from_prior whose <c>sub</c> does not equal the message <c>from</c> (the new DID) is rejected.</summary>
    [TestMethod]
    public async Task SubjectNotEqualFromRejected()
    {
        await using var rotation = await RotationFixture.CreateAsync(Pool, TestContext.CancellationToken).ConfigureAwait(false);

        //The message from is the new DID, but the JWT sub names a different (stranger) DID.
        DidCommMessage message = NewMessage(rotation.NewDid);
        message.FromPrior = await rotation.MintRawFromPriorAsync(
            typ: "JWT", kid: rotation.PriorKid, iss: rotation.PriorDid, sub: "did:example:stranger", TestContext.CancellationToken).ConfigureAwait(false);

        DidCommEncryptedUnpackResult result = await rotation.PackAndUnpackAnoncryptAsync(message, TestContext.CancellationToken).ConfigureAwait(false);

        AssertRotationRejected(result, DidCommDecryptionError.RotationSubjectMismatch);
    }


    /// <summary>A from_prior whose <c>kid</c> base DID does not equal <c>iss</c> is rejected.</summary>
    [TestMethod]
    public async Task KidBaseDidNotEqualIssRejected()
    {
        await using var rotation = await RotationFixture.CreateAsync(Pool, TestContext.CancellationToken).ConfigureAwait(false);

        DidCommMessage message = NewMessage(rotation.NewDid);

        //iss is a stranger DID while the kid's base DID is the prior DID; kid.BaseDid != iss.
        message.FromPrior = await rotation.MintRawFromPriorAsync(
            typ: "JWT", kid: rotation.PriorKid, iss: "did:example:stranger", sub: rotation.NewDid, TestContext.CancellationToken).ConfigureAwait(false);

        DidCommEncryptedUnpackResult result = await rotation.PackAndUnpackAnoncryptAsync(message, TestContext.CancellationToken).ConfigureAwait(false);

        AssertRotationRejected(result, DidCommDecryptionError.RotationIssuerKidMismatch);
    }


    /// <summary>
    /// A rotate-to-nothing JWT (no <c>sub</c>) carried by a message that DOES have a <c>from</c> is rejected
    /// — the presence rule is violated (DIDComm v2.1 §Ending a Relationship: omit sub AND send without from).
    /// </summary>
    [TestMethod]
    public async Task RotateToNothingWithFromRejected()
    {
        await using var rotation = await RotationFixture.CreateAsync(Pool, TestContext.CancellationToken).ConfigureAwait(false);

        //The message carries a from (the new DID), but the JWT omits sub — a presence mismatch.
        DidCommMessage message = NewMessage(rotation.NewDid);
        message.FromPrior = await rotation.MintRawFromPriorAsync(
            typ: "JWT", kid: rotation.PriorKid, iss: rotation.PriorDid, sub: null, TestContext.CancellationToken).ConfigureAwait(false);

        DidCommEncryptedUnpackResult result = await rotation.PackAndUnpackAnoncryptAsync(message, TestContext.CancellationToken).ConfigureAwait(false);

        AssertRotationRejected(result, DidCommDecryptionError.RotationSubjectMismatch);
    }


    /// <summary>
    /// The producer refuses to mint a from_prior whose <c>kid</c> carries no fragment — a structural guard
    /// mirroring the consumer MUST (here the kid is the bare prior DID, which is also iss == sub-illegal).
    /// </summary>
    [TestMethod]
    public async Task PackRejectsKidWithoutFragment()
    {
        await using var rotation = await RotationFixture.CreateAsync(Pool, TestContext.CancellationToken).ConfigureAwait(false);

        DidCommMessage message = NewMessage(rotation.NewDid);

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await message.PackFromPriorAsync(
                rotation.PriorDid,
                rotation.PriorDid,
                rotation.PriorSigningKey,
                DateTimeOffset.FromUnixTimeSeconds(1516239022),
                JwtClaimsJson.HeaderSerializer,
                JwtClaimsJson.PayloadSerializer,
                TestSetup.Base64UrlEncoder,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }


    /// <summary>
    /// The verify path takes the verification algorithm from the resolved prior-DID key, never the JWT
    /// <c>alg</c> header: a from_prior carrying a LYING <c>alg</c> (<c>ES256</c>) but a real Ed25519 signature
    /// still verifies — proving the header <c>alg</c> is not consulted (the algorithm-substitution defense,
    /// the most load-bearing invariant of the verify path).
    /// </summary>
    [TestMethod]
    public async Task HeaderAlgIsIgnoredOnVerify()
    {
        await using var rotation = await RotationFixture.CreateAsync(Pool, TestContext.CancellationToken).ConfigureAwait(false);

        DidCommMessage message = NewMessage(rotation.NewDid);

        //The header alg lies ("ES256"), but MintRawFromPriorAsync signs with the prior DID's real Ed25519
        //key. Verify resolves Ed25519 from the prior-DID verification method and MUST ignore the header alg.
        message.FromPrior = await rotation.MintRawFromPriorAsync(
            typ: "JWT", kid: rotation.PriorKid, iss: rotation.PriorDid, sub: rotation.NewDid, TestContext.CancellationToken, alg: "ES256").ConfigureAwait(false);

        DidCommEncryptedUnpackResult result = await rotation.PackAndUnpackAnoncryptAsync(message, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsUnpacked, $"A real Ed25519 signature MUST verify regardless of a lying header alg. Error: {result.Error}.");
        Assert.IsTrue(result.IsRotation, "The rotation MUST be recognized; the header alg is not consulted.");
        Assert.AreEqual(rotation.PriorDid, result.PriorDid);
        Assert.AreEqual(rotation.NewDid, result.Message!.From);
    }


    /// <summary>
    /// A from_prior whose <c>iss</c> equals its <c>sub</c> is rejected — a rotation MUST move to a DIFFERENT
    /// DID (DIDComm v2.1 §DID Rotation). The message <c>from</c> equals that DID too so the <c>sub</c>==
    /// <c>from</c> check would pass; only the <c>iss</c>!=<c>sub</c> guard can reject it.
    /// </summary>
    [TestMethod]
    public async Task IssEqualToSubRejected()
    {
        await using var rotation = await RotationFixture.CreateAsync(Pool, TestContext.CancellationToken).ConfigureAwait(false);

        //iss == sub == the prior DID, and from is the prior DID, so the kid/iss and sub/from checks pass and
        //only the iss != sub guard can fire.
        DidCommMessage message = NewMessage(rotation.PriorDid);
        message.FromPrior = await rotation.MintRawFromPriorAsync(
            typ: "JWT", kid: rotation.PriorKid, iss: rotation.PriorDid, sub: rotation.PriorDid, TestContext.CancellationToken).ConfigureAwait(false);

        DidCommEncryptedUnpackResult result = await rotation.PackAndUnpackAnoncryptAsync(message, TestContext.CancellationToken).ConfigureAwait(false);

        AssertRotationRejected(result, DidCommDecryptionError.RotationIssuerKidMismatch);
    }


    /// <summary>
    /// A from_prior <c>kid</c> that resolves to a verification method present in the prior DID document under
    /// assertionMethod but NOT authentication is rejected: §DID Rotation requires the signing key be authorized
    /// for the prior DID's AUTHENTICATION relationship specifically. The signature is genuinely the prior key's
    /// (it would verify cryptographically); only the relationship gate rejects it.
    /// </summary>
    [TestMethod]
    public async Task KidAuthorizedOnlyForAssertionMethodRejected()
    {
        await using var rotation = await RotationFixture.CreateAsync(Pool, TestContext.CancellationToken).ConfigureAwait(false);

        //A genuine, validly-signing from_prior from the prior DID's own key.
        DidCommMessage message = NewMessage(rotation.NewDid);
        await rotation.MintFromPriorAsync(message, TestContext.CancellationToken).ConfigureAwait(false);

        //Resolve the prior DID to a document that authorizes that same key only for assertionMethod.
        DidResolver assertionOnlyResolver = rotation.BuildAuthenticationStrippedPriorResolver();
        DidCommEncryptedUnpackResult result = await rotation.PackAndUnpackAnoncryptAsync(
            message, TestContext.CancellationToken, resolverOverride: assertionOnlyResolver).ConfigureAwait(false);

        AssertRotationRejected(result, DidCommDecryptionError.RotationSignerNotAuthorized);
    }


    private static void AssertRotationRejected(DidCommEncryptedUnpackResult result, DidCommDecryptionError expected)
    {
        Assert.IsFalse(result.IsUnpacked, $"The rotation MUST be rejected. Unexpected success, error: {result.Error}.");
        Assert.AreEqual(expected, result.Error);
        Assert.IsNull(result.Message, "Fail-closed: a rejected rotation yields no plaintext.");
        Assert.IsFalse(result.IsRotation, "A rejected rotation MUST NOT be surfaced as a rotation.");
        Assert.IsNull(result.PriorDid, "A rejected rotation MUST NOT surface a prior DID.");
    }


    //Flips the leading character of the compact JWT signature segment to a different valid base64url char,
    //leaving a structurally valid (64-byte) but cryptographically wrong Ed25519 signature.
    private static string TamperSignature(string compactJwt)
    {
        int signatureStart = compactJwt.LastIndexOf('.') + 1;
        char first = compactJwt[signatureStart];
        char replacement = first == 'A' ? 'B' : 'A';

        return compactJwt[..signatureStart] + replacement + compactJwt[(signatureStart + 1)..];
    }


    //A fresh DIDComm message with the shared id/type/body and the given `from` (null for rotate-to-nothing).
    private static DidCommMessage NewMessage(string? from)
    {
        return new DidCommMessage
        {
            Id = MessageId,
            Type = MessageType,
            From = from,
            Body = new Dictionary<string, object> { ["messagespecificattribute"] = "and its value" }
        };
    }
}
