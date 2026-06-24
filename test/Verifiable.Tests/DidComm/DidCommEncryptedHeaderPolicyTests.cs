using System.Buffers;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Peer;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.DidComm;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Tests for <see cref="DidCommEncryptedHeaderPolicy"/> — the spec-compliant enforcement of the MUST-present
/// common protected headers <c>apv</c> (both modes) and <c>apu</c> (authcrypt) on the DIDComm encrypted
/// unpack. The strict default rejects an envelope missing one of these headers early
/// (<see cref="DidCommDecryptionError.MalformedEnvelope"/>); the lenient interop policy defers to the
/// cryptographic layer, which still fails closed because the Concat KDF binds <c>apu</c>/<c>apv</c>.
/// </summary>
/// <remarks>
/// The envelopes are produced by the library (which always stamps <c>apv</c>/<c>apu</c>) and then a MUST
/// header is surgically stripped from the wire's protected header, modelling a non-conformant peer. The
/// existing round-trip suite already proves the strict default accepts conformant envelopes (every test now
/// runs under the strict default); these tests isolate the missing-header behavior the policy governs.
/// </remarks>
[TestClass]
internal sealed class DidCommEncryptedHeaderPolicyTests
{
    /// <summary>Provides the per-test cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;

    //A non-network resolution context; it only satisfies the SSRF-policy-carrying parameter.
    private static readonly ExchangeContext Context = new();

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);


    [TestMethod]
    public async Task StrictByDefaultRejectsMissingApvOnAnoncrypt()
    {
        DidResolver resolver = CreateResolver();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> alice = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory alicePublic = alice.PublicKey;
        using PrivateKeyMemory alicePrivate = alice.PrivateKey;
        string aliceDid = MintPeerDid(alicePublic);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> bob = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory bobPublic = bob.PublicKey;
        using PrivateKeyMemory bobPrivate = bob.PrivateKey;
        string bobDid = MintPeerDid(bobPublic);

        DidDocument bobDocument = await ResolveDocumentAsync(resolver, bobDid).ConfigureAwait(false);
        (string bobKid, VerificationMethod bobMethod) = SingleKeyAgreement(bobDocument, bobDid);
        using PublicKeyMemory bobResolvedKey = bobMethod.ToPublicKeyMemory(Pool);

        using DidCommEncryptedMessage encrypted = await PackAnoncryptAsync(aliceDid, bobDid, bobKid, bobResolvedKey);

        //A non-conformant peer that omits the MUST-present apv: the strict default rejects it BEFORE
        //decryption (DIDComm v2.1 §ECDH-ES key wrapping and common protected headers).
        using DidCommEncryptedMessage stripped = StripProtectedMember(encrypted, "apv");
        DidCommEncryptedUnpackResult result = await UnpackAnoncryptAsync(stripped, bobKid, bobPrivate, resolver);

        Assert.IsFalse(result.IsUnpacked, "A missing apv MUST be rejected under the strict default.");
        Assert.AreEqual(DidCommDecryptionError.MalformedEnvelope, result.Error, "Strict rejects the missing MUST header early, not as a decryption failure.");
    }


    [TestMethod]
    public async Task LenientPolicyDefersMissingApvToTheCryptographicLayer()
    {
        DidResolver resolver = CreateResolver();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> alice = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory alicePublic = alice.PublicKey;
        using PrivateKeyMemory alicePrivate = alice.PrivateKey;
        string aliceDid = MintPeerDid(alicePublic);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> bob = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory bobPublic = bob.PublicKey;
        using PrivateKeyMemory bobPrivate = bob.PrivateKey;
        string bobDid = MintPeerDid(bobPublic);

        DidDocument bobDocument = await ResolveDocumentAsync(resolver, bobDid).ConfigureAwait(false);
        (string bobKid, VerificationMethod bobMethod) = SingleKeyAgreement(bobDocument, bobDid);
        using PublicKeyMemory bobResolvedKey = bobMethod.ToPublicKeyMemory(Pool);

        using DidCommEncryptedMessage encrypted = await PackAnoncryptAsync(aliceDid, bobDid, bobKid, bobResolvedKey);

        //The lenient policy does not early-reject a missing apv — but the Concat KDF binds apv as PartyVInfo
        //and the protected header is the AEAD's additional data, so the stripped envelope still fails closed
        //at decryption rather than ever yielding plaintext.
        using DidCommEncryptedMessage stripped = StripProtectedMember(encrypted, "apv");
        DidCommEncryptedUnpackResult result = await UnpackAnoncryptAsync(stripped, bobKid, bobPrivate, resolver, DidCommEncryptedHeaderPolicy.AllowMissingCommonHeaders);

        Assert.IsFalse(result.IsUnpacked, "Lenient never yields plaintext for a tampered envelope.");
        Assert.AreEqual(DidCommDecryptionError.DecryptionFailed, result.Error, "Lenient defers the failure to the KDF/AEAD, which fails closed.");
    }


    [TestMethod]
    public async Task StrictByDefaultRejectsMissingApuOnAuthcrypt()
    {
        DidResolver resolver = CreateResolver();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> alice = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory alicePublic = alice.PublicKey;
        using PrivateKeyMemory alicePrivate = alice.PrivateKey;
        string aliceDid = MintPeerDid(alicePublic);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> bob = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory bobPublic = bob.PublicKey;
        using PrivateKeyMemory bobPrivate = bob.PrivateKey;
        string bobDid = MintPeerDid(bobPublic);

        DidDocument aliceDocument = await ResolveDocumentAsync(resolver, aliceDid).ConfigureAwait(false);
        (string aliceSkid, _) = SingleKeyAgreement(aliceDocument, aliceDid);

        DidDocument bobDocument = await ResolveDocumentAsync(resolver, bobDid).ConfigureAwait(false);
        (string bobKid, VerificationMethod bobMethod) = SingleKeyAgreement(bobDocument, bobDid);
        using PublicKeyMemory bobResolvedKey = bobMethod.ToPublicKeyMemory(Pool);

        using DidCommEncryptedMessage encrypted = await PackAuthcryptAsync(aliceDid, bobDid, aliceSkid, alicePrivate, bobKid, bobResolvedKey);

        //apu carries base64url(skid) and is MUST-present for authcrypt (DIDComm v2.1 §ECDH-1PU key wrapping);
        //the strict default rejects its absence even though skid is still present.
        using DidCommEncryptedMessage stripped = StripProtectedMember(encrypted, "apu");
        DidCommEncryptedUnpackResult result = await UnpackAuthcryptAsync(stripped, bobKid, bobPrivate, resolver);

        Assert.IsFalse(result.IsUnpacked, "A missing apu MUST be rejected under the strict default.");
        Assert.AreEqual(DidCommDecryptionError.MalformedEnvelope, result.Error);
    }


    //Re-encodes the wire envelope with the named member removed from its base64url protected header,
    //modelling a non-conformant peer that omits a MUST-present common header.
    private static DidCommEncryptedMessage StripProtectedMember(DidCommEncryptedMessage message, string memberName)
    {
        string wireJson = Encoding.UTF8.GetString(message.AsReadOnlySpan());
        JsonObject wire = JsonNode.Parse(wireJson)!.AsObject();

        string protectedEncoded = wire["protected"]!.GetValue<string>();
        byte[] headerBytes = Base64Url.DecodeFromChars(protectedEncoded);
        JsonObject header = JsonNode.Parse(headerBytes)!.AsObject();
        header.Remove(memberName);

        byte[] newHeaderBytes = Encoding.UTF8.GetBytes(header.ToJsonString());
        wire["protected"] = Base64Url.EncodeToString(newHeaderBytes);

        byte[] newWireBytes = Encoding.UTF8.GetBytes(wire.ToJsonString());

        return DidCommEncryptedMessage.Create(newWireBytes, BufferTags.Json, Pool);
    }


    //Anoncrypts a fresh message from `from` to `to` for the resolved recipient key with a fresh ephemeral key.
    private async ValueTask<DidCommEncryptedMessage> PackAnoncryptAsync(string from, string to, string recipientKid, PublicKeyMemory recipientKey)
    {
        DidCommMessage message = new() { Id = "policy-msg", Type = "https://example.com/p/1.0/m", From = from, To = [to], Body = new Dictionary<string, object>() };

        var recipients = new List<GeneralJweRecipientInput> { new(recipientKid, recipientKey) };

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        return await message.PackAnoncryptAsync(
            recipients,
            WellKnownJweAlgorithms.EcdhEsA256Kw,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            DidCommMessageJson.Serializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    //Authcrypts a fresh message from `from` to `to`, signed-into the agreement by the sender skid/private key.
    private async ValueTask<DidCommEncryptedMessage> PackAuthcryptAsync(
        string from, string to, string senderSkid, PrivateKeyMemory senderPrivate, string recipientKid, PublicKeyMemory recipientKey)
    {
        DidCommMessage message = new() { Id = "policy-msg", Type = "https://example.com/p/1.0/m", From = from, To = [to], Body = new Dictionary<string, object>() };

        var recipients = new List<GeneralJweRecipientInput> { new(recipientKid, recipientKey) };

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        return await message.PackAuthcryptAsync(
            recipients,
            senderSkid,
            senderPrivate,
            WellKnownJweAlgorithms.Ecdh1PuA256Kw,
            WellKnownJweEncryptionAlgorithms.A256CbcHs512,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            DidCommMessageJson.Serializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private async ValueTask<DidCommEncryptedUnpackResult> UnpackAnoncryptAsync(
        DidCommEncryptedMessage envelope, string recipientKid, PrivateKeyMemory recipientPrivate, DidResolver resolver,
        DidCommEncryptedHeaderPolicy headerPolicy = DidCommEncryptedHeaderPolicy.Strict)
    {
        return await envelope.UnpackAnoncryptAsync(
            recipientKid,
            recipientPrivate,
            resolver,
            Context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken,
            headerPolicy: headerPolicy).ConfigureAwait(false);
    }


    private async ValueTask<DidCommEncryptedUnpackResult> UnpackAuthcryptAsync(
        DidCommEncryptedMessage envelope, string recipientKid, PrivateKeyMemory recipientPrivate, DidResolver resolver,
        DidCommEncryptedHeaderPolicy headerPolicy = DidCommEncryptedHeaderPolicy.Strict)
    {
        return await envelope.UnpackAuthcryptAsync(
            recipientKid,
            recipientPrivate,
            resolver,
            Context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken,
            headerPolicy: headerPolicy).ConfigureAwait(false);
    }


    private static string MintPeerDid(PublicKeyMemory keyAgreementPublicKey)
    {
        var keys = new List<PeerDidPurposedKey> { new(keyAgreementPublicKey, PeerDidPurpose.KeyAgreement) };

        return PeerDidGenerator.GenerateNumalgo2(keys, [], Pool);
    }


    private async ValueTask<DidDocument> ResolveDocumentAsync(DidResolver resolver, string did)
    {
        DidResolutionResult resolution = await resolver
            .ResolveAsync(did, Context, cancellationToken: TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.IsTrue(resolution.IsSuccessful, $"'{did}' MUST resolve.");
        Assert.IsNotNull(resolution.Document);

        return resolution.Document!;
    }


    private static (string Kid, VerificationMethod Method) SingleKeyAgreement(DidDocument document, string did)
    {
        VerificationMethod[] methods = document.GetLocalKeyAgreementMethods();
        Assert.HasCount(1, methods);

        VerificationMethod method = methods[0];
        Assert.IsNotNull(method.Id);

        string kid = method.Id!.StartsWith('#') ? did + method.Id : method.Id;

        return (kid, method);
    }


    private static DidResolver CreateResolver() =>
        new(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.PeerDidMethodPrefix, PeerDidResolver.Build(Pool, DeserializeDidDocument, SHA256.HashData))));


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
