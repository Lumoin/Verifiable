using System.Diagnostics.CodeAnalysis;
using Verifiable.Cbor.Ctap;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Byte-exactness tests for <see cref="CtapGetAssertionRequestCborWriter"/>, the client-side
/// <c>authenticatorGetAssertion</c> request encoder.
/// </summary>
[TestClass]
internal sealed class CtapGetAssertionRequestCborWriterTests
{
    /// <summary>A fixed 32-byte clientDataHash pattern, distinguishable byte-by-byte in a failure diff.</summary>
    private static byte[] ClientDataHashBytes
    {
        get
        {
            byte[] bytes = new byte[32];
            for(int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = (byte)i;
            }

            return bytes;
        }
    }

    /// <summary>A fixed 2-byte credential identifier pattern, used for allowList entries.</summary>
    private static byte[] ShortCredentialIdBytes => [0xAA, 0xBB];


    /// <summary>
    /// A request carrying only the two Required members (<c>rpId</c>, <c>clientDataHash</c>) encodes
    /// to a 2-entry map in ascending key order.
    /// </summary>
    [TestMethod]
    public void WriteEncodesRequiredMembersOnlyToExactCanonicalBytes()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);

        var request = new CtapGetAssertionRequest("rp.co", clientDataHash);

        TaggedMemory<byte> result = CtapGetAssertionRequestCborWriter.Write(request);

        //map(2): rpId(1)="rp.co", clientDataHash(2)=bytes(32).
        byte[] expected = Convert.FromHexString(
            "A20165" + "72702E636F" +
            "025820" + "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// <c>allowList</c> (key <c>0x03</c>) and <c>options</c> (key <c>0x05</c>) write after the two
    /// Required members, in ascending key order, when present.
    /// </summary>
    [TestMethod]
    public void WriteOrdersAllowListAndOptionsAfterRequiredMembers()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);
        using CredentialId allowCredentialId = CredentialId.Create(ShortCredentialIdBytes, BaseMemoryPool.Shared);

        var request = new CtapGetAssertionRequest(
            "rp.co",
            clientDataHash,
            AllowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = allowCredentialId }],
            Options: new CtapCommandOptions(UserPresence: false));

        TaggedMemory<byte> result = CtapGetAssertionRequestCborWriter.Write(request);

        byte[] expected = Convert.FromHexString(
            "A40165" + "72702E636F" +
            "025820" + "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" +
            "0381A262696442AABB64747970656A7075626C69632D6B6579" + //key 3 (allowList): array(1) of descriptor {id:bytes(2), type:"public-key"}
            "05A1627570F4"); //key 5 (options): map(1) {up: false}

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// Every remaining optional member (<c>extensions</c>, <c>pinUvAuthParam</c>,
    /// <c>pinUvAuthProtocol</c>) writes at its own ascending key position, and <see cref="CtapCommandOptions.ResidentKey"/>
    /// is encoded verbatim even though a conformant platform never sends it here — the writer's own
    /// documented rationale is that a capstone-level negative test needs exactly this to construct the
    /// wire vector proving the authenticator rejects it.
    /// </summary>
    [TestMethod]
    public void WriteEncodesEveryOptionalMemberInAscendingKeyOrder()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);
        using CredentialId allowCredentialId = CredentialId.Create(ShortCredentialIdBytes, BaseMemoryPool.Shared);

        var request = new CtapGetAssertionRequest(
            "rp.co",
            clientDataHash,
            AllowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = allowCredentialId }],
            Extensions: new byte[] { NoneAttestation.CanonicalEmptyMap }, //the canonical empty map, an opaque but well-formed CBOR item
            Options: new CtapCommandOptions(ResidentKey: true, UserPresence: true, UserVerification: false),
            PinUvAuthParam: new byte[] { 0xDE, 0xAD, 0xBE, 0xEF },
            PinUvAuthProtocol: 1);

        TaggedMemory<byte> result = CtapGetAssertionRequestCborWriter.Write(request);

        byte[] expected = Convert.FromHexString(
            "A70165" + "72702E636F" +
            "025820" + "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" +
            "0381A262696442AABB64747970656A7075626C69632D6B6579" +
            "04A0" + //key 4 (extensions): the spliced-in canonical empty map, verbatim
            "05A362726BF5627570F5627576F4" + //key 5 (options): map(3) {rk: true, up: true, uv: false}
            "0644DEADBEEF" + //key 6 (pinUvAuthParam): bytes(4)
            "0701"); //key 7 (pinUvAuthProtocol): 1

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>A <see langword="null"/> request is rejected before any encoding is attempted.</summary>
    [TestMethod]
    public void ThrowsArgumentNullExceptionForNullRequest()
    {
        _ = Assert.ThrowsExactly<ArgumentNullException>(() => CtapGetAssertionRequestCborWriter.Write(null!));
    }


    /// <summary>
    /// A request carrying <c>LargeBlobKey</c> and no raw <c>Extensions</c> bytes writes an
    /// <c>extensions</c> map built from that decoded member, which the shipped reader decodes back to
    /// the same value.
    /// </summary>
    [TestMethod]
    public void WriteEncodesLargeBlobKeyFromTheDecodedMemberWhenExtensionsAreAbsent()
    {
        CtapGetAssertionRequest request = BuildMinimalRequest(largeBlobKey: true);

        CtapGetAssertionRequest decoded = RoundTrip(request);
        try
        {
            Assert.IsTrue(decoded.LargeBlobKey);
        }
        finally
        {
            CtapMakeCredentialGetAssertionFixtures.DisposeGetAssertionRequest(request);
            CtapMakeCredentialGetAssertionFixtures.DisposeGetAssertionRequest(decoded);
        }
    }


    /// <summary>
    /// A request carrying <c>HmacSecret</c> and no raw <c>Extensions</c> bytes writes an
    /// <c>extensions</c> map built from that decoded compound member, which the shipped reader decodes
    /// back to the same keyAgreement/saltEnc/saltAuth/pinUvAuthProtocol values.
    /// </summary>
    [TestMethod]
    public void WriteEncodesHmacSecretFromTheDecodedMemberWhenExtensionsAreAbsent()
    {
        var keyAgreement = new CoseKey(
            kty: CoseKeyTypes.Ec2, alg: WellKnownCoseAlgorithms.Es256, curve: CoseKeyCurves.P256,
            x: new byte[32], y: new byte[32]);
        byte[] saltEnc = [0x11, 0x22, 0x33, 0x44];
        byte[] saltAuth = [0x55, 0x66];

        CtapGetAssertionRequest request = BuildMinimalRequest(
            hmacSecret: new CtapGetAssertionHmacSecretInput(keyAgreement, saltEnc, saltAuth, PinUvAuthProtocol: 2));

        CtapGetAssertionRequest decoded = RoundTrip(request);
        try
        {
            Assert.IsNotNull(decoded.HmacSecret);
            Assert.AreEqual(CoseKeyTypes.Ec2, decoded.HmacSecret.KeyAgreement.Kty);
            Assert.IsTrue(decoded.HmacSecret.SaltEnc.Span.SequenceEqual(saltEnc));
            Assert.IsTrue(decoded.HmacSecret.SaltAuth.Span.SequenceEqual(saltAuth));
            Assert.AreEqual(2, decoded.HmacSecret.PinUvAuthProtocol);
        }
        finally
        {
            CtapMakeCredentialGetAssertionFixtures.DisposeGetAssertionRequest(request);
            CtapMakeCredentialGetAssertionFixtures.DisposeGetAssertionRequest(decoded);
        }
    }


    /// <summary>
    /// With both <c>HmacSecret</c> and <c>LargeBlobKey</c> set and no raw <c>Extensions</c> bytes, the
    /// built <c>extensions</c> map orders <c>"hmac-secret"</c> (11 characters) before
    /// <c>"largeBlobKey"</c> (12 characters) — the CTAP2 canonical shorter-key-first rule.
    /// </summary>
    [TestMethod]
    public void WriteOrdersHmacSecretBeforeLargeBlobKey()
    {
        var keyAgreement = new CoseKey(
            kty: CoseKeyTypes.Ec2, alg: WellKnownCoseAlgorithms.Es256, curve: CoseKeyCurves.P256,
            x: new byte[32], y: new byte[32]);

        CtapGetAssertionRequest request = BuildMinimalRequest(
            hmacSecret: new CtapGetAssertionHmacSecretInput(keyAgreement, new byte[] { 0x91 }, new byte[] { 0x92 }, PinUvAuthProtocol: null),
            largeBlobKey: true);

        CtapGetAssertionRequest decoded = RoundTrip(request);
        try
        {
            ReadOnlySpan<byte> extensions = decoded.Extensions!.Value.Span;

            //The 0x6B/0x6C text-string headers are each key's own length byte (11/12 characters);
            //byte-exact key bytes computed the same way WriteOrdersMultipleDecodedExtensionMembersCanonically
            //verifies the mc-side sibling members.
            byte[] hmacSecretKeyBytes = Convert.FromHexString("6B" + "686D61632D736563726574");
            byte[] largeBlobKeyKeyBytes = Convert.FromHexString("6C" + "6C61726765426C6F624B6579");

            int hmacSecretIndex = extensions.IndexOf(hmacSecretKeyBytes);
            int largeBlobKeyIndex = extensions.IndexOf(largeBlobKeyKeyBytes);

            Assert.IsGreaterThanOrEqualTo(0, hmacSecretIndex, "The hmac-secret key must be present.");
            Assert.IsGreaterThanOrEqualTo(0, largeBlobKeyIndex, "The largeBlobKey key must be present.");
            Assert.IsLessThan(largeBlobKeyIndex, hmacSecretIndex, "hmac-secret must sort before largeBlobKey.");
        }
        finally
        {
            CtapMakeCredentialGetAssertionFixtures.DisposeGetAssertionRequest(request);
            CtapMakeCredentialGetAssertionFixtures.DisposeGetAssertionRequest(decoded);
        }
    }


    /// <summary>
    /// When raw <c>Extensions</c> bytes AND a decoded member (<c>LargeBlobKey</c>) are both set, the
    /// raw bytes are written verbatim — the decoded member is never consulted to build a map of its own.
    /// </summary>
    [TestMethod]
    public void WriteWritesRawExtensionsVerbatimWhenBothRawBytesAndMembersArePresent()
    {
        byte[] rawExtensions = [0xA0]; //the canonical empty map

        CtapGetAssertionRequest request = BuildMinimalRequest(extensions: rawExtensions, largeBlobKey: true);

        CtapGetAssertionRequest decoded = RoundTrip(request);
        try
        {
            Assert.IsTrue(decoded.Extensions!.Value.Span.SequenceEqual(rawExtensions));
            Assert.IsNull(decoded.LargeBlobKey);
        }
        finally
        {
            CtapMakeCredentialGetAssertionFixtures.DisposeGetAssertionRequest(request);
            CtapMakeCredentialGetAssertionFixtures.DisposeGetAssertionRequest(decoded);
        }
    }


    /// <summary>
    /// Builds a request carrying only the two Required members plus whatever optional values are given.
    /// The returned request's own <c>ClientDataHash</c> is NOT disposed here — ownership passes to the
    /// caller, which disposes it (alongside the round-tripped decode result) through
    /// <see cref="CtapMakeCredentialGetAssertionFixtures.DisposeGetAssertionRequest"/>.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of clientDataHash transfers to the returned request, which the caller disposes.")]
    private static CtapGetAssertionRequest BuildMinimalRequest(
        ReadOnlyMemory<byte>? extensions = null, bool? largeBlobKey = null, CtapGetAssertionHmacSecretInput? hmacSecret = null)
    {
        DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);

        return new CtapGetAssertionRequest(
            "rp.co", clientDataHash, Extensions: extensions, LargeBlobKey: largeBlobKey, HmacSecret: hmacSecret);
    }

    /// <summary>Writes <paramref name="request"/> and decodes the result back through the shipped reader.</summary>
    private static CtapGetAssertionRequest RoundTrip(CtapGetAssertionRequest request)
    {
        TaggedMemory<byte> encoded = CtapGetAssertionRequestCborWriter.Write(request);

        return CtapGetAssertionRequestCborReader.Read(encoded.Memory, BaseMemoryPool.Shared);
    }
}
