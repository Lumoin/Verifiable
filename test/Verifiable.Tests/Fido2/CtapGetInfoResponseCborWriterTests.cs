using System;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Byte-exactness tests for <see cref="CtapGetInfoResponseCborWriter"/> — this repository's first
/// CTAP2-canonical CBOR writer, so every assertion pins the exact expected wire bytes rather than
/// merely round-tripping through the paired reader.
/// </summary>
[TestClass]
internal sealed class CtapGetInfoResponseCborWriterTests
{
    /// <summary>A fixed 16-byte AAGUID pattern, distinguishable byte-by-byte in a failure diff.</summary>
    private static byte[] FixedAaguidBytes => [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];

    /// <summary>ASCII bytes of "FIDO_2_3", the version string a CTAP2.3 authenticator MUST report.</summary>
    private static byte[] Fido23Ascii => [0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x33];

    /// <summary>The single-entry <c>algorithms</c> advertisement <see cref="CtapCredentialSigningBackend.CreateEs256Default"/> produces.</summary>
    private static PublicKeyCredentialParameters[] Es256Algorithms =>
        [new PublicKeyCredentialParameters { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Alg = WellKnownCoseAlgorithms.Es256 }];

    /// <summary>
    /// The CBOR bytes of a one-element <c>algorithms</c> array advertising ES256/"public-key":
    /// <c>81</c> array(1), <c>A2</c> map(2), <c>63 "alg"</c>, <c>26</c> (-7, ES256), <c>64 "type"</c>,
    /// <c>6A "public-key"</c> — hand-verified against
    /// <see cref="Verifiable.Cbor.Ctap.CtapCommandEntityCborCodec.WriteParameters"/>'s own fixed
    /// <c>alg</c>-then-<c>type</c> member order.
    /// </summary>
    private static byte[] Es256AlgorithmsBytes =>
        [0x81, 0xA2, 0x63, 0x61, 0x6C, 0x67, 0x26, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6A, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0x2D, 0x6B, 0x65, 0x79];


    /// <summary>
    /// A response with only the two Required members encodes to a 2-entry map: <c>versions</c>
    /// (a 1-element array) then <c>aaguid</c> (a 16-byte string), in that ascending key order.
    /// </summary>
    [TestMethod]
    public void WriteEncodesRequiredMembersOnlyToExactCanonicalBytes()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(Versions: [WellKnownCtapVersions.Fido23], Aaguid: aaguid);

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] expected =
        [
            0xA2, //map(2)
            0x01, 0x81, 0x68, .. Fido23Ascii, //key 1 (versions): array(1) of text(8) "FIDO_2_3"
            0x03, 0x50, .. FixedAaguidBytes //key 3 (aaguid): bytes(16)
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// The <c>options</c> member's keys sort shorter-first: <c>"rk"</c> (2 characters) precedes
    /// <c>"plat"</c> (4 characters) when both are present, per the CTAP2 canonical CBOR key-sort rule.
    /// </summary>
    [TestMethod]
    public void WriteOrdersOptionsKeysRkBeforePlat()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            Options: new CtapGetInfoOptions(ResidentKey: true, Platform: false));

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] expected =
        [
            0xA3, //map(3): versions, aaguid, options
            0x01, 0x81, 0x68, .. Fido23Ascii,
            0x03, 0x50, .. FixedAaguidBytes,
            0x04, 0xA2, //key 4 (options): map(2)
                0x62, 0x72, 0x6B, 0xF5, //"rk" -> true
                0x64, 0x70, 0x6C, 0x61, 0x74, 0xF4 //"plat" -> false
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// <c>"ep"</c> (CTAP 2.3 §7.1.1, R10) sorts FIRST of the whole <c>options</c> map — ahead of even
    /// the other length-2 keys <c>"rk"</c>/<c>"uv"</c> — because the length-2 bytewise tie-break is
    /// <c>'e'</c> (0x65) &lt; <c>'r'</c> (0x72) &lt; <c>'u'</c> (0x75); mirrors
    /// <see cref="WriteOrdersOptionsKeysRkBeforePlat"/>'s shape one option earlier in the canonical
    /// sequence.
    /// </summary>
    [TestMethod]
    public void WriteOrdersEpFirstBeforeRk()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            Options: new CtapGetInfoOptions(Ep: true, ResidentKey: true));

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] expected =
        [
            0xA3,
            0x01, 0x81, 0x68, .. Fido23Ascii,
            0x03, 0x50, .. FixedAaguidBytes,
            0x04, 0xA2, //key 4 (options): map(2)
                0x62, 0x65, 0x70, 0xF5, //"ep" (text(2)) -> true, sorts before "rk"
                0x62, 0x72, 0x6B, 0xF5 //"rk" -> true
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// A capable-but-disabled authenticator emits <c>"ep"</c> present and <see langword="false"/>
    /// (CTAP 2.3 lines 4741-4743: "present and set to false" -&gt; "the authenticator is enterprise
    /// attestation capable, and enterprise attestation is disabled") — the byte-exact proof of R11(b)'s
    /// <c>62 65 70 F4</c> emission.
    /// </summary>
    [TestMethod]
    public void WriteEncodesEnterpriseAttestationCapableDisabledEpFalse()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            Options: new CtapGetInfoOptions(Ep: false, ResidentKey: true));

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] expected =
        [
            0xA3,
            0x01, 0x81, 0x68, .. Fido23Ascii,
            0x03, 0x50, .. FixedAaguidBytes,
            0x04, 0xA2, //key 4 (options): map(2)
                0x62, 0x65, 0x70, 0xF4, //"ep" -> false
                0x62, 0x72, 0x6B, 0xF5 //"rk" -> true
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// The <c>options</c> map's canonical order has a length-2 tie once <c>uv</c> is present alongside
    /// <c>rk</c> (both 2 characters): the tie breaks byte-wise lexically — <c>'r'</c> (0x72) precedes
    /// <c>'u'</c> (0x75) — placing <c>rk</c> before <c>uv</c>, both ahead of <c>plat</c> (4 characters).
    /// </summary>
    [TestMethod]
    public void WriteOrdersUvBetweenRkAndPlat()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            Options: new CtapGetInfoOptions(ResidentKey: true, Uv: false, Platform: true));

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] expected =
        [
            0xA3,
            0x01, 0x81, 0x68, .. Fido23Ascii,
            0x03, 0x50, .. FixedAaguidBytes,
            0x04, 0xA3, //key 4 (options): map(3)
                0x62, 0x72, 0x6B, 0xF5, //"rk" -> true
                0x62, 0x75, 0x76, 0xF4, //"uv" (text(2)) -> false, sorts after "rk"
                0x64, 0x70, 0x6C, 0x61, 0x74, 0xF5 //"plat" -> true
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// An <c>options</c> member with only <c>plat</c> present encodes a single-entry map — <c>rk</c>
    /// is not synthesized when the model leaves it <see langword="null"/>.
    /// </summary>
    [TestMethod]
    public void WriteOmitsAbsentOptionFromOptionsMap()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            Options: new CtapGetInfoOptions(Platform: true));

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] expected =
        [
            0xA3,
            0x01, 0x81, 0x68, .. Fido23Ascii,
            0x03, 0x50, .. FixedAaguidBytes,
            0x04, 0xA1, //key 4 (options): map(1)
                0x64, 0x70, 0x6C, 0x61, 0x74, 0xF5 //"plat" -> true
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// The <c>extensions</c> member (key <c>0x02</c>) writes between <c>versions</c> and
    /// <c>aaguid</c>, preserving the outer map's ascending key order.
    /// </summary>
    [TestMethod]
    public void WriteOrdersExtensionsBetweenVersionsAndAaguid()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            Extensions: ["hmac-secret"]);

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] hmacSecretAscii = "hmac-secret"u8.ToArray();
        byte[] expected =
        [
            0xA3,
            0x01, 0x81, 0x68, .. Fido23Ascii,
            0x02, 0x81, 0x6B, .. hmacSecretAscii, //key 2 (extensions): array(1) of text(11)
            0x03, 0x50, .. FixedAaguidBytes
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// <see cref="CtapAuthenticatorState.DefaultSupportedExtensions"/> — the real, unconditionally
    /// advertised list a default-constructed authenticator reports (contract R1; waveclose adds
    /// <c>hmac-secret</c>/<c>hmac-secret-mc</c>) — encodes to <c>["credProtect", "hmac-secret",
    /// "hmac-secret-mc", "largeBlobKey", "minPinLength"]</c>, correctly cased, in that array-element
    /// order (a CBOR array carries no key-sort rule of its own; the LIST order here is this codebase's
    /// alphabetical convention — trap 1's first ordering).
    /// </summary>
    [TestMethod]
    public void WriteEncodesDefaultAdvertisedExtensionsToExactCanonicalBytes()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            Extensions: CtapAuthenticatorState.DefaultSupportedExtensions);

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] credProtectAscii = "credProtect"u8.ToArray();
        byte[] hmacSecretAscii = "hmac-secret"u8.ToArray();
        byte[] hmacSecretMcAscii = "hmac-secret-mc"u8.ToArray();
        byte[] largeBlobKeyAscii = "largeBlobKey"u8.ToArray();
        byte[] minPinLengthAscii = "minPinLength"u8.ToArray();
        byte[] expected =
        [
            0xA3,
            0x01, 0x81, 0x68, .. Fido23Ascii,
            0x02, 0x85, 0x6B, .. credProtectAscii, 0x6B, .. hmacSecretAscii, 0x6E, .. hmacSecretMcAscii, 0x6C, .. largeBlobKeyAscii, 0x6C, .. minPinLengthAscii, //key 2 (extensions): array(5) of text(11), text(11), text(14), text(12), text(12)
            0x03, 0x50, .. FixedAaguidBytes
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// This subset of the <c>options</c> map — <c>"rk"</c> (2), <c>"plat"</c> (4), <c>"clientPin"</c>
    /// (9), <c>"pinUvAuthToken"</c> (14), <c>"makeCredUvNotRqd"</c> (16) — happens to have five
    /// distinct lengths, so length alone fixes their relative order (CTAP wave-a's getInfo flips,
    /// decision 5; <c>makeCredUvNotRqd</c> added at the tail per wave-5c decision 8). The FULL modeled
    /// option set is no longer all-distinct-length once <c>authnrCfg</c> (9) is also present — see
    /// <see cref="WriteOrdersAuthnrCfgBeforeClientPinOnLengthNineTie"/> for the length-9 tie-break.
    /// </summary>
    [TestMethod]
    public void WriteOrdersClientPinAndPinUvAuthTokenAfterRkAndPlat()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            Options: new CtapGetInfoOptions(ResidentKey: true, Platform: false, ClientPin: false, PinUvAuthToken: true, MakeCredUvNotRqd: true));

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] clientPinAscii = "clientPin"u8.ToArray();
        byte[] pinUvAuthTokenAscii = "pinUvAuthToken"u8.ToArray();
        byte[] makeCredUvNotRqdAscii = "makeCredUvNotRqd"u8.ToArray();
        byte[] expected =
        [
            0xA3,
            0x01, 0x81, 0x68, .. Fido23Ascii,
            0x03, 0x50, .. FixedAaguidBytes,
            0x04, 0xA5, //key 4 (options): map(5)
                0x62, 0x72, 0x6B, 0xF5, //"rk" -> true
                0x64, 0x70, 0x6C, 0x61, 0x74, 0xF4, //"plat" -> false
                0x69, .. clientPinAscii, 0xF4, //"clientPin" (text(9)) -> false
                0x6E, .. pinUvAuthTokenAscii, 0xF5, //"pinUvAuthToken" (text(14)) -> true
                0x70, .. makeCredUvNotRqdAscii, 0xF5 //"makeCredUvNotRqd" (text(16)) -> true
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// <c>clientPin: true</c> (CTAP 2.3 §9 item 2, wave-5b decision 8: state-dependent once a PIN has
    /// been set) writes the identical byte-exact shape as the <see langword="false"/> variant, with
    /// only the boolean's simple-value byte differing — proving the flip is a value change, not a
    /// structural one.
    /// </summary>
    [TestMethod]
    public void WriteEncodesClientPinTrueVariantToExactCanonicalBytes()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            Options: new CtapGetInfoOptions(ResidentKey: true, Platform: false, ClientPin: true, PinUvAuthToken: true, MakeCredUvNotRqd: true));

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] clientPinAscii = "clientPin"u8.ToArray();
        byte[] pinUvAuthTokenAscii = "pinUvAuthToken"u8.ToArray();
        byte[] makeCredUvNotRqdAscii = "makeCredUvNotRqd"u8.ToArray();
        byte[] expected =
        [
            0xA3,
            0x01, 0x81, 0x68, .. Fido23Ascii,
            0x03, 0x50, .. FixedAaguidBytes,
            0x04, 0xA5, //key 4 (options): map(5)
                0x62, 0x72, 0x6B, 0xF5, //"rk" -> true
                0x64, 0x70, 0x6C, 0x61, 0x74, 0xF4, //"plat" -> false
                0x69, .. clientPinAscii, 0xF5, //"clientPin" (text(9)) -> true
                0x6E, .. pinUvAuthTokenAscii, 0xF5, //"pinUvAuthToken" (text(14)) -> true
                0x70, .. makeCredUvNotRqdAscii, 0xF5 //"makeCredUvNotRqd" (text(16)) -> true
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// The <c>pinUvAuthProtocols</c> member (key <c>0x06</c>) writes after <c>options</c> (key
    /// <c>0x04</c>), preserving the outer map's ascending key order; <c>[2, 1]</c> preserves the
    /// caller's element order rather than sorting the array's values (CTAP 2.3 §9 item 6: protocol 2
    /// listed first as this authenticator's preference).
    /// </summary>
    [TestMethod]
    public void WriteOrdersPinUvAuthProtocolsAfterOptionsAndPreservesElementOrder()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            PinUvAuthProtocols: [2, 1]);

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] expected =
        [
            0xA3,
            0x01, 0x81, 0x68, .. Fido23Ascii,
            0x03, 0x50, .. FixedAaguidBytes,
            0x06, 0x82, 0x02, 0x01 //key 6 (pinUvAuthProtocols): array(2) [2, 1]
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// The <c>options</c> map's canonical order has a length-8 tie once <c>credMgmt</c> is present
    /// alongside <c>alwaysUv</c> (both 8 characters): the tie breaks byte-wise lexically —
    /// <c>'a'</c> (0x61) precedes <c>'c'</c> (0x63) — placing <c>alwaysUv</c> first.
    /// </summary>
    [TestMethod]
    public void WriteOrdersAlwaysUvBeforeCredMgmtOnLengthEightTie()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            Options: new CtapGetInfoOptions(AlwaysUv: false, CredMgmt: true));

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] alwaysUvAscii = "alwaysUv"u8.ToArray();
        byte[] credMgmtAscii = "credMgmt"u8.ToArray();
        byte[] expected =
        [
            0xA3,
            0x01, 0x81, 0x68, .. Fido23Ascii,
            0x03, 0x50, .. FixedAaguidBytes,
            0x04, 0xA2, //key 4 (options): map(2)
                0x68, .. alwaysUvAscii, 0xF4, //"alwaysUv" (text(8)) -> false, sorts before "credMgmt"
                0x68, .. credMgmtAscii, 0xF5 //"credMgmt" (text(8)) -> true
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// The <c>options</c> map's canonical order breaks its coincidental all-distinct-length property
    /// once <c>authnrCfg</c> (9) is present alongside <c>clientPin</c> (9): the two share a length, so
    /// the tie breaks byte-wise lexically — <c>'a'</c> (0x61) precedes <c>'c'</c> (0x63) — placing
    /// <c>authnrCfg</c> first.
    /// </summary>
    [TestMethod]
    public void WriteOrdersAuthnrCfgBeforeClientPinOnLengthNineTie()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            Options: new CtapGetInfoOptions(AuthnrCfg: true, ClientPin: false));

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] authnrCfgAscii = "authnrCfg"u8.ToArray();
        byte[] clientPinAscii = "clientPin"u8.ToArray();
        byte[] expected =
        [
            0xA3,
            0x01, 0x81, 0x68, .. Fido23Ascii,
            0x03, 0x50, .. FixedAaguidBytes,
            0x04, 0xA2, //key 4 (options): map(2)
                0x69, .. authnrCfgAscii, 0xF5, //"authnrCfg" (text(9)) -> true, sorts before "clientPin"
                0x69, .. clientPinAscii, 0xF4 //"clientPin" (text(9)) -> false
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// The <c>options</c> map's length-9 tie widens to a THREE-WAY tie once <c>bioEnroll</c> is present
    /// alongside <c>authnrCfg</c> and <c>clientPin</c> (all 9 characters): the tie breaks byte-wise
    /// lexically — <c>'a'</c> (0x61) &lt; <c>'b'</c> (0x62) &lt; <c>'c'</c> (0x63) — placing
    /// <c>authnrCfg</c> first, <c>bioEnroll</c> second, <c>clientPin</c> third.
    /// </summary>
    [TestMethod]
    public void WriteOrdersBioEnrollBetweenAuthnrCfgAndClientPinOnLengthNineThreeWayTie()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            Options: new CtapGetInfoOptions(AuthnrCfg: true, BioEnroll: false, ClientPin: true));

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] authnrCfgAscii = "authnrCfg"u8.ToArray();
        byte[] bioEnrollAscii = "bioEnroll"u8.ToArray();
        byte[] clientPinAscii = "clientPin"u8.ToArray();
        byte[] expected =
        [
            0xA3,
            0x01, 0x81, 0x68, .. Fido23Ascii,
            0x03, 0x50, .. FixedAaguidBytes,
            0x04, 0xA3, //key 4 (options): map(3)
                0x69, .. authnrCfgAscii, 0xF5, //"authnrCfg" (text(9)) -> true, sorts first
                0x69, .. bioEnrollAscii, 0xF4, //"bioEnroll" (text(9)) -> false, sorts second
                0x69, .. clientPinAscii, 0xF5 //"clientPin" (text(9)) -> true, sorts third
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// <c>uvBioEnroll</c> (11 characters) slots between the length-9 tie group and <c>pinUvAuthToken</c>
    /// (14 characters) — its own canonical position, computed fresh from its byte length rather than
    /// guessed.
    /// </summary>
    [TestMethod]
    public void WriteOrdersUvBioEnrollAfterClientPinBeforePinUvAuthToken()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            Options: new CtapGetInfoOptions(ClientPin: true, UvBioEnroll: true, PinUvAuthToken: true));

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] clientPinAscii = "clientPin"u8.ToArray();
        byte[] uvBioEnrollAscii = "uvBioEnroll"u8.ToArray();
        byte[] pinUvAuthTokenAscii = "pinUvAuthToken"u8.ToArray();
        byte[] expected =
        [
            0xA3,
            0x01, 0x81, 0x68, .. Fido23Ascii,
            0x03, 0x50, .. FixedAaguidBytes,
            0x04, 0xA3, //key 4 (options): map(3)
                0x69, .. clientPinAscii, 0xF5, //"clientPin" (text(9)) -> true
                0x6B, .. uvBioEnrollAscii, 0xF5, //"uvBioEnroll" (text(11)) -> true
                0x6E, .. pinUvAuthTokenAscii, 0xF5 //"pinUvAuthToken" (text(14)) -> true
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// <c>largeBlobs</c> (10 characters, R2) slots between <c>clientPin</c> (9) and <c>uvBioEnroll</c>
    /// (11) — a NEW length-10 class with NO tie, its own canonical position computed fresh from its byte
    /// length.
    /// </summary>
    [TestMethod]
    public void WriteOrdersLargeBlobsBetweenClientPinAndUvBioEnroll()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            Options: new CtapGetInfoOptions(ClientPin: true, LargeBlobs: true, UvBioEnroll: true));

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] clientPinAscii = "clientPin"u8.ToArray();
        byte[] largeBlobsAscii = "largeBlobs"u8.ToArray();
        byte[] uvBioEnrollAscii = "uvBioEnroll"u8.ToArray();
        byte[] expected =
        [
            0xA3,
            0x01, 0x81, 0x68, .. Fido23Ascii,
            0x03, 0x50, .. FixedAaguidBytes,
            0x04, 0xA3, //key 4 (options): map(3)
                0x69, .. clientPinAscii, 0xF5, //"clientPin" (text(9)) -> true
                0x6A, .. largeBlobsAscii, 0xF5, //"largeBlobs" (text(10)) -> true
                0x6B, .. uvBioEnrollAscii, 0xF5 //"uvBioEnroll" (text(11)) -> true
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// The outer response map's two new members this wave adds — <c>preferredPlatformUvAttempts</c>
    /// (0x11) and <c>uvModality</c> (0x12) — write in ascending integer-key order between
    /// <c>maxRPIDsForSetMinPINLength</c> (0x10) and <c>remainingDiscoverableCredentials</c> (0x14).
    /// </summary>
    [TestMethod]
    public void WriteOrdersPreferredPlatformUvAttemptsAndUvModalityBetweenMaxRpIdsAndRemainingDiscoverableCredentials()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            MaxRpIdsForSetMinPinLength: 8,
            PreferredPlatformUvAttempts: 3,
            UvModality: 0x00000002,
            RemainingDiscoverableCredentials: 8);

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] expected =
        [
            0xA6, //map(6): versions, aaguid, maxRPIDsForSetMinPINLength, preferredPlatformUvAttempts, uvModality, remainingDiscoverableCredentials
            0x01, 0x81, 0x68, .. Fido23Ascii,
            0x03, 0x50, .. FixedAaguidBytes,
            0x10, 0x08, //key 0x10 (maxRPIDsForSetMinPINLength) -> 8
            0x11, 0x03, //key 0x11 (preferredPlatformUvAttempts) -> 3
            0x12, 0x02, //key 0x12 (uvModality) -> 2 (USER_VERIFY_FINGERPRINT_INTERNAL)
            0x14, 0x08 //key 0x14 (remainingDiscoverableCredentials) -> 8
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// The four new top-level members this wave adds — <c>forcePINChange</c> (0x0C),
    /// <c>minPINLength</c> (0x0D), <c>maxRPIDsForSetMinPINLength</c> (0x10), and
    /// <c>authenticatorConfigCommands</c> (0x1F) — write in ascending integer-key order after
    /// <c>pinUvAuthProtocols</c>; <c>0x1F</c> (31) is the only key in this response map that is
    /// ≥ 24, so it alone requires CBOR's 1-additional-byte unsigned-integer form (<c>0x18</c>
    /// followed by the raw value), while every other key encodes as a single byte.
    /// </summary>
    [TestMethod]
    public void WriteOrdersForcePinChangeMinPinLengthMaxRpIdsAndAuthenticatorConfigCommandsAscending()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            ForcePinChange: true,
            MinPinLength: 6,
            MaxRpIdsForSetMinPinLength: 0,
            AuthenticatorConfigCommands: [2, 3]);

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] expected =
        [
            0xA6, //map(6): versions, aaguid, forcePINChange, minPINLength, maxRPIDsForSetMinPINLength, authenticatorConfigCommands
            0x01, 0x81, 0x68, .. Fido23Ascii,
            0x03, 0x50, .. FixedAaguidBytes,
            0x0C, 0xF5, //key 0x0C (forcePINChange) -> true
            0x0D, 0x06, //key 0x0D (minPINLength) -> 6
            0x10, 0x00, //key 0x10 (maxRPIDsForSetMinPINLength) -> 0
            0x18, 0x1F, 0x82, 0x02, 0x03 //key 0x1F (authenticatorConfigCommands, 2-byte key form) -> [2, 3]
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// The two R5/R6 members this wave adds — <c>maxCredentialCountInList</c> (0x07) and
    /// <c>algorithms</c> (0x0A) — write in ascending integer-key order, inserted between
    /// <c>pinUvAuthProtocols</c> (0x06) and <c>maxSerializedLargeBlobArray</c> (0x0B): trap 7's
    /// ascending-key insertion, <c>0x07</c> strictly before <c>0x0A</c>. The <c>algorithms</c> array's
    /// own element map is text-keyed canonical (<c>"alg"</c> before <c>"type"</c>, length-first) — see
    /// <see cref="Es256AlgorithmsBytes"/>'s own derivation.
    /// </summary>
    [TestMethod]
    public void WriteOrdersMaxCredentialCountInListAndAlgorithmsBetweenPinUvAuthProtocolsAndMaxSerializedLargeBlobArray()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            PinUvAuthProtocols: [2, 1],
            MaxCredentialCountInList: 8,
            Algorithms: Es256Algorithms,
            MaxSerializedLargeBlobArray: CtapAuthenticatorState.MaxSerializedLargeBlobArrayCapacity);

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] expected =
        [
            0xA6, //map(6): versions, aaguid, pinUvAuthProtocols, maxCredentialCountInList, algorithms, maxSerializedLargeBlobArray
            0x01, 0x81, 0x68, .. Fido23Ascii,
            0x03, 0x50, .. FixedAaguidBytes,
            0x06, 0x82, 0x02, 0x01, //key 6 (pinUvAuthProtocols): [2, 1]
            0x07, 0x08, //key 0x07 (maxCredentialCountInList) -> 8
            0x0A, .. Es256AlgorithmsBytes, //key 0x0A (algorithms) -> [{alg: ES256, type: "public-key"}]
            0x0B, 0x19, 0x10, 0x00 //key 0x0B (maxSerializedLargeBlobArray) -> 4096
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// A response carrying <c>maxCredentialCountInList</c> alone (<c>algorithms</c> left
    /// <see langword="null"/>) writes 0x07 with NO following 0x0A entry — the writer omits the
    /// <c>algorithms</c> member entirely rather than emitting an empty array, since
    /// <see cref="CtapGetInfoResponse.Algorithms"/> is itself the omission signal (R6: "MUST NOT... be
    /// empty if present" is satisfied by never presenting an empty array at all).
    /// </summary>
    [TestMethod]
    public void WriteOmitsAlgorithmsWhenNullAlongsideMaxCredentialCountInList()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            MaxCredentialCountInList: 8);

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] expected =
        [
            0xA3, //map(3): versions, aaguid, maxCredentialCountInList
            0x01, 0x81, 0x68, .. Fido23Ascii,
            0x03, 0x50, .. FixedAaguidBytes,
            0x07, 0x08 //key 0x07 (maxCredentialCountInList) -> 8, no 0x0A follows
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// The R7 member <c>firmwareVersion</c> (0x0E) writes in ascending integer-key order, inserted
    /// between <c>minPINLength</c> (0x0D) and <c>maxRPIDsForSetMinPINLength</c> (0x10) — trap 7's second
    /// insertion point.
    /// </summary>
    [TestMethod]
    public void WriteOrdersFirmwareVersionBetweenMinPinLengthAndMaxRpIdsForSetMinPinLength()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            MinPinLength: 4,
            FirmwareVersion: 1,
            MaxRpIdsForSetMinPinLength: 8);

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] expected =
        [
            0xA5, //map(5): versions, aaguid, minPINLength, firmwareVersion, maxRPIDsForSetMinPINLength
            0x01, 0x81, 0x68, .. Fido23Ascii,
            0x03, 0x50, .. FixedAaguidBytes,
            0x0D, 0x04, //key 0x0D (minPINLength) -> 4
            0x0E, 0x01, //key 0x0E (firmwareVersion) -> 1
            0x10, 0x08 //key 0x10 (maxRPIDsForSetMinPINLength) -> 8
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// The full <c>authenticatorConfig</c>+<c>authenticatorCredentialManagement</c>+wavebio getInfo
    /// surface in the <c>alwaysUv</c>-disabled state: the default <c>extensions:["credProtect",
    /// "hmac-secret", "hmac-secret-mc", "largeBlobKey", "minPinLength"]</c> (contract R1), <c>alwaysUv:false</c>,
    /// <c>authnrCfg:true</c>, <c>credMgmt:true</c>, <c>largeBlobs:true</c>, and
    /// <c>setMinPINLength:true</c> unconditionally, <c>makeCredUvNotRqd:true</c> (the derived negation of
    /// <c>alwaysUv</c>), <c>uv:false</c>/<c>bioEnroll:false</c> (R2's shared
    /// <c>HasProvisionedBioEnrollments</c> placeholder, zero enrollments), <c>uvBioEnroll:true</c>
    /// unconditionally, the pre-configured default <c>minPINLength:4</c>, <c>forcePINChange:false</c>,
    /// <c>maxSerializedLargeBlobArray:4096</c>/<c>maxRPIDsForSetMinPINLength:8</c> (both single-sourced
    /// fixed capacity constants), <c>preferredPlatformUvAttempts:3</c>/<c>uvModality:2</c>
    /// (single-sourced statics), <c>remainingDiscoverableCredentials:8</c> (the default resident
    /// credential capacity, empty store), <c>authenticatorConfigCommands:[2, 3]</c>,
    /// <c>maxCredentialCountInList:8</c> (R5), a one-element <c>algorithms:[{alg: ES256, type:
    /// "public-key"}]</c> (R6, the ES256-only default credential-signing backend), and
    /// <c>firmwareVersion:1</c> (R7, <see cref="CtapAuthenticatorState.Initial"/>'s own seed default) —
    /// this is the exact shape
    /// <see cref="Verifiable.Fido2.Ctap.Authenticator.Automata.CtapAuthenticatorTransitions"/>'s
    /// <c>BuildGetInfoResponse</c> produces for a freshly constructed authenticator with the ES256
    /// default backend injected. R11 regression fence: this authenticator is NON-CAPABLE (no
    /// <c>EnterpriseAttestationProvisioning</c> seeded), so <c>ep</c> stays absent and this vector's
    /// <c>options</c> bytes are UNCHANGED by the waveep contract —
    /// <see cref="WriteEncodesEnterpriseAttestationCapableEnabledFullSurfaceToExactCanonicalBytes"/> is
    /// the capable+enabled sibling proving the two profiles diverge only where <c>ep</c> itself differs.
    /// </summary>
    [TestMethod]
    public void WriteEncodesFullAuthenticatorConfigSurfaceWithAlwaysUvDisabledToExactCanonicalBytes()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            Extensions: CtapAuthenticatorState.DefaultSupportedExtensions,
            Options: new CtapGetInfoOptions(
                ResidentKey: true,
                Uv: false,
                Platform: false,
                AlwaysUv: false,
                CredMgmt: true,
                AuthnrCfg: true,
                BioEnroll: false,
                ClientPin: false,
                LargeBlobs: true,
                UvBioEnroll: true,
                PinUvAuthToken: true,
                SetMinPinLength: true,
                MakeCredUvNotRqd: true),
            PinUvAuthProtocols: [2, 1],
            MaxSerializedLargeBlobArray: CtapAuthenticatorState.MaxSerializedLargeBlobArrayCapacity,
            ForcePinChange: false,
            MinPinLength: 4,
            MaxRpIdsForSetMinPinLength: 8,
            PreferredPlatformUvAttempts: 3,
            UvModality: 0x00000002,
            RemainingDiscoverableCredentials: 8,
            AuthenticatorConfigCommands: [2, 3],
            MaxCredentialCountInList: 8,
            Algorithms: Es256Algorithms,
            FirmwareVersion: 1);

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] credProtectAscii = "credProtect"u8.ToArray();
        byte[] hmacSecretAscii = "hmac-secret"u8.ToArray();
        byte[] hmacSecretMcAscii = "hmac-secret-mc"u8.ToArray();
        byte[] largeBlobKeyAscii = "largeBlobKey"u8.ToArray();
        byte[] minPinLengthAscii = "minPinLength"u8.ToArray();
        byte[] alwaysUvAscii = "alwaysUv"u8.ToArray();
        byte[] credMgmtAscii = "credMgmt"u8.ToArray();
        byte[] authnrCfgAscii = "authnrCfg"u8.ToArray();
        byte[] bioEnrollAscii = "bioEnroll"u8.ToArray();
        byte[] clientPinAscii = "clientPin"u8.ToArray();
        byte[] largeBlobsAscii = "largeBlobs"u8.ToArray();
        byte[] uvBioEnrollAscii = "uvBioEnroll"u8.ToArray();
        byte[] pinUvAuthTokenAscii = "pinUvAuthToken"u8.ToArray();
        byte[] setMinPinLengthAscii = "setMinPINLength"u8.ToArray();
        byte[] makeCredUvNotRqdAscii = "makeCredUvNotRqd"u8.ToArray();

        byte[] expected =
        [
            0xB0, //map(16): versions, extensions, aaguid, options, pinUvAuthProtocols, maxCredentialCountInList, algorithms, maxSerializedLargeBlobArray, forcePINChange, minPINLength, firmwareVersion, maxRPIDsForSetMinPINLength, preferredPlatformUvAttempts, uvModality, remainingDiscoverableCredentials, authenticatorConfigCommands
            0x01, 0x81, 0x68, .. Fido23Ascii,
            0x02, 0x85, 0x6B, .. credProtectAscii, 0x6B, .. hmacSecretAscii, 0x6E, .. hmacSecretMcAscii, 0x6C, .. largeBlobKeyAscii, 0x6C, .. minPinLengthAscii, //key 2 (extensions): array(5) of text(11), text(11), text(14), text(12), text(12)
            0x03, 0x50, .. FixedAaguidBytes,
            0x04, 0xAD, //key 4 (options): map(13), canonical order
                0x62, 0x72, 0x6B, 0xF5, //"rk" -> true
                0x62, 0x75, 0x76, 0xF4, //"uv" (text(2)) -> false
                0x64, 0x70, 0x6C, 0x61, 0x74, 0xF4, //"plat" -> false
                0x68, .. alwaysUvAscii, 0xF4, //"alwaysUv" (text(8)) -> false
                0x68, .. credMgmtAscii, 0xF5, //"credMgmt" (text(8)) -> true
                0x69, .. authnrCfgAscii, 0xF5, //"authnrCfg" (text(9)) -> true
                0x69, .. bioEnrollAscii, 0xF4, //"bioEnroll" (text(9)) -> false
                0x69, .. clientPinAscii, 0xF4, //"clientPin" (text(9)) -> false
                0x6A, .. largeBlobsAscii, 0xF5, //"largeBlobs" (text(10)) -> true
                0x6B, .. uvBioEnrollAscii, 0xF5, //"uvBioEnroll" (text(11)) -> true
                0x6E, .. pinUvAuthTokenAscii, 0xF5, //"pinUvAuthToken" (text(14)) -> true
                0x6F, .. setMinPinLengthAscii, 0xF5, //"setMinPINLength" (text(15)) -> true
                0x70, .. makeCredUvNotRqdAscii, 0xF5, //"makeCredUvNotRqd" (text(16)) -> true
            0x06, 0x82, 0x02, 0x01, //key 6 (pinUvAuthProtocols): [2, 1]
            0x07, 0x08, //key 0x07 (maxCredentialCountInList) -> 8
            0x0A, .. Es256AlgorithmsBytes, //key 0x0A (algorithms) -> [{alg: ES256, type: "public-key"}]
            0x0B, 0x19, 0x10, 0x00, //key 0x0B (maxSerializedLargeBlobArray) -> 4096
            0x0C, 0xF4, //key 0x0C (forcePINChange) -> false
            0x0D, 0x04, //key 0x0D (minPINLength) -> 4
            0x0E, 0x01, //key 0x0E (firmwareVersion) -> 1
            0x10, 0x08, //key 0x10 (maxRPIDsForSetMinPINLength) -> 8
            0x11, 0x03, //key 0x11 (preferredPlatformUvAttempts) -> 3
            0x12, 0x02, //key 0x12 (uvModality) -> 2
            0x14, 0x08, //key 0x14 (remainingDiscoverableCredentials) -> 8
            0x18, 0x1F, 0x82, 0x02, 0x03 //key 0x1F (authenticatorConfigCommands) -> [2, 3]
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// The same full surface in the <c>alwaysUv</c>-enabled state: <c>alwaysUv:true</c> flips
    /// <c>makeCredUvNotRqd:false</c> (line 4951's MUST), and a raised <c>minPINLength</c> with
    /// <c>forcePINChange:true</c> writes byte-identically in shape to the disabled variant above,
    /// including the default <c>extensions:["credProtect", "hmac-secret", "hmac-secret-mc",
    /// "largeBlobKey", "minPinLength"]</c> (contract R1), <c>largeBlobs:true</c>/<c>maxSerializedLargeBlobArray:4096</c>,
    /// <c>maxRPIDsForSetMinPINLength:8</c> (R8), and the wavebio <c>uv:false</c>/<c>bioEnroll:false</c>/
    /// <c>uvBioEnroll:true</c>/<c>preferredPlatformUvAttempts:3</c>/<c>uvModality:2</c> surface — bio
    /// enrollment state is independent of <c>alwaysUv</c> — with only the changed booleans/integer
    /// differing, proving the config-state flips are value changes, never structural ones.
    /// <c>maxCredentialCountInList:8</c>/<c>algorithms:[{alg: ES256, type: "public-key"}]</c>/
    /// <c>firmwareVersion:1</c> (R5/R6/R7) are orthogonal to <c>alwaysUv</c> and stay byte-identical to
    /// the disabled variant. R11 regression fence: this authenticator is also NON-CAPABLE, so <c>ep</c>
    /// stays absent here too — this vector's <c>options</c> bytes are UNCHANGED by the waveep contract.
    /// </summary>
    [TestMethod]
    public void WriteEncodesFullAuthenticatorConfigSurfaceWithAlwaysUvEnabledToExactCanonicalBytes()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            Extensions: CtapAuthenticatorState.DefaultSupportedExtensions,
            Options: new CtapGetInfoOptions(
                ResidentKey: true,
                Uv: false,
                Platform: false,
                AlwaysUv: true,
                CredMgmt: true,
                AuthnrCfg: true,
                BioEnroll: false,
                ClientPin: false,
                LargeBlobs: true,
                UvBioEnroll: true,
                PinUvAuthToken: true,
                SetMinPinLength: true,
                MakeCredUvNotRqd: false),
            PinUvAuthProtocols: [2, 1],
            MaxSerializedLargeBlobArray: CtapAuthenticatorState.MaxSerializedLargeBlobArrayCapacity,
            ForcePinChange: true,
            MinPinLength: 6,
            MaxRpIdsForSetMinPinLength: 8,
            PreferredPlatformUvAttempts: 3,
            UvModality: 0x00000002,
            RemainingDiscoverableCredentials: 8,
            AuthenticatorConfigCommands: [2, 3],
            MaxCredentialCountInList: 8,
            Algorithms: Es256Algorithms,
            FirmwareVersion: 1);

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] credProtectAscii = "credProtect"u8.ToArray();
        byte[] hmacSecretAscii = "hmac-secret"u8.ToArray();
        byte[] hmacSecretMcAscii = "hmac-secret-mc"u8.ToArray();
        byte[] largeBlobKeyAscii = "largeBlobKey"u8.ToArray();
        byte[] minPinLengthAscii = "minPinLength"u8.ToArray();
        byte[] alwaysUvAscii = "alwaysUv"u8.ToArray();
        byte[] credMgmtAscii = "credMgmt"u8.ToArray();
        byte[] authnrCfgAscii = "authnrCfg"u8.ToArray();
        byte[] bioEnrollAscii = "bioEnroll"u8.ToArray();
        byte[] clientPinAscii = "clientPin"u8.ToArray();
        byte[] largeBlobsAscii = "largeBlobs"u8.ToArray();
        byte[] uvBioEnrollAscii = "uvBioEnroll"u8.ToArray();
        byte[] pinUvAuthTokenAscii = "pinUvAuthToken"u8.ToArray();
        byte[] setMinPinLengthAscii = "setMinPINLength"u8.ToArray();
        byte[] makeCredUvNotRqdAscii = "makeCredUvNotRqd"u8.ToArray();

        byte[] expected =
        [
            0xB0, //map(16), see WriteEncodesFullAuthenticatorConfigSurfaceWithAlwaysUvDisabledToExactCanonicalBytes
            0x01, 0x81, 0x68, .. Fido23Ascii,
            0x02, 0x85, 0x6B, .. credProtectAscii, 0x6B, .. hmacSecretAscii, 0x6E, .. hmacSecretMcAscii, 0x6C, .. largeBlobKeyAscii, 0x6C, .. minPinLengthAscii, //key 2 (extensions): array(5) of text(11), text(11), text(14), text(12), text(12)
            0x03, 0x50, .. FixedAaguidBytes,
            0x04, 0xAD,
                0x62, 0x72, 0x6B, 0xF5, //"rk" -> true
                0x62, 0x75, 0x76, 0xF4, //"uv" (text(2)) -> false
                0x64, 0x70, 0x6C, 0x61, 0x74, 0xF4, //"plat" -> false
                0x68, .. alwaysUvAscii, 0xF5, //"alwaysUv" -> true
                0x68, .. credMgmtAscii, 0xF5, //"credMgmt" -> true
                0x69, .. authnrCfgAscii, 0xF5, //"authnrCfg" -> true
                0x69, .. bioEnrollAscii, 0xF4, //"bioEnroll" (text(9)) -> false
                0x69, .. clientPinAscii, 0xF4, //"clientPin" -> false
                0x6A, .. largeBlobsAscii, 0xF5, //"largeBlobs" (text(10)) -> true
                0x6B, .. uvBioEnrollAscii, 0xF5, //"uvBioEnroll" (text(11)) -> true
                0x6E, .. pinUvAuthTokenAscii, 0xF5, //"pinUvAuthToken" -> true
                0x6F, .. setMinPinLengthAscii, 0xF5, //"setMinPINLength" -> true
                0x70, .. makeCredUvNotRqdAscii, 0xF4, //"makeCredUvNotRqd" -> false
            0x06, 0x82, 0x02, 0x01,
            0x07, 0x08, //key 0x07 (maxCredentialCountInList) -> 8
            0x0A, .. Es256AlgorithmsBytes, //key 0x0A (algorithms) -> [{alg: ES256, type: "public-key"}]
            0x0B, 0x19, 0x10, 0x00, //key 0x0B (maxSerializedLargeBlobArray) -> 4096
            0x0C, 0xF5, //key 0x0C (forcePINChange) -> true
            0x0D, 0x06, //key 0x0D (minPINLength) -> 6
            0x0E, 0x01, //key 0x0E (firmwareVersion) -> 1
            0x10, 0x08, //key 0x10 (maxRPIDsForSetMinPINLength) -> 8
            0x11, 0x03, //key 0x11 (preferredPlatformUvAttempts) -> 3
            0x12, 0x02, //key 0x12 (uvModality) -> 2
            0x14, 0x08, //key 0x14 (remainingDiscoverableCredentials) -> 8
            0x18, 0x1F, 0x82, 0x02, 0x03 //key 0x1F (authenticatorConfigCommands) -> [2, 3]
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// The full getInfo surface for an enterprise-attestation CAPABLE, ENABLED authenticator (R11(a)):
    /// identical in shape to <see cref="WriteEncodesFullAuthenticatorConfigSurfaceWithAlwaysUvDisabledToExactCanonicalBytes"/>
    /// except for exactly two hand-derived deltas — <c>options</c> gains a 14th entry, <c>"ep" -> true</c>
    /// (<c>62 65 70 F5</c>), written FIRST (before <c>"rk"</c>, R10's own length-2 tie-break), bumping
    /// the options map header from map(13) to map(14); and <c>authenticatorConfigCommands</c> becomes
    /// the ascending 3-element array <c>[1, 2, 3]</c> (<c>83 01 02 03</c>, trap 6) rather than <c>[2, 3]</c>.
    /// <c>maxCredentialCountInList:8</c>/<c>algorithms:[{alg: ES256, type: "public-key"}]</c>/
    /// <c>firmwareVersion:1</c> (R5/R6/R7) are orthogonal to enterprise attestation and stay
    /// byte-identical to the disabled variant. Every other byte is identical to the non-capable
    /// regression-fence vector, proving the capability flip is additive, never structural elsewhere.
    /// </summary>
    [TestMethod]
    public void WriteEncodesEnterpriseAttestationCapableEnabledFullSurfaceToExactCanonicalBytes()
    {
        Guid aaguid = new(FixedAaguidBytes, bigEndian: true);
        var response = new CtapGetInfoResponse(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            Extensions: CtapAuthenticatorState.DefaultSupportedExtensions,
            Options: new CtapGetInfoOptions(
                Ep: true,
                ResidentKey: true,
                Uv: false,
                Platform: false,
                AlwaysUv: false,
                CredMgmt: true,
                AuthnrCfg: true,
                BioEnroll: false,
                ClientPin: false,
                LargeBlobs: true,
                UvBioEnroll: true,
                PinUvAuthToken: true,
                SetMinPinLength: true,
                MakeCredUvNotRqd: true),
            PinUvAuthProtocols: [2, 1],
            MaxSerializedLargeBlobArray: CtapAuthenticatorState.MaxSerializedLargeBlobArrayCapacity,
            ForcePinChange: false,
            MinPinLength: 4,
            MaxRpIdsForSetMinPinLength: 8,
            PreferredPlatformUvAttempts: 3,
            UvModality: 0x00000002,
            RemainingDiscoverableCredentials: 8,
            AuthenticatorConfigCommands: [1, 2, 3],
            MaxCredentialCountInList: 8,
            Algorithms: Es256Algorithms,
            FirmwareVersion: 1);

        TaggedMemory<byte> result = CtapGetInfoResponseCborWriter.Write(response);

        byte[] credProtectAscii = "credProtect"u8.ToArray();
        byte[] hmacSecretAscii = "hmac-secret"u8.ToArray();
        byte[] hmacSecretMcAscii = "hmac-secret-mc"u8.ToArray();
        byte[] largeBlobKeyAscii = "largeBlobKey"u8.ToArray();
        byte[] minPinLengthAscii = "minPinLength"u8.ToArray();
        byte[] alwaysUvAscii = "alwaysUv"u8.ToArray();
        byte[] credMgmtAscii = "credMgmt"u8.ToArray();
        byte[] authnrCfgAscii = "authnrCfg"u8.ToArray();
        byte[] bioEnrollAscii = "bioEnroll"u8.ToArray();
        byte[] clientPinAscii = "clientPin"u8.ToArray();
        byte[] largeBlobsAscii = "largeBlobs"u8.ToArray();
        byte[] uvBioEnrollAscii = "uvBioEnroll"u8.ToArray();
        byte[] pinUvAuthTokenAscii = "pinUvAuthToken"u8.ToArray();
        byte[] setMinPinLengthAscii = "setMinPINLength"u8.ToArray();
        byte[] makeCredUvNotRqdAscii = "makeCredUvNotRqd"u8.ToArray();

        byte[] expected =
        [
            0xB0, //map(16), see WriteEncodesFullAuthenticatorConfigSurfaceWithAlwaysUvDisabledToExactCanonicalBytes
            0x01, 0x81, 0x68, .. Fido23Ascii,
            0x02, 0x85, 0x6B, .. credProtectAscii, 0x6B, .. hmacSecretAscii, 0x6E, .. hmacSecretMcAscii, 0x6C, .. largeBlobKeyAscii, 0x6C, .. minPinLengthAscii, //key 2 (extensions): array(5) of text(11), text(11), text(14), text(12), text(12)
            0x03, 0x50, .. FixedAaguidBytes,
            0x04, 0xAE, //key 4 (options): map(14), canonical order — "ep" now FIRST
                0x62, 0x65, 0x70, 0xF5, //"ep" (text(2)) -> true
                0x62, 0x72, 0x6B, 0xF5, //"rk" -> true
                0x62, 0x75, 0x76, 0xF4, //"uv" (text(2)) -> false
                0x64, 0x70, 0x6C, 0x61, 0x74, 0xF4, //"plat" -> false
                0x68, .. alwaysUvAscii, 0xF4, //"alwaysUv" (text(8)) -> false
                0x68, .. credMgmtAscii, 0xF5, //"credMgmt" (text(8)) -> true
                0x69, .. authnrCfgAscii, 0xF5, //"authnrCfg" (text(9)) -> true
                0x69, .. bioEnrollAscii, 0xF4, //"bioEnroll" (text(9)) -> false
                0x69, .. clientPinAscii, 0xF4, //"clientPin" (text(9)) -> false
                0x6A, .. largeBlobsAscii, 0xF5, //"largeBlobs" (text(10)) -> true
                0x6B, .. uvBioEnrollAscii, 0xF5, //"uvBioEnroll" (text(11)) -> true
                0x6E, .. pinUvAuthTokenAscii, 0xF5, //"pinUvAuthToken" (text(14)) -> true
                0x6F, .. setMinPinLengthAscii, 0xF5, //"setMinPINLength" (text(15)) -> true
                0x70, .. makeCredUvNotRqdAscii, 0xF5, //"makeCredUvNotRqd" (text(16)) -> true
            0x06, 0x82, 0x02, 0x01, //key 6 (pinUvAuthProtocols): [2, 1]
            0x07, 0x08, //key 0x07 (maxCredentialCountInList) -> 8
            0x0A, .. Es256AlgorithmsBytes, //key 0x0A (algorithms) -> [{alg: ES256, type: "public-key"}]
            0x0B, 0x19, 0x10, 0x00, //key 0x0B (maxSerializedLargeBlobArray) -> 4096
            0x0C, 0xF4, //key 0x0C (forcePINChange) -> false
            0x0D, 0x04, //key 0x0D (minPINLength) -> 4
            0x0E, 0x01, //key 0x0E (firmwareVersion) -> 1
            0x10, 0x08, //key 0x10 (maxRPIDsForSetMinPINLength) -> 8
            0x11, 0x03, //key 0x11 (preferredPlatformUvAttempts) -> 3
            0x12, 0x02, //key 0x12 (uvModality) -> 2
            0x14, 0x08, //key 0x14 (remainingDiscoverableCredentials) -> 8
            0x18, 0x1F, 0x83, 0x01, 0x02, 0x03 //key 0x1F (authenticatorConfigCommands, 2-byte key form) -> [1, 2, 3], ascending (trap 6)
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }
}
