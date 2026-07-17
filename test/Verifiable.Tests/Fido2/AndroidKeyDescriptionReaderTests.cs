using System.Security.Cryptography;
using Verifiable.Fido2;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="AndroidKeyDescription.Read"/>: the constants-pinning decode of
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-android-key-es256">W3C Web
/// Authentication Level 3, section 16.14: Android Key Attestation with ES256 Credential</see>'s own
/// key description bytes, BouncyCastle-minted round-trips, and the ASN.1 malformation battery.
/// </summary>
[TestClass]
internal sealed class AndroidKeyDescriptionReaderTests
{
    /// <summary>
    /// The exact <c>KeyDescription</c> SEQUENCE bytes (the android key attestation certificate
    /// extension's <c>extnValue</c> content) embedded in section 16.14's own <c>attestationObject</c>
    /// test vector, extracted byte-for-byte from the CR's own hex literal — not re-derived or
    /// paraphrased.
    /// </summary>
    private const string Section1614KeyDescriptionHex =
        "30430202012c0a01000201000a01000420b435028d7b6a8f83bb461d41c19b053a9d3cdb30351a4f374cd4cde8dbefb60604003000300ea1053103020102bf853e03020100";

    /// <summary>
    /// The section 16.14 vector's <c>clientDataJSON</c> bytes, whose SHA-256 digest equals the
    /// vector's own <c>attestationChallenge</c> — proving the extracted <c>Section1614KeyDescriptionHex</c>
    /// constant was not mistranscribed, independent of <see cref="AndroidKeyDescription.Read"/> itself.
    /// </summary>
    private const string Section1614ClientDataJsonHex =
        "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a2250654877747a5a647a4e345f384d76795869625f7037725f682d385162494438686c334541746d57414641222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a205656316351755232714c4d5f616d50666f487a4c3067227d";


    /// <summary>
    /// Decodes section 16.14's own <c>KeyDescription</c> bytes and asserts the field order, the
    /// <c>softwareEnforced</c>/<c>teeEnforced</c> split, and the <c>purpose</c>/<c>origin</c> values
    /// the CR's own vector carries — the tag-number constants (<c>[1]</c>/<c>[702]</c>) are pinned by
    /// the specification's own bytes, not by trust (owner ruling 2).
    /// </summary>
    [TestMethod]
    public void ReadDecodesSection1614sOwnKeyDescriptionVectorExactly()
    {
        byte[] keyDescriptionBytes = Convert.FromHexString(Section1614KeyDescriptionHex);
        byte[] clientDataJsonBytes = Convert.FromHexString(Section1614ClientDataJsonHex);
        byte[] expectedChallenge = SHA256.HashData(clientDataJsonBytes);

        AndroidKeyDescription keyDescription = AndroidKeyDescription.Read(keyDescriptionBytes);

        Assert.IsTrue(keyDescription.AttestationChallenge.Span.SequenceEqual(expectedChallenge));

        Assert.IsEmpty(keyDescription.SoftwareEnforced.Purposes);
        Assert.IsNull(keyDescription.SoftwareEnforced.Origin);
        Assert.IsFalse(keyDescription.SoftwareEnforced.HasAllApplications);

        Assert.HasCount(1, keyDescription.TeeEnforced.Purposes);
        Assert.Contains(AndroidKeyAttestationTestVectors.KmPurposeSign, keyDescription.TeeEnforced.Purposes);
        Assert.AreEqual(AndroidKeyAttestationTestVectors.KmOriginGenerated, keyDescription.TeeEnforced.Origin);
        Assert.IsFalse(keyDescription.TeeEnforced.HasAllApplications);
    }


    /// <summary>
    /// A key description minted with BouncyCastle's ASN.1 writer — the independent oracle
    /// <see cref="AndroidKeyAttestationTestVectors.EncodeKeyDescriptionExtensionValue"/> uses — round-trips
    /// through <see cref="AndroidKeyDescription.Read"/> with every field preserved, including an
    /// <c>allApplications</c> field present on both lists.
    /// </summary>
    [TestMethod]
    public void ReadRoundTripsABouncyCastleMintedKeyDescriptionWithBothAuthorizationLists()
    {
        byte[] challenge = [1, 2, 3, 4, 5, 6, 7, 8];
        var softwareEnforced = new AndroidKeyAuthorizationList(new HashSet<int> { 3 }, 1, HasAllApplications: true);
        var teeEnforced = new AndroidKeyAuthorizationList(new HashSet<int> { 2, 6 }, 0, HasAllApplications: true);
        byte[] keyDescriptionBytes = AndroidKeyAttestationTestVectors.EncodeKeyDescriptionExtensionValue(challenge, softwareEnforced, teeEnforced);

        AndroidKeyDescription keyDescription = AndroidKeyDescription.Read(keyDescriptionBytes);

        Assert.IsTrue(keyDescription.AttestationChallenge.Span.SequenceEqual(challenge));
        Assert.AreEqual(softwareEnforced, keyDescription.SoftwareEnforced);
        Assert.AreEqual(teeEnforced, keyDescription.TeeEnforced);
    }


    /// <summary>
    /// A key description minted with an empty <c>softwareEnforced</c> and a fully-populated,
    /// conformant <c>teeEnforced</c> list — the typical hardware-backed-key shape — round-trips
    /// with <see cref="AndroidKeyAuthorizationList.HasAllApplications"/> <see langword="false"/> on
    /// both lists.
    /// </summary>
    [TestMethod]
    public void ReadRoundTripsAConformantHardwareBackedKeyDescription()
    {
        byte[] challenge = [9, 9, 9, 9];
        byte[] keyDescriptionBytes = AndroidKeyAttestationTestVectors.EncodeKeyDescriptionExtensionValue(
            challenge, AndroidKeyAttestationTestVectors.EmptyAuthorizationList, AndroidKeyAttestationTestVectors.ConformantAuthorizationList);

        AndroidKeyDescription keyDescription = AndroidKeyDescription.Read(keyDescriptionBytes);

        Assert.AreEqual(AndroidKeyAttestationTestVectors.EmptyAuthorizationList, keyDescription.SoftwareEnforced);
        Assert.AreEqual(AndroidKeyAttestationTestVectors.ConformantAuthorizationList, keyDescription.TeeEnforced);
    }


    /// <summary>A key description truncated mid-<c>KeyDescription</c>-SEQUENCE is rejected.</summary>
    [TestMethod]
    public void ReadRejectsAKeyDescriptionTruncatedMidSequence()
    {
        byte[] valid = AndroidKeyAttestationTestVectors.EncodeKeyDescriptionExtensionValue(
            [1, 2, 3, 4], AndroidKeyAttestationTestVectors.EmptyAuthorizationList, AndroidKeyAttestationTestVectors.ConformantAuthorizationList);
        byte[] truncated = valid[..^4];

        Assert.ThrowsExactly<Fido2FormatException>(() => AndroidKeyDescription.Read(truncated));
    }


    /// <summary>A key description whose length byte overruns the actual buffer is rejected.</summary>
    [TestMethod]
    public void ReadRejectsAKeyDescriptionWithAnOverrunLengthByte()
    {
        byte[] valid = AndroidKeyAttestationTestVectors.EncodeKeyDescriptionExtensionValue(
            [1, 2, 3, 4], AndroidKeyAttestationTestVectors.EmptyAuthorizationList, AndroidKeyAttestationTestVectors.ConformantAuthorizationList);
        byte[] corrupted = [.. valid];

        //The top-level SEQUENCE's own length byte (index 1, short-form since the content is < 128
        //bytes) is inflated far beyond the buffer's actual remaining length.
        corrupted[1] = 0x7E;

        Assert.ThrowsExactly<Fido2FormatException>(() => AndroidKeyDescription.Read(corrupted));
    }


    /// <summary>
    /// A key description whose <c>teeEnforced</c> authorization list wraps a SEQUENCE where the
    /// <c>purpose</c> field's explicit <c>[1]</c> tag is expected to contain a SET — the tag is
    /// present, but its content is a SEQUENCE instead — is rejected, not silently misparsed.
    /// </summary>
    [TestMethod]
    public void ReadRejectsAPurposeFieldWrappingASequenceInsteadOfASet()
    {
        //Hand-assemble a KeyDescription whose teeEnforced list's [1] purpose field wraps a
        //SEQUENCE { INTEGER 2 } (30 03 02 01 02) rather than the required SET.
        byte[] malformedTeeEnforced =
        [
            0x30, 0x07,             //teeEnforced SEQUENCE, len 7
            0xA1, 0x05,             //[1] EXPLICIT, len 5
            0x30, 0x03,             //SEQUENCE (wrong; SET expected), len 3
            0x02, 0x01, 0x02        //INTEGER 2
        ];

        byte[] keyDescriptionBytes = AssembleKeyDescription([1, 2, 3, 4], EncodeEmptySequence(), malformedTeeEnforced);

        Assert.ThrowsExactly<Fido2FormatException>(() => AndroidKeyDescription.Read(keyDescriptionBytes));
    }


    /// <summary>
    /// A key description whose top-level <c>KeyDescription</c> SEQUENCE carries a ninth field beyond
    /// the expected eight positional fields is rejected.
    /// </summary>
    [TestMethod]
    public void ReadRejectsAKeyDescriptionWithATrailingNinthField()
    {
        byte[] valid = AndroidKeyAttestationTestVectors.EncodeKeyDescriptionExtensionValue(
            [1, 2, 3, 4], AndroidKeyAttestationTestVectors.EmptyAuthorizationList, AndroidKeyAttestationTestVectors.ConformantAuthorizationList);

        //Re-wrap the same eight fields' content plus one extra trailing INTEGER inside a SEQUENCE
        //whose own length byte accounts for it, so the malformation is "one field too many", not a
        //length mismatch.
        byte[] innerContent = valid[2..];
        byte[] extraField = [0x02, 0x01, 0x07];
        byte[] newContent = [.. innerContent, .. extraField];
        byte[] withNinthField = [0x30, checked((byte)newContent.Length), .. newContent];

        Assert.ThrowsExactly<Fido2FormatException>(() => AndroidKeyDescription.Read(withNinthField));
    }


    /// <summary>Encodes the DER bytes of an empty SEQUENCE — a placeholder empty authorization list.</summary>
    private static byte[] EncodeEmptySequence() => [0x30, 0x00];


    /// <summary>
    /// Assembles a full <c>KeyDescription</c> SEQUENCE from a caller-supplied <c>attestationChallenge</c>
    /// and pre-encoded <c>softwareEnforced</c>/<c>teeEnforced</c> SEQUENCE bytes, for negative fixtures
    /// that need control over an authorization list's raw bytes beyond what
    /// <see cref="AndroidKeyAttestationTestVectors.EncodeKeyDescriptionExtensionValue"/> exposes.
    /// </summary>
    private static byte[] AssembleKeyDescription(byte[] attestationChallenge, byte[] softwareEnforcedBytes, byte[] teeEnforcedBytes)
    {
        byte[] challengeField = [0x04, checked((byte)attestationChallenge.Length), .. attestationChallenge];
        byte[] content =
        [
            0x02, 0x02, 0x01, 0x2C,     //attestationVersion
            0x0A, 0x01, 0x00,           //attestationSecurityLevel
            0x02, 0x01, 0x00,           //keymasterVersion
            0x0A, 0x01, 0x00,           //keymasterSecurityLevel
            .. challengeField,          //attestationChallenge
            0x04, 0x00,                 //uniqueId
            .. softwareEnforcedBytes,
            .. teeEnforcedBytes
        ];

        return [0x30, checked((byte)content.Length), .. content];
    }
}
