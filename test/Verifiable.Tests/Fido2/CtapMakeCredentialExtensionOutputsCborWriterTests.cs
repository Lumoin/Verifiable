using System;
using System.Collections.Generic;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Byte-exactness tests for <see cref="CtapMakeCredentialExtensionOutputsCborWriter"/>: the four-slot
/// canonical order (contract R12, trap 1 — <c>hmac-secret-mc</c> sorts LAST despite its name prefix, since
/// CTAP2 canonical CBOR sorts shorter keys first), the two-legacy-slot byte-fence (trap 17), the
/// <c>hmac-secret</c> codec-faithfulness split (a foreign <see langword="false"/> round-trips through the
/// writer and the generic <see cref="AuthenticatorExtensionOutputsCborReader"/> even though this
/// authenticator's own call site never supplies one), and the empty-input-produces-absent-output rule.
/// </summary>
[TestClass]
internal sealed class CtapMakeCredentialExtensionOutputsCborWriterTests
{
    /// <summary>ASCII bytes of the <c>credProtect</c> extension identifier (11 characters).</summary>
    private static byte[] CredProtectAscii => "credProtect"u8.ToArray();

    /// <summary>ASCII bytes of the <c>hmac-secret</c> extension identifier (11 characters).</summary>
    private static byte[] HmacSecretAscii => "hmac-secret"u8.ToArray();

    /// <summary>ASCII bytes of the <c>minPinLength</c> extension identifier (12 characters).</summary>
    private static byte[] MinPinLengthAscii => "minPinLength"u8.ToArray();

    /// <summary>ASCII bytes of the <c>hmac-secret-mc</c> extension identifier (14 characters).</summary>
    private static byte[] HmacSecretMcAscii => "hmac-secret-mc"u8.ToArray();

    /// <summary>A fixed 4-byte pattern standing in for an encrypted <c>hmac-secret-mc</c> output, distinguishable in a failure diff.</summary>
    private static byte[] FixedHmacSecretMcOutput => [0xAA, 0xBB, 0xCC, 0xDD];


    /// <summary>
    /// A <c>credProtect</c> value alone encodes to a 1-entry map: <c>{"credProtect": &lt;value&gt;}</c>.
    /// </summary>
    [TestMethod]
    public void WriteEncodesCredProtectOnlyToExactCanonicalBytes()
    {
        TaggedMemory<byte> result = CtapMakeCredentialExtensionOutputsCborWriter.Write(credProtect: 1, hmacSecret: null, minPinLength: null, hmacSecretMc: null);

        byte[] expected =
        [
            0xA1, //map(1)
            0x6B, .. CredProtectAscii, //text(11) "credProtect"
            0x01 //unsigned(1)
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// A <c>minPinLength</c> value alone encodes to a 1-entry map: <c>{"minPinLength": &lt;value&gt;}</c>.
    /// </summary>
    [TestMethod]
    public void WriteEncodesMinPinLengthOnlyToExactCanonicalBytes()
    {
        TaggedMemory<byte> result = CtapMakeCredentialExtensionOutputsCborWriter.Write(credProtect: null, hmacSecret: null, minPinLength: 4, hmacSecretMc: null);

        byte[] expected =
        [
            0xA1, //map(1)
            0x6C, .. MinPinLengthAscii, //text(12) "minPinLength"
            0x04 //unsigned(4)
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// The two-slot shape (contract R12's byte-fence, trap 17): with only
    /// <c>credProtect</c>/<c>minPinLength</c> non-null, <c>hmacSecret</c> and <c>hmacSecretMc</c> both
    /// contribute no map entry, so the emitted bytes carry only the two legacy slots —
    /// <c>credProtect</c> (11-character key) sorted before <c>minPinLength</c> (12-character key), per
    /// the CTAP2 canonical shorter-key-first rule.
    /// </summary>
    [TestMethod]
    public void WriteEncodesTwoNonNullSlotsToExactCanonicalBytes()
    {
        TaggedMemory<byte> result = CtapMakeCredentialExtensionOutputsCborWriter.Write(credProtect: 2, hmacSecret: null, minPinLength: 6, hmacSecretMc: null);

        byte[] expected =
        [
            0xA2, //map(2)
            0x6B, .. CredProtectAscii, 0x02, //"credProtect" -> 2
            0x6C, .. MinPinLengthAscii, 0x06 //"minPinLength" -> 6
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// An <c>hmac-secret</c> value alone encodes to a 1-entry map: <c>{"hmac-secret": &lt;value&gt;}</c>
    /// (CTAP 2.3 §12.7, snapshot lines 13198-13201).
    /// </summary>
    [TestMethod]
    public void WriteEncodesHmacSecretOnlyToExactCanonicalBytes()
    {
        TaggedMemory<byte> result = CtapMakeCredentialExtensionOutputsCborWriter.Write(credProtect: null, hmacSecret: true, minPinLength: null, hmacSecretMc: null);

        byte[] expected =
        [
            0xA1, //map(1)
            0x6B, .. HmacSecretAscii, //text(11) "hmac-secret"
            0xF5 //true
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// An <c>hmac-secret-mc</c> value alone encodes to a 1-entry map:
    /// <c>{"hmac-secret-mc": &lt;bytes&gt;}</c> (CTAP 2.3 §12.8, snapshot line 13408).
    /// </summary>
    [TestMethod]
    public void WriteEncodesHmacSecretMcOnlyToExactCanonicalBytes()
    {
        TaggedMemory<byte> result = CtapMakeCredentialExtensionOutputsCborWriter.Write(
            credProtect: null, hmacSecret: null, minPinLength: null, hmacSecretMc: FixedHmacSecretMcOutput);

        byte[] expected =
        [
            0xA1, //map(1)
            0x6E, .. HmacSecretMcAscii, //text(14) "hmac-secret-mc"
            0x44, .. FixedHmacSecretMcOutput //bytes(4)
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// All four slots together (contract R12, trap 1): the canonical key order is
    /// <c>credProtect</c> (11) &lt; <c>hmac-secret</c> (11, tie broken by <c>'c'</c> 0x63 &lt;
    /// <c>'h'</c> 0x68) &lt; <c>minPinLength</c> (12) &lt; <c>hmac-secret-mc</c> (14) — LAST, despite
    /// sharing <c>hmac-secret</c>'s name prefix, purely because CTAP2 canonical CBOR sorts shorter keys
    /// first.
    /// </summary>
    [TestMethod]
    public void WriteEncodesAllFourSlotsInCanonicalKeyOrder()
    {
        TaggedMemory<byte> result = CtapMakeCredentialExtensionOutputsCborWriter.Write(
            credProtect: 3, hmacSecret: true, minPinLength: 5, hmacSecretMc: FixedHmacSecretMcOutput);

        byte[] expected =
        [
            0xA4, //map(4)
            0x6B, .. CredProtectAscii, 0x03, //"credProtect" -> 3
            0x6B, .. HmacSecretAscii, 0xF5, //"hmac-secret" -> true
            0x6C, .. MinPinLengthAscii, 0x05, //"minPinLength" -> 5
            0x6E, .. HmacSecretMcAscii, 0x44, .. FixedHmacSecretMcOutput //"hmac-secret-mc" -> bytes(4), sorts LAST
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// The writer is a faithful codec (contract R2b, waveep <c>epAtt</c> R9 precedent): given a literal
    /// <see langword="false"/> — a value this authenticator's own call site never supplies, since
    /// CredRandom generation never fails — it emits <c>"hmac-secret": false</c>, and the generic
    /// <see cref="AuthenticatorExtensionOutputsCborReader"/> round-trips that foreign value's raw encoded
    /// bytes (<c>0xF4</c>) without throwing or coercing it away.
    /// </summary>
    [TestMethod]
    public void WriteAndReadRoundTripAForeignHmacSecretFalseFaithfully()
    {
        TaggedMemory<byte> result = CtapMakeCredentialExtensionOutputsCborWriter.Write(credProtect: null, hmacSecret: false, minPinLength: null, hmacSecretMc: null);

        byte[] expected =
        [
            0xA1, //map(1)
            0x6B, .. HmacSecretAscii, //text(11) "hmac-secret"
            0xF4 //false
        ];

        Assert.IsTrue(result.Span.SequenceEqual(expected));

        IReadOnlyList<Fido2ExtensionOutput> outputs = AuthenticatorExtensionOutputsCborReader.Read(result.Memory);
        Fido2ExtensionOutput output = Assert.ContainsSingle(outputs);
        Assert.AreEqual(WellKnownWebAuthnExtensionIdentifiers.HmacSecret, output.Identifier);
        Assert.IsTrue(output.Value.Span.SequenceEqual(new byte[] { 0xF4 }));
    }


    /// <summary>
    /// No parameter present produces <see cref="TaggedMemory{T}.Empty"/> — never an encoded empty CBOR
    /// map (<c>0xA0</c>) — so a caller can distinguish "no extensions output" from "an empty map".
    /// </summary>
    [TestMethod]
    public void WriteReturnsEmptyWhenNoParameterIsPresent()
    {
        TaggedMemory<byte> result = CtapMakeCredentialExtensionOutputsCborWriter.Write(credProtect: null, hmacSecret: null, minPinLength: null, hmacSecretMc: null);

        Assert.IsTrue(result.IsEmpty);
    }
}
