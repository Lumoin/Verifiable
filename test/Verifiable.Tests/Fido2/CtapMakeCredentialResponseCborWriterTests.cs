using System;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Byte-exactness tests for <see cref="CtapMakeCredentialResponseCborWriter"/>, the authenticator-side
/// <c>authenticatorMakeCredential</c> response encoder.
/// </summary>
[TestClass]
internal sealed class CtapMakeCredentialResponseCborWriterTests
{
    /// <summary>A fixed 4-byte authData pattern, distinguishable byte-by-byte in a failure diff.</summary>
    private static byte[] AuthDataBytes => [0xAA, 0xBB, 0xCC, 0xDD];


    /// <summary>
    /// A response with only the two Required members (<c>fmt</c>, <c>authData</c>) encodes to a
    /// 2-entry map in ascending key order, with no <c>attStmt</c> member at all.
    /// </summary>
    [TestMethod]
    public void WriteEncodesRequiredMembersOnlyToExactCanonicalBytes()
    {
        var response = new CtapMakeCredentialResponse(WellKnownWebAuthnAttestationFormats.None, AuthDataBytes);

        TaggedMemory<byte> result = CtapMakeCredentialResponseCborWriter.Write(response);

        //map(2): fmt(1)="none", authData(2)=bytes(4).
        byte[] expected = Convert.FromHexString("A2" + "0164" + "6E6F6E65" + "0244" + "AABBCCDD");

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// A response carrying an <c>attStmt</c> (here the canonical empty <c>none</c>-format map) writes
    /// it, spliced in verbatim, after the two Required members.
    /// </summary>
    [TestMethod]
    public void WriteSplicesAttStmtVerbatimAfterRequiredMembers()
    {
        var response = new CtapMakeCredentialResponse(
            WellKnownWebAuthnAttestationFormats.None, AuthDataBytes, new byte[] { NoneAttestation.CanonicalEmptyMap });

        TaggedMemory<byte> result = CtapMakeCredentialResponseCborWriter.Write(response);

        //map(3): fmt(1)="none", authData(2)=bytes(4), attStmt(3)=the canonical empty map, spliced verbatim.
        byte[] expected = Convert.FromHexString("A3" + "0164" + "6E6F6E65" + "0244" + "AABBCCDD" + "03" + "A0");

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// A response carrying <c>largeBlobKey</c> (<c>0x05</c>, wavelb R8) writes it, as a byte string,
    /// after the two Required members — with both <c>attStmt</c> and <c>epAtt</c> absent (the response's
    /// <c>EpAtt</c> member is <see langword="null"/>), neither key appears at all.
    /// </summary>
    [TestMethod]
    public void WriteOrdersLargeBlobKeyAfterRequiredMembersWhenAttStmtIsAbsent()
    {
        byte[] largeBlobKeyBytes = [0x01, 0x02, 0x03, 0x04];
        var response = new CtapMakeCredentialResponse(WellKnownWebAuthnAttestationFormats.None, AuthDataBytes, AttStmt: null, LargeBlobKey: largeBlobKeyBytes);

        TaggedMemory<byte> result = CtapMakeCredentialResponseCborWriter.Write(response);

        //map(3): fmt(1)="none", authData(2)=bytes(4), largeBlobKey(5)=bytes(4).
        byte[] expected = Convert.FromHexString("A3" + "0164" + "6E6F6E65" + "0244" + "AABBCCDD" + "0544" + "01020304");

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// A response carrying <c>epAtt: true</c> alone (no <c>attStmt</c>, no <c>largeBlobKey</c>) writes it
    /// as CBOR simple-value <c>true</c> (<c>0xF5</c>) right after the two Required members — the
    /// memberCount ternary's own new term (trap 3) proven by the resulting 3-entry map.
    /// </summary>
    [TestMethod]
    public void WriteEncodesEpAttTrueAfterRequiredMembersWhenAloneToExactCanonicalBytes()
    {
        var response = new CtapMakeCredentialResponse(WellKnownWebAuthnAttestationFormats.None, AuthDataBytes, EpAtt: true);

        TaggedMemory<byte> result = CtapMakeCredentialResponseCborWriter.Write(response);

        //map(3): fmt(1)="none", authData(2)=bytes(4), epAtt(4)=true.
        byte[] expected = Convert.FromHexString("A3" + "0164" + "6E6F6E65" + "0244" + "AABBCCDD" + "04F5");

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// An EXPLICIT <c>epAtt: false</c> is emitted as CBOR simple-value <c>false</c> (<c>0xF4</c>), never
    /// omitted — the writer's own codec-faithfulness half of trap 18 (a foreign present-false round-trips
    /// unchanged; only the authenticator's own response-build site chooses absence over false).
    /// </summary>
    [TestMethod]
    public void WriteEmitsExplicitFalseForEpAttWhenGivenExplicitFalse()
    {
        var response = new CtapMakeCredentialResponse(WellKnownWebAuthnAttestationFormats.None, AuthDataBytes, EpAtt: false);

        TaggedMemory<byte> result = CtapMakeCredentialResponseCborWriter.Write(response);

        //map(3): fmt(1)="none", authData(2)=bytes(4), epAtt(4)=false.
        byte[] expected = Convert.FromHexString("A3" + "0164" + "6E6F6E65" + "0244" + "AABBCCDD" + "04F4");

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// A response carrying <c>attStmt</c>, <c>epAtt</c>, AND <c>largeBlobKey</c> together writes
    /// <c>epAtt</c> (<c>0x04</c>) BETWEEN the <c>attStmt</c> (<c>0x03</c>) and <c>largeBlobKey</c>
    /// (<c>0x05</c>) blocks — never appended after <c>largeBlobKey</c> (trap 2/5's own byte-exact proof):
    /// an enterprise-attested resident credential with a <c>largeBlobKey</c> also requested is a
    /// genuinely reachable combination whose wire key order must stay <c>1, 2, 3, 4, 5</c>.
    /// </summary>
    [TestMethod]
    public void WriteOrdersEpAttBetweenAttStmtAndLargeBlobKeyWhenAllThreePresentToExactCanonicalBytes()
    {
        byte[] largeBlobKeyBytes = [0x01, 0x02, 0x03, 0x04];
        var response = new CtapMakeCredentialResponse(
            WellKnownWebAuthnAttestationFormats.None, AuthDataBytes, new byte[] { NoneAttestation.CanonicalEmptyMap }, EpAtt: true, LargeBlobKey: largeBlobKeyBytes);

        TaggedMemory<byte> result = CtapMakeCredentialResponseCborWriter.Write(response);

        //map(5): fmt(1)="none", authData(2)=bytes(4), attStmt(3)=the canonical empty map, epAtt(4)=true, largeBlobKey(5)=bytes(4).
        byte[] expected = Convert.FromHexString("A5" + "0164" + "6E6F6E65" + "0244" + "AABBCCDD" + "03A0" + "04F5" + "0544" + "01020304");

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>A <see langword="null"/> response is rejected before any encoding is attempted.</summary>
    [TestMethod]
    public void ThrowsArgumentNullExceptionForNullResponse()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => CtapMakeCredentialResponseCborWriter.Write(null!));
    }


    /// <summary>A response whose <c>fmt</c> member is <see langword="null"/> is rejected.</summary>
    [TestMethod]
    public void ThrowsArgumentNullExceptionForNullFmt()
    {
        var response = new CtapMakeCredentialResponse(null!, AuthDataBytes);

        Assert.ThrowsExactly<ArgumentNullException>(() => CtapMakeCredentialResponseCborWriter.Write(response));
    }
}
