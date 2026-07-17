using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Unit tests for <see cref="AttestationObjectCborWriter"/>: the production counterpart to
/// <see cref="AttestationObjectCborReader"/>, spanning a hand-computed byte-exact vector, a round trip
/// through the shipped reader, composition with <see cref="NoneAttestation.CanonicalEmptyMap"/>, and the
/// empty-member rejections.
/// </summary>
[TestClass]
internal sealed class AttestationObjectCborWriterTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// <c>fmt="none"</c>, a one-byte <c>attStmt</c>, and a four-byte <c>authData</c> match a fully
    /// hand-computed CTAP2 canonical CBOR byte sequence: a 3-entry text-keyed map in ascending
    /// canonical key order (<c>fmt</c> length 3, <c>attStmt</c> length 7, <c>authData</c> length 8),
    /// which coincides with construction order here.
    /// </summary>
    [TestMethod]
    public void WritesAttestationObjectToHandComputedBytes()
    {
        byte[] attStmt = [0xA0];
        byte[] authData = [0xDE, 0xAD, 0xBE, 0xEF];

        byte[] expected = Convert.FromHexString("A363666D74646E6F6E656761747453746D74A068617574684461746144DEADBEEF");

        TaggedMemory<byte> written = AttestationObjectCborWriter.Write(WellKnownWebAuthnAttestationFormats.None, attStmt, authData);

        Assert.IsTrue(written.Span.SequenceEqual(expected));
        Assert.IsTrue(written.Tag.TryGet(out BufferKind kind));
        Assert.AreEqual(Fido2BufferTags.AttestationObjectKind, kind);
    }


    /// <summary>An arbitrary <c>fmt</c>/<c>attStmt</c>/<c>authData</c> triple round-trips through the shipped <see cref="AttestationObjectCborReader"/>.</summary>
    [TestMethod]
    public void RoundTripsThroughTheShippedReader()
    {
        byte[] attStmt = [0xA1, 0x63, 0x73, 0x69, 0x67, 0x41, 0x00]; //A one-entry map {"sig": h'00'}.
        byte[] authData = [0x01, 0x02, 0x03, 0x04, 0x05];

        TaggedMemory<byte> written = AttestationObjectCborWriter.Write(WellKnownWebAuthnAttestationFormats.Packed, attStmt, authData);

        AttestationObjectParts parts = AttestationObjectCborReader.Parse(written.Memory);

        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.Packed, parts.Format);
        Assert.IsTrue(parts.AttestationStatement.Span.SequenceEqual(attStmt));
        Assert.IsTrue(parts.AuthenticatorData.Span.SequenceEqual(authData));
    }


    /// <summary>
    /// The <c>none</c> attestation statement's canonical empty map
    /// (<see cref="NoneAttestation.CanonicalEmptyMap"/>) splices in and reads back unchanged — proving
    /// the writer composes with the exposed constant without duplicating its literal.
    /// </summary>
    [TestMethod]
    public void ComposesWithNoneAttestationCanonicalEmptyMap()
    {
        byte[] authData = [0xAA, 0xBB, 0xCC];

        TaggedMemory<byte> written = AttestationObjectCborWriter.Write(WellKnownWebAuthnAttestationFormats.None, new byte[] { NoneAttestation.CanonicalEmptyMap }, authData);

        AttestationObjectParts parts = AttestationObjectCborReader.Parse(written.Memory);

        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.None, parts.Format);
        Assert.AreEqual(1, parts.AttestationStatement.Length);
        Assert.AreEqual(NoneAttestation.CanonicalEmptyMap, parts.AttestationStatement.Span[0]);
    }


    /// <summary>An empty <c>attestationStatement</c> is rejected.</summary>
    [TestMethod]
    public void EmptyAttestationStatementThrowsArgumentException()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => AttestationObjectCborWriter.Write(WellKnownWebAuthnAttestationFormats.None, ReadOnlyMemory<byte>.Empty, new byte[] { 0x01 }));
    }


    /// <summary>An empty <c>authenticatorData</c> is rejected.</summary>
    [TestMethod]
    public void EmptyAuthenticatorDataThrowsArgumentException()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => AttestationObjectCborWriter.Write(WellKnownWebAuthnAttestationFormats.None, new byte[] { NoneAttestation.CanonicalEmptyMap }, ReadOnlyMemory<byte>.Empty));
    }


    /// <summary>A <see langword="null"/> <c>format</c> is rejected with <see cref="ArgumentNullException"/>.</summary>
    [TestMethod]
    public void NullFormatThrowsArgumentNullException()
    {
        Assert.ThrowsExactly<ArgumentNullException>(
            () => AttestationObjectCborWriter.Write(null!, new byte[] { NoneAttestation.CanonicalEmptyMap }, new byte[] { 0x01 }));
    }
}
