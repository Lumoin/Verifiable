using System;
using System.Buffers;
using Lumoin.Veritas.Cbor;
using Verifiable.Cbor;
using Verifiable.Cryptography.Pki;
using Verifiable.Foundation;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Tests for the Annex E (normative) alternative-mechanism disclosure convention —
/// <see cref="CBAdESAlternativeMechanismDisclosure"/> (the three-shall-item, four-member model) and
/// <see cref="CBAdESAlternativeMechanismDisclosureRegistry"/> (the registration convention wiring a
/// disclosure to the <c>uHeaders</c> catch-all extension point), per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, Annex E.
/// </summary>
/// <remarks>
/// <para>
/// <strong>No new wire codec.</strong> The extension-point wiring test round-trips a
/// <see cref="CBAdESUnsignedHeaderElementUnknown"/> element through the EXISTING
/// <see cref="CBAdESSerialization.EncodeUnsignedHeaders"/>/<see cref="CBAdESSerialization.TryParseUnsignedHeaders"/>
/// codec, unmodified, and separately proves a disclosure registered against that element's own
/// label is reachable — the registry adds no bytes to the wire.
/// </para>
/// <para>
/// <strong>Independent oracle.</strong> The wiring test's expected bytes are built with a freshly constructed
/// <see cref="CborWriter"/> in canonical mode, written directly against clause 5.3.1's CDDL, mirroring
/// <c>CBAdESUnsignedHeadersTests</c>'s own established oracle convention for this exact catch-all shape —
/// never a helper shared across files (this repository's stated convention for this scenario).
/// </para>
/// </remarks>
[TestClass]
internal sealed class CBAdESAlternativeMechanismDisclosureTests
{
    /// <summary>
    /// CB-E-01/02/03/04: constructing a disclosure with all four Annex E items present succeeds and every
    /// member is reachable exactly as supplied.
    /// </summary>
    [TestMethod]
    public void ConstructingAlternativeMechanismDisclosureWithAllFourItemsSucceeds()
    {
        var disclosure = new CBAdESAlternativeMechanismDisclosure(
            "urn:example:alt-ltaia-mechanism",
            "https://example.org/specs/alt-ltaia-mechanism",
            "Every protected object's digest is chained into a hash tree rooted in a token this mechanism itself issues.",
            "Instances of refs/valData/sigRTst/rfsTst/arcTst incorporated per clause 5.3.5 are left untouched and validated independently.");

        Assert.AreEqual("urn:example:alt-ltaia-mechanism", disclosure.UniqueIdentifier);
        Assert.AreEqual("https://example.org/specs/alt-ltaia-mechanism", disclosure.SemanticsAndSyntaxReference);
        Assert.AreEqual("Every protected object's digest is chained into a hash tree rooted in a token this mechanism itself issues.", disclosure.ProtectionStrategy);
        Assert.AreEqual("Instances of refs/valData/sigRTst/rfsTst/arcTst incorporated per clause 5.3.5 are left untouched and validated independently.", disclosure.CoexistenceStrategy);
    }


    /// <summary>
    /// CB-E-02 (item 1, identifier half): a missing unique identifier fails closed rather than representing a
    /// partial disclosure. <see cref="ArgumentException.ThrowIfNullOrWhiteSpace"/> raises the derived
    /// <see cref="ArgumentNullException"/> for a <see langword="null"/> value specifically.
    /// </summary>
    [TestMethod]
    public void ConstructingAlternativeMechanismDisclosureWithNullUniqueIdentifierThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => _ = new CBAdESAlternativeMechanismDisclosure(null!, "ref", "protection", "coexistence"));
    }


    /// <summary>CB-E-02 (item 1, identifier half): a whitespace-only unique identifier is treated as absent, not as a stated blank value.</summary>
    [TestMethod]
    public void ConstructingAlternativeMechanismDisclosureWithWhiteSpaceUniqueIdentifierThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => _ = new CBAdESAlternativeMechanismDisclosure("   ", "ref", "protection", "coexistence"));
    }


    /// <summary>CB-E-02 (item 1, semantics/syntax-reference half): a missing specification reference fails closed.</summary>
    [TestMethod]
    public void ConstructingAlternativeMechanismDisclosureWithNullSemanticsAndSyntaxReferenceThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => _ = new CBAdESAlternativeMechanismDisclosure("id", null!, "protection", "coexistence"));
    }


    /// <summary>CB-E-03 (item 2): a missing protection-strategy statement fails closed.</summary>
    [TestMethod]
    public void ConstructingAlternativeMechanismDisclosureWithNullProtectionStrategyThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => _ = new CBAdESAlternativeMechanismDisclosure("id", "ref", null!, "coexistence"));
    }


    /// <summary>CB-E-04 (item 3): a missing coexistence-strategy statement fails closed.</summary>
    [TestMethod]
    public void ConstructingAlternativeMechanismDisclosureWithNullCoexistenceStrategyThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => _ = new CBAdESAlternativeMechanismDisclosure("id", "ref", "protection", null!));
    }


    /// <summary><see cref="CBAdESAlternativeMechanismDisclosureRegistry.Register"/> rejects a <see langword="null"/> label.</summary>
    [TestMethod]
    public void RegisterThrowsOnNullLabel()
    {
        var registry = new CBAdESAlternativeMechanismDisclosureRegistry();
        var disclosure = MakeDisclosure();

        Assert.ThrowsExactly<ArgumentNullException>(() => registry.Register(null!, disclosure));
    }


    /// <summary><see cref="CBAdESAlternativeMechanismDisclosureRegistry.Register"/> rejects a <see langword="null"/> disclosure.</summary>
    [TestMethod]
    public void RegisterThrowsOnNullDisclosure()
    {
        var registry = new CBAdESAlternativeMechanismDisclosureRegistry();

        Assert.ThrowsExactly<ArgumentNullException>(() => registry.Register(new CBAdESUnsignedHeaderElementIntegerLabel(1), null!));
    }


    /// <summary>
    /// <see cref="CBAdESAlternativeMechanismDisclosureRegistry.Register"/> refuses
    /// every one of this document's own ten profiled <c>UHeaderInstance</c> labels (Table 8's seven plus the
    /// RFC 9338/RFC 9360 labels 11/12/33) — Annex E's registry exists only for the <c>*label =&gt; value</c>
    /// catch-all a mechanism THIS document does not itself define uses, never for a label the document already
    /// assigns a fixed meaning to.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-E-01.
    /// </remarks>
    /// <param name="profiledLabel">One of the ten profiled integer labels.</param>
    [TestMethod]
    [DataRow(CBAdESUnsignedHeaderElement.SignatureTimestampLabel)]
    [DataRow(CBAdESUnsignedHeaderElement.ValidationDataLabel)]
    [DataRow(CBAdESUnsignedHeaderElement.ArchiveTimestampLabel)]
    [DataRow(CBAdESUnsignedHeaderElement.ReferencesLabel)]
    [DataRow(CBAdESUnsignedHeaderElement.SignatureAndReferencesTimestampLabel)]
    [DataRow(CBAdESUnsignedHeaderElement.ReferencesTimestampLabel)]
    [DataRow(CBAdESUnsignedHeaderElement.SignaturePolicyStoreLabel)]
    [DataRow(CBAdESUnsignedHeaderElement.FullCounterSignatureLabel)]
    [DataRow(CBAdESUnsignedHeaderElement.AbbreviatedCounterSignatureLabel)]
    [DataRow(CBAdESUnsignedHeaderElement.CertificateChainLabel)]
    public void RegisterThrowsOnProfiledLabel(int profiledLabel)
    {
        var registry = new CBAdESAlternativeMechanismDisclosureRegistry();
        var disclosure = MakeDisclosure();

        Assert.ThrowsExactly<ArgumentException>(() => registry.Register(new CBAdESUnsignedHeaderElementIntegerLabel(profiledLabel), disclosure));
    }


    /// <summary>Registering a second disclosure under an already-registered label throws rather than silently replacing the first.</summary>
    [TestMethod]
    public void RegisteringDuplicateLabelThrows()
    {
        var registry = new CBAdESAlternativeMechanismDisclosureRegistry();
        var label = new CBAdESUnsignedHeaderElementIntegerLabel(90210);
        registry.Register(label, MakeDisclosure());

        Assert.ThrowsExactly<ArgumentException>(() => registry.Register(new CBAdESUnsignedHeaderElementIntegerLabel(90210), MakeDisclosure()));
    }


    /// <summary><see cref="CBAdESAlternativeMechanismDisclosureRegistry.TryGetDisclosure"/> reports no match for a label nothing was registered under.</summary>
    [TestMethod]
    public void TryGetDisclosureReturnsFalseWhenNoneRegistered()
    {
        var registry = new CBAdESAlternativeMechanismDisclosureRegistry();

        bool found = registry.TryGetDisclosure(new CBAdESUnsignedHeaderElementIntegerLabel(999), out CBAdESAlternativeMechanismDisclosure? disclosure);

        Assert.IsFalse(found);
        Assert.IsNull(disclosure);
    }


    /// <summary>
    /// CB-E-01: the extension-point wiring. A <see cref="CBAdESUnsignedHeaderElementUnknown"/> catch-all
    /// element (CB-5.3.1-11) carrying an alternative mechanism's bytes round-trips byte-exactly through the
    /// EXISTING <see cref="CBAdESSerialization"/> codec, unmodified by registering a disclosure against it —
    /// and that disclosure is reachable, by value, from the label the round-tripped (freshly parsed) element
    /// itself carries, not merely from the object the producer originally built.
    /// </summary>
    [TestMethod]
    public void RegisteredDisclosureIsReachableAfterUnknownLabelElementRoundTripsByteExactly()
    {
        const int label = 90210;
        const int value = 424242;
        byte[] expected = BuildSingleElementUnsignedHeadersBytes(EncodeUnknownIntElement(label, value));

        CBAdESAlternativeMechanismDisclosure disclosure = MakeDisclosure();
        var registry = new CBAdESAlternativeMechanismDisclosureRegistry();
        registry.Register(new CBAdESUnsignedHeaderElementIntegerLabel(label), disclosure);

        bool parsed = CBAdESSerialization.TryParseUnsignedHeaders(expected, BaseMemoryPool.Shared, out CBAdESUnsignedHeaders? result);

        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        using(result)
        {
            CBAdESUnsignedHeaders header = result!;
            Assert.HasCount(1, header);
            Assert.IsTrue(header[0] is CBAdESUnsignedHeaderElementUnknown, "The catch-all arm must round-trip the unrecognized label, not drop it.");

            var unknown = (CBAdESUnsignedHeaderElementUnknown)header[0];
            Assert.AreEqual(new CBAdESUnsignedHeaderElementIntegerLabel(label), unknown.Label);
            Assert.IsTrue(EncodeIntValue(value).AsSpan().SequenceEqual(unknown.Value.Span), "The mechanism's own opaque bytes must round-trip byte-exactly.");

            using PooledMemory reencoded = CBAdESSerialization.EncodeUnsignedHeaders(header, BaseMemoryPool.Shared);
            Assert.IsTrue(expected.AsSpan().SequenceEqual(reencoded.AsReadOnlySpan()), "Registering a disclosure must never perturb the wire bytes -- Annex E governs specification, not a wire format.");

            bool reached = registry.TryGetDisclosure(unknown.Label, out CBAdESAlternativeMechanismDisclosure? reachedDisclosure);
            Assert.IsTrue(reached, "A disclosure registered under a label must be reachable from an element parsed off the wire carrying the SAME label, by value.");
            Assert.AreSame(disclosure, reachedDisclosure);
        }
    }


    /// <summary>Builds a fully-populated disclosure fixture for the registry tests, which do not exercise the four items' own content.</summary>
    /// <returns>The built disclosure.</returns>
    private static CBAdESAlternativeMechanismDisclosure MakeDisclosure()
    {
        return new CBAdESAlternativeMechanismDisclosure("id", "ref", "protection", "coexistence");
    }


    /// <summary>Encodes a one-element <c>uHeaders</c> CBOR array wrapping <paramref name="elementContentBytes"/> in a <c>bstr</c> (clause 5.3.1 CDDL).</summary>
    /// <param name="elementContentBytes">The already-encoded <c>UHeaderInstance</c> one-entry map bytes.</param>
    /// <returns>The encoded <c>uHeaders</c> array bytes.</returns>
    private static byte[] BuildSingleElementUnsignedHeadersBytes(byte[] elementContentBytes)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartArray(1);
        writer.WriteByteString(elementContentBytes);
        writer.WriteEndArray();

        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>Encodes the unrecognized-integer-label-shaped <c>UHeaderInstance</c> one-entry map: <c>{ label =&gt; value }</c>, the CDDL's <c>*label =&gt; value</c> catch-all's <c>int</c> arm (clause 5.3.1).</summary>
    /// <param name="label">The unrecognized integer label.</param>
    /// <param name="value">The opaque integer value.</param>
    /// <returns>The encoded one-entry map bytes.</returns>
    private static byte[] EncodeUnknownIntElement(int label, int value)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(label);
        writer.WriteInt32(value);
        writer.WriteEndMap();

        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>Encodes a bare canonical CBOR integer value, with no enclosing map -- an unrecognized-integer-label element's opaque VALUE bytes.</summary>
    /// <param name="value">The integer value.</param>
    /// <returns>The encoded value-only bytes.</returns>
    private static byte[] EncodeIntValue(int value)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteInt32(value);

        return writerBuffer.WrittenSpan.ToArray();
    }
}
