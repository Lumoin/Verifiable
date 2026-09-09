using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Veritas.Cbor;
using Verifiable.Cbor;
using Verifiable.Cbor.Mdoc;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Mdoc;

/// <summary>
/// Pins the two halves of the relay contract <see cref="MdocCborDeviceResponseWriter"/> exists to satisfy:
/// foreign bytes the issuer signed pass through the writer unaltered, while every map the writer builds
/// itself is emitted in RFC 8949 §4.2.1 order.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5 §9.1.2.4</see> makes each
/// <c>IssuerSignedItemBytes</c> a Tag-24 wrapper the issuer's Mobile Security Object commits to by digest,
/// and §9.1.2.5 makes those digests the verifier's binding check. Re-encoding such an item — even into a
/// strictly more canonical form — changes the bytes the digest was taken over and breaks the binding, so
/// the relay must be byte-exact. The same holds for the <c>IssuerAuth</c> COSE_Sign1 of §9.1.2.4, whose
/// signature covers its own serialization.
/// </para>
/// <para>
/// That is why <see cref="MdocCborDeviceResponseWriter"/> runs
/// <see cref="CborConformanceMode.Lax"/>: a deterministic-mode writer applies the mode's rules to spliced
/// bytes and would refuse a well-formed but non-canonical foreign item rather than relay it. The
/// canonical-order property the outer envelope still needs is therefore obtained by construction — the
/// writer emits its own keys already sorted — and that is what the ordering tests below check, with the
/// byte-identity test closing the loop by showing the Lax relay changes nothing except the refusal.
/// This is S4 ruling S4-10.
/// </para>
/// </remarks>
[TestClass]
internal sealed class MdocDeviceResponseRelayTests
{
    /// <summary>The document type the fixtures issue into; the EUDI PID type, itself also its namespace.</summary>
    private const string DocType = "eu.europa.ec.eudi.pid.1";

    /// <summary>The ISO/IEC 18013-5 §7.1 mDL namespace, 17 UTF-8 octets.</summary>
    private const string IsoMdlNameSpace = "org.iso.18013.5.1";

    /// <summary>The AAMVA companion namespace, 23 UTF-8 octets.</summary>
    private const string AamvaNameSpace = "org.iso.18013.5.1.aamva";

    /// <summary>A short example namespace, 11 UTF-8 octets.</summary>
    private const string ShortNameSpace = "com.example";

    /// <summary>An mDL-length namespace ending in <c>1</c>, for the equal-length bytewise tiebreak.</summary>
    private const string EqualLengthLowNameSpace = "org.iso.18013.5.1";

    /// <summary>An mDL-length namespace ending in <c>2</c>, for the equal-length bytewise tiebreak.</summary>
    private const string EqualLengthHighNameSpace = "org.iso.18013.5.2";

    /// <summary>The COSE <c>kid</c> header label, 4, which encodes as the single initial byte <c>0x04</c>.</summary>
    private const int CoseKidLabel = 4;

    /// <summary>The COSE <c>x5chain</c> header label, 33, which encodes as the two bytes <c>0x18 0x21</c>.</summary>
    private const int CoseX5ChainLabel = 33;

    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A Tag-24 <c>IssuerSignedItemBytes</c> whose inner <c>IssuerSignedItem</c> map is well-formed but
    /// deliberately NOT in canonical key order relays into the encoded <c>DeviceResponse</c> byte for byte,
    /// and the writer does not refuse it. Per
    /// <see href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5 §9.1.2.4/§9.1.2.5</see> the MSO's
    /// <c>valueDigests</c> entry is the digest of exactly these octets, so any re-encoding — including
    /// re-sorting the inner map into <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC
    /// 8949 §4.2.1</see> order — would destroy the binding the verifier checks.
    /// </summary>
    [TestMethod]
    public void NonCanonicalIssuerSignedItemBytesRelayVerbatim()
    {
        using MeteredHousePool pool = new();
        using MdocIssuerSignedItem item = BuildIssuerSignedItem("family_name", digestId: 0, isCanonicalOrder: false, pool.Pool);
        using MdocIssuerAuth issuerAuth = BuildIssuerAuth(isCanonicalHeaderOrder: false, pool.Pool);
        using MdocDeviceResponse response = BuildDeviceResponse(NameSpacesOf((IsoMdlNameSpace, item)), issuerAuth, deviceSigned: null);

        ReadOnlyMemory<byte> encoded = MdocCborDeviceResponseWriter.EncodeDeviceResponse(response);
        ReadOnlyMemory<byte> relayed = ExtractFirstIssuerSignedItemBytes(encoded, IsoMdlNameSpace);

        Assert.IsTrue(
            relayed.Span.SequenceEqual(item.WireBytes.Span),
            "The non-canonical IssuerSignedItemBytes must reach the wire byte-identically; the MSO digest commits to exactly those octets.");
    }


    /// <summary>
    /// An <c>IssuerAuth</c> COSE_Sign1 whose unprotected header map carries two labels in non-canonical
    /// order — <c>x5chain</c> (33, encoded <c>0x18 0x21</c>) before <c>kid</c> (4, encoded <c>0x04</c>),
    /// the reverse of the length-first order
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see> prescribes —
    /// relays into the encoded <c>DeviceResponse</c> byte for byte. The issuer's signature covers this
    /// serialization (<see href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5 §9.1.2.4</see>),
    /// so a relaying writer must not normalize it.
    /// </summary>
    [TestMethod]
    public void NonCanonicalIssuerAuthUnprotectedHeaderRelaysVerbatim()
    {
        using MeteredHousePool pool = new();
        using MdocIssuerSignedItem item = BuildIssuerSignedItem("family_name", digestId: 0, isCanonicalOrder: false, pool.Pool);
        using MdocIssuerAuth issuerAuth = BuildIssuerAuth(isCanonicalHeaderOrder: false, pool.Pool);
        using MdocDeviceResponse response = BuildDeviceResponse(NameSpacesOf((IsoMdlNameSpace, item)), issuerAuth, deviceSigned: null);

        ReadOnlyMemory<byte> encoded = MdocCborDeviceResponseWriter.EncodeDeviceResponse(response);
        ReadOnlyMemory<byte> issuerSigned = ReadMapEntry(ReadArrayElement(ReadMapEntry(encoded, MdocWellKnownKeys.Documents), 0), MdocWellKnownKeys.IssuerSigned);
        ReadOnlyMemory<byte> relayed = ReadMapEntry(issuerSigned, MdocWellKnownKeys.IssuerAuth);

        Assert.IsTrue(
            relayed.Span.SequenceEqual(issuerAuth.EncodedCoseSign1.AsReadOnlySpan()),
            "The non-canonical IssuerAuth COSE_Sign1 must reach the wire byte-identically; the issuer's signature covers its serialization.");
    }


    /// <summary>
    /// The <c>IssuerSignedItem</c> map the relay tests hand to the writer really is one a deterministic
    /// mode refuses: reading it under <see cref="CborConformanceMode.RfcCanonical"/> raises
    /// <see cref="CborConformanceException"/> under
    /// <see cref="CborConformanceException.MapKeyOrderRule"/>, because
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see> requires
    /// <c>random</c> (6 octets) before <c>elementIdentifier</c> (17) and the fixture writes the reverse.
    /// This is what makes the relay assertion adversarial rather than vacuous — the bytes that survive are
    /// bytes a canonical writer could not have produced.
    /// </summary>
    [TestMethod]
    public void TheRelayedIssuerSignedItemIsOneADeterministicReaderRefuses()
    {
        using MeteredHousePool pool = new();
        using MdocIssuerSignedItem item = BuildIssuerSignedItem("family_name", digestId: 0, isCanonicalOrder: false, pool.Pool);

        ReadOnlyMemory<byte> innerMap = ReadTag24Content(item.WireBytes);

        CborConformanceException refusal = Assert.ThrowsExactly<CborConformanceException>(
            () => ReadFirstTwoTextKeysUnderRfcCanonical(innerMap));

        Assert.AreEqual(CborConformanceException.MapKeyOrderRule, refusal.RuleName);
    }


    /// <summary>
    /// The <c>IssuerAuth</c> COSE_Sign1 the relay tests hand to the writer really is one a deterministic
    /// mode refuses: reading its unprotected header map under
    /// <see cref="CborConformanceMode.RfcCanonical"/> raises <see cref="CborConformanceException"/> under
    /// <see cref="CborConformanceException.MapKeyOrderRule"/>, because
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see> requires the
    /// one-byte label 4 before the two-byte label 33 and the fixture writes the reverse. The relay of such
    /// bytes is therefore a real property of the writer, not an artefact of already-canonical input.
    /// </summary>
    [TestMethod]
    public void TheRelayedIssuerAuthIsOneADeterministicReaderRefuses()
    {
        byte[] coseSign1 = BuildCoseSign1Bytes(isCanonicalHeaderOrder: false);

        CborConformanceException refusal = Assert.ThrowsExactly<CborConformanceException>(
            () => ReadFirstTwoUnprotectedHeaderLabelsUnderRfcCanonical(coseSign1));

        Assert.AreEqual(CborConformanceException.MapKeyOrderRule, refusal.RuleName);
    }


    /// <summary>
    /// The <c>DeviceResponse</c> map the writer builds itself carries its keys in
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see> order:
    /// <c>status</c> (6 octets of text, 7 encoded), <c>version</c> (7, 8), <c>documents</c> (9, 10) — a
    /// strictly ascending run decided by encoded length alone. The wire shape is that of
    /// <see href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5 §8.3.2.1.2.2</see>.
    /// </summary>
    [TestMethod]
    public void DeviceResponseMapKeysAreInCanonicalOrder()
    {
        using MeteredHousePool pool = new();
        using MdocIssuerSignedItem item = BuildIssuerSignedItem("family_name", digestId: 0, isCanonicalOrder: false, pool.Pool);
        using MdocIssuerAuth issuerAuth = BuildIssuerAuth(isCanonicalHeaderOrder: false, pool.Pool);
        using MdocDeviceResponse response = BuildDeviceResponse(NameSpacesOf((IsoMdlNameSpace, item)), issuerAuth, deviceSigned: null);

        ReadOnlyMemory<byte> encoded = MdocCborDeviceResponseWriter.EncodeDeviceResponse(response);
        string[] keys = ReadTextMapKeys(encoded);

        string[] expected = [MdocWellKnownKeys.Status, MdocWellKnownKeys.Version, MdocWellKnownKeys.Documents];

        AssertKeySequence(expected, keys);
    }


    /// <summary>
    /// The <c>Document</c> map the writer builds itself carries its keys in
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see> order:
    /// <c>docType</c> (7 octets of text, 8 encoded) sorts first on length, then <c>deviceSigned</c> and
    /// <c>issuerSigned</c> are both 12 octets (13 encoded) so the bytewise criterion decides —
    /// <c>'d'</c> = 0x64 before <c>'i'</c> = 0x69. The wire shape is that of
    /// <see href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5 §8.3.2.1.2.2</see>.
    /// </summary>
    [TestMethod]
    public void DocumentMapKeysAreInCanonicalOrder()
    {
        using MeteredHousePool pool = new();
        using MdocIssuerSignedItem item = BuildIssuerSignedItem("family_name", digestId: 0, isCanonicalOrder: false, pool.Pool);
        using MdocIssuerAuth issuerAuth = BuildIssuerAuth(isCanonicalHeaderOrder: false, pool.Pool);
        using MdocDeviceSigned deviceSigned = BuildDeviceSigned(pool.Pool);
        using MdocDeviceResponse response = BuildDeviceResponse(NameSpacesOf((IsoMdlNameSpace, item)), issuerAuth, deviceSigned);

        ReadOnlyMemory<byte> encoded = MdocCborDeviceResponseWriter.EncodeDeviceResponse(response);
        ReadOnlyMemory<byte> document = ReadArrayElement(ReadMapEntry(encoded, MdocWellKnownKeys.Documents), 0);
        string[] keys = ReadTextMapKeys(document);

        string[] expected = [MdocWellKnownKeys.DocType, MdocWellKnownKeys.DeviceSigned, MdocWellKnownKeys.IssuerSigned];

        AssertKeySequence(expected, keys);
    }


    /// <summary>
    /// The <c>IssuerSigned</c> map the writer builds itself carries its keys in
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see> order: both
    /// <c>issuerAuth</c> and <c>nameSpaces</c> are 10 octets of text (11 encoded), so the bytewise
    /// criterion decides — <c>'i'</c> = 0x69 before <c>'n'</c> = 0x6E. The wire shape is that of
    /// <see href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5 §8.3.2.1.2.2</see>.
    /// </summary>
    [TestMethod]
    public void IssuerSignedMapKeysAreInCanonicalOrder()
    {
        using MeteredHousePool pool = new();
        using MdocIssuerSignedItem item = BuildIssuerSignedItem("family_name", digestId: 0, isCanonicalOrder: false, pool.Pool);
        using MdocIssuerAuth issuerAuth = BuildIssuerAuth(isCanonicalHeaderOrder: false, pool.Pool);
        using MdocDeviceResponse response = BuildDeviceResponse(NameSpacesOf((IsoMdlNameSpace, item)), issuerAuth, deviceSigned: null);

        ReadOnlyMemory<byte> encoded = MdocCborDeviceResponseWriter.EncodeDeviceResponse(response);
        ReadOnlyMemory<byte> issuerSigned = ReadMapEntry(ReadArrayElement(ReadMapEntry(encoded, MdocWellKnownKeys.Documents), 0), MdocWellKnownKeys.IssuerSigned);
        string[] keys = ReadTextMapKeys(issuerSigned);

        string[] expected = [MdocWellKnownKeys.IssuerAuth, MdocWellKnownKeys.NameSpaces];

        AssertKeySequence(expected, keys);
    }


    /// <summary>
    /// Three namespaces handed to the writer in reverse of their canonical order come out in
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see> length-first
    /// order: <c>com.example</c> (11 octets of text, 12 encoded), <c>org.iso.18013.5.1</c> (17, 18),
    /// <c>org.iso.18013.5.1.aamva</c> (23, 24). ISO/IEC 18013-5 §7.1 namespace identifiers are ASCII
    /// reverse-domain names, so UTF-8 length equals character count and no multi-byte octet complicates
    /// the comparison.
    /// </summary>
    [TestMethod]
    public void NameSpacesMapKeysAreOrderedByEncodedLengthFirst()
    {
        using MeteredHousePool pool = new();
        using MdocIssuerSignedItem aamvaItem = BuildIssuerSignedItem("family_name", digestId: 0, isCanonicalOrder: false, pool.Pool);
        using MdocIssuerSignedItem isoItem = BuildIssuerSignedItem("given_name", digestId: 1, isCanonicalOrder: false, pool.Pool);
        using MdocIssuerSignedItem shortItem = BuildIssuerSignedItem("birth_date", digestId: 2, isCanonicalOrder: false, pool.Pool);
        using MdocIssuerAuth issuerAuth = BuildIssuerAuth(isCanonicalHeaderOrder: false, pool.Pool);

        //Reverse insertion order: longest key first, shortest last.
        using MdocDeviceResponse response = BuildDeviceResponse(
            NameSpacesOf((AamvaNameSpace, aamvaItem), (IsoMdlNameSpace, isoItem), (ShortNameSpace, shortItem)),
            issuerAuth,
            deviceSigned: null);

        ReadOnlyMemory<byte> encoded = MdocCborDeviceResponseWriter.EncodeDeviceResponse(response);
        ReadOnlyMemory<byte> issuerSigned = ReadMapEntry(ReadArrayElement(ReadMapEntry(encoded, MdocWellKnownKeys.Documents), 0), MdocWellKnownKeys.IssuerSigned);
        string[] keys = ReadTextMapKeys(ReadMapEntry(issuerSigned, MdocWellKnownKeys.NameSpaces));

        string[] expected = [ShortNameSpace, IsoMdlNameSpace, AamvaNameSpace];

        AssertKeySequence(expected, keys);
    }


    /// <summary>
    /// Two namespaces of identical encoded length come out in bytewise order, the second criterion of
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see>:
    /// <c>org.iso.18013.5.1</c> and <c>org.iso.18013.5.2</c> are both 17 octets of text (18 encoded) and
    /// differ only in their final octet, <c>'1'</c> = 0x31 before <c>'2'</c> = 0x32, so length cannot
    /// decide and the bytewise comparison must.
    /// </summary>
    [TestMethod]
    public void NameSpacesMapKeysOfEqualLengthAreOrderedBytewise()
    {
        using MeteredHousePool pool = new();
        using MdocIssuerSignedItem highItem = BuildIssuerSignedItem("family_name", digestId: 0, isCanonicalOrder: false, pool.Pool);
        using MdocIssuerSignedItem lowItem = BuildIssuerSignedItem("given_name", digestId: 1, isCanonicalOrder: false, pool.Pool);
        using MdocIssuerAuth issuerAuth = BuildIssuerAuth(isCanonicalHeaderOrder: false, pool.Pool);

        //Reverse insertion order: the bytewise-higher key first.
        using MdocDeviceResponse response = BuildDeviceResponse(
            NameSpacesOf((EqualLengthHighNameSpace, highItem), (EqualLengthLowNameSpace, lowItem)),
            issuerAuth,
            deviceSigned: null);

        ReadOnlyMemory<byte> encoded = MdocCborDeviceResponseWriter.EncodeDeviceResponse(response);
        ReadOnlyMemory<byte> issuerSigned = ReadMapEntry(ReadArrayElement(ReadMapEntry(encoded, MdocWellKnownKeys.Documents), 0), MdocWellKnownKeys.IssuerSigned);
        string[] keys = ReadTextMapKeys(ReadMapEntry(issuerSigned, MdocWellKnownKeys.NameSpaces));

        string[] expected = [EqualLengthLowNameSpace, EqualLengthHighNameSpace];

        AssertKeySequence(expected, keys);
    }


    /// <summary>
    /// With canonical foreign parts, the whole <c>DeviceResponse</c> the Lax relaying writer emits is
    /// byte-identical to the same structure written by a
    /// <see cref="CborConformanceMode.RfcCanonical"/> oracle assembled by hand from the same values. The
    /// canonical writer sorts every map it closes, so an equal result proves the relaying writer's own maps
    /// were already in <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see>
    /// order — that is, the Lax mode buys the relay of
    /// <see href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5 §9.1.2.4</see> foreign bytes and
    /// changes nothing else about the envelope.
    /// </summary>
    [TestMethod]
    public void CanonicalForeignPartsProduceBytesIdenticalToACanonicalOracle()
    {
        using MeteredHousePool pool = new();
        using MdocIssuerSignedItem item = BuildIssuerSignedItem("family_name", digestId: 0, isCanonicalOrder: true, pool.Pool);
        using MdocIssuerAuth issuerAuth = BuildIssuerAuth(isCanonicalHeaderOrder: true, pool.Pool);
        using MdocDeviceResponse response = BuildDeviceResponse(NameSpacesOf((IsoMdlNameSpace, item)), issuerAuth, deviceSigned: null);

        ReadOnlyMemory<byte> encoded = MdocCborDeviceResponseWriter.EncodeDeviceResponse(response);
        byte[] oracle = WriteCanonicalOracleDeviceResponse(DocType, IsoMdlNameSpace, item.WireBytes, issuerAuth.EncodedCoseSign1.AsReadOnlySpan());

        Assert.IsTrue(
            encoded.Span.SequenceEqual(oracle),
            $"The relayed DeviceResponse must equal the canonical oracle byte for byte; got {encoded.Length} octets against the oracle's {oracle.Length}.");
    }


    /// <summary>
    /// Writes the same <c>DeviceResponse</c> shape by hand under
    /// <see cref="CborConformanceMode.RfcCanonical"/>, which sorts every map on close, so the oracle's key
    /// order is decided by the codec's canonical comparator rather than by the order written here. The
    /// foreign parts are spliced, which under a deterministic mode also asserts they are themselves
    /// canonical.
    /// </summary>
    /// <param name="docType">The document type of the single document.</param>
    /// <param name="nameSpace">The single namespace holding the single item.</param>
    /// <param name="issuerSignedItemBytes">The Tag-24 <c>IssuerSignedItemBytes</c> to splice.</param>
    /// <param name="issuerAuthBytes">The <c>IssuerAuth</c> COSE_Sign1 bytes to splice.</param>
    /// <returns>The oracle's encoded <c>DeviceResponse</c>.</returns>
    private static byte[] WriteCanonicalOracleDeviceResponse(
        string docType,
        string nameSpace,
        ReadOnlyMemory<byte> issuerSignedItemBytes,
        ReadOnlySpan<byte> issuerAuthBytes)
    {
        ArrayBufferWriter<byte> buffer = new();
        CborWriter writer = new(buffer, CborOptions.RfcCanonical);

        writer.WriteStartMap(3);

        writer.WriteTextString(MdocWellKnownKeys.Version);
        writer.WriteTextString(MdocWellKnownKeys.Version10);

        writer.WriteTextString(MdocWellKnownKeys.Status);
        writer.WriteUInt32(MdocWellKnownKeys.StatusOk);

        writer.WriteTextString(MdocWellKnownKeys.Documents);
        writer.WriteStartArray(1);

        writer.WriteStartMap(2);

        writer.WriteTextString(MdocWellKnownKeys.IssuerSigned);
        writer.WriteStartMap(2);

        writer.WriteTextString(MdocWellKnownKeys.NameSpaces);
        writer.WriteStartMap(1);
        writer.WriteTextString(nameSpace);
        writer.WriteStartArray(1);
        writer.WriteEncodedValue(issuerSignedItemBytes.Span);
        writer.WriteEndArray();
        writer.WriteEndMap();

        writer.WriteTextString(MdocWellKnownKeys.IssuerAuth);
        writer.WriteEncodedValue(issuerAuthBytes);

        writer.WriteEndMap();

        writer.WriteTextString(MdocWellKnownKeys.DocType);
        writer.WriteTextString(docType);

        writer.WriteEndMap();

        writer.WriteEndArray();

        writer.WriteEndMap();

        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Navigates an encoded <c>DeviceResponse</c> down to the first <c>IssuerSignedItemBytes</c> under
    /// <paramref name="nameSpace"/>, returning the exact octets that reached the wire.
    /// </summary>
    /// <param name="deviceResponse">The encoded <c>DeviceResponse</c>.</param>
    /// <param name="nameSpace">The namespace whose first item to extract.</param>
    /// <returns>The relayed item's wire bytes.</returns>
    private static ReadOnlyMemory<byte> ExtractFirstIssuerSignedItemBytes(ReadOnlyMemory<byte> deviceResponse, string nameSpace)
    {
        ReadOnlyMemory<byte> documents = ReadMapEntry(deviceResponse, MdocWellKnownKeys.Documents);
        ReadOnlyMemory<byte> issuerSigned = ReadMapEntry(ReadArrayElement(documents, 0), MdocWellKnownKeys.IssuerSigned);
        ReadOnlyMemory<byte> nameSpaces = ReadMapEntry(issuerSigned, MdocWellKnownKeys.NameSpaces);

        return ReadArrayElement(ReadMapEntry(nameSpaces, nameSpace), 0);
    }


    /// <summary>
    /// Reads the text keys of a CBOR map in wire order, under
    /// <see cref="CborConformanceMode.Lax"/> so the reader observes rather than polices the order.
    /// </summary>
    /// <param name="encodedMap">The encoded map.</param>
    /// <returns>The map's keys in the order they appear on the wire.</returns>
    private static string[] ReadTextMapKeys(ReadOnlyMemory<byte> encodedMap)
    {
        CborReader reader = new(encodedMap, CborOptions.Lax);
        int? entryCount = reader.ReadStartMap();
        List<string> keys = new(entryCount ?? 0);

        while(reader.PeekState() != CborReaderState.EndMap)
        {
            keys.Add(reader.ReadTextString());
            reader.SkipValue();
        }

        reader.ReadEndMap();

        return [.. keys];
    }


    /// <summary>
    /// Returns the encoded value bytes of the text-keyed entry named <paramref name="key"/>, read under
    /// <see cref="CborConformanceMode.Lax"/> so a deliberately non-canonical relayed value is observable
    /// rather than refused.
    /// </summary>
    /// <param name="encodedMap">The encoded map.</param>
    /// <param name="key">The entry's key.</param>
    /// <returns>The entry's encoded value.</returns>
    /// <exception cref="InvalidOperationException">The map carries no such entry.</exception>
    private static ReadOnlyMemory<byte> ReadMapEntry(ReadOnlyMemory<byte> encodedMap, string key)
    {
        CborReader reader = new(encodedMap, CborOptions.Lax);
        _ = reader.ReadStartMap();

        while(reader.PeekState() != CborReaderState.EndMap)
        {
            string current = reader.ReadTextString();
            ReadOnlyMemory<byte> value = reader.ReadEncodedValue();

            if(string.Equals(current, key, StringComparison.Ordinal))
            {
                return value;
            }
        }

        throw new InvalidOperationException($"The map carries no entry named '{key}'.");
    }


    /// <summary>
    /// Reads a text-keyed map's first two keys under <see cref="CborConformanceMode.RfcCanonical"/>, which
    /// is where that mode's ascending-key rule binds — the second typed key read is the one that refuses a
    /// descending pair.
    /// </summary>
    /// <param name="encodedMap">The encoded map to walk.</param>
    private static void ReadFirstTwoTextKeysUnderRfcCanonical(ReadOnlyMemory<byte> encodedMap)
    {
        CborReader reader = new(encodedMap, CborOptions.RfcCanonical);
        _ = reader.ReadStartMap();
        _ = reader.ReadTextString();
        reader.SkipValue();
        _ = reader.ReadTextString();
    }


    /// <summary>
    /// Walks a COSE_Sign1 down to its unprotected header map and reads that map's first two integer labels
    /// under <see cref="CborConformanceMode.RfcCanonical"/>, where the ascending-key rule binds.
    /// </summary>
    /// <param name="coseSign1">The encoded COSE_Sign1 to walk.</param>
    private static void ReadFirstTwoUnprotectedHeaderLabelsUnderRfcCanonical(ReadOnlyMemory<byte> coseSign1)
    {
        CborReader reader = new(coseSign1, CborOptions.RfcCanonical);
        _ = reader.ReadTag();
        _ = reader.ReadStartArray();
        reader.SkipValue();
        _ = reader.ReadStartMap();
        _ = reader.ReadInt32();
        reader.SkipValue();
        _ = reader.ReadInt32();
    }


    /// <summary>
    /// Unwraps a CBOR Tag 24 "encoded CBOR data item" (RFC 8949 §3.4.5.1), returning the byte string's
    /// content — for an <c>IssuerSignedItemBytes</c>, the inner <c>IssuerSignedItem</c> map.
    /// </summary>
    /// <param name="tagged">The Tag-24 wrapper bytes.</param>
    /// <returns>The wrapped item's encoding.</returns>
    private static ReadOnlyMemory<byte> ReadTag24Content(ReadOnlyMemory<byte> tagged)
    {
        CborReader reader = new(tagged, CborOptions.Lax);
        _ = reader.ReadTag();

        return reader.ReadByteStringMemory();
    }


    /// <summary>Returns the encoded bytes of the element at <paramref name="index"/> of a CBOR array.</summary>
    /// <param name="encodedArray">The encoded array.</param>
    /// <param name="index">The zero-based element index.</param>
    /// <returns>The element's encoded bytes.</returns>
    private static ReadOnlyMemory<byte> ReadArrayElement(ReadOnlyMemory<byte> encodedArray, int index)
    {
        CborReader reader = new(encodedArray, CborOptions.Lax);
        _ = reader.ReadStartArray();

        for(int i = 0; i < index; i++)
        {
            reader.SkipValue();
        }

        return reader.ReadEncodedValue();
    }


    /// <summary>
    /// Builds one <c>IssuerSignedItem</c> carrying hand-written Tag-24 wire bytes whose inner map is either
    /// in the canonical order <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949
    /// §4.2.1</see> prescribes — <c>random</c> (6 octets), <c>digestID</c> (8), <c>elementValue</c> (12),
    /// <c>elementIdentifier</c> (17) — or its exact reverse. Written under
    /// <see cref="CborConformanceMode.Lax"/> so the requested order survives to the wire, the way a foreign
    /// issuer's own encoder would produce it.
    /// </summary>
    /// <param name="elementIdentifier">The claim name.</param>
    /// <param name="digestId">The digest identifier.</param>
    /// <param name="isCanonicalOrder">Whether the inner map's keys are written in canonical order.</param>
    /// <param name="pool">The house pool the item's salt is rented from.</param>
    /// <returns>The item; the caller owns and disposes it.</returns>
    private static MdocIssuerSignedItem BuildIssuerSignedItem(string elementIdentifier, uint digestId, bool isCanonicalOrder, BaseMemoryPool pool)
    {
        Salt random = MdocTestFixtures.ItemRandomSalt(pool);
        byte[] encodedElementValue = MdocTestFixtures.CborText($"value-of-{elementIdentifier}");

        ArrayBufferWriter<byte> innerBuffer = new();
        CborWriter innerWriter = new(innerBuffer, CborOptions.Lax);
        innerWriter.WriteStartMap(4);

        if(isCanonicalOrder)
        {
            innerWriter.WriteTextString(MdocWellKnownKeys.Random);
            innerWriter.WriteByteString(random.AsReadOnlySpan());

            innerWriter.WriteTextString(MdocWellKnownKeys.DigestId);
            innerWriter.WriteUInt32(digestId);

            innerWriter.WriteTextString(MdocWellKnownKeys.ElementValue);
            innerWriter.WriteEncodedValue(encodedElementValue);

            innerWriter.WriteTextString(MdocWellKnownKeys.ElementIdentifier);
            innerWriter.WriteTextString(elementIdentifier);
        }
        else
        {
            innerWriter.WriteTextString(MdocWellKnownKeys.ElementIdentifier);
            innerWriter.WriteTextString(elementIdentifier);

            innerWriter.WriteTextString(MdocWellKnownKeys.ElementValue);
            innerWriter.WriteEncodedValue(encodedElementValue);

            innerWriter.WriteTextString(MdocWellKnownKeys.DigestId);
            innerWriter.WriteUInt32(digestId);

            innerWriter.WriteTextString(MdocWellKnownKeys.Random);
            innerWriter.WriteByteString(random.AsReadOnlySpan());
        }

        innerWriter.WriteEndMap();

        ArrayBufferWriter<byte> outerBuffer = new();
        CborWriter outerWriter = new(outerBuffer, CborOptions.Lax);
        outerWriter.WriteTag(CborTag.EncodedCborDataItem);
        outerWriter.WriteByteString(innerBuffer.WrittenSpan);

        byte[] wireBytes = outerBuffer.WrittenSpan.ToArray();

        return new MdocIssuerSignedItem(digestId, random, elementIdentifier, encodedElementValue, wireBytes);
    }


    /// <summary>
    /// Builds an <c>IssuerAuth</c> carrier over a hand-written COSE_Sign1 whose unprotected header map
    /// carries <c>kid</c> (label 4) and <c>x5chain</c> (label 33) either in the canonical order
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see> prescribes or
    /// reversed. The carried Mobile Security Object is a minimal well-formed view; the relaying writer
    /// never reads it, only the wire bytes.
    /// </summary>
    /// <param name="isCanonicalHeaderOrder">Whether the unprotected header's labels are written in canonical order.</param>
    /// <param name="pool">The house pool the wire-bytes carrier is rented from.</param>
    /// <returns>The carrier; the caller owns and disposes it.</returns>
    private static MdocIssuerAuth BuildIssuerAuth(bool isCanonicalHeaderOrder, BaseMemoryPool pool)
    {
        MdocMobileSecurityObject mso = new(
            version: MdocMsoWellKnownKeys.Version10,
            digestAlgorithm: MdocMsoWellKnownKeys.DigestAlgorithmSha256,
            valueDigests: new Dictionary<string, IReadOnlyDictionary<uint, ReadOnlyMemory<byte>>>(StringComparer.Ordinal),
            deviceKeyInfo: new MdocDeviceKeyInfo(new CoseKey(kty: CoseKeyTypes.Ec2, curve: CoseKeyCurves.P256)),
            docType: DocType,
            validityInfo: new MdocValidityInfo(SampleSigned, SampleSigned, SampleValidUntil));

        return new MdocIssuerAuth(mso, EncodedCoseSign1.FromBytes(BuildCoseSign1Bytes(isCanonicalHeaderOrder), pool));
    }


    /// <summary>
    /// Builds a <c>DeviceSigned</c> over a hand-written COSE_Sign1 and a Tag-24-wrapped empty
    /// <c>DeviceNameSpaces</c> map, enough for the outer <c>Document</c> map to carry its
    /// <c>deviceSigned</c> slot.
    /// </summary>
    /// <param name="pool">The house pool the wire-bytes carrier is rented from.</param>
    /// <returns>The device half; the caller owns and disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the EncodedCoseSign1 transfers into MdocDeviceSignature, of that into MdocDeviceAuth, and of that into the returned MdocDeviceSigned, whose Dispose cascades the whole chain; the test method that receives it holds it in a using declaration.")]
    private static MdocDeviceSigned BuildDeviceSigned(BaseMemoryPool pool)
    {
        //Tag 24 (0xD8 0x18) over a one-octet byte string (0x41) holding the empty map (0xA0).
        byte[] encodedDeviceNameSpacesBytes = [0xD8, 0x18, 0x41, 0xA0];

        return new MdocDeviceSigned(
            MdocDeviceNameSpaces.Empty,
            encodedDeviceNameSpacesBytes,
            new MdocDeviceAuth(new MdocDeviceSignature(EncodedCoseSign1.FromBytes(BuildCoseSign1Bytes(isCanonicalHeaderOrder: true), pool))));
    }


    /// <summary>
    /// Hand-writes a COSE_Sign1 per <see href="https://www.rfc-editor.org/rfc/rfc9052#section-4.2">RFC 9052
    /// §4.2</see>: tag 18 over the four-element array [protected bstr, unprotected map, payload bstr,
    /// signature bstr]. Written under <see cref="CborConformanceMode.Lax"/> so the requested unprotected
    /// header order survives to the wire.
    /// </summary>
    /// <param name="isCanonicalHeaderOrder">Whether the unprotected header's labels are written in canonical order.</param>
    /// <returns>The encoded COSE_Sign1.</returns>
    private static byte[] BuildCoseSign1Bytes(bool isCanonicalHeaderOrder)
    {
        //Protected header h'A10126' — the map {1: -7}, i.e. alg = ES256.
        byte[] protectedHeader = [0xA1, 0x01, 0x26];
        byte[] keyIdentifier = [0x6B, 0x69, 0x64];
        byte[] certificateChain = [0x30, 0x82, 0x01, 0x02];
        byte[] payload = [0xA0];
        byte[] signature = new byte[64];

        ArrayBufferWriter<byte> buffer = new();
        CborWriter writer = new(buffer, CborOptions.Lax);
        writer.WriteTag(new CborTag(CoseTags.Sign1));
        writer.WriteStartArray(4);
        writer.WriteByteString(protectedHeader);

        writer.WriteStartMap(2);

        if(isCanonicalHeaderOrder)
        {
            writer.WriteInt32(CoseKidLabel);
            writer.WriteByteString(keyIdentifier);

            writer.WriteInt32(CoseX5ChainLabel);
            writer.WriteByteString(certificateChain);
        }
        else
        {
            writer.WriteInt32(CoseX5ChainLabel);
            writer.WriteByteString(certificateChain);

            writer.WriteInt32(CoseKidLabel);
            writer.WriteByteString(keyIdentifier);
        }

        writer.WriteEndMap();

        writer.WriteByteString(payload);
        writer.WriteByteString(signature);
        writer.WriteEndArray();

        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Assembles a <c>DeviceResponse</c> around one presentation document, preserving the caller's
    /// insertion order in the namespaces dictionary so the writer's own ordering is what the tests observe.
    /// </summary>
    /// <param name="nameSpaces">The namespaces map, in insertion order.</param>
    /// <param name="issuerAuth">The issuer-signed authentication carrier.</param>
    /// <param name="deviceSigned">The device half, or <see langword="null"/> to omit the slot.</param>
    /// <returns>The response; the caller owns and disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the MdocPresentationDocument transfers into the returned MdocDeviceResponse, whose Dispose disposes every document it carries; the test method that receives the response holds it in a using declaration. The document's IssuerSigned view is borrowed, and the caller separately owns the deviceSigned it passed in.")]
    private static MdocDeviceResponse BuildDeviceResponse(
        IReadOnlyDictionary<string, IReadOnlyList<MdocIssuerSignedItem>> nameSpaces,
        MdocIssuerAuth issuerAuth,
        MdocDeviceSigned? deviceSigned)
    {
        MdocPresentationDocument document = new(
            docType: DocType,
            issuerSigned: new MdocIssuerSignedView(nameSpaces, issuerAuth),
            deviceSigned: deviceSigned);

        return new MdocDeviceResponse(
            version: MdocWellKnownKeys.Version10,
            documents: [document],
            status: MdocWellKnownKeys.StatusOk);
    }


    /// <summary>
    /// Builds an insertion-ordered namespaces map from the supplied pairs, one item per namespace.
    /// A plain <see cref="Dictionary{TKey, TValue}"/> preserves insertion order for an add-only
    /// dictionary, which is what makes "supplied in reverse order" a meaningful input to the writer.
    /// </summary>
    /// <param name="entries">The namespace/item pairs, in the order the writer receives them.</param>
    /// <returns>The namespaces map.</returns>
    private static Dictionary<string, IReadOnlyList<MdocIssuerSignedItem>> NameSpacesOf(
        params (string NameSpace, MdocIssuerSignedItem Item)[] entries)
    {
        Dictionary<string, IReadOnlyList<MdocIssuerSignedItem>> nameSpaces = new(entries.Length, StringComparer.Ordinal);
        foreach((string nameSpace, MdocIssuerSignedItem item) in entries)
        {
            nameSpaces[nameSpace] = [item];
        }

        return nameSpaces;
    }


    /// <summary>Asserts that the wire key sequence equals the expected one, element by element.</summary>
    /// <param name="expected">The expected keys, in canonical order.</param>
    /// <param name="actual">The keys as they appeared on the wire.</param>
    private static void AssertKeySequence(string[] expected, string[] actual)
    {
        Assert.HasCount(expected.Length, actual, $"Expected {expected.Length} keys; got [{string.Join(", ", actual)}].");

        for(int i = 0; i < expected.Length; i++)
        {
            Assert.AreEqual(expected[i], actual[i], $"Key at wire position {i} must be '{expected[i]}'; the wire order was [{string.Join(", ", actual)}].");
        }
    }


    /// <summary>The MSO's signed instant; a fixed point, since nothing under test reads it.</summary>
    private static DateTimeOffset SampleSigned { get; } = new(2026, 5, 25, 8, 0, 0, TimeSpan.Zero);

    /// <summary>The MSO's expiry instant, one year after <see cref="SampleSigned"/>.</summary>
    private static DateTimeOffset SampleValidUntil { get; } = SampleSigned.AddYears(1);
}
