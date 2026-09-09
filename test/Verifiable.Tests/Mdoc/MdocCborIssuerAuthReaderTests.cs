using System.Buffers;
using Lumoin.Veritas.Cbor;
using Verifiable.Cbor;
using Verifiable.Cbor.Mdoc;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.MdocTestFixtures;

namespace Verifiable.Tests.Mdoc;

/// <summary>
/// Tests for <see cref="MdocCborIssuerAuthReader"/> — verifies that an
/// <c>issuerAuth</c> COSE_Sign1 with a Tag-24-wrapped MSO payload parses
/// into a fully-populated <see cref="MdocIssuerAuth"/> carrier.
/// </summary>
/// <remarks>
/// <para>
/// The fixture builds a minimal COSE_Sign1 with an unsigned (zero-byte)
/// signature — M.2 doesn't verify signatures, only walks the wire shape.
/// Real signing lands in M.3.
/// </para>
/// </remarks>
[TestClass]
internal sealed class MdocCborIssuerAuthReaderTests
{
    [TestMethod]
    public void ReadIssuerAuthExtractsParsedMsoAndPreservesWireBytes()
    {
        byte[] msoBytes = MdocCborMsoReaderTestFixtures.BuildSampleMso();
        byte[] issuerAuthBytes = WrapInCoseSign1WithTag24Payload(msoBytes);

        MdocIssuerAuth issuerAuth = MdocCborIssuerAuthReader.Read(issuerAuthBytes, BaseMemoryPool.Shared);

        //Parsed view is populated.
        Assert.AreEqual(MdocMsoWellKnownKeys.Version10, issuerAuth.Mso.Version);
        Assert.AreEqual(MdocMsoWellKnownKeys.DigestAlgorithmSha256, issuerAuth.Mso.DigestAlgorithm);
        Assert.AreEqual("org.iso.18013.5.1.mDL", issuerAuth.Mso.DocType);

        //Wire bytes are preserved verbatim for M.3's COSE_Sign1 signature
        //verification to hash through the Sig_structure.
        Assert.IsTrue(
            issuerAuth.EncodedCoseSign1.AsReadOnlySpan().SequenceEqual(issuerAuthBytes),
            "MdocIssuerAuth must preserve the original COSE_Sign1 wire bytes verbatim.");
    }


    [TestMethod]
    public void ReadIssuerAuthRejectsDetachedPayload()
    {
        //COSE_Sign1 for issuerAuth must carry the MSO inline — detached
        //payloads (nil payload slot) have no place to put the MSO bytes.
        //The shared CoseSerialization.ParseCoseSign1 surfaces the missing
        //byte string ahead of this reader; the explicit IsEmpty guard in
        //MdocCborIssuerAuthReader covers the zero-byte-string case below.
        byte[] issuerAuthBytes = WrapInCoseSign1WithDetachedPayload();

        Exception? caught = null;
        try
        {
            MdocCborIssuerAuthReader.Read(issuerAuthBytes, BaseMemoryPool.Shared);
        }
        catch(Exception ex)
        {
            caught = ex;
        }

        Assert.IsTrue(caught is CborContentException or InvalidOperationException,
            $"Expected the CBOR reader's own detached-payload state fault; got {caught?.GetType().Name}.");
    }


    [TestMethod]
    public void ReadIssuerAuthRejectsEmptyByteStringPayload()
    {
        //Zero-length byte-string payload is valid COSE_Sign1 wire shape but
        //has no MSO inside. The reader's IsEmpty guard catches it explicitly
        //with a CborContentException so callers see the mdoc-specific
        //reason rather than a generic CBOR parse failure further down.
        byte[] issuerAuthBytes = WrapInCoseSign1WithEmptyBstrPayload();

        CborContentException ex = Assert.ThrowsExactly<CborContentException>(() =>
            MdocCborIssuerAuthReader.Read(issuerAuthBytes, BaseMemoryPool.Shared));
        Assert.Contains("empty", ex.Message);
    }


    [TestMethod]
    public void ReadIssuerAuthRejectsNonTag18Payload()
    {
        //Pass arbitrary non-COSE_Sign1 bytes; the underlying CoseSerialization.ParseCoseSign1
        //surfaces the missing Tag 18.
        byte[] arbitrary = [0x80]; //CBOR empty array

        Exception? caught = null;
        try
        {
            MdocCborIssuerAuthReader.Read(arbitrary, BaseMemoryPool.Shared);
        }
        catch(Exception ex)
        {
            caught = ex;
        }

        Assert.IsTrue(caught is CborContentException or InvalidOperationException,
            $"Expected the CBOR reader's own wrong-major-type fault; got {caught?.GetType().Name}.");
    }


    /// <summary>
    /// An MSO whose <c>status</c> member refuses on read (an empty Status map, here) throws after
    /// the rented COSE_Sign1 wire carrier already exists; the carrier must still return to the
    /// pool rather than leak on that failure path — an unauthenticated wallet can otherwise repeat
    /// the malformed presentation at will and burn one pool buffer per attempt.
    /// </summary>
    [TestMethod]
    public void ReadIssuerAuthReturnsWireCarrierToPoolWhenMsoStatusRefuses()
    {
        byte[] msoBytes = BuildMsoWithEmptyStatusMap();
        byte[] issuerAuthBytes = WrapInCoseSign1WithTag24Payload(msoBytes);

        using var metered = new MeteredHousePool();

        Assert.ThrowsExactly<CborContentException>(() =>
            MdocCborIssuerAuthReader.Read(issuerAuthBytes, metered.Pool));

        Assert.IsGreaterThan(0, metered.RentedCount, "metered.Pool must have been exercised, or the balance assertion below is vacuous.");
        Assert.AreEqual(0, metered.OutstandingCount, "A refused MSO status read must not leak the rented COSE_Sign1 wire carrier.");
    }


    /// <summary>Builds an MSO map carrying the six required members plus an empty <c>status</c> map, which Section 6.3 refuses.</summary>
    private static byte[] BuildMsoWithEmptyStatusMap()
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);

        writer.WriteStartMap(7);

        writer.WriteTextString(MdocMsoWellKnownKeys.DeviceKeyInfo);
        WriteDeviceKeyInfo(writer);

        writer.WriteTextString(MdocMsoWellKnownKeys.DigestAlgorithm);
        writer.WriteTextString(MdocMsoWellKnownKeys.DigestAlgorithmSha256);

        writer.WriteTextString(MdocMsoWellKnownKeys.DocType);
        writer.WriteTextString("org.iso.18013.5.1.mDL");

        writer.WriteTextString(MdocMsoWellKnownKeys.ValidityInfo);
        WriteValidityInfo(writer);

        writer.WriteTextString(MdocMsoWellKnownKeys.ValueDigests);
        WriteValueDigests(writer, "org.iso.18013.5.1");

        writer.WriteTextString(MdocMsoWellKnownKeys.Version);
        writer.WriteTextString(MdocMsoWellKnownKeys.Version10);

        writer.WriteTextString(MdocMsoWellKnownKeys.Status);
        writer.WriteStartMap(0);
        writer.WriteEndMap();

        writer.WriteEndMap();

        return buffer.WrittenSpan.ToArray();
    }


    private static byte[] WrapInCoseSign1WithTag24Payload(byte[] msoBytes)
    {
        //Tag 24 wrapper around the MSO bytes per ISO/IEC 18013-5 §9.1.2.4.
        EncodedCborItem tag24 = EncodedCborItem.Wrap(msoBytes);

        //Minimal COSE_Sign1: empty protected header, empty unprotected map,
        //Tag 24 payload, single-byte placeholder signature. M.2 doesn't
        //verify the signature so any non-empty filler works — pool-rented
        //carriers require a non-zero allocation.
        using EncodedCoseProtectedHeader protectedHeader = EncodedCoseProtectedHeader.FromBytes(
            new byte[] { 0xA0 }, //empty CBOR map
            BaseMemoryPool.Shared);
        using Signature signature = new byte[] { 0x00 }.AsSpan().ToSignature(
            CryptoTags.AlgorithmAgnosticSignature,
            BaseMemoryPool.Shared);
        using var message = new CoseSign1Message(
            protectedHeader,
            unprotectedHeader: null,
            payload: tag24.WireBytes,
            signature: signature);

        using EncodedCoseSign1 encoded = CoseSerialization.SerializeCoseSign1(message, BaseMemoryPool.Shared);

        return encoded.AsReadOnlySpan().ToArray();
    }


    private static byte[] WrapInCoseSign1WithDetachedPayload()
    {
        //CBOR Tag 18, [protected (bstr empty-map), unprotected (empty map), nil payload, empty sig].
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteTag(new CborTag(18));
        writer.WriteStartArray(4);
        writer.WriteByteString(new byte[] { 0xA0 });
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteNull();
        writer.WriteByteString([]);
        writer.WriteEndArray();

        return buffer.WrittenSpan.ToArray();
    }


    private static byte[] WrapInCoseSign1WithEmptyBstrPayload()
    {
        //Zero-byte byte string as payload — valid wire shape, but mdoc-empty.
        //The signature is a single-byte placeholder: pool-rented carriers
        //require a non-zero allocation, and the reader's empty-payload
        //guard fires before it ever inspects signature bytes.
        using EncodedCoseProtectedHeader protectedHeader = EncodedCoseProtectedHeader.FromBytes(
            new byte[] { 0xA0 },
            BaseMemoryPool.Shared);
        using Signature signature = new byte[] { 0x00 }.AsSpan().ToSignature(
            CryptoTags.AlgorithmAgnosticSignature,
            BaseMemoryPool.Shared);
        using var message = new CoseSign1Message(
            protectedHeader,
            unprotectedHeader: null,
            payload: ReadOnlyMemory<byte>.Empty,
            signature: signature);

        using EncodedCoseSign1 encoded = CoseSerialization.SerializeCoseSign1(message, BaseMemoryPool.Shared);

        return encoded.AsReadOnlySpan().ToArray();
    }
}


/// <summary>
/// Fixture builders shared across mdoc CBOR reader tests. Kept in a
/// separate file-scoped class so the test files stay focused on their
/// individual assertions; this matches the
/// <c>[[feedback-dcql-fixture-extraction]]</c> direction of consolidating
/// fixture builders rather than reinventing per test category.
/// </summary>
internal static class MdocCborMsoReaderTestFixtures
{
    private const string MdlNamespace = "org.iso.18013.5.1";
    private const string MdlDocType = "org.iso.18013.5.1.mDL";


    /// <summary>
    /// Canonical-form MSO with version, SHA-256 digest algorithm, a single
    /// namespace with two zero-byte digests, a P-256 EC2 deviceKey, the mDL
    /// doctype, and a 2026→2027 validity window.
    /// </summary>
    public static byte[] BuildSampleMso()
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);

        writer.WriteStartMap(6);

        writer.WriteTextString(MdocMsoWellKnownKeys.DeviceKeyInfo);
        WriteDeviceKeyInfo(writer);

        writer.WriteTextString(MdocMsoWellKnownKeys.DigestAlgorithm);
        writer.WriteTextString(MdocMsoWellKnownKeys.DigestAlgorithmSha256);

        writer.WriteTextString(MdocMsoWellKnownKeys.DocType);
        writer.WriteTextString(MdlDocType);

        writer.WriteTextString(MdocMsoWellKnownKeys.ValidityInfo);
        WriteValidityInfo(writer);

        writer.WriteTextString(MdocMsoWellKnownKeys.ValueDigests);
        WriteValueDigests(writer, MdlNamespace);

        writer.WriteTextString(MdocMsoWellKnownKeys.Version);
        writer.WriteTextString(MdocMsoWellKnownKeys.Version10);

        writer.WriteEndMap();

        return buffer.WrittenSpan.ToArray();
    }
}
