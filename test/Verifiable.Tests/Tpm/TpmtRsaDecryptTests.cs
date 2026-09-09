using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// The Spec-layer wire behaviour of <c>TPMI_ALG_RSA_DECRYPT</c> (TPM 2.0 Library Part 2, clause 11.2.4.4, Table
/// 192) and <c>TPMT_RSA_DECRYPT</c> (clause 11.2.4.5, Table 193): a write-then-parse round trip per arm, the
/// serialized widths, the refused selectors and hash algorithms, value equality, the debugger text, the
/// conversions to and from <see cref="TpmtRsaScheme"/>, and <see cref="Tpm2bPublicKeyRsa"/>'s
/// <see cref="Tpm2bPublicKeyRsa.FromMarshaled(IMemoryOwner{byte}, int)"/> bounds and
/// <see cref="Tpm2bPublicKeyRsa.Clear"/>.
/// </summary>
/// <remarks>
/// These are pure structure tests — no simulator, no device, no session. They pin the shape
/// <c>TPM2_RSA_Encrypt()</c>'s and <c>TPM2_RSA_Decrypt()</c>'s <c>inScheme</c> takes on the wire, independently
/// of any command-level rule.
/// </remarks>
[TestClass]
internal sealed class TpmtRsaDecryptTests
{
    /// <summary>A selector no table assigns, for the "outside Table 192's set" and "not a hash algorithm" cases.</summary>
    private const TpmAlgIdConstants UnassignedSelector = (TpmAlgIdConstants)0x7FFF;

    /// <summary>
    /// "The Table 192 list of values that are allowed in a decryption scheme selection as used in
    /// TPM2_RSA_Encrypt() and TPM2_RSA_Decrypt()." A bare <c>TPM_ALG_RSAES</c> selector round-trips as the raw
    /// two-octet value 0x0015.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.4.4</see>.
    /// </summary>
    [TestMethod]
    public void TpmiAlgRsaDecryptRoundTripsTheRsaesBareSelector()
    {
        TpmiAlgRsaDecrypt original = TpmiAlgRsaDecrypt.FromValue(TpmAlgIdConstants.TPM_ALG_RSAES);
        byte[] octets = new byte[sizeof(ushort)];
        var writer = new TpmWriter(octets);
        original.WriteTo(ref writer);

        Assert.AreSequenceEqual(new byte[] { 0x00, 0x15 }, octets, "TPM_ALG_RSAES's raw algorithm value is 0x0015.");

        var reader = new TpmReader(octets);
        TpmiAlgRsaDecrypt parsed = TpmiAlgRsaDecrypt.Parse(ref reader);

        Assert.AreEqual(0, reader.Remaining, "The parse consumes exactly the two-octet selector.");
        Assert.AreEqual(original, parsed, "The round trip reproduces the same selector.");
    }

    /// <summary>
    /// Table 190's <c>rsaes</c> arm is <c>TPMS_EMPTY</c>, so <c>TPMT_RSA_DECRYPT</c> carries no <c>details</c>
    /// for RSAES: it frames as the bare two-octet selector, and its serialized size is two octets.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.4.5</see>.
    /// </summary>
    [TestMethod]
    public void TpmtRsaDecryptRoundTripsRsaesAsTheBareTwoOctetSelector()
    {
        TpmtRsaDecrypt original = TpmtRsaDecrypt.RsaEs;

        Assert.AreEqual(sizeof(ushort), original.SerializedSize, "RSAES carries no details, so its width is the selector alone.");
        Assert.AreSequenceEqual(new byte[] { 0x00, 0x15 }, Serialize(original), "The bare selector is TPM_ALG_RSAES (0x0015).");

        TpmtRsaDecrypt parsed = RoundTrip(original, isNullAdmitted: false);

        Assert.AreEqual(original, parsed, "The round trip reproduces the same scheme.");
    }

    /// <summary>
    /// Table 190's <c>oaep</c> arm is a <c>TPMS_SCHEME_HASH</c>: <c>TPMT_RSA_DECRYPT</c> carries the selector
    /// then one hash algorithm, four octets wide in total.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.4.5</see>.
    /// </summary>
    [TestMethod]
    public void TpmtRsaDecryptRoundTripsOaepWithItsHashAlgorithm()
    {
        TpmtRsaDecrypt original = TpmtRsaDecrypt.Oaep(TpmAlgIdConstants.TPM_ALG_SHA256);

        Assert.AreEqual(sizeof(ushort) + sizeof(ushort), original.SerializedSize, "OAEP carries one hash algorithm beyond the selector.");
        Assert.AreSequenceEqual(new byte[] { 0x00, 0x17, 0x00, 0x0B }, Serialize(original), "OAEP (0x0017) then its hash algorithm, SHA-256 (0x000B).");

        TpmtRsaDecrypt parsed = RoundTrip(original, isNullAdmitted: false);

        Assert.AreEqual(original, parsed, "The round trip reproduces the same scheme and hash.");
    }

    /// <summary>
    /// Table 192's leading <c>+</c> admits <c>TPM_ALG_NULL</c> where the embedding structure allows it: a NULL
    /// scheme round-trips as the bare selector when the caller requests <c>isNullAdmitted: true</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.4.4</see>.
    /// </summary>
    [TestMethod]
    public void TpmtRsaDecryptRoundTripsNullWhenAdmitted()
    {
        TpmtRsaDecrypt original = TpmtRsaDecrypt.Null;

        Assert.AreEqual(sizeof(ushort), original.SerializedSize, "A NULL scheme carries no details.");
        Assert.AreSequenceEqual(new byte[] { 0x00, 0x10 }, Serialize(original), "The bare selector is TPM_ALG_NULL (0x0010).");

        TpmtRsaDecrypt parsed = RoundTrip(original, isNullAdmitted: true);

        Assert.IsTrue(parsed.IsNull, "The round trip reproduces a NULL scheme.");
    }

    /// <summary>
    /// Unmarshaling any value outside Table 192's admitted set is <c>TPM_RC_VALUE</c> (the table's own
    /// <c>#</c>) — a signing selector (<c>TPM_ALG_RSASSA</c>, <c>TPM_ALG_RSAPSS</c>) or an unassigned value is
    /// refused even when NULL is admitted for this call.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.4.4</see>.
    /// </summary>
    /// <param name="selector">The refused selector on the wire.</param>
    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_RSASSA, DisplayName = "RSASSA")]
    [DataRow(TpmAlgIdConstants.TPM_ALG_RSAPSS, DisplayName = "RSAPSS")]
    [DataRow(UnassignedSelector, DisplayName = "an unassigned selector")]
    public void TpmtRsaDecryptParseRefusesASelectorOutsideTable192(TpmAlgIdConstants selector)
    {
        byte[] octets = SelectorOctets(selector);

        _ = Assert.ThrowsExactly<InvalidOperationException>(
            () => ParseCompound(octets, isNullAdmitted: true),
            $"Table 192's # marks '{selector}' as outside {{RSAES, OAEP, NULL}}, refused even with NULL admitted.");
    }

    /// <summary>
    /// "If inScheme is used, and the scheme requires a hash algorithm it may not be TPM_ALG_NULL": Table 173's
    /// <c>hashAlg</c> carries no <c>+</c>, so an OAEP hash algorithm that is <c>TPM_ALG_NULL</c> or unassigned
    /// is refused (<c>TPM_RC_HASH</c>, Table 77).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2</see>.
    /// </summary>
    /// <param name="hashAlg">The refused hash algorithm following the OAEP selector.</param>
    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_NULL, DisplayName = "NULL")]
    [DataRow(UnassignedSelector, DisplayName = "an unassigned value")]
    public void TpmtRsaDecryptParseRefusesAnUnadmittedOaepHashAlgorithm(TpmAlgIdConstants hashAlg)
    {
        byte[] octets = [0x00, 0x17, .. SelectorOctets(hashAlg)];

        _ = Assert.ThrowsExactly<InvalidOperationException>(
            () => ParseCompound(octets, isNullAdmitted: false),
            $"OAEP's hashAlg '{hashAlg}' is not an admitted TCG hash algorithm and carries no NULL exception.");
    }

    /// <summary>
    /// Table 193's leading <c>+</c> is a property of the EMBEDDING structure, not the type itself: without
    /// requesting <c>isNullAdmitted: true</c>, a NULL scheme on the wire is refused exactly like any other
    /// unadmitted selector.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.4.4</see>.
    /// </summary>
    [TestMethod]
    public void TpmtRsaDecryptParseRefusesNullWhenNotAdmitted()
    {
        byte[] octets = [0x00, 0x10];

        _ = Assert.ThrowsExactly<InvalidOperationException>(
            () => ParseCompound(octets, isNullAdmitted: false),
            "The default isNullAdmitted: false must refuse TPM_ALG_NULL.");
    }

    /// <summary>
    /// Two schemes carrying the same selector and hash algorithm are the same value and hash alike; a
    /// different hash algorithm or a different selector makes them different values.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.4.5</see>.
    /// </summary>
    [TestMethod]
    public void TpmtRsaDecryptEqualityHoldsForIdenticalSchemesAndDiffersOtherwise()
    {
        TpmtRsaDecrypt first = TpmtRsaDecrypt.Oaep(TpmAlgIdConstants.TPM_ALG_SHA256);
        TpmtRsaDecrypt second = TpmtRsaDecrypt.Oaep(TpmAlgIdConstants.TPM_ALG_SHA256);
        TpmtRsaDecrypt differentHash = TpmtRsaDecrypt.Oaep(TpmAlgIdConstants.TPM_ALG_SHA384);
        TpmtRsaDecrypt differentSelector = TpmtRsaDecrypt.RsaEs;

        Assert.AreEqual(first, second, "Two OAEP schemes carrying the same hash are the same value.");
        Assert.AreEqual(first.GetHashCode(), second.GetHashCode(), "Equal schemes hash alike.");
        Assert.AreNotEqual(first, differentHash, "Different hash algorithms are different values.");
        Assert.AreNotEqual(first, differentSelector, "Different selectors are different values.");
    }

    /// <summary>
    /// <see cref="TpmtRsaDecrypt.ToRsaScheme"/> and <see cref="TpmtRsaDecrypt.FromRsaScheme(TpmtRsaScheme)"/>
    /// round-trip a key's own <see cref="TpmtRsaScheme"/> for every arm this type admits, the conversion Table
    /// 42's "be the same as scheme" compare relies on.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2</see>.
    /// </summary>
    [TestMethod]
    public void TpmtRsaDecryptConvertsToAndFromTheKeysOwnRsaScheme()
    {
        TpmtRsaDecrypt oaep = TpmtRsaDecrypt.Oaep(TpmAlgIdConstants.TPM_ALG_SHA256);
        TpmtRsaScheme keyScheme = oaep.ToRsaScheme();

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_OAEP, keyScheme.Scheme, "ToRsaScheme carries the selector across.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, keyScheme.HashAlg, "ToRsaScheme carries the hash across.");
        Assert.AreEqual(oaep, TpmtRsaDecrypt.FromRsaScheme(keyScheme), "FromRsaScheme(ToRsaScheme(x)) reproduces x for OAEP.");
        Assert.AreEqual(TpmtRsaDecrypt.RsaEs, TpmtRsaDecrypt.FromRsaScheme(TpmtRsaScheme.RsaEs), "RSAES converts both ways.");
        Assert.IsTrue(TpmtRsaDecrypt.FromRsaScheme(TpmtRsaScheme.Null).IsNull, "NULL converts both ways.");
    }

    /// <summary>
    /// A key's own scheme outside Table 192's set (a signing scheme such as RSASSA) has no
    /// <see cref="TpmiAlgRsaDecrypt"/> counterpart: the conversion is meant only for a scheme already judged
    /// admitted for decryption, never for an arbitrary signing scheme.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.4.4</see>.
    /// </summary>
    [TestMethod]
    public void TpmtRsaDecryptFromRsaSchemeRefusesASigningScheme()
    {
        TpmtRsaScheme signing = TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256);

        _ = Assert.ThrowsExactly<InvalidOperationException>(
            () => TpmtRsaDecrypt.FromRsaScheme(signing),
            "RSASSA has no TPMI_ALG_RSA_DECRYPT counterpart (Table 192 admits only RSAES, OAEP and NULL).");
    }

    /// <summary>
    /// <see cref="TpmiAlgRsaDecrypt.IsRsaDecryptScheme"/> admits exactly Table 192's set — RSAES and OAEP
    /// unconditionally, NULL only under <c>isNullAdmitted</c>, and nothing else — matching the membership
    /// <see cref="TpmiAlgRsaDecrypt.Parse"/> enforces at the wire.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.4.4</see>.
    /// </summary>
    /// <param name="value">The selector under test.</param>
    /// <param name="isNullAdmitted">Whether NULL is admitted for this call.</param>
    /// <param name="expectedIsAdmitted">Whether Table 192 admits <paramref name="value"/> under that condition.</param>
    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_RSAES, false, true, DisplayName = "RSAES admitted")]
    [DataRow(TpmAlgIdConstants.TPM_ALG_OAEP, false, true, DisplayName = "OAEP admitted")]
    [DataRow(TpmAlgIdConstants.TPM_ALG_NULL, false, false, DisplayName = "NULL refused when not admitted")]
    [DataRow(TpmAlgIdConstants.TPM_ALG_NULL, true, true, DisplayName = "NULL admitted on request")]
    [DataRow(TpmAlgIdConstants.TPM_ALG_RSASSA, true, false, DisplayName = "RSASSA never admitted")]
    [DataRow(TpmAlgIdConstants.TPM_ALG_RSAPSS, true, false, DisplayName = "RSAPSS never admitted")]
    [DataRow(UnassignedSelector, true, false, DisplayName = "an unassigned selector never admitted")]
    public void TpmiAlgRsaDecryptIsRsaDecryptSchemeAdmitsExactlyTable192sMembers(TpmAlgIdConstants value, bool isNullAdmitted, bool expectedIsAdmitted)
    {
        Assert.AreEqual(expectedIsAdmitted, TpmiAlgRsaDecrypt.IsRsaDecryptScheme(value, isNullAdmitted), $"'{value}' with isNullAdmitted={isNullAdmitted}.");
    }

    /// <summary>
    /// <see cref="Tpm2bPublicKeyRsa.FromMarshaled(IMemoryOwner{byte}, int)"/> refuses a declared size past the
    /// storage it was handed, and disposes that storage rather than orphaning the rental — observed through a
    /// metered pool's outstanding-rental balance.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.4.6</see>.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the storage transfers to FromMarshaled, which disposes it on this refusing path.")]
    public void Tpm2bPublicKeyRsaFromMarshaledRefusesASizeBeyondTheStorageItWasGiven()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        IMemoryOwner<byte> storage = pool.Rent(50);
        long baseline = trackingPool.OutstandingCount;

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => Tpm2bPublicKeyRsa.FromMarshaled(storage, 51),
            "A declared size past the storage's own length is refused.");
        Assert.AreEqual(baseline - 1, trackingPool.OutstandingCount, "The refusing adoption disposes the storage it was given.");
    }

    /// <summary>
    /// <see cref="Tpm2bPublicKeyRsa.FromMarshaled(IMemoryOwner{byte}, int)"/> refuses a declared size past
    /// <see cref="Tpm2bPublicKeyRsa.MaxRsaKeyBytes"/> (Table 194's <c>MAX_RSA_KEY_BYTES</c>) even when the
    /// storage itself is wide enough, and disposes that storage.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.4.6</see>.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the storage transfers to FromMarshaled, which disposes it on this refusing path.")]
    public void Tpm2bPublicKeyRsaFromMarshaledRefusesASizeBeyondMaxRsaKeyBytes()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        int overBound = Tpm2bPublicKeyRsa.MaxRsaKeyBytes + 1;
        IMemoryOwner<byte> storage = pool.Rent(overBound);
        long baseline = trackingPool.OutstandingCount;

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => Tpm2bPublicKeyRsa.FromMarshaled(storage, overBound),
            "A declared size past MAX_RSA_KEY_BYTES is refused even when the storage is wide enough to hold it.");
        Assert.AreEqual(baseline - 1, trackingPool.OutstandingCount, "The refusing adoption disposes the storage it was given.");
    }

    /// <summary>
    /// <see cref="Tpm2bPublicKeyRsa.FromMarshaled(IMemoryOwner{byte}, int)"/> adopts an already-filled pooled
    /// buffer with no second rental: it wraps the storage it was handed rather than copying it into a fresh
    /// one, so the octets a backend delegate already wrote survive the adoption unchanged, and the rental the
    /// adopted value ends up owning is exactly the one the caller rented — observed through a metered pool's
    /// outstanding-rental balance.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.4.6, Table 194</see>.
    /// </summary>
    [TestMethod]
    public void Tpm2bPublicKeyRsaFromMarshaledAdoptsTheStorageWithoutASecondRental()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        byte[] pattern = [0x01, 0x02, 0x03, 0x04, 0x05];
        IMemoryOwner<byte> storage = pool.Rent(pattern.Length);
        pattern.CopyTo(storage.Memory.Span);
        long baseline = trackingPool.OutstandingCount;

        Tpm2bPublicKeyRsa value = Tpm2bPublicKeyRsa.FromMarshaled(storage, pattern.Length);

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Adoption wraps the storage it was handed rather than renting a second buffer.");
        Assert.IsTrue(value.Buffer.SequenceEqual(pattern), "The adopted buffer's octets are the ones the caller wrote before adopting.");

        value.Dispose();

        Assert.AreEqual(baseline - 1, trackingPool.OutstandingCount, "Disposing the adopted value releases the one rental it wraps.");
    }

    /// <summary>
    /// <see cref="Tpm2bPublicKeyRsa.FromMarshaled(IMemoryOwner{byte}, int)"/> called with a declared size of
    /// zero adopts nothing: it yields the shared <see cref="Tpm2bPublicKeyRsa.Empty"/> singleton, which rents
    /// no storage of its own, and releases the storage it was handed rather than orphaning the rental —
    /// observed through a metered pool's outstanding-rental balance.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.4.6, Table 194</see>.
    /// </summary>
    [TestMethod]
    public void Tpm2bPublicKeyRsaFromMarshaledOfSizeZeroYieldsEmptyAndReleasesTheStorage()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        IMemoryOwner<byte> storage = pool.Rent(4);
        long baseline = trackingPool.OutstandingCount;

        using Tpm2bPublicKeyRsa value = Tpm2bPublicKeyRsa.FromMarshaled(storage, 0);

        Assert.IsTrue(ReferenceEquals(Tpm2bPublicKeyRsa.Empty, value), "A declared size of zero adopts nothing and yields the shared Empty singleton.");
        Assert.AreEqual(baseline - 1, trackingPool.OutstandingCount, "The storage handed in for a zero-size adoption is released rather than orphaned.");
    }

    /// <summary>
    /// <see cref="Tpm2bPublicKeyRsa.Clear"/> zeroes the buffer's octets in place, ahead of the disposal that
    /// releases them — the terminal-owner discipline <c>TPM2_RSA_Decrypt()</c>'s recovered plaintext response
    /// relies on before its rental returns to the pool.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.3</see>.
    /// </summary>
    [TestMethod]
    public void Tpm2bPublicKeyRsaClearZeroesTheOctetsInPlace()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Tpm2bPublicKeyRsa value = Tpm2bPublicKeyRsa.Create([0xAA, 0xBB, 0xCC], pool);

        value.Clear();

        Assert.IsTrue(value.Buffer.SequenceEqual(new byte[] { 0x00, 0x00, 0x00 }), "Clear zeroes every octet in place.");
    }

    /// <summary>
    /// The shared <see cref="Tpm2bPublicKeyRsa.Empty"/> instance owns no storage, so
    /// <see cref="Tpm2bPublicKeyRsa.Clear"/> on it is a no-op — it stays empty and usable afterward, exactly as
    /// <see cref="Tpm2bPublicKeyRsa.Dispose"/> already treats the shared instance.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.4.6</see>.
    /// </summary>
    [TestMethod]
    public void Tpm2bPublicKeyRsaClearOnEmptyIsANoOp()
    {
        Tpm2bPublicKeyRsa.Empty.Clear();

        Assert.AreEqual(0, Tpm2bPublicKeyRsa.Empty.Size, "Clearing the shared empty instance changes nothing.");
    }

    /// <summary>
    /// Calling <see cref="Tpm2bPublicKeyRsa.Clear"/> after <see cref="Tpm2bPublicKeyRsa.Dispose"/> throws
    /// <see cref="ObjectDisposedException"/> rather than touching a released rental.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.4.6</see>.
    /// </summary>
    [TestMethod]
    public void Tpm2bPublicKeyRsaClearAfterDisposeThrows()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Tpm2bPublicKeyRsa value = Tpm2bPublicKeyRsa.Create([0xAA], pool);
        value.Dispose();

        _ = Assert.ThrowsExactly<ObjectDisposedException>(() => value.Clear(), "A disposed carrier refuses Clear() rather than zeroing a released rental.");
    }

    /// <summary>The big-endian octets of an algorithm selector, as it appears on the wire.</summary>
    /// <param name="selector">The selector.</param>
    /// <returns>The two-octet wire form.</returns>
    private static byte[] SelectorOctets(TpmAlgIdConstants selector) => [(byte)((ushort)selector >> 8), (byte)(ushort)selector];

    /// <summary>Parses a <c>TPMT_RSA_DECRYPT</c> through its compound convenience form and discards the result, so a refusing parse can be asserted as one expression.</summary>
    /// <param name="octets">The wire octets.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_ALG_NULL</c> is admitted for the selector.</param>
    private static void ParseCompound(byte[] octets, bool isNullAdmitted)
    {
        var reader = new TpmReader(octets);
        _ = TpmtRsaDecrypt.Parse(ref reader, isNullAdmitted);
    }

    /// <summary>Marshals a <c>TPMT_RSA_DECRYPT</c>.</summary>
    /// <param name="scheme">The structure.</param>
    /// <returns>The octets.</returns>
    private static byte[] Serialize(TpmtRsaDecrypt scheme)
    {
        byte[] octets = new byte[scheme.SerializedSize];
        var writer = new TpmWriter(octets);
        scheme.WriteTo(ref writer);

        return octets;
    }

    /// <summary>Writes a <c>TPMT_RSA_DECRYPT</c> out and parses it back through the compound form, asserting the parse consumed exactly the octets written.</summary>
    /// <param name="original">The structure.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_ALG_NULL</c> is admitted for the selector.</param>
    /// <returns>The parsed structure.</returns>
    private static TpmtRsaDecrypt RoundTrip(TpmtRsaDecrypt original, bool isNullAdmitted)
    {
        byte[] octets = Serialize(original);
        var reader = new TpmReader(octets);
        TpmtRsaDecrypt parsed = TpmtRsaDecrypt.Parse(ref reader, isNullAdmitted);
        Assert.AreEqual(0, reader.Remaining, "The parse consumes exactly the octets WriteTo produced.");

        return parsed;
    }
}
