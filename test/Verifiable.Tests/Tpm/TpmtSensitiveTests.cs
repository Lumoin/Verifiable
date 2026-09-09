using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Text.RegularExpressions;
using Verifiable.Cryptography;
using Verifiable.Tests.Foundation;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// The Spec-layer wire behaviour of <c>TPMT_SENSITIVE</c> (TPM 2.0 Library Part 2, clause 12.3.2, Table 240),
/// its <c>TPMU_SENSITIVE_COMPOSITE</c> union (Table 239), the <c>TPM2B_SENSITIVE</c> frame (clause 12.3.3,
/// Table 241) and the <c>TPM2B_PRIVATE_KEY_RSA</c> arm (clause 11.2.4.8, Table 196): a write-then-parse round
/// trip per arm, the serialized widths, the size-agreement rule of the frame, the bounds, the refused
/// selectors, value equality, and the debugger text each structure presents.
/// </summary>
/// <remarks>
/// These are pure structure tests — no simulator, no device, no session. They pin the shape
/// <c>TPM2_LoadExternal()</c>'s <c>inPrivate</c> takes on the wire, independently of any load rule.
/// </remarks>
[TestClass]
internal sealed class TpmtSensitiveTests
{
    /// <summary>A 128-octet RSA prime factor's octets, the width of one prime of a 2048-bit modulus.</summary>
    private static byte[] RsaPrime { get; } = Fill(128, 0xC1);

    /// <summary>A 32-octet ECC scalar's octets, the P-256 field width.</summary>
    private static byte[] EccScalar { get; } = Fill(32, 0xE1);

    /// <summary>A sealed data object's octets.</summary>
    private static byte[] SealedData { get; } = Fill(24, 0x5D);

    /// <summary>An authorization value's octets.</summary>
    private static byte[] AuthValue { get; } = Fill(16, 0xA1);

    /// <summary>A 32-octet <c>seedValue</c>, one SHA-256 digest wide.</summary>
    private static byte[] SeedValue { get; } = Fill(32, 0x5E);

    /// <summary>The <c>TPM_ALG_SYMCIPHER</c> selector (Part 2, clause 6.3, Table 8), a Table 239 arm this union does not model.</summary>
    private const ushort SymCipherSelector = 0x0025;

    /// <summary>The <c>TPM_ALG_MLDSA</c> selector, a Table 239 arm this union does not model.</summary>
    private const ushort MlDsaSelector = 0x00A1;

    /// <summary>The <c>TPM_ALG_HASH_MLDSA</c> selector, a Table 239 arm this union does not model.</summary>
    private const ushort HashMlDsaSelector = 0x00A2;

    /// <summary>The <c>TPM_ALG_MLKEM</c> selector, a Table 239 arm this union does not model.</summary>
    private const ushort MlKemSelector = 0x00A0;

    /// <summary>A selector no table assigns.</summary>
    private const ushort UnassignedSelector = 0x7FFF;

    /// <summary>
    /// Table 240's four fields — <c>sensitiveType</c>, <c>authValue</c>, <c>seedValue</c> and the type-selected
    /// <c>sensitive</c> arm — survive a write-then-parse round trip for the RSA arm ("a prime factor of the
    /// public key", Table 239) with the prime, the authorization value and the seed intact.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.3.2, Tables 239 and 240</see>.
    /// </summary>
    [TestMethod]
    public void SensitiveAreaRoundTripsTheRsaArm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmtSensitive original = RsaSensitive(pool, AuthValue, SeedValue);

        using TpmtSensitive parsed = RoundTrip(original, pool);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSA, parsed.SensitiveType, "The parsed sensitiveType is the one written.");
        Assert.IsTrue(parsed.AuthValue.AsReadOnlySpan().SequenceEqual(AuthValue), "authValue survives the round trip.");
        Assert.IsTrue(parsed.SeedValue.AsReadOnlySpan().SequenceEqual(SeedValue), "seedValue survives the round trip.");
        Assert.IsTrue(parsed.Sensitive.Rsa.AsReadOnlySpan().SequenceEqual(RsaPrime), "The prime factor survives the round trip.");
        Assert.AreEqual(original.Sensitive, parsed.Sensitive, "The parsed union arm equals the one written.");
    }

    /// <summary>
    /// The ECC arm ("the integer private key", Table 239) survives the round trip, its scalar rented
    /// into a pinned carrier exactly once — the metered pool sees one rental of the scalar's width for the arm.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.3.2, Tables 239 and 240; clause 11.2.5.1, Table 197</see>.
    /// </summary>
    [TestMethod]
    public void SensitiveAreaRoundTripsTheEccArmThroughOnePinnedRental()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmtSensitive original = EccSensitive(pool, authValue: null, seedValue: null, EccScalar);
        byte[] octets = Serialize(original);

        long scalarRentalsBefore = trackingPool.RentedCountOfSize(EccScalar.Length);
        var reader = new TpmReader(octets);
        using TpmtSensitive parsed = TpmtSensitive.Parse(ref reader, pool);

        Assert.AreEqual(0, reader.Remaining, "The parse consumes exactly the octets WriteTo produced.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECC, parsed.SensitiveType, "The parsed sensitiveType is the one written.");
        Assert.IsTrue(parsed.Sensitive.Ecc.AsReadOnlySpan().SequenceEqual(EccScalar), "The scalar survives the round trip.");
        Assert.AreEqual(scalarRentalsBefore + 1, trackingPool.RentedCountOfSize(EccScalar.Length), "The ECC arm rents exactly one carrier of the scalar's width; the pool's pinning is not observable through its meter and is documented on the parser instead.");
        Assert.AreEqual(original.Sensitive, parsed.Sensitive, "The parsed union arm equals the one written.");
    }

    /// <summary>
    /// The KEYEDHASH arm ("the private data", Table 239) survives the round trip in
    /// the shape a sealed data object takes: an authorization value, a digest-wide <c>seedValue</c>, and the
    /// sealed octets as <c>bits</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.3.2, Tables 239 and 240</see>.
    /// </summary>
    [TestMethod]
    public void SensitiveAreaRoundTripsTheKeyedHashArm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmtSensitive original = KeyedHashSensitive(pool, AuthValue, SeedValue, SealedData);

        using TpmtSensitive parsed = RoundTrip(original, pool);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_KEYEDHASH, parsed.SensitiveType, "The parsed sensitiveType is the one written.");
        Assert.IsTrue(parsed.AuthValue.AsReadOnlySpan().SequenceEqual(AuthValue), "authValue survives the round trip.");
        Assert.IsTrue(parsed.SeedValue.AsReadOnlySpan().SequenceEqual(SeedValue), "seedValue survives the round trip.");
        Assert.IsTrue(parsed.Sensitive.Bits.AsReadOnlySpan().SequenceEqual(SealedData), "The sealed octets survive the round trip.");
        Assert.AreEqual(original.Sensitive, parsed.Sensitive, "The parsed union arm equals the one written.");
    }

    /// <summary>
    /// Table 240's width is the two-octet selector plus the three sized fields, each its own size prefix and
    /// octets, and <c>WriteTo</c> fills exactly that.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.3.2, Table 240</see>.
    /// </summary>
    [TestMethod]
    public void SensitiveAreaSerializedSizeIsTheSelectorPlusItsThreeSizedFields()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmtSensitive sensitive = RsaSensitive(pool, AuthValue, SeedValue);

        int expected = sizeof(ushort) + (sizeof(ushort) + AuthValue.Length) + (sizeof(ushort) + SeedValue.Length) + (sizeof(ushort) + RsaPrime.Length);
        Assert.AreEqual(expected, sensitive.SerializedSize, "The declared width is the selector plus authValue, seedValue and the arm, each size-prefixed.");

        byte[] octets = new byte[sensitive.SerializedSize];
        var writer = new TpmWriter(octets);
        sensitive.WriteTo(ref writer);
        Assert.AreEqual(sensitive.SerializedSize, writer.Written, "WriteTo fills exactly the declared width.");
    }

    /// <summary>
    /// Two composites carrying the same selector and identical arm octets are the same value and hash alike;
    /// composites differing in the selector, or in the arm's octets, are not.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.3.2, Table 239</see>.
    /// </summary>
    [TestMethod]
    public void SensitiveCompositesWithTheSameArmAreEqualAndOthersAreNot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmuSensitiveComposite first = EccComposite(pool, EccScalar);
        using TpmuSensitiveComposite second = EccComposite(pool, EccScalar);
        using TpmuSensitiveComposite otherOctets = EccComposite(pool, Fill(32, 0xE2));
        using TpmuSensitiveComposite otherArm = BitsComposite(pool, EccScalar);

        Assert.AreEqual(first, second, "The same selector and octets are the same value.");
        Assert.IsTrue(first == second, "The equality operator agrees with Equals.");
        Assert.AreEqual(first.GetHashCode(), second.GetHashCode(), "Equal composites hash alike.");
        Assert.AreNotEqual(first, otherOctets, "Different arm octets are different values.");
        Assert.AreNotEqual(first, otherArm, "The same octets under a different selector are different values.");
        Assert.IsTrue(first != otherArm, "The inequality operator agrees with Equals.");
    }

    /// <summary>
    /// The arm accessors answer only the selected arm: reading the RSA arm of an ECC composite throws
    /// <see cref="InvalidOperationException"/> rather than answering another arm's octets.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.3.2, Table 239</see>.
    /// </summary>
    [TestMethod]
    public void SensitiveCompositeRefusesTheWrongArmAccessor()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmuSensitiveComposite ecc = EccComposite(pool, EccScalar);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECC, ecc.Type, "The composite carries the ECC selector.");
        _ = Assert.ThrowsExactly<InvalidOperationException>(() => ecc.Rsa, "The RSA accessor of an ECC composite throws.");
        _ = Assert.ThrowsExactly<InvalidOperationException>(() => ecc.Bits, "The KEYEDHASH accessor of an ECC composite throws.");
    }

    /// <summary>
    /// Table 241's <c>TPM2B_SENSITIVE</c> with a size of zero is the absent sensitive area — the public-only
    /// form of <c>TPM2_LoadExternal()</c>: it parses to the shared absent instance, frames as the two-octet size
    /// alone, and survives disposal.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.3.3, Table 241</see>.
    /// </summary>
    [TestMethod]
    public void SensitiveFrameOfSizeZeroIsAbsent()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader([0x00, 0x00]);

        Tpm2bSensitive parsed = Tpm2bSensitive.Parse(ref reader, pool);

        Assert.IsTrue(parsed.IsAbsent, "A size of zero carries no sensitive area.");
        Assert.AreSame(Tpm2bSensitive.Absent, parsed, "The absent frame is the shared instance.");
        Assert.AreEqual(sizeof(ushort), parsed.SerializedSize, "The absent frame is its size field alone.");

        byte[] octets = new byte[sizeof(ushort)];
        var writer = new TpmWriter(octets);
        parsed.WriteTo(ref writer);
        Assert.AreSequenceEqual(new byte[] { 0x00, 0x00 }, octets, "The absent frame writes 00 00.");

        parsed.Dispose();
        Assert.IsTrue(Tpm2bSensitive.Absent.IsAbsent, "Disposing the shared absent instance leaves it usable.");
    }

    /// <summary>
    /// "The unmarshaling function validates that size equals the size of the value that is unmarshaled": a
    /// <c>TPM2B_SENSITIVE</c> whose <c>TPMT_SENSITIVE</c> consumes exactly the declared size parses; one
    /// declaring an octet more than the area consumes is refused by that rule; and one declaring an octet less
    /// — a window that cuts the area's last sized field short — is refused by that field's own bound before
    /// the rule is reached. Each refusal releases what it rented.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.3.3, Table 241</see>.
    /// </summary>
    /// <param name="sizeDelta">The octets added to the declared size beyond what the area consumes.</param>
    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(-1)]
    public void SensitiveFrameSizeMustEqualTheUnmarshaledSize(int sizeDelta)
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        byte[] interior;
        using(TpmtSensitive sensitive = KeyedHashSensitive(pool, authValue: null, seedValue: null, SealedData))
        {
            interior = Serialize(sensitive);
        }

        int declared = interior.Length + sizeDelta;
        byte[] frame = new byte[sizeof(ushort) + Math.Max(declared, interior.Length)];
        frame[0] = (byte)(declared >> 8);
        frame[1] = (byte)declared;
        interior.CopyTo(frame, sizeof(ushort));

        long baseline = trackingPool.OutstandingCount;
        if(sizeDelta == 0)
        {
            var reader = new TpmReader(frame);
            using Tpm2bSensitive parsed = Tpm2bSensitive.Parse(ref reader, pool);
            Assert.IsFalse(parsed.IsAbsent, "A frame whose area consumes exactly the declared size parses.");
            Assert.AreEqual(0, reader.Remaining, "The parse consumes exactly the frame.");
            Assert.IsTrue(parsed.SensitiveArea!.Sensitive.Bits.AsReadOnlySpan().SequenceEqual(SealedData), "The area survives the frame.");
        }
        else if(sizeDelta > 0)
        {
            _ = Assert.ThrowsExactly<InvalidOperationException>(() => ParseSensitiveFrame(frame, pool), "A declared size an octet past the unmarshaled size is refused by the size-agreement rule.");
            Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refused frame releases every carrier the inner parse rented.");
        }
        else
        {
            _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => ParseSensitiveFrame(frame, pool), "A declared size an octet short of the unmarshaled size leaves the area's last sized field reaching past the window, which that field refuses.");
            Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refused frame releases every carrier the inner parse rented.");
        }
    }

    /// <summary>
    /// A <c>TPM2B_SENSITIVE</c> declaring more octets than the frame holds is refused before any carrier is
    /// rented — the truncated-frame channel, distinct from the size-agreement rule.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.3.3, Table 241</see>.
    /// </summary>
    [TestMethod]
    public void SensitiveFrameDeclaringPastTheFrameIsRefusedBeforeAnyRental()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        long baseline = trackingPool.RentedCount;

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => ParseSensitiveFrame([0x00, 0x40, 0x00, 0x08, 0x00, 0x00], pool), "A declared size past the frame is refused.");
        Assert.AreEqual(baseline, trackingPool.RentedCount, "The refusal precedes every rental.");
    }

    /// <summary>
    /// Table 196 bounds <c>TPM2B_PRIVATE_KEY_RSA</c> at <c>RSA_PRIVATE_SIZE</c> octets, half the largest modulus
    /// the profile admits: a prime exactly that wide parses and creates, one an octet wider is refused on the
    /// wire and at construction.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.4.8, Table 196</see>.
    /// </summary>
    [TestMethod]
    public void RsaPrimeFactorIsBoundedAtRsaPrivateSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        int bound = Tpm2bPrivateKeyRsa.MaxSize;

        using Tpm2bPrivateKeyRsa atBound = Tpm2bPrivateKeyRsa.Create(Fill(bound, 0xC2), pool);
        Assert.AreEqual(bound, atBound.Length, "A prime at the bound is admitted.");

        byte[] atBoundFrame = new byte[sizeof(ushort) + bound];
        atBoundFrame[0] = (byte)(bound >> 8);
        atBoundFrame[1] = (byte)bound;
        var atBoundReader = new TpmReader(atBoundFrame);
        using Tpm2bPrivateKeyRsa parsedAtBound = Tpm2bPrivateKeyRsa.Parse(ref atBoundReader, pool);
        Assert.AreEqual(bound, parsedAtBound.Length, "A wire prime at the bound parses.");

        int overBound = bound + 1;
        _ = Assert.ThrowsExactly<ArgumentException>(() => Tpm2bPrivateKeyRsa.Create(Fill(overBound, 0xC3), pool), "A prime an octet over the bound is refused at construction.");
        _ = Assert.ThrowsExactly<InvalidOperationException>(() => ParsePrivateKeyRsa([(byte)(overBound >> 8), (byte)overBound], pool), "A wire prime declaring an octet over the bound is refused before its octets are read.");
    }

    /// <summary>
    /// Table 239's arms this union does not model — <c>TPM_ALG_SYMCIPHER</c>, the ML-DSA, hash-ML-DSA and ML-KEM
    /// arms — and a selector no table assigns are refused at the selector, before any carrier is rented.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.3.2, Table 239</see>.
    /// </summary>
    /// <param name="selector">The <c>sensitiveType</c> selector on the wire.</param>
    [TestMethod]
    [DataRow(SymCipherSelector)]
    [DataRow(MlDsaSelector)]
    [DataRow(HashMlDsaSelector)]
    [DataRow(MlKemSelector)]
    [DataRow(UnassignedSelector)]
    public void SensitiveAreaWithAnUnmodeledSelectorIsRefusedBeforeAnyRental(int selector)
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        long baseline = trackingPool.RentedCount;
        byte[] octets = [(byte)(selector >> 8), (byte)selector, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB];

        _ = Assert.ThrowsExactly<NotSupportedException>(() => ParseSensitiveArea(octets, pool), $"Selector 0x{selector:X4} names an arm this union does not model.");
        Assert.AreEqual(baseline, trackingPool.RentedCount, "The refusal precedes every rental, the authValue's included.");
    }

    /// <summary>
    /// Table 90 bounds <c>TPM2B_DIGEST</c> at the largest digest the profile admits ("used for a sized buffer that
    /// cannot be larger than the largest digest produced by any hash algorithm implemented on the TPM"): a
    /// <c>seedValue</c> declaring an octet more than <see cref="Tpm2bDigest.MaxSize"/> is refused, and the
    /// <c>authValue</c> rental the area made before reaching <c>seedValue</c> is released.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 10.3.2, Table 90</see>.
    /// </summary>
    [TestMethod]
    public void SensitiveAreaWithASeedValueOverTheDigestBoundIsRefusedAndReleasesItsRentals()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        int overBound = Tpm2bDigest.MaxSize + 1;
        byte[] seedValueOctets = Fill(overBound, 0x5E);
        byte[] octets =
        [
            0x00, 0x08,
            0x00, 0x04, 0x01, 0x02, 0x03, 0x04,
            (byte)(overBound >> 8), (byte)overBound, .. seedValueOctets,
            0x00, 0x00,
        ];

        long baseline = trackingPool.OutstandingCount;

        _ = Assert.ThrowsExactly<InvalidOperationException>(() => ParseSensitiveArea(octets, pool), "A seedValue an octet over TPM2B_DIGEST's bound is refused.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The refused parse releases the authValue rental it made before reaching seedValue.");
    }

    /// <summary>
    /// A sensitive-carrying type's <c>DebuggerDisplay</c> names only widths and selectors, never the octets a
    /// prime factor, scalar or sealed value holds — metadata-only presentation for a type that stores key
    /// material. Proved as a source scan of the getter body's own text (never a runtime read through
    /// <c>DebuggerDisplay</c>'s private
    /// accessor): <see cref="TpmtSensitive"/>, <see cref="TpmuSensitiveComposite"/>, <see cref="Tpm2bSensitive"/>
    /// and <see cref="Tpm2bPrivateKeyRsa"/> each declare the property as the last member of their file, so its
    /// text runs from its own declaration to the file's closing brace.
    /// </summary>
    [TestMethod]
    public void SensitiveDebuggerDisplaysNameOnlyWidthsNeverTheUnderlyingOctets()
    {
        string repositoryRoot = SourceHygieneScanner.FindRepositoryRoot();
        string[] relativePaths =
        [
            "src/Verifiable.Tpm.Spec/Structures/TpmtSensitive.cs",
            "src/Verifiable.Tpm.Spec/Structures/TpmuSensitiveComposite.cs",
            "src/Verifiable.Tpm.Spec/Structures/Tpm2bSensitive.cs",
            "src/Verifiable.Tpm.Spec/Structures/Tpm2bPrivateKeyRsa.cs",
        ];

        foreach(string relativePath in relativePaths)
        {
            string getterBody = ReadDebuggerDisplayGetterBody(Path.Combine(repositoryRoot, relativePath));

            Assert.IsFalse(
                RawOctetAccessPattern.IsMatch(getterBody),
                $"{relativePath}: DebuggerDisplay must name a width or selector, never the underlying octets, but its getter reads '{getterBody.Trim()}'.");
        }
    }

    /// <summary>
    /// Matches a span, buffer or array accessor that would surface a sensitive carrier's raw octets rather
    /// than a width — the shape <see cref="SensitiveDebuggerDisplaysNameOnlyWidthsNeverTheUnderlyingOctets"/>
    /// bans from a <c>DebuggerDisplay</c> getter body.
    /// </summary>
    private static Regex RawOctetAccessPattern { get; } = new(
        @"AsReadOnlySpan|AsSpan\(|\.Span\b|\.Buffer\b|\.Memory\b|ToArray\(", RegexOptions.Compiled);

    /// <summary>
    /// Extracts the source text of the <c>private string DebuggerDisplay</c> getter declared at
    /// <paramref name="filePath"/>, from its own declaration to the file's final closing brace — the property
    /// is the last member each of this test's four declaring files defines.
    /// </summary>
    /// <param name="filePath">The absolute path of the declaring file.</param>
    /// <returns>The getter's source text.</returns>
    private static string ReadDebuggerDisplayGetterBody(string filePath)
    {
        string text = File.ReadAllText(filePath);
        int start = text.IndexOf("private string DebuggerDisplay", StringComparison.Ordinal);
        Assert.IsGreaterThanOrEqualTo(0, start, $"'{filePath}' must declare a DebuggerDisplay getter.");

        int end = text.LastIndexOf('}');

        return text[start..end];
    }

    /// <summary>Builds a <c>TPMT_SENSITIVE</c> whose arm is the 128-octet RSA prime factor.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="authValue">The authorization value's octets.</param>
    /// <param name="seedValue">The <c>seedValue</c> octets.</param>
    /// <returns>The structure; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the freshly created carriers transfers to the returned structure, which the caller disposes.")]
    private static TpmtSensitive RsaSensitive(BaseMemoryPool pool, byte[] authValue, byte[] seedValue)
    {
        return new TpmtSensitive(Tpm2bAuth.Create(authValue, pool), Tpm2bDigest.Create(seedValue, pool), TpmuSensitiveComposite.FromRsa(Tpm2bPrivateKeyRsa.Create(RsaPrime, pool)));
    }

    /// <summary>Builds a <c>TPMT_SENSITIVE</c> whose arm is an ECC scalar.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="authValue">The authorization value's octets, or <see langword="null"/> for the Empty Buffer.</param>
    /// <param name="seedValue">The <c>seedValue</c> octets, or <see langword="null"/> for the Empty Buffer.</param>
    /// <param name="scalar">The scalar's octets.</param>
    /// <returns>The structure; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the freshly created carriers transfers to the returned structure, which the caller disposes.")]
    private static TpmtSensitive EccSensitive(BaseMemoryPool pool, byte[]? authValue, byte[]? seedValue, byte[] scalar)
    {
        Tpm2bAuth auth = authValue is null ? Tpm2bAuth.CreateEmpty(pool) : Tpm2bAuth.Create(authValue, pool);
        Tpm2bDigest seed = seedValue is null ? Tpm2bDigest.Empty : Tpm2bDigest.Create(seedValue, pool);

        return new TpmtSensitive(auth, seed, TpmuSensitiveComposite.FromEcc(Tpm2bEccParameter.Create(scalar, pool)));
    }

    /// <summary>Builds a <c>TPMT_SENSITIVE</c> in the sealed data object's shape, the KEYEDHASH arm carrying <paramref name="data"/>.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="authValue">The authorization value's octets, or <see langword="null"/> for the Empty Buffer.</param>
    /// <param name="seedValue">The <c>seedValue</c> octets, or <see langword="null"/> for the Empty Buffer.</param>
    /// <param name="data">The sealed octets.</param>
    /// <returns>The structure; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the freshly created carriers transfers to the returned structure, which the caller disposes.")]
    private static TpmtSensitive KeyedHashSensitive(BaseMemoryPool pool, byte[]? authValue, byte[]? seedValue, byte[] data)
    {
        Tpm2bAuth auth = authValue is null ? Tpm2bAuth.CreateEmpty(pool) : Tpm2bAuth.Create(authValue, pool);
        Tpm2bDigest seed = seedValue is null ? Tpm2bDigest.Empty : Tpm2bDigest.Create(seedValue, pool);

        return TpmtSensitive.ForKeyedHash(auth, seed, Tpm2bSensitiveData.Create(data, pool));
    }

    /// <summary>Builds the ECC arm of the union over <paramref name="scalar"/>.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="scalar">The scalar's octets.</param>
    /// <returns>The composite; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the freshly created carrier transfers to the returned composite, which the caller disposes.")]
    private static TpmuSensitiveComposite EccComposite(BaseMemoryPool pool, byte[] scalar)
    {
        return TpmuSensitiveComposite.FromEcc(Tpm2bEccParameter.Create(scalar, pool));
    }

    /// <summary>Builds the KEYEDHASH arm of the union over <paramref name="octets"/>.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="octets">The sensitive octets.</param>
    /// <returns>The composite; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the freshly created carrier transfers to the returned composite, which the caller disposes.")]
    private static TpmuSensitiveComposite BitsComposite(BaseMemoryPool pool, byte[] octets)
    {
        return TpmuSensitiveComposite.FromBits(Tpm2bSensitiveData.Create(octets, pool));
    }

    /// <summary>Parses a <c>TPM2B_SENSITIVE</c> frame and releases whatever it produced, so a refusing parse can be asserted as one expression.</summary>
    /// <param name="frame">The frame's octets.</param>
    /// <param name="pool">The memory pool.</param>
    private static void ParseSensitiveFrame(byte[] frame, BaseMemoryPool pool)
    {
        var reader = new TpmReader(frame);
        using Tpm2bSensitive parsed = Tpm2bSensitive.Parse(ref reader, pool);
    }

    /// <summary>Parses a <c>TPMT_SENSITIVE</c> area and releases whatever it produced, so a refusing parse can be asserted as one expression.</summary>
    /// <param name="octets">The area's octets.</param>
    /// <param name="pool">The memory pool.</param>
    private static void ParseSensitiveArea(byte[] octets, BaseMemoryPool pool)
    {
        var reader = new TpmReader(octets);
        using TpmtSensitive parsed = TpmtSensitive.Parse(ref reader, pool);
    }

    /// <summary>Parses a <c>TPM2B_PRIVATE_KEY_RSA</c> and releases whatever it produced, so a refusing parse can be asserted as one expression.</summary>
    /// <param name="frame">The frame's octets.</param>
    /// <param name="pool">The memory pool.</param>
    private static void ParsePrivateKeyRsa(byte[] frame, BaseMemoryPool pool)
    {
        var reader = new TpmReader(frame);
        using Tpm2bPrivateKeyRsa parsed = Tpm2bPrivateKeyRsa.Parse(ref reader, pool);
    }

    /// <summary>An array of <paramref name="length"/> octets all set to <paramref name="value"/>.</summary>
    /// <param name="length">The width.</param>
    /// <param name="value">The octet.</param>
    /// <returns>The array.</returns>
    private static byte[] Fill(int length, byte value)
    {
        byte[] octets = new byte[length];
        octets.AsSpan().Fill(value);

        return octets;
    }

    /// <summary>Marshals a <c>TPMT_SENSITIVE</c>, no size prefix.</summary>
    /// <param name="sensitive">The structure.</param>
    /// <returns>The octets.</returns>
    private static byte[] Serialize(TpmtSensitive sensitive)
    {
        byte[] octets = new byte[sensitive.SerializedSize];
        var writer = new TpmWriter(octets);
        sensitive.WriteTo(ref writer);

        return octets;
    }

    /// <summary>Writes a <c>TPMT_SENSITIVE</c> out and parses it back, asserting the parse consumed exactly the octets written.</summary>
    /// <param name="original">The structure.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The parsed structure; the caller disposes it.</returns>
    private static TpmtSensitive RoundTrip(TpmtSensitive original, BaseMemoryPool pool)
    {
        byte[] octets = Serialize(original);
        var reader = new TpmReader(octets);
        TpmtSensitive parsed = TpmtSensitive.Parse(ref reader, pool);
        Assert.AreEqual(0, reader.Remaining, "The parse consumes exactly the octets WriteTo produced.");

        return parsed;
    }
}
