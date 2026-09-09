using System;
using Lumoin.Veritas.Cbor;
using Verifiable.Cbor;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// Pins the preset holder <see cref="CborOptions"/> — the one place this library builds its four shared
/// <see cref="CborSerializerOptions"/> instances — against the wire rules each preset stands for, and against
/// the registry-freeze contract the sharing rests on (contract ruling S4-3: one preset holder, no converters
/// registered, never mutated after publication).
/// </summary>
/// <remarks>
/// Two facts are separable and are proven separately here. The first is per-mode policy: what
/// <see cref="CborSerializerOptions.Default(CborConformanceMode)"/> settles for indefinite-length items and
/// for UTF-8 validation, which is the wire rule the mode carries. The second is lifetime: the converter
/// collection stops accepting registrations the moment the first <see cref="CborReader"/> or
/// <see cref="CborWriter"/> is built from an instance, which is what makes a *shared* preset safe to hand to
/// every call site — and what makes a call site needing its own converters or ceilings build its own instance.
/// </remarks>
[TestClass]
internal sealed class CborOptionsTests
{
    /// <summary>
    /// A minimal legal <see cref="CborConverter{T}"/> used only as a registration probe. Neither of its
    /// members ever runs in these tests: the refusal being proven happens inside
    /// <see cref="CborConverterCollection.Add"/>, before any read or write could reach the converter.
    /// </summary>
    private sealed class Int32ProbeConverter: CborConverter<int>
    {
        /// <summary>Writes the value as a CBOR integer.</summary>
        /// <param name="writer">The writer to emit into.</param>
        /// <param name="value">The value to encode.</param>
        public override void Write(CborWriter writer, int value)
        {
            ArgumentNullException.ThrowIfNull(writer);
            writer.WriteInt32(value);
        }


        /// <summary>Reads a CBOR integer.</summary>
        /// <param name="reader">The reader to consume from.</param>
        /// <returns>The decoded value.</returns>
        public override int Read(CborReader reader)
        {
            ArgumentNullException.ThrowIfNull(reader);

            return reader.ReadInt32();
        }
    }


    /// <summary>
    /// The <see cref="CborOptions.Lax"/> preset carries <see cref="CborConformanceMode.Lax"/> and the two
    /// wire policies that mode stands for: indefinite-length items are admissible, and text-string bytes are
    /// taken as given rather than checked for UTF-8 well-formedness.
    /// </summary>
    /// <remarks>
    /// RFC 8949 admits indefinite-length strings, arrays and maps as a first-class encoding
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.2.2">RFC 8949 §3.2.2</see>), and states
    /// that a major-type-3 text string is UTF-8
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 §3.1</see>) while leaving the
    /// decision to *check* that to the decoder — see the discussion of invalid UTF-8 in
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-5.5">RFC 8949 §5.5</see>. The Lax preset is
    /// the deliberate no-checking end of that latitude: it is what this library reads foreign bytes under
    /// when a later stage, not the decoder, owns the judgement.
    /// </remarks>
    [TestMethod]
    public void LaxPresetAllowsIndefiniteLengthAndDoesNotValidateUtf8()
    {
        CborSerializerOptions preset = CborOptions.Lax;

        Assert.AreEqual(CborConformanceMode.Lax, preset.ConformanceMode);
        Assert.IsTrue(preset.AllowIndefiniteLength, "The Lax preset must admit the indefinite-length forms RFC 8949 §3.2.2 defines.");
        Assert.IsFalse(preset.ValidateUtf8, "The Lax preset must not judge text-string bytes; that is the latitude RFC 8949 §5.5 leaves the decoder.");
    }


    /// <summary>
    /// The <see cref="CborOptions.Strict"/> preset carries <see cref="CborConformanceMode.Strict"/>: text
    /// strings are validated as UTF-8, while the indefinite-length forms stay admissible.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 §3.1</see> defines major type 3
    /// as a UTF-8 string, so validating it is a well-formedness question, not a determinism question — which is
    /// exactly why this mode turns validation on without turning the indefinite-length forms
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.2.2">RFC 8949 §3.2.2</see>) off. Contract
    /// ruling S4-4 makes this preset the destination of every mode-less construction the BCL substrate had, so
    /// the pairing pinned here is what those sites now run under.
    /// </remarks>
    [TestMethod]
    public void StrictPresetValidatesUtf8AndStillAllowsIndefiniteLength()
    {
        CborSerializerOptions preset = CborOptions.Strict;

        Assert.AreEqual(CborConformanceMode.Strict, preset.ConformanceMode);
        Assert.IsTrue(preset.AllowIndefiniteLength, "Strict is a well-formedness mode, not a determinism mode: RFC 8949 §3.2.2's forms stay legal under it.");
        Assert.IsTrue(preset.ValidateUtf8, "Strict must check that a major-type-3 string is the UTF-8 RFC 8949 §3.1 says it is.");
    }


    /// <summary>
    /// The <see cref="CborOptions.RfcCanonical"/> preset carries
    /// <see cref="CborConformanceMode.RfcCanonical"/>: indefinite-length items are refused outright and text
    /// strings are validated.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see> states the core
    /// deterministic encoding requirements, among them that indefinite-length items MUST NOT appear — a
    /// definite-length encoding of the same data is always available and is the only admissible one. Refusing
    /// the form at the options level, rather than at each read, is what makes that MUST hold for every reader
    /// and writer built from this preset.
    /// </remarks>
    [TestMethod]
    public void RfcCanonicalPresetRefusesIndefiniteLengthAndValidatesUtf8()
    {
        CborSerializerOptions preset = CborOptions.RfcCanonical;

        Assert.AreEqual(CborConformanceMode.RfcCanonical, preset.ConformanceMode);
        Assert.IsFalse(preset.AllowIndefiniteLength, "RFC 8949 §4.2.1 forbids indefinite-length items in a deterministic encoding.");
        Assert.IsTrue(preset.ValidateUtf8, "A deterministic encoding of a major-type-3 string presupposes the string is valid UTF-8 (RFC 8949 §3.1).");
    }


    /// <summary>
    /// The <see cref="CborOptions.Ctap2Canonical"/> preset carries
    /// <see cref="CborConformanceMode.Ctap2Canonical"/>: indefinite-length items are refused and text strings
    /// are validated, as the CTAP2 canonical CBOR encoding form requires.
    /// </summary>
    /// <remarks>
    /// The CTAP2 canonical CBOR encoding form
    /// (<see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#ctap2-canonical-cbor-encoding-form">FIDO
    /// CTAP §6, canonical CBOR encoding form</see>) states that indefinite-length items must be made into
    /// definite-length items — the same prohibition
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see> carries, arrived
    /// at independently. This preset is the one every FIDO2/CTAP2 reader and writer in this library rides, so
    /// the prohibition being a property of the preset — not of each call site — is the load-bearing fact.
    /// </remarks>
    [TestMethod]
    public void Ctap2CanonicalPresetRefusesIndefiniteLengthAndValidatesUtf8()
    {
        CborSerializerOptions preset = CborOptions.Ctap2Canonical;

        Assert.AreEqual(CborConformanceMode.Ctap2Canonical, preset.ConformanceMode);
        Assert.IsFalse(preset.AllowIndefiniteLength, "The CTAP2 canonical form requires indefinite-length items be made definite-length.");
        Assert.IsTrue(preset.ValidateUtf8, "The CTAP2 canonical form is a deterministic form, which presupposes well-formed UTF-8 text strings.");
    }


    /// <summary>
    /// A freshly built <see cref="CborSerializerOptions"/> accepts converter registrations, and stops
    /// accepting them the moment the first <see cref="CborReader"/> is constructed from it — the before/after
    /// flip of <see cref="CborConverterCollection.IsReadOnly"/> on one and the same instance.
    /// </summary>
    /// <remarks>
    /// This is the mechanism the preset-sharing contract of ruling S4-3 rests on, so it is proven on a fresh
    /// instance rather than on a preset: a preset that any earlier test or call site has already used would
    /// show only the post-flip half, which cannot distinguish "froze on construction" from "was always
    /// frozen". The single byte handed to the reader is the CBOR unsigned integer 1
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 §3.1</see>, major type 0,
    /// additional information 1); it is never read — construction alone is the event under test.
    /// </remarks>
    [TestMethod]
    public void AFreshOptionsInstanceFreezesItsConverterCollectionOnTheFirstReaderConstruction()
    {
        CborSerializerOptions options = CborSerializerOptions.Default(CborConformanceMode.Strict);

        Assert.IsFalse(options.Converters.IsReadOnly, "An options instance no reader or writer has been built from must still accept registrations.");

        _ = new CborReader(new byte[] { 0x01 }, options);

        Assert.IsTrue(options.Converters.IsReadOnly, "The first reader construction must close registration on the instance it was built from.");
    }


    /// <summary>
    /// The freeze is a property of the shared instance, not of the reader that caused it: after one
    /// <see cref="CborReader"/> is built from each preset, every other holder of that same preset observes
    /// the closed collection through <see cref="CborOptions"/> itself.
    /// </summary>
    /// <remarks>
    /// This is what ruling S4-3's "never mutate a preset" warning is about. The presets are static shared
    /// state; the first reader or writer anywhere in the process closes registration for the whole process,
    /// so a call site that discovers it needs a converter cannot add one to a preset after the fact — it must
    /// build its own <see cref="CborSerializerOptions.Default(CborConformanceMode)"/> instance. The test
    /// causes the freeze itself rather than assuming some earlier test did, so it holds in any run order and
    /// when run alone.
    /// </remarks>
    [TestMethod]
    public void EveryHolderOfASharedPresetObservesTheFreezeCausedByOneReader()
    {
        _ = new CborReader(new byte[] { 0x01 }, CborOptions.Lax);
        _ = new CborReader(new byte[] { 0x01 }, CborOptions.Strict);
        _ = new CborReader(new byte[] { 0x01 }, CborOptions.RfcCanonical);
        _ = new CborReader(new byte[] { 0x01 }, CborOptions.Ctap2Canonical);

        Assert.IsTrue(CborOptions.Lax.Converters.IsReadOnly, "The Lax preset is shared state: one reader closes it for every holder.");
        Assert.IsTrue(CborOptions.Strict.Converters.IsReadOnly, "The Strict preset is shared state: one reader closes it for every holder.");
        Assert.IsTrue(CborOptions.RfcCanonical.Converters.IsReadOnly, "The RfcCanonical preset is shared state: one reader closes it for every holder.");
        Assert.IsTrue(CborOptions.Ctap2Canonical.Converters.IsReadOnly, "The Ctap2Canonical preset is shared state: one reader closes it for every holder.");
    }


    /// <summary>
    /// Registering a converter on an options instance a reader has already been built from is refused with
    /// <see cref="InvalidOperationException"/>, and the collection is left unchanged.
    /// </summary>
    /// <remarks>
    /// The refusal is what makes a shared preset safe rather than merely conventional: a late registration
    /// cannot silently change how every other holder of the instance decodes. It is a caller-protocol fault
    /// rather than a wire fault, so it is an <see cref="InvalidOperationException"/> and not a member of the
    /// <see cref="CborException"/> family — the same taxonomy split ruling S4-6 keeps on the read side. The
    /// count assertion is the adversarial half: a refusal that still mutated the list would leave the shared
    /// preset in a state no holder agreed to.
    /// </remarks>
    [TestMethod]
    public void RegisteringAConverterAfterTheFreezeIsRefusedAndChangesNothing()
    {
        CborSerializerOptions options = CborSerializerOptions.Default(CborConformanceMode.Lax);
        _ = new CborReader(new byte[] { 0x01 }, options);
        int countBeforeTheAttempt = options.Converters.Count;

        _ = Assert.ThrowsExactly<InvalidOperationException>(() => options.Converters.Add(new Int32ProbeConverter()));

        Assert.AreEqual(countBeforeTheAttempt, options.Converters.Count, "A refused registration must not reach the list.");
        Assert.IsFalse(options.TryGetConverter(typeof(int), out _), "A refused registration must not become reachable through lookup.");
    }
}
