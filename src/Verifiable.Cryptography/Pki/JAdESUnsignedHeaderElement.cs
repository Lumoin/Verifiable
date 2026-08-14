using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The whole-array incorporation mode of a JAdES <c>etsiU</c> unsigned-component array, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 5.3.1</see> — this library's reading: "The content of any element of the
/// <c>etsiU</c> array shall be either an
/// unsigned JSON value in clear (clear JSON incorporation), or its base64url encoding (base64url
/// incorporation)" (JA-5.3.1-09), and "the array shall not contain JSON values in clear in some positions, and
/// base64url encoded unsigned JSON values in others" (JA-5.3.1-10/-11) — the duality is a WHOLE-ARRAY fact,
/// never a per-element one. <see cref="JAdESUnsignedHeaders.Mode"/> carries the declared value for a whole
/// container; <see cref="JAdESUnsignedHeaderElement.DeclaredMode"/> carries what a single element self-reports
/// (or <see langword="null"/> when the element's own carrier is mode-agnostic — see that member's remarks).
/// </summary>
public enum JAdESEtsiUIncorporationMode
{
    /// <summary>
    /// Base64url incorporation (JA-5.3.1-09): each <c>etsiU</c> array element is the element's own base64url
    /// encoding, carried as an opaque, byte-exact string — the message-imprint algorithm (clause 5.3.6.2.3)
    /// concatenates this text verbatim, with no canonicalization step.
    /// </summary>
    Base64Url,

    /// <summary>
    /// Clear JSON incorporation (JA-5.3.1-09): each <c>etsiU</c> array element is an unsigned JSON value in
    /// clear — the message-imprint algorithm (clause 5.3.6.2.4) canonicalizes each element before hashing.
    /// </summary>
    ClearJson
}


/// <summary>
/// The DUAL-MODE carrier for one <c>etsiU</c> array element's payload, per this library's reading: either the
/// element's base64url TEXT, byte-exact and unmodified (the
/// text itself IS the message-imprint input under base64url incorporation — clause 5.3.6.2.3 step 7), or the
/// element's decoded semantic value (safe to canonicalize under clear-JSON incorporation — clause 5.3.6.2.4
/// step 7b — since that reading establishes that branch needs canonical-form exactness, not raw-byte
/// preservation). A DU-ready closed sum: no external type may derive from it.
/// </summary>
/// <typeparam name="TValue">The decoded semantic shape this element carries when incorporated in clear.</typeparam>
/// <remarks>
/// <para>
/// <strong>The "canonAlg route".</strong> When <typeparamref name="TValue"/> is <see cref="AdESTimestampContainer"/>
/// (the <c>sigTst</c>/<c>arcTst</c> kinds), the canonicalization-algorithm identifier clause 5.3.6.2.4 step 7b
/// applies is already exposed as <see cref="AdESTimestampContainer.CanonAlg"/> on the decoded value itself — no
/// separate field is needed here. Kinds whose own schema carries no <c>canonAlg</c> member (<c>xVals</c>,
/// <c>rVals</c>, <c>axVals</c>, <c>arVals</c>, <c>anyValData</c>, <c>tstVD</c>, <c>sigPSt</c>) simply have no
/// such route to expose.
/// </para>
/// <para>
/// <strong>§1.4 discipline: decode-for-inspection is not
/// decode-then-re-encode.</strong> This library's own base64url-incorporation reading forbids re-deriving the
/// message-imprint input from a decoded-then-re-serialized value — it never forbade DECODING for inspection
/// alongside the untouched wire text. <see cref="JAdESOpaqueUnsignedValue{TValue}.WireText"/> is the ONLY
/// imprint input, always; <see cref="JAdESOpaqueUnsignedValue{TValue}.DecodedValue"/> is a read-only VIEW
/// carried beside it for structural/CMS inspection, never re-encoded back onto the wire and never consulted by
/// any message-imprint builder (<c>JAdESMessageImprints</c>'s own opaque builders concatenate
/// <see cref="JAdESOpaqueUnsignedValue{TValue}.WireText"/> exclusively).
/// </para>
/// </remarks>
public abstract class JAdESUnsignedValue<TValue>
{
    /// <summary>Restricts direct subtyping to the sibling types declared in this file.</summary>
    private protected JAdESUnsignedValue()
    {
    }
}


/// <summary>
/// The base64url-opaque arm of <see cref="JAdESUnsignedValue{TValue}"/>: <see cref="WireText"/> is the
/// element's own wire TEXT, byte-exact — the ONLY message-imprint input under base64url incorporation
/// (JA-5.3.6.2.3-11, "concatenate all the elements in <c>etsiU</c> JSON array... in the order of appearance");
/// <see cref="DecodedValue"/> is a decode-for-INSPECTION view carried beside it (the §1.4 discipline —
/// see the type remarks on <see cref="JAdESUnsignedValue{TValue}"/>), never re-encoded and never an imprint
/// input. A design that decoded <see cref="WireText"/> and later RE-ENCODED that decoded form for the imprint
/// would be unsafe, since JSON has no canonical serialization (the whole reason this arm preserves wire text at all) — <see cref="WireText"/>
/// exists precisely to avoid that round trip; <see cref="DecodedValue"/> exists to avoid the OPPOSITE mistake
/// of leaving a base64url-incorporated signature structurally unreadable.
/// </summary>
/// <typeparam name="TValue">The decoded semantic shape this element also carries under clear-JSON incorporation.</typeparam>
[DebuggerDisplay("JAdESOpaqueUnsignedValue({WireText.Length} bytes)")]
public sealed class JAdESOpaqueUnsignedValue<TValue>: JAdESUnsignedValue<TValue>, IDisposable
{
    /// <summary>Initializes a new <see cref="JAdESOpaqueUnsignedValue{TValue}"/>.</summary>
    /// <param name="wireText">
    /// The element's own wire TEXT, pool-owned. <strong>Owned</strong> — <see cref="Dispose"/> returns it to its
    /// pool. The ONLY message-imprint input this arm ever contributes.
    /// </param>
    /// <param name="decodedValue">
    /// The element's own content, base64url-decoded and JSON-parsed into the SAME typed model the clear arm holds
    /// — a read-for-inspection view, never re-encoded, never an imprint input.
    /// <strong>Owned</strong> when it implements <see cref="IDisposable"/>.
    /// </param>
    public JAdESOpaqueUnsignedValue(PooledMemory wireText, TValue decodedValue)
    {
        WireText = wireText;
        DecodedValue = decodedValue;
    }

    /// <summary>
    /// The element's own wire TEXT, pool-owned. <strong>Owned</strong> — <see cref="Dispose"/> returns it to its
    /// pool. The ONLY message-imprint input this arm ever contributes.
    /// </summary>
    public PooledMemory WireText { get; }

    /// <summary>
    /// The element's own content, base64url-decoded and JSON-parsed into the SAME typed model the clear arm holds
    /// — a read-for-inspection view, never re-encoded, never an imprint input.
    /// <strong>Owned</strong> when it implements <see cref="IDisposable"/>.
    /// </summary>
    public TValue DecodedValue { get; }

    /// <summary>Disposes <see cref="WireText"/> and, when it implements <see cref="IDisposable"/>, <see cref="DecodedValue"/>.</summary>
    public void Dispose()
    {
        WireText.Dispose();
        if(DecodedValue is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}


/// <summary>
/// The clear-JSON arm of <see cref="JAdESUnsignedValue{TValue}"/>: <see cref="Value"/> is the element's decoded
/// semantic value, safe to canonicalize (clause 5.3.6.2.4 step 7b) rather than needing raw-byte preservation
/// (the same reasoning the opaque arm's own remarks state).
/// </summary>
/// <typeparam name="TValue">The decoded semantic shape.</typeparam>
[DebuggerDisplay("JAdESClearUnsignedValue: {Value}")]
public sealed class JAdESClearUnsignedValue<TValue>: JAdESUnsignedValue<TValue>, IDisposable
{
    /// <summary>Initializes a new <see cref="JAdESClearUnsignedValue{TValue}"/>.</summary>
    /// <param name="value">The decoded value. <strong>Owned</strong> when it implements <see cref="IDisposable"/>.</param>
    public JAdESClearUnsignedValue(TValue value)
    {
        Value = value;
    }

    /// <summary>The decoded value. <strong>Owned</strong> when it implements <see cref="IDisposable"/>.</summary>
    public TValue Value { get; }

    /// <summary>Disposes <see cref="Value"/> when it implements <see cref="IDisposable"/>; otherwise a no-op.</summary>
    public void Dispose()
    {
        if(Value is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}


/// <summary>
/// One element of the <c>etsiU</c> JSON array (clause 5.3.1) — the closed sum of every kind of value an
/// <see cref="JAdESUnsignedHeaders"/> container may carry, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>, clause 5.3.1's own enumeration. A DU-ready closed sum: no external type may
/// derive from it.
/// </summary>
/// <remarks>
/// <para>
/// Seventeen arms: the ten clause 5.3.1 names (<c>sigPSt</c>, <c>cSig</c>, <c>sigTst</c>, <c>xVals</c>,
/// <c>rVals</c>, <c>axVals</c>, <c>arVals</c>, <c>anyValData</c>, <c>tstVD</c>, <c>arcTst</c>), the six Annex A
/// kinds (FIRST-CLASS arms, not folded into the unknown
/// catch-all): <c>xRefs</c>/<c>rRefs</c>/<c>axRefs</c>/<c>arRefs</c> (reference-kind arms modeling their Annex A
/// shapes minimally, <see cref="JAdESCertificateReferenceCollection"/>/<see cref="JAdESRevocationReferenceCollection"/>)
/// and <c>sigRTst</c>/<c>rfsTst</c> (<c>tstContainer</c>-typed arms, the same shape as <c>sigTst</c>/<c>arcTst</c>),
/// plus the unknown-label catch-all (the extension point clause 5.3.1's own text names — JA-5.3.1-13 — mirroring
/// CB-AdES's Annex-E analog; JAdES's own analog is Annex D).
/// </para>
/// <para>
/// <strong><c>cSig</c> stays WireText-only at the model layer; its decoded view is an on-demand seam,
/// not a stored field.</strong> Unlike the other nine named kinds, <see cref="JAdESUnsignedHeaderElementCounterSignature"/>
/// has NO <see cref="JAdESUnsignedValue{TValue}"/> duality of its own — it always carries
/// <see cref="JAdESUnsignedHeaderElementCounterSignature.WireText"/> verbatim, regardless of the enclosing
/// container's <see cref="JAdESUnsignedHeaders.Mode"/> (that text is base64url when the container is
/// <see cref="JAdESEtsiUIncorporationMode.Base64Url"/>, or the element's own raw clear-JSON text when the
/// container is <see cref="JAdESEtsiUIncorporationMode.ClearJson"/>) — this project's leaf-layering rule
/// (<c>Verifiable.Cryptography</c> may not reference <c>Verifiable.JCose</c>, where the nested JWS/JAdES
/// message type this element's own countersignature decodes into is defined) keeps a decoded view OFF this
/// type. <c>Verifiable.JCose</c> supplies the decode capability as a separate, composable seam instead —
/// <c>Verifiable.JCose.TryDecodeJAdESCounterSignatureDelegate</c> (bound in <c>Verifiable.Json</c> as
/// <c>JAdESCounterSignatureJson.TryDecode</c>), consumed on demand by
/// <c>Verifiable.JCose.JAdESLevelRules.CheckCounterSignaturesAsync</c> — the countersignature verbs
/// themselves live in <c>Verifiable.JCose.JAdESCounterSign</c> (clause 5.3.2). <see cref="JAdESUnsignedHeaderElementUnknown"/>
/// keeps the identical WireText-only shape for a different reason: an unrecognized kind's structure is not
/// this library's to claim at all (Annex D's own extension point,
/// <see cref="JAdESAlternativeMechanismDisclosureRegistry"/>).
/// </para>
/// <para>
/// <see cref="Kind"/> exposes each concrete sibling's <c>etsiU</c> JSON key polymorphically (mirroring
/// <c>CBAdESUnsignedHeaderElement.Label</c>), so a caller walking a <see cref="JAdESUnsignedHeaders"/> instance
/// never needs its own type-to-key switch. <see cref="DeclaredMode"/> exposes what THIS element's own carrier
/// self-reports about the container's whole-array duality — <see langword="null"/> for the two
/// mode-agnostic arms (<c>cSig</c>, unknown), which never decode regardless of mode and so cannot self-report
/// one.
/// </para>
/// </remarks>
public abstract class JAdESUnsignedHeaderElement
{
    /// <summary>The <c>sigPSt</c> arm's <c>etsiU</c> JSON key (clause 5.3.1 enumeration item 1).</summary>
    public const string SignaturePolicyStoreKind = "sigPSt";

    /// <summary>The <c>cSig</c> arm's <c>etsiU</c> JSON key (clause 5.3.1 enumeration item 2).</summary>
    public const string CounterSignatureKind = "cSig";

    /// <summary>The <c>sigTst</c> arm's <c>etsiU</c> JSON key (clause 5.3.1 enumeration item 3).</summary>
    public const string SignatureTimestampKind = "sigTst";

    /// <summary>The <c>xVals</c> arm's <c>etsiU</c> JSON key (clause 5.3.1 enumeration item 4).</summary>
    public const string CertificateValuesKind = "xVals";

    /// <summary>The <c>rVals</c> arm's <c>etsiU</c> JSON key (clause 5.3.1 enumeration item 5).</summary>
    public const string RevocationValuesKind = "rVals";

    /// <summary>The <c>axVals</c> arm's <c>etsiU</c> JSON key (clause 5.3.1 enumeration item 6).</summary>
    public const string AttributeCertificateValuesKind = "axVals";

    /// <summary>The <c>arVals</c> arm's <c>etsiU</c> JSON key (clause 5.3.1 enumeration item 7).</summary>
    public const string AttributeRevocationValuesKind = "arVals";

    /// <summary>The <c>anyValData</c> arm's <c>etsiU</c> JSON key (clause 5.3.1 enumeration item 8).</summary>
    public const string AnyValidationDataKind = "anyValData";

    /// <summary>The <c>tstVD</c> arm's <c>etsiU</c> JSON key (clause 5.3.1 enumeration item 9).</summary>
    public const string TimestampValidationDataKind = "tstVD";

    /// <summary>The <c>arcTst</c> arm's <c>etsiU</c> JSON key (clause 5.3.1 enumeration item 10).</summary>
    public const string ArchiveTimestampKind = "arcTst";

    /// <summary>The <c>xRefs</c> arm's <c>etsiU</c> JSON key (Annex A.1.1).</summary>
    public const string CertificateReferencesKind = "xRefs";

    /// <summary>The <c>rRefs</c> arm's <c>etsiU</c> JSON key (Annex A.1.2).</summary>
    public const string RevocationReferencesKind = "rRefs";

    /// <summary>The <c>axRefs</c> arm's <c>etsiU</c> JSON key (Annex A.1.3).</summary>
    public const string AttributeCertificateReferencesKind = "axRefs";

    /// <summary>The <c>arRefs</c> arm's <c>etsiU</c> JSON key (Annex A.1.4).</summary>
    public const string AttributeRevocationReferencesKind = "arRefs";

    /// <summary>The <c>sigRTst</c> arm's <c>etsiU</c> JSON key (Annex A.1.5.1).</summary>
    public const string SignatureAndReferencesTimestampKind = "sigRTst";

    /// <summary>The <c>rfsTst</c> arm's <c>etsiU</c> JSON key (Annex A.1.5.2).</summary>
    public const string ReferencesTimestampKind = "rfsTst";

    /// <summary>Restricts direct subtyping to the sibling types declared in this file.</summary>
    private protected JAdESUnsignedHeaderElement()
    {
    }


    /// <summary>
    /// Gets this element's <c>etsiU</c> JSON key: one of this type's own <c>Kind</c> constants for the ten
    /// named arms, or the free-form label a <see cref="JAdESUnsignedHeaderElementUnknown"/> catch-all entry
    /// carries.
    /// </summary>
    public abstract string Kind { get; }

    /// <summary>
    /// Gets what this element's own carrier self-reports about the enclosing container's whole-array
    /// incorporation mode: <see cref="JAdESEtsiUIncorporationMode.Base64Url"/> when this element
    /// carries opaque wire text as its imprint-relevant payload, <see cref="JAdESEtsiUIncorporationMode.ClearJson"/>
    /// when it carries a decoded semantic value, or <see langword="null"/> for the two mode-agnostic arms
    /// (<c>cSig</c>, unknown) that always carry opaque wire text regardless of the container's declared mode —
    /// see the type remarks.
    /// </summary>
    public abstract JAdESEtsiUIncorporationMode? DeclaredMode { get; }
}


/// <summary>
/// The <c>sigPSt</c> arm (clause 5.3.1 enumeration item 1, clause 5.3.3): one <see cref="JAdESSignaturePolicyStore"/>
/// incorporated as an element of <see cref="JAdESUnsignedHeaders"/>, dual-mode per
/// <see cref="JAdESUnsignedValue{TValue}"/>.
/// </summary>
[DebuggerDisplay("JAdESUnsignedHeaderElementSignaturePolicyStore: {Carriage}")]
public sealed class JAdESUnsignedHeaderElementSignaturePolicyStore    : JAdESUnsignedHeaderElement, IDisposable
{
    /// <summary>Initializes a new <see cref="JAdESUnsignedHeaderElementSignaturePolicyStore"/>.</summary>
    /// <param name="carriage">The dual-mode carriage: opaque wire text, or the decoded signature-policy store.</param>
    public JAdESUnsignedHeaderElementSignaturePolicyStore(JAdESUnsignedValue<JAdESSignaturePolicyStore> carriage)
    {
        Carriage = carriage;
    }

    /// <summary>The dual-mode carriage: opaque wire text, or the decoded signature-policy store.</summary>
    public JAdESUnsignedValue<JAdESSignaturePolicyStore> Carriage { get; }

    /// <summary>Gets <see cref="JAdESUnsignedHeaderElement.SignaturePolicyStoreKind"/> (<c>sigPSt</c>).</summary>
    public override string Kind => SignaturePolicyStoreKind;

    /// <inheritdoc/>
    public override JAdESEtsiUIncorporationMode? DeclaredMode =>
        Carriage is JAdESOpaqueUnsignedValue<JAdESSignaturePolicyStore> ? JAdESEtsiUIncorporationMode.Base64Url : JAdESEtsiUIncorporationMode.ClearJson;

    /// <summary>Disposes <see cref="Carriage"/>.</summary>
    public void Dispose()
    {
        if(Carriage is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}


/// <summary>
/// The <c>cSig</c> arm (clause 5.3.1 enumeration item 2, clause 5.3.2): a countersignature of the JAdES
/// signature, carried OPAQUE — see the family remarks on <see cref="JAdESUnsignedHeaderElement"/>
/// for why this arm has no <see cref="JAdESUnsignedValue{TValue}"/> duality of its own.
/// </summary>
[DebuggerDisplay("JAdESUnsignedHeaderElementCounterSignature({WireText.Length} bytes)")]
public sealed class JAdESUnsignedHeaderElementCounterSignature    : JAdESUnsignedHeaderElement, IDisposable
{
    /// <summary>Initializes a new <see cref="JAdESUnsignedHeaderElementCounterSignature"/>.</summary>
    /// <param name="wireText">
    /// The element's own wire TEXT, pool-owned — base64url when the container is
    /// <see cref="JAdESEtsiUIncorporationMode.Base64Url"/>, or this element's own raw clear-JSON text when the
    /// container is <see cref="JAdESEtsiUIncorporationMode.ClearJson"/>.
    /// </param>
    public JAdESUnsignedHeaderElementCounterSignature(PooledMemory wireText)
    {
        WireText = wireText;
    }

    /// <summary>
    /// The element's own wire TEXT, pool-owned — base64url when the container is
    /// <see cref="JAdESEtsiUIncorporationMode.Base64Url"/>, or this element's own raw clear-JSON text when the
    /// container is <see cref="JAdESEtsiUIncorporationMode.ClearJson"/>.
    /// </summary>
    public PooledMemory WireText { get; }

    /// <summary>Gets <see cref="JAdESUnsignedHeaderElement.CounterSignatureKind"/> (<c>cSig</c>).</summary>
    public override string Kind => CounterSignatureKind;

    /// <summary>Always <see langword="null"/> — <c>cSig</c> is mode-agnostic here.</summary>
    public override JAdESEtsiUIncorporationMode? DeclaredMode => null;

    /// <summary>Disposes <see cref="WireText"/>, returning its pooled buffer.</summary>
    public void Dispose() => WireText.Dispose();
}


/// <summary>
/// The <c>sigTst</c> arm (clause 5.3.1 enumeration item 3, clause 5.3.4): one or more electronic time-stamps
/// time-stamping the JWS Signature Value, dual-mode per <see cref="JAdESUnsignedValue{TValue}"/>.
/// </summary>
/// <remarks>
/// <strong>JA-5.3.4-05, enforced at construction.</strong> "The <c>sigTst</c> JSON object shall not contain the
/// <c>canonAlg</c> member" — an unconditional prohibition (unlike <c>arcTst</c>'s own container-mode-dependent
/// rule, JA-5.3.1-14, which this element cannot check on its own — see <see cref="JAdESUnsignedHeaderElementArchiveTimestamp"/>).
/// Checked directly on a clear-mode <paramref name="Carriage"/>'s decoded <see cref="AdESTimestampContainer.CanonAlg"/>;
/// an opaque-mode carriage is not decoded, so nothing to check.
/// </remarks>
/// <param name="Carriage">The dual-mode carriage: opaque wire text, or the decoded time-stamp container.</param>
[DebuggerDisplay("JAdESUnsignedHeaderElementSignatureTimestamp: {Carriage}")]
public sealed class JAdESUnsignedHeaderElementSignatureTimestamp: JAdESUnsignedHeaderElement, IDisposable
{
    /// <summary>
    /// Initializes a new <see cref="JAdESUnsignedHeaderElementSignatureTimestamp"/>.
    /// </summary>
    /// <param name="carriage">The dual-mode carriage.</param>
    /// <exception cref="ArgumentNullException"><paramref name="carriage"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="carriage"/> is a clear-mode carriage whose decoded value carries a non-null
    /// <see cref="AdESTimestampContainer.CanonAlg"/> (JA-5.3.4-05).
    /// </exception>
    public JAdESUnsignedHeaderElementSignatureTimestamp(JAdESUnsignedValue<AdESTimestampContainer> carriage)
    {
        ArgumentNullException.ThrowIfNull(carriage);

        if(carriage is JAdESClearUnsignedValue<AdESTimestampContainer> clear && clear.Value.CanonAlg is not null)
        {
            throw new ArgumentException(
                "The sigTst JSON object shall not contain the canonAlg member (ETSI TS 119 182-1 V1.2.1, clause 5.3.4, JA-5.3.4-05).",
                nameof(carriage));
        }

        Carriage = carriage;
    }


    /// <summary>Gets the dual-mode carriage.</summary>
    public JAdESUnsignedValue<AdESTimestampContainer> Carriage { get; }

    /// <summary>Gets <see cref="JAdESUnsignedHeaderElement.SignatureTimestampKind"/> (<c>sigTst</c>).</summary>
    public override string Kind => SignatureTimestampKind;

    /// <inheritdoc/>
    public override JAdESEtsiUIncorporationMode? DeclaredMode =>
        Carriage is JAdESOpaqueUnsignedValue<AdESTimestampContainer> ? JAdESEtsiUIncorporationMode.Base64Url : JAdESEtsiUIncorporationMode.ClearJson;

    /// <summary>Disposes <see cref="Carriage"/>.</summary>
    public void Dispose()
    {
        if(Carriage is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}


/// <summary>
/// The <c>xVals</c> arm (clause 5.3.1 enumeration item 4, clause 5.3.5.2): certificate values, dual-mode per
/// <see cref="JAdESUnsignedValue{TValue}"/>.
/// </summary>
[DebuggerDisplay("JAdESUnsignedHeaderElementCertificateValues: {Carriage}")]
public sealed class JAdESUnsignedHeaderElementCertificateValues    : JAdESUnsignedHeaderElement, IDisposable
{
    /// <summary>Initializes a new <see cref="JAdESUnsignedHeaderElementCertificateValues"/>.</summary>
    /// <param name="carriage">The dual-mode carriage: opaque wire text, or the decoded certificate values.</param>
    public JAdESUnsignedHeaderElementCertificateValues(JAdESUnsignedValue<JAdESCertificateValues> carriage)
    {
        Carriage = carriage;
    }

    /// <summary>The dual-mode carriage: opaque wire text, or the decoded certificate values.</summary>
    public JAdESUnsignedValue<JAdESCertificateValues> Carriage { get; }

    /// <summary>Gets <see cref="JAdESUnsignedHeaderElement.CertificateValuesKind"/> (<c>xVals</c>).</summary>
    public override string Kind => CertificateValuesKind;

    /// <inheritdoc/>
    public override JAdESEtsiUIncorporationMode? DeclaredMode =>
        Carriage is JAdESOpaqueUnsignedValue<JAdESCertificateValues> ? JAdESEtsiUIncorporationMode.Base64Url : JAdESEtsiUIncorporationMode.ClearJson;

    /// <summary>Disposes <see cref="Carriage"/>.</summary>
    public void Dispose()
    {
        if(Carriage is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}


/// <summary>
/// The <c>rVals</c> arm (clause 5.3.1 enumeration item 5, clause 5.3.5.3): revocation values, dual-mode per
/// <see cref="JAdESUnsignedValue{TValue}"/>.
/// </summary>
[DebuggerDisplay("JAdESUnsignedHeaderElementRevocationValues: {Carriage}")]
public sealed class JAdESUnsignedHeaderElementRevocationValues    : JAdESUnsignedHeaderElement, IDisposable
{
    /// <summary>Initializes a new <see cref="JAdESUnsignedHeaderElementRevocationValues"/>.</summary>
    /// <param name="carriage">The dual-mode carriage: opaque wire text, or the decoded revocation values.</param>
    public JAdESUnsignedHeaderElementRevocationValues(JAdESUnsignedValue<JAdESRevocationValues> carriage)
    {
        Carriage = carriage;
    }

    /// <summary>The dual-mode carriage: opaque wire text, or the decoded revocation values.</summary>
    public JAdESUnsignedValue<JAdESRevocationValues> Carriage { get; }

    /// <summary>Gets <see cref="JAdESUnsignedHeaderElement.RevocationValuesKind"/> (<c>rVals</c>).</summary>
    public override string Kind => RevocationValuesKind;

    /// <inheritdoc/>
    public override JAdESEtsiUIncorporationMode? DeclaredMode =>
        Carriage is JAdESOpaqueUnsignedValue<JAdESRevocationValues> ? JAdESEtsiUIncorporationMode.Base64Url : JAdESEtsiUIncorporationMode.ClearJson;

    /// <summary>Disposes <see cref="Carriage"/>.</summary>
    public void Dispose()
    {
        if(Carriage is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}


/// <summary>
/// The <c>axVals</c> arm (clause 5.3.1 enumeration item 6, clause 5.3.5.4): certificate values for attribute
/// certificates/signed assertions, dual-mode per <see cref="JAdESUnsignedValue{TValue}"/>. Reuses
/// <see cref="JAdESCertificateValues"/>, the same shared shape <c>xVals</c> uses (Annex B.1 schema
/// <c>"axVals": {"$ref": "#/definitions/xVals"}</c>) — this arm's own type identity, not its value shape, is
/// what distinguishes it from <see cref="JAdESUnsignedHeaderElementCertificateValues"/>.
/// </summary>
[DebuggerDisplay("JAdESUnsignedHeaderElementAttributeCertificateValues: {Carriage}")]
public sealed class JAdESUnsignedHeaderElementAttributeCertificateValues    : JAdESUnsignedHeaderElement, IDisposable
{
    /// <summary>Initializes a new <see cref="JAdESUnsignedHeaderElementAttributeCertificateValues"/>.</summary>
    /// <param name="carriage">The dual-mode carriage: opaque wire text, or the decoded certificate values.</param>
    public JAdESUnsignedHeaderElementAttributeCertificateValues(JAdESUnsignedValue<JAdESCertificateValues> carriage)
    {
        Carriage = carriage;
    }

    /// <summary>The dual-mode carriage: opaque wire text, or the decoded certificate values.</summary>
    public JAdESUnsignedValue<JAdESCertificateValues> Carriage { get; }

    /// <summary>Gets <see cref="JAdESUnsignedHeaderElement.AttributeCertificateValuesKind"/> (<c>axVals</c>).</summary>
    public override string Kind => AttributeCertificateValuesKind;

    /// <inheritdoc/>
    public override JAdESEtsiUIncorporationMode? DeclaredMode =>
        Carriage is JAdESOpaqueUnsignedValue<JAdESCertificateValues> ? JAdESEtsiUIncorporationMode.Base64Url : JAdESEtsiUIncorporationMode.ClearJson;

    /// <summary>Disposes <see cref="Carriage"/>.</summary>
    public void Dispose()
    {
        if(Carriage is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}


/// <summary>
/// The <c>arVals</c> arm (clause 5.3.1 enumeration item 7, clause 5.3.5.5): revocation values for attribute
/// certificates/signed assertions, dual-mode per <see cref="JAdESUnsignedValue{TValue}"/>. Reuses
/// <see cref="JAdESRevocationValues"/>, the same shared shape <c>rVals</c> uses (Annex B.1 schema
/// <c>"arVals": {"$ref": "#/definitions/rVals"}</c>).
/// </summary>
[DebuggerDisplay("JAdESUnsignedHeaderElementAttributeRevocationValues: {Carriage}")]
public sealed class JAdESUnsignedHeaderElementAttributeRevocationValues    : JAdESUnsignedHeaderElement, IDisposable
{
    /// <summary>Initializes a new <see cref="JAdESUnsignedHeaderElementAttributeRevocationValues"/>.</summary>
    /// <param name="carriage">The dual-mode carriage: opaque wire text, or the decoded revocation values.</param>
    public JAdESUnsignedHeaderElementAttributeRevocationValues(JAdESUnsignedValue<JAdESRevocationValues> carriage)
    {
        Carriage = carriage;
    }

    /// <summary>The dual-mode carriage: opaque wire text, or the decoded revocation values.</summary>
    public JAdESUnsignedValue<JAdESRevocationValues> Carriage { get; }

    /// <summary>Gets <see cref="JAdESUnsignedHeaderElement.AttributeRevocationValuesKind"/> (<c>arVals</c>).</summary>
    public override string Kind => AttributeRevocationValuesKind;

    /// <inheritdoc/>
    public override JAdESEtsiUIncorporationMode? DeclaredMode =>
        Carriage is JAdESOpaqueUnsignedValue<JAdESRevocationValues> ? JAdESEtsiUIncorporationMode.Base64Url : JAdESEtsiUIncorporationMode.ClearJson;

    /// <summary>Disposes <see cref="Carriage"/>.</summary>
    public void Dispose()
    {
        if(Carriage is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}


/// <summary>
/// The <c>anyValData</c> arm (clause 5.3.1 enumeration item 8, clause 5.3.5.6): certificate and/or revocation
/// values for validating any signature present anywhere within the JAdES signature, dual-mode per
/// <see cref="JAdESUnsignedValue{TValue}"/>.
/// </summary>
[DebuggerDisplay("JAdESUnsignedHeaderElementAnyValidationData: {Carriage}")]
public sealed class JAdESUnsignedHeaderElementAnyValidationData    : JAdESUnsignedHeaderElement, IDisposable
{
    /// <summary>Initializes a new <see cref="JAdESUnsignedHeaderElementAnyValidationData"/>.</summary>
    /// <param name="carriage">The dual-mode carriage: opaque wire text, or the decoded validation data.</param>
    public JAdESUnsignedHeaderElementAnyValidationData(JAdESUnsignedValue<JAdESValidationData> carriage)
    {
        Carriage = carriage;
    }

    /// <summary>The dual-mode carriage: opaque wire text, or the decoded validation data.</summary>
    public JAdESUnsignedValue<JAdESValidationData> Carriage { get; }

    /// <summary>Gets <see cref="JAdESUnsignedHeaderElement.AnyValidationDataKind"/> (<c>anyValData</c>).</summary>
    public override string Kind => AnyValidationDataKind;

    /// <inheritdoc/>
    public override JAdESEtsiUIncorporationMode? DeclaredMode =>
        Carriage is JAdESOpaqueUnsignedValue<JAdESValidationData> ? JAdESEtsiUIncorporationMode.Base64Url : JAdESEtsiUIncorporationMode.ClearJson;

    /// <summary>Disposes <see cref="Carriage"/>.</summary>
    public void Dispose()
    {
        if(Carriage is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}


/// <summary>
/// The <c>tstVD</c> arm (clause 5.3.1 enumeration item 9, clause 5.3.6.1): validation data for fully verifying
/// electronic time-stamp(s) embedded elsewhere in the JAdES signature, dual-mode per
/// <see cref="JAdESUnsignedValue{TValue}"/>. Reuses <see cref="JAdESValidationData"/>, the same shared shape
/// <c>anyValData</c> uses (Annex B.1 schema <c>"tstVD": {"$ref": "#/definitions/validationVals"}</c>).
/// </summary>
[DebuggerDisplay("JAdESUnsignedHeaderElementTimestampValidationData: {Carriage}")]
public sealed class JAdESUnsignedHeaderElementTimestampValidationData    : JAdESUnsignedHeaderElement, IDisposable
{
    /// <summary>Initializes a new <see cref="JAdESUnsignedHeaderElementTimestampValidationData"/>.</summary>
    /// <param name="carriage">The dual-mode carriage: opaque wire text, or the decoded validation data.</param>
    public JAdESUnsignedHeaderElementTimestampValidationData(JAdESUnsignedValue<JAdESValidationData> carriage)
    {
        Carriage = carriage;
    }

    /// <summary>The dual-mode carriage: opaque wire text, or the decoded validation data.</summary>
    public JAdESUnsignedValue<JAdESValidationData> Carriage { get; }

    /// <summary>Gets <see cref="JAdESUnsignedHeaderElement.TimestampValidationDataKind"/> (<c>tstVD</c>).</summary>
    public override string Kind => TimestampValidationDataKind;

    /// <inheritdoc/>
    public override JAdESEtsiUIncorporationMode? DeclaredMode =>
        Carriage is JAdESOpaqueUnsignedValue<JAdESValidationData> ? JAdESEtsiUIncorporationMode.Base64Url : JAdESEtsiUIncorporationMode.ClearJson;

    /// <summary>Disposes <see cref="Carriage"/>.</summary>
    public void Dispose()
    {
        if(Carriage is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}


/// <summary>
/// The <c>arcTst</c> arm (clause 5.3.1 enumeration item 10, clause 5.3.6.2.1): one or more electronic
/// time-stamps time-stamping the JWS Payload, the JWS Protected Header, the JAdES Signature Value, and the
/// <c>etsiU</c> array (JA-5.3.6.2.1-01), dual-mode per <see cref="JAdESUnsignedValue{TValue}"/>.
/// </summary>
/// <remarks>
/// <strong>JA-5.3.1-14, NOT enforced here.</strong> "If the <c>etsiU</c> header parameter contains JSON values
/// in clear, instances of <c>tstContainer</c> type shall have the <c>canonAlg</c> member, except for the
/// <c>sigTst</c> JSON object" — unlike <c>sigTst</c>'s own unconditional JA-5.3.4-05 prohibition, this rule
/// depends on the ENCLOSING CONTAINER's declared incorporation mode, which a single element under construction
/// does not know. <see cref="JAdESUnsignedHeaders"/>'s own constructor/<see cref="JAdESUnsignedHeaders.Append"/>
/// enforce it once an instance of this type is placed in a container.
/// </remarks>
[DebuggerDisplay("JAdESUnsignedHeaderElementArchiveTimestamp: {Carriage}")]
public sealed class JAdESUnsignedHeaderElementArchiveTimestamp    : JAdESUnsignedHeaderElement, IDisposable
{
    /// <summary>Initializes a new <see cref="JAdESUnsignedHeaderElementArchiveTimestamp"/>.</summary>
    /// <param name="carriage">The dual-mode carriage: opaque wire text, or the decoded time-stamp container.</param>
    public JAdESUnsignedHeaderElementArchiveTimestamp(JAdESUnsignedValue<AdESTimestampContainer> carriage)
    {
        Carriage = carriage;
    }

    /// <summary>The dual-mode carriage: opaque wire text, or the decoded time-stamp container.</summary>
    public JAdESUnsignedValue<AdESTimestampContainer> Carriage { get; }

    /// <summary>Gets <see cref="JAdESUnsignedHeaderElement.ArchiveTimestampKind"/> (<c>arcTst</c>).</summary>
    public override string Kind => ArchiveTimestampKind;

    /// <inheritdoc/>
    public override JAdESEtsiUIncorporationMode? DeclaredMode =>
        Carriage is JAdESOpaqueUnsignedValue<AdESTimestampContainer> ? JAdESEtsiUIncorporationMode.Base64Url : JAdESEtsiUIncorporationMode.ClearJson;

    /// <summary>Disposes <see cref="Carriage"/>.</summary>
    public void Dispose()
    {
        if(Carriage is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}


/// <summary>
/// The <c>xRefs</c> arm (Annex A.1.1): certificate-path digest references, dual-mode per
/// <see cref="JAdESUnsignedValue{TValue}"/>, first-class —
/// participates in <see cref="JAdESUnsignedHeaders"/>'s own DeclaredMode duality like every other named arm; no
/// longer covered by the unknown-arm exemption.
/// </summary>
[DebuggerDisplay("JAdESUnsignedHeaderElementCertificateReferences: {Carriage}")]
public sealed class JAdESUnsignedHeaderElementCertificateReferences    : JAdESUnsignedHeaderElement, IDisposable
{
    /// <summary>Initializes a new <see cref="JAdESUnsignedHeaderElementCertificateReferences"/>.</summary>
    /// <param name="carriage">The dual-mode carriage: opaque wire text, or the decoded certificate references.</param>
    public JAdESUnsignedHeaderElementCertificateReferences(JAdESUnsignedValue<JAdESCertificateReferenceCollection> carriage)
    {
        Carriage = carriage;
    }

    /// <summary>The dual-mode carriage: opaque wire text, or the decoded certificate references.</summary>
    public JAdESUnsignedValue<JAdESCertificateReferenceCollection> Carriage { get; }

    /// <summary>Gets <see cref="JAdESUnsignedHeaderElement.CertificateReferencesKind"/> (<c>xRefs</c>).</summary>
    public override string Kind => CertificateReferencesKind;

    /// <inheritdoc/>
    public override JAdESEtsiUIncorporationMode? DeclaredMode =>
        Carriage is JAdESOpaqueUnsignedValue<JAdESCertificateReferenceCollection> ? JAdESEtsiUIncorporationMode.Base64Url : JAdESEtsiUIncorporationMode.ClearJson;

    /// <summary>Disposes <see cref="Carriage"/>.</summary>
    public void Dispose()
    {
        if(Carriage is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}


/// <summary>
/// The <c>rRefs</c> arm (Annex A.1.2): revocation-data digest references, dual-mode per
/// <see cref="JAdESUnsignedValue{TValue}"/>, first-class.
/// </summary>
[DebuggerDisplay("JAdESUnsignedHeaderElementRevocationReferences: {Carriage}")]
public sealed class JAdESUnsignedHeaderElementRevocationReferences    : JAdESUnsignedHeaderElement, IDisposable
{
    /// <summary>Initializes a new <see cref="JAdESUnsignedHeaderElementRevocationReferences"/>.</summary>
    /// <param name="carriage">The dual-mode carriage: opaque wire text, or the decoded revocation references.</param>
    public JAdESUnsignedHeaderElementRevocationReferences(JAdESUnsignedValue<JAdESRevocationReferenceCollection> carriage)
    {
        Carriage = carriage;
    }

    /// <summary>The dual-mode carriage: opaque wire text, or the decoded revocation references.</summary>
    public JAdESUnsignedValue<JAdESRevocationReferenceCollection> Carriage { get; }

    /// <summary>Gets <see cref="JAdESUnsignedHeaderElement.RevocationReferencesKind"/> (<c>rRefs</c>).</summary>
    public override string Kind => RevocationReferencesKind;

    /// <inheritdoc/>
    public override JAdESEtsiUIncorporationMode? DeclaredMode =>
        Carriage is JAdESOpaqueUnsignedValue<JAdESRevocationReferenceCollection> ? JAdESEtsiUIncorporationMode.Base64Url : JAdESEtsiUIncorporationMode.ClearJson;

    /// <summary>Disposes <see cref="Carriage"/>.</summary>
    public void Dispose()
    {
        if(Carriage is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}


/// <summary>
/// The <c>axRefs</c> arm (Annex A.1.3): certificate-path digest references for attribute certificates/signed
/// assertions, dual-mode per <see cref="JAdESUnsignedValue{TValue}"/>, first-class.
/// Reuses <see cref="JAdESCertificateReferenceCollection"/>, the same shared shape
/// <c>xRefs</c> uses (Annex A.1.3 schema <c>"axRefs": {"$ref": "#/definitions/x5Ids"}</c>).
/// </summary>
[DebuggerDisplay("JAdESUnsignedHeaderElementAttributeCertificateReferences: {Carriage}")]
public sealed class JAdESUnsignedHeaderElementAttributeCertificateReferences    : JAdESUnsignedHeaderElement, IDisposable
{
    /// <summary>Initializes a new <see cref="JAdESUnsignedHeaderElementAttributeCertificateReferences"/>.</summary>
    /// <param name="carriage">The dual-mode carriage: opaque wire text, or the decoded certificate references.</param>
    public JAdESUnsignedHeaderElementAttributeCertificateReferences(JAdESUnsignedValue<JAdESCertificateReferenceCollection> carriage)
    {
        Carriage = carriage;
    }

    /// <summary>The dual-mode carriage: opaque wire text, or the decoded certificate references.</summary>
    public JAdESUnsignedValue<JAdESCertificateReferenceCollection> Carriage { get; }

    /// <summary>Gets <see cref="JAdESUnsignedHeaderElement.AttributeCertificateReferencesKind"/> (<c>axRefs</c>).</summary>
    public override string Kind => AttributeCertificateReferencesKind;

    /// <inheritdoc/>
    public override JAdESEtsiUIncorporationMode? DeclaredMode =>
        Carriage is JAdESOpaqueUnsignedValue<JAdESCertificateReferenceCollection> ? JAdESEtsiUIncorporationMode.Base64Url : JAdESEtsiUIncorporationMode.ClearJson;

    /// <summary>Disposes <see cref="Carriage"/>.</summary>
    public void Dispose()
    {
        if(Carriage is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}


/// <summary>
/// The <c>arRefs</c> arm (Annex A.1.4): revocation-data digest references for attribute certificates/signed
/// assertions, dual-mode per <see cref="JAdESUnsignedValue{TValue}"/>, first-class.
/// Reuses <see cref="JAdESRevocationReferenceCollection"/>, the same shared shape
/// <c>rRefs</c> uses (Annex A.1.4 schema <c>"arRefs": {"$ref": "#/definitions/rRefs"}</c>).
/// </summary>
[DebuggerDisplay("JAdESUnsignedHeaderElementAttributeRevocationReferences: {Carriage}")]
public sealed class JAdESUnsignedHeaderElementAttributeRevocationReferences    : JAdESUnsignedHeaderElement, IDisposable
{
    /// <summary>Initializes a new <see cref="JAdESUnsignedHeaderElementAttributeRevocationReferences"/>.</summary>
    /// <param name="carriage">The dual-mode carriage: opaque wire text, or the decoded revocation references.</param>
    public JAdESUnsignedHeaderElementAttributeRevocationReferences(JAdESUnsignedValue<JAdESRevocationReferenceCollection> carriage)
    {
        Carriage = carriage;
    }

    /// <summary>The dual-mode carriage: opaque wire text, or the decoded revocation references.</summary>
    public JAdESUnsignedValue<JAdESRevocationReferenceCollection> Carriage { get; }

    /// <summary>Gets <see cref="JAdESUnsignedHeaderElement.AttributeRevocationReferencesKind"/> (<c>arRefs</c>).</summary>
    public override string Kind => AttributeRevocationReferencesKind;

    /// <inheritdoc/>
    public override JAdESEtsiUIncorporationMode? DeclaredMode =>
        Carriage is JAdESOpaqueUnsignedValue<JAdESRevocationReferenceCollection> ? JAdESEtsiUIncorporationMode.Base64Url : JAdESEtsiUIncorporationMode.ClearJson;

    /// <summary>Disposes <see cref="Carriage"/>.</summary>
    public void Dispose()
    {
        if(Carriage is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}


/// <summary>
/// The <c>sigRTst</c> arm (Annex A.1.5.1): one or more electronic time-stamps time-stamping the JWS Signature
/// Value plus the referenced-validation-data components, dual-mode per <see cref="JAdESUnsignedValue{TValue}"/>,
/// first-class (<c>tstContainer</c>-typed, the same shape
/// as <c>sigTst</c>/<c>arcTst</c>).
/// </summary>
/// <remarks>
/// <strong>JA-5.3.1-14 applies here (not excepted).</strong> Unlike <c>sigTst</c>'s unconditional JA-5.3.4-05
/// prohibition, <c>sigRTst</c> is not the stated exception to JA-5.3.1-14 — under clear-JSON incorporation this
/// element's decoded time-stamp container must carry <c>canonAlg</c>, checked at
/// <see cref="JAdESUnsignedHeaders"/>'s own construction/<see cref="JAdESUnsignedHeaders.Append"/>, the same
/// container-level enforcement point <see cref="JAdESUnsignedHeaderElementArchiveTimestamp"/> already uses.
/// </remarks>
[DebuggerDisplay("JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp: {Carriage}")]
public sealed class JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp    : JAdESUnsignedHeaderElement, IDisposable
{
    /// <summary>Initializes a new <see cref="JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp"/>.</summary>
    /// <param name="carriage">The dual-mode carriage: opaque wire text, or the decoded time-stamp container.</param>
    public JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp(JAdESUnsignedValue<AdESTimestampContainer> carriage)
    {
        Carriage = carriage;
    }

    /// <summary>The dual-mode carriage: opaque wire text, or the decoded time-stamp container.</summary>
    public JAdESUnsignedValue<AdESTimestampContainer> Carriage { get; }

    /// <summary>Gets <see cref="JAdESUnsignedHeaderElement.SignatureAndReferencesTimestampKind"/> (<c>sigRTst</c>).</summary>
    public override string Kind => SignatureAndReferencesTimestampKind;

    /// <inheritdoc/>
    public override JAdESEtsiUIncorporationMode? DeclaredMode =>
        Carriage is JAdESOpaqueUnsignedValue<AdESTimestampContainer> ? JAdESEtsiUIncorporationMode.Base64Url : JAdESEtsiUIncorporationMode.ClearJson;

    /// <summary>Disposes <see cref="Carriage"/>.</summary>
    public void Dispose()
    {
        if(Carriage is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}


/// <summary>
/// The <c>rfsTst</c> arm (Annex A.1.5.2): one or more electronic time-stamps time-stamping the
/// referenced-validation-data components only (no signature value), dual-mode per
/// <see cref="JAdESUnsignedValue{TValue}"/>, first-class
/// (<c>tstContainer</c>-typed, the same shape as <c>sigTst</c>/<c>arcTst</c>).
/// </summary>
/// <remarks>
/// <strong>JA-5.3.1-14 applies here (not excepted)</strong> — see
/// <see cref="JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp"/>'s identical remark.
/// </remarks>
[DebuggerDisplay("JAdESUnsignedHeaderElementReferencesTimestamp: {Carriage}")]
public sealed class JAdESUnsignedHeaderElementReferencesTimestamp    : JAdESUnsignedHeaderElement, IDisposable
{
    /// <summary>Initializes a new <see cref="JAdESUnsignedHeaderElementReferencesTimestamp"/>.</summary>
    /// <param name="carriage">The dual-mode carriage: opaque wire text, or the decoded time-stamp container.</param>
    public JAdESUnsignedHeaderElementReferencesTimestamp(JAdESUnsignedValue<AdESTimestampContainer> carriage)
    {
        Carriage = carriage;
    }

    /// <summary>The dual-mode carriage: opaque wire text, or the decoded time-stamp container.</summary>
    public JAdESUnsignedValue<AdESTimestampContainer> Carriage { get; }

    /// <summary>Gets <see cref="JAdESUnsignedHeaderElement.ReferencesTimestampKind"/> (<c>rfsTst</c>).</summary>
    public override string Kind => ReferencesTimestampKind;

    /// <inheritdoc/>
    public override JAdESEtsiUIncorporationMode? DeclaredMode =>
        Carriage is JAdESOpaqueUnsignedValue<AdESTimestampContainer> ? JAdESEtsiUIncorporationMode.Base64Url : JAdESEtsiUIncorporationMode.ClearJson;

    /// <summary>Disposes <see cref="Carriage"/>.</summary>
    public void Dispose()
    {
        if(Carriage is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}


/// <summary>
/// The unknown-label catch-all arm (clause 5.3.1, JA-5.3.1-13's extension escape hatch — JAdES's own Annex D,
/// the CB-AdES Annex-E analog): an unsigned <c>etsiU</c> component this library does not
/// itself specify. Carried opaque for the identical reason <c>cSig</c> is — see the family remarks on
/// <see cref="JAdESUnsignedHeaderElement"/>.
/// </summary>
[DebuggerDisplay("JAdESUnsignedHeaderElementUnknown: {Kind}, {WireText.Length} bytes")]
public sealed class JAdESUnsignedHeaderElementUnknown: JAdESUnsignedHeaderElement, IDisposable
{
    /// <summary>
    /// Initializes a new <see cref="JAdESUnsignedHeaderElementUnknown"/>.
    /// </summary>
    /// <param name="label">The catch-all JSON key identifying this element.</param>
    /// <param name="wireText">
    /// The element's own wire TEXT, pool-owned — base64url when the container is
    /// <see cref="JAdESEtsiUIncorporationMode.Base64Url"/>, or this element's own raw clear-JSON text when the
    /// container is <see cref="JAdESEtsiUIncorporationMode.ClearJson"/>.
    /// </param>
    /// <exception cref="ArgumentException"><paramref name="label"/> is <see langword="null"/> or empty.</exception>
    public JAdESUnsignedHeaderElementUnknown(string label, PooledMemory wireText)
    {
        ArgumentException.ThrowIfNullOrEmpty(label);

        Kind = label;
        WireText = wireText;
    }


    /// <summary>Gets the catch-all JSON key identifying this element.</summary>
    public override string Kind { get; }

    /// <summary>Always <see langword="null"/> — the unknown arm is mode-agnostic here.</summary>
    public override JAdESEtsiUIncorporationMode? DeclaredMode => null;

    /// <summary>Gets the element's own wire TEXT, pool-owned.</summary>
    public PooledMemory WireText { get; }

    /// <summary>Disposes <see cref="WireText"/>, returning its pooled buffer.</summary>
    public void Dispose() => WireText.Dispose();
}
