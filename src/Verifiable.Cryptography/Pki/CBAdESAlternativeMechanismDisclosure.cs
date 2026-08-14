using System;
using System.Collections.Generic;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The four disclosure items Annex E (normative) requires be specified for an alternative mechanism that
/// achieves long-term availability and integrity of validation data by means other than <c>arcTst</c>
/// (clause 5.3.5), per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, Annex E</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Annex reference, corrected.</strong> Clause 6.1 NOTE 4 names "Annex C" as the place
/// describing this convention ("Annex C defines what needs to be taken into account when using other
/// techniques for long term availability and integrity of validation data ... and incorporating a new
/// component in the <c>uHeaders</c> unsigned header parameter derived from these techniques into the
/// signature"), but Annex C is "URIs defined for commitment type" (informative, unrelated to long-term
/// availability techniques) — the content NOTE 4 describes is verbatim Annex E's own title and scope
/// ("Alternative mechanisms for long term availability and integrity of validation data", normative); the
/// ruled reading is "Annex E" — the same numeral/cross-reference defect family as the message-imprint step-citation slip
/// <see cref="CBAdESArchiveTimestamp"/> notes.
/// </para>
/// <para>
/// <strong>Annex E, in full.</strong> "There may be mechanisms to achieve long-term availability and
/// integrity of validation data different from the ones described in clause 5.3.5 of the present document.
/// If such a mechanism is incorporated using an unsigned component into the signature, then for this
/// mechanism, all the following shall be specified: 1) the clear specification of the semantics and syntax of
/// the component including its unique identifier; 2) the strategy of how this mechanism guarantees that all
/// necessary parts of the signature are protected by this component; and 3) the strategy of how to handle
/// signatures containing components defined in the present document." The EXAMPLE names the objects of IETF
/// RFC 4998 Annex A (Evidence Record Syntax) as a mechanism meeting items 1) and 2) only.
/// </para>
/// <para>
/// <strong>Four members for three shall-items.</strong> Item 1) names two things in one sentence — "the
/// clear specification of the semantics and syntax of the component" AND "its unique identifier" — so this
/// record carries <see cref="UniqueIdentifier"/> and <see cref="SemanticsAndSyntaxReference"/> as its own
/// members, plus <see cref="ProtectionStrategy"/> (item 2) and <see cref="CoexistenceStrategy"/> (item 3).
/// </para>
/// <para>
/// <strong>Not a wire format.</strong> Annex E governs how an alternative mechanism must be SPECIFIED — a
/// documentation obligation on whoever defines it — not a CBOR encoding of its own; this record carries no
/// codec of its own. A mechanism's own instances still ride the CBOR wire exclusively through the CB-AdES
/// <c>uHeaders</c> array's existing <c>*label =&gt; value</c> catch-all (CB-5.3.1-11,
/// <see cref="CBAdESUnsignedHeaderElementUnknown"/>) — the same extension point the spec's EXAMPLE mechanism
/// would itself use. <see cref="CBAdESAlternativeMechanismDisclosureRegistry"/> is the registration
/// convention that associates a disclosure with the catch-all label a mechanism's instances carry on the
/// wire.
/// </para>
/// <para>
/// <strong>Fail-closed construction.</strong> Annex E's lead-in states all three items as an unconditional
/// SHALL once a mechanism is incorporated ("all the following shall be specified") — every member here is
/// required and validated non-blank at construction; a disclosure missing one item is not a partial
/// disclosure this library represents, it is an absent one. (The EXAMPLE's own "only handle points 1) and 2)"
/// caveat is a documented shortfall of that EXAMPLE mechanism as commonly implemented, not a relief this
/// constructor extends to every alternative mechanism it records.)
/// </para>
/// </remarks>
public sealed record CBAdESAlternativeMechanismDisclosure
{
    /// <summary>
    /// Gets the mechanism's unique identifier (Annex E item 1, "... including its unique identifier") — the
    /// same identifying value the wire key of the <see cref="CBAdESUnsignedHeaderElementUnknown"/> catch-all
    /// label a mechanism's own instances carry should name (an object identifier, a URI, or any other stable
    /// name the mechanism defines for itself).
    /// </summary>
    public string UniqueIdentifier { get; }

    /// <summary>
    /// Gets a reference to the mechanism's own specification of its semantics and syntax (Annex E item 1,
    /// "the clear specification of the semantics and syntax of the component") — a citation or URI to the
    /// document defining the component's wire shape and meaning (the EXAMPLE names
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#appendix-a">IETF RFC 4998, Annex A</see> for this
    /// role).
    /// </summary>
    public string SemanticsAndSyntaxReference { get; }

    /// <summary>
    /// Gets the statement of the strategy by which this mechanism guarantees that all necessary parts of the
    /// signature are protected by its component (Annex E item 2, "the strategy of how this mechanism
    /// guarantees that all necessary parts of the signature are protected by this component").
    /// </summary>
    public string ProtectionStrategy { get; }

    /// <summary>
    /// Gets the statement of the strategy for handling signatures that contain components this document
    /// (ETSI TS 119 152-1) itself defines alongside this mechanism's own component (Annex E item 3, "the
    /// strategy of how to handle signatures containing components defined in the present document").
    /// </summary>
    public string CoexistenceStrategy { get; }


    /// <summary>
    /// Initializes a new <see cref="CBAdESAlternativeMechanismDisclosure"/> from its four Annex E disclosure
    /// items.
    /// </summary>
    /// <param name="uniqueIdentifier">The mechanism's unique identifier.</param>
    /// <param name="semanticsAndSyntaxReference">The reference to the mechanism's semantics/syntax specification.</param>
    /// <param name="protectionStrategy">The mechanism's protection-strategy statement.</param>
    /// <param name="coexistenceStrategy">The mechanism's coexistence-strategy statement.</param>
    /// <exception cref="ArgumentNullException">Any parameter is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// Any parameter is empty or white space — Annex E states all three shall-items (four members here)
    /// unconditionally once a mechanism is incorporated; a disclosure missing one is not representable.
    /// </exception>
    public CBAdESAlternativeMechanismDisclosure(
        string uniqueIdentifier,
        string semanticsAndSyntaxReference,
        string protectionStrategy,
        string coexistenceStrategy)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(uniqueIdentifier);
        ArgumentException.ThrowIfNullOrWhiteSpace(semanticsAndSyntaxReference);
        ArgumentException.ThrowIfNullOrWhiteSpace(protectionStrategy);
        ArgumentException.ThrowIfNullOrWhiteSpace(coexistenceStrategy);

        UniqueIdentifier = uniqueIdentifier;
        SemanticsAndSyntaxReference = semanticsAndSyntaxReference;
        ProtectionStrategy = protectionStrategy;
        CoexistenceStrategy = coexistenceStrategy;
    }
}


/// <summary>
/// The Annex E registration convention: an in-memory association between an alternative mechanism's
/// <see cref="CBAdESUnsignedHeaderElementUnknown"/> catch-all wire key
/// (<see cref="CBAdESUnsignedHeaderElement.Label"/>) and the <see cref="CBAdESAlternativeMechanismDisclosure"/>
/// Annex E requires be specified for it — wired at the existing <c>*label =&gt; value</c> catch-all extension
/// point (CB-5.3.1-11) the <c>uHeaders</c> CDDL already provides, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, Annex E</see> — see
/// <see cref="CBAdESAlternativeMechanismDisclosure"/>'s own remarks for the "Annex C"/"Annex E" reading.
/// </summary>
/// <remarks>
/// <para>
/// <strong>No new wire codec.</strong> Registration never touches the CBOR wire encoding: a
/// <see cref="CBAdESUnsignedHeaderElementUnknown"/> instance's encode/parse round trip through the CB-AdES
/// codec is exactly as byte-exact with or without a disclosure registered against its label — Annex E governs
/// how the mechanism must be SPECIFIED, not a wire format this registry adds a codec for.
/// </para>
/// <para>
/// <strong>Reachable across a wire round trip.</strong> <see cref="CBAdESUnsignedHeaderElementLabel"/>'s two
/// sibling arms (<see cref="CBAdESUnsignedHeaderElementIntegerLabel"/>,
/// <see cref="CBAdESUnsignedHeaderElementTextLabel"/>) are records with structural equality, so a label
/// freshly reconstructed by parsing wire bytes is equal-by-value to the label a disclosure was registered
/// under, even though it is never the same object — <see cref="TryGetDisclosure"/> resolves either one
/// identically.
/// </para>
/// <para>
/// Instance state, not a static table: unlike the fixed, ETSI-defined Table 14 registry
/// (<see cref="CBAdESBaselineLevelTable"/>), the set of alternative mechanisms in use is open-ended and
/// application-defined (Annex E's own "there MAY be mechanisms ... different from the ones described"), so a
/// caller constructs and populates its own registry rather than reading one this library ships pre-populated.
/// </para>
/// <para>
/// <strong>Threading contract: populate at composition, read-only thereafter.</strong>
/// A caller builds one instance, calls <see cref="Register"/> for every alternative mechanism its deployment
/// recognizes while composing the validation pipeline (e.g. once at startup, alongside registering the
/// <see cref="VerifyCmsSignedDataDelegate"/> the deployment's backend needs), and then hands the now-fixed
/// instance to every concurrent level-rule evaluation as a shared, read-only reference — the JCose-layer
/// orchestrator's <c>CBAdESLevelRuleContext.AlternativeMechanismDisclosures</c> member is exactly this handoff
/// point. The backing <see cref="Dictionary{TKey,TValue}"/> is not synchronized: concurrent <see cref="Register"/>
/// calls, or a <see cref="Register"/> call racing a <see cref="TryGetDisclosure"/> read on another thread, are
/// not supported. <see cref="TryGetDisclosure"/> alone is safe to call concurrently from many threads once
/// population has finished and stopped — the same read-after-write handoff every other caller-supplied,
/// registry-shaped context member in this validation surface relies on.
/// </para>
/// </remarks>
public sealed class CBAdESAlternativeMechanismDisclosureRegistry
{
    /// <summary>The backing association from catch-all wire key to its registered Annex E disclosure.</summary>
    private Dictionary<CBAdESUnsignedHeaderElementLabel, CBAdESAlternativeMechanismDisclosure> DisclosuresByLabel { get; } = [];


    /// <summary>
    /// Registers <paramref name="disclosure"/> as the Annex E specification for the alternative mechanism
    /// whose <see cref="CBAdESUnsignedHeaderElementUnknown"/> instances carry <paramref name="label"/>.
    /// </summary>
    /// <param name="label">The mechanism's catch-all wire key (the CDDL's <c>label</c> rule, clause 5.2.5).</param>
    /// <param name="disclosure">The mechanism's Annex E disclosure.</param>
    /// <exception cref="ArgumentNullException"><paramref name="label"/> or <paramref name="disclosure"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="label"/> names one of this document's own ten profiled <c>UHeaderInstance</c> arms
    /// (Table 8's <c>sigTst</c>/<c>valData</c>/<c>arcTst</c>/<c>refs</c>/<c>sigRTst</c>/<c>rfsTst</c>/
    /// <c>sigPSt</c>, or the RFC 9338/RFC 9360 counter-signature/<c>x5chain</c> labels) — Annex E governs
    /// mechanisms "different from the ones described in clause 5.3.5", never this document's own components, so
    /// none of its fixed labels is a legal registration target — or a disclosure is
    /// already registered for <paramref name="label"/>.
    /// </exception>
    public void Register(CBAdESUnsignedHeaderElementLabel label, CBAdESAlternativeMechanismDisclosure disclosure)
    {
        ArgumentNullException.ThrowIfNull(label);
        ArgumentNullException.ThrowIfNull(disclosure);

        if(IsProfiledLabel(label))
        {
            throw new ArgumentException(
                $"'{label}' is one of this document's own profiled UHeaderInstance labels (Table 8, or the " +
                "RFC 9338/RFC 9360 counter-signature/x5chain labels) -- Annex E's disclosure convention exists " +
                "only for the *label => value catch-all a mechanism this document does not itself define uses.",
                nameof(label));
        }

        if(!DisclosuresByLabel.TryAdd(label, disclosure))
        {
            throw new ArgumentException($"A disclosure is already registered for label '{label}'.", nameof(label));
        }

        /// <summary>
        /// Determines whether <paramref name="candidate"/> is one of this document's own ten profiled
        /// <c>UHeaderInstance</c> arms — Table 8's seven (labels <c>1</c>-<c>7</c>) plus the RFC 9338
        /// counter-signature pair (<c>11</c>/<c>12</c>) and the RFC 9360 <c>x5chain</c> arm (<c>33</c>), per
        /// <see cref="CBAdESUnsignedHeaderElement"/>'s own label constants.
        /// </summary>
        /// <param name="candidate">The label to classify.</param>
        /// <returns><see langword="true"/> when <paramref name="candidate"/> names a profiled arm.</returns>
        static bool IsProfiledLabel(CBAdESUnsignedHeaderElementLabel candidate) => candidate switch
        {
            CBAdESUnsignedHeaderElementIntegerLabel
            {
                Value: CBAdESUnsignedHeaderElement.SignatureTimestampLabel
                    or CBAdESUnsignedHeaderElement.ValidationDataLabel
                    or CBAdESUnsignedHeaderElement.ArchiveTimestampLabel
                    or CBAdESUnsignedHeaderElement.ReferencesLabel
                    or CBAdESUnsignedHeaderElement.SignatureAndReferencesTimestampLabel
                    or CBAdESUnsignedHeaderElement.ReferencesTimestampLabel
                    or CBAdESUnsignedHeaderElement.SignaturePolicyStoreLabel
                    or CBAdESUnsignedHeaderElement.FullCounterSignatureLabel
                    or CBAdESUnsignedHeaderElement.AbbreviatedCounterSignatureLabel
                    or CBAdESUnsignedHeaderElement.CertificateChainLabel
            } => true,
            _ => false
        };
    }


    /// <summary>
    /// Attempts to reach the Annex E disclosure registered for <paramref name="label"/> — the extension
    /// point's own reachability surface: any <see cref="CBAdESUnsignedHeaderElement.Label"/>, including one
    /// belonging to an instance freshly parsed off the wire, resolves here by value (see the remarks on
    /// reachability across a wire round trip).
    /// </summary>
    /// <param name="label">The catch-all wire key to look up.</param>
    /// <param name="disclosure">The registered disclosure, or <see langword="null"/> when none is registered.</param>
    /// <returns><see langword="true"/> when a disclosure is registered for <paramref name="label"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="label"/> is <see langword="null"/>.</exception>
    public bool TryGetDisclosure(CBAdESUnsignedHeaderElementLabel label, out CBAdESAlternativeMechanismDisclosure? disclosure)
    {
        ArgumentNullException.ThrowIfNull(label);

        return DisclosuresByLabel.TryGetValue(label, out disclosure);
    }
}
