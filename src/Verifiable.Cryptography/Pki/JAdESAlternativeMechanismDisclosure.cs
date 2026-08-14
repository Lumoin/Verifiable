using System;
using System.Collections.Generic;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The three disclosure items Annex D (normative) requires be specified for an alternative mechanism that
/// achieves long-term availability and integrity of validation data by means other than <c>arcTst</c>
/// (clause 5.3.6), per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, Annex D</see> — the JAdES-side counterpart of
/// <see cref="CBAdESAlternativeMechanismDisclosure"/>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The origin of the CB-AdES mis-citation this same defect propagated into.</strong> Clause 6.1
/// NOTE 4 names "Annex C" as the place describing this
/// convention, but Annex C is "Correspondence between XAdES tags and JAdES tags" (informative, a 28-row
/// tag-name table wholly unrelated to preservation techniques) — the content NOTE 4 describes is verbatim
/// Annex D's own heading ("Alternative mechanisms for long term availability and integrity of validation
/// data", normative); the ruled reading is "Annex D".
/// </para>
/// <para>
/// <strong>Annex D, in full (JA-D-01/-02).</strong> "There may be mechanisms to achieve long-term availability
/// and integrity of validation data different from the ones described in clause 5.3.6. If such a mechanism is
/// incorporated using an unsigned component into the signature, then for this mechanism shall be specified:
/// 1) The clear specification of the semantics and syntax of the component including its unique identifier.
/// 2) The strategy of how this mechanism guarantees that all necessary parts of the signature are protected by
/// this component. 3) The strategy of how to handle signatures containing components defined in the present
/// document." The EXAMPLE names the objects of IETF RFC 4998 Annex A (Evidence Record Syntax) as a mechanism
/// meeting items 1) and 2) only.
/// </para>
/// <para>
/// <strong>Four members for three shall-items — identical split to <see cref="CBAdESAlternativeMechanismDisclosure"/>.</strong>
/// Item 1) names two things in one sentence — "the clear specification of the semantics and syntax of the
/// component" AND "its unique identifier" — so this record carries <see cref="UniqueIdentifier"/> and
/// <see cref="SemanticsAndSyntaxReference"/> as its own members, plus <see cref="ProtectionStrategy"/> (item 2)
/// and <see cref="CoexistenceStrategy"/> (item 3).
/// </para>
/// <para>
/// <strong>Not a wire format.</strong> Annex D governs how an alternative mechanism must be SPECIFIED — a
/// documentation obligation on whoever defines it — not a JSON encoding of its own; this record carries no
/// codec. A mechanism's own instances still ride the JAdES wire exclusively through the <c>etsiU</c> array's
/// existing catch-all extension point (JA-5.3.1-13,
/// <see cref="JAdESUnsignedHeaderElementUnknown"/>) — the same extension point the spec's EXAMPLE mechanism
/// would itself use. <see cref="JAdESAlternativeMechanismDisclosureRegistry"/> is the registration convention
/// that associates a disclosure with the catch-all kind a mechanism's instances carry on the wire.
/// </para>
/// <para>
/// <strong>Fail-closed construction.</strong> Annex D's lead-in states all three items as an unconditional
/// SHALL once a mechanism is incorporated ("for this mechanism shall be specified") — every member here is
/// required and validated non-blank at construction; a disclosure missing one item is not a partial disclosure
/// this library represents, it is an absent one.
/// </para>
/// </remarks>
public sealed record JAdESAlternativeMechanismDisclosure
{
    /// <summary>
    /// Gets the mechanism's unique identifier (Annex D item 1, "... including its unique identifier") — the
    /// same identifying value the <c>etsiU</c> JSON key a mechanism's own
    /// <see cref="JAdESUnsignedHeaderElementUnknown"/> instances carry should name (an object identifier, a
    /// URI, or any other stable name the mechanism defines for itself).
    /// </summary>
    public string UniqueIdentifier { get; }

    /// <summary>
    /// Gets a reference to the mechanism's own specification of its semantics and syntax (Annex D item 1, "the
    /// clear specification of the semantics and syntax of the component") — a citation or URI to the document
    /// defining the component's wire shape and meaning (the EXAMPLE names
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#appendix-a">IETF RFC 4998, Annex A</see> for this
    /// role).
    /// </summary>
    public string SemanticsAndSyntaxReference { get; }

    /// <summary>
    /// Gets the statement of the strategy by which this mechanism guarantees that all necessary parts of the
    /// signature are protected by its component (Annex D item 2, "the strategy of how this mechanism guarantees
    /// that all necessary parts of the signature are protected by this component").
    /// </summary>
    public string ProtectionStrategy { get; }

    /// <summary>
    /// Gets the statement of the strategy for handling signatures that contain components this document (ETSI
    /// TS 119 182-1) itself defines alongside this mechanism's own component (Annex D item 3, "the strategy of
    /// how to handle signatures containing components defined in the present document").
    /// </summary>
    public string CoexistenceStrategy { get; }


    /// <summary>
    /// Initializes a new <see cref="JAdESAlternativeMechanismDisclosure"/> from its four Annex D disclosure
    /// items.
    /// </summary>
    /// <param name="uniqueIdentifier">The mechanism's unique identifier.</param>
    /// <param name="semanticsAndSyntaxReference">The reference to the mechanism's semantics/syntax specification.</param>
    /// <param name="protectionStrategy">The mechanism's protection-strategy statement.</param>
    /// <param name="coexistenceStrategy">The mechanism's coexistence-strategy statement.</param>
    /// <exception cref="ArgumentNullException">Any parameter is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// Any parameter is empty or white space — Annex D states all three shall-items (four members here)
    /// unconditionally once a mechanism is incorporated; a disclosure missing one is not representable.
    /// </exception>
    public JAdESAlternativeMechanismDisclosure(
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
/// The Annex D registration convention: an in-memory association between an alternative mechanism's
/// <see cref="JAdESUnsignedHeaderElementUnknown"/> catch-all <c>etsiU</c> JSON key
/// (<see cref="JAdESUnsignedHeaderElement.Kind"/>) and the <see cref="JAdESAlternativeMechanismDisclosure"/>
/// Annex D requires be specified for it — wired at the existing catch-all extension point (JA-5.3.1-13) the
/// <c>etsiU</c> array already provides, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, Annex D</see>, mirroring <see cref="CBAdESAlternativeMechanismDisclosureRegistry"/>'s
/// identical convention one document removed.
/// </summary>
/// <remarks>
/// <para>
/// <strong>No new wire codec.</strong> Registration never touches the JSON wire encoding: a
/// <see cref="JAdESUnsignedHeaderElementUnknown"/> instance's encode/parse round trip through the JAdES codec
/// is exactly as byte-exact with or without a disclosure registered against its kind — Annex D governs how the
/// mechanism must be SPECIFIED, not a wire format this registry adds a codec for.
/// </para>
/// <para>
/// <strong>Keyed by plain string, unlike the CB-AdES analog.</strong> <see cref="CBAdESUnsignedHeaderElementLabel"/>
/// is a closed sum (integer or text CBOR label); <see cref="JAdESUnsignedHeaderElement.Kind"/> is always a
/// plain JSON object key, so the registry keys directly on <see cref="string"/> — a kind freshly reconstructed
/// by parsing wire bytes is equal by ordinal comparison to the kind a disclosure was registered under.
/// </para>
/// <para>
/// Instance state, not a static table: unlike the fixed, ETSI-defined Table 1 registry
/// (<see cref="JAdESBaselineLevelTable"/>), the set of alternative mechanisms in use is open-ended and
/// application-defined (Annex D's own "there MAY be mechanisms ... different from the ones described"), so a
/// caller constructs and populates its own registry rather than reading one this library ships pre-populated.
/// </para>
/// <para>
/// <strong>Threading contract: populate at composition, read-only thereafter.</strong> A caller builds one
/// instance, calls <see cref="Register"/> for every alternative mechanism its deployment recognizes while
/// composing the validation pipeline, and then hands the now-fixed instance to every concurrent level-rule
/// evaluation as a shared, read-only reference — <c>JAdESLevelRuleContext.AlternativeMechanismDisclosures</c>
/// is exactly this handoff point (<c>Verifiable.JCose</c>). The backing <see cref="Dictionary{TKey,TValue}"/>
/// is not synchronized: concurrent <see cref="Register"/> calls, or a <see cref="Register"/> call racing a
/// <see cref="TryGetDisclosure"/> read on another thread, are not supported. <see cref="TryGetDisclosure"/>
/// alone is safe to call concurrently from many threads once population has finished and stopped.
/// </para>
/// </remarks>
public sealed class JAdESAlternativeMechanismDisclosureRegistry
{
    /// <summary>The backing association from catch-all <c>etsiU</c> JSON key to its registered Annex D disclosure.</summary>
    private Dictionary<string, JAdESAlternativeMechanismDisclosure> DisclosuresByKind { get; } = [];


    /// <summary>
    /// Registers <paramref name="disclosure"/> as the Annex D specification for the alternative mechanism whose
    /// <see cref="JAdESUnsignedHeaderElementUnknown"/> instances carry <paramref name="kind"/>.
    /// </summary>
    /// <param name="kind">The mechanism's catch-all <c>etsiU</c> JSON key.</param>
    /// <param name="disclosure">The mechanism's Annex D disclosure.</param>
    /// <exception cref="ArgumentException">
    /// <paramref name="kind"/> is <see langword="null"/> or empty; names one of this document's own sixteen
    /// named <c>etsiU</c> arms (the ten clause 5.3.1 kinds plus the six Annex A kinds — Annex D governs
    /// mechanisms this document does not itself define, so none of its own fixed kinds is a legal registration
    /// target); or a disclosure is already registered for <paramref name="kind"/>.
    /// </exception>
    /// <exception cref="ArgumentNullException"><paramref name="disclosure"/> is <see langword="null"/>.</exception>
    public void Register(string kind, JAdESAlternativeMechanismDisclosure disclosure)
    {
        ArgumentException.ThrowIfNullOrEmpty(kind);
        ArgumentNullException.ThrowIfNull(disclosure);

        if(IsProfiledKind(kind))
        {
            throw new ArgumentException(
                $"'{kind}' is one of this document's own named etsiU arms (clause 5.3.1 or Annex A) -- Annex " +
                "D's disclosure convention exists only for the catch-all a mechanism this document does not " +
                "itself define uses.",
                nameof(kind));
        }

        if(!DisclosuresByKind.TryAdd(kind, disclosure))
        {
            throw new ArgumentException($"A disclosure is already registered for kind '{kind}'.", nameof(kind));
        }

        /// <summary>
        /// Determines whether <paramref name="candidate"/> is one of this document's own sixteen named
        /// <c>etsiU</c> arms — the ten clause 5.3.1 kinds plus the six Annex A kinds, per
        /// <see cref="JAdESUnsignedHeaderElement"/>'s own kind constants.
        /// </summary>
        /// <param name="candidate">The kind to classify.</param>
        /// <returns><see langword="true"/> when <paramref name="candidate"/> names a profiled arm.</returns>
        static bool IsProfiledKind(string candidate) => candidate switch
        {
            JAdESUnsignedHeaderElement.SignaturePolicyStoreKind
                or JAdESUnsignedHeaderElement.CounterSignatureKind
                or JAdESUnsignedHeaderElement.SignatureTimestampKind
                or JAdESUnsignedHeaderElement.CertificateValuesKind
                or JAdESUnsignedHeaderElement.RevocationValuesKind
                or JAdESUnsignedHeaderElement.AttributeCertificateValuesKind
                or JAdESUnsignedHeaderElement.AttributeRevocationValuesKind
                or JAdESUnsignedHeaderElement.AnyValidationDataKind
                or JAdESUnsignedHeaderElement.TimestampValidationDataKind
                or JAdESUnsignedHeaderElement.ArchiveTimestampKind
                or JAdESUnsignedHeaderElement.CertificateReferencesKind
                or JAdESUnsignedHeaderElement.RevocationReferencesKind
                or JAdESUnsignedHeaderElement.AttributeCertificateReferencesKind
                or JAdESUnsignedHeaderElement.AttributeRevocationReferencesKind
                or JAdESUnsignedHeaderElement.SignatureAndReferencesTimestampKind
                or JAdESUnsignedHeaderElement.ReferencesTimestampKind => true,
            _ => false
        };
    }


    /// <summary>
    /// Attempts to reach the Annex D disclosure registered for <paramref name="kind"/> — the extension point's
    /// own reachability surface: any <see cref="JAdESUnsignedHeaderElement.Kind"/>, including one belonging to
    /// an instance freshly parsed off the wire, resolves here by ordinal string comparison.
    /// </summary>
    /// <param name="kind">The catch-all <c>etsiU</c> JSON key to look up.</param>
    /// <param name="disclosure">The registered disclosure, or <see langword="null"/> when none is registered.</param>
    /// <returns><see langword="true"/> when a disclosure is registered for <paramref name="kind"/>.</returns>
    /// <exception cref="ArgumentException"><paramref name="kind"/> is <see langword="null"/> or empty.</exception>
    public bool TryGetDisclosure(string kind, out JAdESAlternativeMechanismDisclosure? disclosure)
    {
        ArgumentException.ThrowIfNullOrEmpty(kind);

        return DisclosuresByKind.TryGetValue(kind, out disclosure);
    }
}
