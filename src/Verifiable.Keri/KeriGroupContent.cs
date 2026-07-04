namespace Verifiable.Keri;

/// <summary>
/// What the body of a KERI / ACDC count group frames, and so which walk a consumer runs over it. The CESR codec
/// frames a group and hands its body back whole; this classification — the genus-specific meaning of the group
/// code — tells the consumer whether to walk that body as indexed signatures, as a flat sequence of primitives,
/// or to descend it as nested groups.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#master-code-table-for-genusversion--_aaacaa-keriacdc-protocol-stack-version-200">
/// Master code table for genus/version -_AAACAA</see>. The codec deliberately leaves this meaning to the
/// protocol layer: it ships the walk mechanism, and the genus (which the consumer knows) chooses the walk.
/// </para>
/// </remarks>
public enum KeriGroupContent
{
    /// <summary>
    /// The body is a sequence of indexed CONTROLLER signatures: the indexed controller signature group
    /// (<c>-K</c>). A controller signature's index refers to the establishment event's own current signing-key
    /// list (field <c>k</c>).
    /// </summary>
    ControllerSignatures = 0,

    /// <summary>
    /// The body is a sequence of indexed WITNESS signatures: the indexed witness signature group (<c>-L</c>). A
    /// witness signature's index refers to the event's witness (backer) list, not its signing-key list.
    /// </summary>
    WitnessSignatures = 1,

    /// <summary>
    /// The body is a flat sequence of CESR primitives grouped in fixed-arity tuples: the seal, receipt, replay,
    /// and blinded-state codes (for example <c>-M</c> receipt couples, <c>-Q</c> digest seal singles, <c>-T</c>
    /// anchoring seal triples). A consumer walks the primitives and groups them by the code's arity.
    /// </summary>
    Primitives = 2,

    /// <summary>
    /// The body contains nested count groups or a structured message rather than a homogeneous sequence of
    /// elements: the generic pipeline, message, attachment, datagram, ESSR, native-message, field-map, list,
    /// pathed, and transferable indexed-signature groups (for example <c>-A</c>, <c>-B</c>, <c>-C</c>, <c>-X</c>).
    /// Walking these requires descending into their structure, which a later capability provides.
    /// </summary>
    NestedGroups = 3
}
