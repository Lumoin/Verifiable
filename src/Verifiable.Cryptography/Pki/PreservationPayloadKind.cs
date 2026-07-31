namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Discriminates what a pooled carrier holding the octets of one preservation-protocol payload holds.
/// </summary>
/// <remarks>
/// <para>
/// Used as a <see cref="Tag"/> component so a block of protocol-payload octets can be routed and reported on
/// without re-parsing it, the same job <see cref="AsicObjectKind"/> does for container octets and
/// <see cref="EArkObjectKind"/> does for an Information Package's metadata. It is a separate enumeration rather
/// than more members of either of those because a preservation-protocol message is neither a container nor a
/// package: it is a request or a response of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> clause 5, and widening either of the other two would make its own documented
/// statement about what it discriminates false.
/// </para>
/// <para>
/// <see cref="None"/> occupies zero so a default-initialised tag component never reads as a protocol payload.
/// </para>
/// </remarks>
public enum PreservationPayloadKind
{
    /// <summary>No payload kind specified. The value of an unset component, by design.</summary>
    None = 0,

    /// <summary>
    /// The octets a preservation object carries — the value of the <c>PO</c> component of clause 5.4.5, in
    /// whichever of its two content forms the wire stated it.
    /// </summary>
    PreservationObject = 1,

    /// <summary>
    /// The octets a preservation evidence carries — the value of the <c>Evidence</c> component of clause 5.4.4,
    /// which extends <c>PO</c> and whose format identifier the same clause makes mandatory.
    /// </summary>
    PreservationEvidence = 2,

    /// <summary>
    /// The octets of one sub-component this document defines only by reference to an external specification —
    /// an <c>OptionalInputs</c> or <c>OptionalOutputs</c> instance of clause 5.3.1, or an <c>Extension</c> of the
    /// <c>Profile</c> component of clause 5.4.7. This library models none of those shapes and carries them
    /// verbatim instead, so nothing is invented and nothing is dropped.
    /// </summary>
    OpaqueElement = 3,

    /// <summary>
    /// The octets of one <c>Extension</c> element of a container manifest carrying a payload of clause 5.5 — the
    /// whole element as the serialisation seam produced or found it, which is what
    /// <see cref="AsicManifestExtension.Content"/> holds.
    /// </summary>
    AsicExtension = 4
}
