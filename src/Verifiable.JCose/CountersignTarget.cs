namespace Verifiable.JCose;

/// <summary>
/// Closed-sum discriminator for the structure a version 2 countersignature countersigns, per
/// <see href="https://www.rfc-editor.org/rfc/rfc9338#section-3.3">RFC 9338 §3.3</see>. Only
/// the two structures ETSI TS 119 152-1 profiles are modeled —
/// <see cref="CoseSignatureCountersignTarget"/> (a <c>COSE_Signature</c>) and
/// <see cref="CoseSign1CountersignTarget"/> (a <c>COSE_Sign1</c>); RFC 9338 §3.3 also admits
/// COSE_Sign, COSE_Mac, COSE_Mac0, COSE_Encrypt, and COSE_Encrypt0 as targets, which are out
/// of scope here.
/// </summary>
/// <remarks>
/// The target discriminates <see cref="CountersignStructureInput.Payload"/> and
/// <see cref="CountersignStructureInput.OtherFieldsSignature"/>: RFC 9338 §3.3 counts the target's own <c>bstr</c>
/// fields in wire order, assigns the first to <c>body_protected</c> and the second to
/// Countersign_structure's own <c>payload</c> slot, and folds any remaining ones into
/// <c>other_fields</c> — a structural property of the TARGET being countersigned, never of
/// the countersignature carrying it. See each sibling's own remarks for the derivation.
/// </remarks>
public abstract class CountersignTarget
{
    /// <summary>Restricts direct subtyping to the sibling types declared in this file.</summary>
    private protected CountersignTarget()
    {
    }
}


/// <summary>
/// A <c>COSE_Signature</c> countersign target — e.g. one signer's own entry within a
/// <c>COSE_Sign</c> message, or a full countersignature itself being countersigned (RFC 9338
/// §3.1: "the countersignature can itself be countersigned").
/// </summary>
public sealed class CoseSignatureCountersignTarget : CountersignTarget
{
    /// <summary>Initializes a new <see cref="CoseSignatureCountersignTarget"/>.</summary>
    /// <param name="protectedHeader">
    /// The target's own serialized protected header bytes — Countersign_structure's own
    /// <c>body_protected</c> field.
    /// </param>
    /// <param name="signature">
    /// The target's own signature value bytes. <c>COSE_Signature = [protected, unprotected,
    /// signature]</c> carries exactly two <c>bstr</c> fields in order (<c>protected</c>,
    /// <c>signature</c>); the first becomes <c>body_protected</c>, the
    /// second (this field) becomes Countersign_structure's own <c>payload</c> — no field remains,
    /// so <c>other_fields</c> is omitted (RFC 9338 §3.3: "Omitted if there are only two bstr
    /// fields in the target structure").
    /// </param>
    public CoseSignatureCountersignTarget(ReadOnlyMemory<byte> protectedHeader, ReadOnlyMemory<byte> signature)
    {
        ProtectedHeader = protectedHeader;
        Signature = signature;
    }

    /// <summary>
    /// The target's own serialized protected header bytes — Countersign_structure's own
    /// <c>body_protected</c> field.
    /// </summary>
    public ReadOnlyMemory<byte> ProtectedHeader { get; }

    /// <summary>
    /// The target's own signature value bytes. <c>COSE_Signature = [protected, unprotected,
    /// signature]</c> carries exactly two <c>bstr</c> fields in order (<c>protected</c>,
    /// <c>signature</c>); the first becomes <c>body_protected</c>, the
    /// second (this field) becomes Countersign_structure's own <c>payload</c> — no field remains,
    /// so <c>other_fields</c> is omitted (RFC 9338 §3.3: "Omitted if there are only two bstr
    /// fields in the target structure").
    /// </summary>
    public ReadOnlyMemory<byte> Signature { get; }
}


/// <summary>
/// A <c>COSE_Sign1</c> countersign target.
/// </summary>
public sealed class CoseSign1CountersignTarget : CountersignTarget
{
    /// <summary>Initializes a new <see cref="CoseSign1CountersignTarget"/>.</summary>
    /// <param name="protectedHeader">
    /// The target's own serialized protected header bytes — Countersign_structure's own
    /// <c>body_protected</c> field.
    /// </param>
    /// <param name="payload">
    /// The target's own payload bytes — Countersign_structure's own <c>payload</c> slot.
    /// </param>
    /// <param name="signature">
    /// The target's own signature value bytes. <c>COSE_Sign1 = [protected, unprotected, payload,
    /// signature]</c> carries three <c>bstr</c> fields in order (<c>protected</c>, <c>payload</c>,
    /// <c>signature</c>); the first becomes <c>body_protected</c>, the
    /// second becomes <see cref="Payload"/>, and the third (this field) is the one remaining
    /// <c>bstr</c> field — <c>other_fields</c> is present, one element, matching RFC 9338 §3.3's
    /// own worked example: "an array of one element for the COSE_Sign1 structure containing the
    /// signature value."
    /// </param>
    public CoseSign1CountersignTarget(ReadOnlyMemory<byte> protectedHeader, ReadOnlyMemory<byte> payload, ReadOnlyMemory<byte> signature)
    {
        ProtectedHeader = protectedHeader;
        Payload = payload;
        Signature = signature;
    }

    /// <summary>
    /// The target's own serialized protected header bytes — Countersign_structure's own
    /// <c>body_protected</c> field.
    /// </summary>
    public ReadOnlyMemory<byte> ProtectedHeader { get; }

    /// <summary>
    /// The target's own payload bytes — Countersign_structure's own <c>payload</c> slot.
    /// </summary>
    public ReadOnlyMemory<byte> Payload { get; }

    /// <summary>
    /// The target's own signature value bytes. <c>COSE_Sign1 = [protected, unprotected, payload,
    /// signature]</c> carries three <c>bstr</c> fields in order (<c>protected</c>, <c>payload</c>,
    /// <c>signature</c>); the first becomes <c>body_protected</c>, the
    /// second becomes <see cref="Payload"/>, and the third (this field) is the one remaining
    /// <c>bstr</c> field — <c>other_fields</c> is present, one element, matching RFC 9338 §3.3's
    /// own worked example: "an array of one element for the COSE_Sign1 structure containing the
    /// signature value."
    /// </summary>
    public ReadOnlyMemory<byte> Signature { get; }
}


/// <summary>
/// Input to <see cref="BuildCountersignStructureDelegate"/> — the RFC 9338 §3.3
/// Countersign_structure's own fields, already resolved for one target/countersignature-form
/// combination.
/// </summary>
/// <param name="IsAbbreviated">
/// <see langword="true"/> when the countersignature being built or verified is a
/// <see cref="CounterSignature0V2"/> (no <see cref="SignProtected"/> of its own);
/// <see langword="false"/> for a <see cref="CounterSignatureV2"/>.
/// </param>
/// <param name="BodyProtected">The countersigned target's own serialized protected header bytes.</param>
/// <param name="SignProtected">
/// The countersignature's own serialized protected header bytes. RFC 9338 §3.3: "This field
/// is omitted for the Countersignature0V2 attribute" — <see langword="null"/> when
/// <paramref name="IsAbbreviated"/> is <see langword="true"/>; otherwise present, even if
/// zero-length.
/// </param>
/// <param name="ExternalAad">The externally supplied additional authenticated data.</param>
/// <param name="Payload">The countersigned target's own payload bytes, per <see cref="CountersignTarget"/>.</param>
/// <param name="OtherFieldsSignature">
/// The countersigned target's own signature value, when the target has one <c>bstr</c> field
/// remaining after <see cref="Payload"/> (present for <see cref="CoseSign1CountersignTarget"/>,
/// omitted for <see cref="CoseSignatureCountersignTarget"/>) — the sole content of
/// Countersign_structure's <c>other_fields</c> array in either scoped target shape.
/// </param>
public readonly record struct CountersignStructureInput(
    bool IsAbbreviated,
    ReadOnlyMemory<byte> BodyProtected,
    ReadOnlyMemory<byte>? SignProtected,
    ReadOnlyMemory<byte> ExternalAad,
    ReadOnlyMemory<byte> Payload,
    ReadOnlyMemory<byte>? OtherFieldsSignature)
{
    /// <summary>
    /// Builds a <see cref="CountersignStructureInput"/> for <paramref name="target"/>, deriving
    /// <see cref="Payload"/> and <see cref="OtherFieldsSignature"/> from the countersigned
    /// TARGET structure's own bstr-field count — never from the carrying
    /// countersignature's own structure.
    /// </summary>
    /// <param name="target">The countersigned target.</param>
    /// <param name="isAbbreviated">See <see cref="IsAbbreviated"/>.</param>
    /// <param name="signProtected">See <see cref="SignProtected"/>.</param>
    /// <param name="externalAad">See <see cref="ExternalAad"/>.</param>
    /// <returns>The resolved input.</returns>
    public static CountersignStructureInput ForTarget(
        CountersignTarget target,
        bool isAbbreviated,
        ReadOnlyMemory<byte>? signProtected,
        ReadOnlyMemory<byte> externalAad)
    {
        ArgumentNullException.ThrowIfNull(target);

        //The (ReadOnlyMemory<byte>?) casts are load-bearing, not redundant: ReadOnlyMemory<byte> has
        //its own implicit conversion from a null array, so without the cast the switch's inferred
        //common type for this position is the non-nullable ReadOnlyMemory<byte> and a "null" arm
        //silently becomes an empty-but-present memory (HasValue true, Length 0) instead of "absent"
        //(HasValue false) — collapsing the has-other_fields distinction this input carries.
        (ReadOnlyMemory<byte> bodyProtected, ReadOnlyMemory<byte> payload, ReadOnlyMemory<byte>? otherFieldsSignature) = target switch
        {
            CoseSignatureCountersignTarget signatureTarget =>
                (signatureTarget.ProtectedHeader, signatureTarget.Signature, (ReadOnlyMemory<byte>?)null),
            CoseSign1CountersignTarget sign1Target =>
                (sign1Target.ProtectedHeader, sign1Target.Payload, (ReadOnlyMemory<byte>?)sign1Target.Signature),
            _ => throw new ArgumentOutOfRangeException(
                nameof(target), target, "Unsupported countersign target; only COSE_Signature and COSE_Sign1 targets are modeled.")
        };

        return new CountersignStructureInput(isAbbreviated, bodyProtected, signProtected, externalAad, payload, otherFieldsSignature);
    }
}
