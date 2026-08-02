using System.Diagnostics;

namespace Verifiable.JCose;

/// <summary>
/// The general COSE header-parameter <c>label</c> CDDL union
/// (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-1.4">RFC 9052 §1.4</see>: <c>label = int / tstr</c>,
/// reused by the <c>crit</c> header parameter's syntax at
/// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3.1">RFC 9052 §3.1</see>), used wherever a CB-AdES
/// protected header carries a label this document does not itself narrow to an integer — the <c>crit</c> header
/// parameter's array elements
/// (<see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clause 5.1.10) and the open <c>*label =&gt; value</c> unprofiled-header
/// extension set (<see cref="CBAdESProtectedHeaders.UnprofiledHeaders"/>, clause 4.4 NOTE 4: "Header parameters
/// defined elsewhere and not further profiled by the present document, may also be added as signed header
/// parameters or as elements of uHeaders header parameter within the CB-AdES [signature]"). A DU-ready closed
/// sum: no external type may derive from it.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Not used for the seven clause-5.2 CB-AdES-specific components.</strong> Clause 5.2.1 requires those
/// labels (261-267, <see cref="CBAdESHeaderParameters"/>) to be integers ("All of them shall be identified by a
/// label in the corresponding CBOR map that shall be an integer") — genuinely integer-only, unlike the general
/// COSE label union this type models. <see cref="Verifiable.Cbor.CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader"/>'s
/// fixed profiled-header entries for those seven labels (plus <c>alg</c>, <c>content type</c>, <c>kid</c>, CWT
/// Claims, <c>x5chain</c>, <c>x5t</c>, <c>x5u</c>) are always minted as <see cref="CoseHeaderIntegerLabel"/>;
/// only <c>crit</c>'s array elements and <see cref="CBAdESProtectedHeaders.UnprofiledHeaders"/>'s keys can ever
/// carry the <see cref="CoseHeaderTextLabel"/> arm. Likewise the S1/S2 CB-AdES component codecs' own internal
/// CBOR maps (clause 4.6: "The keys of the CBOR maps pairs shall be integers") stay <see langword="int"/>-only
/// through <c>ReadAscendingMapKey</c>/<c>ReadInt32Array</c> — this union governs only the outer protected-headers
/// map's own label space, the general COSE substrate concern, not the CB-AdES-defined component internals.
/// </para>
/// <para>
/// Both sibling arms carry the record-generated structural <see cref="IEquatable{T}"/> implementation, so two
/// labels compare equal exactly when they are the same CDDL choice arm holding the same value — an integer
/// label never compares equal to a textual one, even when their printed forms coincide (e.g. <c>34</c> vs
/// <c>"34"</c>).
/// </para>
/// </remarks>
public abstract record CoseHeaderLabel
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected CoseHeaderLabel()
    {
    }
}


/// <summary>
/// The <c>int</c> arm of the <c>label: int / tstr</c> CDDL union (see <see cref="CoseHeaderLabel"/>) — every
/// header-parameter label this library's own registries (<see cref="CoseHeaderParameters"/>,
/// <see cref="CBAdESHeaderParameters"/>) assign.
/// </summary>
/// <param name="Value">The integer label.</param>
[DebuggerDisplay("CoseHeaderIntegerLabel: {Value}")]
public sealed record CoseHeaderIntegerLabel(int Value) : CoseHeaderLabel;


/// <summary>
/// The <c>tstr</c> arm of the <c>label: int / tstr</c> CDDL union (see <see cref="CoseHeaderLabel"/>) — a
/// textual label for a header parameter defined elsewhere and not further profiled by this document, per
/// clause 4.4 NOTE 4's explicit allowance.
/// </summary>
/// <param name="Value">The textual label.</param>
[DebuggerDisplay("CoseHeaderTextLabel: {Value}")]
public sealed record CoseHeaderTextLabel(string Value) : CoseHeaderLabel;
