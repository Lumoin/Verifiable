using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The six well-known CB-AdES signer-commitment-type identifiers registered in Annex C of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, each exposed both as its URI form — the value
/// <c>srCms.commId.id</c> (clause 5.2.3) carries on the wire, since <c>srCms</c> SHALL express
/// the commitment type with a URI — and its numeric OID arc form (<c>id-cti-ets-*</c>,
/// <see href="https://www.rfc-editor.org/rfc/rfc5126">IETF RFC 5126</see>, Annex B.2), reused
/// unchanged from the CAdES/XAdES/JAdES commitment-type family.
/// </summary>
/// <remarks>
/// <para>
/// Annex C's printed table mislabels the symbolic OID name of the "Proof of sender", "Proof of
/// approval" and "Proof of creation" rows as <c>id-cti-ets-proofOfOrigin</c> — a spec-original
/// copy/paste defect (each row's numeric arc suffix and URI are correct and distinct). Callers
/// MUST identify a commitment type by its URI (e.g. <see cref="ProofOfOriginUri"/>) or numeric
/// OID (e.g. <see cref="ProofOfOriginOid"/>) form, never by a printed symbolic name.
/// </para>
/// <para>
/// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, Annex C</see>.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "These identifiers are compared and written as exact character sequences (see CBAdESCommitmentTypes.Equals and the callers matching srCms.commId.id) — System.Uri normalizes on construction, which would make two spellings that should compare unequal collapse together.")]
public static class CBAdESCommitmentTypes
{
    /// <summary>The proof-of-origin commitment type URI (Annex C, OID arc suffix 1).</summary>
    public static string ProofOfOriginUri => "http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin";

    /// <summary>
    /// The proof-of-origin commitment type OID, <c>id-cti-ets-proofOfOrigin</c> (Annex C, OID arc
    /// suffix 1).
    /// </summary>
    public static string ProofOfOriginOid => "1.2.840.113549.1.9.16.6.1";

    /// <summary>The proof-of-receipt commitment type URI (Annex C, OID arc suffix 2).</summary>
    public static string ProofOfReceiptUri => "http://uri.etsi.org/01903/v1.2.2#ProofOfReceipt";

    /// <summary>
    /// The proof-of-receipt commitment type OID, <c>id-cti-ets-proofOfReceipt</c> (Annex C, OID
    /// arc suffix 2).
    /// </summary>
    public static string ProofOfReceiptOid => "1.2.840.113549.1.9.16.6.2";

    /// <summary>The proof-of-delivery commitment type URI (Annex C, OID arc suffix 3).</summary>
    public static string ProofOfDeliveryUri => "http://uri.etsi.org/01903/v1.2.2#ProofOfDelivery";

    /// <summary>
    /// The proof-of-delivery commitment type OID, <c>id-cti-ets-proofOfDelivery</c> (Annex C, OID
    /// arc suffix 3).
    /// </summary>
    public static string ProofOfDeliveryOid => "1.2.840.113549.1.9.16.6.3";

    /// <summary>The proof-of-sender commitment type URI (Annex C, OID arc suffix 4).</summary>
    public static string ProofOfSenderUri => "http://uri.etsi.org/01903/v1.2.2#ProofOfSender";

    /// <summary>
    /// The proof-of-sender commitment type OID, <c>id-cti-ets-proofOfSender</c> (Annex C, OID arc
    /// suffix 4). Annex C's own table misprints this row's symbolic name as
    /// <c>id-cti-ets-proofOfOrigin</c> — see the type-level remarks; this is the correct name per
    /// RFC 5126 Annex B.2.
    /// </summary>
    public static string ProofOfSenderOid => "1.2.840.113549.1.9.16.6.4";

    /// <summary>The proof-of-approval commitment type URI (Annex C, OID arc suffix 5).</summary>
    public static string ProofOfApprovalUri => "http://uri.etsi.org/01903/v1.2.2#ProofOfApproval";

    /// <summary>
    /// The proof-of-approval commitment type OID, <c>id-cti-ets-proofOfApproval</c> (Annex C, OID
    /// arc suffix 5). Annex C's own table misprints this row's symbolic name as
    /// <c>id-cti-ets-proofOfOrigin</c> — see the type-level remarks; this is the correct name per
    /// RFC 5126 Annex B.2.
    /// </summary>
    public static string ProofOfApprovalOid => "1.2.840.113549.1.9.16.6.5";

    /// <summary>The proof-of-creation commitment type URI (Annex C, OID arc suffix 6).</summary>
    public static string ProofOfCreationUri => "http://uri.etsi.org/01903/v1.2.2#ProofOfCreation";

    /// <summary>
    /// The proof-of-creation commitment type OID, <c>id-cti-ets-proofOfCreation</c> (Annex C, OID
    /// arc suffix 6). Annex C's own table misprints this row's symbolic name as
    /// <c>id-cti-ets-proofOfOrigin</c> — see the type-level remarks; this is the correct name per
    /// RFC 5126 Annex B.2.
    /// </summary>
    public static string ProofOfCreationOid => "1.2.840.113549.1.9.16.6.6";


    /// <summary>Whether <paramref name="value"/> is the proof-of-origin commitment type, by URI or OID.</summary>
    /// <param name="value">The <c>srCms.commId.id</c> value or an OID to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="ProofOfOriginUri"/> or <see cref="ProofOfOriginOid"/>; otherwise, <see langword="false"/>.</returns>
    public static bool IsProofOfOrigin(string value) => Equals(value, ProofOfOriginUri) || Equals(value, ProofOfOriginOid);


    /// <summary>Whether <paramref name="value"/> is the proof-of-receipt commitment type, by URI or OID.</summary>
    /// <param name="value">The <c>srCms.commId.id</c> value or an OID to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="ProofOfReceiptUri"/> or <see cref="ProofOfReceiptOid"/>; otherwise, <see langword="false"/>.</returns>
    public static bool IsProofOfReceipt(string value) => Equals(value, ProofOfReceiptUri) || Equals(value, ProofOfReceiptOid);


    /// <summary>Whether <paramref name="value"/> is the proof-of-delivery commitment type, by URI or OID.</summary>
    /// <param name="value">The <c>srCms.commId.id</c> value or an OID to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="ProofOfDeliveryUri"/> or <see cref="ProofOfDeliveryOid"/>; otherwise, <see langword="false"/>.</returns>
    public static bool IsProofOfDelivery(string value) => Equals(value, ProofOfDeliveryUri) || Equals(value, ProofOfDeliveryOid);


    /// <summary>Whether <paramref name="value"/> is the proof-of-sender commitment type, by URI or OID.</summary>
    /// <param name="value">The <c>srCms.commId.id</c> value or an OID to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="ProofOfSenderUri"/> or <see cref="ProofOfSenderOid"/>; otherwise, <see langword="false"/>.</returns>
    public static bool IsProofOfSender(string value) => Equals(value, ProofOfSenderUri) || Equals(value, ProofOfSenderOid);


    /// <summary>Whether <paramref name="value"/> is the proof-of-approval commitment type, by URI or OID.</summary>
    /// <param name="value">The <c>srCms.commId.id</c> value or an OID to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="ProofOfApprovalUri"/> or <see cref="ProofOfApprovalOid"/>; otherwise, <see langword="false"/>.</returns>
    public static bool IsProofOfApproval(string value) => Equals(value, ProofOfApprovalUri) || Equals(value, ProofOfApprovalOid);


    /// <summary>Whether <paramref name="value"/> is the proof-of-creation commitment type, by URI or OID.</summary>
    /// <param name="value">The <c>srCms.commId.id</c> value or an OID to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="ProofOfCreationUri"/> or <see cref="ProofOfCreationOid"/>; otherwise, <see langword="false"/>.</returns>
    public static bool IsProofOfCreation(string value) => Equals(value, ProofOfCreationUri) || Equals(value, ProofOfCreationOid);


    /// <summary>Whether <paramref name="value"/> is any of the six well-known CB-AdES Annex C commitment types, by URI or OID.</summary>
    /// <param name="value">The <c>srCms.commId.id</c> value or an OID to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> matches one of the six well-known commitment types; otherwise, <see langword="false"/>.</returns>
    public static bool IsWellKnownCommitmentType(string value) =>
        IsProofOfOrigin(value)
        || IsProofOfReceipt(value)
        || IsProofOfDelivery(value)
        || IsProofOfSender(value)
        || IsProofOfApproval(value)
        || IsProofOfCreation(value);


    /// <summary>
    /// Compares two commitment-type identifiers (URI or OID form) for equality.
    /// </summary>
    /// <param name="valueA">The first identifier.</param>
    /// <param name="valueB">The second identifier.</param>
    /// <returns><see langword="true"/> if the identifiers are the same; otherwise, <see langword="false"/>.</returns>
    public static bool Equals(string valueA, string valueB) =>
        ReferenceEquals(valueA, valueB) || StringComparer.Ordinal.Equals(valueA, valueB);
}
