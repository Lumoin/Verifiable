namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Input for one issuer claim flowing into
/// <see cref="MdocIssuance.BuildDocument"/>. Carries the namespace, the
/// element identifier within the namespace, and the pre-encoded element
/// value bytes.
/// </summary>
/// <remarks>
/// <para>
/// The encoding of <see cref="EncodedElementValue"/> is the caller's
/// responsibility: they know the element-identifier semantics (CBOR tdate
/// for <c>issue_date</c>, CBOR full-date for <c>birth_date</c>, CBOR bool
/// for <c>age_over_18</c>, …). Format-specific encoders supply convenience
/// extension methods at the serialization layer; this input record is
/// format-agnostic.
/// </para>
/// <para>
/// Mirrors the <c>CredentialSubjectInput</c> shape used by
/// <see cref="Verifiable.Core.Model.Credentials.CredentialBuilder"/> — a
/// plain POCO with get/init properties, no record machinery, so consumers
/// can construct via object initializers.
/// </para>
/// </remarks>
public sealed class MdocClaimInput
{
    /// <summary>
    /// The namespace string — e.g. <c>org.iso.18013.5.1</c> for the ISO mDL
    /// namespace or <c>eu.europa.ec.eudi.pid.1</c> for the EUDI PID
    /// namespace.
    /// </summary>
    public required string NameSpace { get; init; }

    /// <summary>
    /// The claim name within the namespace (e.g. <c>family_name</c>,
    /// <c>birth_date</c>, <c>age_over_18</c>).
    /// </summary>
    public required string ElementIdentifier { get; init; }

    /// <summary>
    /// The pre-encoded element value bytes. Format-specific — for the
    /// ISO 18013-5 CBOR wire shape this is one encoded CBOR data item.
    /// </summary>
    public required ReadOnlyMemory<byte> EncodedElementValue { get; init; }
}
