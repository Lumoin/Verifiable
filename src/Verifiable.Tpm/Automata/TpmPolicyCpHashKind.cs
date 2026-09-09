namespace Verifiable.Tpm.Automata;

/// <summary>
/// Which deferred assertion occupies a policy session's shared <c>cpHash</c> slot (TPM 2.0 Library Part 1,
/// Table 8: "This structure member is permitted to be shared" by <c>TPM2_PolicyCpHash()</c>,
/// <c>TPM2_PolicyNameHash()</c>, <c>TPM2_PolicyDuplicationSelect()</c>, <c>TPM2_PolicyParameters()</c> and
/// <c>TPM2_PolicyTemplate()</c>; Part 3, clause 23.2.4). The kind decides what the latched digest is compared
/// against when the session authorizes a command (Part 4 <c>CheckPolicyAuthSession</c>: the command's cpHash,
/// the digest of its handle Names, the digest of its command code and parameters, or the digest of its
/// creation template) and which later assertions may re-propose the slot (a proposal of another kind is
/// <c>TPM_RC_CPHASH</c> even when the octets agree).
/// </summary>
public enum TpmPolicyCpHashKind
{
    /// <summary>The slot holds its initialization value, the Empty Buffer; any kind may latch it.</summary>
    None,

    /// <summary>
    /// The slot holds a command-parameter digest: <c>TPM2_PolicyCpHash()</c>'s <c>cpHashA</c>, or the
    /// <c>cpHashA</c> a <c>TPM2_PolicySigned()</c>/<c>TPM2_PolicySecret()</c>/<c>TPM2_PolicyTicket()</c>
    /// authorization bound (Part 3, clause 23.2.2 item 6). Compared against the authorized command's own cpHash.
    /// </summary>
    CpHash,

    /// <summary>
    /// The slot holds a digest of the Names of the handles the authorized command must reference —
    /// <c>TPM2_PolicyNameHash()</c>'s caller-supplied <c>nameHash</c> (Part 3, clause 23.14) or the
    /// <c>H(objectName ‖ newParentName)</c> <c>TPM2_PolicyDuplicationSelect()</c> computes itself (clause 23.15) —
    /// compared against <c>H(Name1 ‖ … ‖ NameN)</c> under the session hash.
    /// </summary>
    NameHash,

    /// <summary>
    /// The slot holds <c>TPM2_PolicyParameters()</c>'s digest of the command code and parameters the authorized
    /// command must carry (Part 3, clause 23.24), compared against <c>H(commandCode ‖ parameters)</c> under the
    /// session hash — the Names skipped, the parameters as received (Part 4 <c>CompareParametersHash</c>).
    /// </summary>
    ParametersHash,

    /// <summary>
    /// The slot holds <c>TPM2_PolicyTemplate()</c>'s digest of the creation template (Part 3, clause 23.21),
    /// compared against the digest of an object-creation command's <c>inPublic</c> buffer and unsatisfiable by
    /// any other command.
    /// </summary>
    TemplateHash
}
