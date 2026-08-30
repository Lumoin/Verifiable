namespace Verifiable.Tpm.Automata;

/// <summary>
/// Selects which <c>PolicyUpdate</c> formula a policyDigest fold applies (TPM 2.0 Library Part 3, clause 23;
/// Part 1, clause 16.7). Every fold in the simulator runs through one seam keyed by this value, so the
/// destination is rented at the session's digest width in a frame that holds a memory pool.
/// </summary>
/// <remarks>
/// An assertion whose fold already sits downstream of an effect that runs anyway — <c>TPM2_PolicySigned()</c>
/// and <c>TPM2_PolicyAuthorize()</c> on their non-trial arms, <c>TPM2_PolicyTicket()</c>,
/// <c>TPM2_PolicyNV()</c>, and <c>TPM2_PolicySecret()</c>'s ticket arm — names its formula here from inside
/// that effect. The rest declare the shared <see cref="TpmFoldPolicyDigestAction"/>, which carries only the
/// subset of values reachable that way.
/// </remarks>
public enum TpmPolicyDigestFold
{
    /// <summary><c>TPM2_PolicyCommandCode()</c>: <c>H(policyDigest ‖ TPM_CC_PolicyCommandCode ‖ code)</c> (Part 3, clause 23.11).</summary>
    CommandCode,

    /// <summary><c>TPM2_PolicyAuthValue()</c>: <c>H(policyDigest ‖ TPM_CC_PolicyAuthValue)</c> (Part 3, clause 23.17).</summary>
    AuthValue,

    /// <summary><c>TPM2_PolicyPCR()</c>: <c>H(policyDigest ‖ TPM_CC_PolicyPCR ‖ pcrs ‖ pcrDigest)</c>, over the live composite on a real session (Part 3, clause 23.7).</summary>
    Pcr,

    /// <summary><c>TPM2_PolicyOR()</c>: <c>H(0…0 ‖ TPM_CC_PolicyOR ‖ branches)</c> (Part 3, clause 23.6).</summary>
    Or,

    /// <summary><c>TPM2_PolicyCounterTimer()</c>: <c>H(policyDigest ‖ TPM_CC_PolicyCounterTimer ‖ argHash)</c> (Part 3, clause 23.10).</summary>
    CounterTimer,

    /// <summary><c>TPM2_PolicySecret()</c>'s trial and no-ticket arms: <c>H(policyDigest ‖ TPM_CC_PolicySecret ‖ authName)</c> then the policyRef hash (Part 3, Section 23.4).</summary>
    Secret,

    /// <summary><c>TPM2_PolicySigned()</c>'s trial arm: <c>H(policyDigest ‖ TPM_CC_PolicySigned ‖ authObjectName)</c> then the policyRef hash (Part 3, Section 23.3).</summary>
    Signed,

    /// <summary><c>TPM2_PolicyAuthorize()</c>'s trial arm: <c>H(0…0 ‖ TPM_CC_PolicyAuthorize ‖ keySign)</c> then the policyRef hash (Part 3, Section 23.16).</summary>
    Authorize,

    /// <summary><c>TPM2_PolicyNV()</c>: <c>H(policyDigest ‖ TPM_CC_PolicyNV ‖ H(operandB ‖ offset ‖ operation) ‖ nvName)</c> (Part 3, clause 23.9), applied inside the Name-computation effect the assertion already runs.</summary>
    Nv,

    /// <summary><c>TPM2_PolicyCpHash()</c>: <c>H(policyDigest ‖ TPM_CC_PolicyCpHash ‖ cpHashA)</c> (Part 3, clause 23.13).</summary>
    CpHash,

    /// <summary><c>TPM2_PolicyNameHash()</c>: <c>H(policyDigest ‖ TPM_CC_PolicyNameHash ‖ nameHash)</c> (Part 3, clause 23.14).</summary>
    NameHash,

    /// <summary><c>TPM2_PolicyTemplate()</c>: <c>H(policyDigest ‖ TPM_CC_PolicyTemplate ‖ templateHash)</c> (Part 3, clause 23.21).</summary>
    Template,

    /// <summary><c>TPM2_PolicyDuplicationSelect()</c>: <c>H(policyDigest ‖ TPM_CC_PolicyDuplicationSelect ‖ [objectName ‖] newParentName ‖ includeObject)</c>, the object Name folded only when <c>includeObject</c> is YES; the effect also computes the <c>H(objectName ‖ newParentName)</c> nameHash the resuming transition latches (Part 3, clause 23.15).</summary>
    DuplicationSelect,

    /// <summary><c>TPM2_PolicyParameters()</c>: <c>H(policyDigest ‖ TPM_CC_PolicyParameters ‖ pHash)</c> (Part 3, clause 23.24).</summary>
    Parameters,

    /// <summary><c>TPM2_PolicyLocality()</c>: <c>H(policyDigest ‖ TPM_CC_PolicyLocality ‖ locality)</c> over the octet as sent (Part 3, clause 23.8).</summary>
    Locality,

    /// <summary><c>TPM2_PolicyNvWritten()</c>: <c>H(policyDigest ‖ TPM_CC_PolicyNvWritten ‖ writtenSet)</c> (Part 3, clause 23.20).</summary>
    NvWritten,

    /// <summary><c>TPM2_PolicyAuthorizeNV()</c>: <c>H(0…0 ‖ TPM_CC_PolicyAuthorizeNV ‖ nvName)</c>, resetting to a Zero Digest first (Part 3, clause 23.22, equation 9), applied inside the Name-computation effect the assertion already runs.</summary>
    AuthorizeNv
}
