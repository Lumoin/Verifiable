namespace Verifiable.Tpm.Automata;

/// <summary>
/// Selects which <c>PolicyUpdate</c> formula a policyDigest fold applies (TPM 2.0 Library Part 3, clause 23;
/// Part 1, clause 17.7). Every fold in the simulator runs through one seam keyed by this value, so the
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
    Nv
}
