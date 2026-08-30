namespace Verifiable.Tpm.Automata;

/// <summary>
/// The per-register PCR attributes of the TCG PC Client Platform TPM Profile (PTP 1.07, clause 4.7.1, Table 14
/// "PCR Attributes", and clause 4.7.2, Table 15 "PCR Initial and Reset Values"), rendered for the one locality
/// this simulator receives commands at: locality 0.
/// </summary>
/// <remarks>
/// <para>
/// TPM 2.0 Library Part 1, clause 14.1 leaves a PCR's reset value and the localities that may extend or reset it
/// to "a platform-specific specification"; Table 14 is that specification for a PC Client TPM. Every command
/// reaches this simulator over one interface with no locality signal, so the model is fixed at locality 0 —
/// the locality software uses — and each Table 14 locality column is read at <c>x = 0</c>: "Extended by
/// TPM2_PCR_Extend" is Y for PCR 0–16 and 23 and N for the D-RTM registers 17–22; "Reset by TPM2_PCR_Reset" is
/// Y for PCR 16 (Debug) and 23 (Application Specific) only. A refused extend or reset answers
/// <c>TPM_RC_LOCALITY</c> (Part 3, clause 22.8.1: "TPM_RC_LOCALITY is returned because the reset attributes are
/// defined on a per-locality basis"; Part 4 <c>PCRIsExtendAllowed</c>/<c>PCRIsResetAllowed</c>). The higher
/// localities exist only for the D-RTM hardware and are not modelled.
/// </para>
/// <para>
/// Two further columns drive the change counter and the Startup rule. <c>TPM_PT_PCR_NO_INCREMENT</c> is SET on
/// PCR 16, 21, 22 and 23: a change to those registers does not move <c>pcrUpdateCounter</c> (Part 3, clause
/// 22.1: "unless the platform-specific specification explicitly excludes the PCR from being counted"; Part 1,
/// clause 14.9; Part 4 <c>PCRBelongsTCBGroup</c>). <c>TPM_PT_PCR_SAVE</c> is SET on PCR 0–15 only: those are
/// the registers a TPM Resume restores, every other register returning to its reset image (Part 1, clause 14.1;
/// Part 4 <c>PCRStartup</c>). Table 15 gives the reset image: PCR 0 the Startup locality indicator (0 at locality
/// 0), PCR 1–16 and 23 all zeros, and the D-RTM registers 17–22 −1, all ones.
/// </para>
/// </remarks>
public static class PcClientPcrAttributes
{
    /// <summary>The Debug register (Table 14 alias), resettable and extendable at every software locality.</summary>
    public const int DebugPcr = 16;

    /// <summary>The first D-RTM register (Locality 4, Table 14 alias) — the start of the all-ones reset image.</summary>
    public const int FirstDynamicRootPcr = 17;

    /// <summary>The last D-RTM register (Dynamic OS Controlled, Table 14 alias) — the end of the all-ones reset image.</summary>
    public const int LastDynamicRootPcr = 22;

    /// <summary>The Application Specific register (Table 14 alias), resettable and extendable at every locality.</summary>
    public const int ApplicationPcr = 23;

    /// <summary>The last register a TPM Resume restores (<c>TPM_PT_PCR_SAVE</c> SET on PCR 0–15).</summary>
    public const int LastResumePreservedPcr = 15;

    /// <summary>
    /// The number of registers whose change moves <c>pcrUpdateCounter</c>: the 24 registers less the four
    /// <c>TPM_PT_PCR_NO_INCREMENT</c> ones. This is also the counter's value after a TPM Reset, which clears it
    /// and then re-initializes every register (Part 4 <c>PCRStartup</c>: <c>PCRChanged</c> once per register not
    /// restored from saved state).
    /// </summary>
    public static int CountedPcrCount { get; } = CountRegisters(static pcr => IsUpdateCounted(pcr));

    /// <summary>
    /// The number of counted registers a TPM Resume re-initializes — those NOT preserved by
    /// <c>TPM_PT_PCR_SAVE</c> and counted: PCR 17–20. A Resume moves <c>pcrUpdateCounter</c> by this amount.
    /// </summary>
    public static int CountedPcrsResetByResume { get; } = CountRegisters(static pcr => !IsPreservedByResume(pcr) && IsUpdateCounted(pcr));

    /// <summary>
    /// Whether <c>TPM2_PCR_Extend()</c>, <c>TPM2_PCR_Event()</c> and <c>TPM2_EventSequenceComplete()</c> may
    /// extend <paramref name="pcr"/> at locality 0 (Table 14, column "Extended by TPM2_PCR_Extend", x = 0).
    /// </summary>
    /// <param name="pcr">The register index.</param>
    /// <returns><see langword="true"/> for PCR 0–16 and 23; <see langword="false"/> for the D-RTM registers 17–22.</returns>
    public static bool IsExtendAllowedAtLocalityZero(int pcr) => pcr is (>= 0 and <= DebugPcr) or ApplicationPcr;

    /// <summary>
    /// Whether <c>TPM2_PCR_Reset()</c> may reset <paramref name="pcr"/> at locality 0 (Table 14, column "Reset by
    /// TPM2_PCR_Reset", x = 0).
    /// </summary>
    /// <param name="pcr">The register index.</param>
    /// <returns><see langword="true"/> for PCR 16 and 23 only.</returns>
    public static bool IsResetAllowedAtLocalityZero(int pcr) => pcr is DebugPcr or ApplicationPcr;

    /// <summary>
    /// Whether a change to <paramref name="pcr"/> moves <c>pcrUpdateCounter</c> — the complement of Table 14's
    /// <c>TPM_PT_PCR_NO_INCREMENT</c> column, SET on PCR 16, 21, 22 and 23.
    /// </summary>
    /// <param name="pcr">The register index.</param>
    /// <returns><see langword="true"/> unless the register is one of the four excluded ones.</returns>
    public static bool IsUpdateCounted(int pcr) => pcr is not (DebugPcr or 21 or 22 or ApplicationPcr);

    /// <summary>
    /// Whether a TPM Resume carries <paramref name="pcr"/> forward as it was at <c>TPM2_Shutdown(STATE)</c> —
    /// Table 14's <c>TPM_PT_PCR_SAVE</c> column, SET on PCR 0–15.
    /// </summary>
    /// <param name="pcr">The register index.</param>
    /// <returns><see langword="true"/> for PCR 0–15.</returns>
    public static bool IsPreservedByResume(int pcr) => pcr is >= 0 and <= LastResumePreservedPcr;

    /// <summary>
    /// Whether <paramref name="pcr"/>'s reset image is all ones (Table 15's −1): the D-RTM registers 17–22.
    /// Every other register resets to all zeros (PCR 0's locality indicator is 0 at locality 0).
    /// </summary>
    /// <param name="pcr">The register index.</param>
    /// <returns><see langword="true"/> for PCR 17–22.</returns>
    public static bool HasAllOnesResetImage(int pcr) => pcr is >= FirstDynamicRootPcr and <= LastDynamicRootPcr;

    /// <summary>
    /// Counts the registers of a bank satisfying <paramref name="predicate"/>.
    /// </summary>
    /// <param name="predicate">The per-register test.</param>
    /// <returns>The number of matching registers.</returns>
    private static int CountRegisters(System.Func<int, bool> predicate)
    {
        int count = 0;
        for(int pcr = 0; pcr < PcrBankState.PcrCount; pcr++)
        {
            if(predicate(pcr))
            {
                count++;
            }
        }

        return count;
    }
}
