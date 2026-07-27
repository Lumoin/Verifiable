using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Attributes;

/// <summary>
/// Extension methods for <see cref="TpmEoConstants"/>.
/// </summary>
public static class TpmEoConstantsExtensions
{
    /// <summary>
    /// Gets a value indicating whether <paramref name="operation"/> is one of the 12 values <see cref="TpmEoConstants"/>
    /// defines (TPM 2.0 Library Specification, Part 2: Structures, Section 6.8, Table 22). An undefined <c>TPM_EO</c>
    /// must be rejected at unmarshal (Part 3, clause 5.1), so this is checked at PARSE time by both
    /// <c>TpmSimulator.TryParsePolicyNv</c> and <c>TpmSimulator.TryParsePolicyCounterTimer</c> — before a
    /// <c>TpmPolicyNvRequested</c>/<c>TpmPolicyCounterTimerRequested</c> carrying the value is ever built, so a real
    /// and a trial policy session reject an undefined operation identically instead of the real session's
    /// <see cref="TpmEoComparator.TryEvaluate"/> throwing while a trial session silently folds it unchecked.
    /// </summary>
    /// <param name="operation">The value to check.</param>
    /// <returns><see langword="true"/> when <paramref name="operation"/> is a defined <c>TPM_EO</c> value; otherwise <see langword="false"/>.</returns>
    public static bool IsDefined(this TpmEoConstants operation) => operation switch
    {
        TpmEoConstants.TPM_EO_EQ
            or TpmEoConstants.TPM_EO_NEQ
            or TpmEoConstants.TPM_EO_SIGNED_GT
            or TpmEoConstants.TPM_EO_UNSIGNED_GT
            or TpmEoConstants.TPM_EO_SIGNED_LT
            or TpmEoConstants.TPM_EO_UNSIGNED_LT
            or TpmEoConstants.TPM_EO_SIGNED_GE
            or TpmEoConstants.TPM_EO_UNSIGNED_GE
            or TpmEoConstants.TPM_EO_SIGNED_LE
            or TpmEoConstants.TPM_EO_UNSIGNED_LE
            or TpmEoConstants.TPM_EO_BITSET
            or TpmEoConstants.TPM_EO_BITCLEAR => true,
        _ => false
    };
}
