namespace Verifiable.Tpm.Spec.Constants;

/// <summary>
/// Extension methods for <see cref="TpmClockAdjustConstants"/>.
/// </summary>
public static class TpmClockAdjustConstantsExtensions
{
    /// <summary>
    /// Gets whether <paramref name="value"/> names one of Table 19's seven defined
    /// <c>TPM_CLOCK_ADJUST</c> steps rather than an octet the wire carried outside that set.
    /// </summary>
    /// <param name="value">
    /// The value read from the wire, unchecked — <c>TPM_CLOCK_ADJUST</c> is unmarshaled without
    /// validation (TPM 2.0 Library Part 2, clause 6.7, Table 19's <c>#TPM_RC_VALUE</c> marker), so an
    /// out-of-range octet reaches this predicate as an ordinary enum value rather than a parse failure.
    /// </param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is one of the seven Table 19 members.</returns>
    public static bool IsDefined(this TpmClockAdjustConstants value)
    {
        return value switch
        {
            TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER => true,
            TpmClockAdjustConstants.TPM_CLOCK_MEDIUM_SLOWER => true,
            TpmClockAdjustConstants.TPM_CLOCK_FINE_SLOWER => true,
            TpmClockAdjustConstants.TPM_CLOCK_NO_CHANGE => true,
            TpmClockAdjustConstants.TPM_CLOCK_FINE_FASTER => true,
            TpmClockAdjustConstants.TPM_CLOCK_MEDIUM_FASTER => true,
            TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER => true,
            _ => false
        };
    }
}
