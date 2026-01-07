namespace Verifiable.Core.Assessment
{
    /// <summary>
    /// Provides context information for a failed claim, enabling enhanced
    /// traceability and auditability for validation failures.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="FailedClaimContext"/> is designed to capture additional context 
    /// specifically related to claims that could not be generated 
    /// due to a failure or exception in the validation logic. This can include 
    /// details such as the name of the delegate that 
    /// encountered the failure and the exception message, aiding in:
    /// </para>
    /// <list type="bullet">
    /// <item>
    /// <description><strong>Debugging</strong>: Facilitating the identification and resolution 
    /// of issues in the validation logic.</description>
    /// </item>
    /// <item>
    /// <description><strong>Auditability</strong>: Ensuring that failures in the validation logic 
    /// can be audited and analyzed for systemic issues or for improving validation logic.</description>
    /// </item>
    /// <item>
    /// <description><strong>Reporting</strong>: Enhancing the ability to report failures and issues
    /// to stakeholders or systems in a detailed and informative manner.</description>
    /// </item>
    /// </list>
    /// </remarks>
    public record FailedClaimContext: ClaimContext
    {
        /// <summary>
        /// Gets the name of the delegate or validation rule that encountered the failure.
        /// </summary>
        public string FailedRuleIdentifier { get; init; } = string.Empty;

        /// <summary>
        /// Gets the exception message or error message associated with the failure.
        /// </summary>
        public string FailureMessage { get; init; } = string.Empty;
    }
}
