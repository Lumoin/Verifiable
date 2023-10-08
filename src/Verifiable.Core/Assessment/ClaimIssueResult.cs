using System;
using System.Collections.Generic;

namespace Verifiable.Assessment
{
    /// <summary>
    /// The data or conditions upon which claims are based.
    /// </summary>
    public class ClaimIssueResultContext
    {
        /// <summary>
        /// Gets or sets the inputs used for the claim generation operation.        
        /// </summary>
        public object? Inputs { get; set; }
    }


    /// <summary>
    /// <para>
    /// Consolidates the outputs of a claim generation step, including the claims themselves,
    /// tracing identifiers, and any extra metadata. This makes possible follow the validation process across multiple steps
    /// from where it started to where it ended.
    /// </para>
    /// <para>
    /// This record is designed to be passed to subsequent stages of the validation and assessment pipeline, potentially
    /// including archival or further analysis.
    /// </para>
    /// </summary>
    /// <param name="ClaimIssueResultId">Identifier for this issued <see cref="ClaimIssueResult"/>.</param>
    /// <param name="ClaimIssuerId">Identifier for the claim issuer.</param>
    /// <param name="Claims">List of claims generated.</param>
    /// <param name="CorrelationId">User-supplied identifier to correlate claim generation with other operations.</param>
    /// <param name="CreationTimestampInUtc">UTC timestamp indicating when the claim results were generated.</param>    
    /// <param name="IssuingContext">Optional context data related to the issuing process.</param>
    /// <param name="ClaimIssuerTraceId">Tracing identifier for the claim generation operation.</param>
    /// <param name="ClaimIssuerSpanId">Span identifier for the claim generation operation.</param>
    /// <param name="Baggage">Additional context for the claim generation operation.</param>    
    public record ClaimIssueResult(
        string ClaimIssueResultId,
        string ClaimIssuerId,
        string CorrelationId,
        IList<Claim> Claims,
        DateTime CreationTimestampInUtc,
        ClaimIssueResultContext? IssuingContext = null,
        string? ClaimIssuerTraceId = null,
        string? ClaimIssuerSpanId = null,
        IReadOnlyDictionary<string, string>? Baggage = null);
}
