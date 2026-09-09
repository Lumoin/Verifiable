using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Diagnostics;

namespace Verifiable.Core.Assessment
{
    /// <summary>
    /// Signature to generate the identifier for a single archiving operation.
    /// </summary>
    /// <param name="cancellationToken">Token to monitor for cancellation.</param>
    /// <returns>The identifier minted for this archiving operation.</returns>
    public delegate ValueTask<string> GenerateArchivingIdAsync(CancellationToken cancellationToken = default);


    /// <summary>
    /// Orchestrates the archiving of assessment results with consistent time handling,
    /// tracing, and support for regulatory retrieval requirements.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The <see cref="AssessmentArchiver"/> provides a structured approach to persisting
    /// assessment results for long-term storage, audit trails, and regulatory compliance.
    /// It ensures that archived data includes comprehensive provenance information.
    /// </para>
    ///
    /// <para>
    /// <strong>Archive Contents:</strong>
    /// </para>
    /// <para>
    /// Each archive operation captures:
    /// </para>
    /// <list type="bullet">
    /// <item><description>The complete <see cref="AssessmentResult"/> or <see cref="AggregatedAssessmentResult"/>.</description></item>
    /// <item><description>Timestamps from the caller's <see cref="TimeProvider"/>.</description></item>
    /// <item><description>OpenTelemetry trace correlation (TraceId, SpanId, Baggage).</description></item>
    /// <item><description>Archiver version for tracking archival logic changes.</description></item>
    /// <item><description>User-supplied correlation ID for cross-system linking.</description></item>
    /// </list>
    ///
    /// <para>
    /// <strong>Regulatory Retrieval:</strong>
    /// </para>
    /// <para>
    /// The archiver is designed to support post-facto retrieval for:
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// <strong>Compliance Audits:</strong> Retrieve all assessments for a given DID,
    /// credential type, or time period.
    /// </description></item>
    /// <item><description>
    /// <strong>Remediation:</strong> When issues are discovered, trace back to the
    /// original assessment decision and all contributing factors.
    /// </description></item>
    /// <item><description>
    /// <strong>Model Governance:</strong> Link assessments to specific ML model versions,
    /// Docker image SHAs, and code commits via baggage propagation.
    /// </description></item>
    /// <item><description>
    /// <strong>Dispute Resolution:</strong> Provide cryptographic proof of what was
    /// assessed and when, supporting legal and contractual obligations.
    /// </description></item>
    /// </list>
    ///
    /// <para>
    /// <strong>Integration Points:</strong>
    /// </para>
    /// <para>
    /// Archives can be correlated with external systems:
    /// </para>
    /// <list type="bullet">
    /// <item><description>OpenTelemetry backends (Jaeger, Tempo) via TraceId.</description></item>
    /// <item><description>Sigstore/SPIFFE for identity attestation.</description></item>
    /// <item><description>Container registries via Docker image SHAs in baggage.</description></item>
    /// <item><description>Version control via commit SHAs in baggage.</description></item>
    /// <item><description>Temporal databases for point-in-time state reconstruction.</description></item>
    /// </list>
    /// </remarks>
    public class AssessmentArchiver
    {
        /// <summary>
        /// Default archiving ID generator, minting a new <see cref="Guid"/> per call.
        /// </summary>
        /// <param name="cancellationToken">Token to monitor for cancellation.</param>
        /// <returns>A newly minted, GUID-based archiving identifier.</returns>
        public static ValueTask<string> DefaultArchivingIdGenerator(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(Guid.NewGuid().ToString());
        }

        /// <summary>
        /// The delegate that performs the actual archiving.
        /// </summary>
        private ArchiveDelegateAsync Archiver { get; }

        /// <summary>
        /// Unique identifier for this archiver instance.
        /// </summary>
        private string ArchiverId { get; }

        /// <summary>
        /// Time provider for timestamps.
        /// </summary>
        private TimeProvider TimeProvider { get; }

        /// <summary>
        /// Mints the identifier ("<c>ArchivingId</c>") the archiver assigns to each archiving
        /// operation it performs, distinct from <see cref="ArchivingResult.ArchiveId"/>, which the
        /// archiving delegate itself assigns to identify the stored data.
        /// </summary>
        private GenerateArchivingIdAsync ArchivingIdGenerator { get; }


        /// <summary>
        /// Constructs an <see cref="AssessmentArchiver"/> with the specified configuration.
        /// </summary>
        /// <param name="archiver">The delegate that performs the actual archiving.</param>
        /// <param name="archiverId">Unique identifier for this archiver.</param>
        /// <param name="timeProvider">Time provider for timestamps.</param>
        /// <param name="archivingIdGenerator">
        /// Mints the identifier for each archiving operation this archiver performs. Callers that
        /// want GUID-based identifiers pass <see cref="DefaultArchivingIdGenerator"/> explicitly.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="archiver"/>, <paramref name="timeProvider"/>, or
        /// <paramref name="archivingIdGenerator"/> is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="archiverId"/> is null or empty.
        /// </exception>
        public AssessmentArchiver(
            ArchiveDelegateAsync archiver,
            string archiverId,
            TimeProvider timeProvider,
            GenerateArchivingIdAsync archivingIdGenerator)
        {
            ArgumentNullException.ThrowIfNull(archiver, nameof(archiver));
            ArgumentException.ThrowIfNullOrEmpty(archiverId, nameof(archiverId));
            ArgumentNullException.ThrowIfNull(timeProvider, nameof(timeProvider));
            ArgumentNullException.ThrowIfNull(archivingIdGenerator, nameof(archivingIdGenerator));

            Archiver = archiver;
            ArchiverId = archiverId;
            TimeProvider = timeProvider;
            ArchivingIdGenerator = archivingIdGenerator;
        }


        /// <summary>
        /// Archives a single assessment result.
        /// </summary>
        /// <param name="assessmentResult">The assessment result to archive.</param>
        /// <param name="cancellationToken">Token to monitor for cancellation.</param>
        /// <returns>The archiving result indicating success or failure.</returns>
        /// <exception cref="InvalidOperationException">
        /// Thrown when the archiving delegate returns a result whose <see cref="ArchivingResult.ArchivingId"/>
        /// differs from the identifier this archiver minted for the operation via <see cref="ArchivingIdGenerator"/>.
        /// </exception>
        public async ValueTask<ArchivingResult> ArchiveAsync(
            AssessmentResult assessmentResult,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(assessmentResult, nameof(assessmentResult));

            string archivingId = await ArchivingIdGenerator(cancellationToken).ConfigureAwait(false);
            var creationTimestamp = TimeProvider.GetUtcNow().UtcDateTime;
            var traceId = TracingUtilities.GetOrCreateTraceId();
            var spanId = TracingUtilities.GetOrCreateSpanId();
            var baggage = TracingUtilities.GetOrCreateBaggage();

            ArchivingResult result = await Archiver(
                assessmentResult,
                ArchiverId,
                archivingId,
                creationTimestamp,
                traceId,
                spanId,
                baggage,
                cancellationToken).ConfigureAwait(false);

            if(result.ArchivingId != archivingId)
            {
                throw new InvalidOperationException(
                    $"The archiving delegate returned ArchivingId '{result.ArchivingId}', but the archiver minted '{archivingId}' for this operation.");
            }

            return result;
        }


        /// <summary>
        /// Archives an aggregated assessment result from parallel assessors.
        /// </summary>
        /// <param name="aggregatedResult">The aggregated assessment result to archive.</param>
        /// <param name="cancellationToken">Token to monitor for cancellation.</param>
        /// <returns>
        /// A list of archiving results, one for each individual assessment within the aggregation.
        /// </returns>
        /// <remarks>
        /// <para>
        /// This method archives each completed assessment result individually, enabling
        /// fine-grained retrieval and independent lifecycle management.
        /// </para>
        /// </remarks>
        /// <exception cref="InvalidOperationException">
        /// Thrown when the archiving delegate returns a result whose <see cref="ArchivingResult.ArchivingId"/>
        /// differs from the identifier minted for that individual result via <see cref="ArchivingIdGenerator"/>:
        /// <see cref="ArchiveAsync"/> enforces the archiving-identifier contract on every individual result.
        /// </exception>
        public async ValueTask<IReadOnlyList<ArchivingResult>> ArchiveAggregatedAsync(
            AggregatedAssessmentResult aggregatedResult,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(aggregatedResult, nameof(aggregatedResult));

            var results = new List<ArchivingResult>();
            foreach(var individual in aggregatedResult.IndividualResults)
            {
                if(individual.Result != null)
                {
                    var result = await ArchiveAsync(
                        individual.Result,
                        cancellationToken).ConfigureAwait(false);

                    results.Add(result);
                }
            }

            return results;
        }
    }
}
