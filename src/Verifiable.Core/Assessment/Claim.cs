﻿using System;

namespace Verifiable.Assessment
{
    /// <summary>
    /// Represents a generic context for a claim, providing a mechanism to associate 
    /// additional information or metadata with a validation claim.
    /// </summary>
    /// <remarks>
    /// <para>
    /// ClaimContext is intended to encapsulate any additional information or metadata
    /// relevant to a claim that might be pertinent for further processing, auditing, 
    /// or debugging. This can include details such as the circumstances under which 
    /// the claim was generated, additional data used in the validation, or any other 
    /// relevant context information.
    /// </para>
    /// <para>
    /// The availability of context information enhances the traceability and auditability 
    /// of claims, especially in scenarios where post-processing verification or analysis is required.
    /// </para>
    /// </remarks>
    public record ClaimContext()
    {
        /// <summary>
        /// This means that the claim is not associated with any particular context.
        /// For instance, a straightforward parameter validation may not need context.
        /// </summary>
        public static ClaimContext None { get; } = new ClaimContext();
    }


    /// <summary>
    /// Provides context information for a claim generated using a machine learning model, 
    /// enabling enhanced traceability, auditability, and interpretability for model-driven validation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// MachineLearningClaimContext is designed to capture and provide additional context 
    /// specifically related to claims generated through machine learning model inference. 
    /// This can include details such as the version of the model used, potentially aiding in:
    /// </para>
    /// <list type="bullet">
    /// <item>
    /// <description><strong>Traceability</strong>: Ensuring the origin and the process of 
    /// claim generation can be retraced and verified.</description>
    /// </item>
    /// <item>
    /// <description><strong>Auditability</strong>: Facilitating auditing processes by 
    /// providing clear context and origin details of the claim.</description>
    /// </item>
    /// <item>
    /// <description><strong>Debugging</strong>: Enhancing the ability to investigate 
    /// and resolve issues related to claim generation by machine learning models.</description>
    /// </item>
    /// <item>
    /// <description><strong>Interpretability</strong>: Allowing deeper insight into the decision-making
    /// process of machine learning models by potentially correlating claim contexts with model interpretation
    /// techniques, such as SHAPley values.</description>
    /// </item>
    /// </list>
    /// <para>
    /// This additional context is crucial in environments where regulatory compliance,
    /// system transparency, and data integrity are paramount. It becomes especially vital
    /// when the model's decisions need to be interpreted and justified, for instance, by 
    /// using SHAPley values to elucidate the influence of input features on the model's predictions.
    /// </para>
    /// <para>
    /// Developers utilizing machine learning models that employ techniques like <c>SHAPley</c> values
    /// to explain predictions can extend this context to encapsulate such interpretability 
    /// metrics, ensuring that claims generated by the model can be thoroughly analyzed and justified.
    /// </para>
    /// </remarks>
    public record MachineLearningClaimContext: ClaimContext
    {
        /// <summary>
        /// Version of the machine learning model used to generate the claim, providing a 
        /// reference point for auditing, validating, and interpreting the generated claim.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The model version can be crucial for tracing the origin of the claim and ensuring
        /// that any interpretations, validations, or analyses related to the claim can be 
        /// accurately aligned with the correct version of the model. This ensures consistency
        /// and accuracy in operations that involve reviewing, debugging, or validating claims 
        /// in scenarios where multiple model versions may exist.
        /// </para>
        /// </remarks>
        public string ModelVersion { get; set; } = string.Empty;
    }



    /// <summary>
    /// Represents possible outcomes of a claim, especially pertinent to inference and validation operations.
    /// </summary>
    public enum ClaimOutcome
    {
        /// <summary>
        /// Indicates that the validation or inference was successful and meets acceptable confidence or validity bounds.
        /// </summary>
        Success,

        /// <summary>
        /// Indicates that the validation or inference was clearly unsuccessful or produced an invalid result.
        /// </summary>
        Failure,

        /// <summary>
        /// Indicates that the result of the validation or inference is not definitive, or the confidence is below a certain acceptable threshold.
        /// </summary>
        Inconclusive,

        /// <summary>
        /// Indicates that the validation logic or inference model couldn't be applied or was not relevant for the given input or context.
        /// </summary>
        NotApplicable
    }


    /// <summary>
    /// Represents an individual validation claim as an immutable record.
    /// Each Claim provides a verifiable assertion regarding a particular validation 
    /// operation and is designed to be processed, stored, and potentially verified in
    /// various decentralized and distributed system architectures.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The Claim structure is intended to provide a robust, traceable, and auditable record 
    /// of individual validation operations, supporting various use cases including:
    /// </para>
    /// <list type="bullet">
    /// <item>
    /// <description><strong>Decentralized Systems:</strong> Claims can be generated, processed, and verified across distributed systems without a centralized authority, adhering to decentralized governance models.</description>
    /// </item>
    /// <item>
    /// <description><strong>Regulatory Adherence:</strong> The immutability and traceability of Claims support adherence to various regulatory and contractual obligations, providing a transparent and auditable trail of validations, decisions, and actions taken by the system.</description>
    /// </item>
    /// <item>
    /// <description><strong>Multi-Temporal Processing:</strong> Claims can be utilized in environments that operate on various time scales, facilitating real-time to slower, deliberate processing and decision-making models.</description>
    /// </item>
    /// <item>
    /// <description><strong>Duty of Care:</strong> Claims enable systems to demonstrate a duty of care by preserving a transparent and verifiable record of validations and actions, which can be reviewed and audited post-processing.</description>
    /// </item>
    /// </list>
    /// <para>
    /// Claims are designed to be aggregated into a <see cref="ClaimIssueResult"/> by <see cref="ClaimIssuer{TInput}"/>, 
    /// providing a comprehensive and transparent record of validation operations, supporting auditability, traceability, and 
    /// regulatory adherence in complex distributed environments.
    /// </para>
    /// </remarks>
    /// <param name="Id">An identifier for the claim.</param>
    /// <param name="IsSuccess">Indicates if this individual validation claim is considered successful.</param>
    public record Claim
    {
        /// <summary>
        /// The identifier for this claim.
        /// </summary>
        public ClaimId Id { get; }


        /// <summary>
        /// The claim check outcome.
        /// </summary>
        public ClaimOutcome Outcome { get; }


        /// <summary>
        /// Metadata, or context information, associated with the claim.
        /// </summary>
        public ClaimContext Context { get; }


        /// <summary>
        /// <see cref="Claim"/> constructor.
        /// </summary>
        /// <param name="id">The identifier for this claim.</param>
        /// <param name="outcome">The outcome of the claim check.</param>
        /// <param name="context">Metadata, or context information, associated with the claim.</param>
        public Claim(ClaimId id, ClaimOutcome outcome, ClaimContext context)
        {
            ArgumentNullException.ThrowIfNull(id, nameof(id));
            ArgumentNullException.ThrowIfNull(context, nameof(context));

            Id = id;
            Outcome = outcome;
            Context = context;
        }


        /// <summary>
        /// <see cref="Claim"/> constructor.
        /// </summary>
        /// <param name="id">The identifier for this claim.</param>
        /// <param name="outcome">The outcome of the claim check.</param>
        public Claim(ClaimId id, ClaimOutcome outcome) : this(id, outcome, ClaimContext.None) { }
    }


    /// <summary>
    /// Represents a specialized claim indicating a failure in claim generation, 
    /// providing a mechanism to record and report issues or malfunctions in the validation logic.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="FailedClaim"/> is intended to serve as a clear and explicit indicator of a failure or issue
    /// encountered during the claim generation process. It encapsulates details about the failure, 
    /// providing valuable context and information that can be used for debugging, auditing, and reporting purposes.
    /// </para>
    /// <para>
    /// This claim type is crucial in ensuring the robustness, reliability, and transparency of 
    /// the validation and claim generation process, especially in scenarios where comprehensive 
    /// auditing and error tracking are required.
    /// </para>
    /// </remarks>
    public record FailedClaim: Claim
    {
        public FailedClaim(string failedRuleIdentifier, string failureContext): base(
            ClaimId.FailedClaim,
            ClaimOutcome.Failure,
            new FailedClaimContext { FailedRuleIdentifier = failedRuleIdentifier, FailureMessage = failureContext })
        { }
    }
}