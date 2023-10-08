using System;
using System.Collections.Generic;
using System.Threading.Tasks;


namespace Verifiable.Assessment
{
    // <summary>
    /// Defines a signature for rules to validate inputs.
    /// </summary>
    /// <param name="input">The input to validate.</param>
    /// <typeparam name="TInput">The type of input.</typeparam>
    /// <returns>A list of <see cref="Claim"/> objects indicating the result of each validation.</returns>
    /// <remarks>
    /// <para>
    /// This delegate type is intended to encapsulate the various validation rules applicable to input.
    /// Each rule should produce one or more <see cref="Claim"/> objects that capture the outcome of the validation.
    /// </para>
    /// </remarks>
    public delegate ValueTask<IList<Claim>> ClaimDelegateAsync<TInput>(TInput input);


    /// <summary>
    /// Represents a wrapper for a claim generation delegate, designed to provide additional metadata about the claims 
    /// it is expected to produce, enhancing traceability, debugging, and validation across distributed, regulated, and multi-temporal environments.
    /// </summary>
    /// <remarks>
    /// <para>
    /// ClaimDelegateWrapper acts as an augmented delegate, encapsulating not only the delegate itself but also a list of expected 
    /// claim IDs it should generate, serving various essential purposes in systems, especially those operating in distributed, 
    /// decentralized, and regulated contexts:
    /// </para>
    /// <list type="bullet">
    /// <item>
    /// <description><strong>Traceability</strong>: It maps validation rules to their output, enabling clear tracking of claim origins
    /// and contributing to a transparent and auditable validation process.</description>
    /// </item>
    /// <item>
    /// <description><strong>Failure Tracking</strong>: Helps in identifying missing claims, which might indicate issues or 
    /// malfunctions in rule execution, thus aiding in ensuring the reliability and integrity of validations.</description>
    /// </item>    
    /// <item>
    /// <description><strong>Debugging and Logging</strong>: Enhances the system’s diagnostic capabilities by providing 
    /// richer context in tracing the decision-making process, aiding in analysis, debugging, and reporting.</description>
    /// </item>
    /// <item>    
    /// <description><strong>Documentation</strong>: Serves as embedded documentation, preserving knowledge about the system’s 
    /// expected behavior and the origin of claims, which is crucial for maintenance, review, and knowledge transfer.</description>
    /// </item>
    /// <item>
    /// <description><strong>Validation</strong>: Aids in validating the correctness and completeness of rule implementations, 
    /// especially during updates or expansions, ensuring the consistent and accurate generation of claims.</description>
    /// </item>
    /// </list>
    /// <para>
    /// This wrapper contributes to building a robust, traceable, and maintainable system, providing potent debugging, monitoring, 
    /// and reporting capabilities, especially in environments that demand regulatory adherence, distributed governance, and varied processing timelines.
    /// </para>
    /// </remarks>
    /// <typeparam name="TInput">The type of input the delegate will process.</typeparam>
    public class ClaimDelegate<TInput>
    {
        /// <summary>
        /// Gets the claim generation delegate.
        /// </summary>
        /// <value>The claim generation delegate that processes the input and generates claims.</value>
        /// <remarks>
        /// The Delegate is responsible for executing the validation logic and producing claims 
        /// based on the input it processes. It plays a fundamental role in the generation of claims 
        /// that are then utilized for assessment, reporting, and auditing.
        /// </remarks>
        public ClaimDelegateAsync<TInput> Delegate { get; }

        /// <summary>
        /// Gets the list of expected claim IDs that the delegate should produce.
        /// </summary>
        /// <value>A list of expected claim IDs.</value>
        /// <remarks>
        /// ExpectedClaimIds provide a predefined set of claim IDs that the delegate is expected to produce, 
        /// serving as a contract or a set of expectations that aid in validation, debugging, and auditing, 
        /// ensuring that the delegate produces the expected claims during its execution.
        /// </remarks>
        public List<ClaimId> ExpectedClaimIds { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="ClaimDelegate{TInput}"/> class.
        /// </summary>
        /// <param name="delegate">The claim generation delegate.</param>
        /// <param name="expectedClaimIds">The list of expected claim IDs.</param>
        /// <remarks>
        /// The constructor initializes the ClaimDelegateWrapper with a specified delegate and a list of expected claim IDs, 
        /// ensuring that the wrapper has the necessary components to execute the delegate and validate its output against 
        /// the expected claims.
        /// </remarks>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="delegate"/> or <paramref name="expectedClaimIds"/> is null.</exception>
        public ClaimDelegate(ClaimDelegateAsync<TInput> @delegate, List<ClaimId> expectedClaimIds)
        {
            ArgumentNullException.ThrowIfNull(@delegate, nameof(@delegate));
            ArgumentNullException.ThrowIfNull(expectedClaimIds, nameof(expectedClaimIds));

            Delegate = @delegate;
            ExpectedClaimIds = expectedClaimIds;
        }
    }
}
