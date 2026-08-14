using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One entry of the mapping "between acceptable signature creation policies and their corresponding signature
/// validation policies" the Driving Application may provide to the validation context initialization building
/// block, per clause 5.2.4.4 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>.
/// </summary>
/// <param name="SignaturePolicyIdentifier">The signature creation policy identifier a signature may declare.</param>
/// <param name="Constraints">The validation constraints the SVA applies for that creation policy.</param>
[DebuggerDisplay("SignaturePolicyConstraintsMapping: {SignaturePolicyIdentifier}")]
public sealed record SignaturePolicyConstraintsMapping(string SignaturePolicyIdentifier, SignatureValidationConstraints Constraints);


/// <summary>
/// What the validation context initialization building block does with a signature that declares a creation
/// policy the mapping does not cover — the choice clause 5.2.4.4 states "shall be a policy decision (local
/// configuration)": "whether default rules apply for the validation, or if the validation process is to be
/// terminated".
/// </summary>
public enum UnmappedSignaturePolicyHandling
{
    /// <summary>
    /// Terminate the validation. The default, because it is the branch that assumes nothing: applying default
    /// rules to a signature created under a policy the verifier has not accepted validates it against
    /// constraints its signer never agreed to.
    /// </summary>
    TerminateValidation = 0,

    /// <summary>Apply the default validation constraints and continue.</summary>
    ApplyDefaultConstraints = 1
}


/// <summary>
/// Whether the electronic document containing the details of a signature policy could be accessed and processed
/// — the two failure branches clause 5.2.4.4 of EN 319 102-1 distinguishes.
/// </summary>
public enum SignaturePolicyResolutionStatus
{
    /// <summary>No resolution has been attempted. The value of an unset field, by design.</summary>
    NotResolved = 0,

    /// <summary>The policy document was accessed and its constraints extracted.</summary>
    Resolved = 1,

    /// <summary>The policy document "is not available" — the <c>SIGNATURE_POLICY_NOT_AVAILABLE</c> branch.</summary>
    NotAvailable = 2,

    /// <summary>The policy document "cannot be parsed or processed for any other reason" — the <c>POLICY_PROCESSING_ERROR</c> branch.</summary>
    ProcessingError = 3
}


/// <summary>
/// What a <see cref="ResolveSignatureValidationPolicyAsyncDelegate"/> made of the signature policy a signature
/// declares.
/// </summary>
[DebuggerDisplay("SignaturePolicyResolution: {Status}")]
public sealed record SignaturePolicyResolution
{
    /// <summary>Whether the policy document could be accessed and processed.</summary>
    public required SignaturePolicyResolutionStatus Status { get; init; }

    /// <summary>The constraints extracted from the policy; non-<see langword="null"/> exactly when <see cref="Status"/> is <see cref="SignaturePolicyResolutionStatus.Resolved"/>.</summary>
    public SignatureValidationConstraints? Constraints { get; init; }

    /// <summary>What the resolver could state about a failure — the "additional information on the problem" a <see cref="PolicyProcessingErrorReportData"/> carries; <see langword="null"/> on success.</summary>
    public string? Problem { get; init; }
}


/// <summary>
/// The per-call context a <see cref="ResolveSignatureValidationPolicyAsyncDelegate"/> implementation receives,
/// so the delegate carries no caller data through a lambda closure.
/// </summary>
[DebuggerDisplay("SignaturePolicyResolutionContext: {SignaturePolicyIdentifier}")]
public sealed record SignaturePolicyResolutionContext
{
    /// <summary>The signature policy identifier the signature declares.</summary>
    public required string SignaturePolicyIdentifier { get; init; }

    /// <summary>The signature's facts, for a resolver that has to read the policy attribute's own contents to locate the document.</summary>
    public required SignatureFacts Signature { get; init; }
}


/// <summary>
/// Accesses "the electronic document identified by the contents of the property/attribute and containing the
/// details of the policy" that clause 5.2.4.4 of EN 319 102-1 requires the validation context initialization
/// building block to obtain, and extracts the validation constraints it encodes.
/// </summary>
/// <param name="context">The declared policy identifier and the signature's facts.</param>
/// <param name="pool">The memory pool any scratch buffer is rented from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The resolution. A resolver reports a failure rather than throwing, so the block can map it to the sub-indication the clause names.</returns>
/// <remarks>
/// A seam rather than a parser, per the standing rule that transport is caller-supplied and per the scope
/// decision that this library consumes validation constraints rather than the policy artefact they came from.
/// </remarks>
public delegate ValueTask<SignaturePolicyResolution> ResolveSignatureValidationPolicyAsyncDelegate(
    SignaturePolicyResolutionContext context,
    BaseMemoryPool pool,
    CancellationToken cancellationToken);


/// <summary>
/// What the validation context initialization building block concluded — the outputs of Table 11 of clause
/// 5.2.4.3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> <see cref="CertificateValidationData"/> holds non-owning references to carriers
/// the signature's facts or the caller own.
/// </remarks>
[DebuggerDisplay("ValidationContextInitializationResult: {Conclusion.Indication}")]
public sealed record ValidationContextInitializationResult
{
    /// <summary>The block's conclusion.</summary>
    public required BuildingBlockConclusion Conclusion { get; init; }

    /// <summary>
    /// Table 11's <c>PASSED</c> outputs, in one record: the X.509 validation parameters and constraints, the
    /// cryptographic constraints and the signature elements constraints. <see langword="null"/> on
    /// <c>INDETERMINATE</c>.
    /// </summary>
    public SignatureValidationConstraints? Constraints { get; init; }

    /// <summary>
    /// Table 11's "Certificate Validation Data" output: the certificates, certificate revocation lists and OCSP
    /// responses gathered from the signature and from the caller, each carrying its own
    /// <see cref="PkiObjectKind"/> discriminator.
    /// </summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateValidationData { get; init; } = [];
}


/// <summary>
/// The validation context initialization building block of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.2.4</see>: it settles which validation constraints the rest of the
/// validation runs under, and gathers the certificate validation data those later blocks consume.
/// </summary>
/// <remarks>
/// <para>
/// The constraints themselves are caller-supplied declarative records, so this block selects rather than
/// parses. Clause 5.1.4.1 admits constraints "defined by a formal signature policy specification", "explicitly
/// in system specific control data" or "implicitly by the implementation", and every one of those reaches the
/// algorithm as a <see cref="SignatureValidationConstraints"/>. A caller driven by a formal policy artefact
/// supplies a <see cref="ResolveSignatureValidationPolicyAsyncDelegate"/> that turns the artefact into one.
/// </para>
/// </remarks>
public static class ValidationContextInitialization
{
    /// <summary>
    /// Selects the validation constraints and gathers the certificate validation data.
    /// </summary>
    /// <param name="signature">Table 10's mandatory "Signature" input, in the form the engine holds it.</param>
    /// <param name="defaultConstraints">The default validation policy clause 5.2.4.4 has the block select when the signature declares no creation policy.</param>
    /// <param name="policyMappings">Table 10's optional "Signature Validation Policies" input, as the mapping of clause 5.2.4.4; empty when the caller supplies none.</param>
    /// <param name="unmappedPolicyHandling">The local configuration decision for a declared creation policy the mapping does not cover.</param>
    /// <param name="resolveSignaturePolicy">The seam accessing a policy document the mapping does not cover, or <see langword="null"/> when the caller configures none.</param>
    /// <param name="callerSuppliedValidationData">Certificate validation data the Driving Application supplies in addition to what the signature carries — Table 10's "Trust anchor list" and "Local configuration" material.</param>
    /// <param name="pool">The memory pool the policy resolver rents any scratch buffer from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The conclusion of Table 11 and, on <c>PASSED</c>, the selected constraints and the gathered validation data.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    public static async ValueTask<ValidationContextInitializationResult> InitializeAsync(
        SignatureFacts signature,
        SignatureValidationConstraints defaultConstraints,
        IReadOnlyList<SignaturePolicyConstraintsMapping> policyMappings,
        UnmappedSignaturePolicyHandling unmappedPolicyHandling,
        ResolveSignatureValidationPolicyAsyncDelegate? resolveSignaturePolicy,
        IReadOnlyList<PkiCertificateMemory> callerSuppliedValidationData,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(defaultConstraints);
        ArgumentNullException.ThrowIfNull(policyMappings);
        ArgumentNullException.ThrowIfNull(callerSuppliedValidationData);
        ArgumentNullException.ThrowIfNull(pool);

        if(!signature.IsExtracted)
        {
            //Clause 5.1.3 requires a custom diagnostic when no Table 6 sub-indication maps to the reason; no
            //Table 11 sub-indication covers being handed a signature whose facts were never extracted.
            return Indeterminate(
                SignatureValidationSubIndication.Custom,
                [new CustomDiagnosticReportData("The validation context cannot be initialized for a signature whose facts were not extracted.")]);
        }

        if(signature.SignaturePolicyIdentifier is not string declaredPolicy)
        {
            //Clause 5.2.4.4: "If no signature creation policy is contained in the signature, the building block
            //should select a default signature validation policy."
            return Passed(defaultConstraints, signature, callerSuppliedValidationData);
        }

        for(int i = 0; i < policyMappings.Count; ++i)
        {
            if(string.Equals(policyMappings[i].SignaturePolicyIdentifier, declaredPolicy, StringComparison.Ordinal))
            {
                //Clause 5.2.4.4: the corresponding validation policy is applied during validation.
                return Passed(policyMappings[i].Constraints, signature, callerSuppliedValidationData);
            }
        }

        if(resolveSignaturePolicy is not null)
        {
            SignaturePolicyResolution resolution;
            try
            {
                resolution = await resolveSignaturePolicy(
                    new SignaturePolicyResolutionContext { SignaturePolicyIdentifier = declaredPolicy, Signature = signature },
                    pool,
                    cancellationToken).ConfigureAwait(false);
            }
            catch(Exception exception) when(exception is not OperationCanceledException)
            {
                //A resolver that throws has not processed the policy, which is exactly what
                //POLICY_PROCESSING_ERROR reports.
                resolution = new SignaturePolicyResolution
                {
                    Status = SignaturePolicyResolutionStatus.ProcessingError,
                    Problem = exception.Message
                };
            }

            return resolution.Status switch
            {
                SignaturePolicyResolutionStatus.Resolved when resolution.Constraints is not null =>
                    Passed(resolution.Constraints, signature, callerSuppliedValidationData),
                SignaturePolicyResolutionStatus.NotAvailable =>
                    Indeterminate(SignatureValidationSubIndication.SignaturePolicyNotAvailable, []),
                _ => Indeterminate(
                    SignatureValidationSubIndication.PolicyProcessingError,
                    [new PolicyProcessingErrorReportData(resolution.Problem ?? "The signature policy could not be processed.")])
            };
        }

        //Clause 5.2.4.4: with the creation policy outside the list of mappings, the local configuration decides.
        return unmappedPolicyHandling == UnmappedSignaturePolicyHandling.ApplyDefaultConstraints
            ? Passed(defaultConstraints, signature, callerSuppliedValidationData)
            : Indeterminate(
                SignatureValidationSubIndication.PolicyProcessingError,
                [new PolicyProcessingErrorReportData($"The signature declares the signature policy '{declaredPolicy}', which the validation policy mapping does not cover.")]);

        //Builds the PASSED outcome of Table 11: the selected constraints plus the gathered certificate
        //validation data.
        static ValidationContextInitializationResult Passed(
            SignatureValidationConstraints constraints,
            SignatureFacts signature,
            IReadOnlyList<PkiCertificateMemory> callerSuppliedValidationData)
        {
            List<PkiCertificateMemory> validationData = [];
            validationData.AddRange(signature.EmbeddedCertificates);
            validationData.AddRange(signature.EmbeddedCertificateRevocationLists);
            validationData.AddRange(signature.EmbeddedOcspResponses);
            validationData.AddRange(callerSuppliedValidationData);

            return new ValidationContextInitializationResult
            {
                Conclusion = BuildingBlockConclusion.Passed,
                Constraints = constraints,
                CertificateValidationData = validationData
            };
        }

        //Builds an INDETERMINATE outcome of Table 11.
        static ValidationContextInitializationResult Indeterminate(
            SignatureValidationSubIndication subIndication,
            IReadOnlyList<SignatureValidationReportData> reportData) => new()
            {
                Conclusion = BuildingBlockConclusion.Indeterminate(subIndication, reportData)
            };
    }
}
