using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using Verifiable.Core;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Core.Resolvers;
using Verifiable.Core.StatusLists;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Vcalm;

/// <summary>
/// The VCALM 1.0 §3.3 verification orchestration: it COMPOSES the library's tested Data Integrity
/// verify surface (<see cref="CredentialDataIntegrityExtensions.VerifyAsync"/> /
/// <see cref="PresentationDataIntegrityExtensions.VerifyAsync"/>, W3C VC Data Integrity §4.4) and
/// maps each step's outcome onto the §3.8.1 error/warning model. It does not re-roll cryptography:
/// the cryptosuite-specific seams flow in on <see cref="VcalmCredentialVerification"/>.
/// </summary>
/// <remarks>
/// <para>
/// §3.8.1 fixes the roll-up the service computes: "Errors are ProblemDetails relating to
/// cryptography, data model, and malformed context and are unrecoverable. Warnings are
/// ProblemDetails relating to status and validity periods […] If an error is included, the verified
/// property […] MUST be set to false; if no errors are included, it MUST be set to true." So a
/// proof-verification failure is an ERROR (flips <c>verified</c>), while a future <c>validFrom</c>,
/// a past <c>validUntil</c>, or a revoked / suspended status is a WARNING (does not).
/// </para>
/// <para>
/// The issuer DID is derived from the credential proof's <c>verificationMethod</c> DID URL and
/// resolved through the supplied <see cref="VcalmCredentialVerification.Resolver"/>, threading the
/// verify request's <see cref="ExchangeContext"/> for the SSRF policy — the same shape the di_vp
/// validator uses.
/// </para>
/// </remarks>
public static class VcalmVerificationService
{
    /// <summary>The <see cref="ExchangeContext"/> key backing the dependency-budget-exhausted flag of one verify request.</summary>
    private static string DependencyBudgetExhaustedKey { get; } = "vcalm.verify.dependency_budget_exhausted";

    /// <summary>
    /// The detail ending every problem reported for a dependency fetch this verifier did not attempt because an
    /// earlier dependency of the same verify request had already exhausted its own budget.
    /// </summary>
    private static string DependencyNotAttemptedDetail { get; } = "not attempted: an earlier dependency of this request exhausted its budget.";

    /// <summary>
    /// The detail ending every problem reported for a dependency fetch that ended on its own budget while the caller's
    /// token was still live.
    /// </summary>
    private static string CancelledByOwnBudgetDetail { get; } = "the fetch was cancelled by its own budget.";

    /// <summary>
    /// The <see cref="ExchangeContext"/> key backing the controller-document resolutions of one verify request, the memo
    /// <see cref="ResolveDocumentAsync"/> consults before it asks the DID resolver.
    /// </summary>
    private static string ControllerResolutionsKey { get; } = "vcalm.verify.controller_resolutions";

    extension(ExchangeContext context)
    {
        /// <summary>
        /// Whether a dependency fetch of THIS verify request (a JSON-LD context, a controller document, a
        /// status list, or a schema document) already ended on its own budget. The flag lives on the
        /// request's own <see cref="ExchangeContext"/>, never on shared state, so it bounds only the
        /// request that met the stall: once it is set, every later fetch site of that same request
        /// reports the problem its phase reports for a failed fetch instead of fetching again, so one
        /// slow host cannot multiply a request's cost by the number of credentials it contains.
        /// </summary>
        private bool HasExhaustedDependencyBudget =>
            context.TryGetValue(DependencyBudgetExhaustedKey, out object? flag) && flag is true;

        /// <summary>Records on the request's context that one of its dependency fetches ended on its own budget.</summary>
        private void SetDependencyBudgetExhausted() => context[DependencyBudgetExhaustedKey] = true;

        /// <summary>
        /// The controller documents this verify request has already asked its DID resolver for, keyed by the controller
        /// document URL: the resolver's own answer, a document or its typed failure, or <see langword="null"/> when the
        /// resolver threw. The memo lives on the request's own <see cref="ExchangeContext"/> and is created on first use,
        /// so every proof and contained credential of the request that names one controller shares one resolution, while
        /// no other request, and so no other tenant, ever reads it.
        /// </summary>
        /// <returns>The request's controller-resolution memo.</returns>
        private Dictionary<string, DidResolutionResult?> GetControllerResolutions()
        {
            if(context.TryGetValue(ControllerResolutionsKey, out object? memo) && memo is Dictionary<string, DidResolutionResult?> resolutions)
            {
                return resolutions;
            }

            Dictionary<string, DidResolutionResult?> created = new(StringComparer.Ordinal);
            context[ControllerResolutionsKey] = created;

            return created;
        }
    }


    /// <summary>
    /// Verifies one §3.3.1 credential: its embedded Data Integrity proof chain (ERRORs on failure),
    /// its <c>validFrom</c> / <c>validUntil</c> validity period (WARNINGs out of window), its
    /// <c>credentialStatus</c> (a set revocation / suspension bit is a §3.8.1 status WARNING), and
    /// rolls the §3.8.1 outcome up into <see cref="VcalmVerificationOutcome.Verified"/>.
    /// </summary>
    /// <param name="credential">The parsed embedded-secured credential.</param>
    /// <param name="verification">The application-supplied Data Integrity verify seams, or <see langword="null"/> (fail-closed — proofs report unverifiable).</param>
    /// <param name="resolveStatusList">
    /// The application-supplied seam resolving the decoded status list a credential's
    /// <c>credentialStatus</c> points at, or <see langword="null"/>. When unwired (or when it returns
    /// <see langword="null"/>) the credential's status is left unresolved and no status warning is
    /// emitted (an undeterminable status is not asserted as revoked); a credential with no
    /// <c>credentialStatus</c> never invokes it.
    /// </param>
    /// <param name="now">The verification instant the validity period and status are measured against.</param>
    /// <param name="context">The per-request context threaded to the DID resolver and canonicalizer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<VcalmVerificationOutcome> VerifyCredentialAsync(
        DataIntegritySecuredCredential credential,
        VcalmCredentialVerification? verification,
        ResolveVcalmStatusListDelegate? resolveStatusList,
        DateTimeOffset now,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(context);

        //A document carrying more proofs than the verifier admits is refused before any proof, status or schema work:
        //each proof would cost a controller resolution, a canonicalization and a signature check.
        List<DataIntegrityProof>? proofs = credential.Proof;
        int maxProofs = GetMaxProofsPerDocument(verification);
        if(proofs is { Count: var proofCount } && proofCount > maxProofs)
        {
            return new VcalmVerificationOutcome
            {
                Verified = false,
                ProblemDetails = [TooManyProofs(proofCount, maxProofs)]
            };
        }

        ImmutableArray<VcalmProblemDetail>.Builder problems = ImmutableArray.CreateBuilder<VcalmProblemDetail>();
        ImmutableArray<VcalmInputResult>.Builder proofResults = ImmutableArray.CreateBuilder<VcalmInputResult>();

        //Data Integrity §4.4 identifies an absent proof as a parsing error.
        if(proofs is null || proofs.Count == 0)
        {
            problems.Add(VcalmProblemDetail.Error(
                VcalmProblemTypes.ParsingError,
                "PARSING_ERROR",
                "The secured credential carries no Data Integrity proof map to verify."));
        }
        else
        {
            ProofVerificationOutcome proofOutcome = await VerifyCredentialProofAsync(
                credential, verification, context, cancellationToken).ConfigureAwait(false);

            //§3.3.1 results.proof[]: one entry per proof, input is the proof's verificationMethod.
            //The chain verifies as a whole (Data Integrity §2.1.2); a single failing link fails the
            //whole credential, which the per-entry verified mirrors.
            foreach(DataIntegrityProof proof in proofs)
            {
                proofResults.Add(new VcalmInputResult
                {
                    Verified = proofOutcome.IsValid,
                    Input = proof?.VerificationMethod?.Id ?? string.Empty
                });
            }

            if(proofOutcome.Problem is { } problem)
            {
                problems.Add(problem);
            }
        }

        //§3.8.1: validity-period ProblemDetails are WARNINGs — they do not flip verified.
        VcalmInputResult? validFromResult = EvaluateValidFrom(credential.ValidFrom, now, problems);
        VcalmInputResult? validUntilResult = EvaluateValidUntil(credential.ValidUntil, now, problems);

        //§3.8.1: a status ProblemDetail is a WARNING ("Warnings are ProblemDetails relating to status
        //and validity periods"), so a revoked / suspended status does NOT flip verified. A credential
        //with no credentialStatus, or a verifier with no status seam wired, contributes no status
        //results and no warning.
        ImmutableArray<VcalmStatusResult> statusResults = resolveStatusList is null
            ? ImmutableArray<VcalmStatusResult>.Empty
            : await EvaluateStatusAsync(credential, resolveStatusList, now, problems, context, cancellationToken).ConfigureAwait(false);

        //§3.3.1 results.credentialSchema[]: one entry per credentialSchema object evaluated through
        //the schema seams. A Failure is a MALFORMED_VALUE_ERROR (§3.8.1 classifies only status and
        //validity ProblemDetails as warnings, so a document that does not conform to its declared
        //schema is an error and flips verified), and so is a declared schema whose fetch ended on its
        //own budget or was never attempted; an Indeterminate evaluation reports verified:false
        //without asserting an error.
        ImmutableArray<VcalmSchemaResult> schemaResults = await EvaluateSchemaAsync(
            credential, verification, problems, context, cancellationToken).ConfigureAwait(false);

        bool hasError = false;
        foreach(VcalmProblemDetail problem in problems)
        {
            if(problem.IsError)
            {
                hasError = true;
                break;
            }
        }

        return new VcalmVerificationOutcome
        {
            //§3.8.1: verified MUST be false if any error is included, true otherwise.
            Verified = !hasError,
            ValidFrom = validFromResult,
            ValidUntil = validUntilResult,
            StatusResults = statusResults,
            SchemaResults = schemaResults,
            ProofResults = proofResults.ToImmutable(),
            ProblemDetails = problems.ToImmutable()
        };
    }


    /// <summary>
    /// The number of proofs one document may carry for this verifier: the configured
    /// <see cref="VcalmCredentialVerification.MaxProofsPerDocument"/>, or
    /// <see cref="VcalmCredentialVerification.DefaultMaxProofsPerDocument"/> when the verification seams are unwired, so
    /// the bound holds whether or not a proof could be verified at all.
    /// </summary>
    /// <param name="verification">The application-supplied verification seams, or <see langword="null"/>.</param>
    private static int GetMaxProofsPerDocument(VcalmCredentialVerification? verification) =>
        verification?.MaxProofsPerDocument ?? VcalmCredentialVerification.DefaultMaxProofsPerDocument;


    /// <summary>
    /// The error for a document carrying more proofs than <see cref="GetMaxProofsPerDocument"/> admits: the
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#problem-details">VC Data Model 2.0 §7.2</see> RANGE_ERROR,
    /// "A provided value is outside of the expected range of an associated value".
    /// </summary>
    /// <param name="proofCount">The number of proofs the document carries.</param>
    /// <param name="maximum">The number of proofs this verifier admits per document.</param>
    private static VcalmProblemDetail TooManyProofs(int proofCount, int maximum) =>
        VcalmProblemDetail.Error(
            VcalmProblemTypes.RangeError,
            "RANGE_ERROR",
            $"The document carries {proofCount.ToString(CultureInfo.InvariantCulture)} proofs, more than the "
            + $"{maximum.ToString(CultureInfo.InvariantCulture)} this verifier accepts per document.");


    /// <summary>
    /// Evaluates every §3.3.1 <c>credentialSchema</c> object the credential declares through the
    /// schema seams, producing one <see cref="VcalmSchemaResult"/> per entry.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Per VC Data Model 2.0 §4.11 each entry MUST specify its <c>type</c> and an <c>id</c> URL,
    /// and with multiple schemas validity is determined per each associated <c>type</c>'s
    /// processing rules: entries are evaluated independently and each contributes its own result.
    /// The <see href="https://www.w3.org/TR/vc-json-schema/#evaluation">VC JSON Schema §4.2</see>
    /// tri-state collapses onto the §3.3.1 boolean as: Success → <c>verified:true</c>;
    /// Failure → <c>verified:false</c> plus a MALFORMED_VALUE_ERROR; Indeterminate (unsupported
    /// schema version, a schema document the resolver did not return, or an unregistered mechanism type) →
    /// <c>verified:false</c> with no ProblemDetail, so an undeterminable schema neither asserts
    /// conformance nor flips the overall <c>verified</c>.
    /// </para>
    /// <para>
    /// A declared schema that is never checked is not Indeterminate: whether its schema document fetch ended on its own
    /// budget while the caller's token was still live (<see cref="ResolveSchemaDocumentAsync"/>) or an earlier
    /// dependency of the same request had already exhausted its budget so the fetch was never attempted, an unchecked
    /// declared schema is an unrecoverable data-model condition under
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verification-errors-vs-warnings">VCALM §3.8.1</see> ("Errors are
    /// ProblemDetails relating to cryptography, data model, and malformed context and are unrecoverable"). The entry
    /// reports MALFORMED_VALUE_ERROR with a detail naming the stall or saying the fetch was not attempted, and
    /// <c>verified</c> is false.
    /// </para>
    /// <para>
    /// With no declared schemas, or with the seams unwired
    /// (<see cref="VcalmCredentialVerification.SchemaValidators"/> /
    /// <see cref="VcalmCredentialVerification.ResolveSchemaDocument"/>), the results stay empty.
    /// </para>
    /// </remarks>
    private static async ValueTask<ImmutableArray<VcalmSchemaResult>> EvaluateSchemaAsync(
        DataIntegritySecuredCredential credential,
        VcalmCredentialVerification? verification,
        ImmutableArray<VcalmProblemDetail>.Builder problems,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        List<CredentialSchema>? entries = credential.CredentialSchema;
        VcalmSchemaValidatorRegistry? validators = verification?.SchemaValidators;
        ResolveVcalmSchemaDocumentDelegate? resolveSchema = verification?.ResolveSchemaDocument;
        if(entries is null || entries.Count == 0 || validators is null || resolveSchema is null)
        {
            return ImmutableArray<VcalmSchemaResult>.Empty;
        }

        string credentialJson = verification!.SerializeCredential(credential);
        ImmutableArray<VcalmSchemaResult>.Builder results = ImmutableArray.CreateBuilder<VcalmSchemaResult>(entries.Count);
        foreach(CredentialSchema entry in entries)
        {
            //VC Data Model 2.0 §4.11: each credentialSchema MUST specify its type and an id URL.
            //A malformed entry cannot identify a schema to conform to, which is a malformed value.
            if(string.IsNullOrEmpty(entry.Id) || string.IsNullOrEmpty(entry.Type))
            {
                problems.Add(VcalmProblemDetail.Error(
                    VcalmProblemTypes.MalformedValueError,
                    "MALFORMED_VALUE_ERROR",
                    "A credentialSchema entry must specify its type and an id URL (VC Data Model 2.0 §4.11)."));
                results.Add(new VcalmSchemaResult { Verified = false, Id = entry.Id ?? string.Empty, Type = entry.Type ?? string.Empty });

                continue;
            }

            if(!validators.IsRegistered(entry.Type))
            {
                //An unregistered mechanism type cannot be evaluated: Indeterminate.
                results.Add(new VcalmSchemaResult { Verified = false, Id = entry.Id, Type = entry.Type });

                continue;
            }

            //An earlier dependency of this request that exhausted its own budget bounds the request's cost: the
            //schema document is not fetched. A declared schema that is never checked is an unrecoverable data-model
            //condition (§3.8.1), so the entry is an error rather than an Indeterminate that would leave verified true.
            if(context.HasExhaustedDependencyBudget)
            {
                problems.Add(VcalmProblemDetail.Error(
                    VcalmProblemTypes.MalformedValueError,
                    "MALFORMED_VALUE_ERROR",
                    $"The credential's conformance to its declared schema '{entry.Id}' was not evaluated: " + DependencyNotAttemptedDetail));
                results.Add(new VcalmSchemaResult { Verified = false, Id = entry.Id, Type = entry.Type });

                continue;
            }

            SchemaDocumentRetrieval retrieval = await ResolveSchemaDocumentAsync(resolveSchema, entry.Id, context, cancellationToken).ConfigureAwait(false);
            if(retrieval.IsCancelledByOwnBudget)
            {
                //The fetch ended on its own budget, so the declared schema is never checked: the same unrecoverable
                //data-model condition (§3.8.1) as a schema this request never attempted, never an Indeterminate.
                problems.Add(VcalmProblemDetail.Error(
                    VcalmProblemTypes.MalformedValueError,
                    "MALFORMED_VALUE_ERROR",
                    $"The credential's conformance to its declared schema '{entry.Id}' was not evaluated: " + CancelledByOwnBudgetDetail));
                results.Add(new VcalmSchemaResult { Verified = false, Id = entry.Id, Type = entry.Type });

                continue;
            }

            if(retrieval.SchemaJson is not { } schemaJson)
            {
                //A schema document the resolver did not return cannot be evaluated: Indeterminate.
                results.Add(new VcalmSchemaResult { Verified = false, Id = entry.Id, Type = entry.Type });

                continue;
            }

            CredentialSchemaValidationResult validation = await validators.ValidateAsync(
                entry.Type, schemaJson, credentialJson, cancellationToken).ConfigureAwait(false);
            if(validation.Outcome == CredentialSchemaValidationOutcome.Failure)
            {
                problems.Add(VcalmProblemDetail.Error(
                    VcalmProblemTypes.MalformedValueError,
                    "MALFORMED_VALUE_ERROR",
                    $"The credential does not conform to its declared schema '{entry.Id}'."));
            }

            results.Add(new VcalmSchemaResult
            {
                Verified = validation.Outcome == CredentialSchemaValidationOutcome.Success,
                Id = entry.Id,
                Type = entry.Type
            });
        }

        return results.ToImmutable();
    }


    /// <summary>
    /// Retrieves one schema document for <see cref="EvaluateSchemaAsync"/> through the application's
    /// <see cref="ResolveVcalmSchemaDocumentDelegate"/>. The call is a boundary over a dependency that throws, as
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#error-handling">VCALM §3.8</see> recommends: "avoid raising
    /// errors while performing verification, and instead gather ProblemDetails objects". A retrieval that ends on its
    /// own budget while the caller's token is still live, its cancellation bare or carried inside another exception
    /// (<see cref="WrappedCancellation.IsOwnBudgetCancellation"/>), is reported as such, so the schema phase reports the
    /// unchecked schema as an error, and it is recorded on the request's <see cref="ExchangeContext"/> so no further
    /// dependency of this request is fetched. A retrieval that fails in any other way retrieves no document, which the
    /// schema phase reports as Indeterminate exactly like a resolver that returns <see langword="null"/>. The caller's own
    /// cancellation, bare or carried, and <see cref="OutOfMemoryException"/> propagate.
    /// </summary>
    /// <param name="resolveSchema">The application's schema document resolver.</param>
    /// <param name="schemaId">The <c>credentialSchema</c> entry's <c>id</c> URL.</param>
    /// <param name="context">The verify request's context, carrying the dependency-budget flag.</param>
    /// <param name="cancellationToken">The caller's cancellation token.</param>
    /// <returns>The retrieved schema document, none, or the fetch that ended on its own budget.</returns>
    private static async ValueTask<SchemaDocumentRetrieval> ResolveSchemaDocumentAsync(
        ResolveVcalmSchemaDocumentDelegate resolveSchema, string schemaId, ExchangeContext context, CancellationToken cancellationToken)
    {
        try
        {
            string? schemaJson = await resolveSchema(schemaId, context, cancellationToken).ConfigureAwait(false);

            return new SchemaDocumentRetrieval(schemaJson, IsCancelledByOwnBudget: false);
        }
        catch(Exception exception) when(WrappedCancellation.IsOwnBudgetCancellation(exception, cancellationToken))
        {
            context.SetDependencyBudgetExhausted();

            return SchemaDocumentRetrieval.CancelledByOwnBudget;
        }
        catch(Exception exception) when(exception is not OperationCanceledException and not OutOfMemoryException)
        {
            //The caller's own cancellation carried inside the resolver's exception propagates as that cancellation.
            WrappedCancellation.ThrowIfCarried(exception);

            return SchemaDocumentRetrieval.NotRetrieved;
        }
    }


    /// <summary>
    /// The outcome of retrieving one schema document for <see cref="EvaluateSchemaAsync"/>: the document, none, or a
    /// fetch that ended on its own budget, which the schema phase reports as an error rather than an Indeterminate.
    /// </summary>
    /// <param name="SchemaJson">The retrieved schema document, or <see langword="null"/> when none was retrieved.</param>
    /// <param name="IsCancelledByOwnBudget">Whether the fetch ended on its own budget while the caller's token was live.</param>
    private readonly record struct SchemaDocumentRetrieval(string? SchemaJson, bool IsCancelledByOwnBudget)
    {
        /// <summary>No schema document was retrieved: the resolver returned none or failed.</summary>
        public static SchemaDocumentRetrieval NotRetrieved { get; } = new(null, IsCancelledByOwnBudget: false);

        /// <summary>The fetch ended on its own budget while the caller's token was still live.</summary>
        public static SchemaDocumentRetrieval CancelledByOwnBudget { get; } = new(null, IsCancelledByOwnBudget: true);
    }


    /// <summary>
    /// The §3.3.1 status check: for each <c>BitstringStatusListEntry</c> the credential carries,
    /// resolves the referenced status list through <paramref name="resolveStatusList"/>, reads the
    /// bit, and classifies per §3.8.1. A set bit (revoked / suspended) is a status WARNING — it
    /// populates the returned results with <c>verified:false</c> but does NOT add an ERROR, so it
    /// does not flip the overall <c>verified</c>. A credential with no <c>credentialStatus</c> yields
    /// an empty result set and no warning; every other path that cannot establish a status (an
    /// unresolvable list, a <see cref="BitstringStatusListException"/>, a malformed entry, a fetch that ended on its own
    /// budget, or an entry never attempted because the request's dependency budget is already exhausted) reports
    /// exactly one §3.8.1 WARNING through <paramref name="problems"/> and adds no result.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The resolve-and-validate step is a boundary over dependencies that throw: the application's
    /// resolver and the status library's <see cref="BitstringStatusListValidation.GetStatus"/>, whose
    /// <see cref="BitstringStatusListException"/> carries the specification's own error kind. A fetch that
    /// ends on its own budget while the caller's token is still live, its cancellation bare or carried inside another
    /// exception (<see cref="WrappedCancellation.IsOwnBudgetCancellation"/>), reports
    /// <see cref="VcalmProblemTypes.StatusRetrievalError"/>, the status phase's own type for a failed
    /// retrieval, and is recorded on the request's <see cref="ExchangeContext"/>. Once any dependency of the request has
    /// exhausted its budget, each remaining entry reports the same type without a fetch. The caller's own cancellation,
    /// bare or carried, and <see cref="OutOfMemoryException"/> propagate.
    /// </para>
    /// <para>
    /// Every one of these is a WARNING, never an error:
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verification-errors-vs-warnings">VCALM §3.8.1</see> states "Warnings
    /// are ProblemDetails relating to status and validity periods", so a status that could not be established, whether
    /// its fetch failed, stalled or was never attempted, does not by itself make <c>verified</c> false.
    /// </para>
    /// </remarks>
    private static async ValueTask<ImmutableArray<VcalmStatusResult>> EvaluateStatusAsync(
        DataIntegritySecuredCredential credential,
        ResolveVcalmStatusListDelegate resolveStatusList,
        DateTimeOffset now,
        ImmutableArray<VcalmProblemDetail>.Builder problems,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        List<CredentialStatus>? statuses = credential.CredentialStatus;
        if(statuses is null || statuses.Count == 0)
        {
            return ImmutableArray<VcalmStatusResult>.Empty;
        }

        ImmutableArray<VcalmStatusResult>.Builder results = ImmutableArray.CreateBuilder<VcalmStatusResult>();
        foreach(CredentialStatus status in statuses)
        {
            if(!TryMapStatusEntry(status, out bool isMalformedStatusEntry, out BitstringStatusListEntry? entry))
            {
                //A foreign type is not a W3C status reference this verifier implements an algorithm
                //for, and the specification names no error for it: it is skipped silently. A
                //BitstringStatusListEntry with a missing / unparseable statusListIndex,
                //statusListCredential, or statusPurpose IS the specification's shape but cannot be
                //resolved: §3.5 STATUS_VERIFICATION_ERROR.
                if(isMalformedStatusEntry)
                {
                    problems.Add(VcalmProblemDetail.Warning(
                        VcalmProblemTypes.StatusVerificationError,
                        "STATUS_VERIFICATION_ERROR",
                        "A BitstringStatusListEntry credentialStatus entry lacks, or carries an unparseable, "
                        + "statusListIndex, statusListCredential, or statusPurpose."));
                }

                continue;
            }

            //An earlier dependency of this request already cancelled on its own budget: bound the request's
            //total cost by never attempting another dependency fetch for it. §3.8.1 makes status ProblemDetails
            //warnings, so the entry never retrieved reports the status phase's retrieval failure as a warning.
            if(context.HasExhaustedDependencyBudget)
            {
                problems.Add(VcalmProblemDetail.Warning(
                    VcalmProblemTypes.StatusRetrievalError,
                    "STATUS_RETRIEVAL_ERROR",
                    $"The status list referenced by the '{entry.StatusPurpose}' credentialStatus entry "
                    + "was not retrieved: " + DependencyNotAttemptedDetail));

                continue;
            }

            //§3.8 process-safety boundary: the status resolver dereferences the statusListCredential
            //(through the SSRF-policed OutboundFetch when remote), verifies its proof, and decodes the
            //bitstring — all throw-prone over attacker-influenced input — and GetStatus then enforces the
            //§3.2 purpose / window / length / range checks. A throw from EITHER must not become a 500:
            //§3.8.1 makes status a WARNING, reporting the specification's own error type instead of the
            //exception's message, type name, or stack (§3.8: "sanitize all server errors").
            VcalmResolvedStatusList? resolved = null;
            try
            {
                resolved = await resolveStatusList(entry, context, cancellationToken).ConfigureAwait(false);
                if(resolved is null)
                {
                    problems.Add(VcalmProblemDetail.Warning(
                        VcalmProblemTypes.StatusRetrievalError,
                        "STATUS_RETRIEVAL_ERROR",
                        $"The status list referenced by the '{entry.StatusPurpose}' credentialStatus "
                        + "entry could not be retrieved."));

                    continue;
                }

                BitstringStatusListStatus statusResult = BitstringStatusListValidation.GetStatus(
                    entry, resolved.StatusList, resolved.Purposes, now, resolved.ValidFrom, resolved.ValidUntil);

                results.Add(new VcalmStatusResult
                {
                    Value = statusResult.Status,
                    Verified = statusResult.IsValid,
                    Input = status.Id ?? string.Empty,
                    Purpose = statusResult.Purpose,
                    Message = statusResult.Message
                });

                //§3.8.1: a set revocation / suspension bit is a status WARNING (does not flip
                //verified). A valid (cleared) bit asserts nothing — no problem detail is added.
                if(!statusResult.IsValid)
                {
                    problems.Add(VcalmProblemDetail.Warning(
                        VcalmProblemTypes.StatusWarning,
                        "STATUS_WARNING",
                        $"The credential's '{entry.StatusPurpose}' status is set (status value "
                        + $"{statusResult.Status}) in the referenced status list."));
                }
            }
            catch(Exception exception) when(WrappedCancellation.IsOwnBudgetCancellation(exception, cancellationToken))
            {
                //A status fetch that ends on its own budget while the caller's token is still live, the
                //cancellation bare or carried inside another exception, retrieves no status list; recorded on
                //the request context so no further dependency of this request is fetched.
                context.SetDependencyBudgetExhausted();
                problems.Add(VcalmProblemDetail.Warning(
                    VcalmProblemTypes.StatusRetrievalError,
                    "STATUS_RETRIEVAL_ERROR",
                    $"The status list referenced by the '{entry.StatusPurpose}' credentialStatus "
                    + "entry could not be retrieved: " + CancelledByOwnBudgetDetail));
            }
            catch(Exception exception) when(exception is not OperationCanceledException and not OutOfMemoryException)
            {
                //The caller's own cancellation carried inside the resolver's exception propagates as that cancellation.
                WrappedCancellation.ThrowIfCarried(exception);
                problems.Add(BuildStatusUnavailableProblem(entry.StatusPurpose, exception));
            }
            finally
            {
                resolved?.StatusList.Dispose();
            }
        }

        return results.ToImmutable();
    }


    /// <summary>
    /// Builds the §3.8.1 status WARNING for a status entry whose status could not be established
    /// because <see cref="EvaluateStatusAsync"/>'s resolve-and-validate step threw. A
    /// <see cref="BitstringStatusListException"/> reports the specification's own error kind (§3.5
    /// Processing Errors, or the §3.2 <c>RANGE_ERROR</c>); any other exception reports
    /// <see cref="VcalmProblemTypes.StatusRetrievalError"/> — the application's resolver failed and
    /// said no more. The detail is this library's own fixed sentence: it never carries the
    /// exception's message, type name, or stack (§3.8: "sanitize all server errors").
    /// </summary>
    private static VcalmProblemDetail BuildStatusUnavailableProblem(string purpose, Exception exception) =>
        exception is BitstringStatusListException bitstringException
            ? VcalmProblemDetail.Warning(
                bitstringException.ErrorType switch
                {
                    BitstringStatusListErrorType.StatusRetrieval => VcalmProblemTypes.StatusRetrievalError,
                    BitstringStatusListErrorType.StatusVerification => VcalmProblemTypes.StatusVerificationError,
                    BitstringStatusListErrorType.StatusListLength => VcalmProblemTypes.StatusListLengthError,
                    BitstringStatusListErrorType.Range => VcalmProblemTypes.RangeError,
                    BitstringStatusListErrorType.MalformedValue => VcalmProblemTypes.MalformedValueError,
                    _ => VcalmProblemTypes.StatusRetrievalError
                },
                bitstringException.ErrorCode,
                $"The '{purpose}' credentialStatus entry's status could not be established.")
            : VcalmProblemDetail.Warning(
                VcalmProblemTypes.StatusRetrievalError,
                "STATUS_RETRIEVAL_ERROR",
                $"The '{purpose}' credentialStatus entry's status could not be established: the "
                + "application's resolver failed and said no more.");


    /// <summary>
    /// Maps the credential's <see cref="CredentialStatus"/> (a VC Data Model 2.0 §4.10 status entry)
    /// to the typed Core <see cref="BitstringStatusListEntry"/> the resolver and validation surface
    /// read.
    /// </summary>
    /// <param name="status">The credential's status entry.</param>
    /// <param name="isMalformedStatusEntry">
    /// <see langword="true"/> when <paramref name="status"/> IS a <c>BitstringStatusListEntry</c> but
    /// its <c>statusListIndex</c>, <c>statusListCredential</c>, or <c>statusPurpose</c> is missing or
    /// unparseable, its <c>statusSize</c> is not a positive integer, its <c>statusMessage</c> array's
    /// length does not equal the number of possible values <c>statusSize</c> indicates, or
    /// <c>statusSize</c> is greater than <c>1</c> without a <c>statusMessage</c> array — the
    /// specification's shape, malformed (§2.1). <see langword="false"/> for an entry of another
    /// <c>type</c>, which this verifier implements no algorithm for.
    /// </param>
    /// <param name="entry">The mapped entry, or <see langword="null"/> when mapping failed.</param>
    /// <returns><see langword="true"/> when <paramref name="status"/> mapped to a resolvable entry.</returns>
    private static bool TryMapStatusEntry(
        CredentialStatus status, out bool isMalformedStatusEntry, [NotNullWhen(true)] out BitstringStatusListEntry? entry)
    {
        entry = null;
        isMalformedStatusEntry = false;

        if(!string.Equals(status.Type, BitstringStatusListConstants.EntryType, StringComparison.Ordinal))
        {
            return false;
        }

        if(string.IsNullOrEmpty(status.StatusListCredential)
            || string.IsNullOrEmpty(status.StatusPurpose)
            || !int.TryParse(status.StatusListIndex, NumberStyles.Integer, CultureInfo.InvariantCulture, out int index))
        {
            isMalformedStatusEntry = true;

            return false;
        }

        //§2.1: absent statusSize MUST be processed as 1; if present it MUST be an integer greater
        //than zero.
        int statusSize = status.StatusSize ?? 1;
        if(statusSize <= 0)
        {
            isMalformedStatusEntry = true;

            return false;
        }

        //§2.1: a present statusMessage array's length MUST equal the number of possible status
        //values statusSize indicates (2^statusSize). A statusSize this large already exceeds any
        //array a caller could supply, so it is compared against an unreachable ceiling rather than
        //shifted, avoiding a 32-bit shift-count wraparound.
        long expectedMessageCount = statusSize < 31 ? 1L << statusSize : long.MaxValue;
        if(status.StatusMessage is not null && status.StatusMessage.Count != expectedMessageCount)
        {
            isMalformedStatusEntry = true;

            return false;
        }

        //§2.1: statusMessage MUST be present when statusSize is greater than 1.
        if(statusSize > 1 && (status.StatusMessage is null || status.StatusMessage.Count == 0))
        {
            isMalformedStatusEntry = true;

            return false;
        }

        entry = new BitstringStatusListEntry
        {
            Id = status.Id,
            StatusPurpose = status.StatusPurpose,
            StatusListIndex = index,
            StatusListCredential = status.StatusListCredential,
            StatusSize = statusSize,
            StatusMessages = status.StatusMessage,
            StatusReference = status.StatusReference
        };

        return true;
    }


    /// <summary>
    /// Verifies a presentation through <see cref="PresentationDataIntegrityExtensions"/> while
    /// retaining the cause required by <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>.
    /// The call is a boundary over dependencies that throw, contained as in <see cref="VerifyCredentialProofAsync"/>:
    /// a dependency cancelled on its own budget while the caller's token is live, the cancellation bare or carried inside
    /// another exception, is the active phase's failure and is recorded on the request's <see cref="ExchangeContext"/>,
    /// and the caller's own cancellation, bare or carried, propagates.
    /// </summary>
    /// <param name="presentation">The parsed embedded-secured presentation.</param>
    /// <param name="expectedChallenge">The challenge the verifier gave, or <see langword="null"/> when it gave none.</param>
    /// <param name="expectedDomain">The domain the verifier gave, or <see langword="null"/> when it gave none.</param>
    /// <param name="verification">The application-supplied Data Integrity verify seams, or <see langword="null"/>.</param>
    /// <param name="context">The per-request context threaded to the DID resolver and canonicalizer.</param>
    /// <param name="cancellationToken">The caller's cancellation token.</param>
    /// <returns>The presentation proof's result with the bound inputs and its ProblemDetails.</returns>
    public static async ValueTask<VcalmPresentationProofResult> VerifyPresentationProofAsync(
        DataIntegritySecuredPresentation presentation,
        string? expectedChallenge,
        string? expectedDomain,
        VcalmCredentialVerification? verification,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        ArgumentNullException.ThrowIfNull(context);

        //A presentation carrying more proofs than the verifier admits is refused before any proof work.
        int maxProofs = GetMaxProofsPerDocument(verification);
        if(presentation.Proof is { Count: var proofCount } && proofCount > maxProofs)
        {
            return new VcalmPresentationProofResult
            {
                Verified = false,
                Challenge = expectedChallenge,
                Domain = expectedDomain,
                Holder = presentation.Holder,
                ProofInput = string.Empty,
                ProblemDetails = [TooManyProofs(proofCount, maxProofs)]
            };
        }

        DataIntegrityProof? proof = presentation.Proof is { Count: > 0 } proofs ? proofs[0] : null;
        ProofVerificationAttempt attempt = new(verification);
        ProofVerificationOutcome outcome;
        try
        {
            outcome = await VerifyPresentationProofCoreAsync(
                presentation, proof, expectedChallenge, expectedDomain, verification, attempt, context, cancellationToken)
                .ConfigureAwait(false);
        }
        catch(Exception exception) when(WrappedCancellation.IsOwnBudgetCancellation(exception, cancellationToken))
        {
            context.SetDependencyBudgetExhausted();
            outcome = attempt.UnexpectedFailure(isCancelledByOwnBudget: true);
        }
        catch(Exception exception) when(exception is not OperationCanceledException and not OutOfMemoryException)
        {
            //The caller's own cancellation carried inside a dependency's exception propagates as that cancellation.
            WrappedCancellation.ThrowIfCarried(exception);
            outcome = attempt.UnexpectedFailure();
        }

        return new VcalmPresentationProofResult
        {
            Verified = outcome.IsValid,
            Challenge = expectedChallenge,
            Domain = expectedDomain,
            Holder = presentation.Holder,
            ProofInput = proof?.VerificationMethod?.Id ?? string.Empty,
            ProblemDetails = outcome.Problem is { } problem ? [problem] : []
        };
    }


    /// <summary>
    /// The boundary over the dependencies a credential proof's verification calls, all of which throw: the
    /// application's JSON-LD canonicalizer and context resolver (the transformation phase), the proof-value and
    /// key decoders (multibase, base58 and base64url), the DID resolver and the signature function. A failure is
    /// contained as a sanitized <see cref="ProofVerificationOutcome"/> classified by the active phase through
    /// <see cref="ProofVerificationAttempt.UnexpectedFailure"/>. An <see cref="OperationCanceledException"/> raised
    /// while the caller's token is still live, bare or carried inside another exception
    /// (<see cref="WrappedCancellation.IsOwnBudgetCancellation"/>), comes from a dependency's own budget: it is that
    /// phase's failure and is recorded on the request's <see cref="ExchangeContext"/> so no later dependency of the
    /// request is fetched. The caller's own cancellation, bare or carried, propagates, and
    /// <see cref="OutOfMemoryException"/> is never caught, because neither is a verification verdict.
    /// </summary>
    /// <param name="credential">The parsed embedded-secured credential.</param>
    /// <param name="verification">The application-supplied Data Integrity verify seams, or <see langword="null"/>.</param>
    /// <param name="context">The per-request context threaded to the DID resolver and canonicalizer.</param>
    /// <param name="cancellationToken">The caller's cancellation token.</param>
    /// <returns>The classified outcome of the credential's proofs.</returns>
    private static async ValueTask<ProofVerificationOutcome> VerifyCredentialProofAsync(
        DataIntegritySecuredCredential credential,
        VcalmCredentialVerification? verification,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ProofVerificationAttempt attempt = new(verification);
        try
        {
            return await VerifyCredentialProofCoreAsync(credential, verification, attempt, context, cancellationToken)
                .ConfigureAwait(false);
        }
        catch(Exception exception) when(WrappedCancellation.IsOwnBudgetCancellation(exception, cancellationToken))
        {
            context.SetDependencyBudgetExhausted();

            return attempt.UnexpectedFailure(isCancelledByOwnBudget: true);
        }
        catch(Exception exception) when(exception is not OperationCanceledException and not OutOfMemoryException)
        {
            //The caller's own cancellation carried inside a dependency's exception propagates as that cancellation.
            WrappedCancellation.ThrowIfCarried(exception);

            return attempt.UnexpectedFailure();
        }
    }


    /// <summary>
    /// Composes <see cref="CredentialDataIntegrityExtensions.VerifyAsync"/> after validating
    /// proof options and the CID retrieval steps, preserving their distinct failure outcomes. A
    /// selective-disclosure proof is verified only as a document's single proof, so one anywhere in a proof set or
    /// chain is refused before any resolution. The controller document comes from <see cref="ResolveDocumentAsync"/>,
    /// which resolves each controller once per verify request however many proofs and contained credentials name it.
    /// Proofs naming the same verification method share one <see cref="ValidateVerificationMethod"/> of it, so the
    /// relationship scan and the key decode run once per method identifier however many proofs of the document name it;
    /// that check stays per document, since its issuer binding depends on the document. The transformation fetches JSON-LD
    /// contexts, so once an earlier dependency of the same request has exhausted its own budget it is not attempted
    /// and reports <see cref="ProofVerificationAttempt.TransformationNotAttempted"/>.
    /// </summary>
    private static async ValueTask<ProofVerificationOutcome> VerifyCredentialProofCoreAsync(
        DataIntegritySecuredCredential credential,
        VcalmCredentialVerification? verification,
        ProofVerificationAttempt attempt,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        List<DataIntegrityProof> proofs = credential.Proof!;
        foreach(DataIntegrityProof proof in proofs)
        {
            ProofVerificationOutcome options = ValidateProofOptions(proof, AssertionMethod.Purpose);
            if(!options.IsValid)
            {
                return options;
            }

            ProofVerificationOutcome mechanism = ValidateSecuringMechanism(proof, verification, isPresentation: false);
            if(!mechanism.IsValid)
            {
                return mechanism;
            }
        }

        //Selective disclosure is verified for exactly one derived proof: a selective-disclosure proof in any
        //position of a proof set or chain is a composition this verifier cannot dispatch.
        bool isSelectiveDisclosure = proofs.Exists(IsSelectiveDisclosureProof);
        if(isSelectiveDisclosure && proofs.Count != 1)
        {
            return ProofVerificationOutcome.Failure(VcalmProblemTypes.UnsupportedSecuringMechanism,
                VcalmProblemTypes.UnsupportedSecuringMechanismDetail);
        }

        DataIntegrityProof firstProof = proofs[0];
        DocumentResolutionOutcome resolution = await ResolveDocumentAsync(
            verification!.Resolver, firstProof.VerificationMethod!.Id!, context, cancellationToken).ConfigureAwait(false);
        if(resolution.Problem is { } resolutionProblem)
        {
            return new(resolutionProblem);
        }

        DidDocument document = resolution.Document!;
        Dictionary<string, ProofVerificationOutcome> validatedMethods = new(StringComparer.Ordinal);
        foreach(DataIntegrityProof proof in proofs)
        {
            string methodIdentifier = proof.VerificationMethod!.Id!;
            if(!validatedMethods.TryGetValue(methodIdentifier, out ProofVerificationOutcome method))
            {
                method = ValidateVerificationMethod(document, proof, AssertionMethod.Purpose, credential.Issuer?.Id, verification.MemoryPool);
                validatedMethods[methodIdentifier] = method;
            }

            if(!method.IsValid)
            {
                return method;
            }
        }

        if(isSelectiveDisclosure)
        {
            return await VerifyEcdsaSd2023DerivedProofAsync(
                credential, verification, document, attempt, context, cancellationToken).ConfigureAwait(false);
        }

        if(context.HasExhaustedDependencyBudget)
        {
            return ProofVerificationAttempt.TransformationNotAttempted;
        }

        CredentialVerificationResult<DataIntegritySecuredCredential> result = await credential.VerifyAsync(
            document, attempt.Canonicalize!, verification.ContextResolver, verification.KnownContext,
            verification.DecodeProofValue, verification.SerializeCredential, verification.SerializeProofOptions,
            verification.Decoder, verification.ComputeDigest, verification.MemoryPool, context, cancellationToken)
            .ConfigureAwait(false);

        return attempt.MapResult(result.IsValid, result.FailureReason);
    }


    /// <summary>
    /// Dispatches the wired derived-proof mechanism without using a parsing exception to choose
    /// an algorithm, then maps <see cref="VerificationFailureReason"/> to its defining problem type.
    /// A proof value that is not multibase base64url-encoded, or whose decoded bytes do not start with the
    /// disclosure proof header, reports <see cref="VcalmProblemTypes.ProofVerificationError"/> as
    /// <see href="https://www.w3.org/TR/vc-di-ecdsa/#parsederivedproofvalue">VC-DI-ECDSA §3.5.8
    /// parseDerivedProofValue</see> requires. Once an earlier dependency of the same request has exhausted
    /// its own budget, the transformation is not attempted and reports
    /// <see cref="ProofVerificationAttempt.TransformationNotAttempted"/>.
    /// </summary>
    private static async ValueTask<ProofVerificationOutcome> VerifyEcdsaSd2023DerivedProofAsync(
        DataIntegritySecuredCredential credential,
        VcalmCredentialVerification verification,
        DidDocument document,
        ProofVerificationAttempt attempt,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        attempt.IsSelectiveDisclosure = true;
        string? proofValue = credential.Proof![0].ProofValue;
        if(string.IsNullOrEmpty(proofValue) || proofValue[0] != MultibaseAlgorithms.Base64Url)
        {
            return ProofVerificationOutcome.Failure(VcalmProblemTypes.ProofVerificationError,
                "An error was encountered during selective-disclosure proof decoding.");
        }

        using System.Buffers.IMemoryOwner<byte> decoded = verification.SdProofDecoder!(proofValue.AsSpan(1), verification.MemoryPool);
        if(decoded.Memory.Span is not [0xd9, 0x5d, 0x01, ..])
        {
            //A wrong or unrecognised header, including a base proof's 0xd9 0x5d 0x00, is a structural
            //defect in the proof value, not a mechanism this verifier cannot dispatch: VC-DI-ECDSA
            //parseDerivedProofValue raises PROOF_VERIFICATION_ERROR when the decoded value does not start
            //with the disclosure proof header bytes 0xd9, 0x5d and 0x01.

            return ProofVerificationOutcome.Failure(VcalmProblemTypes.ProofVerificationError,
                "An error was encountered during selective-disclosure proof decoding because the disclosure proof header is not recognized.");
        }

        if(context.HasExhaustedDependencyBudget)
        {
            return ProofVerificationAttempt.TransformationNotAttempted;
        }

        VerificationMethod method = document.GetLocalAssertionMethodById(credential.Proof[0].VerificationMethod!.Id!)!;
        using PublicKeyMemory issuerPublicKey = method.ToPublicKeyMemory(verification.MemoryPool);
        CredentialVerificationResult<DataIntegritySecuredCredential> result = await credential.VerifyDerivedProofAsync(
            issuerPublicKey, attempt.VerifyDerivedSignature!, verification.ParseDerivedProof!,
            attempt.Canonicalize!, verification.ContextResolver, verification.KnownContext,
            verification.SerializeCredential, verification.SerializeProofOptions,
            verification.SdProofEncoder!, verification.SdProofDecoder!, verification.MemoryPool, context, cancellationToken)
            .ConfigureAwait(false);

        return attempt.MapResult(result.IsValid, result.FailureReason);
    }


    /// <summary>
    /// Verifies the presentation's authentication proof after the
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>
    /// option and binding checks and <see cref="ResolveDocumentAsync"/>. Each binding check runs only when the
    /// verifier gave its value, as §4.4 words them ("If domain was given, and it does not contain the same strings as
    /// proof.domain" and "If challenge was given, and it does not match proof.challenge"), so a proof without a
    /// challenge or domain the verifier never asked for is not a binding failure. Once an earlier dependency of the
    /// same request has exhausted its own budget, the transformation is not attempted and reports
    /// <see cref="ProofVerificationAttempt.TransformationNotAttempted"/>.
    /// </summary>
    private static async ValueTask<ProofVerificationOutcome> VerifyPresentationProofCoreAsync(
        DataIntegritySecuredPresentation presentation,
        DataIntegrityProof? proof,
        string? expectedChallenge,
        string? expectedDomain,
        VcalmCredentialVerification? verification,
        ProofVerificationAttempt attempt,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ProofVerificationOutcome options = ValidateProofOptions(proof, AuthenticationMethod.Purpose);
        if(!options.IsValid)
        {
            return options;
        }

        if(expectedDomain is not null && (proof!.Domain is not { Count: 1 } domains
            || !string.Equals(domains[0], expectedDomain, StringComparison.Ordinal)))
        {
            return ProofVerificationOutcome.Failure(VcalmProblemTypes.InvalidDomainError,
                "The domain value in the proof did not match the expected value.");
        }

        if(expectedChallenge is not null && !string.Equals(proof!.Challenge, expectedChallenge, StringComparison.Ordinal))
        {
            return ProofVerificationOutcome.Failure(VcalmProblemTypes.InvalidChallengeError,
                "The challenge value in the proof did not match the expected value.");
        }

        ProofVerificationOutcome mechanism = ValidateSecuringMechanism(proof!, verification, isPresentation: true);
        if(!mechanism.IsValid)
        {
            return mechanism;
        }

        //verification cannot be null here: ValidateSecuringMechanism's first arm already fails the
        //mechanism check above whenever verification is null, so this call is reached only when it
        //is not.
        DocumentResolutionOutcome resolution = await ResolveDocumentAsync(
            verification!.Resolver, proof!.VerificationMethod!.Id!, context, cancellationToken).ConfigureAwait(false);
        if(resolution.Problem is { } problem)
        {
            return new(problem);
        }

        ProofVerificationOutcome method = ValidateVerificationMethod(resolution.Document!, proof, AuthenticationMethod.Purpose, presentation.Holder, verification.MemoryPool);
        if(!method.IsValid)
        {
            return method;
        }

        if(context.HasExhaustedDependencyBudget)
        {
            return ProofVerificationAttempt.TransformationNotAttempted;
        }

        //Data Integrity §4.4 runs the binding checks only "If domain was given" and "If challenge was given": a
        //verifier that bound neither accepts a proof carrying neither, so only the values actually given are passed on.
        CredentialVerificationResult<DataIntegritySecuredPresentation> result = await presentation.VerifyGivenBindingAsync(
            resolution.Document!, expectedChallenge, expectedDomain, attempt.Canonicalize!, verification.ContextResolver,
            verification.KnownContext, verification.DecodeProofValue, verification.SerializePresentation,
            verification.SerializeProofOptions, verification.Decoder, verification.ComputeDigest,
            verification.MemoryPool, context, cancellationToken).ConfigureAwait(false);

        return attempt.MapResult(result.IsValid, result.FailureReason);
    }


    /// <summary>
    /// Retains the mandatory proof-option failures from
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>
    /// as <see cref="ProofVerificationOutcome"/> values before dispatch or retrieval.
    /// </summary>
    private static ProofVerificationOutcome ValidateProofOptions(DataIntegrityProof? proof, string expectedPurpose) => proof switch
    {
        null => ProofVerificationOutcome.Failure(VcalmProblemTypes.ParsingError,
            "The secured document carries no Data Integrity proof map to verify."),
        _ when !HasMandatoryProofOptions(proof) => ProofVerificationOutcome.Failure(VcalmProblemTypes.ProofVerificationError,
            "An error was encountered during proof verification because type, verificationMethod or proofPurpose is missing."),
        _ when !string.Equals(proof.ProofPurpose, expectedPurpose, StringComparison.Ordinal) =>
            ProofVerificationOutcome.Failure(VcalmProblemTypes.ProofVerificationError,
                "The proof purpose does not match the expected proof purpose."),
        _ when !IsValidVerificationMethodUrl(proof.VerificationMethod!.Id!) =>
            ProofVerificationOutcome.Failure(VcalmProblemTypes.InvalidVerificationMethodUrl,
                "The verification method identifier is not a valid URL."),
        _ => ProofVerificationOutcome.Success
    };


    /// <summary>
    /// Whether <paramref name="proof"/> carries every member
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see> requires before
    /// verification: "If one or more of proof.type, proof.verificationMethod, and proof.proofPurpose does not
    /// exist, an error MUST be raised". The verifier reports a missing member as
    /// <see cref="VcalmProblemTypes.ProofVerificationError"/>; the issuing and presenting endpoints refuse an input
    /// proof that lacks one before any signing, so no signing path re-serializes or chains a defective proof.
    /// </summary>
    /// <param name="proof">The proof to inspect; an absent entry carries none of the members.</param>
    /// <returns><see langword="true"/> when <c>type</c>, <c>verificationMethod</c> and <c>proofPurpose</c> are all present.</returns>
    internal static bool HasMandatoryProofOptions(DataIntegrityProof? proof) =>
        proof is not null
        && !string.IsNullOrEmpty(proof.Type)
        && !string.IsNullOrEmpty(proof.VerificationMethod?.Id)
        && !string.IsNullOrEmpty(proof.ProofPurpose);


    /// <summary>
    /// The MALFORMED_VALUE_ERROR detail with which the issuing and presenting endpoints refuse an input proof that
    /// fails <see cref="HasMandatoryProofOptions"/>, before any signing.
    /// </summary>
    internal static string IncompleteInputProofDetail { get; } =
        "An input proof lacks its type, verificationMethod or proofPurpose, which Data Integrity §4.4 requires of every proof.";


    /// <summary>
    /// Checks the URL scheme's syntax before <see cref="ResolveDocumentAsync"/> so a malformed
    /// DID URL is distinguished from failure to retrieve a valid controller URL
    /// (<see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3</see>: "If
    /// vmIdentifier is not a valid URL, an error MUST be raised"). An absolute URI whose scheme is
    /// <c>file</c> is refused: <see cref="Uri.TryCreate(string, UriKind, out Uri)"/> turns an implicit
    /// file path into a <c>file:</c> URI (a rooted path such as <c>/x#k</c> on Unix-like platforms, a
    /// drive path such as <c>C:\x#k</c> on Windows), so without this check the same identifier would be
    /// accepted on one platform and refused on another, and a local file is never a verification method.
    /// </summary>
    private static bool IsValidVerificationMethodUrl(string identifier) =>
        Uri.TryCreate(identifier, UriKind.Absolute, out Uri? parsed)
        && !identifier.Any(char.IsWhiteSpace)
        && !string.Equals(parsed.Scheme, Uri.UriSchemeFile, StringComparison.Ordinal)
        && (!string.Equals(parsed.Scheme, "did", StringComparison.Ordinal)
            || DidUrl.TryParseAbsolute(identifier, out _));


    /// <summary>
    /// Identifies mechanisms the supplied <see cref="VcalmCredentialVerification"/> cannot dispatch;
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-4">RFC 9457 §4</see> supplies the library type.
    /// </summary>
    private static ProofVerificationOutcome ValidateSecuringMechanism(
        DataIntegrityProof proof, VcalmCredentialVerification? verification, bool isPresentation) => proof switch
        {
            _ when verification is null || proof.Type != DataIntegrityProof.DataIntegrityProofType
                || proof.Cryptosuite is UnknownCryptosuiteInfo
                || proof.Cryptosuite?.CryptosuiteName == CredentialConstants.Cryptosuites.Bbs2023 =>
                ProofVerificationOutcome.Failure(VcalmProblemTypes.UnsupportedSecuringMechanism,
                    VcalmProblemTypes.UnsupportedSecuringMechanismDetail),
            { Cryptosuite: null } => ProofVerificationOutcome.Failure(VcalmProblemTypes.ProofVerificationError,
                "An error was encountered during proof verification because the cryptosuite is missing."),
            _ when proof.Cryptosuite.CryptosuiteName == CredentialConstants.Cryptosuites.EcdsaSd2023
                && (isPresentation || verification.ParseDerivedProof is null || verification.VerifyDerivedSignature is null
                    || verification.SdProofEncoder is null || verification.SdProofDecoder is null) =>
                ProofVerificationOutcome.Failure(VcalmProblemTypes.UnsupportedSecuringMechanism,
                    VcalmProblemTypes.UnsupportedSecuringMechanismDetail),
            _ when proof.Cryptosuite.CryptosuiteName != CredentialConstants.Cryptosuites.EcdsaSd2023 =>
                ValidateCryptoRegistry(proof.Cryptosuite.SignatureAlgorithm),
            _ => ProofVerificationOutcome.Success
        };


    /// <summary>
    /// Whether <paramref name="proof"/> is an ecdsa-sd-2023 selective-disclosure proof, which this verifier dispatches
    /// only as a document's single proof (<see cref="VerifyEcdsaSd2023DerivedProofAsync"/>).
    /// </summary>
    /// <param name="proof">The proof to classify.</param>
    private static bool IsSelectiveDisclosureProof(DataIntegrityProof proof) =>
        string.Equals(proof.Cryptosuite?.CryptosuiteName, CredentialConstants.Cryptosuites.EcdsaSd2023, StringComparison.Ordinal);


    /// <summary>
    /// Checks dispatch availability in <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>:
    /// an uninitialized registry or a null lookup result means unavailable. Matcher exceptions
    /// reach <see cref="ProofVerificationAttempt.UnexpectedFailure"/> as unclassified dependency failures.
    /// </summary>
    private static ProofVerificationOutcome ValidateCryptoRegistry(CryptoAlgorithm algorithm) =>
        CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.IsInitialized
            && CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, Purpose.Verification) is not null
            ? ProofVerificationOutcome.Success
            : ProofVerificationOutcome.Failure(VcalmProblemTypes.UnsupportedSecuringMechanism,
                VcalmProblemTypes.UnsupportedSecuringMechanismDetail);


    /// <summary>
    /// Resolves the primary resource of the proof's URL and preserves
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3</see>
    /// document and identifier failures without exposing <see cref="DidResolutionMetadata"/> diagnostics.
    /// A resolver refusal that states <see cref="InvalidDidDocumentReason.IdMismatch"/> is step 6 and every other
    /// refusal is step 5. The resolution is a boundary over a dependency that throws, classified by phase: any
    /// failure while retrieving the controller document that is not the caller's cancellation, a throwing method
    /// selector included, means a conforming controlled identifier document was not retrieved (step 5, "If
    /// controllerDocument is not a conforming controlled identifier document, an error MUST be raised and SHOULD
    /// convey an error type of INVALID_CONTROLLED_IDENTIFIER_DOCUMENT"). A resolution cancelled while the caller's
    /// token is still live, the cancellation bare or carried inside another exception
    /// (<see cref="WrappedCancellation.IsOwnBudgetCancellation"/>), ended on its own budget and is recorded on the
    /// request's <see cref="ExchangeContext"/>; once any dependency of the request has exhausted its budget a document
    /// not yet resolved is not fetched and step 5 is reported without a fetch. The caller's own cancellation, bare or
    /// carried, propagates.
    /// </summary>
    /// <remarks>
    /// The resolver's answer for one controller document URL, a document, a typed failure or a throw, is kept on the
    /// request's own <see cref="ExchangeContext"/> (<c>GetControllerResolutions</c>) and reused for every later proof and
    /// contained credential of the same request that names that controller, so a presentation of many credentials from
    /// one issuer resolves the issuer once. Each caller still classifies the answer itself, so a detail names the
    /// caller's own verification method URL, and the memo never outlives the request or reaches another tenant.
    /// </remarks>
    /// <param name="resolver">The verifier's DID resolver.</param>
    /// <param name="verificationMethodId">The caller-supplied verification method URL the proof names.</param>
    /// <param name="context">The verify request's context, carrying the dependency-budget flag and the resolution memo.</param>
    /// <param name="cancellationToken">The caller's cancellation token.</param>
    /// <returns>The conforming controller document, or the classified CID §3.3 failure.</returns>
    private static async ValueTask<DocumentResolutionOutcome> ResolveDocumentAsync(
        DidResolver resolver, string verificationMethodId, ExchangeContext context, CancellationToken cancellationToken)
    {
        if(!IsValidVerificationMethodUrl(verificationMethodId))
        {
            return new(null, ProofVerificationOutcome.Failure(VcalmProblemTypes.InvalidVerificationMethodUrl,
                "The verification method identifier is not a valid URL.").Problem);
        }

        string controllerId = GetControllerDocumentId(verificationMethodId);
        Dictionary<string, DidResolutionResult?> resolutions = context.GetControllerResolutions();
        if(!resolutions.TryGetValue(controllerId, out DidResolutionResult? resolution))
        {
            if(context.HasExhaustedDependencyBudget)
            {
                return new(null, ControllerDocumentNotRetrieved(verificationMethodId, DependencyNotAttemptedDetail).Problem);
            }

            try
            {
                resolution = await resolver.ResolveAsync(controllerId, context, options: null, cancellationToken).ConfigureAwait(false);
            }
            catch(Exception exception) when(WrappedCancellation.IsOwnBudgetCancellation(exception, cancellationToken))
            {
                //The fetch ended on its own budget while the caller still waits, so the controller document could not
                //be retrieved: CID §3.3 step 5, the same as a transport failure the DID resolver contains.
                context.SetDependencyBudgetExhausted();

                return new(null, ControllerDocumentNotRetrieved(verificationMethodId, CancelledByOwnBudgetDetail).Problem);
            }
            catch(Exception exception) when(exception is not OperationCanceledException and not OutOfMemoryException)
            {
                //The caller's own cancellation carried inside the resolver's exception propagates as that cancellation;
                //any other throw is recorded as no answer, which every caller of this request reports as step 5.
                WrappedCancellation.ThrowIfCarried(exception);
                resolution = null;
            }

            resolutions[controllerId] = resolution;
        }

        if(resolution is null)
        {
            return new(null, ControllerDocumentNotRetrieved(verificationMethodId, cause: null).Problem);
        }

        VcalmProblemDetail? problem = resolution switch
        {
            //The resolver refused a document whose id is not the requested identifier. The DID Resolution error
            //stays invalidDidDocument; its stated reason is what separates step 6 from step 5. The comparison goes
            //through DidProblemDetails equality because Uri equality ignores the fragment that alone distinguishes
            //the DID Resolution error types.
            { InvalidDocumentReason: InvalidDidDocumentReason.IdMismatch }
                when DidResolutionErrors.InvalidDidDocument.Equals(resolution.ResolutionMetadata.Error) =>
                DocumentIdMismatch(verificationMethodId).Problem,
            _ when !resolution.IsSuccessful || resolution.Document?.Id is null
                || !DidUrl.TryParseAbsolute(resolution.Document.Id.ToString(), out _)
                || resolution.Document.Controller?.Any(controller => controller is null || !IsValidVerificationMethodUrl(controller.Did)) == true =>
                ControllerDocumentNotRetrieved(verificationMethodId, cause: null).Problem,
            _ when !string.Equals(resolution.Document.Id.ToString(), controllerId, StringComparison.Ordinal) =>
                DocumentIdMismatch(verificationMethodId).Problem,
            _ => null
        };

        return new(problem is null ? resolution.Document : null, problem);
    }


    /// <summary>
    /// The <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3</see> step 5 failure that
    /// <see cref="ResolveDocumentAsync"/> reports when no conforming controller document was retrieved: "If
    /// controllerDocument is not a conforming controlled identifier document, an error MUST be raised and SHOULD convey
    /// an error type of INVALID_CONTROLLED_IDENTIFIER_DOCUMENT."
    /// </summary>
    /// <param name="verificationMethodId">The caller-supplied verification method URL the detail names.</param>
    /// <param name="cause">The detail ending naming why no fetch was made or completed, or <see langword="null"/> for none.</param>
    private static ProofVerificationOutcome ControllerDocumentNotRetrieved(string verificationMethodId, string? cause) =>
        ProofVerificationOutcome.Failure(VcalmProblemTypes.InvalidControlledIdentifierDocument, cause is null
            ? $"A conforming controlled identifier document could not be retrieved for '{verificationMethodId}'."
            : $"A conforming controlled identifier document could not be retrieved for '{verificationMethodId}': {cause}");


    /// <summary>
    /// The <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3</see> step 6 failure
    /// that <see cref="ResolveDocumentAsync"/> reports whether the resolver refused the document or returned one:
    /// "If controllerDocument.id does not match the controllerDocumentUrl, an error MUST be raised and SHOULD convey
    /// an error type of INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID."
    /// </summary>
    /// <param name="verificationMethodId">The caller-supplied verification method URL the detail names.</param>
    private static ProofVerificationOutcome DocumentIdMismatch(string verificationMethodId) =>
        ProofVerificationOutcome.Failure(VcalmProblemTypes.InvalidControlledIdentifierDocumentId,
            $"The controlled identifier document id does not match the controller document URL for '{verificationMethodId}'.");


    /// <summary>
    /// Checks the method and relationship steps of
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3</see> in the algorithm's own
    /// order, raising at the first failing step, before <see cref="CredentialDataIntegrityExtensions"/> could combine
    /// missing-method and relationship failures. Step 8, "If verificationMethod is not a conforming verification method,
    /// an error MUST be raised and SHOULD convey an error type of INVALID_VERIFICATION_METHOD", comes first: the
    /// method's shape, a key agreement type (key material that never verifies a signature) and key material that is
    /// not a signing key of the method's declared type all fail it. Step 9 compares the method's <c>id</c> with
    /// <c>vmIdentifier</c> and step 10 its controller with the controller document URL, both INVALID_VERIFICATION_METHOD;
    /// step 11, "If verificationMethod is not associated ... with the verification relationship array in the
    /// controllerDocument identified by verificationRelationship", reports INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD.
    /// </summary>
    /// <remarks>
    /// Only after every CID step does this library's own binding run: the method's controller must be the credential's
    /// issuer or the presentation's holder, which no CID §3.3 step defines, so it reports
    /// <see cref="VcalmProblemTypes.VerificationMethodControllerMismatch"/>. A conforming method whose type the catalogue
    /// does not describe cannot be dispatched, which is last and reports
    /// <see cref="VcalmProblemTypes.UnsupportedSecuringMechanism"/>.
    /// </remarks>
    /// <param name="document">The retrieved controller document.</param>
    /// <param name="proof">The proof naming the verification method.</param>
    /// <param name="purpose">The verification relationship the proof's purpose requires.</param>
    /// <param name="claimedController">The credential's issuer or the presentation's holder.</param>
    /// <param name="memoryPool">The pool the key material is decoded into.</param>
    private static ProofVerificationOutcome ValidateVerificationMethod(
        DidDocument document, DataIntegrityProof proof, string purpose, string? claimedController, BaseMemoryPool memoryPool)
    {
        string identifier = proof.VerificationMethod!.Id!;
        VerificationMethod? related = purpose switch
        {
            AssertionMethod.Purpose => document.GetLocalAssertionMethodById(identifier),
            _ => document.GetLocalAuthenticationMethodById(identifier)
        };
        VerificationMethod? method = related ?? document.ResolveVerificationMethodReference(identifier)
            ?? document.GetLocalAssertionMethodById(identifier)
            ?? document.GetLocalAuthenticationMethodById(identifier)
            ?? document.GetLocalKeyAgreementMethodById(identifier)
            ?? document.GetLocalCapabilityInvocationMethodById(identifier)
            ?? document.GetLocalCapabilityDelegationMethodById(identifier);

        return method switch
        {
            null => ProofVerificationOutcome.Failure(VcalmProblemTypes.InvalidVerificationMethod,
                $"The verification method '{identifier}' is not a conforming verification method."),
            _ when !IsValidVerificationMethodType(method.Type) || method.KeyFormat is null
                || method.Controller is null || !IsValidVerificationMethodUrl(method.Controller) =>
                ProofVerificationOutcome.Failure(VcalmProblemTypes.InvalidVerificationMethod,
                    $"The verification method '{identifier}' is not a conforming verification method."),
            _ when IsKeyAgreementVerificationMethodType(method.Type!) => ProofVerificationOutcome.Failure(
                VcalmProblemTypes.InvalidVerificationMethod,
                $"The verification method '{identifier}' is of a key agreement type, not a signing type."),
            _ when ValidateVerificationMethodKey(method, memoryPool) is { IsValid: false } keyFailure => keyFailure,
            _ when !string.Equals(method.Id, identifier, StringComparison.Ordinal) =>
                ProofVerificationOutcome.Failure(VcalmProblemTypes.InvalidVerificationMethod,
                    $"The verification method's id does not equal '{identifier}'."),
            _ when !string.Equals(method.Controller, GetControllerDocumentId(identifier), StringComparison.Ordinal) =>
                ProofVerificationOutcome.Failure(VcalmProblemTypes.InvalidVerificationMethod,
                    $"The controller of the verification method '{identifier}' does not equal its controller document URL."),
            _ when related is null => ProofVerificationOutcome.Failure(VcalmProblemTypes.InvalidRelationshipForVerificationMethod,
                $"The verification method '{identifier}' is not associated with the required '{purpose}' verification relationship."),
            _ when !string.Equals(method.Controller, claimedController, StringComparison.Ordinal) =>
                ProofVerificationOutcome.Failure(VcalmProblemTypes.VerificationMethodControllerMismatch,
                    $"The controller of the verification method '{identifier}' is not the credential's issuer or the presentation's holder."),
            _ when !IsCatalogVerificationMethodType(method.Type!) => ProofVerificationOutcome.Failure(
                VcalmProblemTypes.UnsupportedSecuringMechanism, VcalmProblemTypes.UnsupportedSecuringMechanismDetail),
            _ => ProofVerificationOutcome.Success
        };
    }


    /// <summary>
    /// Recognizes any non-empty verification method type string as a conforming shape, before
    /// <see cref="ValidateVerificationMethodKey"/>, per
    /// <see href="https://www.w3.org/TR/cid-1.0/#verification-methods">CID §2.2</see>: "The value of the type
    /// property MUST be a string that references exactly one verification method type." Whether this verifier
    /// can dispatch the type is a separate question <see cref="IsCatalogVerificationMethodType"/> answers.
    /// </summary>
    private static bool IsValidVerificationMethodType(string? type) => !string.IsNullOrEmpty(type);


    /// <summary>
    /// Whether <paramref name="type"/> names an entry of Core's <see cref="VerificationMethodTypeInfo"/> catalogue,
    /// read from the catalogue itself (<see cref="VerificationMethodTypeInfoExtensions"/>) so this verifier holds no
    /// type name of its own. A conforming method whose type the catalogue does not know cannot be dispatched, which
    /// <see cref="ValidateVerificationMethod"/> reports as <see cref="VcalmProblemTypes.UnsupportedSecuringMechanism"/>
    /// rather than as a nonconforming method.
    /// </summary>
    /// <param name="type">The verification method's non-empty <c>type</c> value.</param>
    private static bool IsCatalogVerificationMethodType(string type) =>
        VerificationMethodTypeInfo.Catalogued.Any(known => IsDeclaredType(type, known));


    /// <summary>
    /// Whether <paramref name="type"/> is one of the catalogue's key agreement types, whose key material serves key
    /// agreement and never verifies a signature, so a proof's verification method of such a type does not conform.
    /// </summary>
    /// <param name="type">The verification method's non-empty <c>type</c> value.</param>
    private static bool IsKeyAgreementVerificationMethodType(string type) =>
        IsDeclaredType(type, VerificationMethodTypeInfo.X25519KeyAgreementKey2020)
        || IsDeclaredType(type, VerificationMethodTypeInfo.X25519KeyAgreementKey2019);


    /// <summary>
    /// Whether decoded key material agrees with the type its verification method declares: the material is a
    /// signature verification key, and a declared type that names one key algorithm names the algorithm the material
    /// decodes to. The generic key containers (<c>Multikey</c>, <c>JsonWebKey2020</c>, <c>JwsVerificationKey2020</c>)
    /// carry a key of any signing algorithm, so their material is checked for its purpose alone.
    /// </summary>
    /// <param name="declaredType">The verification method's declared <c>type</c>.</param>
    /// <param name="algorithm">The algorithm the key material decoded to.</param>
    /// <param name="purpose">The purpose the key material decoded to.</param>
    private static bool IsKeyMaterialOfDeclaredType(string declaredType, CryptoAlgorithm algorithm, Purpose purpose) => declaredType switch
    {
        _ when !purpose.Equals(Purpose.Verification) => false,
        _ when IsDeclaredType(declaredType, VerificationMethodTypeInfo.Ed25519VerificationKey2020)
            || IsDeclaredType(declaredType, VerificationMethodTypeInfo.Ed25519VerificationKey2018) => algorithm.Equals(CryptoAlgorithm.Ed25519),
        _ when IsDeclaredType(declaredType, VerificationMethodTypeInfo.Secp256k1VerificationKey2018) => algorithm.Equals(CryptoAlgorithm.Secp256k1),
        _ when IsDeclaredType(declaredType, VerificationMethodTypeInfo.RsaVerificationKey2018) =>
            algorithm.Equals(CryptoAlgorithm.Rsa2048) || algorithm.Equals(CryptoAlgorithm.Rsa4096),
        _ when IsDeclaredType(declaredType, VerificationMethodTypeInfo.Bls12381G2) => algorithm.Equals(CryptoAlgorithm.Bls12381G2),
        _ => true
    };


    /// <summary>Whether a verification method's declared <c>type</c> is the catalogue entry <paramref name="typeInfo"/>.</summary>
    /// <param name="declaredType">The verification method's declared <c>type</c>.</param>
    /// <param name="typeInfo">The catalogue entry compared with.</param>
    private static bool IsDeclaredType(string declaredType, VerificationMethodTypeInfo typeInfo) =>
        string.Equals(declaredType, typeInfo.TypeName, StringComparison.Ordinal);


    /// <summary>
    /// Checks that a verification method carries conforming public key material, so a malformed key is reported as
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3</see>
    /// INVALID_VERIFICATION_METHOD instead of being mistaken for a failed signature. Absent material is an input
    /// result decided before any conversion: a blank multibase value, or a <see cref="PublicKeyJwk.Header"/> without
    /// the string <c>kty</c> member of which
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.1">RFC 7517 §4.1</see> says "This member MUST be
    /// present in a JWK". Material that is present is decoded through
    /// <see cref="VerificationMethodCryptoConversions.DefaultConverter"/>, a boundary over decoders that throw: a
    /// malformed multibase, base58 or base64url encoding raises <see cref="ArgumentException"/> or
    /// <see cref="FormatException"/>, which is this step's INVALID_VERIFICATION_METHOD, and every other exception
    /// reaches the phase boundary of <see cref="VerifyCredentialProofAsync"/> or
    /// <see cref="VerifyPresentationProofAsync"/>. Decoded material that is not a signing key of the method's declared
    /// type (<see cref="IsKeyMaterialOfDeclaredType"/>), such as a P-256 multikey filed under an Ed25519 type, does not
    /// conform either, so it is refused here rather than handed to a signature check under the wrong algorithm.
    /// </summary>
    private static ProofVerificationOutcome ValidateVerificationMethodKey(VerificationMethod method, BaseMemoryPool memoryPool)
    {
        bool hasKeyMaterial = method.KeyFormat switch
        {
            PublicKeyMultibase multibase => !string.IsNullOrWhiteSpace(multibase.Key),
            PublicKeyJwk jwk => jwk.Header is not null
                && jwk.Header.TryGetValue(WellKnownJwkMemberNames.Kty, out object? keyType)
                && keyType is string keyTypeValue
                && !string.IsNullOrWhiteSpace(keyTypeValue),
            _ => false
        };
        if(!hasKeyMaterial)
        {
            return ProofVerificationOutcome.Failure(VcalmProblemTypes.InvalidVerificationMethod,
                "The verification method does not contain conforming public key material.");
        }

        try
        {
            var material = VerificationMethodCryptoConversions.DefaultConverter(method, memoryPool);
            using System.Buffers.IMemoryOwner<byte>? key = material.keyMaterial;

            return key switch
            {
                null => ProofVerificationOutcome.Failure(VcalmProblemTypes.InvalidVerificationMethod,
                    "The verification method does not contain conforming public key material."),
                _ when !IsKeyMaterialOfDeclaredType(method.Type!, material.Algorithm, material.Purpose) =>
                    ProofVerificationOutcome.Failure(VcalmProblemTypes.InvalidVerificationMethod,
                        "The verification method's public key material is not a signing key of its declared type."),
                _ => ProofVerificationOutcome.Success
            };
        }
        catch(Exception exception) when(exception is ArgumentException or FormatException)
        {
            //The converter's decoders report a malformed encoding of present material by throwing one of these two
            //types and offer no result-returning entry point; every other exception reaches the phase boundary.

            return ProofVerificationOutcome.Failure(VcalmProblemTypes.InvalidVerificationMethod,
                "The verification method does not contain conforming public key material.");
        }
    }


    /// <summary>Extracts the primary resource URL required by <see cref="ResolveDocumentAsync"/>.</summary>
    private static string GetControllerDocumentId(string verificationMethodId)
    {
        int fragmentIndex = verificationMethodId.IndexOf('#', StringComparison.Ordinal);

        return fragmentIndex < 0 ? verificationMethodId : verificationMethodId[..fragmentIndex];
    }


    /// <summary>Retains a proof's error instead of collapsing it to the validity flag in <see cref="VcalmInputResult"/>.</summary>
    /// <param name="Problem">The classified error, or null for success.</param>
    private readonly record struct ProofVerificationOutcome(VcalmProblemDetail? Problem)
    {
        /// <summary>Whether <see cref="Problem"/> contains no error.</summary>
        public bool IsValid => Problem is null;

        /// <summary>A successful outcome with no <see cref="VcalmProblemDetail"/>.</summary>
        public static ProofVerificationOutcome Success { get; } = new(null);

        /// <summary>Constructs the error whose title is its <see cref="VcalmProblemTypes"/> code.</summary>
        public static ProofVerificationOutcome Failure(string type, string detail) =>
            new(VcalmProblemDetail.Error(type, type[(type.IndexOf('#', StringComparison.Ordinal) + 1)..], detail));
    }


    /// <summary>Retains the CID failure alongside a successfully resolved <see cref="DidDocument"/>.</summary>
    /// <param name="Document">The conforming document, or null on failure.</param>
    /// <param name="Problem">The classified resolution error, or null on success.</param>
    private readonly record struct DocumentResolutionOutcome(DidDocument? Document, VcalmProblemDetail? Problem);


    /// <summary>
    /// The phase of a proof's verification by which <see cref="ProofVerificationAttempt"/> classifies a dependency
    /// failure: <see href="https://www.w3.org/TR/vc-data-integrity/#processing-errors">Data Integrity §4.7</see> names
    /// PROOF_TRANSFORMATION_ERROR for "An error was encountered during the transformation process" and
    /// PROOF_VERIFICATION_ERROR for "An error was encountered during proof verification".
    /// </summary>
    private enum ProofVerificationPhase
    {
        /// <summary>Everything outside the transformation: option checks, resolution, key decoding and the signature check.</summary>
        Verification,

        /// <summary>The canonicalization of the document and its proof options, which fetches JSON-LD contexts.</summary>
        Transformation
    }


    /// <summary>
    /// Observes the transformation boundary so <see cref="VerificationFailureReason.ContextValidationFailed"/>
    /// retains whether the failure occurred during transformation or subsequent context validation.
    /// </summary>
    private sealed class ProofVerificationAttempt
    {
        /// <summary>The active phase used to classify and sanitize failures into <see cref="VcalmProblemDetail.Detail"/>.</summary>
        private ProofVerificationPhase Phase { get; set; } = ProofVerificationPhase.Verification;

        /// <summary>The active phase as the sanitized detail names it.</summary>
        private string PhaseName => Phase switch
        {
            ProofVerificationPhase.Transformation => "proof transformation",
            _ => "proof verification"
        };

        /// <summary>Whether this attempt dispatched <see cref="CredentialEcdsaSd2023Extensions"/>.</summary>
        public bool IsSelectiveDisclosure { get; set; }

        /// <summary>Whether an actual selective-disclosure signature check returned false through <see cref="VerifyDerivedSignature"/>.</summary>
        private bool HasInvalidSignature { get; set; }

        /// <summary>The observed <see cref="VcalmCredentialVerification.VerifyDerivedSignature"/> delegate, retaining actual crypto verdicts.</summary>
        public VerificationDelegate? VerifyDerivedSignature { get; }

        /// <summary>The wrapped <see cref="CanonicalizationDelegate"/> for this attempt only.</summary>
        public CanonicalizationDelegate? Canonicalize { get; }

        /// <summary>Wraps the supplied <see cref="VcalmCredentialVerification.Canonicalize"/> without changing its result or exceptions.</summary>
        public ProofVerificationAttempt(VcalmCredentialVerification? verification)
        {
            Canonicalize = verification is null ? null : async (json, resolver, context, cancellationToken) =>
            {
                Phase = ProofVerificationPhase.Transformation;
                CanonicalizationResult result = await verification.Canonicalize(json, resolver, context, cancellationToken).ConfigureAwait(false);
                Phase = ProofVerificationPhase.Verification;

                return result;
            };
            VerifyDerivedSignature = verification?.VerifyDerivedSignature is not { } verify ? null : async (data, signature, key, context, cancellationToken) =>
            {
                var result = await verify(data, signature, key, context, cancellationToken).ConfigureAwait(false);
                HasInvalidSignature |= !result.IsVerified;

                return result;
            };
        }


        /// <summary>Maps an actual thrown dependency failure to its <see cref="Phase"/>, never to tampering.</summary>
        /// <param name="isCancelledByOwnBudget">Whether the dependency cancelled while the caller's token was still live.</param>
        public ProofVerificationOutcome UnexpectedFailure(bool isCancelledByOwnBudget = false) => ProofVerificationOutcome.Failure(
            Phase switch
            {
                ProofVerificationPhase.Transformation => VcalmProblemTypes.ProofTransformationError,
                _ => VcalmProblemTypes.ProofVerificationError
            },
            isCancelledByOwnBudget
                ? $"An error was encountered during {PhaseName}: the fetch or operation was cancelled by its own budget."
                : $"An error was encountered during {PhaseName}.");


        /// <summary>
        /// The outcome for a proof whose transformation is never started because an earlier dependency of
        /// the same request already exhausted its own budget: the transformation fetches JSON-LD contexts,
        /// so it reports <see cref="VcalmProblemTypes.ProofTransformationError"/>, the type a failed context
        /// fetch reports (<see href="https://www.w3.org/TR/vc-data-integrity/#processing-errors">Data
        /// Integrity §4.7</see>: "An error was encountered during the transformation process").
        /// </summary>
        public static ProofVerificationOutcome TransformationNotAttempted { get; } = ProofVerificationOutcome.Failure(
            VcalmProblemTypes.ProofTransformationError,
            "An error was encountered during proof transformation: " + DependencyNotAttemptedDetail);


        /// <summary>Maps the library's typed <see cref="VerificationFailureReason"/> according to the defining specification.</summary>
        /// <remarks>
        /// <see cref="VerificationFailureReason.ControllerMismatch"/> has no mapping of its own: <see cref="ValidateVerificationMethod"/>
        /// checks the same binding of the method's controller to the issuer or holder before Core verifies, so a method
        /// that reaches Core has already passed it.
        /// </remarks>
        /// <param name="isValid">Whether Core verified the proof.</param>
        /// <param name="reason">The reason Core reported when it did not.</param>
        public ProofVerificationOutcome MapResult(bool isValid, VerificationFailureReason reason) => (isValid, reason) switch
        {
            (true, _) => ProofVerificationOutcome.Success,
            (_, VerificationFailureReason.SignatureInvalid) when IsSelectiveDisclosure && !HasInvalidSignature =>
                ProofVerificationOutcome.Failure(VcalmProblemTypes.ProofVerificationError,
                    "An error was encountered during selective-disclosure proof verification."),
            (_, VerificationFailureReason.SignatureInvalid) => ProofVerificationOutcome.Failure(VcalmProblemTypes.CryptographicSecurityError,
                "The securing mechanism detected a modification in the document contents since it was created; potential tampering detected."),
            (_, VerificationFailureReason.NoProof) => ProofVerificationOutcome.Failure(VcalmProblemTypes.ParsingError,
                "The secured document carries no Data Integrity proof map to verify."),
            (_, VerificationFailureReason.ContextValidationFailed) when Phase == ProofVerificationPhase.Transformation => UnexpectedFailure(),
            (_, VerificationFailureReason.ContextValidationFailed) => ProofVerificationOutcome.Failure(VcalmProblemTypes.ContextValidationError,
                "The document context failed context validation after proof transformation."),
            (_, VerificationFailureReason.VerificationMethodNotFound) => ProofVerificationOutcome.Failure(VcalmProblemTypes.InvalidVerificationMethod,
                "The verification method is not a conforming verification method of the controller document."),
            (_, VerificationFailureReason.DomainMismatch) => ProofVerificationOutcome.Failure(VcalmProblemTypes.InvalidDomainError,
                "The domain value in the proof did not match the expected value."),
            (_, VerificationFailureReason.ChallengeMismatch) => ProofVerificationOutcome.Failure(VcalmProblemTypes.InvalidChallengeError,
                "The challenge value in the proof did not match the expected value."),
            _ => ProofVerificationOutcome.Failure(VcalmProblemTypes.ProofVerificationError,
                "An error was encountered during proof verification.")
        };
    }


    /// <summary>
    /// §3.8.1: validFrom in the future is a validity-period WARNING (recoverable; does not flip
    /// verified). The result's verified is false when the window is not yet open, true otherwise.
    /// </summary>
    private static VcalmInputResult? EvaluateValidFrom(
        string? validFrom, DateTimeOffset now, ImmutableArray<VcalmProblemDetail>.Builder problems)
    {
        if(string.IsNullOrEmpty(validFrom))
        {
            return null;
        }

        bool isInWindow = !TryParseTimestamp(validFrom, out DateTimeOffset parsed) || now >= parsed;
        if(!isInWindow)
        {
            problems.Add(VcalmProblemDetail.Warning(
                VcalmProblemTypes.ValidityPeriodWarning,
                "VALIDITY_PERIOD_WARNING",
                $"The credential's validFrom ({validFrom}) is in the future relative to the verification time."));
        }

        return new VcalmInputResult { Verified = isInWindow, Input = validFrom };
    }


    /// <summary>
    /// §3.8.1: validUntil in the past is a validity-period WARNING (recoverable; does not flip
    /// verified). The result's verified is false when the window has closed, true otherwise.
    /// </summary>
    private static VcalmInputResult? EvaluateValidUntil(
        string? validUntil, DateTimeOffset now, ImmutableArray<VcalmProblemDetail>.Builder problems)
    {
        if(string.IsNullOrEmpty(validUntil))
        {
            return null;
        }

        bool isInWindow = !TryParseTimestamp(validUntil, out DateTimeOffset parsed) || now <= parsed;
        if(!isInWindow)
        {
            problems.Add(VcalmProblemDetail.Warning(
                VcalmProblemTypes.ValidityPeriodWarning,
                "VALIDITY_PERIOD_WARNING",
                $"The credential's validUntil ({validUntil}) is in the past relative to the verification time."));
        }

        return new VcalmInputResult { Verified = isInWindow, Input = validUntil };
    }


    /// <summary>Parses a credential validity timestamp for <see cref="EvaluateValidFrom"/> and <see cref="EvaluateValidUntil"/> using invariant UTC semantics.</summary>
    /// <param name="value">The timestamp supplied in the credential.</param>
    /// <param name="parsed">The UTC instant when parsing succeeds.</param>
    /// <returns>Whether <paramref name="value"/> represents a timestamp.</returns>
    private static bool TryParseTimestamp(string value, out DateTimeOffset parsed) =>
        DateTimeOffset.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out parsed);
}


/// <summary>
/// The result of verifying one VCALM 1.0 §3.3.2 presentation proof: the per-proof verified outcome,
/// the bound challenge / domain / holder it was checked against, and any §3.8.1 ProblemDetails.
/// </summary>
[DebuggerDisplay("VcalmPresentationProofResult Verified={Verified}")]
public sealed record VcalmPresentationProofResult
{
    /// <summary>The presentation-proof verification result.</summary>
    public required bool Verified { get; init; }

    /// <summary>The expected challenge the proof was checked against, or <see langword="null"/> when unbound.</summary>
    public string? Challenge { get; init; }

    /// <summary>The expected domain the proof was checked against, or <see langword="null"/> when unbound.</summary>
    public string? Domain { get; init; }

    /// <summary>The presentation's holder, or <see langword="null"/> when absent.</summary>
    public string? Holder { get; init; }

    /// <summary>The proof's <c>verificationMethod</c> as the §3.3.2 <c>results.presentation.proof[].input</c>.</summary>
    public required string ProofInput { get; init; }

    /// <summary>The §3.8.1 ProblemDetails gathered for this presentation proof.</summary>
    public ImmutableArray<VcalmProblemDetail> ProblemDetails { get; init; } = ImmutableArray<VcalmProblemDetail>.Empty;
}
