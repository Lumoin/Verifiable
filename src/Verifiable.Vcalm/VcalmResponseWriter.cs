using System.Collections.Immutable;
using System.Text;

namespace Verifiable.Vcalm;

/// <summary>
/// Hand-built JSON writers for the VCALM 1.0 §3.3 verifier response bodies — the §3.3.1
/// VerificationResponse, the §3.3.2 presentation VerificationResponse, the §3.3.3 challenge
/// response, and the §3.8 ProblemDetails array — through <see cref="JsonAppender"/> per the
/// <c>Verifiable.Vcalm</c> serialization firewall (no <c>System.Text.Json</c>). The credential /
/// presentation echo members are emitted with <see cref="JsonAppender.AppendRawField"/> from the
/// verbatim JSON the parser preserved, so the §3.3.1 "in the form in which it was verified" echo is
/// byte-faithful without a re-serialization round-trip.
/// </summary>
public static class VcalmResponseWriter
{
    /// <summary>
    /// Writes the §3.3.1 credential VerificationResponse: the REQUIRED <c>verified</c>, the optional
    /// <c>credential</c> echo (when <c>returnCredential</c>), the optional <c>problemDetails</c>
    /// array (when <c>returnProblemDetails</c>), and the optional verbose <c>results</c> object
    /// (when <c>returnResults</c>).
    /// </summary>
    public static string BuildCredentialVerificationResponse(
        VcalmVerificationOutcome outcome,
        VcalmVerifyOptions options,
        string? credentialJson)
    {
        ArgumentNullException.ThrowIfNull(outcome);
        ArgumentNullException.ThrowIfNull(options);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;
            JsonAppender.AppendBoolField(sb, VcalmParameterNames.Verified, outcome.Verified, ref first);

            if(options.ReturnCredential && credentialJson is not null)
            {
                JsonAppender.AppendRawField(sb, VcalmParameterNames.Credential, credentialJson, ref first);
            }

            if(options.ReturnProblemDetails)
            {
                AppendProblemDetailsArray(sb, VcalmParameterNames.ProblemDetails, outcome.ProblemDetails, ref first);
            }

            if(options.ReturnResults)
            {
                AppendCredentialResults(sb, outcome, ref first);
            }

            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Writes the §3.3.2 presentation VerificationResponse: the REQUIRED <c>verified</c>, the
    /// optional <c>verifiablePresentation</c> echo (when <c>returnPresentation</c>), the optional
    /// <c>problemDetails</c> array, and the optional verbose <c>results</c> object carrying the
    /// presentation sub-result and the per-credential results.
    /// </summary>
    public static string BuildPresentationVerificationResponse(
        bool verified,
        VcalmPresentationProofResult presentationResult,
        IReadOnlyList<VcalmVerificationOutcome> credentialOutcomes,
        ImmutableArray<VcalmProblemDetail> presentationLevelProblems,
        VcalmVerifyOptions options,
        string? presentationJson)
    {
        ArgumentNullException.ThrowIfNull(presentationResult);
        ArgumentNullException.ThrowIfNull(credentialOutcomes);
        ArgumentNullException.ThrowIfNull(options);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;
            JsonAppender.AppendBoolField(sb, VcalmParameterNames.Verified, verified, ref first);

            if(options.ReturnPresentation && presentationJson is not null)
            {
                JsonAppender.AppendRawField(sb, VcalmParameterNames.VerifiablePresentation, presentationJson, ref first);
            }

            if(options.ReturnProblemDetails)
            {
                AppendProblemDetailsArray(sb, VcalmParameterNames.ProblemDetails, presentationLevelProblems, ref first);
            }

            if(options.ReturnResults)
            {
                AppendPresentationResults(sb, presentationResult, credentialOutcomes, ref first);
            }

            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Writes the §3.2.1 IssueCredentialResponse (a 201 body) and the §3.2.2 retrieval response (a
    /// 200 body): the single <c>verifiableCredential</c> member carrying the secured credential's
    /// verbatim JSON — either a Data-Integrity-secured VC object or an
    /// <c>EnvelopedVerifiableCredential</c>. The credential is emitted with
    /// <see cref="JsonAppender.AppendRawField"/> so the secured bytes ride through byte-faithful.
    /// </summary>
    public static string BuildVerifiableCredentialResponse(string securedCredentialJson)
    {
        ArgumentException.ThrowIfNullOrEmpty(securedCredentialJson);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;
            JsonAppender.AppendRawField(sb, VcalmParameterNames.VerifiableCredential, securedCredentialJson, ref first);
            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Writes the §C.1 <c>POST /status-lists</c> 201 response: the <c>verifiableCredential</c> member
    /// carrying the secured status-list credential's verbatim JSON, plus the <c>id</c> member naming
    /// the created status-list credential (the §C.2 retrieval key). The credential is emitted with
    /// <see cref="JsonAppender.AppendRawField"/> so the secured bytes ride through byte-faithful.
    /// </summary>
    public static string BuildCreateStatusListResponse(string securedStatusListJson, string statusListId)
    {
        ArgumentException.ThrowIfNullOrEmpty(securedStatusListJson);
        ArgumentException.ThrowIfNullOrEmpty(statusListId);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;
            JsonAppender.AppendRawField(sb, VcalmParameterNames.VerifiableCredential, securedStatusListJson, ref first);
            JsonAppender.AppendStringField(sb, VcalmParameterNames.Id, statusListId, ref first);
            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Writes the §3.5.2 create-presentation 201 response: the single <c>verifiablePresentation</c>
    /// member carrying the secured presentation's verbatim JSON — either a Data-Integrity-secured
    /// presentation object or an <c>EnvelopedVerifiablePresentation</c>. The presentation is emitted
    /// with <see cref="JsonAppender.AppendRawField"/> so the secured bytes ride through byte-faithful.
    /// </summary>
    public static string BuildVerifiablePresentationResponse(string securedPresentationJson)
    {
        ArgumentException.ThrowIfNullOrEmpty(securedPresentationJson);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;
            JsonAppender.AppendRawField(sb, VcalmParameterNames.VerifiablePresentation, securedPresentationJson, ref first);
            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Writes the §3.5.3 list-presentations 200 response: a JSON array whose items are the stored
    /// secured presentations' verbatim JSON ("Each item in the array MUST be a JSON-LD Verifiable
    /// Presentation"). Each item is emitted raw so the secured bytes ride through byte-faithful.
    /// </summary>
    public static string BuildPresentationsListResponse(IReadOnlyList<string> securedPresentationJsons)
    {
        ArgumentNullException.ThrowIfNull(securedPresentationJsons);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('[');
            for(int i = 0; i < securedPresentationJsons.Count; ++i)
            {
                if(i > 0)
                {
                    sb.Append(',');
                }

                sb.Append(securedPresentationJsons[i]);
            }

            sb.Append(']');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>Writes the §3.3.3 challenge response: the single <c>challenge</c> member.</summary>
    public static string BuildChallengeResponse(string challenge)
    {
        ArgumentException.ThrowIfNullOrEmpty(challenge);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;
            JsonAppender.AppendStringField(sb, VcalmParameterNames.Challenge, challenge, ref first);
            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    //§3.3.1 results: validFrom, validUntil, credentialSchema, credentialStatus, proof.
    private static void AppendCredentialResults(
        StringBuilder sb, VcalmVerificationOutcome outcome, ref bool first)
    {
        if(!first)
        {
            sb.Append(',');
        }

        sb.Append('"');
        JsonAppender.AppendEscapedString(sb, VcalmParameterNames.Results);
        sb.Append("\":");
        AppendCredentialResultsObject(sb, outcome);

        first = false;
    }


    //The §3.3.1 results object value, reused for each per-credential result in §3.3.2.
    private static void AppendCredentialResultsObject(StringBuilder sb, VcalmVerificationOutcome outcome)
    {
        sb.Append('{');
        bool resultsFirst = true;

        if(outcome.ValidFrom is not null)
        {
            AppendInputResultField(sb, VcalmParameterNames.ValidFrom, outcome.ValidFrom, ref resultsFirst);
        }

        if(outcome.ValidUntil is not null)
        {
            AppendInputResultField(sb, VcalmParameterNames.ValidUntil, outcome.ValidUntil, ref resultsFirst);
        }

        //credentialSchema results are emitted as an empty array in V-1 (schema validation is a
        //later chunk); the member is always present per the §3.3.1 results shape.
        AppendEmptyArrayField(sb, VcalmParameterNames.CredentialSchema, ref resultsFirst);
        AppendStatusResultsField(sb, VcalmParameterNames.CredentialStatus, outcome.StatusResults, ref resultsFirst);
        AppendInputResultArrayField(sb, VcalmParameterNames.Proof, outcome.ProofResults, ref resultsFirst);

        sb.Append('}');
    }


    //§3.3.2 results: presentation { challenge, domain, holder, proof[] } + credentials[].
    private static void AppendPresentationResults(
        StringBuilder sb,
        VcalmPresentationProofResult presentationResult,
        IReadOnlyList<VcalmVerificationOutcome> credentialOutcomes,
        ref bool first)
    {
        if(!first)
        {
            sb.Append(',');
        }

        sb.Append('"');
        JsonAppender.AppendEscapedString(sb, VcalmParameterNames.Results);
        sb.Append("\":{");

        bool resultsFirst = true;

        //results.presentation { challenge?, domain?, holder?, proof[] }.
        if(!resultsFirst)
        {
            sb.Append(',');
        }

        sb.Append('"');
        JsonAppender.AppendEscapedString(sb, VcalmParameterNames.Presentation);
        sb.Append("\":{");

        bool presentationFirst = true;
        if(presentationResult.Challenge is not null)
        {
            AppendInputResultField(
                sb,
                VcalmParameterNames.Challenge,
                new VcalmInputResult { Verified = presentationResult.Verified, Input = presentationResult.Challenge },
                ref presentationFirst);
        }

        if(presentationResult.Domain is not null)
        {
            AppendInputResultField(
                sb,
                VcalmParameterNames.Domain,
                new VcalmInputResult { Verified = presentationResult.Verified, Input = presentationResult.Domain },
                ref presentationFirst);
        }

        if(presentationResult.Holder is not null)
        {
            AppendInputResultField(
                sb,
                VcalmParameterNames.Holder,
                new VcalmInputResult { Verified = presentationResult.Verified, Input = presentationResult.Holder },
                ref presentationFirst);
        }

        AppendInputResultArrayField(
            sb,
            VcalmParameterNames.Proof,
            [new VcalmInputResult { Verified = presentationResult.Verified, Input = presentationResult.ProofInput }],
            ref presentationFirst);

        sb.Append('}');
        resultsFirst = false;

        //results.credentials[]: one §3.3.1 VerificationResponse-shaped result per contained credential.
        if(!resultsFirst)
        {
            sb.Append(',');
        }

        sb.Append('"');
        JsonAppender.AppendEscapedString(sb, VcalmParameterNames.Credentials);
        sb.Append("\":[");

        for(int i = 0; i < credentialOutcomes.Count; ++i)
        {
            if(i > 0)
            {
                sb.Append(',');
            }

            VcalmVerificationOutcome credentialOutcome = credentialOutcomes[i];
            sb.Append('{');
            bool credentialFirst = true;
            JsonAppender.AppendBoolField(sb, VcalmParameterNames.Verified, credentialOutcome.Verified, ref credentialFirst);
            AppendProblemDetailsArray(sb, VcalmParameterNames.ProblemDetails, credentialOutcome.ProblemDetails, ref credentialFirst);

            if(!credentialFirst)
            {
                sb.Append(',');
            }

            sb.Append('"');
            JsonAppender.AppendEscapedString(sb, VcalmParameterNames.Results);
            sb.Append("\":");
            AppendCredentialResultsObject(sb, credentialOutcome);

            sb.Append('}');
        }

        sb.Append(']');

        sb.Append('}');
        first = false;
    }


    //A §3.3.1 per-step sub-result object: { verified, input }.
    private static void AppendInputResultField(
        StringBuilder sb, string key, VcalmInputResult result, ref bool first)
    {
        if(!first)
        {
            sb.Append(',');
        }

        sb.Append('"');
        JsonAppender.AppendEscapedString(sb, key);
        sb.Append("\":{");

        bool resultFirst = true;
        JsonAppender.AppendBoolField(sb, VcalmParameterNames.Verified, result.Verified, ref resultFirst);
        JsonAppender.AppendStringField(sb, VcalmParameterNames.Input, result.Input, ref resultFirst);

        sb.Append('}');
        first = false;
    }


    //A §3.3.1 array of per-step sub-results, e.g. results.proof[].
    private static void AppendInputResultArrayField(
        StringBuilder sb, string key, IReadOnlyList<VcalmInputResult> results, ref bool first)
    {
        if(!first)
        {
            sb.Append(',');
        }

        sb.Append('"');
        JsonAppender.AppendEscapedString(sb, key);
        sb.Append("\":[");

        for(int i = 0; i < results.Count; ++i)
        {
            if(i > 0)
            {
                sb.Append(',');
            }

            sb.Append('{');
            bool resultFirst = true;
            JsonAppender.AppendBoolField(sb, VcalmParameterNames.Verified, results[i].Verified, ref resultFirst);
            JsonAppender.AppendStringField(sb, VcalmParameterNames.Input, results[i].Input, ref resultFirst);
            sb.Append('}');
        }

        sb.Append(']');
        first = false;
    }


    //A §3.3.1 results.credentialStatus[] array: { value, verified, input }.
    private static void AppendStatusResultsField(
        StringBuilder sb, string key, IReadOnlyList<VcalmStatusResult> results, ref bool first)
    {
        if(!first)
        {
            sb.Append(',');
        }

        sb.Append('"');
        JsonAppender.AppendEscapedString(sb, key);
        sb.Append("\":[");

        for(int i = 0; i < results.Count; ++i)
        {
            if(i > 0)
            {
                sb.Append(',');
            }

            sb.Append('{');
            bool resultFirst = true;
            JsonAppender.AppendInt64Field(sb, VcalmParameterNames.Value, results[i].Value, ref resultFirst);
            JsonAppender.AppendBoolField(sb, VcalmParameterNames.Verified, results[i].Verified, ref resultFirst);
            JsonAppender.AppendStringField(sb, VcalmParameterNames.Input, results[i].Input, ref resultFirst);
            sb.Append('}');
        }

        sb.Append(']');
        first = false;
    }


    private static void AppendEmptyArrayField(StringBuilder sb, string key, ref bool first)
    {
        if(!first)
        {
            sb.Append(',');
        }

        sb.Append('"');
        JsonAppender.AppendEscapedString(sb, key);
        sb.Append("\":[]");
        first = false;
    }


    /// <summary>
    /// Writes a §3.8 ProblemDetails array: each element carries the REQUIRED <c>type</c> URL and the
    /// SHOULD <c>title</c> / <c>detail</c>. The internal §3.8.1 error/warning flag is not emitted.
    /// </summary>
    private static void AppendProblemDetailsArray(
        StringBuilder sb, string key, ImmutableArray<VcalmProblemDetail> problems, ref bool first)
    {
        if(!first)
        {
            sb.Append(',');
        }

        sb.Append('"');
        JsonAppender.AppendEscapedString(sb, key);
        sb.Append("\":[");

        for(int i = 0; i < problems.Length; ++i)
        {
            if(i > 0)
            {
                sb.Append(',');
            }

            VcalmProblemDetail problem = problems[i];
            sb.Append('{');
            bool problemFirst = true;
            JsonAppender.AppendStringField(sb, VcalmParameterNames.ProblemType, problem.Type, ref problemFirst);
            if(problem.Title is not null)
            {
                JsonAppender.AppendStringField(sb, VcalmParameterNames.ProblemTitle, problem.Title, ref problemFirst);
            }

            if(problem.Detail is not null)
            {
                JsonAppender.AppendStringField(sb, VcalmParameterNames.ProblemDetail, problem.Detail, ref problemFirst);
            }

            sb.Append('}');
        }

        sb.Append(']');
        first = false;
    }


    /// <summary>
    /// Writes a standalone §3.8 ProblemDetails object (the body of a 400 that carries a single
    /// ProblemDetail, e.g. the §2.4 UNKNOWN_OPTION_PROVIDED rejection).
    /// </summary>
    public static string BuildProblemDetailBody(VcalmProblemDetail problem)
    {
        ArgumentNullException.ThrowIfNull(problem);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;
            JsonAppender.AppendStringField(sb, VcalmParameterNames.ProblemType, problem.Type, ref first);
            if(problem.Title is not null)
            {
                JsonAppender.AppendStringField(sb, VcalmParameterNames.ProblemTitle, problem.Title, ref first);
            }

            if(problem.Detail is not null)
            {
                JsonAppender.AppendStringField(sb, VcalmParameterNames.ProblemDetail, problem.Detail, ref first);
            }

            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }
}
