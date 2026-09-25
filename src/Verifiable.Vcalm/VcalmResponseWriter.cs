using System.Collections.Immutable;
using System.Text;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;

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
            _ = sb.Append('{');
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

            _ = sb.Append('}');

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
            _ = sb.Append('{');
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
                AppendPresentationResults(sb, presentationResult, credentialOutcomes, presentationLevelProblems, ref first);
            }

            _ = sb.Append('}');

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
            _ = sb.Append('{');
            bool first = true;
            JsonAppender.AppendRawField(sb, VcalmParameterNames.VerifiableCredential, securedCredentialJson, ref first);
            _ = sb.Append('}');

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
            _ = sb.Append('{');
            bool first = true;
            JsonAppender.AppendRawField(sb, VcalmParameterNames.VerifiableCredential, securedStatusListJson, ref first);
            JsonAppender.AppendStringField(sb, VcalmParameterNames.Id, statusListId, ref first);
            _ = sb.Append('}');

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
            _ = sb.Append('{');
            bool first = true;
            JsonAppender.AppendRawField(sb, VcalmParameterNames.VerifiablePresentation, securedPresentationJson, ref first);
            _ = sb.Append('}');

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
            _ = sb.Append('[');
            for(int i = 0; i < securedPresentationJsons.Count; ++i)
            {
                if(i > 0)
                {
                    _ = sb.Append(',');
                }

                _ = sb.Append(securedPresentationJsons[i]);
            }

            _ = sb.Append(']');

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
            _ = sb.Append('{');
            bool first = true;
            JsonAppender.AppendStringField(sb, VcalmParameterNames.Challenge, challenge, ref first);
            _ = sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Writes the §3.3.1 <c>results</c> member of a credential VerificationResponse: the validFrom, validUntil,
    /// credentialSchema, credentialStatus and proof sub-results <see cref="AppendCredentialResultsObject"/> writes.
    /// </summary>
    private static void AppendCredentialResults(
        StringBuilder sb, VcalmVerificationOutcome outcome, ref bool first)
    {
        if(!first)
        {
            _ = sb.Append(',');
        }

        _ = sb.Append('"');
        JsonAppender.AppendEscapedString(sb, VcalmParameterNames.Results);
        _ = sb.Append("\":");
        AppendCredentialResultsObject(sb, outcome);

        first = false;
    }


    /// <summary>
    /// Writes the §3.3.1 <c>results</c> object value, reused by <see cref="AppendPresentationResults"/> for each
    /// per-credential result of a §3.3.2 response.
    /// </summary>
    private static void AppendCredentialResultsObject(StringBuilder sb, VcalmVerificationOutcome outcome)
    {
        _ = sb.Append('{');
        bool resultsFirst = true;

        if(outcome.ValidFrom is not null)
        {
            AppendInputResultField(sb, VcalmParameterNames.ValidFrom, outcome.ValidFrom, ref resultsFirst);
        }

        if(outcome.ValidUntil is not null)
        {
            AppendInputResultField(sb, VcalmParameterNames.ValidUntil, outcome.ValidUntil, ref resultsFirst);
        }

        //§3.3.1 results.credentialSchema[]: one {verified, input} item per evaluated credentialSchema
        //object; the member is always present per the results shape and empty when the credential
        //declares no schemas or the schema seams are unwired.
        AppendSchemaResultsField(sb, VcalmParameterNames.CredentialSchema, outcome.SchemaResults, ref resultsFirst);
        AppendStatusResultsField(sb, VcalmParameterNames.CredentialStatus, outcome.StatusResults, ref resultsFirst);
        AppendProofResultsArrayField(sb, VcalmParameterNames.Proof, outcome.ProofResults, ref resultsFirst);

        _ = sb.Append('}');
    }


    /// <summary>
    /// Writes the §3.3.2 <c>results</c> object: <c>presentation</c> with its <c>challenge</c>, <c>domain</c>,
    /// <c>holder</c> and <c>proof[]</c> sub-results, and <c>credentials[]</c> with one §3.3.1-shaped result per
    /// contained credential.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verify-presentation">VCALM §3.3.2</see> defines
    /// <c>challenge.verified</c> as the "Result of verifying the security challenge across all proofs provided" and
    /// <c>domain.verified</c> as the "Result of verifying the security domain across all proofs provided". Each is
    /// false whenever the presentation proof failed or its own check produced an error among the presentation-level
    /// problems, a challenge the verifier never issued included, so a sub-result never reads true beside its error.
    /// The same clause requires "Checking that the holder in the presentation matches the verification method used
    /// in the presentation's proof", so <c>holder.verified</c> is true only beside a proof that itself verified,
    /// never merely because no challenge or domain was requested of an unproofed presentation.
    /// </remarks>
    /// <param name="sb">The builder receiving the JSON.</param>
    /// <param name="presentationResult">The presentation proof's outcome and bound inputs.</param>
    /// <param name="credentialOutcomes">The contained credentials' outcomes, in presentation order.</param>
    /// <param name="presentationLevelProblems">Every presentation-level ProblemDetail, the endpoint's own checks included.</param>
    /// <param name="first">Whether the receiving object has no earlier member.</param>
    private static void AppendPresentationResults(
        StringBuilder sb,
        VcalmPresentationProofResult presentationResult,
        IReadOnlyList<VcalmVerificationOutcome> credentialOutcomes,
        ImmutableArray<VcalmProblemDetail> presentationLevelProblems,
        ref bool first)
    {
        if(!first)
        {
            _ = sb.Append(',');
        }

        _ = sb.Append('"');
        JsonAppender.AppendEscapedString(sb, VcalmParameterNames.Results);
        _ = sb.Append("\":{");

        bool resultsFirst = true;

        //results.presentation { challenge?, domain?, holder?, proof[] }.
        if(!resultsFirst)
        {
            _ = sb.Append(',');
        }

        _ = sb.Append('"');
        JsonAppender.AppendEscapedString(sb, VcalmParameterNames.Presentation);
        _ = sb.Append("\":{");

        bool presentationFirst = true;
        if(presentationResult.Challenge is not null)
        {
            bool isChallengeVerified = presentationResult.Verified
                && !HasProblemOfType(presentationLevelProblems, VcalmProblemTypes.InvalidChallengeError)
                && !HasProblemOfType(presentationLevelProblems, VcalmProblemTypes.ChallengeNotIssued);
            AppendInputResultField(
                sb,
                VcalmParameterNames.Challenge,
                new VcalmInputResult { Verified = isChallengeVerified, Input = presentationResult.Challenge },
                ref presentationFirst);
        }

        if(presentationResult.Domain is not null)
        {
            bool isDomainVerified = presentationResult.Verified
                && !HasProblemOfType(presentationLevelProblems, VcalmProblemTypes.InvalidDomainError);
            AppendInputResultField(
                sb,
                VcalmParameterNames.Domain,
                new VcalmInputResult { Verified = isDomainVerified, Input = presentationResult.Domain },
                ref presentationFirst);
        }

        if(presentationResult.Holder is not null)
        {
            //§3.3.2 "matches the verification method used in the presentation's proof" (see the
            //remarks above): true only beside a proof that itself verified.
            bool isHolderVerified = presentationResult.ProofResults is [{ Verified: true }, ..];
            AppendInputResultField(
                sb,
                VcalmParameterNames.Holder,
                new VcalmInputResult { Verified = isHolderVerified, Input = presentationResult.Holder },
                ref presentationFirst);
        }

        AppendProofResultsArrayField(sb, VcalmParameterNames.Proof, presentationResult.ProofResults, ref presentationFirst);

        _ = sb.Append('}');
        resultsFirst = false;

        //results.credentials[]: one §3.3.1 VerificationResponse-shaped result per contained credential.
        if(!resultsFirst)
        {
            _ = sb.Append(',');
        }

        _ = sb.Append('"');
        JsonAppender.AppendEscapedString(sb, VcalmParameterNames.Credentials);
        _ = sb.Append("\":[");

        for(int i = 0; i < credentialOutcomes.Count; ++i)
        {
            if(i > 0)
            {
                _ = sb.Append(',');
            }

            VcalmVerificationOutcome credentialOutcome = credentialOutcomes[i];
            _ = sb.Append('{');
            bool credentialFirst = true;
            JsonAppender.AppendBoolField(sb, VcalmParameterNames.Verified, credentialOutcome.Verified, ref credentialFirst);
            AppendProblemDetailsArray(sb, VcalmParameterNames.ProblemDetails, credentialOutcome.ProblemDetails, ref credentialFirst);

            if(!credentialFirst)
            {
                _ = sb.Append(',');
            }

            _ = sb.Append('"');
            JsonAppender.AppendEscapedString(sb, VcalmParameterNames.Results);
            _ = sb.Append("\":");
            AppendCredentialResultsObject(sb, credentialOutcome);

            _ = sb.Append('}');
        }

        _ = sb.Append(']');

        _ = sb.Append('}');
        first = false;
    }


    /// <summary>
    /// Whether <paramref name="problems"/> carries a ProblemDetail of exactly <paramref name="type"/>, so a
    /// §3.3.2 per-check sub-result written by <see cref="AppendPresentationResults"/> is false beside its own
    /// check's error.
    /// </summary>
    /// <param name="problems">The presentation-level §3.8 ProblemDetails.</param>
    /// <param name="type">The problem type identifying the specific check.</param>
    /// <returns><see langword="true"/> when a ProblemDetail of <paramref name="type"/> is present.</returns>
    private static bool HasProblemOfType(ImmutableArray<VcalmProblemDetail> problems, string type)
    {
        foreach(VcalmProblemDetail problem in problems)
        {
            if(string.Equals(problem.Type, type, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>Writes one §3.3.1 per-step sub-result member, an object of the form <c>{ verified, input }</c>.</summary>
    private static void AppendInputResultField(
        StringBuilder sb, string key, VcalmInputResult result, ref bool first)
    {
        if(!first)
        {
            _ = sb.Append(',');
        }

        _ = sb.Append('"');
        JsonAppender.AppendEscapedString(sb, key);
        _ = sb.Append("\":{");

        bool resultFirst = true;
        JsonAppender.AppendBoolField(sb, VcalmParameterNames.Verified, result.Verified, ref resultFirst);
        JsonAppender.AppendStringField(sb, VcalmParameterNames.Input, result.Input, ref resultFirst);

        _ = sb.Append('}');
        first = false;
    }


    /// <summary>
    /// Writes a §3.3.1 / §3.3.2 array member of proof sub-results, such as <c>results.proof[]</c>:
    /// each item is <c>{ verified, input }</c> where <c>input</c> is the proof examined, echoed
    /// through <see cref="AppendProofInputField"/>.
    /// </summary>
    private static void AppendProofResultsArrayField(
        StringBuilder sb, string key, IReadOnlyList<VcalmProofResult> results, ref bool first)
    {
        if(!first)
        {
            _ = sb.Append(',');
        }

        _ = sb.Append('"');
        JsonAppender.AppendEscapedString(sb, key);
        _ = sb.Append("\":[");

        for(int i = 0; i < results.Count; ++i)
        {
            if(i > 0)
            {
                _ = sb.Append(',');
            }

            _ = sb.Append('{');
            bool resultFirst = true;
            JsonAppender.AppendBoolField(sb, VcalmParameterNames.Verified, results[i].Verified, ref resultFirst);
            AppendProofInputField(sb, results[i].Proof, ref resultFirst);
            _ = sb.Append('}');
        }

        _ = sb.Append(']');
        first = false;
    }


    /// <summary>
    /// Writes the <c>input</c> member of one §3.3.1 / §3.3.2 proof sub-result: the proof's own
    /// received wire JSON (<see cref="DataIntegrityProof.ReceivedProofJson"/>) when the proof was
    /// read from a wire document, so the object echoed is byte-faithful to what the caller sent;
    /// otherwise a reconstruction from the proof's typed members, for a proof built in memory.
    /// </summary>
    private static void AppendProofInputField(StringBuilder sb, DataIntegrityProof proof, ref bool first)
    {
        if(proof.ReceivedProofJson is { Length: > 0 } receivedProofJson)
        {
            JsonAppender.AppendRawField(sb, VcalmParameterNames.Input, receivedProofJson, ref first);

            return;
        }

        if(!first)
        {
            _ = sb.Append(',');
        }

        _ = sb.Append('"');
        JsonAppender.AppendEscapedString(sb, VcalmParameterNames.Input);
        _ = sb.Append("\":");
        AppendProofObject(sb, proof);

        first = false;
    }


    /// <summary>
    /// Reconstructs a proof's members as a JSON object — the fallback <c>input</c> shape for a proof
    /// with no <see cref="DataIntegrityProof.ReceivedProofJson"/> (one built in memory rather than
    /// read from the wire, or an empty received value). Members absent on <paramref name="proof"/> are
    /// omitted, in the order <c>DataIntegrityProofConverter.Write</c> emits them. An embedded
    /// <c>verificationMethod</c> object reduces to its identifying <c>id</c>, since reconstructing the
    /// full embedded object would need a JSON writer this library keeps out of <c>Verifiable.Vcalm</c>.
    /// </summary>
    private static void AppendProofObject(StringBuilder sb, DataIntegrityProof proof)
    {
        _ = sb.Append('{');
        bool proofFirst = true;

        if(proof.Id is not null)
        {
            JsonAppender.AppendStringField(sb, VcalmParameterNames.Id, proof.Id, ref proofFirst);
        }

        JsonAppender.AppendStringField(sb, VcalmParameterNames.Type, proof.Type, ref proofFirst);

        if(proof.Cryptosuite is not null)
        {
            JsonAppender.AppendStringField(sb, VcalmParameterNames.Cryptosuite, proof.Cryptosuite.CryptosuiteName, ref proofFirst);
        }

        if(proof.Created is not null)
        {
            JsonAppender.AppendStringField(sb, VcalmParameterNames.Created, proof.Created, ref proofFirst);
        }

        if(proof.Expires is not null)
        {
            JsonAppender.AppendStringField(sb, VcalmParameterNames.Expires, proof.Expires, ref proofFirst);
        }

        if(proof.VerificationMethod?.Id is { } verificationMethodId)
        {
            JsonAppender.AppendStringField(sb, VcalmParameterNames.VerificationMethod, verificationMethodId, ref proofFirst);
        }

        if(proof.ProofPurpose is not null)
        {
            JsonAppender.AppendStringField(sb, VcalmParameterNames.ProofPurpose, proof.ProofPurpose, ref proofFirst);
        }

        if(proof.ProofValue is not null)
        {
            JsonAppender.AppendStringField(sb, VcalmParameterNames.ProofValue, proof.ProofValue, ref proofFirst);
        }

        if(proof.Domain is { Count: 1 } singleDomain)
        {
            JsonAppender.AppendStringField(sb, VcalmParameterNames.Domain, singleDomain[0], ref proofFirst);
        }
        else if(proof.Domain is { Count: > 1 } domains)
        {
            JsonAppender.AppendStringArrayField(sb, VcalmParameterNames.Domain, domains, ref proofFirst);
        }

        if(proof.Challenge is not null)
        {
            JsonAppender.AppendStringField(sb, VcalmParameterNames.Challenge, proof.Challenge, ref proofFirst);
        }

        if(proof.Nonce is not null)
        {
            JsonAppender.AppendStringField(sb, VcalmParameterNames.Nonce, proof.Nonce, ref proofFirst);
        }

        if(proof.PreviousProof is not null)
        {
            JsonAppender.AppendStringField(sb, VcalmParameterNames.PreviousProof, proof.PreviousProof, ref proofFirst);
        }

        _ = sb.Append('}');
    }


    /// <summary>
    /// Appends the §3.3.1 <c>results.credentialSchema[]</c> array: each item is
    /// <c>{verified, input}</c> where <c>input</c> is the examined <c>credentialSchema</c> object's
    /// identifying members.
    /// </summary>
    /// <param name="sb">The builder receiving the JSON.</param>
    /// <param name="key">The array member's key.</param>
    /// <param name="results">The per-entry schema results, in entry order.</param>
    /// <param name="first">Whether the receiving object has no earlier member.</param>
    private static void AppendSchemaResultsField(
        StringBuilder sb, string key, IReadOnlyList<VcalmSchemaResult> results, ref bool first)
    {
        if(!first)
        {
            _ = sb.Append(',');
        }

        _ = sb.Append('"');
        JsonAppender.AppendEscapedString(sb, key);
        _ = sb.Append("\":[");

        for(int i = 0; i < results.Count; ++i)
        {
            if(i > 0)
            {
                _ = sb.Append(',');
            }

            _ = sb.Append('{');
            bool resultFirst = true;
            JsonAppender.AppendBoolField(sb, VcalmParameterNames.Verified, results[i].Verified, ref resultFirst);

            _ = sb.Append(",\"");
            JsonAppender.AppendEscapedString(sb, VcalmParameterNames.Input);
            _ = sb.Append("\":{");
            bool inputFirst = true;
            JsonAppender.AppendStringField(sb, VcalmParameterNames.Id, results[i].Id, ref inputFirst);
            JsonAppender.AppendStringField(sb, VcalmParameterNames.Type, results[i].Type, ref inputFirst);
            _ = sb.Append('}');

            _ = sb.Append('}');
        }

        _ = sb.Append(']');
        first = false;
    }


    /// <summary>
    /// Writes the §3.3.1 <c>results.credentialStatus[]</c> array: each item is
    /// <c>{ value, verified, input }</c> where <c>input</c> is the examined status entry's identifying
    /// members (<c>id</c>, <c>type</c>, <c>statusPurpose</c>, <c>statusListIndex</c>,
    /// <c>statusListCredential</c>), not every member <see cref="CredentialStatus"/> carries.
    /// </summary>
    private static void AppendStatusResultsField(
        StringBuilder sb, string key, IReadOnlyList<VcalmStatusResult> results, ref bool first)
    {
        if(!first)
        {
            _ = sb.Append(',');
        }

        _ = sb.Append('"');
        JsonAppender.AppendEscapedString(sb, key);
        _ = sb.Append("\":[");

        for(int i = 0; i < results.Count; ++i)
        {
            if(i > 0)
            {
                _ = sb.Append(',');
            }

            _ = sb.Append('{');
            bool resultFirst = true;
            JsonAppender.AppendInt64Field(sb, VcalmParameterNames.Value, results[i].Value, ref resultFirst);
            JsonAppender.AppendBoolField(sb, VcalmParameterNames.Verified, results[i].Verified, ref resultFirst);
            AppendCredentialStatusInputField(sb, results[i].Entry, ref resultFirst);
            _ = sb.Append('}');
        }

        _ = sb.Append(']');
        first = false;
    }


    /// <summary>
    /// Writes the <c>input</c> member of one §3.3.1 <c>results.credentialStatus[]</c> item: the
    /// examined <see cref="CredentialStatus"/> entry's own members (<c>id</c>, <c>type</c>,
    /// <c>statusPurpose</c>, <c>statusListIndex</c>, <c>statusListCredential</c>), each present only
    /// when <paramref name="entry"/> carries it.
    /// </summary>
    private static void AppendCredentialStatusInputField(StringBuilder sb, CredentialStatus entry, ref bool first)
    {
        if(!first)
        {
            _ = sb.Append(',');
        }

        _ = sb.Append('"');
        JsonAppender.AppendEscapedString(sb, VcalmParameterNames.Input);
        _ = sb.Append("\":{");

        bool entryFirst = true;
        if(entry.Id is not null)
        {
            JsonAppender.AppendStringField(sb, VcalmParameterNames.Id, entry.Id, ref entryFirst);
        }

        JsonAppender.AppendStringField(sb, VcalmParameterNames.Type, entry.Type, ref entryFirst);

        if(entry.StatusPurpose is not null)
        {
            JsonAppender.AppendStringField(sb, VcalmParameterNames.StatusPurpose, entry.StatusPurpose, ref entryFirst);
        }

        if(entry.StatusListIndex is not null)
        {
            JsonAppender.AppendStringField(sb, VcalmParameterNames.StatusListIndex, entry.StatusListIndex, ref entryFirst);
        }

        if(entry.StatusListCredential is not null)
        {
            JsonAppender.AppendStringField(sb, VcalmParameterNames.StatusListCredential, entry.StatusListCredential, ref entryFirst);
        }

        _ = sb.Append('}');
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
            _ = sb.Append(',');
        }

        _ = sb.Append('"');
        JsonAppender.AppendEscapedString(sb, key);
        _ = sb.Append("\":[");

        for(int i = 0; i < problems.Length; ++i)
        {
            if(i > 0)
            {
                _ = sb.Append(',');
            }

            VcalmProblemDetail problem = problems[i];
            _ = sb.Append('{');
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

            _ = sb.Append('}');
        }

        _ = sb.Append(']');
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
            _ = sb.Append('{');
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

            _ = sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }
}
