using System;
using System.Buffers;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using Verifiable.Core;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Resolvers;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;

namespace Verifiable.Vcalm;

/// <summary>
/// The VCALM 1.0 §3.3 verification orchestration: it COMPOSES the library's tested Data Integrity
/// verify surface (<see cref="CredentialDataIntegrityExtensions.VerifyAsync"/> /
/// <see cref="PresentationDataIntegrityExtensions.VerifyAsync"/>, W3C VC Data Integrity §4.3) and
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
[DebuggerDisplay("VcalmVerificationService")]
public static class VcalmVerificationService
{
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

        ImmutableArray<VcalmProblemDetail>.Builder problems = ImmutableArray.CreateBuilder<VcalmProblemDetail>();
        ImmutableArray<VcalmInputResult>.Builder proofResults = ImmutableArray.CreateBuilder<VcalmInputResult>();

        //§3.8.1: a missing / unverifiable proof is a cryptographic ERROR. A credential with no
        //proof cannot be cryptographically authentic, so it flips verified to false.
        List<DataIntegrityProof>? proofs = credential.Proof;
        if(proofs is null || proofs.Count == 0)
        {
            problems.Add(VcalmProblemDetail.Error(
                VcalmProblemTypes.CryptographicSecurityError,
                "CRYPTOGRAPHIC_SECURITY_ERROR",
                "The credential carries no Data Integrity proof to verify."));
        }
        else
        {
            bool isCredentialProofValid = await VerifyCredentialProofAsync(
                credential, verification, context, cancellationToken).ConfigureAwait(false);

            //§3.3.1 results.proof[]: one entry per proof, input is the proof's verificationMethod.
            //The chain verifies as a whole (Data Integrity §2.1.2); a single failing link fails the
            //whole credential, which the per-entry verified mirrors.
            foreach(DataIntegrityProof proof in proofs)
            {
                proofResults.Add(new VcalmInputResult
                {
                    Verified = isCredentialProofValid,
                    Input = proof.VerificationMethod?.Id ?? string.Empty
                });
            }

            if(!isCredentialProofValid)
            {
                problems.Add(VcalmProblemDetail.Error(
                    VcalmProblemTypes.CryptographicSecurityError,
                    "CRYPTOGRAPHIC_SECURITY_ERROR",
                    "The cryptographic security mechanism could not be verified. This is likely due "
                    + "to a malformed proof, an unresolvable verificationMethod, or an invalid signature."));
            }
        }

        //§3.8.1: validity-period ProblemDetails are WARNINGs — they do not flip verified.
        VcalmInputResult? validFromResult = EvaluateValidFrom(credential.ValidFrom, now, problems);
        VcalmInputResult? validUntilResult = EvaluateValidUntil(credential.ValidUntil, now, problems);

        //§3.8.1: a status ProblemDetail is a WARNING ("Warnings are ProblemDetails relating to status
        //and validity periods"), so a revoked / suspended status does NOT flip verified. A credential
        //with no credentialStatus contributes no status results and no warning.
        ImmutableArray<VcalmStatusResult> statusResults = await EvaluateStatusAsync(
            credential, resolveStatusList, now, problems, context, cancellationToken).ConfigureAwait(false);

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
            ProofResults = proofResults.ToImmutable(),
            ProblemDetails = problems.ToImmutable()
        };
    }


    //§3.3.1 status check: for each BitstringStatusListEntry the credential carries, resolve the
    //referenced status list through the seam, read the bit, and classify per §3.8.1. A set bit
    //(revoked / suspended) is a status WARNING — it populates StatusResults with verified:false but
    //does NOT add an error, so it does not flip the overall verified. A credential with no
    //credentialStatus, an unwired resolver, or a list that cannot be resolved yields an empty result
    //set and no warning (an undeterminable status is not asserted as revoked).
    private static async ValueTask<ImmutableArray<VcalmStatusResult>> EvaluateStatusAsync(
        DataIntegritySecuredCredential credential,
        ResolveVcalmStatusListDelegate? resolveStatusList,
        DateTimeOffset now,
        ImmutableArray<VcalmProblemDetail>.Builder problems,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        List<CredentialStatus>? statuses = credential.CredentialStatus;
        if(resolveStatusList is null || statuses is null || statuses.Count == 0)
        {
            return ImmutableArray<VcalmStatusResult>.Empty;
        }

        ImmutableArray<VcalmStatusResult>.Builder results = ImmutableArray.CreateBuilder<VcalmStatusResult>();
        foreach(CredentialStatus status in statuses)
        {
            if(!TryMapStatusEntry(status, out BitstringStatusListEntry? entry))
            {
                continue;
            }

            //§3.8 process-safety boundary: the status resolver dereferences the statusListCredential
            //(through the SSRF-policed OutboundFetch when remote), verifies its proof, and decodes the
            //bitstring — all throw-prone over attacker-influenced input — and GetStatus then enforces the
            //§3.2 purpose / window / length / range checks. A throw from EITHER must not become a 500:
            //§3.8.1 makes status a WARNING, so an undeterminable status yields no result and no warning
            //(it never flips verified), matching the documented null-resolution behaviour.
            VcalmResolvedStatusList? resolved = null;
            try
            {
                resolved = await resolveStatusList(entry, context, cancellationToken).ConfigureAwait(false);
                if(resolved is null)
                {
                    continue;
                }

                BitstringStatusListStatus statusResult = BitstringStatusListValidation.GetStatus(
                    entry, resolved.StatusList, resolved.Purposes, now, resolved.ValidFrom, resolved.ValidUntil);

                results.Add(new VcalmStatusResult
                {
                    Value = statusResult.Status,
                    Verified = statusResult.IsValid,
                    Input = status.Id ?? string.Empty
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
            catch(Exception ex) when(ex is not OperationCanceledException and not OutOfMemoryException)
            {
                //An unresolvable / unverifiable / undecodable status list (or one failing the §3.2
                //purpose / window / length / range checks) cannot establish the status: no result, no
                //warning, never a 500. §3.8.1 status is a warning, so this does not flip verified.
            }
            finally
            {
                resolved?.StatusList.Dispose();
            }
        }

        return results.ToImmutable();
    }


    //Maps the credential's CredentialStatus (a VC-DM 2.0 §4.10 status entry) to the typed Core
    //BitstringStatusListEntry the resolver and validation surface read. Returns false for an entry
    //that is not a BitstringStatusListEntry or whose statusListIndex / statusListCredential is
    //missing or unparseable — such an entry is not a resolvable W3C status reference.
    private static bool TryMapStatusEntry(
        CredentialStatus status, [NotNullWhen(true)] out BitstringStatusListEntry? entry)
    {
        entry = null;

        if(!string.Equals(status.Type, BitstringStatusListConstants.EntryType, StringComparison.Ordinal))
        {
            return false;
        }

        if(string.IsNullOrEmpty(status.StatusListCredential)
            || string.IsNullOrEmpty(status.StatusPurpose)
            || !int.TryParse(status.StatusListIndex, NumberStyles.Integer, CultureInfo.InvariantCulture, out int index))
        {
            return false;
        }

        entry = new BitstringStatusListEntry
        {
            Id = status.Id,
            StatusPurpose = status.StatusPurpose,
            StatusListIndex = index,
            StatusListCredential = status.StatusListCredential
        };

        return true;
    }


    /// <summary>
    /// Verifies one §3.3.2 presentation proof against the expected <paramref name="challenge"/> and
    /// <paramref name="domain"/>, resolving the holder DID through the supplied resolver. Returns the
    /// per-proof result and any §3.8.1 ProblemDetails (a presentation-proof failure is a
    /// cryptographic ERROR). A <see langword="null"/> expected challenge or domain skips that
    /// binding check (the caller did not bind it).
    /// </summary>
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

        ImmutableArray<VcalmProblemDetail>.Builder problems = ImmutableArray.CreateBuilder<VcalmProblemDetail>();

        DataIntegrityProof? proof = presentation.Proof is { Count: > 0 } proofs ? proofs[0] : null;
        if(proof is null)
        {
            problems.Add(VcalmProblemDetail.Error(
                VcalmProblemTypes.CryptographicSecurityError,
                "CRYPTOGRAPHIC_SECURITY_ERROR",
                "The presentation carries no Data Integrity proof to verify."));

            return new VcalmPresentationProofResult
            {
                Verified = false,
                Challenge = expectedChallenge,
                Domain = expectedDomain,
                Holder = presentation.Holder,
                ProofInput = string.Empty,
                ProblemDetails = problems.ToImmutable()
            };
        }

        //§3.8 / §3.8.1 process-safety boundary (mirrors the credential path): a malformed presentation
        //the canonicalizer rejects must surface as a §3.8.1 cryptographic ERROR (verified:false), not a
        //500. Cancellation propagates.
        bool isValid;
        try
        {
            isValid = await VerifyPresentationProofCoreAsync(
                presentation, proof, expectedChallenge, expectedDomain, verification, context, cancellationToken)
                .ConfigureAwait(false);
        }
        catch(Exception ex) when(ex is not OperationCanceledException and not OutOfMemoryException)
        {
            isValid = false;
        }

        if(!isValid)
        {
            problems.Add(VcalmProblemDetail.Error(
                VcalmProblemTypes.CryptographicSecurityError,
                "CRYPTOGRAPHIC_SECURITY_ERROR",
                "The presentation proof could not be verified against the expected challenge, domain, "
                + "and holder verification method."));
        }

        return new VcalmPresentationProofResult
        {
            Verified = isValid,
            Challenge = expectedChallenge,
            Domain = expectedDomain,
            Holder = presentation.Holder,
            ProofInput = proof.VerificationMethod?.Id ?? string.Empty,
            ProblemDetails = problems.ToImmutable()
        };
    }


    //§3.8 / §3.8.1 process-safety boundary: the verification process runs over attacker-controlled
    //credential content and can THROW — a malformed @context the JSON-LD canonicalizer rejects, an
    //undecodable proofValue, an unparseable verificationMethod. §3.8 requires the verifier to "avoid
    //raising errors while performing verification, and instead gather ProblemDetails objects" and to
    //sanitize server errors, and §3.8.1 classifies cryptography / data-model / malformed-context
    //failures as ERRORs (verified:false). So a throw during verification is a §3.8.1 ERROR, never a
    //500. Cancellation is not a verification outcome; it propagates.
    private static async ValueTask<bool> VerifyCredentialProofAsync(
        DataIntegritySecuredCredential credential,
        VcalmCredentialVerification? verification,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        try
        {
            return await VerifyCredentialProofCoreAsync(credential, verification, context, cancellationToken)
                .ConfigureAwait(false);
        }
        catch(Exception ex) when(ex is not OperationCanceledException and not OutOfMemoryException)
        {
            return false;
        }
    }


    //Composes the Core credential verifier. Resolves the issuer DID document from the proof's
    //verificationMethod through the seam's resolver, then runs §4.3 verify. Any null seam, an
    //underivable issuer DID, a resolution failure, or a §4.3 failure all map to "not verified" —
    //fail-closed, since none of those can establish cryptographic authenticity.
    private static async ValueTask<bool> VerifyCredentialProofCoreAsync(
        DataIntegritySecuredCredential credential,
        VcalmCredentialVerification? verification,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        if(verification is null)
        {
            return false;
        }

        DataIntegrityProof? firstProof = credential.Proof?[0];
        string? issuerDid = DeriveControllerDid(credential.Issuer?.Id, firstProof);
        if(issuerDid is null)
        {
            return false;
        }

        DidDocument? document = await ResolveDocumentAsync(
            verification.Resolver, issuerDid, context, cancellationToken).ConfigureAwait(false);
        if(document is null)
        {
            return false;
        }

        //§3.4 ecdsa-sd-2023: a DERIVED proof (the form a holder presents after selective disclosure)
        //carries a CBOR 0xd9 5d 01-tagged proofValue the generic §4.3 verifier cannot reconstruct —
        //it is verified through the cryptosuite-specific derived-proof verifier (W3C VC-DI-ECDSA
        //§3.4.8 verifyDerivedProof). Every other cryptosuite (eddsa-rdfc-2022, eddsa-jcs-2022, and the
        //base/simple Data Integrity algorithm) goes through the generic verifier unchanged.
        if(IsEcdsaSd2023DerivedProof(firstProof, verification))
        {
            //The issuer key is extracted from the same resolved DID document the generic verifier
            //would use — the proof's verificationMethod resolved against the issuer document. An
            //unresolvable / unconvertible method leaves the SD proof unverifiable (verified:false),
            //never wrongly true.
            using PublicKeyMemory? issuerPublicKey = TryExtractIssuerPublicKey(
                document, firstProof, verification.MemoryPool);
            if(issuerPublicKey is null)
            {
                return false;
            }

            return await VerifyEcdsaSd2023DerivedProofAsync(
                credential, verification, issuerPublicKey, context, cancellationToken).ConfigureAwait(false);
        }

        CredentialVerificationResult<DataIntegritySecuredCredential> result = await credential.VerifyAsync(
            document,
            verification.Canonicalize,
            verification.ContextResolver,
            verification.DecodeProofValue,
            verification.SerializeCredential,
            verification.SerializeProofOptions,
            verification.Decoder,
            verification.ComputeDigest,
            verification.MemoryPool,
            context,
            cancellationToken).ConfigureAwait(false);

        return result.IsValid;

        //Determines whether the credential's proof is an ecdsa-sd-2023 DERIVED proof this verifier can
        //selectively-disclosure-verify. A derived proof requires ALL of: the ecdsa-sd-2023 cryptosuite
        //name, the wired SD seams, a u-prefixed base64url multibase proofValue, and a CBOR 0xd9 5d 01
        //derived tag (NOT the 0xd9 5d 00 base tag — a base proof is issuer-held, not presented to a
        //verifier). Any miss leaves the proof on the generic path. This never returns true for a
        //non-derived proof, so it cannot route a non-SD proof to the SD verifier (preserving the
        //no-false-positive property).
        static bool IsEcdsaSd2023DerivedProof(
            DataIntegrityProof? proof,
            VcalmCredentialVerification verification)
        {
            if(proof?.Cryptosuite is null
                || !string.Equals(proof.Cryptosuite.CryptosuiteName, CredentialConstants.Cryptosuites.EcdsaSd2023, StringComparison.Ordinal))
            {
                return false;
            }

            if(verification.ParseDerivedProof is null
                || verification.VerifyDerivedSignature is null
                || verification.SdProofEncoder is null
                || verification.SdProofDecoder is null
                || string.IsNullOrEmpty(proof.ProofValue))
            {
                return false;
            }

            //§3.4 multibase: a u-prefixed base64url value whose CBOR body is 0xd9 5d 01-tagged is a
            //derived proof; the parser throws on a base (0xd9 5d 00) or malformed header, so a base
            //proof is not routed here.
            if(proof.ProofValue![0] != MultibaseAlgorithms.Base64Url)
            {
                return false;
            }

            try
            {
                using DerivedProofValue parsed = verification.ParseDerivedProof(
                    proof.ProofValue, verification.SdProofDecoder, verification.SdProofEncoder, verification.MemoryPool);

                return true;
            }
            catch(FormatException)
            {
                return false;
            }
        }
    }


    //Extracts the issuer's public key from the resolved DID document: the proof's verificationMethod
    //resolved to a method, then converted to a PublicKeyMemory through the project's crypto-infra
    //conversion. Returns null when the verificationMethod is missing, unresolvable, or carries a key
    //format the converter cannot read — none of which can anchor the issuer signature.
    private static PublicKeyMemory? TryExtractIssuerPublicKey(
        DidDocument document, DataIntegrityProof? proof, MemoryPool<byte> memoryPool)
    {
        string? verificationMethodId = proof?.VerificationMethod?.Id;
        if(string.IsNullOrEmpty(verificationMethodId))
        {
            return null;
        }

        VerificationMethod? verificationMethod = document.ResolveVerificationMethodReference(verificationMethodId);
        if(verificationMethod is null)
        {
            return null;
        }

        try
        {
            return verificationMethod.ToPublicKeyMemory(memoryPool);
        }
        catch(Exception exception) when(exception is ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }


    //Runs the ecdsa-sd-2023 derived-proof verifier (W3C VC-DI-ECDSA §3.4.8) and maps its verdict to
    //the §3.8.1 model: a verify failure is a CRYPTOGRAPHIC_SECURITY_ERROR (verified:false), a success
    //asserts no error (verified:true). The verifier reconstructs the issuer's base signature over the
    //disclosed mandatory statements and checks each disclosed-statement signature under the embedded
    //ephemeral key — it never returns true for a tampered derived credential, so the no-false-positive
    //property holds. The issuer key is the same DID document the verifier already resolved.
    private static async ValueTask<bool> VerifyEcdsaSd2023DerivedProofAsync(
        DataIntegritySecuredCredential credential,
        VcalmCredentialVerification verification,
        PublicKeyMemory issuerPublicKey,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        CredentialVerificationResult<DataIntegritySecuredCredential> result = await credential.VerifyDerivedProofAsync(
            issuerPublicKey,
            verification.VerifyDerivedSignature!,
            verification.ParseDerivedProof!,
            verification.Canonicalize,
            verification.ContextResolver,
            verification.SerializeCredential,
            verification.SerializeProofOptions,
            verification.SdProofEncoder!,
            verification.SdProofDecoder!,
            verification.MemoryPool,
            context,
            cancellationToken).ConfigureAwait(false);

        return result.IsValid;
    }


    //Composes the Core presentation verifier. The presentation proof's verificationMethod names the
    //holder key; the holder DID is the presentation's holder member, else the base DID of that
    //verificationMethod. A null challenge/domain expectation is satisfied by passing the proof's own
    //value, so the §4.3 binding check passes for that dimension (the caller did not constrain it).
    private static async ValueTask<bool> VerifyPresentationProofCoreAsync(
        DataIntegritySecuredPresentation presentation,
        DataIntegrityProof proof,
        string? expectedChallenge,
        string? expectedDomain,
        VcalmCredentialVerification? verification,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        if(verification is null)
        {
            return false;
        }

        string? holderDid = DeriveControllerDid(presentation.Holder, proof);
        if(holderDid is null)
        {
            return false;
        }

        DidDocument? document = await ResolveDocumentAsync(
            verification.Resolver, holderDid, context, cancellationToken).ConfigureAwait(false);
        if(document is null)
        {
            return false;
        }

        //The Core verifier requires non-empty expectations. When the caller did not bind a value,
        //the proof's own value is passed so that dimension's set-equality check is a no-op — the
        //binding is enforced only for the dimensions the caller actually constrained.
        string challenge = string.IsNullOrEmpty(expectedChallenge) ? proof.Challenge ?? string.Empty : expectedChallenge;
        string domain = string.IsNullOrEmpty(expectedDomain)
            ? (proof.Domain is { Count: > 0 } proofDomain ? proofDomain[0] : string.Empty)
            : expectedDomain;

        //A proof with neither a bound nor a present challenge/domain cannot satisfy the Core
        //verifier's non-empty-argument contract; treat it as not verified rather than throwing.
        if(string.IsNullOrEmpty(challenge) || string.IsNullOrEmpty(domain))
        {
            return false;
        }

        CredentialVerificationResult<DataIntegritySecuredPresentation> result = await presentation.VerifyAsync(
            document,
            challenge,
            domain,
            verification.Canonicalize,
            verification.ContextResolver,
            verification.DecodeProofValue,
            verification.SerializePresentation,
            verification.SerializeProofOptions,
            verification.Decoder,
            verification.ComputeDigest,
            verification.MemoryPool,
            context,
            cancellationToken).ConfigureAwait(false);

        return result.IsValid;
    }


    //Resolves a DID to its document through the library's resolver seam, threading the context so a
    //remote did:web controller is fetched under the context's SSRF OutboundFetch policy. A
    //non-document result (resolution failure, or a method that yields a URL the caller must fetch)
    //cannot anchor the controller key.
    private static async ValueTask<DidDocument?> ResolveDocumentAsync(
        DidResolver resolver,
        string did,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        DidResolutionResult resolution = await resolver.ResolveAsync(
            did, context, options: null, cancellationToken).ConfigureAwait(false);

        return resolution.IsSuccessful ? resolution.Document : null;
    }


    //The controller DID: the explicit controller id (issuer.id / holder) when present, else the
    //base DID of the proof's verificationMethod DID URL — the DID the verificationMethod key lives
    //under. Returns null when neither names a resolvable DID.
    private static string? DeriveControllerDid(string? explicitController, DataIntegrityProof? proof)
    {
        if(!string.IsNullOrEmpty(explicitController) && DidUrl.TryParseAbsolute(explicitController, out _))
        {
            return explicitController;
        }

        string? verificationMethodId = proof?.VerificationMethod?.Id;
        if(verificationMethodId is not null && DidUrl.TryParseAbsolute(verificationMethodId, out DidUrl? parsed))
        {
            return parsed.BaseDid;
        }

        return null;
    }


    //§3.8.1: validFrom in the future is a validity-period WARNING (recoverable; does not flip
    //verified). The result's verified is false when the window is not yet open, true otherwise.
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


    //§3.8.1: validUntil in the past is a validity-period WARNING (recoverable; does not flip
    //verified). The result's verified is false when the window has closed, true otherwise.
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
