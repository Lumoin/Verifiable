using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;

namespace Verifiable.Vcalm;

/// <summary>
/// The VCALM 1.0 §3.2.1 issuance orchestration: it COMPOSES the library's tested Data Integrity sign
/// surface (<see cref="CredentialDataIntegrityExtensions.SignAsync"/>, W3C VC Data Integrity §4.2 Add
/// Proof) to secure a credential with the instance's one-or-more proof descriptors, applying the
/// §3.2.1 existing-proof configuration. It does not re-roll cryptography: the cryptosuite-specific
/// seams flow in on <see cref="VcalmCredentialIssuance"/>.
/// </summary>
/// <remarks>
/// §3.2.1: "If a use case requires an issuer instance to attach multiple proofs … the instance MUST
/// attach all of these proofs in response to a single call." This service applies every descriptor in
/// <see cref="VcalmCredentialIssuance.SigningDescriptors"/> within one call. The multi-descriptor
/// proofs are appended in list order as a §2.1.2 proof chain (each <see cref="SignAsync"/> append
/// chains onto the prior via <c>previousProof</c>); the caller-supplied existing-proof case is handled
/// per <see cref="VcalmCredentialIssuance.ExistingProofHandling"/>.
/// </remarks>
[DebuggerDisplay("VcalmCredentialIssuanceService")]
public static class VcalmCredentialIssuanceService
{
    /// <summary>
    /// Secures <paramref name="credential"/> with the instance's proof descriptors and returns the
    /// secured credential, or a failure when the §3.2.1 existing-proof configuration rejects a
    /// pre-proofed input.
    /// </summary>
    /// <param name="credential">The unsecured (or caller-pre-proofed) credential to secure.</param>
    /// <param name="hasExistingProof">Whether the caller supplied <c>credential.proof</c> (§3.2.1 existing-proof case).</param>
    /// <param name="issuance">The instance's signing configuration.</param>
    /// <param name="proofCreated">The timestamp written into each proof's <c>created</c> member.</param>
    /// <param name="context">The per-request context threaded to the canonicalizer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<VcalmIssuanceResult> IssueAsync(
        VerifiableCredential credential,
        bool hasExistingProof,
        VcalmCredentialIssuance issuance,
        DateTime proofCreated,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(issuance);
        ArgumentNullException.ThrowIfNull(context);

        //§3.2.1 Error Handling: an instance configured to only accept credentials without existing
        //proofs returns an error when a pre-proofed credential is provided.
        if(hasExistingProof && issuance.ExistingProofHandling == VcalmExistingProofHandling.Error)
        {
            return VcalmIssuanceResult.ExistingProofRejected();
        }

        //§3.2.1 Proof Sets: the new proofs exist in parallel with the caller's existing ones with no
        //chain binding. SignAsync chains onto existing proofs, so the set is built by securing the
        //credential WITHOUT its existing proofs (each descriptor over the bare credential) and then
        //placing every resulting proof side by side, each with no previousProof link.
        bool isProofSet =
            hasExistingProof && issuance.ExistingProofHandling == VcalmExistingProofHandling.ProofSet;

        DataIntegritySecuredCredential secured = isProofSet
            ? await SignAsProofSetAsync(credential, issuance, proofCreated, context, cancellationToken).ConfigureAwait(false)
            : await SignAsProofChainAsync(credential, issuance, proofCreated, context, cancellationToken).ConfigureAwait(false);

        return VcalmIssuanceResult.Issued(secured);
    }


    //§3.2.1 Proof Chain (and the no-existing-proof default): apply each descriptor in order over the
    //running credential. SignAsync appends a chained proof when the credential already carries proofs
    //(its previousProof references the last proof's id), so the result is a single linear chain that
    //the §2.1.2 verifier walks — whether the existing proofs came from the caller or from a prior
    //descriptor in this same call.
    private static async ValueTask<DataIntegritySecuredCredential> SignAsProofChainAsync(
        VerifiableCredential credential,
        VcalmCredentialIssuance issuance,
        DateTime proofCreated,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        VerifiableCredential running = credential;
        foreach(VcalmProofDescriptor descriptor in issuance.SigningDescriptors)
        {
            running = await SignWithDescriptorAsync(
                running, descriptor, issuance.MemoryPool, proofCreated, context, cancellationToken).ConfigureAwait(false);
        }

        return (DataIntegritySecuredCredential)running;
    }


    //§3.2.1 Proof Set: secure the credential's claims with each descriptor independently, then gather
    //every produced proof into one parallel set with the caller's existing proofs, none carrying a
    //previousProof link. Each descriptor signs over the bare (existing-proof-stripped) credential so
    //the set members are independent assertions over the same claims (§2.1.1).
    private static async ValueTask<DataIntegritySecuredCredential> SignAsProofSetAsync(
        VerifiableCredential credential,
        VcalmCredentialIssuance issuance,
        DateTime proofCreated,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        List<DataIntegrityProof> proofSet = [];

        //Preserve the caller's existing proofs as parallel set members (§3.2.1: "first converting any
        //existing single proof to a list if necessary").
        if(credential is DataIntegritySecuredCredential existing && existing.Proof is { Count: > 0 } existingProofs)
        {
            proofSet.AddRange(existingProofs);
        }

        VerifiableCredential bare = StripProofs(credential);
        foreach(VcalmProofDescriptor descriptor in issuance.SigningDescriptors)
        {
            DataIntegritySecuredCredential signed = await SignWithDescriptorAsync(
                bare, descriptor, issuance.MemoryPool, proofCreated, context, cancellationToken).ConfigureAwait(false);

            //A descriptor over the bare credential yields a single proof; it joins the set with no
            //chain link (a set member, §2.1.1, not a §2.1.2 chain link).
            if(signed.Proof is { Count: > 0 } produced)
            {
                DataIntegrityProof setMember = produced[^1];
                setMember.PreviousProof = null;
                proofSet.Add(setMember);
            }
        }

        DataIntegritySecuredCredential result = StripProofs(credential) as DataIntegritySecuredCredential
            ?? ToSecured(StripProofs(credential));
        result.Proof = proofSet;

        return result;
    }


    private static async ValueTask<DataIntegritySecuredCredential> SignWithDescriptorAsync(
        VerifiableCredential credential,
        VcalmProofDescriptor descriptor,
        System.Buffers.MemoryPool<byte> memoryPool,
        DateTime proofCreated,
        ExchangeContext context,
        CancellationToken cancellationToken) =>
        await credential.SignAsync(
            descriptor.PrivateKey,
            descriptor.VerificationMethodId,
            descriptor.Cryptosuite,
            proofCreated,
            descriptor.Canonicalize,
            descriptor.ContextResolver,
            descriptor.EncodeProofValue,
            descriptor.SerializeCredential,
            descriptor.DeserializeCredential,
            descriptor.SerializeProofOptions,
            descriptor.Encoder,
            descriptor.ComputeDigest,
            memoryPool,
            context,
            cancellationToken).ConfigureAwait(false);


    //Returns a credential view carrying the same claims and metadata but no proofs — the §2.1.1
    //"unsecured document" each proof-set member is independently computed over.
    private static VerifiableCredential StripProofs(VerifiableCredential credential)
    {
        if(credential is not DataIntegritySecuredCredential)
        {
            return credential;
        }

        return ToSecured(credential);
    }


    //Copies the credential's claim and metadata members into a fresh DataIntegritySecuredCredential
    //with no proof attached. The proof-set path needs a secured-typed, proof-free instance to carry
    //the gathered set.
    private static DataIntegritySecuredCredential ToSecured(VerifiableCredential credential) =>
        new()
        {
            Context = credential.Context,
            Id = credential.Id,
            Type = credential.Type,
            Name = credential.Name,
            Description = credential.Description,
            Issuer = credential.Issuer,
            CredentialSubject = credential.CredentialSubject,
            ValidFrom = credential.ValidFrom,
            ValidUntil = credential.ValidUntil,
            CredentialStatus = credential.CredentialStatus,
            CredentialSchema = credential.CredentialSchema,
            RelatedResource = credential.RelatedResource,
            RefreshService = credential.RefreshService,
            TermsOfUse = credential.TermsOfUse,
            Evidence = credential.Evidence,
            AdditionalData = credential.AdditionalData,
            Proof = null
        };
}


/// <summary>
/// The outcome of a VCALM 1.0 §3.2.1 issuance: the secured credential on success, or the
/// existing-proof rejection (§3.2.1 400) when the instance is configured to reject pre-proofed input.
/// </summary>
[DebuggerDisplay("VcalmIssuanceResult IsSuccess={IsSuccess}")]
public sealed record VcalmIssuanceResult
{
    /// <summary>Whether the credential was secured.</summary>
    public required bool IsSuccess { get; init; }

    /// <summary>The secured credential when <see cref="IsSuccess"/> is set; otherwise <see langword="null"/>.</summary>
    public DataIntegritySecuredCredential? SecuredCredential { get; init; }


    /// <summary>Creates a successful issuance result.</summary>
    public static VcalmIssuanceResult Issued(DataIntegritySecuredCredential securedCredential)
    {
        ArgumentNullException.ThrowIfNull(securedCredential);

        return new VcalmIssuanceResult { IsSuccess = true, SecuredCredential = securedCredential };
    }


    /// <summary>
    /// Creates the §3.2.1 existing-proof rejection (the instance is configured to only accept
    /// credentials without existing proofs → 400).
    /// </summary>
    public static VcalmIssuanceResult ExistingProofRejected() =>
        new() { IsSuccess = false };
}
