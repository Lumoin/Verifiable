using Verifiable.Cryptography.Pki;

namespace Verifiable.Cryptography;

/// <summary>
/// A verification provenance whose identity a typed gate actually checked against the value it accompanies.
/// </summary>
/// <remarks>
/// <para>
/// <strong>What the boundary is, stated exactly.</strong> The constructor is <see langword="private"/> and the
/// four producers below are <see langword="internal"/>, so no <see cref="BoundProvenance"/> producer and neither
/// <see cref="Verified{T}"/> mint is reachable BY COMPILED REFERENCE from outside the assemblies this one names in
/// <c>InternalsVisibleTo</c>. Two caveats bound that claim, and neither is closed here because neither is closable
/// by any in-process capability design: the grants are simple-name only (this assembly is not strong-named), so an
/// assembly that merely CLAIMS one of those names is inside the boundary as far as the CLR is concerned; and
/// <c>BindingFlags.NonPublic</c> reflection bypasses accessibility entirely. Both presuppose hostile code already
/// loaded in the same process, which defeats any capability design equally — this boundary defends against
/// ACCIDENTAL and BY-REFERENCE misuse, not against hostile in-process code. It is emphatically not "the CLR forbids
/// this from any assembly."
/// </para>
/// <para>
/// Within the boundary the producers are NOT uniform in strength. <see cref="TryBindByCertificateDigestAsync"/>
/// recomputes the identified certificate's digest in-body and compares it against the signature's own signed
/// reference — that catches "verified under Y, signed-reference names X" regardless of caller. The next three are
/// witness gates that trust the caller's own already-performed flow rather than recomputing it independently:
/// <see cref="TryBindByResolvedMethod"/>, <see cref="TryBindByControllerArtifact"/>, and
/// <see cref="TryBindByKeyAgreement"/> each compare caller-supplied identity strings for consistency (the
/// DID-document resolution or key-agreement decryption that produced them is the CALL SITE's responsibility, not
/// this gate's) — <see cref="TryBindByKeyAgreement"/> additionally checks its decryption-succeeded evidence
/// in-body rather than inferring it from having been called at all. This is precisely DIDComm's existing
/// bar, not a stronger one. <see cref="TryBindByKeriAnchor"/> is also a witness gate by shape (it compares two
/// strings), but its resolved-side input is structurally tighter than the other three's: a plain
/// <see cref="KeyId"/> or <see cref="string"/> is trivially caller-forgeable, while the AID
/// <see cref="TryBindByKeriAnchor"/> is handed can ONLY have been produced by an actual KERI key event log replay
/// that verified end to end (its producer's own construction boundary makes any other origin unrepresentable) —
/// so this gate's residual trust is "the caller actually ran that replay," not "the caller's claim is honest."
/// </para>
/// <para>
/// <strong>The witness tie.</strong> Every producer takes the exact <c>subject</c> instance the binding
/// is being established for and records it; <see cref="Witnesses(object)"/> reports whether a later value is
/// that SAME instance. <see cref="Verified{T}.TryCreateBound"/> calls it before minting, so a legitimate
/// <see cref="BoundProvenance"/> for one verified value can never be paired with a different
/// <see cref="Verified{T}"/> instance. This is an INSTANCE-identity witness, not a content witness:
/// a shared mutable payload mutated after mint keeps <see cref="Verified{T}.IsIdentityBound"/>
/// <see langword="true"/> even though its content has since changed. <see cref="Verified{T}"/> is documented as
/// an immutable post-verification snapshot boundary as the convention that keeps this residual closed in
/// practice; closing it structurally would need per-payload content-commitment witnesses, a distinct design
/// axis left for a follow-up.
/// </para>
/// <para>
/// <strong>The digest recomputation trusts the registry.</strong> <see cref="TryBindByCertificateDigestAsync"/> recomputes its digest
/// through the ambient <c>ComputeDigestDelegate</c> registry
/// (<see cref="CryptographicKeyEvents.ComputeDigestAsync"/>). Re-registering that delegate at process startup
/// would defeat this gate — but it would equally defeat every digest computation in the library, so this is a
/// trusted-startup property of the crypto registry, not a hole specific to this kernel.
/// </para>
/// <para>
/// <strong>Attribution-honesty convention (no analyzer).</strong> A verify path is
/// expected to reach for one of the four producers above whenever a resolvable identity commitment
/// exists in scope (a signed certificate reference, a resolved DID verification method, a resolved
/// controller artifact, an authenticated key-agreement sender) and to settle for
/// <see cref="Verified{T}.CreateAsserted"/> only for a genuine bring-your-own-key path with nothing
/// to resolve against — see the fuller statement on <see cref="Verified{T}"/>'s own remarks. This
/// producer set plus the private constructor already make a forged <see cref="Verified{T}.IsIdentityBound"/>
/// unrepresentable; no analyzer exists to catch the one thing the type system cannot: a future
/// verify path settling for <see cref="Verified{T}.CreateAsserted"/> where one of the four producers
/// above was in fact reachable and would have succeeded. That is a code-review concern, recorded
/// here as the convention, not a compiler check.
/// </para>
/// </remarks>
public sealed class BoundProvenance: VerificationProvenance
{
    private object Subject { get; }

    /// <summary>Which typed gate produced this provenance.</summary>
    public ResolutionSource Source { get; }

    /// <summary>
    /// The verification relationship or signing-certificate role <see cref="VerificationProvenance.Identity"/>
    /// was resolved under, or <see langword="null"/> when the producer names none (<see cref="TryBindByKeyAgreement"/>).
    /// </summary>
    public VerificationRelationship? Relationship { get; }


    private BoundProvenance(KeyId? identity, ResolutionSource source, VerificationRelationship? relationship, object subject): base(identity)
    {
        Source = source;
        Relationship = relationship;
        this.Subject = subject;
    }


    /// <summary>Reports whether this provenance was established for exactly <paramref name="value"/>.</summary>
    /// <param name="value">The candidate value.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is the same instance this provenance was bound to.</returns>
    internal bool Witnesses(object value)
    {
        return ReferenceEquals(Subject, value);
    }


    /// <summary>
    /// Binds by recomputing the identified signing certificate's own digest and comparing it against the
    /// signature's signed <c>SigningCertificateV2</c>/<c>CertDigest</c> signer reference — applied to the
    /// certificate the crypto-verification outcome actually ran under, never a caller-supplied variable that
    /// could diverge from it. The recompute itself is
    /// <see cref="XAdESLevelRules.TryMatchSigningCertificateDigestAsync"/>, the ONE implementation this gate and
    /// <see cref="XAdESLevelRules.CheckSigningCertificateBindingAsync"/> both delegate to.
    /// </summary>
    /// <param name="signingCertificateReferences">The signature's signing-certificate identifier references; the signer reference (<see cref="SigningCertificateReference.IsSignerReference"/>) among them is the one checked.</param>
    /// <param name="cryptographicVerification">The clause 5.2.7.4 outcome; refused unless it is <see cref="SignatureCryptographicOutcome.Verified"/> and carries a non-<see langword="null"/> <see cref="SignatureCryptographicVerification.SigningCertificate"/> (<see cref="BoundProvenance"/> witnesses both crypto success and identity).</param>
    /// <param name="subject">The exact value this provenance is being established for.</param>
    /// <param name="pool">The memory pool the digest recompute rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A <see cref="BoundProvenance"/> when the recomputed digest matches the signer reference's own digest; otherwise <see langword="null"/>.</returns>
    /// <remarks>
    /// The recompute buffer length is the RESOLVED <see cref="PkiDigestAlgorithm.OutputByteLength"/> for
    /// <paramref name="signingCertificateReferences"/>'s signer reference's own algorithm OID, never the
    /// wire-supplied <c>referenceDigest.Length</c>: a reference whose length disagrees with its own stated
    /// algorithm is refused (returns <see langword="null"/>) rather than handed to the digest computation, which
    /// would otherwise throw <see cref="ArgumentException"/> for a too-short or too-long buffer. Mirrors the
    /// CAdES reader's own length validation (<see cref="CAdESSignatureFacts.ReadEssCertificateReferences"/>).
    /// </remarks>
    /// <exception cref="ArgumentNullException">A required argument is <see langword="null"/>.</exception>
    internal static async ValueTask<BoundProvenance?> TryBindByCertificateDigestAsync(
        IReadOnlyList<SigningCertificateReference> signingCertificateReferences,
        SignatureCryptographicVerification cryptographicVerification,
        object subject,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(signingCertificateReferences);
        ArgumentNullException.ThrowIfNull(cryptographicVerification);
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(pool);

        if(cryptographicVerification.Outcome != SignatureCryptographicOutcome.Verified
            || cryptographicVerification.SigningCertificate is not PkiCertificateMemory verifiedCertificate)
        {
            return null;
        }

        SigningCertificateReference? signerReference = null;
        for(int i = 0; i < signingCertificateReferences.Count; ++i)
        {
            if(signingCertificateReferences[i].IsSignerReference)
            {
                signerReference = signingCertificateReferences[i];
                break;
            }
        }

        using DigestValue? candidateDigest = await XAdESLevelRules.TryMatchSigningCertificateDigestAsync(
            signerReference, verifiedCertificate.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);

        if(candidateDigest is null)
        {
            return null;
        }

        return new BoundProvenance(
            new KeyId(Convert.ToHexStringLower(candidateDigest.AsReadOnlySpan())),
            ResolutionSource.CertificateDigest,
            VerificationRelationship.SignerCertificate,
            subject);
    }

    /// <summary>
    /// Binds by consistency: witnesses that <paramref name="claimedIdentity"/> names exactly
    /// <paramref name="resolvedMethodId"/>, the verification method the caller already resolved and authorized
    /// through its own flow. The residual trust this rests on is the caller's already-audited resolve+authorize
    /// step — the bar DIDComm's signed and authenticated-encryption verify paths already clear before reaching
    /// this gate.
    /// </summary>
    /// <param name="claimedIdentity">The identity the value under verification claims.</param>
    /// <param name="resolvedMethodId">The verification method id the caller's own resolution settled on.</param>
    /// <param name="relationship">
    /// The relationship the resolution was scoped to. RECORDED as the caller's own already-performed scoping —
    /// this gate does not itself verify that <paramref name="resolvedMethodId"/> actually carries
    /// <paramref name="relationship"/> in a DID document; it only checks that <paramref name="claimedIdentity"/>
    /// and <paramref name="resolvedMethodId"/> agree.
    /// </param>
    /// <param name="subject">The exact value this provenance is being established for.</param>
    /// <returns>A <see cref="BoundProvenance"/> naming <paramref name="claimedIdentity"/> when the two agree; otherwise <see langword="null"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="resolvedMethodId"/> or <paramref name="subject"/> is <see langword="null"/>.</exception>
    internal static BoundProvenance? TryBindByResolvedMethod(KeyId claimedIdentity, string resolvedMethodId, VerificationRelationship relationship, object subject)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(resolvedMethodId);
        ArgumentNullException.ThrowIfNull(subject);

        //default(KeyId) (Value is null) can never name a principal -- refuse explicitly rather than relying
        //on the string comparison below to fail incidentally.
        if(string.IsNullOrWhiteSpace(claimedIdentity.Value))
        {
            return null;
        }

        if(!string.Equals(claimedIdentity.Value, resolvedMethodId, StringComparison.Ordinal))
        {
            return null;
        }

        return new BoundProvenance(claimedIdentity, ResolutionSource.MethodResolved, relationship, subject);
    }

    /// <summary>
    /// Binds a resolved verification method to a claimed controller artifact: refuses unless
    /// <paramref name="claimedController"/> matches the resolved method's own controller AND
    /// <paramref name="declaredProofPurpose"/> corresponds to <paramref name="expectedRelationship"/>
    /// (<c>"assertionMethod"</c> ↔ <see cref="VerificationRelationship.AssertionMethod"/>, <c>"authentication"</c>
    /// ↔ <see cref="VerificationRelationship.Authentication"/>). Takes the resolved artifact's primitive fields
    /// rather than a DID document type: this assembly does not reference <c>Verifiable.Core</c>, so the DID
    /// document resolution itself stays the call site's own responsibility, documented at the call site.
    /// </summary>
    /// <param name="claimedController">The controller the value under verification claims (for example a credential's <c>issuer</c> or a presentation's <c>holder</c>).</param>
    /// <param name="resolvedMethodId">The verification method id the caller's own resolution settled on.</param>
    /// <param name="resolvedMethodController">The controller the resolved verification method itself belongs to.</param>
    /// <param name="declaredProofPurpose">The proof's own declared purpose string.</param>
    /// <param name="expectedRelationship">The relationship the proof purpose is expected to correspond to.</param>
    /// <param name="subject">The exact value this provenance is being established for.</param>
    /// <returns>A <see cref="BoundProvenance"/> naming <paramref name="resolvedMethodId"/> when both checks hold; otherwise <see langword="null"/>.</returns>
    /// <exception cref="ArgumentNullException">A required string argument or <paramref name="subject"/> is <see langword="null"/>.</exception>
    internal static BoundProvenance? TryBindByControllerArtifact(
        string claimedController,
        string resolvedMethodId,
        string resolvedMethodController,
        string declaredProofPurpose,
        VerificationRelationship expectedRelationship,
        object subject)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(claimedController);
        ArgumentException.ThrowIfNullOrWhiteSpace(resolvedMethodId);
        ArgumentException.ThrowIfNullOrWhiteSpace(resolvedMethodController);
        ArgumentException.ThrowIfNullOrWhiteSpace(declaredProofPurpose);
        ArgumentNullException.ThrowIfNull(subject);

        if(!string.Equals(claimedController, resolvedMethodController, StringComparison.Ordinal))
        {
            return null;
        }

        bool purposeMatchesRelationship =
            (expectedRelationship == VerificationRelationship.AssertionMethod && string.Equals(declaredProofPurpose, "assertionMethod", StringComparison.Ordinal))
            || (expectedRelationship == VerificationRelationship.Authentication && string.Equals(declaredProofPurpose, "authentication", StringComparison.Ordinal));
        if(!purposeMatchesRelationship)
        {
            return null;
        }

        return new BoundProvenance(new KeyId(resolvedMethodId), ResolutionSource.CallerControllerArtifact, expectedRelationship, subject);
    }

    /// <summary>
    /// Binds an authenticated-encryption sender identity: checks, in-body, that the caller's own decryption
    /// actually succeeded under a key agreeing with <paramref name="senderKeyId"/>, rather than trusting the
    /// call site by convention.
    /// </summary>
    /// <param name="senderKeyId">The sender identity the message claims (the wire <c>skid</c>/<c>apu</c>).</param>
    /// <param name="isDecryptionAuthenticated">
    /// Whether the caller's own ECDH-1PU key-agreement decryption actually succeeded — checked in-body
    /// (mirrors <see cref="TryBindByCertificateDigestAsync"/>'s own in-body <c>Outcome</c> check) rather than
    /// inferred from having reached this call at all.
    /// </param>
    /// <param name="resolvedSenderKeyId">
    /// The verification method id the ECDH-1PU step actually resolved and ran under (the caller's own
    /// already-performed <c>keyAgreement</c> lookup) — witnessed for consistency against
    /// <paramref name="senderKeyId"/>, the same claimed-vs-resolved shape <see cref="TryBindByResolvedMethod"/>
    /// checks.
    /// </param>
    /// <param name="subject">The exact value this provenance is being established for.</param>
    /// <returns>
    /// A <see cref="BoundProvenance"/> naming <paramref name="senderKeyId"/>, or <see langword="null"/> when
    /// <paramref name="senderKeyId"/> is <see langword="default"/>(<see cref="KeyId"/>) (a null/whitespace
    /// identity can never name a principal), <paramref name="isDecryptionAuthenticated"/> is
    /// <see langword="false"/> (the evidence is absent), or <paramref name="resolvedSenderKeyId"/> disagrees
    /// with <paramref name="senderKeyId"/> (the evidence is inconsistent).
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="subject"/> is <see langword="null"/>.</exception>
    internal static BoundProvenance? TryBindByKeyAgreement(KeyId senderKeyId, bool isDecryptionAuthenticated, KeyId resolvedSenderKeyId, object subject)
    {
        ArgumentNullException.ThrowIfNull(subject);

        //default(KeyId) (Value is null) can never name a principal.
        if(string.IsNullOrWhiteSpace(senderKeyId.Value))
        {
            return null;
        }

        //The evidence that decryption actually succeeded under senderKeyId, checked in-body rather than
        //trusted by convention.
        if(!isDecryptionAuthenticated)
        {
            return null;
        }

        if(!string.Equals(senderKeyId.Value, resolvedSenderKeyId.Value, StringComparison.Ordinal))
        {
            return null;
        }

        return new BoundProvenance(senderKeyId, ResolutionSource.KeyAgreement, null, subject);
    }

    /// <summary>
    /// Binds a KERI issuer AID by consistency: witnesses that <paramref name="claimedIssuerAid"/> names exactly
    /// <paramref name="resolvedAnchorAid"/>, the AID a KERI key event log replay independently established for the
    /// verified event that anchored the value under verification. The residual trust this rests on is the
    /// caller's already-performed KEL replay — but unlike <see cref="TryBindByResolvedMethod"/>'s plain
    /// <see cref="string"/> input, <paramref name="resolvedAnchorAid"/> can only have come from a replay that
    /// actually verified: its producer's own construction boundary makes a caller-asserted AID unrepresentable.
    /// </summary>
    /// <param name="claimedIssuerAid">The Issuer AID the value under verification claims.</param>
    /// <param name="resolvedAnchorAid">The AID a KERI KEL replay established for the verified event that anchored the value.</param>
    /// <param name="subject">The exact value this provenance is being established for.</param>
    /// <returns>A <see cref="BoundProvenance"/> naming <paramref name="claimedIssuerAid"/> when the two agree; otherwise <see langword="null"/>.</returns>
    /// <exception cref="ArgumentException"><paramref name="resolvedAnchorAid"/> is null or whitespace.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="subject"/> is <see langword="null"/>.</exception>
    internal static BoundProvenance? TryBindByKeriAnchor(string claimedIssuerAid, string resolvedAnchorAid, object subject)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(resolvedAnchorAid);
        ArgumentNullException.ThrowIfNull(subject);

        //A null/whitespace claimed identity can never name a principal.
        if(string.IsNullOrWhiteSpace(claimedIssuerAid))
        {
            return null;
        }

        if(!string.Equals(claimedIssuerAid, resolvedAnchorAid, StringComparison.Ordinal))
        {
            return null;
        }

        return new BoundProvenance(new KeyId(claimedIssuerAid), ResolutionSource.KeriAnchor, null, subject);
    }
}
