using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One reference, carried by an object a time-stamp protects, that names another object by a hash value of it —
/// the material step 4) of clause 5.6.2.3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> derives a proof of existence for a hash value from, and the material step 4)b)
/// derives an indirect proof for the referenced object from.
/// </summary>
/// <param name="ReferencedObject">The identity of the object the reference names.</param>
/// <param name="ReferenceDigestAlgorithm">The cryptographic hash function <c>h</c> the reference carries the value of, whose asserted reliability gates both derivations.</param>
[DebuggerDisplay("ProtectedObjectReference: {ReferencedObject} under {ReferenceDigestAlgorithm.Oid}")]
public sealed record ProtectedObjectReference(
    ValidationObjectIdentity ReferencedObject,
    AlgorithmIdentifier ReferenceDigestAlgorithm);


/// <summary>
/// The set <c>S</c> of steps 1) and 2) of clause 5.6.2.3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>: "the set of references to objects and objects that are part of the signature
/// and are protected by the time-stamp", closed under step 2)'s rule that objects contained in those objects and
/// usable in signature validation join the set.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> The identities here carry non-owning references to digests the run owns.
/// </remarks>
[DebuggerDisplay("ProtectedObjectSet: {Objects.Count} objects, {References.Count} references")]
public sealed record ProtectedObjectSet
{
    /// <summary>The objects in the set, which step 5) adds a proof of existence for at the time-stamp's generation time.</summary>
    public IReadOnlyList<ValidationObjectIdentity> Objects { get; init; } = [];

    /// <summary>The references in the set that carry a hash value of a referenced object, which step 4) reasons over.</summary>
    public IReadOnlyList<ProtectedObjectReference> References { get; init; } = [];
}


/// <summary>
/// The POE extraction building block of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.6.2.3</see>: it derives proofs of existence from a time-stamp, both the
/// direct proofs of step 5) for every object the time-stamp protects and the indirect proofs of step 4)b) for an
/// object a protected reference names by hash value.
/// </summary>
/// <remarks>
/// <para>
/// Clause 5.6.2.3.1 states the assumptions this block is used under: the time-stamp validation has returned
/// <c>PASSED</c>, and the hash function the time-stamp itself uses is reliable at the relevant time. Both are the
/// caller's to establish — step 5)b) of clause 5.6.3.4 states them as conditions on calling this block — and
/// neither is re-decided here.
/// </para>
/// <para>
/// Every object identity is keyed on a digest taken through the registered digest seam, which is the library's
/// canonical identity hash and is a different thing from the hash function <c>h</c> a reference in the signature
/// carries a value under. Step 4)'s reliability gate is about the latter.
/// </para>
/// <para>
/// The closure of step 2) walks an explicit <see cref="Stack{T}"/> with a bounded number of iterations, never
/// recursion: the time-stamp tokens it opens are attacker-reachable and can nest.
/// </para>
/// </remarks>
public static class ProofOfExistenceExtraction
{
    /// <summary>The largest number of objects the closure of step 2) will admit into the set, so a nested structure cannot make the walk unbounded.</summary>
    private const int MaximumProtectedObjects = 256;

    /// <summary>The largest number of container objects the closure of step 2) will open, for the same reason.</summary>
    private const int MaximumContainersOpened = 64;


    /// <summary>
    /// Derives the set of proofs of existence one time-stamp establishes.
    /// </summary>
    /// <param name="signature">Table 25's mandatory "Signature" input, as the facts the format binding extracted.</param>
    /// <param name="timestamp">Table 25's mandatory "An attribute with a time-stamp token" input.</param>
    /// <param name="generationTime">The generation time <c>T1</c> of the time-stamp token, as the time-stamp validation building block of clause 5.4 returned it.</param>
    /// <param name="proofsOfExistence">Table 25's mandatory "A set of POEs" input, which may be empty.</param>
    /// <param name="cryptographicConstraints">The cryptographic constraints whose hash-reliability assertions gate steps 4)a) and 4)b).</param>
    /// <param name="signatureElementsConstraints">The signature elements constraints, whose <see cref="SignatureElementsConstraints.AcceptsUnverifiableTimestampCoverage"/> decides what step 1) does with a time-stamp whose coverage the format binding cannot state.</param>
    /// <param name="seams">The format binding the closure of step 2) opens contained objects with.</param>
    /// <param name="resources">The ledger the digests this call computes are tracked in.</param>
    /// <param name="pool">The memory pool the run rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The set <c>P</c> of clause 5.6.2.3.3, which may be empty.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    public static async ValueTask<ProofOfExistenceSet> ExtractAsync(
        SignatureFacts signature,
        EmbeddedTimestamp timestamp,
        DateTimeOffset generationTime,
        ProofOfExistenceSet proofsOfExistence,
        CryptographicConstraints cryptographicConstraints,
        SignatureElementsConstraints signatureElementsConstraints,
        SignatureValidationSeams seams,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(timestamp);
        ArgumentNullException.ThrowIfNull(proofsOfExistence);
        ArgumentNullException.ThrowIfNull(cryptographicConstraints);
        ArgumentNullException.ThrowIfNull(signatureElementsConstraints);
        ArgumentNullException.ThrowIfNull(seams);
        ArgumentNullException.ThrowIfNull(resources);
        ArgumentNullException.ThrowIfNull(pool);

        //Steps 1) and 2).
        ProtectedObjectSet protectedObjects = await DetermineProtectedObjectsAsync(
            signature, timestamp, signatureElementsConstraints, seams, resources, pool, cancellationToken).ConfigureAwait(false);

        ValidationObjectIdentity tokenIdentity = await CreateIdentityAsync(
            timestamp.Token.AsReadOnlyMemory(), ValidationObjectKind.TimestampToken, timestamp.Identifier, resources, pool, cancellationToken).ConfigureAwait(false);

        //Step 3): the set P starts empty.
        List<ProofOfExistence> derived = [];

        //Step 4): the references that carry a hash value of a referenced object. The gate is "trusted until at
        //least a date after the time of the generation of the timestamp (named T1)", so a reliability assertion
        //that ends exactly at T1 does not satisfy it.
        for(int i = 0; i < protectedObjects.References.Count; ++i)
        {
            ProtectedObjectReference reference = protectedObjects.References[i];
            if(!cryptographicConstraints.IsHashTrustedAfter(reference.ReferenceDigestAlgorithm, generationTime))
            {
                continue;
            }

            //Step 4)a): a proof for the hash value of the object at T1.
            derived.Add(new ProofOfExistence
            {
                ObjectIdentity = reference.ReferencedObject,
                Instant = generationTime,
                Scope = ProofOfExistenceScope.DigestOfObject,
                Origin = ProofOfExistenceOrigin.TimestampToken,
                ReferenceDigestAlgorithm = reference.ReferenceDigestAlgorithm,
                EstablishedBy = tokenIdentity
            });

            //Step 4)b): a proof for the object itself at T1, when the object is already proven to have existed at
            //some later T2 and the hash function is asserted reliable until at least T2.
            if(EarliestObjectInstantAfter(proofsOfExistence, reference.ReferencedObject, generationTime) is DateTimeOffset laterInstant
                && cryptographicConstraints.IsHashTrustedUntilAtLeast(reference.ReferenceDigestAlgorithm, laterInstant))
            {
                derived.Add(new ProofOfExistence
                {
                    ObjectIdentity = reference.ReferencedObject,
                    Instant = generationTime,
                    Scope = ProofOfExistenceScope.Object,
                    Origin = ProofOfExistenceOrigin.IndirectDerivation,
                    ReferenceDigestAlgorithm = reference.ReferenceDigestAlgorithm,
                    EstablishedBy = tokenIdentity
                });
            }
        }

        //Step 5): every object the time-stamp protects existed at T1.
        for(int i = 0; i < protectedObjects.Objects.Count; ++i)
        {
            derived.Add(new ProofOfExistence
            {
                ObjectIdentity = protectedObjects.Objects[i],
                Instant = generationTime,
                Scope = ProofOfExistenceScope.Object,
                Origin = ProofOfExistenceOrigin.TimestampToken,
                EstablishedBy = tokenIdentity
            });
        }

        //Step 6).
        return ProofOfExistenceSet.Create(derived);
    }


    /// <summary>
    /// Determines the set <c>S</c> of steps 1) and 2) of clause 5.6.2.3: the objects and references of the
    /// signature that one time-stamp protects, closed under the objects those objects contain.
    /// </summary>
    /// <param name="signature">The signature's facts.</param>
    /// <param name="timestamp">The time-stamp whose protected objects are wanted.</param>
    /// <param name="signatureElementsConstraints">The signature elements constraints, whose <see cref="SignatureElementsConstraints.AcceptsUnverifiableTimestampCoverage"/> decides what happens for a time-stamp whose coverage the format binding cannot state.</param>
    /// <param name="seams">The format binding the closure opens contained objects with.</param>
    /// <param name="resources">The ledger the digests this call computes are tracked in.</param>
    /// <param name="pool">The memory pool the run rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The set.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    /// <remarks>
    /// <para>
    /// The set holds the objects "protected by the time-stamp", so what the token's <c>messageImprint</c> is
    /// computed over decides membership. The format binding states those octets through
    /// <see cref="StateTimestampCoverageAsyncDelegate"/> and this block verifies the imprint against them: a
    /// token whose imprint does not bind protects nothing and yields an empty set. The attribute a token was
    /// found in is not evidence of coverage — for every class but the content time-stamp that attribute is
    /// unsigned, so it is chosen by whoever last rewrote the Signed Data Object.
    /// </para>
    /// <para>
    /// What a verified time-stamp protects then follows from what class it is, which is the classification
    /// clause 5.6.3.1 enumerates: a time-stamp on the Signed Data Object protects the signed content, a
    /// time-stamp on the signature value protects the signature value, a time-stamp on the references of
    /// validation data protects the validation material, and an archive time-stamp protects "the whole signature
    /// except the last archive time-stamp" — the signature, its content and value, every certificate and
    /// revocation data object it carries, and every earlier time-stamp token.
    /// </para>
    /// <para>
    /// The closure of step 2) opens each protected time-stamp token through the format binding and admits the
    /// certificates and revocation data it contains, which is what makes the certificates of a Time-Stamping
    /// Authority reachable as proven objects.
    /// </para>
    /// <para>
    /// <strong>The class rule is the coarsest reading, and a binding may narrow it.</strong> A format whose
    /// time-stamps name their protected objects one by one — the <c>ats-hash-index-v3</c> of ETSI EN 319 122-1
    /// clause 5.5.2 does exactly that — supplies
    /// <see cref="SignatureFormatSeam.StateTimestampProtectsObject"/>, and every object the class rule proposes is
    /// then put to it before joining the set. Without it the class rule stands unnarrowed, which is what every
    /// binding that states nothing at object granularity gets. The narrowing matters because the class rule alone
    /// would grant a proof of existence to material appended to the signature <em>after</em> the time-stamp was
    /// applied: such material has no entry in that time-stamp's index, so nothing in the signature establishes it
    /// existed at the time-stamp's instant.
    /// </para>
    /// </remarks>
    public static async ValueTask<ProtectedObjectSet> DetermineProtectedObjectsAsync(
        SignatureFacts signature,
        EmbeddedTimestamp timestamp,
        SignatureElementsConstraints signatureElementsConstraints,
        SignatureValidationSeams seams,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(timestamp);
        ArgumentNullException.ThrowIfNull(signatureElementsConstraints);
        ArgumentNullException.ThrowIfNull(seams);
        ArgumentNullException.ThrowIfNull(resources);
        ArgumentNullException.ThrowIfNull(pool);

        if(!await ProtectsTheSignatureAsync(signature, timestamp, signatureElementsConstraints, seams, pool, cancellationToken).ConfigureAwait(false))
        {
            return new ProtectedObjectSet();
        }

        List<ValidationObjectIdentity> objects = [];
        List<ProtectedObjectReference> references = [];
        var containers = new Stack<PkiCertificateMemory>();

        //The binding's object-granular narrowing of step 1), when it states one. Bundled with the two inputs every
        //call needs so the filter travels as one explicit parameter rather than a captured closure.
        ProtectedObjectAdmission? admission = seams.Format.StateTimestampProtectsObject is StateTimestampProtectsObjectAsyncDelegate statesProtection
            ? new ProtectedObjectAdmission { States = statesProtection, Signature = signature, Timestamp = timestamp }
            : null;

        //Step 1): what a time-stamp protects follows from its class. A token whose class the binding could not
        //state protects nothing this algorithm can name.
        switch(timestamp.Class)
        {
            case SignatureTimestampClass.ContentTimestamp:
                await AddContentAsync(signature, objects, resources, pool, cancellationToken).ConfigureAwait(false);

                break;

            case SignatureTimestampClass.SignatureTimestamp:
                await AddSignatureValueAsync(signature, objects, resources, pool, cancellationToken).ConfigureAwait(false);

                break;

            case SignatureTimestampClass.ValidationDataTimestamp:
                await AddValidationMaterialAsync(signature, objects, admission, resources, pool, cancellationToken).ConfigureAwait(false);

                break;

            case SignatureTimestampClass.ArchiveTimestamp:
                await AddArchiveMaterialAsync(signature, timestamp, objects, containers, admission, resources, pool, cancellationToken).ConfigureAwait(false);

                break;

            default:
                break;
        }

        //An archive time-stamp protects the signature's signed attributes too, and the signing certificate
        //identifier attributes among them are references naming an object by a hash value under a stated
        //function — exactly the shape step 4) reasons over. A reference is admitted when the object it names is
        //in hand, because step 4)b) has to ask the set of POEs about that object. The narrowing filter does not
        //apply to the references: what the imprint binds is the signed attribute carrying the reference, which is
        //part of the time-stamped material by construction rather than by the format's index of protected objects.
        if(timestamp.Class == SignatureTimestampClass.ArchiveTimestamp)
        {
            await AddSigningCertificateReferencesAsync(signature, references, resources, pool, cancellationToken).ConfigureAwait(false);
        }

        //Step 2): the closure over the objects the protected objects contain, walked iteratively.
        int containersOpened = 0;
        while(containers.Count > 0 && containersOpened < MaximumContainersOpened && objects.Count < MaximumProtectedObjects)
        {
            PkiCertificateMemory container = containers.Pop();
            ++containersOpened;

            CmsSignedData carrier = resources.Track(CmsSignedData.FromBytes(container.AsReadOnlySpan(), pool));
            SignatureFacts contained;
            try
            {
                contained = resources.Track(await seams.Format.ExtractFacts(
                    new SignatureFactsExtractionContext { SignedDataObject = carrier }, pool, cancellationToken).ConfigureAwait(false));
            }
            catch(Exception exception) when(exception is not OperationCanceledException)
            {
                //A container the binding cannot open contains nothing this algorithm can name.
                continue;
            }

            if(!contained.IsExtracted)
            {
                continue;
            }

            //The contents of a container that is itself protected are protected with it, so the narrowing filter
            //does not apply here: it answers about objects of the outer signature, not about objects inside one of
            //them, and a container the filter denied never reached this stack.
            await AddCarriersAsync(contained.EmbeddedCertificates, ValidationObjectKind.Certificate, objects, admission: null, resources, pool, cancellationToken).ConfigureAwait(false);
            await AddCarriersAsync(contained.EmbeddedCertificateRevocationLists, ValidationObjectKind.RevocationData, objects, admission: null, resources, pool, cancellationToken).ConfigureAwait(false);
            await AddCarriersAsync(contained.EmbeddedOcspResponses, ValidationObjectKind.RevocationData, objects, admission: null, resources, pool, cancellationToken).ConfigureAwait(false);
        }

        return new ProtectedObjectSet { Objects = objects, References = references };
    }


    /// <summary>
    /// Decides whether a time-stamp is shown to protect the signature it is embedded in, by verifying its
    /// <c>messageImprint</c> against the octets the format binding states it is computed over.
    /// </summary>
    /// <param name="signature">The signature's facts.</param>
    /// <param name="timestamp">The time-stamp to test.</param>
    /// <param name="signatureElementsConstraints">The constraints, whose <see cref="SignatureElementsConstraints.AcceptsUnverifiableTimestampCoverage"/> decides the case where the binding states nothing.</param>
    /// <param name="seams">The format binding.</param>
    /// <param name="pool">The memory pool the read and the computed digest rent from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when the objects of the token's class may be admitted into the set.</returns>
    private static async ValueTask<bool> ProtectsTheSignatureAsync(
        SignatureFacts signature,
        EmbeddedTimestamp timestamp,
        SignatureElementsConstraints signatureElementsConstraints,
        SignatureValidationSeams seams,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        if(seams.Format.StateTimestampCoverage is not StateTimestampCoverageAsyncDelegate stateCoverage)
        {
            return signatureElementsConstraints.AcceptsUnverifiableTimestampCoverage;
        }

        SignedContentMemory? covered;
        try
        {
            covered = await stateCoverage(
                new TimestampCoverageContext { Signature = signature, Timestamp = timestamp }, pool, cancellationToken).ConfigureAwait(false);
        }
        catch(Exception exception) when(exception is not OperationCanceledException)
        {
            //A binding that cannot state coverage for a token it cannot read states none.
            return signatureElementsConstraints.AcceptsUnverifiableTimestampCoverage;
        }

        if(covered is null)
        {
            return signatureElementsConstraints.AcceptsUnverifiableTimestampCoverage;
        }

        using(covered)
        {
            try
            {
                using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(
                    timestamp.Token, pool, cancellationToken).ConfigureAwait(false);

                return info.IsRead
                    && await info.VerifyMessageImprintAsync(covered.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
            }
            catch(InvalidOperationException)
            {
                //No CMS verification or digest seam is registered, so nothing about this token can be verified.
                return false;
            }
        }
    }


    /// <summary>
    /// States the canonical identity of one object: its digest under the library's identity hash, taken through
    /// the registered digest seam, together with what the object is.
    /// </summary>
    /// <param name="objectBytes">The object's encoded octets.</param>
    /// <param name="kind">What the object is.</param>
    /// <param name="reference">The object's own identifier where its format supplies one; otherwise <see langword="null"/>.</param>
    /// <param name="resources">The ledger the computed digest is tracked in, because the identity holds a non-owning reference to it.</param>
    /// <param name="pool">The memory pool the digest is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The identity.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">Thrown when no <see cref="ComputeDigestDelegate"/> has been registered — a composition fault of the host, not an outcome of the signature.</exception>
    public static async ValueTask<ValidationObjectIdentity> CreateIdentityAsync(
        ReadOnlyMemory<byte> objectBytes,
        ValidationObjectKind kind,
        string? reference,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resources);
        ArgumentNullException.ThrowIfNull(pool);

        PkiDigestAlgorithm identityAlgorithm = PkiDigestAlgorithm.Sha256;
        DigestValue digest = resources.Track(await CryptographicKeyEvents.ComputeDigestAsync(
            objectBytes, identityAlgorithm.OutputByteLength, identityAlgorithm.DigestTag, pool,
            cancellationToken: cancellationToken).ConfigureAwait(false));

        return new ValidationObjectIdentity
        {
            Kind = kind,
            Digest = digest,
            DigestAlgorithm = identityAlgorithm.Identifier,
            Reference = reference
        };
    }


    /// <summary>
    /// States the earliest instant strictly after a given one at which a set of proofs proves an object itself
    /// existed — the date <c>T2</c> of step 4)b) of clause 5.6.2.3.
    /// </summary>
    /// <param name="proofsOfExistence">The set to ask.</param>
    /// <param name="objectIdentity">The object to ask about.</param>
    /// <param name="instant">The instant <c>T1</c> the answer has to be after.</param>
    /// <returns>The earliest such instant, or <see langword="null"/> when the set proves nothing about that object after it.</returns>
    private static DateTimeOffset? EarliestObjectInstantAfter(
        ProofOfExistenceSet proofsOfExistence,
        ValidationObjectIdentity objectIdentity,
        DateTimeOffset instant)
    {
        IReadOnlyList<ProofOfExistence> proofs = proofsOfExistence.For(objectIdentity);
        DateTimeOffset? earliest = null;
        for(int i = 0; i < proofs.Count; ++i)
        {
            if(proofs[i].Scope == ProofOfExistenceScope.Object
                && proofs[i].Instant > instant
                && (earliest is null || proofs[i].Instant < earliest))
            {
                earliest = proofs[i].Instant;
            }
        }

        return earliest;
    }


    /// <summary>
    /// Admits the signature as a whole — the Signed Data Object the facts were extracted from.
    /// </summary>
    /// <param name="signature">The signature's facts.</param>
    /// <param name="objects">The set being built.</param>
    /// <param name="resources">The ledger the computed digest is tracked in.</param>
    /// <param name="pool">The memory pool the digest is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    private static async ValueTask AddSignatureAsync(
        SignatureFacts signature,
        List<ValidationObjectIdentity> objects,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        if(signature.SignedDataObject is SensitiveMemory signedDataObject)
        {
            objects.Add(await CreateIdentityAsync(
                signedDataObject.AsReadOnlyMemory(), ValidationObjectKind.Signature, reference: null, resources, pool, cancellationToken).ConfigureAwait(false));
        }
    }


    /// <summary>
    /// Admits the signature value — the object clause 5.6.2.4 asks a proof of existence about.
    /// </summary>
    /// <param name="signature">The signature's facts.</param>
    /// <param name="objects">The set being built.</param>
    /// <param name="resources">The ledger the computed digest is tracked in.</param>
    /// <param name="pool">The memory pool the digest is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    private static async ValueTask AddSignatureValueAsync(
        SignatureFacts signature,
        List<ValidationObjectIdentity> objects,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        if(signature.SignatureValue is SignedContentMemory signatureValue)
        {
            objects.Add(await CreateIdentityAsync(
                signatureValue.AsReadOnlyMemory(), ValidationObjectKind.SignatureValue, reference: null, resources, pool, cancellationToken).ConfigureAwait(false));
        }
    }


    /// <summary>
    /// Admits the signed content the signature encapsulates.
    /// </summary>
    /// <param name="signature">The signature's facts.</param>
    /// <param name="objects">The set being built.</param>
    /// <param name="resources">The ledger the computed digest is tracked in.</param>
    /// <param name="pool">The memory pool the digest is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    private static async ValueTask AddContentAsync(
        SignatureFacts signature,
        List<ValidationObjectIdentity> objects,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        if(signature.SignedContent is SignedContentMemory content)
        {
            objects.Add(await CreateIdentityAsync(
                content.AsReadOnlyMemory(), ValidationObjectKind.SignedDataObject, signature.SignedContentIdentifier, resources, pool, cancellationToken).ConfigureAwait(false));
        }
    }


    /// <summary>
    /// Admits every certificate and revocation data object the signature carries that the time-stamp is shown to
    /// protect.
    /// </summary>
    /// <param name="signature">The signature's facts.</param>
    /// <param name="objects">The set being built.</param>
    /// <param name="admission">The binding's object-granular narrowing of step 1), or <see langword="null"/> when the class rule stands unnarrowed.</param>
    /// <param name="resources">The ledger the computed digests are tracked in.</param>
    /// <param name="pool">The memory pool the digests are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    private static async ValueTask AddValidationMaterialAsync(
        SignatureFacts signature,
        List<ValidationObjectIdentity> objects,
        ProtectedObjectAdmission? admission,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        await AddCarriersAsync(signature.EmbeddedCertificates, ValidationObjectKind.Certificate, objects, admission, resources, pool, cancellationToken).ConfigureAwait(false);
        await AddCarriersAsync(signature.EmbeddedCertificateRevocationLists, ValidationObjectKind.RevocationData, objects, admission, resources, pool, cancellationToken).ConfigureAwait(false);
        await AddCarriersAsync(signature.EmbeddedOcspResponses, ValidationObjectKind.RevocationData, objects, admission, resources, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Admits everything an archive time-stamp protects: the signature, its value, its content, the validation
    /// material it carries, and every earlier time-stamp token — "the whole signature except the last archive
    /// time-stamp" of clause 5.6.3.1.
    /// </summary>
    /// <param name="signature">The signature's facts.</param>
    /// <param name="timestamp">The archive time-stamp being extracted from.</param>
    /// <param name="objects">The set being built.</param>
    /// <param name="containers">The stack of objects whose contents step 2) still has to admit.</param>
    /// <param name="admission">The binding's object-granular narrowing of step 1), or <see langword="null"/> when the class rule stands unnarrowed.</param>
    /// <param name="resources">The ledger the computed digests are tracked in.</param>
    /// <param name="pool">The memory pool the digests are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <remarks>
    /// The signature, its value and its content are not put to the narrowing filter: what makes a time-stamp an
    /// archive time-stamp at all is that its message imprint is computed over those very octets — for CAdES, parts
    /// 1) to 3) of the concatenation of ETSI EN 319 122-1 clause 5.5.3 — so a token whose imprint verified against
    /// the binding's stated coverage has already been shown to protect them. What the filter narrows is the
    /// material a signature can gain after the fact: the certificates, the revocation data and the earlier
    /// time-stamp tokens, each of which is bound only through that format's own index of protected objects.
    /// </remarks>
    private static async ValueTask AddArchiveMaterialAsync(
        SignatureFacts signature,
        EmbeddedTimestamp timestamp,
        List<ValidationObjectIdentity> objects,
        Stack<PkiCertificateMemory> containers,
        ProtectedObjectAdmission? admission,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        await AddSignatureAsync(signature, objects, resources, pool, cancellationToken).ConfigureAwait(false);
        await AddSignatureValueAsync(signature, objects, resources, pool, cancellationToken).ConfigureAwait(false);
        await AddContentAsync(signature, objects, resources, pool, cancellationToken).ConfigureAwait(false);
        await AddValidationMaterialAsync(signature, objects, admission, resources, pool, cancellationToken).ConfigureAwait(false);
        await AddEarlierTimestampsAsync(signature, timestamp, objects, containers, admission, resources, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Admits the signing certificate identifier references the signature carries, each paired with the object it
    /// names when that object is among the certificates the signature carries.
    /// </summary>
    /// <param name="signature">The signature's facts.</param>
    /// <param name="references">The reference set being built.</param>
    /// <param name="resources">The ledger the computed digests are tracked in.</param>
    /// <param name="pool">The memory pool the digests are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    private static async ValueTask AddSigningCertificateReferencesAsync(
        SignatureFacts signature,
        List<ProtectedObjectReference> references,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        for(int i = 0; i < signature.SigningCertificateReferences.Count; ++i)
        {
            SigningCertificateReference reference = signature.SigningCertificateReferences[i];
            PkiDigestAlgorithm? algorithm = PkiDigestAlgorithm.FromOid(reference.DigestAlgorithm.Oid);
            if(reference.CertificateDigest is null || algorithm is null)
            {
                //A reference under a function this library cannot compute names no object it can match, so the
                //derivation of step 4) has nothing to work from and the reference is left out.
                continue;
            }

            for(int c = 0; c < signature.EmbeddedCertificates.Count; ++c)
            {
                using DigestValue computed = await CryptographicKeyEvents.ComputeDigestAsync(
                    signature.EmbeddedCertificates[c].AsReadOnlyMemory(), algorithm.Value.OutputByteLength, algorithm.Value.DigestTag, pool,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
                if(!computed.AsReadOnlySpan().SequenceEqual(reference.CertificateDigest.AsReadOnlySpan()))
                {
                    continue;
                }

                ValidationObjectIdentity referenced = await CreateIdentityAsync(
                    signature.EmbeddedCertificates[c].AsReadOnlyMemory(), ValidationObjectKind.Certificate, reference: null, resources, pool, cancellationToken).ConfigureAwait(false);
                references.Add(new ProtectedObjectReference(referenced, reference.DigestAlgorithm));

                break;
            }
        }
    }


    /// <summary>
    /// Admits every time-stamp token the signature carries other than the one being extracted from, which is
    /// what "the whole signature except the last archive time-stamp" means for an archive time-stamp, and queues
    /// each of them for the closure of step 2).
    /// </summary>
    /// <param name="signature">The signature's facts.</param>
    /// <param name="timestamp">The time-stamp being extracted from.</param>
    /// <param name="objects">The set being built.</param>
    /// <param name="containers">The stack of objects whose contents step 2) still has to admit.</param>
    /// <param name="admission">The binding's object-granular narrowing of step 1), or <see langword="null"/> when the class rule stands unnarrowed.</param>
    /// <param name="resources">The ledger the computed digests are tracked in.</param>
    /// <param name="pool">The memory pool the digests are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <remarks>
    /// A token the filter denies is neither admitted nor queued for the closure of step 2): its own contents are
    /// no better protected than it is, and a later archive time-stamp of the same signature is exactly such a
    /// token — carried in an unsigned attribute this one's index cannot name, because it did not yet exist.
    /// </remarks>
    private static async ValueTask AddEarlierTimestampsAsync(
        SignatureFacts signature,
        EmbeddedTimestamp timestamp,
        List<ValidationObjectIdentity> objects,
        Stack<PkiCertificateMemory> containers,
        ProtectedObjectAdmission? admission,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        for(int i = 0; i < signature.Timestamps.Count; ++i)
        {
            EmbeddedTimestamp candidate = signature.Timestamps[i];
            if(ReferenceEquals(candidate, timestamp) || candidate.Token.Equals(timestamp.Token))
            {
                continue;
            }

            if(!await AdmitsAsync(admission, candidate.Token, ValidationObjectKind.TimestampToken, pool, cancellationToken).ConfigureAwait(false))
            {
                continue;
            }

            objects.Add(await CreateIdentityAsync(
                candidate.Token.AsReadOnlyMemory(), ValidationObjectKind.TimestampToken, candidate.Identifier, resources, pool, cancellationToken).ConfigureAwait(false));
            containers.Push(candidate.Token);
        }
    }


    /// <summary>
    /// Admits every carrier of a list as an object of a stated kind, less the ones the binding's object-granular
    /// filter shows the time-stamp does not protect.
    /// </summary>
    /// <param name="carriers">The carriers to admit.</param>
    /// <param name="kind">What the carriers are.</param>
    /// <param name="objects">The set being built.</param>
    /// <param name="admission">The binding's object-granular narrowing of step 1), or <see langword="null"/> when the class rule stands unnarrowed.</param>
    /// <param name="resources">The ledger the computed digests are tracked in.</param>
    /// <param name="pool">The memory pool the digests are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    private static async ValueTask AddCarriersAsync(
        IReadOnlyList<PkiCertificateMemory> carriers,
        ValidationObjectKind kind,
        List<ValidationObjectIdentity> objects,
        ProtectedObjectAdmission? admission,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        for(int i = 0; i < carriers.Count && objects.Count < MaximumProtectedObjects; ++i)
        {
            if(!await AdmitsAsync(admission, carriers[i], kind, pool, cancellationToken).ConfigureAwait(false))
            {
                continue;
            }

            ValidationObjectIdentity identity = await CreateIdentityAsync(
                carriers[i].AsReadOnlyMemory(), kind, reference: null, resources, pool, cancellationToken).ConfigureAwait(false);
            if(!objects.Contains(identity))
            {
                objects.Add(identity);
            }
        }
    }


    /// <summary>
    /// Asks the binding's object-granular filter whether one candidate object may join the set.
    /// </summary>
    /// <param name="admission">The filter and the two inputs it needs, or <see langword="null"/> when no binding stated one.</param>
    /// <param name="candidate">The candidate object.</param>
    /// <param name="kind">What the candidate is.</param>
    /// <param name="pool">The memory pool the filter rents any scratch buffer from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when the object may join the set.</returns>
    /// <remarks>
    /// No filter means the per-class admission of clause 5.6.3.1 stands: this returns <see langword="true"/> and
    /// nothing about the surrounding algorithm changes. A filter that throws has not shown the object to be
    /// protected, which is the fail-closed answer the same way an unstatable coverage is.
    /// </remarks>
    private static async ValueTask<bool> AdmitsAsync(
        ProtectedObjectAdmission? admission,
        PkiCertificateMemory candidate,
        ValidationObjectKind kind,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        if(admission is null)
        {
            return true;
        }

        try
        {
            return await admission.States(
                new TimestampProtectedObjectContext
                {
                    Signature = admission.Signature,
                    Timestamp = admission.Timestamp,
                    Object = candidate,
                    Kind = kind
                },
                pool,
                cancellationToken).ConfigureAwait(false);
        }
        catch(Exception exception) when(exception is not OperationCanceledException)
        {
            //A binding that cannot decide about an object has not shown the time-stamp protects it.
            return false;
        }
    }


    /// <summary>
    /// The binding's object-granular narrowing of step 1) together with the two inputs every call of it needs, so
    /// the filter travels through the walk as one explicit parameter rather than as data captured in a closure.
    /// </summary>
    [DebuggerDisplay("ProtectedObjectAdmission: {Timestamp.Class} from {Timestamp.Identifier}")]
    private sealed record ProtectedObjectAdmission
    {
        /// <summary>The binding's filter.</summary>
        public required StateTimestampProtectsObjectAsyncDelegate States { get; init; }

        /// <summary>The signature every candidate object is asked about.</summary>
        public required SignatureFacts Signature { get; init; }

        /// <summary>The time-stamp every candidate object is asked about.</summary>
        public required EmbeddedTimestamp Timestamp { get; init; }
    }
}
