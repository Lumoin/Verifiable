using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Creates a CAdES-B-B signature
/// (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1</see>): the baseline signed-attribute set of clauses 5.1/5.2.1/5.2.2 plus the
/// <see href="https://www.rfc-editor.org/rfc/rfc5652">RFC 5652</see> CMS <c>SignedData</c> envelope.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The three-phase split is the API's spine.</strong> <see cref="PrepareAsync"/> assembles the signed
/// attributes and returns the exact octets a signer signs (the inverse of
/// <see cref="ManagedCmsVerification"/>'s <c>ReencodeSignedAttributes</c>, authored through
/// <see cref="CmsSignedAttributesEncoding"/>) together with their digest;
/// <see cref="Complete(CAdESSignaturePreparation, PkiCertificateMemory, CryptoAlgorithm, ReadOnlyMemory{byte}, IReadOnlyList{PkiCertificateMemory}?, MemoryPool{byte})"/> takes a
/// signature value produced however the caller obtained it and assembles the final <c>SignedData</c>;
/// <see cref="SignAsync(PkiCertificateMemory, PrivateKeyMemory, ReadOnlyMemory{byte}?, ReadOnlyMemory{byte}?, DateTimeOffset, IReadOnlyList{PkiCertificateMemory}?, CryptographicConstraints?, bool, MemoryPool{byte}, CancellationToken)"/>
/// composes both phases around a <see cref="SigningDelegate"/> resolved from the signer's <see cref="Tag"/>
/// through <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> — the same shape
/// <see cref="Verifiable.JCose.Cose"/>'s <c>SignAsync</c> uses for COSE_Sign1. A remote signer (CSC,
/// ETSI TS 119 432) consumes phases 1 and 2 unchanged: it never sees a private key, only the bytes-to-sign
/// phase 1 returns and the signature value it hands to phase 2.
/// </para>
/// <para>
/// <strong>Byte-exact reuse.</strong> Every completion here writes <see cref="CAdESSignaturePreparation.EmbeddedForm"/>
/// verbatim into <c>SignerInfo.signedAttrs</c> — the same octets the digest and the signature were computed
/// over, so nothing is re-encoded between preparation and completion.
/// </para>
/// <para>
/// <strong>Version rules (clause 4.4).</strong> Clause 4.4 delegates the <c>CMSVersion</c> of both
/// <c>SignedData</c> and <c>SignerInfo</c> to the version-assignment rule of
/// <see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.1">RFC 5652 §5.1</see>. This surface always
/// emits <c>eContentType = id-data</c> (requirement f), an <c>IssuerAndSerialNumber</c>
/// <c>SignerIdentifier</c>, no attribute certificates, and no other-format certificate or revocation member —
/// the single branch of that rule's cascade that assigns 1 — so both versions are hard-coded to 1. A later
/// validation-data placement that embeds an other-format revocation member raises <c>SignedData.version</c>
/// to 5, as the same §5.1 rule requires; that is <see cref="CAdESSignatureAugmentation"/>'s concern, not this
/// creation surface's. The degenerate no-signer case (clause 4.6) cannot arise: every completion writes at
/// least one <c>SignerInfo</c>, and the multi-signer
/// <see cref="Complete(IReadOnlyList{CAdESSignerCompletion}, IReadOnlyList{PkiCertificateMemory}?, MemoryPool{byte})"/>
/// refuses an empty signer list.
/// </para>
/// <para>
/// <strong>Parallel signers share the same three phases too.</strong> Several signers of the same content
/// stand side by side as sibling <c>SignerInfo</c> structures (RFC 5652 §5.1, more than one signer), each a
/// whole CAdES signer with its own signed attributes: <see cref="PrepareParallelSignatureAsync"/> prepares
/// the attribute set over an existing structure's own <c>eContent</c> (or the detached content's digest
/// carrier), <see cref="CompleteParallelSignature"/> assembles the whole <c>SignerInfo</c> through the same
/// writer, and <see cref="CmsSignedDataAugmentation.AddSignerInfo"/> places it while preserving every octet
/// already there;
/// <see cref="AddParallelSignatureAsync(CmsSignedData, PkiCertificateMemory, PrivateKeyMemory, DigestValue?, DateTimeOffset, CryptographicConstraints?, bool, MemoryPool{byte}, CancellationToken, CAdESOptionalSignedAttributes?)"/>
/// composes the three. Signers completing one fresh <c>SignedData</c> together go through the multi-signer
/// <see cref="Complete(IReadOnlyList{CAdESSignerCompletion}, IReadOnlyList{PkiCertificateMemory}?, MemoryPool{byte})"/>
/// instead, and the per-signer verification addressing of a multi-signer structure is
/// <see cref="CmsSignedDataReduction.SelectSigner"/>'s projection.
/// </para>
/// <para>
/// <strong>Algorithm gating (R-8).</strong> MD5 is refused unconditionally and SHA-1 is refused as a
/// creation-side digest (<see cref="EnsureDigestAlgorithmAllowedForCreation"/>) — the consequence is that
/// this surface emits ESS <c>signing-certificate-v2</c> only, never the SHA-1-only v1 form (requirement i).
/// A caller-supplied dated <see cref="CryptographicConstraints"/> table is additionally consulted at the
/// signing instant; without one, only the hard MD5/SHA-1 refusals apply. Only P-256/P-384/P-521 (ECDSA) and
/// RSA-2048/4096 (RSASSA-PKCS1-v1.5 with SHA-256) signers are supported (<see cref="ResolveSigningProfile"/>);
/// an optional <c>cms-algorithm-protection</c> attribute (RFC 6211) may be added — Table 1 NOTE 8's
/// algorithm-substitution rationale, most relevant for ECDSA/RSA-PSS signers whose signature scheme does not
/// otherwise bind the digest algorithm.
/// </para>
/// <para>
/// Creation-side failures are typed exceptions (<see cref="ArgumentException"/>, <see cref="NotSupportedException"/>),
/// never the validation-side <see cref="SignatureValidationConclusion"/> model, matching the JCose/COSE
/// creation precedent.
/// </para>
/// <para>
/// <strong>Optional Table 1 attributes.</strong> <see cref="PrepareAsync"/>'s trailing
/// <see cref="CAdESOptionalSignedAttributes"/> parameter carries the "may be present"/"should be present"
/// signed attributes of clause 6.3 (<c>commitment-type-indication</c>, <c>content-hints</c>/<c>mime-type</c>,
/// <c>signer-location</c>, <c>content-reference</c>, <c>content-identifier</c>, <c>signature-policy-identifier</c>,
/// <c>signer-attributes-v2</c>, <c>content-time-stamp</c>) as one options record — the "options record for the OPTIONAL attribute set only"
/// this file's own flag authorized, rather than growing <see cref="PrepareAsync"/>'s already-wide flat parameter
/// list further. It is appended as the LAST parameter of every public entry point here, after
/// <c>cancellationToken</c>, deliberately out of the usual "cancellation token last" convention: every existing
/// positional call this wave's earlier stages wrote ends at <c>cancellationToken</c>, and a new trailing optional
/// parameter never breaks a shorter positional call, while inserting it earlier would silently retarget those
/// calls' final positional argument. <c>signature-policy-store</c> (clause 5.2.10) is unsigned and therefore not
/// part of this record; it is added after signing, through
/// <see cref="CAdESSignatureAugmentation.AddSignaturePolicyStore"/>.
/// </para>
/// <para>
/// <strong>Countersignatures share the same three phases.</strong> A <c>countersignature</c> (clause 5.2.7,
/// <see href="https://www.rfc-editor.org/rfc/rfc5652#section-11.4">RFC 5652 §11.4</see>) is itself a
/// <c>SignerInfo</c>, signed over the outer <c>SignerInfo.signature</c> value octets and carrying no
/// <c>content-type</c> attribute, so it is produced here rather than by a separate signing path:
/// <see cref="PrepareCountersignatureAsync"/>, <see cref="CompleteCountersignature"/>, and
/// <see cref="CountersignAsync(CmsSignedData, int, PkiCertificateMemory, PrivateKeyMemory, DateTimeOffset, CryptographicConstraints?, bool, MemoryPool{byte}, CancellationToken)"/>
/// mirror the three phases above and reuse the same attribute builders, the same R-8 algorithm gate, the same
/// signing-profile resolution and the same <c>SignerInfo</c> writer. It becomes an unsigned attribute of the
/// signature it counters through <see cref="CAdESSignatureAugmentation.AddCountersignatureAsync"/>, which is the
/// byte-preserving splice.
/// </para>
/// </remarks>
public static class CAdESSignatureCreation
{
    /// <summary>The id-signedData content type (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.1">RFC 5652 §5.1</see>).</summary>
    private const string SignedDataOid = "1.2.840.113549.1.7.2";

    /// <summary>The id-data content type (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-4">RFC 5652 §4</see>) — the only <c>eContentType</c> this surface emits (requirement f).</summary>
    private const string DataOid = "1.2.840.113549.1.7.1";

    /// <summary>The <c>id-aa-cmsAlgorithmProtect</c> attribute (<see href="https://www.rfc-editor.org/rfc/rfc6211#section-3">RFC 6211 §3</see>).</summary>
    private const string CmsAlgorithmProtectionAttributeOid = "1.2.840.113549.1.9.52";

    /// <summary>The MD5 digest algorithm (<see href="https://www.rfc-editor.org/rfc/rfc1319">RFC 1319</see>) — refused unconditionally, clause 6.2.1.</summary>
    private const string Md5Oid = "1.2.840.113549.2.5";

    /// <summary>The <c>ecdsa-with-SHA256</c> signature algorithm (<see href="https://www.rfc-editor.org/rfc/rfc3279#section-2.2.3">RFC 3279 §2.2.3</see>, as updated by RFC 5480).</summary>
    private const string EcdsaWithSha256Oid = "1.2.840.10045.4.3.2";

    /// <summary>The <c>ecdsa-with-SHA384</c> signature algorithm.</summary>
    private const string EcdsaWithSha384Oid = "1.2.840.10045.4.3.3";

    /// <summary>The <c>ecdsa-with-SHA512</c> signature algorithm.</summary>
    private const string EcdsaWithSha512Oid = "1.2.840.10045.4.3.4";

    /// <summary>The <c>sha256WithRSAEncryption</c> signature algorithm (<see href="https://www.rfc-editor.org/rfc/rfc8017">RFC 8017</see>) — the only RSA signature scheme this surface emits, matching <see cref="ManagedCmsVerification"/>'s RSA verification support.</summary>
    private const string Sha256WithRsaEncryptionOid = WellKnownOids.Sha256WithRsaEncryption;

    /// <summary>The <c>CMSVersion</c> both <c>SignedData</c> and <c>SignerInfo</c> carry: clause 4.4 delegates it to RFC 5652 §5.1's version-assignment rule, whose cascade yields 1 for the <c>eContentType = id-data</c> / <c>IssuerAndSerialNumber</c> / no-attribute-certificate / no-other-format combination this surface always produces.</summary>
    private const int CmsVersion1 = 1;

    /// <summary>The largest encoded attribute value this surface stack-allocates a scratch buffer for before falling back to the heap; every value this surface builds (a hash, an OID, a short SEQUENCE) fits well within it.</summary>
    private const int MaximumStackAllocatedAttributeValueLength = 512;

    /// <summary>The <c>[0]</c> constructed context tag: <c>ContentInfo.content</c>, <c>SignedData.certificates</c>, <c>SignerInfo.signedAttrs</c> (already DER-encoded and spliced in verbatim, so not written through this tag directly), <c>SignerLocation.countryName</c> (clause 5.2.5), and <c>SignerAttributeV2.claimedAttributes</c> (clause 5.2.6.1).</summary>
    private static Asn1Tag ContextConstructed0 { get; } = new(TagClass.ContextSpecific, 0, isConstructed: true);

    /// <summary>The <c>[1]</c> constructed context tag: <c>SignerInfo.unsignedAttrs</c> (RFC 5652 §5.3), <c>CMSAlgorithmProtection.signatureAlgorithm</c> (RFC 6211 §3), and <c>SignerLocation.localityName</c> (clause 5.2.5).</summary>
    private static Asn1Tag ContextConstructed1 { get; } = new(TagClass.ContextSpecific, 1, isConstructed: true);

    /// <summary>The <c>[2]</c> constructed context tag: <c>SignerLocation.postalAddress</c> (clause 5.2.5).</summary>
    private static Asn1Tag ContextConstructed2 { get; } = new(TagClass.ContextSpecific, 2, isConstructed: true);


    /// <summary>
    /// Assembles the CAdES-B-B signed attributes — phase (1) of the data-to-sign/signature-value split —
    /// and returns the octets a signer signs together with their digest.
    /// </summary>
    /// <param name="signerCertificate">The signer's own certificate, hashed into the ESS <c>signing-certificate-v2</c> attribute.</param>
    /// <param name="content">The content to sign, attached (§4.5): its digest is computed here and <c>eContent</c> is embedded. Exactly one of this and <paramref name="detachedContentDigest"/> must be supplied.</param>
    /// <param name="detachedContentDigest">A caller-computed digest of externally-held content (§4.5, detached): <c>eContent</c> is omitted. Must be exactly <paramref name="messageDigestAlgorithm"/>'s output length.</param>
    /// <param name="messageDigestAlgorithm">The digest algorithm for <c>message-digest</c> (RFC 5652 §5.4), the ESS certificate hash, and — when supplied — <c>SignerInfo.digestAlgorithm</c>'s eventual value.</param>
    /// <param name="signingTime">The <c>signing-time</c> attribute value and the instant a supplied <paramref name="algorithmConstraints"/> table is assessed at.</param>
    /// <param name="algorithmConstraints">A caller-supplied dated cryptographic-constraints table (ETSI EN 319 102-1 clause 5.1.4.3); when supplied, <paramref name="messageDigestAlgorithm"/> must be asserted reliable at <paramref name="signingTime"/>. <see langword="null"/> applies only the hard MD5/SHA-1 refusals.</param>
    /// <param name="cmsAlgorithmProtectionSignatureAlgorithmOid">When non-<see langword="null"/>, adds the opt-in <c>cms-algorithm-protection</c> attribute (RFC 6211) naming this signature algorithm alongside <paramref name="messageDigestAlgorithm"/>.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <param name="optionalAttributes">The opt-in Table 1 attribute set of clause 6.3 (<see cref="CAdESOptionalSignedAttributes"/>), or <see langword="null"/> to add none of them.</param>
    /// <returns>The prepared signed attributes. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signerCertificate"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When neither or both of <paramref name="content"/>/<paramref name="detachedContentDigest"/> are supplied, <paramref name="detachedContentDigest"/>'s length does not match <paramref name="messageDigestAlgorithm"/>, or an optional attribute in <paramref name="optionalAttributes"/> is malformed.</exception>
    /// <exception cref="NotSupportedException">When <paramref name="messageDigestAlgorithm"/> is MD5, SHA-1, an unrecognised digest, or a supplied <paramref name="algorithmConstraints"/> table does not assert it reliable at <paramref name="signingTime"/>.</exception>
    /// <exception cref="TimestampAcquisitionException">When a requested <c>content-time-stamp</c> token could not be acquired or verified (<see cref="CAdESOptionalSignedAttributes.ContentTimestampRequests"/>).</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the two encoded carriers and the digest transfers to the returned preparation, which the caller disposes; the catch disposes the source attributes and, on later failure, the encoding's own carriers.")]
    [SuppressMessage("Design", "CA1068:CancellationToken parameters must come last",
        Justification = "optionalAttributes is deliberately the LAST parameter, after cancellationToken (see the class remarks): every positional call this wave's earlier stages wrote ends at cancellationToken, and a new trailing optional parameter never breaks a shorter positional call, while inserting it before cancellationToken would silently retarget those calls' final positional argument.")]
    public static async ValueTask<CAdESSignaturePreparation> PrepareAsync(
        PkiCertificateMemory signerCertificate,
        ReadOnlyMemory<byte>? content,
        ReadOnlyMemory<byte>? detachedContentDigest,
        PkiDigestAlgorithm messageDigestAlgorithm,
        DateTimeOffset signingTime,
        CryptographicConstraints? algorithmConstraints,
        string? cmsAlgorithmProtectionSignatureAlgorithmOid,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default,
        CAdESOptionalSignedAttributes? optionalAttributes = null)
    {
        ArgumentNullException.ThrowIfNull(signerCertificate);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        if(content is null == detachedContentDigest is null)
        {
            throw new ArgumentException(
                "Exactly one of content (attached, clause 4.5) or detachedContentDigest (detached, clause 4.5) must be supplied.",
                nameof(content));
        }

        EnsureDigestAlgorithmAllowedForCreation(messageDigestAlgorithm, algorithmConstraints, signingTime);

        if(detachedContentDigest is { } suppliedDigest && suppliedDigest.Length != messageDigestAlgorithm.OutputByteLength)
        {
            throw new ArgumentException(
                $"A detached content digest must be exactly {messageDigestAlgorithm.OutputByteLength} bytes for '{messageDigestAlgorithm.Identifier.Oid}'.",
                nameof(detachedContentDigest));
        }

        DigestValue? messageDigest = null;
        List<CmsAttribute> attributes = [];
        try
        {
            //The attached case computes the content digest; the detached case wraps the caller-supplied octets
            //in the same tagged carrier, so the message-digest attribute and the content-time-stamp acquisition
            //consume one semantic digest whichever way the content arrived.
            messageDigest = content is { } attachedContent
                ? await CryptographicKeyEvents.ComputeDigestAsync(
                    attachedContent, messageDigestAlgorithm.OutputByteLength, messageDigestAlgorithm.DigestTag, pool,
                    cancellationToken: cancellationToken).ConfigureAwait(false)
                : WrapDetachedDigest(detachedContentDigest!.Value, messageDigestAlgorithm, pool);

            using DigestValue certificateHash = await CryptographicKeyEvents.ComputeDigestAsync(
                signerCertificate.AsReadOnlyMemory(), messageDigestAlgorithm.OutputByteLength, messageDigestAlgorithm.DigestTag, pool,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            attributes.Add(BuildContentTypeAttribute(pool));
            attributes.Add(BuildMessageDigestAttribute(messageDigest.AsReadOnlySpan(), pool));
            attributes.Add(BuildSigningTimeAttribute(signingTime, pool));
            attributes.Add(BuildSigningCertificateV2Attribute(certificateHash.AsReadOnlySpan(), messageDigestAlgorithm, pool));
            if(cmsAlgorithmProtectionSignatureAlgorithmOid is not null)
            {
                attributes.Add(BuildCmsAlgorithmProtectionAttribute(messageDigestAlgorithm, cmsAlgorithmProtectionSignatureAlgorithmOid, pool));
            }

            if(optionalAttributes is not null)
            {
                if(optionalAttributes.CommitmentType is { } commitmentType)
                {
                    attributes.Add(BuildCommitmentTypeIndicationAttribute(commitmentType, pool));
                }

                if(optionalAttributes.ContentHints is { } contentHints)
                {
                    attributes.Add(BuildContentHintsAttribute(contentHints, pool));
                }

                if(optionalAttributes.MimeType is { } mimeType)
                {
                    attributes.Add(BuildMimeTypeAttribute(mimeType, pool));
                }

                if(optionalAttributes.SignerLocation is { } signerLocation)
                {
                    attributes.Add(BuildSignerLocationAttribute(signerLocation, pool));
                }

                if(optionalAttributes.ContentReference is { } contentReference)
                {
                    attributes.Add(BuildContentReferenceAttribute(contentReference, pool));
                }

                if(optionalAttributes.ContentIdentifier is { } contentIdentifier)
                {
                    attributes.Add(BuildContentIdentifierAttribute(contentIdentifier.Span, pool));
                }

                if(optionalAttributes.SignaturePolicyIdentifier is { } signaturePolicyIdentifier)
                {
                    attributes.Add(BuildSignaturePolicyIdentifierAttribute(signaturePolicyIdentifier, pool));
                }

                if(optionalAttributes.SignerAttributes is { } signerAttributes)
                {
                    attributes.Add(BuildSignerAttributesV2Attribute(signerAttributes, pool));
                }

                if(optionalAttributes.ContentTimestampRequests is { Count: > 0 } contentTimestampRequests)
                {
                    attributes.Add(await BuildContentTimestampAttributeAsync(
                        contentTimestampRequests, messageDigest, pool, cancellationToken).ConfigureAwait(false));
                }
            }

            //Ownership of both encoded carriers transfers directly to the returned preparation below; the
            //CmsSignedAttributesEncoding wrapper itself holds no resource of its own beyond them.
            CmsSignedAttributesEncoding encoding = CmsSignedAttributesEncoding.Create(attributes, pool);
            DisposeAll(attributes);
            attributes.Clear();

            try
            {
                DigestValue signingInputDigest = await CryptographicKeyEvents.ComputeDigestAsync(
                    encoding.SigningInput.AsReadOnlyMemory(), messageDigestAlgorithm.OutputByteLength, messageDigestAlgorithm.DigestTag, pool,
                    cancellationToken: cancellationToken).ConfigureAwait(false);

                //The content commitment transfers to the preparation (its ContentDigest), so the finally
                //below releases it only on a failure path.
                CAdESSignaturePreparation preparation = new(encoding.SigningInput, encoding.EmbeddedForm, signingInputDigest, messageDigest, messageDigestAlgorithm, content);
                messageDigest = null;

                return preparation;
            }
            catch
            {
                encoding.SigningInput.Dispose();
                encoding.EmbeddedForm.Dispose();

                throw;
            }
        }
        catch
        {
            DisposeAll(attributes);

            throw;
        }
        finally
        {
            messageDigest?.Dispose();
        }


        //Wraps a caller-supplied detached content digest in the tagged carrier the message-digest attribute and
        //the content-time-stamp acquisition consume; copied because the carrier owns its memory.
        static DigestValue WrapDetachedDigest(ReadOnlyMemory<byte> digest, PkiDigestAlgorithm algorithm, MemoryPool<byte> pool)
        {
            IMemoryOwner<byte> owner = pool.Rent(digest.Length);
            digest.Span.CopyTo(owner.Memory.Span);

            return new DigestValue(owner, algorithm.DigestTag);
        }
    }


    /// <summary>
    /// Assembles the final CAdES-B-B <c>SignedData</c> — phase (2) of the split — from a signature value
    /// produced however the caller obtained it.
    /// </summary>
    /// <param name="preparation">The prepared signed attributes from <see cref="PrepareAsync"/>.</param>
    /// <param name="signerCertificate">The signer certificate; placed first in <c>SignedData.certificates</c> (requirement a).</param>
    /// <param name="signingAlgorithm">The algorithm the signature value was produced under, resolving <c>SignerInfo.signatureAlgorithm</c> (<see cref="ResolveSigningProfile"/>).</param>
    /// <param name="signatureValue">The externally produced signature value, already in its final wire encoding (a DER <c>Ecdsa-Sig-Value</c> for an ECDSA signer, the raw RSA signature for an RSA signer).</param>
    /// <param name="additionalCertificates">Further certificates for <c>SignedData.certificates</c> (chain, revocation-signer, TSA certificates — requirement d); an entry identical to <paramref name="signerCertificate"/>'s own DER is skipped (requirement e, avoid duplication).</param>
    /// <param name="pool">The memory pool the returned carrier is rented from.</param>
    /// <returns>The completed CAdES-B-B <c>SignedData</c> wire bytes. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="preparation"/>, <paramref name="signerCertificate"/>, or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="signatureValue"/> is empty, or <paramref name="signingAlgorithm"/>'s natural digest does not match the digest <paramref name="preparation"/> was built under.</exception>
    /// <exception cref="NotSupportedException">When <paramref name="signingAlgorithm"/> is not one <see cref="ResolveSigningProfile"/> recognises.</exception>
    public static CmsSignedData Complete(
        CAdESSignaturePreparation preparation,
        PkiCertificateMemory signerCertificate,
        CryptoAlgorithm signingAlgorithm,
        ReadOnlyMemory<byte> signatureValue,
        IReadOnlyList<PkiCertificateMemory>? additionalCertificates,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(preparation);
        ArgumentNullException.ThrowIfNull(signerCertificate);

        return Complete(
            [new CAdESSignerCompletion(preparation, signerCertificate, signingAlgorithm, signatureValue)],
            additionalCertificates,
            pool);
    }


    /// <summary>
    /// Assembles a CAdES-B-B <c>SignedData</c> carrying one <c>SignerInfo</c> per signer — the multi-signer
    /// shape of <see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.1">RFC 5652 §5.1</see>, where
    /// several signers sign the same content side by side — from signature values produced however each
    /// signer obtained them.
    /// </summary>
    /// <param name="signers">One completion per signer: the prepared signed attributes from <see cref="PrepareAsync"/>, the signer certificate, the signing algorithm, and the externally produced signature value. At least one; RFC 5652 §5.1 has <c>signerInfos</c> as a set of these, and the degenerate certificate-only form (clause 4.6) is not a signature this surface produces.</param>
    /// <param name="additionalCertificates">Further certificates for <c>SignedData.certificates</c> (chains, revocation-signer, TSA certificates — requirement d); an entry whose DER is identical to one already placed is skipped (requirement e, avoid duplication).</param>
    /// <param name="pool">The memory pool the returned carrier is rented from.</param>
    /// <returns>The completed CAdES-B-B <c>SignedData</c> wire bytes. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signers"/>, one of its entries or their members, or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="signers"/> is empty, a signature value is empty, a signing algorithm's natural digest does not match the digest its preparation was built under, or the preparations disagree on the content (attached against detached, differing attached octets, or two detached preparations under one digest algorithm stating different <c>message-digest</c> values — one <c>encapContentInfo</c> holds one content; detached signers under different algorithms cannot be compared without the content and are accepted, which mixed classical-plus-post-quantum signing legitimately needs).</exception>
    /// <exception cref="NotSupportedException">When a signing algorithm is not one <see cref="ResolveSigningProfile"/> recognises.</exception>
    /// <remarks>
    /// <para>
    /// Each signer's <c>SignerInfo</c> stands alone — its signature covers its own signed attributes and the
    /// shared content, never a sibling's — so every entry is validated exactly as the single-signer
    /// <see cref="Complete(CAdESSignaturePreparation, PkiCertificateMemory, CryptoAlgorithm, ReadOnlyMemory{byte}, IReadOnlyList{PkiCertificateMemory}?, MemoryPool{byte})"/>
    /// validates its one signer, and the single-signer form is this method over one entry.
    /// </para>
    /// <para>
    /// <c>digestAlgorithms</c> lists each distinct digest algorithm once (§5.1's collection "intended to
    /// list" each signer's); <c>CMSVersion</c> stays 1, because every <c>SignerInfo</c> written here is
    /// version 1 with an <c>IssuerAndSerialNumber</c> identifier and <c>eContentType</c> is <c>id-data</c>
    /// (the same §5.1 cascade branch the class remarks state). The writer emits DER, so both
    /// <c>SET OF</c> fields — <c>digestAlgorithms</c> and <c>signerInfos</c> — leave in X.690 clause 11.6
    /// order whatever order the entries arrived in.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented buffer transfers to the returned carrier, which the caller disposes; the catch disposes it on a partial failure.")]
    public static CmsSignedData Complete(
        IReadOnlyList<CAdESSignerCompletion> signers,
        IReadOnlyList<PkiCertificateMemory>? additionalCertificates,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(signers);
        ArgumentNullException.ThrowIfNull(pool);
        if(signers.Count == 0)
        {
            throw new ArgumentException(
                "A SignedData this surface produces carries at least one SignerInfo; the degenerate certificate-only form (clause 4.6) is not a signature.",
                nameof(signers));
        }

        //Every entry is validated before the first octet is written, so a refusal leaves no partial output.
        var profiles = new CAdESSigningProfile[signers.Count];
        var parsedSigners = new ManagedCertificate[signers.Count];
        ReadOnlyMemory<byte>? content = null;
        for(int i = 0; i < signers.Count; ++i)
        {
            CAdESSignerCompletion signer = signers[i];
            ArgumentNullException.ThrowIfNull(signer, nameof(signers));
            ArgumentNullException.ThrowIfNull(signer.Preparation, nameof(signers));
            ArgumentNullException.ThrowIfNull(signer.SignerCertificate, nameof(signers));
            if(signer.SignatureValue.IsEmpty)
            {
                throw new ArgumentException("An externally produced signature value is required to complete a CAdES signature.", nameof(signers));
            }

            profiles[i] = ResolveSigningProfile(signer.SigningAlgorithm);
            if(!string.Equals(profiles[i].DigestAlgorithm.Identifier.Oid, signer.Preparation.MessageDigestAlgorithm.Identifier.Oid, StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    $"Signing algorithm '{signer.SigningAlgorithm}' expects digest '{profiles[i].DigestAlgorithm.Identifier.Oid}', but the prepared signed attributes were built under '{signer.Preparation.MessageDigestAlgorithm.Identifier.Oid}'.",
                    nameof(signers));
            }

            if(i == 0)
            {
                content = signer.Preparation.Content;
            }
            else if(signer.Preparation.Content is null != content is null)
            {
                throw new ArgumentException(
                    "Every parallel signer signs the same content the same way: all preparations attached or all detached, because one encapContentInfo holds one content (RFC 5652 §5.1).",
                    nameof(signers));
            }
            else if(signer.Preparation.Content is { } thisContent && !thisContent.Span.SequenceEqual(content!.Value.Span))
            {
                throw new ArgumentException(
                    "The prepared content octets differ between signers; parallel SignerInfo structures share one eContent (RFC 5652 §5.1).",
                    nameof(signers));
            }

            if(i > 0 && signer.Preparation.Content is null)
            {
                //Detached signers under one digest algorithm commit to one message-digest value; under
                //different algorithms the external content is not here to compare, which mixed
                //classical-plus-post-quantum signing legitimately needs.
                for(int j = 0; j < i; ++j)
                {
                    if(string.Equals(signers[j].Preparation.MessageDigestAlgorithm.Identifier.Oid, signer.Preparation.MessageDigestAlgorithm.Identifier.Oid, StringComparison.Ordinal)
                        && !signers[j].Preparation.ContentDigest.AsReadOnlySpan().SequenceEqual(signer.Preparation.ContentDigest.AsReadOnlySpan()))
                    {
                        throw new ArgumentException(
                            "Two detached preparations under one digest algorithm state different message-digest values; parallel signers sign the same content (RFC 5652 §5.1), and a differing commitment is the substitution shape this surface refuses.",
                            nameof(signers));
                    }
                }
            }

            parsedSigners[i] = ManagedCertificate.Parse(signer.SignerCertificate.AsReadOnlyMemory());
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())                                          //ContentInfo
        {
            writer.WriteObjectIdentifier(SignedDataOid);
            using(writer.PushSequence(ContextConstructed0))                   //content [0] EXPLICIT
            {
                using(writer.PushSequence())                                  //SignedData
                {
                    writer.WriteInteger(CmsVersion1);
                    using(writer.PushSetOf())                                 //digestAlgorithms
                    {
                        //One DigestAlgorithmIdentifier per distinct algorithm: the collection lists each
                        //signer's algorithm once, however many signers share it (RFC 5652 §5.1).
                        for(int i = 0; i < signers.Count; ++i)
                        {
                            if(!AppearsEarlier(signers, i))
                            {
                                WriteDigestAlgorithmIdentifier(writer, signers[i].Preparation.MessageDigestAlgorithm);
                            }
                        }
                    }

                    using(writer.PushSequence())                              //encapContentInfo
                    {
                        writer.WriteObjectIdentifier(DataOid);
                        if(content is { } attachedContent)
                        {
                            using(writer.PushSequence(ContextConstructed0))   //eContent [0] EXPLICIT
                            {
                                writer.WriteOctetString(attachedContent.Span);
                            }
                        }
                    }

                    using(writer.PushSetOf(ContextConstructed0))              //certificates [0] IMPLICIT
                    {
                        //Each signer's certificate once, then the additional ones, an exact-DER duplicate
                        //skipped wherever it appears (requirement e, duplication should be avoided).
                        var writtenCertificates = new List<ReadOnlyMemory<byte>>(signers.Count + (additionalCertificates?.Count ?? 0));
                        for(int i = 0; i < signers.Count; ++i)
                        {
                            WriteCertificateOnce(writer, writtenCertificates, signers[i].SignerCertificate.AsReadOnlyMemory());
                        }

                        if(additionalCertificates is not null)
                        {
                            for(int i = 0; i < additionalCertificates.Count; ++i)
                            {
                                WriteCertificateOnce(writer, writtenCertificates, additionalCertificates[i].AsReadOnlyMemory());
                            }
                        }
                    }

                    using(writer.PushSetOf())                                 //signerInfos
                    {
                        //No unsignedAttrs at B-B (clause 6.1): level-raising augmentation adds them later,
                        //through the byte-preserving splice rather than by re-encoding this structure.
                        for(int i = 0; i < signers.Count; ++i)
                        {
                            WriteSignerInfo(writer, signers[i].Preparation, parsedSigners[i], profiles[i], signers[i].SignatureValue, unsignedAttributes: null);
                        }
                    }
                }
            }
        }

        int encodedLength = writer.GetEncodedLength();
        IMemoryOwner<byte> owner = pool.Rent(encodedLength);
        try
        {
            _ = writer.TryEncode(owner.Memory.Span, out _);

            return new CmsSignedData(owner, CryptoTags.CmsEncodedSignedData);
        }
        catch
        {
            owner.Dispose();

            throw;
        }


        //States whether an earlier signer already contributed this signer's digest algorithm to the set.
        static bool AppearsEarlier(IReadOnlyList<CAdESSignerCompletion> signers, int index)
        {
            string oid = signers[index].Preparation.MessageDigestAlgorithm.Identifier.Oid;
            for(int i = 0; i < index; ++i)
            {
                if(string.Equals(signers[i].Preparation.MessageDigestAlgorithm.Identifier.Oid, oid, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }


        //Writes a certificate unless its exact DER was already written into the open certificates set.
        static void WriteCertificateOnce(AsnWriter writer, List<ReadOnlyMemory<byte>> written, ReadOnlyMemory<byte> candidate)
        {
            for(int i = 0; i < written.Count; ++i)
            {
                if(written[i].Span.SequenceEqual(candidate.Span))
                {
                    return;
                }
            }

            writer.WriteEncodedValue(candidate.Span);
            written.Add(candidate);
        }
    }


    /// <summary>
    /// Composes <see cref="PrepareAsync"/> and
    /// <see cref="Complete(CAdESSignaturePreparation, PkiCertificateMemory, CryptoAlgorithm, ReadOnlyMemory{byte}, IReadOnlyList{PkiCertificateMemory}?, MemoryPool{byte})"/>
    /// around a <see cref="SigningDelegate"/>
    /// resolved from <paramref name="privateKey"/>'s <see cref="Tag"/> — phase (3), the convenience the
    /// registry-resolved <see cref="Verifiable.JCose.Cose"/>'s <c>SignAsync</c> overload mirrors.
    /// </summary>
    /// <param name="signerCertificate">The signer's own certificate.</param>
    /// <param name="privateKey">The signing key; its <see cref="Tag"/> resolves both the <see cref="SigningDelegate"/> and the ESS/CMS algorithm identities.</param>
    /// <param name="content">The content to sign, attached. Exactly one of this and <paramref name="detachedContentDigest"/> must be supplied.</param>
    /// <param name="detachedContentDigest">A caller-computed digest of externally-held content, detached.</param>
    /// <param name="signingTime">The <c>signing-time</c> attribute value.</param>
    /// <param name="additionalCertificates">Further certificates for <c>SignedData.certificates</c>.</param>
    /// <param name="algorithmConstraints">A caller-supplied dated cryptographic-constraints table; see <see cref="PrepareAsync"/>.</param>
    /// <param name="includeCmsAlgorithmProtection">Whether to add the opt-in <c>cms-algorithm-protection</c> attribute (RFC 6211) naming <paramref name="privateKey"/>'s signature and digest algorithms.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <param name="optionalAttributes">The opt-in Table 1 attribute set of clause 6.3; see <see cref="PrepareAsync"/>.</param>
    /// <returns>The completed CAdES-B-B <c>SignedData</c> wire bytes. The caller owns and disposes it.</returns>
    [SuppressMessage("Design", "CA1068:CancellationToken parameters must come last",
        Justification = "optionalAttributes is deliberately the LAST parameter, after cancellationToken; see PrepareAsync's remarks and its matching suppression.")]
    public static ValueTask<CmsSignedData> SignAsync(
        PkiCertificateMemory signerCertificate,
        PrivateKeyMemory privateKey,
        ReadOnlyMemory<byte>? content,
        ReadOnlyMemory<byte>? detachedContentDigest,
        DateTimeOffset signingTime,
        IReadOnlyList<PkiCertificateMemory>? additionalCertificates,
        CryptographicConstraints? algorithmConstraints,
        bool includeCmsAlgorithmProtection,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default,
        CAdESOptionalSignedAttributes? optionalAttributes = null)
    {
        ArgumentNullException.ThrowIfNull(privateKey);

        CryptoAlgorithm algorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);

        return SignAsync(
            signerCertificate, privateKey, signingDelegate, content, detachedContentDigest, signingTime,
            additionalCertificates, algorithmConstraints, includeCmsAlgorithmProtection, pool,
            cancellationToken: cancellationToken, optionalAttributes: optionalAttributes);
    }


    /// <summary>
    /// Composes <see cref="PrepareAsync"/> and
    /// <see cref="Complete(CAdESSignaturePreparation, PkiCertificateMemory, CryptoAlgorithm, ReadOnlyMemory{byte}, IReadOnlyList{PkiCertificateMemory}?, MemoryPool{byte})"/>
    /// around an explicit
    /// <see cref="SigningDelegate"/>, for a caller that has already resolved one (testing, or a custom
    /// cryptographic backend) rather than routing through the registry.
    /// </summary>
    /// <param name="signerCertificate">The signer's own certificate.</param>
    /// <param name="privateKey">The signing key; its <see cref="Tag"/> resolves the ESS/CMS algorithm identities.</param>
    /// <param name="signingDelegate">The signing delegate to invoke.</param>
    /// <param name="content">The content to sign, attached. Exactly one of this and <paramref name="detachedContentDigest"/> must be supplied.</param>
    /// <param name="detachedContentDigest">A caller-computed digest of externally-held content, detached.</param>
    /// <param name="signingTime">The <c>signing-time</c> attribute value.</param>
    /// <param name="additionalCertificates">Further certificates for <c>SignedData.certificates</c>.</param>
    /// <param name="algorithmConstraints">A caller-supplied dated cryptographic-constraints table; see <see cref="PrepareAsync"/>.</param>
    /// <param name="includeCmsAlgorithmProtection">Whether to add the opt-in <c>cms-algorithm-protection</c> attribute.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="eventSink">
    /// Receives the <see cref="SignatureProducedEvent"/> <paramref name="signingDelegate"/> constructs, or
    /// <see langword="null"/> to route it to <see cref="CryptographicKeyEvents.DefaultSink"/>.
    /// </param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <param name="optionalAttributes">The opt-in Table 1 attribute set of clause 6.3; see <see cref="PrepareAsync"/>.</param>
    /// <returns>The completed CAdES-B-B <c>SignedData</c> wire bytes. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signerCertificate"/>, <paramref name="privateKey"/>, <paramref name="signingDelegate"/>, or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="NotSupportedException">When <paramref name="privateKey"/>'s algorithm is not one <see cref="ResolveSigningProfile"/> recognises.</exception>
    [SuppressMessage("Design", "CA1068:CancellationToken parameters must come last",
        Justification = "optionalAttributes is deliberately the LAST parameter, after cancellationToken; see PrepareAsync's remarks and its matching suppression.")]
    public static async ValueTask<CmsSignedData> SignAsync(
        PkiCertificateMemory signerCertificate,
        PrivateKeyMemory privateKey,
        SigningDelegate signingDelegate,
        ReadOnlyMemory<byte>? content,
        ReadOnlyMemory<byte>? detachedContentDigest,
        DateTimeOffset signingTime,
        IReadOnlyList<PkiCertificateMemory>? additionalCertificates,
        CryptographicConstraints? algorithmConstraints,
        bool includeCmsAlgorithmProtection,
        MemoryPool<byte> pool,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default,
        CAdESOptionalSignedAttributes? optionalAttributes = null)
    {
        ArgumentNullException.ThrowIfNull(signerCertificate);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(signingDelegate);
        ArgumentNullException.ThrowIfNull(pool);

        cancellationToken.ThrowIfCancellationRequested();

        CryptoAlgorithm signingAlgorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        CAdESSigningProfile profile = ResolveSigningProfile(signingAlgorithm);
        string? cmsAlgorithmProtectionOid = includeCmsAlgorithmProtection ? profile.SignatureAlgorithmOid : null;

        using CAdESSignaturePreparation preparation = await PrepareAsync(
            signerCertificate, content, detachedContentDigest, profile.DigestAlgorithm, signingTime,
            algorithmConstraints, cmsAlgorithmProtectionOid, pool, cancellationToken, optionalAttributes).ConfigureAwait(false);

        (Signature signature, CryptoEvent? evt) = await signingDelegate(
            privateKey.AsReadOnlyMemory(), preparation.SigningInput.AsReadOnlyMemory(), pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        using(signature)
        {
            if(evt is not null)
            {
                (eventSink ?? CryptographicKeyEvents.DefaultSink)(evt);
            }

            if(profile.IsEllipticCurve)
            {
                //The registered signing seam produces the fixed-width IEEE P1363 r‖s form; CMS/X.509 wire
                //encoding requires the DER Ecdsa-Sig-Value SEQUENCE the platform and BouncyCastle readers expect.
                using IMemoryOwner<byte> derSignature = EcdsaSignatureEncoding.ConvertP1363ToDer(signature.AsReadOnlySpan(), pool, out int derLength);

                return Complete(preparation, signerCertificate, signingAlgorithm, derSignature.Memory[..derLength], additionalCertificates, pool);
            }

            return Complete(preparation, signerCertificate, signingAlgorithm, signature.AsReadOnlyMemory(), additionalCertificates, pool);
        }
    }


    /// <summary>
    /// Assembles a <c>countersignature</c>'s signed attributes — phase (1) of the split, for the counter signer
    /// of clause 5.2.7 / <see href="https://www.rfc-editor.org/rfc/rfc5652#section-11.4">RFC 5652 §11.4</see> —
    /// and returns the octets the counter signer signs together with their digest.
    /// </summary>
    /// <param name="countersignedSignature">The signature being countersigned; its <c>SignerInfo.signature</c> value octets are what the <c>message-digest</c> attribute covers.</param>
    /// <param name="countersignedSignerIndex">The zero-based index of the <c>SignerInfo</c> being countersigned.</param>
    /// <param name="countersignerCertificate">The counter signer's own certificate, hashed into the ESS <c>signing-certificate-v2</c> attribute.</param>
    /// <param name="messageDigestAlgorithm">The digest algorithm for <c>message-digest</c>, the ESS certificate hash, and the counter signer's <c>SignerInfo.digestAlgorithm</c>.</param>
    /// <param name="signingTime">The <c>signing-time</c> attribute value and the instant a supplied <paramref name="algorithmConstraints"/> table is assessed at.</param>
    /// <param name="algorithmConstraints">A caller-supplied dated cryptographic-constraints table; see <see cref="PrepareAsync"/>.</param>
    /// <param name="cmsAlgorithmProtectionSignatureAlgorithmOid">When non-<see langword="null"/>, adds the opt-in <c>cms-algorithm-protection</c> attribute (RFC 6211) naming this signature algorithm.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The prepared signed attributes, whose <see cref="CAdESSignaturePreparation.Content"/> is <see langword="null"/> because a countersignature encapsulates nothing. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="countersignedSignature"/>, <paramref name="countersignerCertificate"/>, or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="countersignedSignerIndex"/> is negative.</exception>
    /// <exception cref="NotSupportedException">When <paramref name="messageDigestAlgorithm"/> is refused by <see cref="EnsureDigestAlgorithmAllowedForCreation"/>.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">When <paramref name="countersignedSignature"/> is not a CMS <c>SignedData</c> holding a <c>SignerInfo</c> at that index.</exception>
    /// <exception cref="AsnContentException">When <paramref name="countersignedSignature"/> is malformed, truncated, or carries trailing octets.</exception>
    /// <remarks>
    /// <para>
    /// <strong>No <c>content-type</c> attribute is built here, and that is normative.</strong> RFC 5652 §11.4
    /// item 1: "The <c>signedAttributes</c> field MUST NOT contain a <c>content-type</c> attribute; there is no
    /// content type for countersignatures." Item 2 requires <c>message-digest</c> whenever any other attribute is
    /// present, which it always is here. Item 3 fixes what that digest is over: "the contents octets of the DER
    /// encoding of the <c>signatureValue</c> field of the <c>SignerInfo</c> value with which the attribute is
    /// associated" — the value octets alone, no tag and no length, which is what
    /// <see cref="CmsSignedDataAugmentation.ReadSignatureValue"/> returns. That is the same raw-value convention
    /// clause 5.3 states for a <c>signature-time-stamp</c> imprint over the same octets, and deliberately not
    /// clause 5.5.3's TLV-inclusive concatenation.
    /// </para>
    /// <para>
    /// <strong>The counter signer is bound by ESS <c>signing-certificate-v2</c> as any CAdES signer is.</strong>
    /// Clause 5.2.7 has the attribute "include a counter signature on the CAdES signature", so the counter
    /// signature is itself a CAdES signature and the requirement i) attribute applies to it; without it, a
    /// substituted counter signer certificate could be passed off as the counter signer. <c>signing-time</c> is
    /// added for the same reason it is on the main signature.
    /// </para>
    /// <para>
    /// <strong>The optional Table 1 attribute set is not offered here.</strong> Clause 5.2.7 profiles a
    /// countersignature only by reference to RFC 5652 §11.4 and Table 1's rows are the outer signature's own; of
    /// the opt-in attributes <see cref="CAdESOptionalSignedAttributes"/> carries, the content-describing ones
    /// (<c>content-hints</c>, <c>mime-type</c>, <c>content-reference</c>, <c>content-identifier</c>,
    /// <c>content-time-stamp</c>) have no signed content to describe in a structure whose signed object is another
    /// signature's signature value. A counter signer needing a signer-side attribute
    /// (<c>commitment-type-indication</c>, <c>signer-location</c>, <c>signer-attributes-v2</c>) is a widening this
    /// surface can take later without changing anything already produced.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the two encoded carriers and the digest transfers to the returned preparation, which the caller disposes; the catch disposes the source attributes and, on later failure, the encoding's own carriers.")]
    public static async ValueTask<CAdESSignaturePreparation> PrepareCountersignatureAsync(
        CmsSignedData countersignedSignature,
        int countersignedSignerIndex,
        PkiCertificateMemory countersignerCertificate,
        PkiDigestAlgorithm messageDigestAlgorithm,
        DateTimeOffset signingTime,
        CryptographicConstraints? algorithmConstraints,
        string? cmsAlgorithmProtectionSignatureAlgorithmOid,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(countersignedSignature);
        ArgumentNullException.ThrowIfNull(countersignerCertificate);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(countersignedSignerIndex);
        cancellationToken.ThrowIfCancellationRequested();

        EnsureDigestAlgorithmAllowedForCreation(messageDigestAlgorithm, algorithmConstraints, signingTime);

        //RFC 5652 §11.4 item 3: the value octets of the countersigned SignerInfo's signature field.
        ReadOnlyMemory<byte> countersignedSignatureValue = CmsSignedDataAugmentation.ReadSignatureValue(
            countersignedSignature, countersignedSignerIndex);

        DigestValue? messageDigest = null;
        List<CmsAttribute> attributes = [];
        try
        {
            messageDigest = await CryptographicKeyEvents.ComputeDigestAsync(
                countersignedSignatureValue, messageDigestAlgorithm.OutputByteLength, messageDigestAlgorithm.DigestTag, pool,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            using DigestValue certificateHash = await CryptographicKeyEvents.ComputeDigestAsync(
                countersignerCertificate.AsReadOnlyMemory(), messageDigestAlgorithm.OutputByteLength, messageDigestAlgorithm.DigestTag, pool,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            //No content-type attribute: RFC 5652 §11.4 item 1 forbids it outright.
            attributes.Add(BuildMessageDigestAttribute(messageDigest.AsReadOnlySpan(), pool));
            attributes.Add(BuildSigningTimeAttribute(signingTime, pool));
            attributes.Add(BuildSigningCertificateV2Attribute(certificateHash.AsReadOnlySpan(), messageDigestAlgorithm, pool));
            if(cmsAlgorithmProtectionSignatureAlgorithmOid is not null)
            {
                attributes.Add(BuildCmsAlgorithmProtectionAttribute(messageDigestAlgorithm, cmsAlgorithmProtectionSignatureAlgorithmOid, pool));
            }

            CmsSignedAttributesEncoding encoding = CmsSignedAttributesEncoding.Create(attributes, pool);
            DisposeAll(attributes);
            attributes.Clear();

            try
            {
                DigestValue signingInputDigest = await CryptographicKeyEvents.ComputeDigestAsync(
                    encoding.SigningInput.AsReadOnlyMemory(), messageDigestAlgorithm.OutputByteLength, messageDigestAlgorithm.DigestTag, pool,
                    cancellationToken: cancellationToken).ConfigureAwait(false);

                //The commitment — here the countersigned signature value's digest — transfers to the
                //preparation (its ContentDigest), so the finally below releases it only on a failure path.
                CAdESSignaturePreparation preparation = new(encoding.SigningInput, encoding.EmbeddedForm, signingInputDigest, messageDigest, messageDigestAlgorithm, content: null);
                messageDigest = null;

                return preparation;
            }
            catch
            {
                encoding.SigningInput.Dispose();
                encoding.EmbeddedForm.Dispose();

                throw;
            }
        }
        catch
        {
            DisposeAll(attributes);

            throw;
        }
        finally
        {
            messageDigest?.Dispose();
        }
    }


    /// <summary>
    /// Assembles the <c>Countersignature</c> itself — phase (2) for a counter signer: the whole DER
    /// <c>SignerInfo</c> that <c>Countersignature ::= SignerInfo</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-11.4">RFC 5652 §11.4</see>) names, from a
    /// signature value produced however the caller obtained it.
    /// </summary>
    /// <param name="preparation">The prepared signed attributes from <see cref="PrepareCountersignatureAsync"/>.</param>
    /// <param name="countersignerCertificate">The counter signer's certificate, for the <c>IssuerAndSerialNumber</c> signer identifier.</param>
    /// <param name="signingAlgorithm">The algorithm the signature value was produced under, resolving <c>SignerInfo.signatureAlgorithm</c>.</param>
    /// <param name="signatureValue">The externally produced signature value, already in its final wire encoding.</param>
    /// <param name="unsignedAttributes">Unsigned attributes to place inside the countersignature's own <c>SignerInfo</c>, or <see langword="null"/> to omit the field.</param>
    /// <param name="pool">The memory pool the returned carrier is rented from.</param>
    /// <returns>The DER-encoded <c>Countersignature</c>. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="preparation"/>, <paramref name="countersignerCertificate"/>, or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="signatureValue"/> is empty, or <paramref name="signingAlgorithm"/>'s natural digest does not match the digest <paramref name="preparation"/> was built under.</exception>
    /// <exception cref="NotSupportedException">When <paramref name="signingAlgorithm"/> is not one <see cref="ResolveSigningProfile"/> recognises.</exception>
    /// <remarks>
    /// <para>
    /// The result is a bare <c>SignerInfo</c> rather than a finished attribute, because RFC 5652 §11.4 places no
    /// cardinality restriction on the <c>countersignature</c> attribute's values and clause 5.5.3 NOTE 6 names
    /// both shapes explicitly: a further countersignature may be added "in the same attribute or as a new
    /// countersignature attribute". One value is
    /// <see cref="CmsAttribute.Create(string, ReadOnlySpan{byte}, MemoryPool{byte})"/> over these octets — which
    /// is what <see cref="CountersignAsync(CmsSignedData, int, PkiCertificateMemory, PrivateKeyMemory, DateTimeOffset, CryptographicConstraints?, bool, MemoryPool{byte}, CancellationToken)"/>
    /// does; several are <see cref="CmsAttribute.Create(string, IReadOnlyList{ReadOnlyMemory{byte}}, MemoryPool{byte})"/>
    /// over several of them.
    /// </para>
    /// <para>
    /// <paramref name="unsignedAttributes"/> exists because a <c>SignerInfo</c> has the field and RFC 5652 §11.4
    /// notes a countersignature can itself carry a <c>countersignature</c> attribute. Adding one to a
    /// countersignature that an <c>archive-time-stamp-v3</c> already protects is exactly what clause 5.5.3
    /// NOTE 6 warns breaks that archive time-stamp — the outer attribute value's octets change, so the
    /// <c>ats-hash-index-v3</c> entry naming them matches nothing. Placing them at creation time, before any
    /// archive time-stamp exists, does not.
    /// </para>
    /// </remarks>
    public static PooledMemory CompleteCountersignature(
        CAdESSignaturePreparation preparation,
        PkiCertificateMemory countersignerCertificate,
        CryptoAlgorithm signingAlgorithm,
        ReadOnlyMemory<byte> signatureValue,
        IReadOnlyList<CmsAttribute>? unsignedAttributes,
        MemoryPool<byte> pool) =>
        CompleteSignerInfo(preparation, countersignerCertificate, signingAlgorithm, signatureValue, unsignedAttributes, pool, "countersignature");


    /// <summary>
    /// Assembles a parallel signer's whole DER <c>SignerInfo</c> — phase (2) for a signer joining an existing
    /// <c>SignedData</c> — from a signature value produced however the caller obtained it, ready for
    /// <see cref="CmsSignedDataAugmentation.AddSignerInfo"/>'s byte-preserving placement.
    /// </summary>
    /// <param name="preparation">The prepared signed attributes from <see cref="PrepareParallelSignatureAsync"/>.</param>
    /// <param name="signerCertificate">The parallel signer's certificate, for the <c>IssuerAndSerialNumber</c> signer identifier.</param>
    /// <param name="signingAlgorithm">The algorithm the signature value was produced under, resolving <c>SignerInfo.signatureAlgorithm</c>.</param>
    /// <param name="signatureValue">The externally produced signature value, already in its final wire encoding.</param>
    /// <param name="pool">The memory pool the returned carrier is rented from.</param>
    /// <returns>The DER-encoded <c>SignerInfo</c>. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="preparation"/>, <paramref name="signerCertificate"/>, or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="signatureValue"/> is empty, or <paramref name="signingAlgorithm"/>'s natural digest does not match the digest <paramref name="preparation"/> was built under.</exception>
    /// <exception cref="NotSupportedException">When <paramref name="signingAlgorithm"/> is not one <see cref="ResolveSigningProfile"/> recognises.</exception>
    /// <remarks>
    /// A parallel signer is a whole CAdES signer of the shared content — its signed attributes carry
    /// <c>content-type</c>, <c>message-digest</c> over the same <c>eContent</c>, and its own ESS
    /// <c>signing-certificate-v2</c> — where a <c>Countersignature</c> (RFC 5652 §11.4) signs another
    /// signature's value and carries no <c>content-type</c>. The two completions therefore share one
    /// <c>SignerInfo</c> writer and differ in which prepared attributes reach it, exactly as the
    /// countersignature's own remarks state. No <c>unsignedAttrs</c> are placed at completion: augmentation
    /// adds them later at the placed signer's own index, through the byte-preserving splice.
    /// </remarks>
    public static PooledMemory CompleteParallelSignature(
        CAdESSignaturePreparation preparation,
        PkiCertificateMemory signerCertificate,
        CryptoAlgorithm signingAlgorithm,
        ReadOnlyMemory<byte> signatureValue,
        MemoryPool<byte> pool) =>
        CompleteSignerInfo(preparation, signerCertificate, signingAlgorithm, signatureValue, unsignedAttributes: null, pool, "parallel signature");


    /// <summary>
    /// The one completion both <see cref="CompleteCountersignature"/> and
    /// <see cref="CompleteParallelSignature"/> resolve to: validates the signature value and the
    /// algorithm-digest agreement, and writes the whole DER <c>SignerInfo</c> through the same writer
    /// <see cref="Complete(IReadOnlyList{CAdESSignerCompletion}, IReadOnlyList{PkiCertificateMemory}?, MemoryPool{byte})"/>
    /// uses, because RFC 5652 defines both results as a <c>SignerInfo</c>.
    /// </summary>
    /// <param name="preparation">The prepared signed attributes.</param>
    /// <param name="signerCertificate">The signer certificate, for the <c>IssuerAndSerialNumber</c> signer identifier.</param>
    /// <param name="signingAlgorithm">The algorithm the signature value was produced under.</param>
    /// <param name="signatureValue">The externally produced signature value.</param>
    /// <param name="unsignedAttributes">Unsigned attributes to place inside the <c>SignerInfo</c>, or <see langword="null"/> to omit the field.</param>
    /// <param name="pool">The memory pool the returned carrier is rented from.</param>
    /// <param name="operationDescription">The operation's name for the empty-signature refusal message.</param>
    /// <returns>The DER-encoded <c>SignerInfo</c>. The caller owns and disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented buffer transfers to the returned carrier, which the caller disposes; the catch disposes it on a partial failure.")]
    private static PooledMemory CompleteSignerInfo(
        CAdESSignaturePreparation preparation,
        PkiCertificateMemory signerCertificate,
        CryptoAlgorithm signingAlgorithm,
        ReadOnlyMemory<byte> signatureValue,
        IReadOnlyList<CmsAttribute>? unsignedAttributes,
        MemoryPool<byte> pool,
        string operationDescription)
    {
        ArgumentNullException.ThrowIfNull(preparation);
        ArgumentNullException.ThrowIfNull(signerCertificate);
        ArgumentNullException.ThrowIfNull(pool);
        if(signatureValue.IsEmpty)
        {
            throw new ArgumentException($"An externally produced signature value is required to complete a {operationDescription}.", nameof(signatureValue));
        }

        CAdESSigningProfile profile = ResolveSigningProfile(signingAlgorithm);
        if(!string.Equals(profile.DigestAlgorithm.Identifier.Oid, preparation.MessageDigestAlgorithm.Identifier.Oid, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"Signing algorithm '{signingAlgorithm}' expects digest '{profile.DigestAlgorithm.Identifier.Oid}', but the prepared signed attributes were built under '{preparation.MessageDigestAlgorithm.Identifier.Oid}'.",
                nameof(signingAlgorithm));
        }

        ManagedCertificate signer = ManagedCertificate.Parse(signerCertificate.AsReadOnlyMemory());

        var writer = new AsnWriter(AsnEncodingRules.DER);
        WriteSignerInfo(writer, preparation, signer, profile, signatureValue, unsignedAttributes);

        int encodedLength = writer.GetEncodedLength();
        IMemoryOwner<byte> owner = pool.Rent(encodedLength);
        try
        {
            _ = writer.TryEncode(owner.Memory.Span, out int written);

            return new PooledMemory(owner, written, CryptoTags.CmsEncodedSignerInfo);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Composes <see cref="PrepareCountersignatureAsync"/> and <see cref="CompleteCountersignature"/> around a
    /// <see cref="SigningDelegate"/> resolved from <paramref name="countersignerPrivateKey"/>'s
    /// <see cref="Tag"/> — phase (3) for a counter signer — and wraps the result in the one-valued
    /// <c>countersignature</c> attribute of clause 5.2.7 ready for attachment.
    /// </summary>
    /// <param name="countersignedSignature">The signature being countersigned.</param>
    /// <param name="countersignedSignerIndex">The zero-based index of the <c>SignerInfo</c> being countersigned.</param>
    /// <param name="countersignerCertificate">The counter signer's own certificate.</param>
    /// <param name="countersignerPrivateKey">The counter signer's key; its <see cref="Tag"/> resolves both the <see cref="SigningDelegate"/> and the ESS/CMS algorithm identities.</param>
    /// <param name="signingTime">The <c>signing-time</c> attribute value.</param>
    /// <param name="algorithmConstraints">A caller-supplied dated cryptographic-constraints table; see <see cref="PrepareAsync"/>.</param>
    /// <param name="includeCmsAlgorithmProtection">Whether to add the opt-in <c>cms-algorithm-protection</c> attribute (RFC 6211).</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The one-valued <c>countersignature</c> attribute. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    public static ValueTask<CmsAttribute> CountersignAsync(
        CmsSignedData countersignedSignature,
        int countersignedSignerIndex,
        PkiCertificateMemory countersignerCertificate,
        PrivateKeyMemory countersignerPrivateKey,
        DateTimeOffset signingTime,
        CryptographicConstraints? algorithmConstraints,
        bool includeCmsAlgorithmProtection,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(countersignerPrivateKey);

        CryptoAlgorithm algorithm = countersignerPrivateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = countersignerPrivateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);

        return CountersignAsync(
            countersignedSignature, countersignedSignerIndex, countersignerCertificate, countersignerPrivateKey,
            signingDelegate, signingTime, algorithmConstraints, includeCmsAlgorithmProtection, pool,
            cancellationToken: cancellationToken);
    }


    /// <summary>
    /// Composes <see cref="PrepareCountersignatureAsync"/> and <see cref="CompleteCountersignature"/> around an
    /// explicit <see cref="SigningDelegate"/>, for a caller that has already resolved one.
    /// </summary>
    /// <param name="countersignedSignature">The signature being countersigned.</param>
    /// <param name="countersignedSignerIndex">The zero-based index of the <c>SignerInfo</c> being countersigned.</param>
    /// <param name="countersignerCertificate">The counter signer's own certificate.</param>
    /// <param name="countersignerPrivateKey">The counter signer's key; its <see cref="Tag"/> resolves the ESS/CMS algorithm identities.</param>
    /// <param name="signingDelegate">The signing delegate to invoke.</param>
    /// <param name="signingTime">The <c>signing-time</c> attribute value.</param>
    /// <param name="algorithmConstraints">A caller-supplied dated cryptographic-constraints table; see <see cref="PrepareAsync"/>.</param>
    /// <param name="includeCmsAlgorithmProtection">Whether to add the opt-in <c>cms-algorithm-protection</c> attribute (RFC 6211).</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="eventSink">
    /// Receives the <see cref="SignatureProducedEvent"/> <paramref name="signingDelegate"/> constructs, or
    /// <see langword="null"/> to route it to <see cref="CryptographicKeyEvents.DefaultSink"/>.
    /// </param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The one-valued <c>countersignature</c> attribute. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="NotSupportedException">When the key's algorithm is not one <see cref="ResolveSigningProfile"/> recognises.</exception>
    public static async ValueTask<CmsAttribute> CountersignAsync(
        CmsSignedData countersignedSignature,
        int countersignedSignerIndex,
        PkiCertificateMemory countersignerCertificate,
        PrivateKeyMemory countersignerPrivateKey,
        SigningDelegate signingDelegate,
        DateTimeOffset signingTime,
        CryptographicConstraints? algorithmConstraints,
        bool includeCmsAlgorithmProtection,
        MemoryPool<byte> pool,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(countersignedSignature);
        ArgumentNullException.ThrowIfNull(countersignerCertificate);
        ArgumentNullException.ThrowIfNull(countersignerPrivateKey);
        ArgumentNullException.ThrowIfNull(signingDelegate);
        ArgumentNullException.ThrowIfNull(pool);

        cancellationToken.ThrowIfCancellationRequested();

        CryptoAlgorithm signingAlgorithm = countersignerPrivateKey.Tag.Get<CryptoAlgorithm>();
        CAdESSigningProfile profile = ResolveSigningProfile(signingAlgorithm);
        string? cmsAlgorithmProtectionOid = includeCmsAlgorithmProtection ? profile.SignatureAlgorithmOid : null;

        using CAdESSignaturePreparation preparation = await PrepareCountersignatureAsync(
            countersignedSignature, countersignedSignerIndex, countersignerCertificate, profile.DigestAlgorithm,
            signingTime, algorithmConstraints, cmsAlgorithmProtectionOid, pool, cancellationToken).ConfigureAwait(false);

        (Signature signature, CryptoEvent? evt) = await signingDelegate(
            countersignerPrivateKey.AsReadOnlyMemory(), preparation.SigningInput.AsReadOnlyMemory(), pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        using(signature)
        {
            if(evt is not null)
            {
                (eventSink ?? CryptographicKeyEvents.DefaultSink)(evt);
            }

            if(profile.IsEllipticCurve)
            {
                using IMemoryOwner<byte> derSignature = EcdsaSignatureEncoding.ConvertP1363ToDer(signature.AsReadOnlySpan(), pool, out int derLength);
                using PooledMemory countersignature = CompleteCountersignature(
                    preparation, countersignerCertificate, signingAlgorithm, derSignature.Memory[..derLength], unsignedAttributes: null, pool);

                return CmsAttribute.Create(CAdESSignatureFacts.CountersignatureAttributeOid, countersignature.AsReadOnlySpan(), pool);
            }

            using PooledMemory rsaCountersignature = CompleteCountersignature(
                preparation, countersignerCertificate, signingAlgorithm, signature.AsReadOnlyMemory(), unsignedAttributes: null, pool);

            return CmsAttribute.Create(CAdESSignatureFacts.CountersignatureAttributeOid, rsaCountersignature.AsReadOnlySpan(), pool);
        }
    }


    /// <summary>
    /// Assembles a parallel signer's CAdES-B-B signed attributes over an existing <c>SignedData</c>'s own
    /// content — phase (1) for a signer joining it side by side
    /// (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.1">RFC 5652 §5.1</see>, more than one
    /// <c>SignerInfo</c>) — and returns the octets that signer signs together with their digest.
    /// </summary>
    /// <param name="signedData">The Signed Data Object being joined; its own <c>eContent</c> is what the new signer's <c>message-digest</c> covers when the content travels attached.</param>
    /// <param name="signerCertificate">The joining signer's own certificate, hashed into its ESS <c>signing-certificate-v2</c> attribute.</param>
    /// <param name="detachedContentDigest">For a structure that encapsulates no content (the detached form, §5.2): the digest of the externally held content, carrying its own algorithm in its tag. Refused beside an attached content — two contents with only one of them checked is the shape a substitution attack takes.</param>
    /// <param name="messageDigestAlgorithm">The digest algorithm for the new signer's <c>message-digest</c>, ESS certificate hash, and <c>SignerInfo.digestAlgorithm</c>; a supplied <paramref name="detachedContentDigest"/>'s tag must name the same algorithm.</param>
    /// <param name="signingTime">The <c>signing-time</c> attribute value and the instant a supplied <paramref name="algorithmConstraints"/> table is assessed at.</param>
    /// <param name="algorithmConstraints">A caller-supplied dated cryptographic-constraints table; see <see cref="PrepareAsync"/>.</param>
    /// <param name="cmsAlgorithmProtectionSignatureAlgorithmOid">When non-<see langword="null"/>, adds the opt-in <c>cms-algorithm-protection</c> attribute (RFC 6211) naming this signature algorithm.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <param name="optionalAttributes">The opt-in Table 1 attribute set of clause 6.3; see <see cref="PrepareAsync"/>. The content-describing members apply here — unlike a countersignature, a parallel signer signs the content itself.</param>
    /// <returns>The prepared signed attributes. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signedData"/>, <paramref name="signerCertificate"/>, or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="detachedContentDigest"/> is supplied beside an attached content or missing for a detached structure, its tag names no digest algorithm this library states in PKI structures or a different one than <paramref name="messageDigestAlgorithm"/>, its length is not that algorithm's output length, or an existing signer's <c>message-digest</c> under the same algorithm states different octets (parallel signers sign the same content; a signer under a different algorithm cannot be compared without the content and does not refuse the join).</exception>
    /// <exception cref="NotSupportedException">When the structure's <c>eContentType</c> is not <c>id-data</c> (this surface emits requirement f's <c>id-data</c> <c>content-type</c> attribute only), or <paramref name="messageDigestAlgorithm"/> is refused as <see cref="PrepareAsync"/> refuses it.</exception>
    /// <exception cref="CryptographicException">When the structure is not a CMS SignedData this library reads, or its <c>eContent</c> is not one primitive definite-length OCTET STRING (<see cref="CmsSignedDataAugmentation.ReadEncapsulatedContentInfo"/>).</exception>
    [SuppressMessage("Design", "CA1068:CancellationToken parameters must come last",
        Justification = "optionalAttributes is deliberately the LAST parameter, after cancellationToken; see PrepareAsync's remarks and its matching suppression.")]
    public static async ValueTask<CAdESSignaturePreparation> PrepareParallelSignatureAsync(
        CmsSignedData signedData,
        PkiCertificateMemory signerCertificate,
        DigestValue? detachedContentDigest,
        PkiDigestAlgorithm messageDigestAlgorithm,
        DateTimeOffset signingTime,
        CryptographicConstraints? algorithmConstraints,
        string? cmsAlgorithmProtectionSignatureAlgorithmOid,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default,
        CAdESOptionalSignedAttributes? optionalAttributes = null)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(signerCertificate);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        CmsEncapsulatedContent encapsulated = CmsSignedDataAugmentation.ReadEncapsulatedContentInfo(signedData);
        if(!string.Equals(encapsulated.ContentType, DataOid, StringComparison.Ordinal))
        {
            throw new NotSupportedException(
                $"A parallel signature is prepared over eContentType id-data only — the one content type this surface's content-type attribute states (requirement f) — and the structure states '{encapsulated.ContentType}'.");
        }

        if(encapsulated.Content is { } attachedContent)
        {
            if(detachedContentDigest is not null)
            {
                throw new ArgumentException(
                    "The structure encapsulates its own content; a detached content digest beside it is the two-contents shape a substitution attack takes.",
                    nameof(detachedContentDigest));
            }

            return await PrepareAsync(
                signerCertificate, attachedContent, detachedContentDigest: null, messageDigestAlgorithm, signingTime,
                algorithmConstraints, cmsAlgorithmProtectionSignatureAlgorithmOid, pool,
                cancellationToken: cancellationToken, optionalAttributes: optionalAttributes).ConfigureAwait(false);
        }

        if(detachedContentDigest is null)
        {
            throw new ArgumentException(
                "The structure encapsulates no content (the detached form, RFC 5652 §5.2); the digest of the externally held content is required.",
                nameof(detachedContentDigest));
        }

        PkiDigestAlgorithm carried = PkiDigestAlgorithm.FromDigest(detachedContentDigest)
            ?? throw new ArgumentException(
                "The digest carrier's tag names no digest algorithm this library states in PKI structures.",
                nameof(detachedContentDigest));
        if(!string.Equals(carried.Identifier.Oid, messageDigestAlgorithm.Identifier.Oid, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"The digest carrier's tag names '{carried.Identifier.Oid}', but the parallel signature is being prepared under '{messageDigestAlgorithm.Identifier.Oid}'.",
                nameof(detachedContentDigest));
        }

        //The structure's own signers state their commitments in their message-digest attributes; where one
        //shares this preparation's algorithm, it must state these very octets. Under a different algorithm
        //the external content is not here to compare — which mixed classical-plus-post-quantum signing
        //legitimately needs — so only the comparable case is held.
        foreach(CmsSignedDataAugmentation.SignerContentCommitment commitment in CmsSignedDataAugmentation.ReadSignerContentCommitments(signedData))
        {
            if(commitment.HasMessageDigest
                && string.Equals(commitment.DigestAlgorithmOid, messageDigestAlgorithm.Identifier.Oid, StringComparison.Ordinal)
                && !commitment.MessageDigest.Span.SequenceEqual(detachedContentDigest.AsReadOnlySpan()))
            {
                throw new ArgumentException(
                    "An existing signer's message-digest under the same algorithm states different octets; parallel signers sign the same content (RFC 5652 §5.1), and a differing commitment is the substitution shape this surface refuses.",
                    nameof(detachedContentDigest));
            }
        }

        return await PrepareAsync(
            signerCertificate, content: null, detachedContentDigest.AsReadOnlyMemory(), messageDigestAlgorithm, signingTime,
            algorithmConstraints, cmsAlgorithmProtectionSignatureAlgorithmOid, pool,
            cancellationToken: cancellationToken, optionalAttributes: optionalAttributes).ConfigureAwait(false);
    }


    /// <summary>
    /// Composes <see cref="PrepareParallelSignatureAsync"/>, <see cref="CompleteParallelSignature"/>, and
    /// <see cref="CmsSignedDataAugmentation.AddSignerInfo"/> around a <see cref="SigningDelegate"/> resolved
    /// from <paramref name="privateKey"/>'s <see cref="Tag"/> — phase (3) for a signer joining an existing
    /// <c>SignedData</c> side by side, the parallel counterpart of
    /// <see cref="CountersignAsync(CmsSignedData, int, PkiCertificateMemory, PrivateKeyMemory, DateTimeOffset, CryptographicConstraints?, bool, MemoryPool{byte}, CancellationToken)"/>.
    /// </summary>
    /// <param name="signedData">The Signed Data Object being joined. Not modified; the result is a new carrier.</param>
    /// <param name="signerCertificate">The joining signer's own certificate; placed into <c>SignedData.certificates</c> (requirement a) alongside the new <c>SignerInfo</c>.</param>
    /// <param name="privateKey">The signing key; its <see cref="Tag"/> resolves both the <see cref="SigningDelegate"/> and the ESS/CMS algorithm identities.</param>
    /// <param name="detachedContentDigest">For a detached structure: the digest of the externally held content, carrying its own algorithm in its tag; see <see cref="PrepareParallelSignatureAsync"/>.</param>
    /// <param name="signingTime">The <c>signing-time</c> attribute value.</param>
    /// <param name="algorithmConstraints">A caller-supplied dated cryptographic-constraints table; see <see cref="PrepareAsync"/>.</param>
    /// <param name="includeCmsAlgorithmProtection">Whether to add the opt-in <c>cms-algorithm-protection</c> attribute (RFC 6211).</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <param name="optionalAttributes">The opt-in Table 1 attribute set of clause 6.3; see <see cref="PrepareParallelSignatureAsync"/>.</param>
    /// <returns>The Signed Data Object with the new parallel <c>SignerInfo</c> placed. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    [SuppressMessage("Design", "CA1068:CancellationToken parameters must come last",
        Justification = "optionalAttributes is deliberately the LAST parameter, after cancellationToken; see PrepareAsync's remarks and its matching suppression.")]
    public static ValueTask<CmsSignedData> AddParallelSignatureAsync(
        CmsSignedData signedData,
        PkiCertificateMemory signerCertificate,
        PrivateKeyMemory privateKey,
        DigestValue? detachedContentDigest,
        DateTimeOffset signingTime,
        CryptographicConstraints? algorithmConstraints,
        bool includeCmsAlgorithmProtection,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default,
        CAdESOptionalSignedAttributes? optionalAttributes = null)
    {
        ArgumentNullException.ThrowIfNull(privateKey);

        CryptoAlgorithm algorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);

        return AddParallelSignatureAsync(
            signedData, signerCertificate, privateKey, signingDelegate, detachedContentDigest, signingTime,
            algorithmConstraints, includeCmsAlgorithmProtection, pool,
            cancellationToken: cancellationToken, optionalAttributes: optionalAttributes);
    }


    /// <summary>
    /// Composes <see cref="PrepareParallelSignatureAsync"/>, <see cref="CompleteParallelSignature"/>, and
    /// <see cref="CmsSignedDataAugmentation.AddSignerInfo"/> around an explicit <see cref="SigningDelegate"/>,
    /// for a caller that has already resolved one.
    /// </summary>
    /// <param name="signedData">The Signed Data Object being joined. Not modified; the result is a new carrier.</param>
    /// <param name="signerCertificate">The joining signer's own certificate.</param>
    /// <param name="privateKey">The signing key; its <see cref="Tag"/> resolves the ESS/CMS algorithm identities.</param>
    /// <param name="signingDelegate">The signing delegate to invoke.</param>
    /// <param name="detachedContentDigest">For a detached structure: the digest of the externally held content, carrying its own algorithm in its tag.</param>
    /// <param name="signingTime">The <c>signing-time</c> attribute value.</param>
    /// <param name="algorithmConstraints">A caller-supplied dated cryptographic-constraints table; see <see cref="PrepareAsync"/>.</param>
    /// <param name="includeCmsAlgorithmProtection">Whether to add the opt-in <c>cms-algorithm-protection</c> attribute (RFC 6211).</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="eventSink">
    /// Receives the <see cref="SignatureProducedEvent"/> <paramref name="signingDelegate"/> constructs, or
    /// <see langword="null"/> to route it to <see cref="CryptographicKeyEvents.DefaultSink"/>.
    /// </param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <param name="optionalAttributes">The opt-in Table 1 attribute set of clause 6.3; see <see cref="PrepareParallelSignatureAsync"/>.</param>
    /// <returns>The Signed Data Object with the new parallel <c>SignerInfo</c> placed. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="NotSupportedException">When <paramref name="privateKey"/>'s algorithm is not one <see cref="ResolveSigningProfile"/> recognises, or the structure's <c>eContentType</c> is not <c>id-data</c>.</exception>
    [SuppressMessage("Design", "CA1068:CancellationToken parameters must come last",
        Justification = "optionalAttributes is deliberately the LAST parameter, after cancellationToken; see PrepareAsync's remarks and its matching suppression.")]
    public static async ValueTask<CmsSignedData> AddParallelSignatureAsync(
        CmsSignedData signedData,
        PkiCertificateMemory signerCertificate,
        PrivateKeyMemory privateKey,
        SigningDelegate signingDelegate,
        DigestValue? detachedContentDigest,
        DateTimeOffset signingTime,
        CryptographicConstraints? algorithmConstraints,
        bool includeCmsAlgorithmProtection,
        MemoryPool<byte> pool,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default,
        CAdESOptionalSignedAttributes? optionalAttributes = null)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(signerCertificate);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(signingDelegate);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        CryptoAlgorithm signingAlgorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        CAdESSigningProfile profile = ResolveSigningProfile(signingAlgorithm);
        string? cmsAlgorithmProtectionOid = includeCmsAlgorithmProtection ? profile.SignatureAlgorithmOid : null;

        using CAdESSignaturePreparation preparation = await PrepareParallelSignatureAsync(
            signedData, signerCertificate, detachedContentDigest, profile.DigestAlgorithm, signingTime,
            algorithmConstraints, cmsAlgorithmProtectionOid, pool,
            cancellationToken: cancellationToken, optionalAttributes: optionalAttributes).ConfigureAwait(false);

        (Signature signature, CryptoEvent? evt) = await signingDelegate(
            privateKey.AsReadOnlyMemory(), preparation.SigningInput.AsReadOnlyMemory(), pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        using(signature)
        {
            if(evt is not null)
            {
                (eventSink ?? CryptographicKeyEvents.DefaultSink)(evt);
            }

            if(profile.IsEllipticCurve)
            {
                using IMemoryOwner<byte> derSignature = EcdsaSignatureEncoding.ConvertP1363ToDer(signature.AsReadOnlySpan(), pool, out int derLength);
                using PooledMemory ecdsaSignerInfo = CompleteParallelSignature(
                    preparation, signerCertificate, signingAlgorithm, derSignature.Memory[..derLength], pool);

                return CmsSignedDataAugmentation.AddSignerInfo(signedData, ecdsaSignerInfo, [signerCertificate.AsReadOnlyMemory()], pool);
            }

            using PooledMemory rsaSignerInfo = CompleteParallelSignature(
                preparation, signerCertificate, signingAlgorithm, signature.AsReadOnlyMemory(), pool);

            return CmsSignedDataAugmentation.AddSignerInfo(signedData, rsaSignerInfo, [signerCertificate.AsReadOnlyMemory()], pool);
        }
    }


    /// <summary>
    /// Refuses a digest algorithm this surface must not create a signature under (R-8): MD5 unconditionally
    /// (clause 6.2.1 SHALL NOT), SHA-1 as a creation-side digest (the consequence is ESS
    /// <c>signing-certificate-v2</c> only, requirement i), and anything <see cref="PkiDigestAlgorithm.FromOid"/>
    /// does not itself recognise. When <paramref name="algorithmConstraints"/> is supplied, the algorithm must
    /// additionally be asserted reliable at <paramref name="instant"/>.
    /// </summary>
    /// <param name="digestAlgorithm">The digest algorithm to assess.</param>
    /// <param name="algorithmConstraints">The optional dated cryptographic-constraints table.</param>
    /// <param name="instant">The instant to assess <paramref name="algorithmConstraints"/> at (the signing time).</param>
    /// <exception cref="NotSupportedException">When the algorithm is refused.</exception>
    private static void EnsureDigestAlgorithmAllowedForCreation(
        PkiDigestAlgorithm digestAlgorithm, CryptographicConstraints? algorithmConstraints, DateTimeOffset instant)
    {
        string oid = digestAlgorithm.Identifier.Oid;
        if(string.Equals(oid, Md5Oid, StringComparison.Ordinal))
        {
            throw new NotSupportedException("MD5 shall not be used as a digest algorithm (ETSI EN 319 122-1 clause 6.2.1).");
        }

        if(string.Equals(oid, WellKnownOids.Sha1, StringComparison.Ordinal))
        {
            throw new NotSupportedException(
                "SHA-1 is refused as a CAdES creation-side digest algorithm; creation emits signing-certificate-v2 only (ETSI EN 319 122-1 requirement i).");
        }

        if(PkiDigestAlgorithm.FromOid(oid) is null)
        {
            throw new NotSupportedException($"CAdES creation supports SHA-256, SHA-384 and SHA-512 digests only; '{oid}' is not recognised.");
        }

        if(algorithmConstraints is not null)
        {
            var use = new AlgorithmUse(digestAlgorithm.Identifier, null, "CAdES creation message-digest / signing-certificate-v2 digest algorithm");
            AlgorithmReliabilityAssessment assessment = algorithmConstraints.Assess(use, instant);
            if(!assessment.IsReliable)
            {
                throw new NotSupportedException(
                    $"The supplied cryptographic constraints table does not assert digest '{oid}' reliable at {instant:O} (ETSI EN 319 102-1 clause 5.1.4.3).");
            }
        }
    }


    /// <summary>
    /// Resolves the digest algorithm, <c>SignerInfo.signatureAlgorithm</c> identity, and elliptic-curve field
    /// width for a signing algorithm. The curated set — P-256/384/521 (ECDSA) and RSA-2048/4096 (RSASSA-PKCS1-v1.5
    /// with SHA-256, matching <see cref="ManagedCmsVerification"/>'s RSA verification support) — is itself the
    /// gate: no mapping exists to MD5 or SHA-1, so a creation-side digest weaker than SHA-256 cannot be reached
    /// through this resolution path.
    /// </summary>
    /// <param name="signingAlgorithm">The signing algorithm to resolve.</param>
    /// <returns>The resolved profile.</returns>
    /// <exception cref="NotSupportedException">When <paramref name="signingAlgorithm"/> is not one of the curated algorithms.</exception>
    private static CAdESSigningProfile ResolveSigningProfile(CryptoAlgorithm signingAlgorithm) => signingAlgorithm switch
    {
        var a when a == CryptoAlgorithm.P256 => new CAdESSigningProfile(PkiDigestAlgorithm.Sha256, EcdsaWithSha256Oid, IsEllipticCurve: true, EllipticCurveFieldWidthBytes: 32),
        var a when a == CryptoAlgorithm.P384 => new CAdESSigningProfile(PkiDigestAlgorithm.Sha384, EcdsaWithSha384Oid, IsEllipticCurve: true, EllipticCurveFieldWidthBytes: 48),
        var a when a == CryptoAlgorithm.P521 => new CAdESSigningProfile(PkiDigestAlgorithm.Sha512, EcdsaWithSha512Oid, IsEllipticCurve: true, EllipticCurveFieldWidthBytes: 66),
        var a when a == CryptoAlgorithm.Rsa2048 => new CAdESSigningProfile(PkiDigestAlgorithm.Sha256, Sha256WithRsaEncryptionOid, IsEllipticCurve: false, EllipticCurveFieldWidthBytes: 0),
        var a when a == CryptoAlgorithm.Rsa4096 => new CAdESSigningProfile(PkiDigestAlgorithm.Sha256, Sha256WithRsaEncryptionOid, IsEllipticCurve: false, EllipticCurveFieldWidthBytes: 0),
        _ => throw new NotSupportedException($"CAdES creation does not support the signing algorithm '{signingAlgorithm}' (ETSI EN 319 122-1 clause 6.2.1 / requirement i).")
    };


    /// <summary>Builds the mandatory <c>content-type</c> attribute (RFC 5652 §11.1), always <c>id-data</c> (requirement f).</summary>
    private static CmsAttribute BuildContentTypeAttribute(MemoryPool<byte> pool)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteObjectIdentifier(DataOid);

        return EncodeAttribute(CAdESSignatureFacts.ContentTypeAttributeOid, writer, pool);
    }


    /// <summary>Builds the mandatory <c>message-digest</c> attribute (RFC 5652 §5.4/§11.2).</summary>
    private static CmsAttribute BuildMessageDigestAttribute(ReadOnlySpan<byte> digest, MemoryPool<byte> pool)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteOctetString(digest);

        return EncodeAttribute(CAdESSignatureFacts.MessageDigestAttributeOid, writer, pool);
    }


    /// <summary>
    /// Builds the mandatory <c>signing-time</c> attribute (RFC 5652 §11.3): a <c>UTCTime</c> for years
    /// 1950-2049, a <c>GeneralizedTime</c> otherwise, mirroring <see cref="ManagedCertificate"/>'s own reading
    /// convention for the same <c>Time</c> CHOICE.
    /// </summary>
    private static CmsAttribute BuildSigningTimeAttribute(DateTimeOffset signingTime, MemoryPool<byte> pool)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        if(signingTime.Year is >= 1950 and <= 2049)
        {
            writer.WriteUtcTime(signingTime);
        }
        else
        {
            writer.WriteGeneralizedTime(signingTime);
        }

        return EncodeAttribute(CAdESSignatureFacts.SigningTimeAttributeOid, writer, pool);
    }


    /// <summary>
    /// Builds the ESS <c>signing-certificate-v2</c> attribute (<see href="https://www.rfc-editor.org/rfc/rfc5035#section-4">RFC 5035 §4</see>):
    /// one <c>ESSCertIDv2</c> over <paramref name="certificateHash"/>, with <c>issuerSerial</c> omitted
    /// (requirement g) and the <c>hashAlgorithm DEFAULT {algorithm sha-256}</c> field omitted precisely when
    /// it applies (X.690 clause 11.5) — matching how <see cref="CAdESVerification"/> reads the default back.
    /// The <c>policies</c> field is never written (clauses 5.2.2.2/.3).
    /// </summary>
    private static CmsAttribute BuildSigningCertificateV2Attribute(ReadOnlySpan<byte> certificateHash, PkiDigestAlgorithm digestAlgorithm, MemoryPool<byte> pool)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())                  //SigningCertificateV2
        {
            using(writer.PushSequence())               //certs SEQUENCE OF ESSCertIDv2
            {
                using(writer.PushSequence())           //ESSCertIDv2
                {
                    bool isDefaultSha256 = string.Equals(digestAlgorithm.Identifier.Oid, WellKnownOids.Sha256, StringComparison.Ordinal);
                    if(!isDefaultSha256)
                    {
                        using(writer.PushSequence())   //hashAlgorithm AlgorithmIdentifier
                        {
                            writer.WriteObjectIdentifier(digestAlgorithm.Identifier.Oid);
                        }
                    }

                    writer.WriteOctetString(certificateHash);
                }
            }
        }

        return EncodeAttribute(CAdESSignatureFacts.SigningCertificateV2AttributeOid, writer, pool);
    }


    /// <summary>
    /// Builds the opt-in <c>cms-algorithm-protection</c> attribute
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6211#section-3">RFC 6211 §3</see>): the digest algorithm
    /// and the (IMPLICIT <c>[1]</c>) signature algorithm, no <c>macAlgorithm</c> (not applicable to signing).
    /// </summary>
    private static CmsAttribute BuildCmsAlgorithmProtectionAttribute(PkiDigestAlgorithm digestAlgorithm, string signatureAlgorithmOid, MemoryPool<byte> pool)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())                                    //CMSAlgorithmProtection
        {
            WriteDigestAlgorithmIdentifier(writer, digestAlgorithm);
            using(writer.PushSequence(ContextConstructed1))              //signatureAlgorithm [1] IMPLICIT
            {
                writer.WriteObjectIdentifier(signatureAlgorithmOid);
                if(RequiresNullParameters(signatureAlgorithmOid))
                {
                    writer.WriteNull();
                }
            }
        }

        return EncodeAttribute(CmsAlgorithmProtectionAttributeOid, writer, pool);
    }


    /// <summary>
    /// Builds the opt-in <c>commitment-type-indication</c> attribute (clause 5.2.3):
    /// <c>CommitmentTypeIndication ::= SEQUENCE { commitmentTypeId CommitmentTypeIdentifier,
    /// commitmentTypeQualifier SEQUENCE SIZE (1..MAX) OF CommitmentTypeQualifier OPTIONAL }</c>. The qualifier,
    /// when supplied, is spliced in as a pre-encoded value (<see cref="CAdESCommitmentType.Qualifiers"/>).
    /// </summary>
    private static CmsAttribute BuildCommitmentTypeIndicationAttribute(CAdESCommitmentType commitmentType, MemoryPool<byte> pool)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())                                    //CommitmentTypeIndication
        {
            writer.WriteObjectIdentifier(commitmentType.CommitmentTypeId);
            if(commitmentType.Qualifiers is { } qualifiers)
            {
                writer.WriteEncodedValue(qualifiers.Span);
            }
        }

        return EncodeAttribute(CAdESSignatureFacts.CommitmentTypeIndicationAttributeOid, writer, pool);
    }


    /// <summary>
    /// Builds the opt-in <c>content-hints</c> attribute (clause 5.2.4.1, ESS
    /// <see href="https://www.rfc-editor.org/rfc/rfc2634#section-2.9">RFC 2634 §2.9</see>):
    /// <c>ContentHints ::= SEQUENCE { contentDescription UTF8String OPTIONAL, contentType ContentType }</c>.
    /// </summary>
    private static CmsAttribute BuildContentHintsAttribute(CAdESContentHints contentHints, MemoryPool<byte> pool)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())                                    //ContentHints
        {
            if(contentHints.ContentDescription is { } description)
            {
                writer.WriteCharacterString(UniversalTagNumber.UTF8String, description);
            }

            writer.WriteObjectIdentifier(contentHints.ContentType);
        }

        return EncodeAttribute(CAdESSignatureFacts.ContentHintsAttributeOid, writer, pool);
    }


    /// <summary>Builds the opt-in <c>mime-type</c> attribute (clause 5.2.4.2): a bare <c>MimeType ::= UTF8String</c>.</summary>
    private static CmsAttribute BuildMimeTypeAttribute(string mimeType, MemoryPool<byte> pool)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteCharacterString(UniversalTagNumber.UTF8String, mimeType);

        return EncodeAttribute(CAdESSignatureFacts.MimeTypeAttributeOid, writer, pool);
    }


    /// <summary>
    /// Builds the opt-in <c>signer-location</c> attribute (clause 5.2.5):
    /// <c>SignerLocation ::= SEQUENCE { countryName [0] DirectoryString OPTIONAL, localityName [1]
    /// DirectoryString OPTIONAL, postalAddress [2] PostalAddress OPTIONAL }</c>, where
    /// <c>PostalAddress ::= SEQUENCE SIZE(1..6) OF DirectoryString</c> and <c>DirectoryString</c> is a CHOICE
    /// (this surface always chooses <c>utf8String</c>). The Annex D module (<c>ETSI-CAdES-ExplicitSyntax97</c>)
    /// opens <c>DEFINITIONS EXPLICIT TAGS</c>, so every <c>[n]</c> tag is written CONSTRUCTED and ENCLOSES the
    /// tagged type's own tag rather than replacing it: <c>countryName</c>/<c>localityName</c> each enclose the
    /// chosen <c>DirectoryString</c> alternative, and <c>postalAddress</c> encloses the <c>PostalAddress</c>
    /// SEQUENCE OF — <c>[2] { SEQUENCE { DirectoryString, ... } }</c>. (The <c>DirectoryString</c> CHOICE would
    /// force an explicit tag on <c>countryName</c>/<c>localityName</c> even under a module with a different
    /// TagDefault; <c>postalAddress</c> is a <c>SEQUENCE OF</c>, so it is explicit solely because of the module's
    /// EXPLICIT TagDefault.)
    /// </summary>
    private static CmsAttribute BuildSignerLocationAttribute(CAdESSignerLocation location, MemoryPool<byte> pool)
    {
        bool hasPostalAddress = location.PostalAddress is { Count: > 0 };
        if(location.CountryName is null && location.LocalityName is null && !hasPostalAddress)
        {
            throw new ArgumentException(
                "A signer-location attribute states at least one of countryName, localityName or postalAddress (ETSI EN 319 122-1 clause 5.2.5).",
                nameof(location));
        }

        if(location.PostalAddress is { Count: > 6 })
        {
            throw new ArgumentException(
                "A signer-location postalAddress carries at most six lines (ETSI EN 319 122-1 clause 5.2.5, PostalAddress SIZE(1..6)).",
                nameof(location));
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())                                    //SignerLocation
        {
            if(location.CountryName is { } country)
            {
                using(writer.PushSequence(ContextConstructed0))          //countryName [0] DirectoryString (CHOICE, explicit per X.680)
                {
                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, country);
                }
            }

            if(location.LocalityName is { } locality)
            {
                using(writer.PushSequence(ContextConstructed1))          //localityName [1] DirectoryString
                {
                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, locality);
                }
            }

            if(hasPostalAddress)
            {
                using(writer.PushSequence(ContextConstructed2))          //postalAddress [2] EXPLICIT (the Annex D module is DEFINITIONS EXPLICIT TAGS)
                {
                    using(writer.PushSequence())                        //PostalAddress ::= SEQUENCE SIZE(1..6) OF DirectoryString
                    {
                        IReadOnlyList<string> lines = location.PostalAddress!;
                        for(int i = 0; i < lines.Count; ++i)
                        {
                            writer.WriteCharacterString(UniversalTagNumber.UTF8String, lines[i]);
                        }
                    }
                }
            }
        }

        return EncodeAttribute(CAdESSignatureFacts.SignerLocationAttributeOid, writer, pool);
    }


    /// <summary>
    /// Builds the opt-in <c>content-reference</c> attribute (clause 5.2.11, ESS
    /// <see href="https://www.rfc-editor.org/rfc/rfc2634#section-2.11">RFC 2634 §2.11</see>):
    /// <c>ContentReference ::= SEQUENCE { contentType ContentType, signedContentIdentifier ContentIdentifier,
    /// originatorSignatureValue OCTET STRING }</c>.
    /// </summary>
    private static CmsAttribute BuildContentReferenceAttribute(CAdESContentReference contentReference, MemoryPool<byte> pool)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())                                    //ContentReference
        {
            writer.WriteObjectIdentifier(contentReference.ContentType);
            writer.WriteOctetString(contentReference.SignedContentIdentifier.Span);
            writer.WriteOctetString(contentReference.OriginatorSignatureValue.Span);
        }

        return EncodeAttribute(CAdESSignatureFacts.ContentReferenceAttributeOid, writer, pool);
    }


    /// <summary>Builds the opt-in <c>content-identifier</c> attribute (clause 5.2.12): a bare <c>ContentIdentifier ::= OCTET STRING</c>.</summary>
    private static CmsAttribute BuildContentIdentifierAttribute(ReadOnlySpan<byte> contentIdentifier, MemoryPool<byte> pool)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteOctetString(contentIdentifier);

        return EncodeAttribute(CAdESSignatureFacts.ContentIdentifierAttributeOid, writer, pool);
    }


    /// <summary>
    /// Builds the opt-in <c>signature-policy-identifier</c> attribute (clause 5.2.9.1), always the
    /// <c>signaturePolicyId</c> CHOICE alternative — the clause states <c>signaturePolicyImplied</c> shall not
    /// be used, and an untagged CHOICE alternative is written as its own type's tag, here a SEQUENCE:
    /// <c>SignaturePolicyId ::= SEQUENCE { sigPolicyId SigPolicyId, sigPolicyHash SigPolicyHash,
    /// sigPolicyQualifiers SEQUENCE SIZE (1..MAX) OF SigPolicyQualifierInfo OPTIONAL }</c>.
    /// </summary>
    private static CmsAttribute BuildSignaturePolicyIdentifierAttribute(CAdESSignaturePolicyIdentifier identifier, MemoryPool<byte> pool)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())                                    //SignaturePolicyId
        {
            writer.WriteObjectIdentifier(identifier.SigPolicyId);
            using(writer.PushSequence())                                //sigPolicyHash: OtherHashAlgAndValue
            {
                WriteDigestAlgorithmIdentifier(writer, identifier.HashAlgorithm);
                writer.WriteOctetString(identifier.SigPolicyHash.Span);
            }

            if(identifier.Qualifiers is { } qualifiers)
            {
                writer.WriteEncodedValue(qualifiers.Span);
            }
        }

        return EncodeAttribute(CAdESSignatureFacts.SignaturePolicyIdentifierAttributeOid, writer, pool);
    }


    /// <summary>
    /// Builds the opt-in <c>signer-attributes-v2</c> attribute (clause 5.2.6.1) carrying the
    /// <c>claimedAttributes</c> arm alone:
    /// <c>SignerAttributeV2 ::= SEQUENCE { claimedAttributes [0] ClaimedAttributes OPTIONAL, certifiedAttributesV2
    /// [1] CertifiedAttributesV2 OPTIONAL, signedAssertions [2] SignedAssertions OPTIONAL }</c> with
    /// <c>ClaimedAttributes ::= SEQUENCE OF Attribute</c>.
    /// </summary>
    /// <param name="signerAttributes">The claimed attributes to place, each a whole DER <c>Attribute</c>.</param>
    /// <param name="pool">The memory pool the encoded attribute is rented from.</param>
    /// <returns>The encoded attribute; the caller disposes it.</returns>
    /// <exception cref="ArgumentException">When no claimed attribute is supplied — clause 5.2.6.1: "Empty <c>signer-attributes-v2</c> shall not be created".</exception>
    /// <remarks>
    /// <para>
    /// <strong>The <c>[0]</c> tag is EXPLICIT, so the inner <c>SEQUENCE OF</c> tag is written too.</strong> The
    /// ASN.1 module that defines <c>SignerAttributeV2</c> (Annex D of ETSI EN 319 122-1, module
    /// <c>ETSI-CAdES-ExplicitSyntax97</c>) opens <c>DEFINITIONS EXPLICIT TAGS</c>, and <c>ClaimedAttributes</c> is
    /// a <c>SEQUENCE OF</c> rather than an untagged CHOICE, so the context tag encloses that type's own tag
    /// instead of replacing it: the encoding is <c>[0] { SEQUENCE { Attribute, ... } }</c>.
    /// </para>
    /// <para>
    /// Only the <c>claimedAttributes</c> arm is offered; <see cref="CAdESSignerAttributesV2"/>'s own remarks record
    /// why <c>certifiedAttributesV2</c> and <c>signedAssertions</c> are a deliberate pass and what holds by
    /// construction because of it.
    /// </para>
    /// </remarks>
    private static CmsAttribute BuildSignerAttributesV2Attribute(CAdESSignerAttributesV2 signerAttributes, MemoryPool<byte> pool)
    {
        IReadOnlyList<CmsAttribute> claimed = signerAttributes.ClaimedAttributes;
        if(claimed is null || claimed.Count == 0)
        {
            throw new ArgumentException(
                "A signer-attributes-v2 attribute states at least one claimed attribute: empty signer-attributes-v2 shall not be created (ETSI EN 319 122-1 clause 5.2.6.1).",
                nameof(signerAttributes));
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())                                    //SignerAttributeV2
        {
            using(writer.PushSequence(ContextConstructed0))              //claimedAttributes [0] EXPLICIT
            {
                using(writer.PushSequence())                            //ClaimedAttributes ::= SEQUENCE OF Attribute
                {
                    for(int i = 0; i < claimed.Count; ++i)
                    {
                        ArgumentNullException.ThrowIfNull(claimed[i], nameof(signerAttributes));
                        writer.WriteEncodedValue(claimed[i].AsReadOnlySpan());
                    }
                }
            }
        }

        return EncodeAttribute(CAdESSignatureFacts.SignerAttributesV2AttributeOid, writer, pool);
    }


    /// <summary>
    /// Acquires zero or more <c>content-time-stamp</c> tokens (clause 5.2.8) over the same raw message-digest
    /// octets and algorithm the <c>message-digest</c> attribute uses, and builds the one multi-valued
    /// <c>content-time-stamp</c> attribute carrying all of them (cardinality <c>&gt;= 0</c>, one
    /// <c>AttributeValue</c> per token — RFC 5652 §5.3 forbids a repeated attribute type within one
    /// <c>signedAttrs</c>, so several tokens are several values of the one attribute, not several attributes).
    /// Each token is acquired and verified through <see cref="TimestampAcquisition.AcquireAsync"/> before its
    /// octets are trusted enough to embed — the same verify-before-attach discipline the level-raising surfaces
    /// use. Clause 5.2.8's message imprint is the RAW hash of the signed content, without ASN.1 tag and length —
    /// never the <c>archive-time-stamp-v3</c> TLV concatenation of clause 5.5.3 — which is exactly what
    /// <paramref name="messageImprint"/> already carries (the same digest the <c>message-digest</c> attribute
    /// states).
    /// </summary>
    private static async ValueTask<CmsAttribute> BuildContentTimestampAttributeAsync(
        IReadOnlyList<CAdESContentTimestampRequest> requests,
        DigestValue messageImprint,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        List<AcquiredTimestampToken> tokens = new(requests.Count);
        try
        {
            List<ReadOnlyMemory<byte>> values = new(requests.Count);
            for(int i = 0; i < requests.Count; ++i)
            {
                CAdESContentTimestampRequest request = requests[i];
                AcquiredTimestampToken token = await TimestampAcquisition.AcquireAsync(
                    messageImprint, request.TsaUri, request.FetchResponse, pool,
                    request.ReqPolicyOid, request.NonceByteLength, request.IncludeNonce, cancellationToken).ConfigureAwait(false);
                tokens.Add(token);
                values.Add(token.Token.AsReadOnlyMemory());
            }

            return CmsAttribute.Create(CAdESSignatureFacts.ContentTimestampAttributeOid, values, pool);
        }
        finally
        {
            for(int i = 0; i < tokens.Count; ++i)
            {
                tokens[i].Dispose();
            }
        }
    }


    /// <summary>
    /// Writes one whole <c>SignerInfo</c> SEQUENCE
    /// (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.3">RFC 5652 §5.3</see>): the version, the
    /// <c>IssuerAndSerialNumber</c> signer identifier, the digest algorithm, the prepared <c>signedAttrs</c>
    /// octets spliced in verbatim, the signature algorithm, the signature value, and — when supplied — an
    /// <c>unsignedAttrs</c> set.
    /// </summary>
    /// <param name="writer">The writer positioned where the <c>SignerInfo</c> goes.</param>
    /// <param name="preparation">The prepared signed attributes, whose <see cref="CAdESSignaturePreparation.EmbeddedForm"/> octets are written unchanged.</param>
    /// <param name="signer">The parsed signer certificate, for the <c>issuer</c> and <c>serialNumber</c> fields.</param>
    /// <param name="profile">The resolved signing profile, for <c>signatureAlgorithm</c>.</param>
    /// <param name="signatureValue">The signature value, already in its final wire encoding.</param>
    /// <param name="unsignedAttributes">The <c>unsignedAttrs</c> to write, or <see langword="null"/>/empty to omit the field.</param>
    /// <remarks>
    /// One writer serves every completion here — the outer signers of both <c>Complete</c> forms, the
    /// <c>Countersignature</c> of <see cref="CompleteCountersignature"/>, and the parallel signer of
    /// <see cref="CompleteParallelSignature"/> — because RFC 5652 defines each result as a
    /// <c>SignerInfo</c>: they differ in which signed attributes reach <paramref name="preparation"/> and in
    /// what encloses the result, never in this structure.
    /// </remarks>
    private static void WriteSignerInfo(
        AsnWriter writer,
        CAdESSignaturePreparation preparation,
        ManagedCertificate signer,
        CAdESSigningProfile profile,
        ReadOnlyMemory<byte> signatureValue,
        IReadOnlyList<CmsAttribute>? unsignedAttributes)
    {
        using(writer.PushSequence())                          //SignerInfo
        {
            writer.WriteInteger(CmsVersion1);
            using(writer.PushSequence())                      //sid: IssuerAndSerialNumber
            {
                writer.WriteEncodedValue(signer.IssuerDer.Span);
                writer.WriteInteger(signer.SerialNumber.Span);
            }

            WriteDigestAlgorithmIdentifier(writer, preparation.MessageDigestAlgorithm);

            //signedAttrs [0] IMPLICIT: the exact octets the digest and signature were computed over, spliced in
            //verbatim — nothing here is re-encoded.
            writer.WriteEncodedValue(preparation.EmbeddedForm.AsReadOnlySpan());

            WriteSignatureAlgorithmIdentifier(writer, profile);
            writer.WriteOctetString(signatureValue.Span);

            if(unsignedAttributes is { Count: > 0 })
            {
                using(writer.PushSetOf(ContextConstructed1))  //unsignedAttrs [1] IMPLICIT
                {
                    for(int i = 0; i < unsignedAttributes.Count; ++i)
                    {
                        writer.WriteEncodedValue(unsignedAttributes[i].AsReadOnlySpan());
                    }
                }
            }
        }
    }


    /// <summary>
    /// Writes a <c>DigestAlgorithmIdentifier</c> SEQUENCE with parameters absent — the SHA-2 family generation
    /// rule (<see href="https://www.rfc-editor.org/rfc/rfc5754#section-2">RFC 5754 §2</see>) this codebase
    /// already applies for <c>ats-hash-index-v3</c> (<see cref="AtsHashIndexV3"/>).
    /// </summary>
    private static void WriteDigestAlgorithmIdentifier(AsnWriter writer, PkiDigestAlgorithm digestAlgorithm)
    {
        using(writer.PushSequence())
        {
            writer.WriteObjectIdentifier(digestAlgorithm.Identifier.Oid);
        }
    }


    /// <summary>
    /// Writes <c>SignerInfo.signatureAlgorithm</c>: no parameters for ECDSA
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3279#section-2.2.3">RFC 3279 §2.2.3</see>), explicit
    /// <c>NULL</c> parameters for the RSA <c>sha256WithRSAEncryption</c> form
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8017">RFC 8017</see> convention).
    /// </summary>
    private static void WriteSignatureAlgorithmIdentifier(AsnWriter writer, CAdESSigningProfile profile)
    {
        using(writer.PushSequence())
        {
            writer.WriteObjectIdentifier(profile.SignatureAlgorithmOid);
            if(RequiresNullParameters(profile.SignatureAlgorithmOid))
            {
                writer.WriteNull();
            }
        }
    }


    /// <summary>States whether a signature algorithm identifier's <c>AlgorithmIdentifier.parameters</c> field must be an explicit <c>NULL</c> (the RSA convention) rather than absent (the ECDSA convention).</summary>
    private static bool RequiresNullParameters(string signatureAlgorithmOid) =>
        string.Equals(signatureAlgorithmOid, Sha256WithRsaEncryptionOid, StringComparison.Ordinal);


    /// <summary>
    /// Encodes the completed value <paramref name="valueWriter"/> holds into a whole <c>Attribute</c> SEQUENCE
    /// via <see cref="CmsAttribute.Create(string, ReadOnlySpan{byte}, MemoryPool{byte})"/>, using a stack
    /// buffer for the small, bounded values every attribute this surface builds encodes to.
    /// </summary>
    private static CmsAttribute EncodeAttribute(string attributeType, AsnWriter valueWriter, MemoryPool<byte> pool)
    {
        int length = valueWriter.GetEncodedLength();
        Span<byte> buffer = length <= MaximumStackAllocatedAttributeValueLength ? stackalloc byte[length] : new byte[length];
        _ = valueWriter.TryEncode(buffer, out int written);

        return CmsAttribute.Create(attributeType, buffer[..written], pool);
    }


    /// <summary>Disposes every entry of <paramref name="attributes"/>, for a partial-failure or already-consumed cleanup.</summary>
    private static void DisposeAll(List<CmsAttribute> attributes)
    {
        for(int i = 0; i < attributes.Count; ++i)
        {
            attributes[i].Dispose();
        }
    }


    /// <summary>
    /// The per-signing-algorithm identities <see cref="ResolveSigningProfile"/> resolves: the digest algorithm
    /// this surface pairs with it, the <c>SignerInfo.signatureAlgorithm</c> object identifier, and — for an
    /// elliptic-curve algorithm — the curve's field width in bytes, needed to split the registered signing
    /// seam's fixed-width P1363 output into its <c>r</c>/<c>s</c> halves before DER conversion.
    /// </summary>
    /// <param name="DigestAlgorithm">The digest algorithm this signing algorithm is paired with.</param>
    /// <param name="SignatureAlgorithmOid">The <c>SignerInfo.signatureAlgorithm</c> object identifier.</param>
    /// <param name="IsEllipticCurve">Whether the algorithm is an elliptic-curve (ECDSA) algorithm, requiring P1363-to-DER conversion of the registered seam's raw signature output.</param>
    /// <param name="EllipticCurveFieldWidthBytes">The curve's field width in bytes; <c>0</c> when <paramref name="IsEllipticCurve"/> is <see langword="false"/>.</param>
    private readonly record struct CAdESSigningProfile(
        PkiDigestAlgorithm DigestAlgorithm,
        string SignatureAlgorithmOid,
        bool IsEllipticCurve,
        int EllipticCurveFieldWidthBytes);
}


/// <summary>
/// The result of <see cref="CAdESSignatureCreation.PrepareAsync"/>: the CAdES-B-B <c>SignedAttributes</c> in
/// both DER forms and their digest, ready for either an external signer (phases 1+2, e.g. CSC/TS 119 432) or
/// the registered signing seam (<see cref="CAdESSignatureCreation.SignAsync(PkiCertificateMemory, PrivateKeyMemory, ReadOnlyMemory{byte}?, ReadOnlyMemory{byte}?, DateTimeOffset, IReadOnlyList{PkiCertificateMemory}?, CryptographicConstraints?, bool, MemoryPool{byte}, CancellationToken)"/>).
/// </summary>
public sealed class CAdESSignaturePreparation: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a new <see cref="CAdESSignaturePreparation"/>, taking ownership of the four owned carriers.
    /// </summary>
    /// <param name="signingInput">The universal <c>SET OF</c> form — the octets a signer signs. Ownership transfers to this instance.</param>
    /// <param name="embeddedForm">The <c>[0] IMPLICIT</c> form — the octets that go into <c>SignerInfo.signedAttrs</c> verbatim. Ownership transfers to this instance.</param>
    /// <param name="digest">The digest of <paramref name="signingInput"/> under <paramref name="messageDigestAlgorithm"/>, for a signer that consumes a pre-hashed value. Ownership transfers to this instance.</param>
    /// <param name="contentDigest">The <c>message-digest</c> attribute's own value — the digest of what this signer commits to (the content, or a countersigned signature value), computed or wrapped during preparation. Ownership transfers to this instance.</param>
    /// <param name="messageDigestAlgorithm">The digest algorithm every digest in this preparation was computed under.</param>
    /// <param name="content">The attached content, when one was supplied; <see langword="null"/> for a detached signature. Not owned — a borrowed view of the caller's own memory.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="signingInput"/>, <paramref name="embeddedForm"/>, <paramref name="digest"/>, or <paramref name="contentDigest"/> is <see langword="null"/>.</exception>
    public CAdESSignaturePreparation(PooledMemory signingInput, PooledMemory embeddedForm, DigestValue digest, DigestValue contentDigest, PkiDigestAlgorithm messageDigestAlgorithm, ReadOnlyMemory<byte>? content)
    {
        ArgumentNullException.ThrowIfNull(signingInput);
        ArgumentNullException.ThrowIfNull(embeddedForm);
        ArgumentNullException.ThrowIfNull(digest);
        ArgumentNullException.ThrowIfNull(contentDigest);

        SigningInput = signingInput;
        EmbeddedForm = embeddedForm;
        Digest = digest;
        ContentDigest = contentDigest;
        MessageDigestAlgorithm = messageDigestAlgorithm;
        Content = content;
    }


    /// <summary>Gets the universal <c>SET OF</c> encoding — the exact octets a signer signs (RFC 5652 §5.4). Owned by this instance.</summary>
    public PooledMemory SigningInput { get; }

    /// <summary>Gets the <c>[0] IMPLICIT</c> encoding — the octets that occupy <c>SignerInfo.signedAttrs</c> on the wire (RFC 5652 §5.3). Owned by this instance.</summary>
    public PooledMemory EmbeddedForm { get; }

    /// <summary>Gets the digest of <see cref="SigningInput"/> under <see cref="MessageDigestAlgorithm"/> — for a signer (CSC, PKCS#11) that signs a pre-hashed value rather than hashing itself. Owned by this instance.</summary>
    public DigestValue Digest { get; }

    /// <summary>Gets the <c>message-digest</c> attribute's value (RFC 5652 §5.4/§11.2) — the digest of what this signer commits to — surviving preparation so a multi-signer completion can hold detached signers under one algorithm to one commitment. Owned by this instance.</summary>
    public DigestValue ContentDigest { get; }

    /// <summary>Gets the digest algorithm every digest in this preparation was computed under.</summary>
    public PkiDigestAlgorithm MessageDigestAlgorithm { get; }

    /// <summary>Gets the attached content this preparation's <c>message-digest</c> attribute covers, or <see langword="null"/> for a detached signature (§4.5).</summary>
    public ReadOnlyMemory<byte>? Content { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            SigningInput.Dispose();
            EmbeddedForm.Dispose();
            Digest.Dispose();
            ContentDigest.Dispose();
            disposed = true;
        }
    }
}


/// <summary>
/// One signer's inputs to the multi-signer
/// <see cref="CAdESSignatureCreation.Complete(IReadOnlyList{CAdESSignerCompletion}, IReadOnlyList{PkiCertificateMemory}?, MemoryPool{byte})"/> —
/// one <c>SignerInfo</c> per signer, the multi-signer shape of
/// <see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.1">RFC 5652 §5.1</see>.
/// </summary>
/// <param name="Preparation">The signer's prepared signed attributes from <see cref="CAdESSignatureCreation.PrepareAsync"/>. Borrowed — the caller keeps ownership and disposes it after completion.</param>
/// <param name="SignerCertificate">The signer's own certificate, for the <c>IssuerAndSerialNumber</c> signer identifier and <c>SignedData.certificates</c> (requirement a). Borrowed.</param>
/// <param name="SigningAlgorithm">The algorithm the signature value was produced under, resolving <c>SignerInfo.signatureAlgorithm</c>.</param>
/// <param name="SignatureValue">The externally produced signature value, already in its final wire encoding (a DER <c>Ecdsa-Sig-Value</c> for an ECDSA signer, the raw RSA signature for an RSA signer).</param>
[DebuggerDisplay("CAdESSignerCompletion({SigningAlgorithm}, digest {Preparation.MessageDigestAlgorithm.Identifier.Oid,nq})")]
public sealed record CAdESSignerCompletion(
    CAdESSignaturePreparation Preparation,
    PkiCertificateMemory SignerCertificate,
    CryptoAlgorithm SigningAlgorithm,
    ReadOnlyMemory<byte> SignatureValue);
