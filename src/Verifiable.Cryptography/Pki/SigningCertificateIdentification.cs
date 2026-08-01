using System;
using System.Buffers;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// What the identification of the signing certificate building block concluded — the outputs of clause 5.2.3.3
/// of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> <see cref="SigningCertificate"/> is a non-owning reference: it is either the
/// certificate the caller supplied or one the signature's facts own.
/// </remarks>
[DebuggerDisplay("SigningCertificateIdentificationResult: {Conclusion.Indication}")]
public sealed record SigningCertificateIdentificationResult
{
    /// <summary>The block's conclusion: <c>PASSED</c> when a signing certificate was identified, <c>INDETERMINATE</c> with <c>NO_SIGNING_CERTIFICATE_FOUND</c> when it was not.</summary>
    public required BuildingBlockConclusion Conclusion { get; init; }

    /// <summary>The identified signing certificate — clause 5.2.3.3's success output; <see langword="null"/> when none could be identified.</summary>
    public PkiCertificateMemory? SigningCertificate { get; init; }

    /// <summary>
    /// Whether step 3) of clause 5.2.3.4 found the issuer name and serial number of the matching reference to
    /// disagree with the identified certificate, for which the clause requires "an additional warning" to be
    /// returned with the output. The identification itself still succeeded: the certificate hash matched.
    /// </summary>
    public bool HasIssuerSerialMismatchWarning { get; init; }
}


/// <summary>
/// The identification of the signing certificate building block of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.2.3</see>: it settles which certificate the rest of the validation treats
/// as the signer's, and checks it against every reference the signature's signing certificate identifier
/// attributes carry.
/// </summary>
/// <remarks>
/// <para>
/// The candidate is the certificate the Driving Application supplied — Table 9's optional "Signing Certificate"
/// input — and otherwise the copy the signature carries. Every digest is taken through the registered digest
/// seam, so a reference under an algorithm this library cannot compute matches nothing and the block fails
/// closed with <c>NO_SIGNING_CERTIFICATE_FOUND</c> rather than accepting an unchecked binding.
/// </para>
/// <para>
/// NOTE 2 of clause 5.2.3.4 is respected: this block can succeed for a signature that carries no reference at
/// all. Enforcing the presence of the attribute is the signature elements constraints' job, applied by the
/// signature acceptance validation building block.
/// </para>
/// </remarks>
public static class SigningCertificateIdentification
{
    /// <summary>
    /// Identifies the signing certificate.
    /// </summary>
    /// <param name="signature">Table 9's mandatory "Signature" input, in the form the engine holds it.</param>
    /// <param name="signingCertificate">Table 9's optional "Signing Certificate" input — the certificate the Driving Application supplied, or <see langword="null"/>.</param>
    /// <param name="pool">The memory pool the certificate digests are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The conclusion of clause 5.2.3.3 and, on success, the identified certificate.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    public static async ValueTask<SigningCertificateIdentificationResult> IdentifyAsync(
        SignatureFacts signature,
        PkiCertificateMemory? signingCertificate,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(pool);

        PkiCertificateMemory? candidate = signingCertificate ?? signature.SigningCertificate;
        if(candidate is null)
        {
            //Clause 5.2.3.4: "If no certificate can be retrieved, the building block shall return the indication
            //INDETERMINATE and the sub-indication NO_SIGNING_CERTIFICATE_FOUND."
            return NotFound();
        }

        if(signature.SigningCertificateReferences.Count == 0)
        {
            //Clause 5.2.3.4, last paragraph: with no signing certificate identifier attribute present, the copy
            //of the signing certificate the signature carries is returned as the signing certificate.
            return new SigningCertificateIdentificationResult
            {
                Conclusion = BuildingBlockConclusion.Passed,
                SigningCertificate = candidate
            };
        }

        //Steps 1) and 2): the reference the format identifies as the signer's is checked first, then the
        //remaining references in order until one matches.
        for(int pass = 0; pass < 2; ++pass)
        {
            for(int i = 0; i < signature.SigningCertificateReferences.Count; ++i)
            {
                SigningCertificateReference reference = signature.SigningCertificateReferences[i];
                bool isDirectPass = pass == 0;
                if(isDirectPass != reference.IsSignerReference)
                {
                    continue;
                }

                bool matches;
                try
                {
                    matches = await MatchesAsync(reference, candidate, pool, cancellationToken).ConfigureAwait(false);
                }
                catch(InvalidOperationException)
                {
                    //No digest seam is registered, so no reference can be checked. Nothing about the binding can
                    //be ascertained, which is the INDETERMINATE this block reports.
                    return NotFound();
                }

                if(!matches)
                {
                    continue;
                }

                //Step 3): the optional issuer and serial number are compared, and a disagreement is a warning
                //rather than a failure — the certificate hash has already established the binding.
                return new SigningCertificateIdentificationResult
                {
                    Conclusion = BuildingBlockConclusion.Passed,
                    SigningCertificate = candidate,
                    HasIssuerSerialMismatchWarning = HasIssuerSerialMismatch(reference, candidate)
                };
            }
        }

        //Step 2), last sentence: "If the last element is reached without finding any match, the validation of
        //this property shall be taken as failed."
        return NotFound();

        //Builds the single INDETERMINATE outcome clause 5.2.3.3 defines for this block.
        static SigningCertificateIdentificationResult NotFound() => new()
        {
            Conclusion = BuildingBlockConclusion.Indeterminate(SignatureValidationSubIndication.NoSigningCertificateFound, [])
        };
    }


    /// <summary>
    /// Checks whether one reference's certificate hash is the digest of the candidate certificate under the
    /// algorithm the reference declares.
    /// </summary>
    /// <param name="reference">The reference to check.</param>
    /// <param name="candidate">The candidate signing certificate.</param>
    /// <param name="pool">The memory pool the computed digest is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> only when the digests are equal.</returns>
    /// <exception cref="InvalidOperationException">Thrown when no <see cref="ComputeDigestDelegate"/> has been registered.</exception>
    private static async ValueTask<bool> MatchesAsync(
        SigningCertificateReference reference,
        PkiCertificateMemory candidate,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        if(reference.CertificateDigest is null)
        {
            //The reference declares an algorithm this library cannot compute, so the binding cannot be checked.
            return false;
        }

        PkiDigestAlgorithm? algorithm = PkiDigestAlgorithm.FromOid(reference.DigestAlgorithm.Oid);
        if(algorithm is null)
        {
            return false;
        }

        using DigestValue computed = await CryptographicKeyEvents.ComputeDigestAsync(
            candidate.AsReadOnlyMemory(), algorithm.Value.OutputByteLength, algorithm.Value.DigestTag, pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return computed.AsReadOnlySpan().SequenceEqual(reference.CertificateDigest.AsReadOnlySpan());
    }


    /// <summary>
    /// Compares the issuer name and serial number a reference carries with the candidate certificate's own,
    /// per step 3) of clause 5.2.3.4.
    /// </summary>
    /// <param name="reference">The matching reference.</param>
    /// <param name="candidate">The candidate signing certificate.</param>
    /// <returns><see langword="true"/> when the reference states an issuer and serial number that disagree with the certificate.</returns>
    private static bool HasIssuerSerialMismatch(SigningCertificateReference reference, PkiCertificateMemory candidate)
    {
        if(reference.IssuerName is null && reference.SerialNumber is null)
        {
            return false;
        }

        try
        {
            ManagedCertificate parsed = ManagedCertificate.Parse(candidate.AsReadOnlyMemory());
            bool issuerDisagrees = reference.IssuerName is not null
                && !string.Equals(reference.IssuerName, PkiDistinguishedNameText.FromDer(parsed.IssuerDer), StringComparison.Ordinal);
            bool serialDisagrees = reference.SerialNumber is not null
                && !string.Equals(reference.SerialNumber, Convert.ToHexString(parsed.SerialNumber.Span), StringComparison.Ordinal);

            return issuerDisagrees || serialDisagrees;
        }
        catch(AsnContentException)
        {
            //A candidate whose own issuer field cannot be read cannot be shown to agree with the reference.
            return true;
        }
    }
}
