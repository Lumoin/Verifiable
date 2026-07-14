using System.Diagnostics.CodeAnalysis;
using System.Security;
using System.Security.Cryptography;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;

namespace Verifiable.Fido2;

/// <summary>
/// Verifies a Metadata BLOB against a caller's trust anchors, and evaluates the caller's status and
/// staleness policy against the payload.
/// </summary>
/// <param name="request">The verification inputs.</param>
/// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
/// <returns>The verification result.</returns>
public delegate ValueTask<MetadataBlobResult> VerifyMetadataBlobAsyncDelegate(MetadataBlobVerificationRequest request, CancellationToken cancellationToken);


/// <summary>
/// Builds the Metadata BLOB verification procedure.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob-proc-rules">FIDO
/// Metadata Service v3.1, section 3.2: Metadata BLOB object processing rules.</see> This library
/// implements the <c>x5c</c> trust branch only — the <c>x5u</c> branch requires an HTTP fetch, which
/// is out of scope for a capability library that performs zero network I/O (see
/// <see cref="ParseMetadataBlobDelegate"/>'s remarks on <c>x5u</c> rejection). Mirrors
/// <see cref="PackedAttestation"/>'s <c>Build</c>/chain-validation shape exactly.
/// </remarks>
public static class MetadataBlobVerification
{
    /// <summary>
    /// The key identifier passed to <see cref="CryptographicKeyFactory"/> for the BLOB signing
    /// certificate's leaf key. Not a DID or credential id — this seam has no such identity to carry,
    /// only the key material and its algorithm tag.
    /// </summary>
    private const string LeafCertificateKeyIdentifier = "metadata-blob:leaf-certificate";


    /// <summary>
    /// Builds the Metadata BLOB verification procedure's <see cref="VerifyMetadataBlobAsyncDelegate"/>.
    /// </summary>
    /// <param name="parseBlob">Decodes the raw compact-JWS BLOB bytes.</param>
    /// <param name="validateChain">Validates the BLOB's <c>x5c</c> certificate path against the request's trust anchors.</param>
    /// <param name="checkRevocation">
    /// A revocation-status seam, forwarded to <paramref name="validateChain"/> only for a request
    /// whose <see cref="MetadataBlobVerificationRequest.RevocationPolicy"/> is
    /// <see cref="MetadataBlobRevocationPolicy.Required"/> — a request declaring
    /// <see cref="MetadataBlobRevocationPolicy.NotChecked"/> never receives it, even when wired here.
    /// When <see langword="null"/> (the default), a <see cref="MetadataBlobRevocationPolicy.Required"/>
    /// request fails closed with <see cref="MetadataBlobStoreUnavailableResult"/>. See
    /// <see cref="Fido2MetadataErrors.BlobChainValidationFailed"/>'s remarks on the <c>x5u</c>-vs-<c>x5c</c>
    /// revocation asymmetry this library resolves by applying the same discipline to both branches.
    /// </param>
    /// <param name="completeChain">
    /// An optional chain-completion seam. When <see langword="null"/> (the default) the BLOB's
    /// <c>x5c</c> is passed to <paramref name="validateChain"/> unchanged.
    /// </param>
    /// <param name="resolvePreviousSerialNumber">
    /// The read half of the serial-number tracking pair, consulted only for a request whose
    /// <see cref="MetadataBlobVerificationRequest.SerialNumberPolicy"/> is
    /// <see cref="MetadataBlobSerialNumberPolicy.Required"/>. When <see langword="null"/> (the
    /// default), such a request fails closed with <see cref="MetadataBlobStoreUnavailableResult"/>.
    /// See <see cref="ResolvePreviousMetadataBlobSerialNumberAsyncDelegate"/>'s own remarks.
    /// </param>
    /// <param name="persistVerifiedBlob">
    /// The write half of the serial-number tracking pair, invoked only for a request whose
    /// <see cref="MetadataBlobVerificationRequest.SerialNumberPolicy"/> is
    /// <see cref="MetadataBlobSerialNumberPolicy.Required"/>, immediately before an accepted result
    /// is returned. When <see langword="null"/> (the default), such a request fails closed with
    /// <see cref="MetadataBlobStoreUnavailableResult"/>. See
    /// <see cref="PersistVerifiedMetadataBlobAsyncDelegate"/>'s own remarks.
    /// </param>
    /// <returns>The verification delegate.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="parseBlob"/> or <paramref name="validateChain"/> is <see langword="null"/>.</exception>
    public static VerifyMetadataBlobAsyncDelegate Build(
        ParseMetadataBlobDelegate parseBlob,
        ValidateCertificateChainAsyncDelegate validateChain,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation = null,
        CompleteCertificateChainAsyncDelegate? completeChain = null,
        ResolvePreviousMetadataBlobSerialNumberAsyncDelegate? resolvePreviousSerialNumber = null,
        PersistVerifiedMetadataBlobAsyncDelegate? persistVerifiedBlob = null)
    {
        ArgumentNullException.ThrowIfNull(parseBlob);
        ArgumentNullException.ThrowIfNull(validateChain);

        return (request, cancellationToken) =>
            VerifyAsync(request, parseBlob, validateChain, checkRevocation, completeChain, resolvePreviousSerialNumber, persistVerifiedBlob, cancellationToken);
    }


    /// <summary>
    /// Implements the section 3.2 processing rules this library's capability surface covers: parse,
    /// algorithm allowlist, chain validation, signature verification, serial-number monotonicity,
    /// and <c>nextUpdate</c> staleness. The serial-number resolve/persist pair and the revocation
    /// seam are consulted or bypassed strictly per the request's own declared policies — one atomic
    /// flow a caller cannot half-take: a <see cref="VerifiedMetadataBlobResult"/> is returned only
    /// after every Required seam ran, and <paramref name="persistVerifiedBlob"/> never runs on any
    /// rejection path.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership transfer: ToVerified() moves the blob's owned members into the verified instance the returned VerifiedMetadataBlobResult carries; the caller owns its disposal, and disposing here would dispose the live content the result hands out.")]
    private static async ValueTask<MetadataBlobResult> VerifyAsync(
        MetadataBlobVerificationRequest request,
        ParseMetadataBlobDelegate parseBlob,
        ValidateCertificateChainAsyncDelegate validateChain,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation,
        CompleteCertificateChainAsyncDelegate? completeChain,
        ResolvePreviousMetadataBlobSerialNumberAsyncDelegate? resolvePreviousSerialNumber,
        PersistVerifiedMetadataBlobAsyncDelegate? persistVerifiedBlob,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        UnverifiedMetadataBlob blob;
        try
        {
            blob = parseBlob(request.BlobBytes, request.Pool);
        }
        catch(Fido2FormatException)
        {
            return new RejectedMetadataBlobResult(Fido2MetadataErrors.MalformedBlob);
        }

        if(!(WellKnownJwaValues.IsEs256(blob.Algorithm) || WellKnownJwaValues.IsRs256(blob.Algorithm)))
        {
            blob.Dispose();
            return new RejectedMetadataBlobResult(Fido2MetadataErrors.UnsupportedBlobAlgorithm);
        }

        if(request.TrustAnchors.Count == 0)
        {
            blob.Dispose();
            return new RejectedMetadataBlobResult(Fido2MetadataErrors.NoBlobTrustAnchors);
        }

        //A Required posture demands a wired revocation delegate; a NotChecked posture never forwards
        //one downstream even when Build() was given one — the per-request policy is authoritative, not
        //merely a default a caller can be silently overridden by a shared, procedure-wide wiring.
        if(request.RevocationPolicy == MetadataBlobRevocationPolicy.Required && checkRevocation is null)
        {
            blob.Dispose();
            return new MetadataBlobStoreUnavailableResult(Fido2MetadataErrors.RevocationCheckUnavailable);
        }

        CheckCertificateRevocationStatusAsyncDelegate? effectiveCheckRevocation =
            request.RevocationPolicy == MetadataBlobRevocationPolicy.Required ? checkRevocation : null;

        PublicKeyMemory leafKeyMemory;
        IReadOnlyList<PkiCertificateMemory> chainToValidate = blob.X5c;
        int acquiredCertificateCount = 0;
        try
        {
            if(completeChain is not null)
            {
                //Chain completion is append-only (see CompleteCertificateChainAsyncDelegate's contract): any
                //entries beyond X5c's own Count are newly acquired for this call and are this method's to dispose;
                //X5c's own entries stay owned by blob throughout.
                chainToValidate = await completeChain(blob.X5c, request.TrustAnchors, request.Pool, cancellationToken).ConfigureAwait(false);
                acquiredCertificateCount = chainToValidate.Count - blob.X5c.Count;
            }

            leafKeyMemory = await validateChain(chainToValidate, request.TrustAnchors, request.ValidationTime, request.Pool, effectiveCheckRevocation, cancellationToken).ConfigureAwait(false);
        }
        catch(SecurityException)
        {
            blob.Dispose();
            return new RejectedMetadataBlobResult(Fido2MetadataErrors.BlobChainValidationFailed);
        }
        finally
        {
            for(int acquiredIndex = blob.X5c.Count; acquiredIndex < blob.X5c.Count + acquiredCertificateCount; acquiredIndex++)
            {
                chainToValidate[acquiredIndex].Dispose();
            }
        }

        //CreatePublicKey takes ownership of leafKeyMemory; disposing leafPublicKey below releases it.
        using PublicKey leafPublicKey = CryptographicKeyFactory.CreatePublicKey(leafKeyMemory, LeafCertificateKeyIdentifier, leafKeyMemory.Tag);

        bool signatureValid;
        try
        {
            using Signature signature = blob.Signature.Span.ToSignature(CryptoTags.AlgorithmAgnosticSignature, request.Pool);
            signatureValid = await leafPublicKey.VerifyAsync(blob.SigningInput, signature).ConfigureAwait(false);
        }
        catch(CryptographicException)
        {
            //A signature whose shape does not match the leaf key's own algorithm: fail-closed to an
            //invalid signature, per section 3.2 item 6's "Verify the signature".
            signatureValid = false;
        }

        if(!signatureValid)
        {
            blob.Dispose();
            return new RejectedMetadataBlobResult(Fido2MetadataErrors.InvalidBlobSignature);
        }

        if(request.SerialNumberPolicy == MetadataBlobSerialNumberPolicy.Required)
        {
            //Both halves of the pair are treated as one indivisible capability, mirroring
            //JtiReplayGuard's "a read-only half-wiring would never trip, so the two are one
            //capability" rationale: a resolve-only wiring would check monotonicity without ever
            //recording a new baseline, and a persist-only wiring would record without ever checking.
            if(resolvePreviousSerialNumber is null || persistVerifiedBlob is null)
            {
                blob.Dispose();
                return new MetadataBlobStoreUnavailableResult(Fido2MetadataErrors.SerialNumberStoreUnavailable);
            }

            long? previousSerialNumber;
            try
            {
                previousSerialNumber = await resolvePreviousSerialNumber(request.TenantId, cancellationToken).ConfigureAwait(false);
            }
            catch(Exception ex) when(ex is not OperationCanceledException)
            {
                //A failing store is indistinguishable from an unwired one for fail-closed purposes —
                //this procedure never lets a storage failure surface as an unhandled exception
                //mid-verification.
                blob.Dispose();
                return new MetadataBlobStoreUnavailableResult(Fido2MetadataErrors.SerialNumberStoreUnavailable);
            }

            if(previousSerialNumber is { } previous && blob.Payload.No <= previous)
            {
                blob.Dispose();
                return new RejectedMetadataBlobResult(Fido2MetadataErrors.SerialNumberNotIncreasing);
            }
        }

        if(blob.Payload.NextUpdate < DateOnly.FromDateTime(request.ValidationTime.UtcDateTime))
        {
            blob.Dispose();
            return new RejectedMetadataBlobResult(Fido2MetadataErrors.BlobStale);
        }

        //Only now, with every processing-rules check passed, is blob's content trustworthy enough to
        //hand to a caller: the projection moves ownership of X5c and Payload into verifiedBlob without
        //copying, so blob must not be used (and in particular must not be disposed) after this point.
        MetadataBlob verifiedBlob = blob.ToVerified();
        var verified = new VerifiedMetadataBlobResult(verifiedBlob, request.RevocationPolicy);
        if(request.SerialNumberPolicy == MetadataBlobSerialNumberPolicy.Required)
        {
            await persistVerifiedBlob!(request.TenantId, verified, cancellationToken).ConfigureAwait(false);
        }

        return verified;
    }
}
