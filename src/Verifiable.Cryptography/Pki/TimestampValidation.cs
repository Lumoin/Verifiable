using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// What the time-stamp validation building block concluded — the output of clause 5.4.3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> together with the data items step 3) of clause 5.4.4 extracts from the
/// <c>TSTInfo</c> field.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> Every carrier this record references belongs to the
/// <see cref="SignatureValidationResources"/> of the run that produced it.
/// </remarks>
[DebuggerDisplay("TimestampValidationResult: {Conclusion.Indication}, generated at {GenerationTime}")]
public sealed record TimestampValidationResult
{
    /// <summary>The block's conclusion: <c>PASSED</c> when the token validated as a Basic Signature and its <c>TSTInfo</c> could be read, and otherwise the indication the validation process returned.</summary>
    public required BuildingBlockConclusion Conclusion { get; init; }

    /// <summary>The <c>genTime</c> step 3) of clause 5.4.4 requires the block to return; <see langword="null"/> when the block did not reach that step.</summary>
    public DateTimeOffset? GenerationTime { get; init; }

    /// <summary>The <c>messageImprint.hashedMessage</c> step 3) requires the block to return; <see langword="null"/> when the block did not reach that step.</summary>
    public DigestValue? MessageImprint { get; init; }

    /// <summary>The <c>messageImprint.hashAlgorithm</c>, whose reliability clause 5.6.2.3.1 and step 5)b) of clause 5.6.3.4 gate proof-of-existence extraction on; <see langword="null"/> when the block did not reach step 3).</summary>
    public AlgorithmIdentifier? MessageImprintAlgorithm { get; init; }

    /// <summary>The <c>accuracy</c> field, which step 4)e) of clause 5.5.4 applies the ordering rules of <see href="https://www.rfc-editor.org/rfc/rfc3161">RFC 3161</see> §2.4.2 with; <see langword="null"/> when the token states none.</summary>
    public TimeSpan? Accuracy { get; init; }

    /// <summary>The <c>ordering</c> field, which step 4)e) of clause 5.5.4 applies the same rules with.</summary>
    public bool IsOrdered { get; init; }

    /// <summary>The <c>policy</c> field of the <c>TSTInfo</c>; <see langword="null"/> when the block did not reach step 3).</summary>
    public string? PolicyOid { get; init; }

    /// <summary>The <c>serialNumber</c> field as upper-case hexadecimal; <see langword="null"/> when the block did not reach step 3).</summary>
    public string? SerialNumber { get; init; }

    /// <summary>The <c>tsa</c> name hint as a rendered directory name; <see langword="null"/> when the token states none.</summary>
    public string? TimestampAuthorityName { get; init; }

    /// <summary>The certificate of the Time-Stamping Authority the token's own validation identified, which the past signature validation building block of clause 5.6.2.4 takes as its target certificate; <see langword="null"/> when none was identified.</summary>
    public PkiCertificateMemory? TimestampCertificate { get; init; }

    /// <summary>The certificate chain the token's own validation built.</summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateChain { get; init; } = [];

    /// <summary>What the validation process for Basic Signatures made of the token's own signature in step 1) — the full result step 5)c) of clause 5.6.3.4 hands to the past signature validation building block.</summary>
    public required BasicSignatureValidationResult TokenSignatureValidation { get; init; }
}


/// <summary>
/// The time-stamp validation building block of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.4</see>: the validation of an
/// <see href="https://www.rfc-editor.org/rfc/rfc3161">RFC 3161</see> time-stamp token.
/// </summary>
/// <remarks>
/// <para>
/// Clause 5.4.1 states that a time-stamp token is a Basic Signature, so step 1) of clause 5.4.4 runs the
/// validation process for Basic Signatures of clause 5.3 over the token with the trust anchors and the policy
/// the validation policy makes applicable to time-stamps, and step 3) then extracts the <c>TSTInfo</c> data
/// items. That is exactly what this block does: it composes clause 5.3 rather than re-deciding anything the
/// process already decides.
/// </para>
/// <para>
/// The composition is finite: the clause 5.3 run this block performs is given no time-stamp validation seam, so
/// it cannot come back here.
/// </para>
/// </remarks>
public static class TimestampValidation
{
    /// <summary>
    /// Validates one time-stamp token.
    /// </summary>
    /// <param name="token">Table 19's mandatory "Time-stamp token" input.</param>
    /// <param name="inputs">The run's inputs; the trust anchors and policy applicable to time-stamps are taken from <see cref="SignatureValidationInputs.ConstraintsForTimestamps"/> and the optional time-stamp certificate from <see cref="SignatureValidationInputs.TimestampCertificate"/>.</param>
    /// <param name="seams">The format binding and certificate seams the token's own validation composes.</param>
    /// <param name="validationTime">The instant the token is validated at.</param>
    /// <param name="resources">The ledger the carriers this call creates are tracked in.</param>
    /// <param name="pool">The memory pool the run rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The conclusion of clause 5.4.3 and the <c>TSTInfo</c> data items of step 3).</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    public static async ValueTask<TimestampValidationResult> ValidateAsync(
        PkiCertificateMemory token,
        SignatureValidationInputs inputs,
        SignatureValidationSeams seams,
        DateTimeOffset validationTime,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(inputs);
        ArgumentNullException.ThrowIfNull(seams);
        ArgumentNullException.ThrowIfNull(resources);
        ArgumentNullException.ThrowIfNull(pool);

        //Step 1): the token is a Signed Data Object in its own right. The carrier is a copy because the token's
        //own bytes are owned by whatever surfaced them, and the format binding takes a Signed Data Object.
        CmsSignedData tokenCarrier = resources.Track(CmsSignedData.FromBytes(token.AsReadOnlySpan(), pool));
        SignatureValidationInputs tokenInputs = inputs with
        {
            SignedDataObject = tokenCarrier,
            SignerDocuments = [],
            SigningCertificate = inputs.TimestampCertificate,
            Constraints = inputs.ConstraintsForTimestamps,
            TimestampConstraints = null,
            TimeIndicationForSignatureExistence = null
        };

        BasicSignatureValidationResult tokenValidation = await BasicSignatureValidation.ValidateAsync(
            tokenInputs, seams, validateTimestampToken: null, validationTime, resources, pool, cancellationToken).ConfigureAwait(false);

        //Step 2): anything other than PASSED is returned as the block's own conclusion.
        if(tokenValidation.Conclusion.Indication != BuildingBlockIndication.Passed)
        {
            return new TimestampValidationResult
            {
                Conclusion = tokenValidation.Conclusion,
                TimestampCertificate = tokenValidation.SigningCertificate,
                CertificateChain = tokenValidation.CertificateChain,
                TokenSignatureValidation = tokenValidation
            };
        }

        //Step 3): data extraction from the TSTInfo field.
        TimestampTokenInfo info = resources.Track(await TimestampTokenInfo.ReadFromTokenAsync(token, pool, cancellationToken).ConfigureAwait(false));
        if(!info.IsRead)
        {
            //A token whose own signature validates but whose TSTInfo cannot be read carries no generation time and
            //no message imprint, which is the conformance failure clause 5.2.2.3 names.
            return new TimestampValidationResult
            {
                Conclusion = BuildingBlockConclusion.Failed(
                    SignatureValidationSubIndication.FormatFailure,
                    [new FormatFailureReportData($"The time-stamp token's TSTInfo could not be read ({info.Status}).")]),
                TimestampCertificate = tokenValidation.SigningCertificate,
                CertificateChain = tokenValidation.CertificateChain,
                TokenSignatureValidation = tokenValidation
            };
        }

        return new TimestampValidationResult
        {
            Conclusion = tokenValidation.Conclusion,
            GenerationTime = info.GenerationTime,
            MessageImprint = info.MessageImprint,
            MessageImprintAlgorithm = info.MessageImprintAlgorithm,
            Accuracy = info.Accuracy,
            IsOrdered = info.IsOrdered,
            PolicyOid = info.PolicyOid,
            SerialNumber = info.SerialNumber,
            TimestampAuthorityName = info.TimestampAuthorityName,
            TimestampCertificate = tokenValidation.SigningCertificate,
            CertificateChain = tokenValidation.CertificateChain,
            TokenSignatureValidation = tokenValidation
        };
    }


    /// <summary>
    /// Reads a time-stamp token's generation time without validating it, so that the process of clause 5.6.3.4
    /// can order the time-stamp attributes "newest first" as its step 5)a) requires before any of them has been
    /// validated.
    /// </summary>
    /// <param name="token">The DER-encoded time-stamp token.</param>
    /// <param name="pool">The memory pool the read rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The generation time, or <see langword="null"/> when the token cannot be opened or read.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    /// <remarks>
    /// The value this states orders a loop and decides nothing: every token it ordered is subsequently validated
    /// through <see cref="ValidateAsync"/>, and only the generation time that validation returns reaches a
    /// conclusion.
    /// </remarks>
    public static async ValueTask<DateTimeOffset?> ReadGenerationTimeAsync(
        PkiCertificateMemory token,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(pool);

        try
        {
            using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(token, pool, cancellationToken).ConfigureAwait(false);

            return info.IsRead ? info.GenerationTime : null;
        }
        catch(InvalidOperationException)
        {
            //No CMS verification seam is registered, so no token can be opened at all.
            return null;
        }
    }


    /// <summary>
    /// Checks that a time-stamp token's message imprint was generated over the octets a signature format binds
    /// it to — the check step 3)a) of clause 5.5.4 performs before it validates a signature time-stamp token,
    /// and the check step 2) of clause 5.2.8.4.2.5 performs for a time-stamp on a Signed Data Object.
    /// </summary>
    /// <param name="token">The DER-encoded time-stamp token.</param>
    /// <param name="timestampedOctets">The octets the format specification says the token's message imprint is taken over.</param>
    /// <param name="pool">The memory pool the computed digest is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> only when the token's message imprint is the digest of those octets under the algorithm the token names.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    public static async ValueTask<bool> VerifyMessageImprintAsync(
        PkiCertificateMemory token,
        ReadOnlyMemory<byte> timestampedOctets,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(pool);

        try
        {
            using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(token, pool, cancellationToken).ConfigureAwait(false);

            return info.IsRead
                && await info.VerifyMessageImprintAsync(timestampedOctets, pool, cancellationToken).ConfigureAwait(false);
        }
        catch(InvalidOperationException)
        {
            //Without the seams the check needs nothing can be established about the binding, which fails closed.
            return false;
        }
    }
}
