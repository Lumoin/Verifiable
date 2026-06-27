using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// ICAO Doc 9303 Part 11 Passive Authentication: verifies that the data read from an eMRTD is
/// authentic and unaltered by checking the EF.SOD signature, chaining the Document Signer to a
/// trusted Country Signing CA, and matching each read data group's hash against the signed value.
/// </summary>
/// <remarks>
/// <para>
/// Passive Authentication is the mandatory eMRTD data-integrity mechanism. It composes three
/// independent pieces: the neutral CMS signature verification seam (the EF.SOD is CMS SignedData),
/// the X.509 chain seam (the Document Signer certificate must chain to a CSCA trust anchor), and the
/// LDS Security Object (which lists the expected hash of each data group). The CMS verification and
/// the chain validation are fail-closed — a bad signature or an untrusted signer throws — while the
/// per-data-group hash results are reported so the caller sees exactly which groups matched.
/// </para>
/// </remarks>
public static class PassiveAuthentication
{
    /// <summary>
    /// Performs Passive Authentication over an EF.SOD and the data groups read from the chip.
    /// </summary>
    /// <param name="efSod">The EF.SOD elementary file.</param>
    /// <param name="dataGroups">The read data groups, keyed by data-group number, as the chip returned them.</param>
    /// <param name="cscaTrustAnchors">The trusted Country Signing CA certificates.</param>
    /// <param name="validationTime">The time at which to evaluate certificate validity.</param>
    /// <param name="validateChain">The certificate-chain validation seam (the application's trust policy).</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The per-data-group hash results and the overall outcome.</returns>
    /// <exception cref="CryptographicException">Thrown when the EF.SOD signature does not verify.</exception>
    /// <exception cref="System.Security.SecurityException">Thrown when the Document Signer does not chain to a trusted CSCA.</exception>
    public static async ValueTask<PassiveAuthenticationResult> VerifyAsync(
        ElementaryFile efSod,
        IReadOnlyDictionary<int, ElementaryFile> dataGroups,
        IReadOnlyList<PkiCertificateMemory> cscaTrustAnchors,
        DateTimeOffset validationTime,
        ValidateCertificateChainAsyncDelegate validateChain,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(efSod);
        ArgumentNullException.ThrowIfNull(dataGroups);
        ArgumentNullException.ThrowIfNull(cscaTrustAnchors);
        ArgumentNullException.ThrowIfNull(validateChain);
        ArgumentNullException.ThrowIfNull(pool);

        VerifyCmsSignedDataDelegate verifyCms = Resolve<VerifyCmsSignedDataDelegate>();
        ComputeDigestDelegate computeDigest = Resolve<ComputeDigestDelegate>();

        using CmsSignedData signedData = DocumentSecurityObject.ExtractSignedData(efSod, pool);

        //Step 1: verify the EF.SOD CMS signature (fail-closed).
        using CmsVerifiedContent verified = await verifyCms(signedData, pool, cancellationToken).ConfigureAwait(false);

        //Step 2: chain the Document Signer to a trusted CSCA (fail-closed).
        using PublicKeyMemory documentSignerKey = await validateChain(
            verified.Certificates, cscaTrustAnchors, validationTime, pool, cancellationToken).ConfigureAwait(false);

        //Step 3: match each read data group's hash against the signed LDS Security Object.
        using LdsSecurityObject securityObject = LdsSecurityObject.Parse(verified.Content, pool);

        var results = new Dictionary<int, bool>(dataGroups.Count);
        bool allValid = true;
        foreach((int dataGroupNumber, ElementaryFile dataGroup) in dataGroups)
        {
            bool valid = securityObject.DataGroupHashes.TryGetValue(dataGroupNumber, out DigestValue? expected)
                && await HashMatchesAsync(dataGroup.AsReadOnlyMemory(), expected, securityObject.HashAlgorithm, computeDigest, pool, cancellationToken).ConfigureAwait(false);
            results[dataGroupNumber] = valid;
            allValid = allValid && valid;
        }

        return new PassiveAuthenticationResult(securityObject.HashAlgorithm, results, allValid);
    }


    /// <summary>
    /// Computes the hash of a data group with the security object's algorithm and compares it to the expected value.
    /// </summary>
    private static async ValueTask<bool> HashMatchesAsync(
        ReadOnlyMemory<byte> dataGroup,
        DigestValue expected,
        HashAlgorithmName hashAlgorithm,
        ComputeDigestDelegate computeDigest,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        (Tag tag, int length) = DigestTag(hashAlgorithm);
        if(expected.Length != length)
        {
            return false;
        }

        (DigestValue digest, _) = await computeDigest(
            new System.Buffers.ReadOnlySequence<byte>(dataGroup), length, tag, pool, null, cancellationToken).ConfigureAwait(false);
        try
        {
            return CryptographicOperations.FixedTimeEquals(digest.AsReadOnlySpan(), expected.AsReadOnlySpan());
        }
        finally
        {
            digest.Dispose();
        }
    }


    /// <summary>
    /// Resolves the digest tag and output length for a hash algorithm.
    /// </summary>
    private static (Tag Tag, int Length) DigestTag(HashAlgorithmName hashAlgorithm)
    {
        if(hashAlgorithm == HashAlgorithmName.SHA256) { return (CryptoTags.Sha256Digest, 32); }
        if(hashAlgorithm == HashAlgorithmName.SHA384) { return (CryptoTags.Sha384Digest, 48); }
        if(hashAlgorithm == HashAlgorithmName.SHA512) { return (CryptoTags.Sha512Digest, 64); }
        if(hashAlgorithm == HashAlgorithmName.SHA1)
        {
            //The convenience tags omit SHA-1 by design; older eMRTD security objects still use it, so it is composed inline.
            Tag sha1 = Tag.Create(
                (typeof(HashAlgorithmName), HashAlgorithmName.SHA1),
                (typeof(Purpose), Purpose.Digest),
                (typeof(EncodingScheme), EncodingScheme.Raw));

            return (sha1, 20);
        }

        throw new InvalidOperationException($"Unsupported hash algorithm '{hashAlgorithm.Name}'.");
    }


    /// <summary>
    /// Resolves a registered delegate or throws.
    /// </summary>
    private static TDelegate Resolve<TDelegate>() where TDelegate: Delegate =>
        CryptographicKeyFactory.GetFunction<TDelegate>(typeof(TDelegate))
            ?? throw new InvalidOperationException($"No {typeof(TDelegate).Name} has been registered.");
}


/// <summary>
/// The outcome of Passive Authentication: the hash algorithm used, the per-data-group hash results,
/// and whether every provided data group matched its signed value.
/// </summary>
public sealed class PassiveAuthenticationResult
{
    /// <summary>
    /// Initialises a new <see cref="PassiveAuthenticationResult"/>.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm the LDS Security Object used.</param>
    /// <param name="dataGroupHashesValid">Per-data-group hash validity, keyed by data-group number.</param>
    /// <param name="allDataGroupsValid">Whether every provided data group matched its signed hash.</param>
    public PassiveAuthenticationResult(
        HashAlgorithmName hashAlgorithm,
        IReadOnlyDictionary<int, bool> dataGroupHashesValid,
        bool allDataGroupsValid)
    {
        ArgumentNullException.ThrowIfNull(dataGroupHashesValid);

        HashAlgorithm = hashAlgorithm;
        DataGroupHashesValid = dataGroupHashesValid;
        AllDataGroupsValid = allDataGroupsValid;
    }


    /// <summary>Gets the hash algorithm the LDS Security Object used.</summary>
    public HashAlgorithmName HashAlgorithm { get; }

    /// <summary>Gets the per-data-group hash results, keyed by data-group number.</summary>
    public IReadOnlyDictionary<int, bool> DataGroupHashesValid { get; }

    /// <summary>
    /// Gets whether the EF.SOD signature verified, the signer chained to a trusted CSCA (both
    /// enforced before this result is produced), and every provided data group matched its signed hash.
    /// </summary>
    public bool AllDataGroupsValid { get; }
}
