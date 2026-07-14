using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Security;
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
    /// <param name="policy">The Passive Authentication policy, or <see langword="null"/> for <see cref="PassiveAuthenticationPolicy.Default"/> (which rejects a SHA-1 LDS Security Object and a non-conformant Document Signer certificate).</param>
    /// <param name="checkRevocation">An optional Document Signer revocation-status seam (an OCSP/CRL-backed checker the application supplies), forwarded to <paramref name="validateChain"/> as part of path validation. When supplied it is consulted fail-closed — a revoked or indeterminate signer rejects the document; when <see langword="null"/> (the default) no revocation is performed. The library ships the seam, not an OCSP/CRL client.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The per-data-group hash results and the overall outcome.</returns>
    /// <exception cref="CryptographicException">Thrown when the EF.SOD signature does not verify, or when the Document Signer certificate is malformed (for example it carries a duplicate extension that RFC 5280 §4.2 forbids).</exception>
    /// <exception cref="SecurityException">Thrown when the Document Signer certificate does not conform to the ICAO Doc 9303 Part 12 §7.1 profile (and the policy does not allow it), when the Document Signer does not chain to a trusted CSCA, when a revocation checker is supplied and the Document Signer is revoked or of indeterminate status, or when the LDS Security Object uses SHA-1 and the policy does not allow it.</exception>
    public static async ValueTask<PassiveAuthenticationResult> VerifyAsync(
        ElementaryFile efSod,
        IReadOnlyDictionary<int, ElementaryFile> dataGroups,
        IReadOnlyList<PkiCertificateMemory> cscaTrustAnchors,
        DateTimeOffset validationTime,
        ValidateCertificateChainAsyncDelegate validateChain,
        MemoryPool<byte> pool,
        PassiveAuthenticationPolicy? policy = null,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(efSod);
        ArgumentNullException.ThrowIfNull(dataGroups);
        ArgumentNullException.ThrowIfNull(cscaTrustAnchors);
        ArgumentNullException.ThrowIfNull(validateChain);
        ArgumentNullException.ThrowIfNull(pool);

        VerifyCmsSignedDataDelegate verifyCms = Resolve<VerifyCmsSignedDataDelegate>();
        ComputeDigestDelegate computeDigest = Resolve<ComputeDigestDelegate>();

        //The policy governs which inputs Passive Authentication accepts; the default is the secure profile.
        PassiveAuthenticationPolicy effectivePolicy = policy ?? PassiveAuthenticationPolicy.Default;

        using CmsSignedData signedData = DocumentSecurityObject.ExtractSignedData(efSod, pool);

        //Step 1: verify the EF.SOD CMS signature (fail-closed).
        using CmsVerifiedContent verified = await verifyCms(signedData, pool, cancellationToken).ConfigureAwait(false);

        //Step 2: enforce the ICAO Doc 9303 Part 12 §7.1 Document Signer certificate profile (fail-closed). The
        //Document Signer signs documents, not certificates: it MUST assert the digitalSignature key usage and MUST
        //NOT be a certificate authority (asserting keyCertSign or marked cA=TRUE), so a leaked or coerced Document
        //Signer key cannot issue further certificates that would themselves chain to the trusted CSCA. A deployment
        //that must accept a non-conformant signer opts out through the policy. Reading the profile also rejects a
        //structurally malformed signer (a certificate carrying a duplicate extension, which RFC 5280 §4.2 forbids and
        //which would make the profile ambiguous); that integrity check is part of reading the profile, so it is
        //intentionally forgone together with the profile when a deployment opts out.
        if(!effectivePolicy.AllowNonConformantDocumentSignerCertificate)
        {
            ReadCertificateProfileDelegate readProfile = Resolve<ReadCertificateProfileDelegate>();
            EnsureConformantDocumentSigner(readProfile(verified.SignerCertificate));
        }

        //Step 3: chain the Document Signer to a trusted CSCA — and, when a revocation source is supplied, check the
        //signer's revocation status as part of path validation. Both are fail-closed. The Document Signer is the
        //chain leaf: the CMS embeds the signer first, so it is verified.Certificates[0], which is the certificate the
        //chain validator both builds from and revocation-checks. eMRTD Passive Authentication does not mandate
        //revocation universally and the library ships no OCSP/CRL client, so revocation happens only when a deployment
        //supplies the checker; then a revoked or indeterminate signer rejects the document.
        using PublicKeyMemory documentSignerKey = await validateChain(
            verified.Certificates, cscaTrustAnchors, validationTime, pool, checkRevocation, cancellationToken).ConfigureAwait(false);

        //Step 4: match each read data group's hash against the signed LDS Security Object.
        using LdsSecurityObject securityObject = LdsSecurityObject.Parse(verified.Content, pool);

        //Hash-strength policy: SHA-1 is collision-forgeable, so a forged data group can be crafted to share a
        //genuine one's SHA-1 digest and slip past the per-group hash match below. The secure default rejects a
        //SHA-1 LDS Security Object; only a deployment that must still verify older SHA-1-sealed documents opts in.
        if(securityObject.HashAlgorithm == HashAlgorithmName.SHA1 && !effectivePolicy.AllowSha1SecurityObject)
        {
            throw new SecurityException(
                "The eMRTD LDS Security Object uses SHA-1, which is collision-forgeable; Passive Authentication rejects it unless the policy allows SHA-1 security objects.");
        }

        var results = new Dictionary<int, bool>(dataGroups.Count);

        //An empty set verifies nothing, so it is not "all valid": seed the verdict from whether any data group
        //was presented at all, then require every presented one to match.
        bool allValid = dataGroups.Count > 0;
        foreach((int dataGroupNumber, ElementaryFile dataGroup) in dataGroups)
        {
            bool valid = securityObject.DataGroupHashes.TryGetValue(dataGroupNumber, out DigestValue? expected)
                && await HashMatchesAsync(dataGroup.AsReadOnlyMemory(), expected, securityObject.HashAlgorithm, computeDigest, pool, cancellationToken).ConfigureAwait(false);
            results[dataGroupNumber] = valid;
            allValid = allValid && valid;
        }

        //Surface the security object's signed set so a caller can enforce completeness. A data group the SOD
        //covers but that was not presented is never hash-checked, so a malicious chip could withhold a group it
        //tampered and still leave every presented group valid; AllDataGroupsValid speaks only to the presented
        //groups, and MissingDataGroupNumbers is what a strict inspection policy must additionally require to be empty.
        int[] coveredDataGroupNumbers = [.. securityObject.DataGroupHashes.Keys.Order()];
        int[] missingDataGroupNumbers = [.. coveredDataGroupNumbers.Where(number => !dataGroups.ContainsKey(number))];

        return new PassiveAuthenticationResult(
            securityObject.HashAlgorithm, results, coveredDataGroupNumbers, missingDataGroupNumbers, allValid);

        //Throws when the Document Signer certificate asserts a usage a Document Signer must not have, naming
        //every violation of the ICAO Doc 9303 Part 12 §7.1 profile it found.
        static void EnsureConformantDocumentSigner(X509CertificateProfile profile)
        {
            var violations = new List<string>(3);
            if(!profile.AssertsDigitalSignature)
            {
                violations.Add("its Key Usage does not assert digitalSignature");
            }

            if(profile.AssertsKeyCertSign)
            {
                violations.Add("its Key Usage asserts keyCertSign");
            }

            if(profile.IsCertificateAuthority)
            {
                violations.Add("its Basic Constraints mark it as a certificate authority (cA=TRUE)");
            }

            if(violations.Count > 0)
            {
                throw new SecurityException(
                    "The eMRTD Document Signer certificate does not conform to the ICAO Doc 9303 Part 12 " +
                    $"Document Signer profile: {string.Join("; ", violations)}. A Document Signer must assert " +
                    "digitalSignature and must not be a certificate authority.");
            }
        }
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
            Tag sha1 = Tag.Create(HashAlgorithmName.SHA1).With(Purpose.Digest).With(EncodingScheme.Raw);

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
/// The policy governing which Passive Authentication inputs are accepted. The default
/// (<see cref="Default"/>) is the secure profile: a SHA-1 LDS Security Object is rejected because SHA-1 is
/// collision-forgeable, and a Document Signer certificate that does not conform to the ICAO Doc 9303 Part 12
/// §7.1 profile is rejected; only a deployment that must still verify such documents opts back in.
/// </summary>
public sealed record PassiveAuthenticationPolicy
{
    /// <summary>
    /// Gets whether an LDS Security Object whose data-group hashes use SHA-1 is accepted. Defaults to
    /// <see langword="false"/>: a collision-forgeable SHA-1 digest lets a forged data group be crafted to share a
    /// genuine one's hash, so the secure default rejects it. A deployment that must still verify older SHA-1-sealed
    /// eMRTDs sets this to <see langword="true"/>, accepting the weaker assurance.
    /// </summary>
    public bool AllowSha1SecurityObject { get; init; }

    /// <summary>
    /// Gets whether a Document Signer certificate that does not conform to the ICAO Doc 9303 Part 12 §7.1 Document
    /// Signer profile is accepted. Defaults to <see langword="false"/>: the secure default requires the signer to
    /// assert the digitalSignature key usage and to not be a certificate authority (no keyCertSign, cA=FALSE), so a
    /// Document Signer cannot also issue certificates. A deployment that must still accept a non-conformant signer
    /// sets this to <see langword="true"/>, accepting the weaker assurance.
    /// </summary>
    public bool AllowNonConformantDocumentSignerCertificate { get; init; }


    /// <summary>Gets the secure default policy: a SHA-1 LDS Security Object and a non-conformant Document Signer certificate are both rejected.</summary>
    public static PassiveAuthenticationPolicy Default { get; } = new();
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
    /// <param name="coveredDataGroupNumbers">The data-group numbers the signed LDS Security Object covers.</param>
    /// <param name="missingDataGroupNumbers">The covered data groups that were not presented for verification.</param>
    /// <param name="allDataGroupsValid">Whether at least one data group was presented and every presented one matched its signed hash.</param>
    public PassiveAuthenticationResult(
        HashAlgorithmName hashAlgorithm,
        IReadOnlyDictionary<int, bool> dataGroupHashesValid,
        IReadOnlyList<int> coveredDataGroupNumbers,
        IReadOnlyList<int> missingDataGroupNumbers,
        bool allDataGroupsValid)
    {
        ArgumentNullException.ThrowIfNull(dataGroupHashesValid);
        ArgumentNullException.ThrowIfNull(coveredDataGroupNumbers);
        ArgumentNullException.ThrowIfNull(missingDataGroupNumbers);

        HashAlgorithm = hashAlgorithm;
        DataGroupHashesValid = dataGroupHashesValid;
        CoveredDataGroupNumbers = coveredDataGroupNumbers;
        MissingDataGroupNumbers = missingDataGroupNumbers;
        AllDataGroupsValid = allDataGroupsValid;
    }


    /// <summary>Gets the hash algorithm the LDS Security Object used.</summary>
    public HashAlgorithmName HashAlgorithm { get; }

    /// <summary>Gets the per-data-group hash results, keyed by data-group number.</summary>
    public IReadOnlyDictionary<int, bool> DataGroupHashesValid { get; }

    /// <summary>
    /// Gets the data-group numbers the signed LDS Security Object covers, in ascending order — the set a complete
    /// document presents. Comparing it against the groups actually read tells a caller which signed groups are absent.
    /// </summary>
    public IReadOnlyList<int> CoveredDataGroupNumbers { get; }

    /// <summary>
    /// Gets the covered data groups that were not presented for verification, in ascending order. A strict
    /// inspection policy treats a non-empty set as incomplete, since a withheld group is never hash-checked even
    /// though the document is signed to contain it.
    /// </summary>
    public IReadOnlyList<int> MissingDataGroupNumbers { get; }

    /// <summary>
    /// Gets whether the EF.SOD signature verified, the signer chained to a trusted CSCA (both enforced before this
    /// result is produced), at least one data group was presented, and every presented data group matched its
    /// signed hash. This does not by itself assert completeness — see <see cref="MissingDataGroupNumbers"/>.
    /// </summary>
    public bool AllDataGroupsValid { get; }
}
