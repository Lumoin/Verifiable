using System.Security.Cryptography;

namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Validates the binding between each <see cref="MdocIssuerSignedItem"/>'s
/// wire bytes and the MSO's <see cref="MdocMobileSecurityObject.ValueDigests"/>
/// commitments per ISO/IEC 18013-5 §9.1.2.5 — the "did the issuer commit to
/// exactly these claim wire-form bytes" check that a verifier runs before
/// trusting any of the items it received.
/// </summary>
/// <remarks>
/// <para>
/// The validator is format-agnostic — it consumes the parsed namespaces
/// dictionary and the parsed MSO, hashing <see cref="MdocIssuerSignedItem.WireBytes"/>
/// under the MSO's declared digest algorithm. The CBOR encoding choice
/// lives in the writer that filled <see cref="MdocIssuerSignedItem.WireBytes"/>;
/// the validator only checks that <c>hash(wireBytes) == valueDigests[ns][id]</c>.
/// </para>
/// <para>
/// Two overloads exist so both ownership shapes the codebase uses for
/// issuer-signed material flow through the validator unchanged: the
/// owned <see cref="MdocIssuerSigned"/> (verifier-side parse from wire)
/// and the borrowed <see cref="MdocIssuerSignedView"/> (wallet-side
/// trimmed presentation projection). Both delegate to a single private
/// implementation that walks the structural shape (NameSpaces +
/// IssuerAuth).
/// </para>
/// <para>
/// Signature verification on the MSO COSE_Sign1 is a separate concern (see
/// <see cref="Verifiable.Cbor.Mdoc.MdocCborIssuerAuthVerifier"/> in
/// <c>Verifiable.Cbor</c>). The verifier-side trust chain typically runs
/// both checks in series: signature first (does the MSO belong to a key the
/// verifier trusts), then this binding (did that signed MSO commit to the
/// items the wallet presented).
/// </para>
/// <para>
/// Inline <see cref="SHA256"/> / <see cref="SHA384"/> / <see cref="SHA512"/>
/// computation matches the precedent set by
/// <see cref="Verifiable.Cbor.Mdoc.MdocCborIssuance"/> and the SD-CWT
/// pipeline. A future refactor to route through the registry-resolved
/// digest delegate is a project-wide direction noted alongside the result-
/// object direction.
/// </para>
/// </remarks>
public static class MdocMsoDigestBindingValidator
{
    /// <summary>
    /// Validates that every <see cref="MdocIssuerSignedItem"/> in
    /// <paramref name="issuerSigned"/> is committed by the MSO carried in
    /// <see cref="MdocIssuerSigned.IssuerAuth"/>. Verifier-side entry point
    /// — the owned shape is what a CBOR reader produces on the parse path.
    /// </summary>
    /// <param name="issuerSigned">The parsed owned issuer-signed half of an mdoc document.</param>
    /// <returns>
    /// An <see cref="MdocDigestBindingResult"/> carrying the overall pass/fail
    /// plus per-item outcomes. Callers ready to disclose claims to a verifier
    /// check <see cref="MdocDigestBindingResult.IsValid"/>; diagnostics-oriented
    /// callers iterate <see cref="MdocDigestBindingResult.ItemResults"/> for
    /// the per-item picture.
    /// </returns>
    public static MdocDigestBindingResult Validate(MdocIssuerSigned issuerSigned)
    {
        ArgumentNullException.ThrowIfNull(issuerSigned);

        return ValidateCore(issuerSigned.NameSpaces, issuerSigned.IssuerAuth);
    }


    /// <summary>
    /// Validates that every <see cref="MdocIssuerSignedItem"/> in the
    /// trimmed <paramref name="view"/> is committed by the MSO carried in
    /// <see cref="MdocIssuerSignedView.IssuerAuth"/>. Wallet-side or
    /// test-side entry point — accepts the borrowed projection that
    /// <see cref="MdocIssuerSignedTrimmer.Trim"/> returns.
    /// </summary>
    /// <param name="view">The trimmed view referencing a subset of the owned items.</param>
    /// <returns>The validation result with overall and per-item outcomes.</returns>
    public static MdocDigestBindingResult Validate(MdocIssuerSignedView view)
    {
        ArgumentNullException.ThrowIfNull(view);

        return ValidateCore(view.NameSpaces, view.IssuerAuth);
    }


    private static MdocDigestBindingResult ValidateCore(
        IReadOnlyDictionary<string, IReadOnlyList<MdocIssuerSignedItem>> nameSpaces,
        MdocIssuerAuth issuerAuth)
    {
        if(!IsSupportedDigestAlgorithm(issuerAuth.Mso.DigestAlgorithm))
        {
            return MdocDigestBindingResult.Failed(MdocDigestBindingFailureReason.UnsupportedDigestAlgorithm);
        }

        List<MdocDigestBindingItemResult> itemResults = [];
        bool anyFailed = false;

        foreach(KeyValuePair<string, IReadOnlyList<MdocIssuerSignedItem>> nsEntry in nameSpaces)
        {
            string nameSpace = nsEntry.Key;
            issuerAuth.Mso.ValueDigests.TryGetValue(nameSpace, out IReadOnlyDictionary<uint, ReadOnlyMemory<byte>>? msoNamespaceDigests);

            foreach(MdocIssuerSignedItem item in nsEntry.Value)
            {
                MdocDigestBindingItemResult itemResult = EvaluateItem(item, nameSpace, msoNamespaceDigests, issuerAuth.Mso.DigestAlgorithm);
                itemResults.Add(itemResult);

                if(!itemResult.IsValid)
                {
                    anyFailed = true;
                }
            }
        }

        return anyFailed
            ? MdocDigestBindingResult.Failed(MdocDigestBindingFailureReason.ItemBindingFailed, itemResults)
            : MdocDigestBindingResult.Success(itemResults);
    }


    /// <summary>
    /// Computes the per-item outcome. Separated from the orchestration
    /// loop so the per-item failure modes (missing wire bytes, namespace
    /// not committed, digest ID not committed, digest mismatch) each have
    /// their own narrow scope.
    /// </summary>
    private static MdocDigestBindingItemResult EvaluateItem(
        MdocIssuerSignedItem item,
        string nameSpace,
        IReadOnlyDictionary<uint, ReadOnlyMemory<byte>>? msoNamespaceDigests,
        string digestAlgorithm)
    {
        if(msoNamespaceDigests is null)
        {
            return MdocDigestBindingItemResult.Failed(item, nameSpace, MdocDigestBindingItemFailureReason.NamespaceNotCommittedInMso);
        }

        if(!msoNamespaceDigests.TryGetValue(item.DigestId, out ReadOnlyMemory<byte> expectedDigest))
        {
            return MdocDigestBindingItemResult.Failed(item, nameSpace, MdocDigestBindingItemFailureReason.DigestIdNotCommittedInMso);
        }

        byte[] computedDigest = ComputeDigest(digestAlgorithm, item.WireBytes.Span);

        return expectedDigest.Span.SequenceEqual(computedDigest)
            ? MdocDigestBindingItemResult.Success(item, nameSpace)
            : MdocDigestBindingItemResult.Failed(item, nameSpace, MdocDigestBindingItemFailureReason.DigestMismatch);
    }


    private static bool IsSupportedDigestAlgorithm(string digestAlgorithm) =>
        digestAlgorithm == MdocMsoWellKnownKeys.DigestAlgorithmSha256
        || digestAlgorithm == MdocMsoWellKnownKeys.DigestAlgorithmSha384
        || digestAlgorithm == MdocMsoWellKnownKeys.DigestAlgorithmSha512;


    /// <summary>
    /// Computes the digest of <paramref name="input"/> under the
    /// ISO/IEC 18013-5 §9.1.2.5 algorithm name. Caller has already
    /// validated <paramref name="digestAlgorithm"/> via
    /// <see cref="IsSupportedDigestAlgorithm"/>.
    /// </summary>
    private static byte[] ComputeDigest(string digestAlgorithm, ReadOnlySpan<byte> input)
    {
        return digestAlgorithm switch
        {
            MdocMsoWellKnownKeys.DigestAlgorithmSha256 => SHA256.HashData(input),
            MdocMsoWellKnownKeys.DigestAlgorithmSha384 => SHA384.HashData(input),
            MdocMsoWellKnownKeys.DigestAlgorithmSha512 => SHA512.HashData(input),
            _ => throw new InvalidOperationException(
                $"Unsupported MSO digestAlgorithm '{digestAlgorithm}' reached ComputeDigest after the gate.")
        };
    }
}
