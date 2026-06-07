using Verifiable.Core.Model.SelectiveDisclosure;

namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Wallet-side selective disclosure for mdoc — trims an
/// <see cref="MdocIssuerSigned"/> down to the items a DCQL evaluation
/// (or any other selection mechanism) picked, returning an
/// <see cref="MdocIssuerSignedView"/> that borrows references to the
/// originally-owned items.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors the <c>BaseProofResult</c> → <c>EcdsaSdDerivedProof</c> split
/// the codebase already uses for ECDSA-SD-2023 selective disclosure: the
/// owned full proof and the non-owned derived/trimmed projection are
/// distinct types so ownership shows up in the type system rather than in
/// prose-only contracts. The same pattern
/// <see cref="Verifiable.Core.SelectiveDisclosure.SdDisclosureSelection.SelectDisclosures"/>
/// uses on the SD-JWT/SD-CWT side, where the filtered output is a plain
/// <see cref="IReadOnlyList{T}"/> of borrowed disclosure references rather
/// than a re-wrapped owning container.
/// </para>
/// <para>
/// The trimmed view shares <see cref="MdocIssuerSignedItem"/> references
/// (and therefore their <see cref="Verifiable.Cryptography.Salt"/> owners)
/// with the original <see cref="MdocIssuerSigned"/>. The view itself is
/// not <see cref="IDisposable"/>; the originating owned shape's
/// <see cref="MdocIssuerSigned.Dispose"/> releases the salts. Callers
/// arrange their scopes so the owned shape outlives any views derived
/// from it.
/// </para>
/// <para>
/// The trimmed view still carries the original's <see cref="MdocIssuerAuth"/>
/// because the MSO commits to digests of ALL items the issuer signed, not
/// just the trimmed subset. The verifier checks <c>hash(item.WireBytes) ==
/// MSO.valueDigests[ns][digestID]</c> for each item the wallet PRESENTS;
/// items the wallet omits never reach the validator. ISO/IEC 18013-5
/// §9.1.2.5 explicitly allows the wallet to send any subset of the
/// issuer's items, so the verifier's digest binding works on the trimmed
/// shape unchanged.
/// </para>
/// </remarks>
public static class MdocIssuerSignedTrimmer
{
    /// <summary>
    /// Returns an <see cref="MdocIssuerSignedView"/> containing only the
    /// items whose <c>[namespace, element_identifier]</c>
    /// <see cref="Verifiable.Core.SelectiveDisclosure.CredentialPath"/> is
    /// in <paramref name="selectedPaths"/>. Per-namespace ordering of
    /// retained items matches the original.
    /// </summary>
    /// <param name="full">The full issuer-signed shape from issuance or hydration.</param>
    /// <param name="selectedPaths">
    /// The paths the wallet chose to present — typically the output of
    /// the DCQL evaluator + selective-disclosure decision graph.
    /// </param>
    /// <returns>
    /// A view borrowing item references from <paramref name="full"/>. The
    /// originating <paramref name="full"/>'s lifetime must bracket the
    /// view's; the salts release when <paramref name="full"/> is disposed.
    /// </returns>
    public static MdocIssuerSignedView Trim(
        MdocIssuerSigned full,
        IReadOnlySet<CredentialPath> selectedPaths)
    {
        ArgumentNullException.ThrowIfNull(full);
        ArgumentNullException.ThrowIfNull(selectedPaths);

        Dictionary<string, IReadOnlyList<MdocIssuerSignedItem>> trimmed =
            new(StringComparer.Ordinal);

        foreach(KeyValuePair<string, IReadOnlyList<MdocIssuerSignedItem>> nsEntry in full.NameSpaces)
        {
            List<MdocIssuerSignedItem> keptItems = [];
            foreach(MdocIssuerSignedItem item in nsEntry.Value)
            {
                if(selectedPaths.Contains(PathFor(nsEntry.Key, item.ElementIdentifier)))
                {
                    keptItems.Add(item);
                }
            }

            if(keptItems.Count > 0)
            {
                trimmed[nsEntry.Key] = keptItems.ToArray();
            }
        }

        return new MdocIssuerSignedView(trimmed, full.IssuerAuth);
    }


    /// <summary>
    /// Builds the <see cref="CredentialPath"/> for an mdoc claim
    /// (<c>[namespace, element_identifier]</c>) using the same convention
    /// <see cref="Verifiable.Core.Model.Dcql.DcqlClaimPattern.ForMdoc"/>
    /// uses. Exposed so call sites that already have the namespace +
    /// identifier strings can construct the lookup key without going
    /// through the pattern type.
    /// </summary>
    public static CredentialPath PathFor(string nameSpace, string elementIdentifier)
    {
        ArgumentException.ThrowIfNullOrEmpty(nameSpace);
        ArgumentException.ThrowIfNullOrEmpty(elementIdentifier);

        Verifiable.JsonPointer.JsonPointer pointer =
            Verifiable.JsonPointer.JsonPointer.Root
                .Append(nameSpace)
                .Append(elementIdentifier);

        return new CredentialPath(pointer);
    }
}
