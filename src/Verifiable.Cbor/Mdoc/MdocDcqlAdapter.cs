using System.Formats.Cbor;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Core.Model.SelectiveDisclosure;

namespace Verifiable.Cbor.Mdoc;

/// <summary>
/// Adapter that plugs <see cref="MdocDocument"/> into the format-agnostic
/// <see cref="DcqlEvaluator"/>. Exposes the two extension points the
/// evaluator consumes — <see cref="DcqlMetadataExtractor{TCredential}"/>
/// and <see cref="DcqlClaimExtractor{TCredential}"/> — bound to the mdoc
/// namespace-and-element-identifier shape.
/// </summary>
/// <remarks>
/// <para>
/// DCQL claim patterns for mdoc follow the
/// <see cref="DcqlClaimPattern.ForMdoc"/> convention: a two-segment path
/// where the first segment is the namespace and the second is the element
/// identifier (e.g. <c>["org.iso.18013.5.1", "family_name"]</c> →
/// <see cref="MdocIssuerSigned.NameSpaces"/>[<c>"org.iso.18013.5.1"</c>]
/// item with <see cref="MdocIssuerSignedItem.ElementIdentifier"/> ==
/// <c>"family_name"</c>).
/// </para>
/// <para>
/// Values are decoded from each item's
/// <see cref="MdocIssuerSignedItem.EncodedElementValue"/> through
/// <see cref="CborValueConverter.ReadValue(CborReader)"/>, producing the
/// native .NET shape (string, long, bool, Dictionary, etc.) the
/// <see cref="ClaimsQuery.Values"/> constraint check compares against —
/// same shape SD-JWT VC values arrive in.
/// </para>
/// </remarks>
public static class MdocDcqlAdapter
{
    /// <summary>
    /// The OID4VP format identifier <see cref="DcqlCredentialMetadata.Format"/>
    /// reports for an mdoc credential — mirrors
    /// <c>WellKnownCredentialFormats.MsoMdoc</c> in
    /// <c>Verifiable.OAuth.Oid4Vp</c>. Inlined pending a later pass that
    /// adds the OAuth project reference to <c>Verifiable.Cbor</c> and
    /// collapses the two onto a single source-of-truth constant.
    /// </summary>
    public const string FormatIdentifier = "mso_mdoc";


    /// <summary>
    /// Extracts <see cref="DcqlCredentialMetadata"/> from an
    /// <see cref="MdocDocument"/>. Format is always <see cref="FormatIdentifier"/>;
    /// credential type is the document's <see cref="MdocDocument.DocType"/>;
    /// available paths enumerate every namespace × every
    /// <see cref="MdocIssuerSignedItem.ElementIdentifier"/> in the
    /// issuer-signed shape.
    /// </summary>
    public static DcqlMetadataExtractor<MdocDocument> MetadataExtractor { get; } = static document =>
    {
        ArgumentNullException.ThrowIfNull(document);

        HashSet<CredentialPath> availablePaths = new();
        foreach(KeyValuePair<string, IReadOnlyList<MdocIssuerSignedItem>> nsEntry in document.IssuerSigned.NameSpaces)
        {
            foreach(MdocIssuerSignedItem item in nsEntry.Value)
            {
                DcqlClaimPattern pattern = DcqlClaimPattern.ForMdoc(nsEntry.Key, item.ElementIdentifier);
                if(pattern.TryResolve(out CredentialPath path))
                {
                    availablePaths.Add(path);
                }
            }
        }

        return new DcqlCredentialMetadata
        {
            Format = FormatIdentifier,
            CredentialType = document.DocType,
            AvailablePaths = availablePaths
        };
    };


    /// <summary>
    /// Extracts the claim value at the given pattern from an
    /// <see cref="MdocDocument"/>. Patterns are two-segment
    /// <c>[namespace, element_identifier]</c>; anything else
    /// (single-segment, wildcards, deeper paths) returns
    /// <see langword="false"/> — DCQL wildcard expansion runs through
    /// <see cref="DcqlPathResolver"/> before the extractor is invoked.
    /// </summary>
    public static DcqlClaimExtractor<MdocDocument> ClaimExtractor { get; } = static (MdocDocument document, DcqlClaimPattern pattern, out object? value) =>
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(pattern);

        value = null;

        if(pattern.Count != 2 || !pattern[0].IsKey || !pattern[1].IsKey)
        {
            return false;
        }

        string nameSpace = pattern[0].KeyValue!;
        string elementIdentifier = pattern[1].KeyValue!;

        if(!document.IssuerSigned.NameSpaces.TryGetValue(nameSpace, out IReadOnlyList<MdocIssuerSignedItem>? items))
        {
            return false;
        }

        MdocIssuerSignedItem? match = null;
        foreach(MdocIssuerSignedItem item in items)
        {
            if(string.Equals(item.ElementIdentifier, elementIdentifier, StringComparison.Ordinal))
            {
                match = item;
                break;
            }
        }

        if(match is null)
        {
            return false;
        }

        //Decode the CBOR-encoded element value into the native .NET shape
        //DCQL's value-constraint comparison expects. The CborValueConverter
        //handles all primitive types plus maps/arrays uniformly.
        var reader = new CborReader(match.EncodedElementValue.ToArray(), CborConformanceMode.Lax);
        value = CborValueConverter.ReadValue(reader);

        return true;
    };
}
