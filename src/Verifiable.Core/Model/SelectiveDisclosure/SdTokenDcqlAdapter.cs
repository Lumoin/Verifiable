using System;
using System.Collections.Generic;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using JsonPointerType = Verifiable.JsonPointer.JsonPointer;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Adapter that plugs a parsed <see cref="SdToken{TEnvelope}"/> into the
/// format-agnostic <see cref="DcqlEvaluator"/>, exposing the two extension
/// points the evaluator consumes — <see cref="DcqlMetadataExtractor{TCredential}"/>
/// and <see cref="DcqlClaimExtractor{TCredential}"/>. One adapter serves both
/// SD-JWT VC (<c>SdToken&lt;string&gt;</c>) and SD-CWT
/// (<c>SdToken&lt;ReadOnlyMemory&lt;byte&gt;&gt;</c>).
/// </summary>
/// <remarks>
/// <para>
/// Unlike <c>MdocDcqlAdapter</c> — which lives in the CBOR assembly because it
/// must CBOR-decode each element value — an <see cref="SdToken{TEnvelope}"/> is
/// already the parsed form: every <see cref="SdDisclosure"/> carries its
/// <see cref="SdDisclosure.ClaimName"/> and pre-decoded
/// <see cref="SdDisclosure.ClaimValue"/>. So both extractors operate purely on
/// the disclosure list with no serialization dependency, and this adapter lives
/// in <c>Verifiable.Core</c> and is format-neutral.
/// </para>
/// <para>
/// DCQL claim patterns for SD-* are single-segment <c>[claim_name]</c> paths
/// (e.g. <c>["given_name"]</c> for SD-JWT VC, <c>["100"]</c> for an integer
/// SD-CWT claim key), mapped to <see cref="CredentialPath"/> via the same
/// <c>/claimName</c> JSON-Pointer convention <see cref="SdDisclosureSelection"/>
/// uses, so the resolved paths line up with the disclosure-selection lattice.
/// </para>
/// <para>
/// The credential's <c>vct</c>/<c>doctype</c>-equivalent type and <c>iss</c>
/// live inside the signed envelope (JSON for SD-JWT, CBOR for SD-CWT), whose
/// parsing belongs to the serialization layer. Rather than couple this Core
/// adapter to a serializer, the caller supplies the credential's
/// <paramref name="credentialType"/> / <paramref name="issuer"/> to
/// <see cref="CreateMetadataExtractor{TEnvelope}"/> when the DCQL query
/// constrains on them; claims-only queries pass neither.
/// </para>
/// </remarks>
public static class SdTokenDcqlAdapter
{
    /// <summary>
    /// Builds a <see cref="DcqlMetadataExtractor{TCredential}"/> for an
    /// <see cref="SdToken{TEnvelope}"/>. <see cref="DcqlCredentialMetadata.AvailablePaths"/>
    /// enumerates every object-property disclosure's <c>/claimName</c> path;
    /// <see cref="DcqlCredentialMetadata.Format"/> /
    /// <see cref="DcqlCredentialMetadata.CredentialType"/> /
    /// <see cref="DcqlCredentialMetadata.Issuer"/> come from the supplied values.
    /// </summary>
    /// <typeparam name="TEnvelope">The SD-token envelope type (<c>string</c> for SD-JWT VC, <c>ReadOnlyMemory&lt;byte&gt;</c> for SD-CWT).</typeparam>
    /// <param name="format">The DCQL format identifier (e.g. <c>dc+sd-jwt</c>, <c>dc+sd-cwt</c>).</param>
    /// <param name="credentialType">The credential's <c>vct</c> (or SD-CWT type), or <see langword="null"/> when the query does not constrain on it.</param>
    /// <param name="issuer">The credential's <c>iss</c>, or <see langword="null"/> when the query does not constrain on it.</param>
    public static DcqlMetadataExtractor<SdToken<TEnvelope>> CreateMetadataExtractor<TEnvelope>(
        string format,
        string? credentialType = null,
        string? issuer = null)
        where TEnvelope : notnull
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(format);

        return token =>
        {
            ArgumentNullException.ThrowIfNull(token);

            HashSet<CredentialPath> availablePaths = new();
            foreach(SdDisclosure disclosure in token.Disclosures)
            {
                if(disclosure.ClaimName is { } claimName)
                {
                    availablePaths.Add(ClaimNameToPath(claimName));
                }
            }

            return new DcqlCredentialMetadata
            {
                Format = format,
                CredentialType = credentialType,
                Issuer = issuer,
                AvailablePaths = availablePaths
            };
        };
    }


    /// <summary>
    /// Extracts the claim value at the given pattern from an
    /// <see cref="SdToken{TEnvelope}"/>. Patterns are single-segment
    /// <c>[claim_name]</c>; anything else (multi-segment, wildcards, array-index)
    /// returns <see langword="false"/> — DCQL wildcard expansion runs through
    /// <see cref="DcqlPathResolver"/> before the extractor is invoked. Matches a
    /// disclosure by <see cref="SdDisclosure.ClaimName"/> and returns its
    /// pre-decoded <see cref="SdDisclosure.ClaimValue"/>.
    /// </summary>
    /// <typeparam name="TEnvelope">The SD-token envelope type.</typeparam>
    public static bool ClaimExtractor<TEnvelope>(
        SdToken<TEnvelope> credential,
        DcqlClaimPattern pattern,
        out object? value)
        where TEnvelope : notnull
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(pattern);

        value = null;

        if(pattern.Count != 1 || !pattern[0].IsKey)
        {
            return false;
        }

        string claimName = pattern[0].KeyValue!;
        foreach(SdDisclosure disclosure in credential.Disclosures)
        {
            if(string.Equals(disclosure.ClaimName, claimName, StringComparison.Ordinal))
            {
                value = disclosure.ClaimValue;
                return true;
            }
        }

        return false;
    }


    //The /claimName JSON-Pointer mapping SdDisclosureSelection uses, so the
    //paths the evaluator resolves match the disclosure-selection lattice.
    private static CredentialPath ClaimNameToPath(string claimName) =>
        CredentialPath.FromJsonPointer($"/{JsonPointerType.Escape(claimName)}");
}
