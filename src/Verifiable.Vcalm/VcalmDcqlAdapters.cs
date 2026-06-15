using System.Collections.Generic;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.JsonPointer;

namespace Verifiable.Vcalm;

/// <summary>
/// The VC-DM 2.0 view of a held credential for the existing <see cref="DcqlEvaluator"/> — a
/// <see cref="DcqlMetadataExtractor{TCredential}"/> / <see cref="DcqlClaimExtractor{TCredential}"/>
/// pair that presents a <see cref="VerifiableCredential"/> to the DCQL engine so the §3.4
/// <c>DigitalCredentialQueryLanguage</c> query type evaluates through DCQL rather than a
/// VCALM-specific re-implementation.
/// </summary>
/// <remarks>
/// VCALM admits DCQL as a co-equal query type over the same VC-DM 2.0 credentials a Query By Example
/// targets; the natural <c>format</c> for an embedded VC-DM 2.0 credential is its first
/// non-<c>VerifiableCredential</c> <c>type</c> token, and claim paths navigate the credential's
/// <c>credentialSubject</c>. The metadata's <see cref="DcqlCredentialMetadata.Format"/> is therefore
/// the credential type token, so a DCQL <see cref="CredentialQuery.Format"/> naming that type matches.
/// </remarks>
public static class VcalmDcqlAdapters
{
    /// <summary>
    /// The default VC-DM 2.0 metadata extractor: the credential's most-specific <c>type</c> as the
    /// DCQL <c>format</c> and <c>credentialType</c>, and the issuer id as the DCQL issuer.
    /// </summary>
    public static DcqlMetadataExtractor<VerifiableCredential> MetadataExtractor { get; } = credential =>
    {
        string credentialType = MostSpecificType(credential);

        return new DcqlCredentialMetadata
        {
            Format = credentialType,
            CredentialType = credentialType,
            Issuer = credential.Issuer?.Id,
            AvailablePaths = CollectSubjectPaths(credential)
        };
    };


    /// <summary>
    /// The default VC-DM 2.0 claim extractor: resolves a concrete (wildcard-free) claim pattern to a
    /// <c>credentialSubject</c> path and reads the value, navigating nested objects.
    /// </summary>
    public static DcqlClaimExtractor<VerifiableCredential> ClaimExtractor { get; } =
        (VerifiableCredential credential, DcqlClaimPattern pattern, out object? value) =>
        {
            value = null;
            if(!pattern.TryResolve(out CredentialPath path) || !path.IsJsonPath)
            {
                return false;
            }

            return TryReadSubjectValue(credential, ToKeys(path.JsonPointer), out value);
        };


    //§4.5 VC-DM 2.0: the first type token other than VerifiableCredential is the credential's
    //most-specific type. Falls back to VerifiableCredential when no more-specific type is present.
    private static string MostSpecificType(VerifiableCredential credential)
    {
        if(credential.Type is { Count: > 0 })
        {
            foreach(string type in credential.Type)
            {
                if(!string.Equals(type, CredentialConstants.VerifiableCredentialType, StringComparison.Ordinal))
                {
                    return type;
                }
            }

            return credential.Type[0];
        }

        return CredentialConstants.VerifiableCredentialType;
    }


    //The reference-token sequence of a JSON pointer, materialized from the pointer's span so it can
    //cross into the value-navigation helpers.
    private static string[] ToKeys(JsonPointer.JsonPointer pointer)
    {
        ReadOnlySpan<JsonPointerSegment> segments = pointer.Segments;
        string[] keys = new string[segments.Length];
        for(int i = 0; i < segments.Length; i++)
        {
            keys[i] = segments[i].Value;
        }

        return keys;
    }


    //The concrete credentialSubject claim paths a held credential can disclose, for coarse DCQL
    //availability matching.
    private static HashSet<CredentialPath> CollectSubjectPaths(VerifiableCredential credential)
    {
        HashSet<CredentialPath> paths = [];
        if(credential.CredentialSubject is null)
        {
            return paths;
        }

        foreach(CredentialSubject subject in credential.CredentialSubject)
        {
            if(subject.AdditionalData is null)
            {
                continue;
            }

            foreach(KeyValuePair<string, object> field in subject.AdditionalData)
            {
                JsonPointer.JsonPointer pointer = JsonPointer.JsonPointer.Root
                    .Append(VcalmParameterNames.CredentialSubject)
                    .Append(field.Key);
                paths.Add(new CredentialPath(pointer));
            }
        }

        return paths;
    }


    //Reads a JSON-pointer reference-token path rooted at the credential against its credentialSubject.
    //The supported shape is /credentialSubject/<field>[/<nested>...]; a path naming the claim directly
    //(no leading credentialSubject token) is also read against the subject claims.
    private static bool TryReadSubjectValue(VerifiableCredential credential, string[] keys, out object? value)
    {
        value = null;
        if(credential.CredentialSubject is null || keys.Length == 0)
        {
            return false;
        }

        int startIndex = string.Equals(keys[0], VcalmParameterNames.CredentialSubject, StringComparison.Ordinal)
            ? 1
            : 0;
        if(startIndex >= keys.Length)
        {
            return false;
        }

        foreach(CredentialSubject subject in credential.CredentialSubject)
        {
            if(subject.AdditionalData is null)
            {
                continue;
            }

            if(TryNavigate(subject.AdditionalData, keys, startIndex, out value))
            {
                return true;
            }
        }

        return false;
    }


    private static bool TryNavigate(IDictionary<string, object> data, string[] keys, int index, out object? value)
    {
        value = null;
        if(!data.TryGetValue(keys[index], out object? current))
        {
            return false;
        }

        if(index == keys.Length - 1)
        {
            value = current;

            return true;
        }

        if(current is IDictionary<string, object> nested)
        {
            return TryNavigate(nested, keys, index + 1, out value);
        }

        return false;
    }
}
