using System;
using System.Globalization;
using Verifiable.Core.Model.Did;
using Verifiable.Foundation;

namespace Verifiable.Core.Did.Methods.WebPlus;

/// <summary>
/// The single-document validation of a did:webplus DID document: the steps that can be decided from one
/// document in isolation, independent of its predecessor (did:webplus Draft v0.4, Validation of DID Documents,
/// steps 1–5 and the root <c>versionId</c> constraint).
/// </summary>
/// <remarks>
/// <para>
/// "All validations MUST succeed in order for a DID document to be considered valid"; this method fails closed,
/// returning a human-readable reason on the first unmet obligation and <see langword="null"/> only when every
/// single-document obligation holds. The cross-document obligations — that a non-root document's <c>id</c>,
/// <c>prevDIDDocumentSelfHash</c>, <c>validFrom</c> and <c>versionId</c> agree with its predecessor, that its
/// proofs satisfy the predecessor's <c>updateRules</c>, and the recursive validity of the whole history — are
/// folded by the microledger replay; the self-hash and proof obligations are verified by
/// <see cref="WebPlusSelfHash"/> and the proofs slice. This is the did:webplus cousin of
/// <see cref="WebVh.WebVhChainVerification"/>'s per-entry checks.
/// </para>
/// <para>
/// Step 1 (the document equals its JCS-serialized form) is decided here by canonicalizing the received bytes
/// through the <see cref="WebPlusJcsCanonicalizer"/> seam and comparing byte-for-byte; the remaining steps run
/// against the parsed <see cref="WebPlusDidDocument"/>. Both seams are supplied by the <c>Verifiable.Json</c>
/// leaf so this stays free of a serializer dependency.
/// </para>
/// </remarks>
internal static class WebPlusDataModelValidation
{
    //The multibase prefixes a did:webplus MBHash may use: 'u' (base64url, RECOMMENDED) and 'z' (base58btc)
    //(did:webplus Draft v0.4, MBHash Values — Multibases). The full multihash decode is the MBHash slice; the
    //data model here checks the value is multibase-shaped.
    private const char Base64UrlMultibasePrefix = 'u';
    private const char Base58BtcMultibasePrefix = 'z';

    /// <summary>
    /// Validates the single-document obligations of a received did:webplus DID document.
    /// </summary>
    /// <param name="received">The received DID document bytes, as served in the <c>did-documents.jsonl</c> microledger.</param>
    /// <param name="parser">The JSON parser that produces the structural <see cref="WebPlusDidDocument"/>.</param>
    /// <param name="canonicalizer">The JCS canonicalizer used for the byte-equality check (step 1).</param>
    /// <returns><see langword="null"/> when every single-document obligation holds; otherwise the reason the document is invalid.</returns>
    public static string? Validate(
        ReadOnlyMemory<byte> received,
        WebPlusDidDocumentParser parser,
        WebPlusJcsCanonicalizer canonicalizer)
    {
        ArgumentNullException.ThrowIfNull(parser);
        ArgumentNullException.ThrowIfNull(canonicalizer);

        //Step 1: the DID document MUST be exactly equal to its JCS-serialized form. A document whose bytes differ
        //from their canonicalization (extra whitespace, unsorted keys, non-minimal escaping) is rejected before
        //any field is trusted (did:webplus Draft v0.4, Validation of DID Documents, step 1).
        TaggedMemory<byte> canonical = canonicalizer(received);
        if(!received.Span.SequenceEqual(canonical.Span))
        {
            return "The did:webplus DID document is not equal to its JCS-serialized form.";
        }

        //Step 2: the document MUST deserialize into the data model. The parser rejects shape-level violations
        //(for example a verificationMethod field that is present but not an array) by throwing; the field-level
        //data-model rules are checked below. Extra fields are allowed.
        WebPlusDidDocument document = parser(received.Span);

        //WP-DM-2: id MUST be a valid did:webplus DID with no query parameters or fragment.
        if(document.Id?.Id is not { Length: > 0 } id)
        {
            return "The did:webplus DID document MUST have a string 'id'.";
        }

        if(!id.StartsWith(WellKnownDidMethodPrefixes.WebPlusDidMethodPrefix + ":", StringComparison.Ordinal))
        {
            return $"The did:webplus DID document 'id' '{id}' MUST be a did:webplus DID.";
        }

        if(id.Contains('?', StringComparison.Ordinal) || id.Contains('#', StringComparison.Ordinal))
        {
            return $"The did:webplus DID document 'id' '{id}' MUST NOT contain query parameters or a fragment.";
        }

        //WP-DM-3: selfHash MUST be a valid MBHash self-hash.
        if(document.SelfHash is not { Length: > 0 } selfHash || !IsMbHashShaped(selfHash))
        {
            return "The did:webplus DID document 'selfHash' MUST be a valid MBHash value.";
        }

        //WP-DM-4: prevDIDDocumentSelfHash MUST be null or a valid MBHash. (A null value marks a root document and
        //is handled by the root/non-root classification below.)
        bool isRoot = document.PrevDidDocumentSelfHash is null;
        if(!isRoot && !IsMbHashShaped(document.PrevDidDocumentSelfHash!))
        {
            return "The did:webplus DID document 'prevDIDDocumentSelfHash' MUST be null or a valid MBHash value.";
        }

        //WP-DM-5: updateRules MUST be present (its validity as an UpdateRules expression is verified by the
        //update-rules evaluation).
        if(document.UpdateRules is null)
        {
            return "The did:webplus DID document MUST have an 'updateRules' field.";
        }

        //WP-DM-8: versionId MUST be an unsigned integer (a JSON number, not a string). The parser surfaces a
        //non-conforming value as null.
        if(document.VersionId is not { } versionId)
        {
            return "The did:webplus DID document 'versionId' MUST be an unsigned integer.";
        }

        //Steps 3 and 4: validFrom MUST be a valid RFC 3339 timestamp with precision no greater than milliseconds,
        //and MUST NOT be before the UNIX epoch.
        string? validFromError = ValidateValidFrom(document.ValidFrom);
        if(validFromError is not null)
        {
            return validFromError;
        }

        //Step 5: each verification method id MUST be a fully-qualified DID resource URL: it MUST carry the
        //selfHash and versionId query parameters in that order, equal to the document's selfHash and versionId,
        //and MUST have a URL fragment.
        foreach(VerificationMethod verificationMethod in document.VerificationMethod ?? Array.Empty<VerificationMethod>())
        {
            if(verificationMethod.Id is not { Length: > 0 } verificationMethodId)
            {
                return "Each did:webplus verification method MUST have a string 'id'.";
            }

            string? verificationMethodError = ValidateVerificationMethodId(verificationMethodId, selfHash, versionId);
            if(verificationMethodError is not null)
            {
                return verificationMethodError;
            }
        }

        //Root constraint (did:webplus Draft v0.4, Validation of DID Documents, step 6 — root branch): a root DID
        //document's versionId MUST be the numeric value 0. The non-root cross-document constraints are folded by
        //the microledger replay.
        if(isRoot && versionId != 0)
        {
            return $"The did:webplus root DID document 'versionId' MUST be 0; it is {versionId}.";
        }

        return null;
    }


    //A verification method id MUST be of the canonical form
    //"<did>?selfHash=<doc.selfHash>&versionId=<doc.versionId>#<fragment>". Requiring the query to be exactly the
    //selfHash and versionId parameters, in that order, enforces in one comparison that both are present, in the
    //specified order, and equal to the document's selfHash and versionId fields.
    private static string? ValidateVerificationMethodId(string verificationMethodId, string selfHash, ulong versionId)
    {
        int fragmentSeparator = verificationMethodId.IndexOf('#', StringComparison.Ordinal);
        if(fragmentSeparator < 0 || fragmentSeparator == verificationMethodId.Length - 1)
        {
            return $"The did:webplus verification method id '{verificationMethodId}' MUST have a URL fragment.";
        }

        int querySeparator = verificationMethodId.IndexOf('?', StringComparison.Ordinal);
        if(querySeparator < 0 || querySeparator > fragmentSeparator)
        {
            return $"The did:webplus verification method id '{verificationMethodId}' MUST have 'selfHash' and 'versionId' query parameters.";
        }

        ReadOnlySpan<char> query = verificationMethodId.AsSpan((querySeparator + 1)..fragmentSeparator);
        string expectedQuery = $"{WellKnownWebPlusValues.SelfHashQueryParameter}={selfHash}&{WellKnownWebPlusValues.VersionIdQueryParameter}={versionId.ToString(CultureInfo.InvariantCulture)}";
        if(!query.SequenceEqual(expectedQuery))
        {
            return $"The did:webplus verification method id '{verificationMethodId}' MUST carry the document's selfHash and versionId, in that order, as query parameters.";
        }

        return null;
    }


    //Steps 3 and 4: validFrom MUST be a valid RFC 3339 timestamp with millisecond-or-coarser precision (for
    //interoperability with Javascript implementations) and MUST NOT be before the UNIX epoch.
    private static string? ValidateValidFrom(string? validFrom)
    {
        if(validFrom is not { Length: > 0 } value)
        {
            return "The did:webplus DID document 'validFrom' MUST be a valid RFC 3339 timestamp.";
        }

        if(!DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTimeOffset timestamp))
        {
            return $"The did:webplus DID document 'validFrom' '{value}' MUST be a valid RFC 3339 timestamp.";
        }

        if(!HasRfc3339Offset(value))
        {
            //RFC 3339 requires an explicit time-offset; DateTimeOffset.TryParse would otherwise bind an offset-less
            //value to the resolver host's local zone, so two resolvers in different zones could order the history
            //(WP-VAL-7c strictly-later, versionTime selection) differently. An offset-less value is rejected.
            return $"The did:webplus DID document 'validFrom' '{value}' MUST be a valid RFC 3339 timestamp with an explicit offset (a trailing 'Z' or +hh:mm).";
        }

        if(FractionalDigitCount(value) > 3)
        {
            return $"The did:webplus DID document 'validFrom' '{value}' MUST have precision no greater than milliseconds.";
        }

        if(timestamp < DateTimeOffset.UnixEpoch)
        {
            return $"The did:webplus DID document 'validFrom' '{value}' MUST NOT be before the UNIX epoch.";
        }

        return null;
    }


    //Whether an RFC 3339 timestamp carries an explicit time-offset: a trailing 'Z' (UTC) or a numeric +hh:mm /
    //-hh:mm offset. The offset sign lives in the time portion after the 'T' separator, so the date's own hyphens
    //are excluded by scanning only that portion. A timestamp with no explicit offset is not valid RFC 3339.
    private static bool HasRfc3339Offset(string timestamp)
    {
        int timeSeparator = timestamp.IndexOf('T', StringComparison.OrdinalIgnoreCase);
        if(timeSeparator < 0)
        {
            return false;
        }

        ReadOnlySpan<char> time = timestamp.AsSpan(timeSeparator + 1);

        return (time.Length > 0 && (time[^1] == 'Z' || time[^1] == 'z')) || time.Contains('+') || time.Contains('-');
    }


    //Counts the fractional-second digits in an RFC 3339 timestamp: the run of decimal digits immediately after
    //the '.' that follows the seconds. Returns 0 when there is no fractional part.
    private static int FractionalDigitCount(string timestamp)
    {
        int dot = timestamp.IndexOf('.', StringComparison.Ordinal);
        if(dot < 0)
        {
            return 0;
        }

        int count = 0;
        for(int i = dot + 1; i < timestamp.Length && char.IsAsciiDigit(timestamp[i]); i++)
        {
            count++;
        }

        return count;
    }


    //A did:webplus MBHash is a multibase string: a base64url ('u', RECOMMENDED) or base58btc ('z') prefix
    //followed by the encoded self-describing multihash. The full multihash decode is the MBHash slice; this
    //checks the multibase shape the data model requires.
    private static bool IsMbHashShaped(string value)
    {
        return value.Length > 1 && value[0] is Base64UrlMultibasePrefix or Base58BtcMultibasePrefix;
    }
}
