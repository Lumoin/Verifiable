using System;
using System.Collections.Generic;
using System.Text.Json;
using Verifiable.Core.SecurityEvents;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> parser for the Shared Signals Transmitter
/// Configuration Metadata document (<c>/.well-known/ssf-configuration</c>,
/// OpenID SSF 1.0 §7.1) — the JSON side the <c>Verifiable.Core</c> serialization
/// firewall keeps out of the core.
/// </summary>
/// <remarks>
/// <para>
/// Parsing is <strong>faithful and strict</strong>: it reads with
/// <see cref="JsonDocument"/> so string values stay strings (no date coercion,
/// matching the AuthZEN parser path). <c>issuer</c> is required; a body that is
/// not a JSON object, lacks <c>issuer</c>, carries a wrongly-typed field, or
/// gives <c>default_subjects</c> a value other than <c>ALL</c>/<c>NONE</c> yields
/// <see langword="null"/>. It never throws to the caller.
/// </para>
/// <para>
/// The same document is served at <c>/.well-known/risc-configuration</c> by a
/// Transmitter supporting the legacy RISC discovery path (SSF §7.2.2); this
/// parser is path-agnostic — the caller chooses which well-known URI to fetch.
/// </para>
/// </remarks>
public static class SsfDiscoveryJsonParsing
{
    /// <summary>
    /// Parses a Transmitter Configuration Metadata document. Returns
    /// <see langword="null"/> on any structural or conformance failure.
    /// </summary>
    /// <param name="metadataJson">The fetched metadata document.</param>
    public static SsfTransmitterConfiguration? ParseTransmitterConfiguration(string metadataJson)
    {
        ArgumentNullException.ThrowIfNull(metadataJson);

        try
        {
            using JsonDocument document = JsonDocument.Parse(metadataJson, SsfJsonReadHelpers.DocumentOptions);
            JsonElement root = document.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            string? issuer = SsfJsonReadHelpers.ReadOptionalString(root, SsfMetadataParameterNames.Issuer);
            if(string.IsNullOrEmpty(issuer))
            {
                return null;
            }

            string? defaultSubjects = SsfJsonReadHelpers.ReadOptionalString(root, SsfMetadataParameterNames.DefaultSubjects);
            if(defaultSubjects is not null
                && !string.Equals(defaultSubjects, SsfMetadataParameterNames.DefaultSubjectsAll, StringComparison.Ordinal)
                && !string.Equals(defaultSubjects, SsfMetadataParameterNames.DefaultSubjectsNone, StringComparison.Ordinal))
            {
                return null;
            }

            return new SsfTransmitterConfiguration
            {
                Issuer = issuer,
                SpecVersion = SsfJsonReadHelpers.ReadOptionalString(root, SsfMetadataParameterNames.SpecVersion),
                JwksUri = SsfJsonReadHelpers.ReadOptionalString(root, SsfMetadataParameterNames.JwksUri),
                DeliveryMethodsSupported = SsfJsonReadHelpers.ReadStringArray(root, SsfMetadataParameterNames.DeliveryMethodsSupported),
                ConfigurationEndpoint = SsfJsonReadHelpers.ReadOptionalString(root, SsfMetadataParameterNames.ConfigurationEndpoint),
                StatusEndpoint = SsfJsonReadHelpers.ReadOptionalString(root, SsfMetadataParameterNames.StatusEndpoint),
                AddSubjectEndpoint = SsfJsonReadHelpers.ReadOptionalString(root, SsfMetadataParameterNames.AddSubjectEndpoint),
                RemoveSubjectEndpoint = SsfJsonReadHelpers.ReadOptionalString(root, SsfMetadataParameterNames.RemoveSubjectEndpoint),
                VerificationEndpoint = SsfJsonReadHelpers.ReadOptionalString(root, SsfMetadataParameterNames.VerificationEndpoint),
                CriticalSubjectMembers = SsfJsonReadHelpers.ReadStringArray(root, SsfMetadataParameterNames.CriticalSubjectMembers),
                AuthorizationSchemes = ReadAuthorizationSchemes(root),
                DefaultSubjects = defaultSubjects
            };
        }
        catch(Exception ex) when(SsfJsonReadHelpers.IsParseFailure(ex))
        {
            return null;
        }
    }


    private static List<SsfAuthorizationScheme>? ReadAuthorizationSchemes(JsonElement root)
    {
        if(!root.TryGetProperty(SsfMetadataParameterNames.AuthorizationSchemes, out JsonElement value))
        {
            return null;
        }

        if(value.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException($"Field '{SsfMetadataParameterNames.AuthorizationSchemes}' must be an array.");
        }

        var schemes = new List<SsfAuthorizationScheme>(value.GetArrayLength());
        foreach(JsonElement entry in value.EnumerateArray())
        {
            if(entry.ValueKind != JsonValueKind.Object)
            {
                throw new JsonException("Each authorization scheme must be a JSON object.");
            }

            string? specUrn = SsfJsonReadHelpers.ReadOptionalString(entry, SsfMetadataParameterNames.SpecUrn);
            if(string.IsNullOrEmpty(specUrn))
            {
                throw new JsonException($"An authorization scheme is missing required '{SsfMetadataParameterNames.SpecUrn}'.");
            }

            schemes.Add(new SsfAuthorizationScheme { SpecUrn = specUrn });
        }

        return schemes;
    }
}
