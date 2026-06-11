using System.Collections;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// OID4VCI 1.0 §12.2.4 inner-<c>REQUIRED</c> member validation for the application-supplied
/// <see cref="CredentialIssuerMetadataContribution"/>, as a LIBRARY GUARANTEE rather than an
/// unguarded deployment responsibility: the Credential Issuer Metadata endpoint runs it before
/// serving the document, so a misconfigured deployment fails LOUD (the same way the endpoint
/// already fails when <c>credential_endpoint</c> is absent) instead of silently emitting a
/// non-conformant document. The deployment MAY also call <see cref="Validate"/> itself.
/// </summary>
/// <remarks>
/// <para>
/// The library validates the §12.2.4 REQUIRED inner members it can check structurally — the
/// presence (and, where the spec states a numeric floor, the value) of:
/// </para>
/// <list type="bullet">
/// <item>each <c>credential_configurations_supported</c> entry's <c>format</c>:
/// "<c>format</c> : REQUIRED. A JSON string identifying the format of this Credential";</item>
/// <item>each <c>proof_types_supported</c> entry's <c>proof_signing_alg_values_supported</c> when
/// <c>proof_types_supported</c> is present:
/// "<c>proof_signing_alg_values_supported</c> : REQUIRED. A non-empty array of algorithm
/// identifiers that the Issuer supports for this proof type";</item>
/// <item><c>batch_credential_issuance.batch_size</c> when <c>batch_credential_issuance</c> is
/// present, and that it is "2 or greater":
/// "<c>batch_size</c> : REQUIRED. Integer value specifying the maximum array size for the proofs
/// parameter in a Credential Request. It MUST be 2 or greater";</item>
/// <item>the <c>credential_request_encryption</c> object's <c>jwks</c>, <c>enc_values_supported</c>,
/// and <c>encryption_required</c> when that object is present (each "REQUIRED");</item>
/// <item>the <c>credential_response_encryption</c> object's <c>alg_values_supported</c>,
/// <c>enc_values_supported</c>, and <c>encryption_required</c> when that object is present (each
/// "REQUIRED");</item>
/// <item>each Credential Issuer <c>display</c> entry's <c>name</c>.</item>
/// </list>
/// <para>
/// The genuinely Credential-Format-specific REQUIRED members (the <c>format</c>-dependent claims
/// the Appendix A profiles add inside a configuration, and a <c>credential_metadata.display</c>
/// entry's REQUIRED <c>name</c>, which the library does not model as a typed slot) are DELEGATED
/// to the deployment — this helper is available to the deployment to check them alongside its own
/// format knowledge.
/// </para>
/// </remarks>
public static class CredentialIssuerMetadataValidation
{
    /// <summary>
    /// Validates the §12.2.4 REQUIRED inner members of <paramref name="contribution"/> the
    /// library can check. Returns the first violation as a human-readable message, or
    /// <see langword="null"/> when every checked member is conformant.
    /// </summary>
    /// <param name="contribution">The application-supplied Credential Issuer Metadata.</param>
    /// <returns>A description of the first §12.2.4 REQUIRED-member violation, or <see langword="null"/>.</returns>
    public static string? Validate(CredentialIssuerMetadataContribution contribution)
    {
        ArgumentNullException.ThrowIfNull(contribution);

        string? configurationsFault = ValidateCredentialConfigurations(contribution.CredentialConfigurationsSupported);
        if(configurationsFault is not null)
        {
            return configurationsFault;
        }

        string? batchFault = ValidateBatchCredentialIssuance(contribution.BatchCredentialIssuance);
        if(batchFault is not null)
        {
            return batchFault;
        }

        string? requestEncryptionFault = ValidateRequestEncryption(contribution.CredentialRequestEncryption);
        if(requestEncryptionFault is not null)
        {
            return requestEncryptionFault;
        }

        string? responseEncryptionFault = ValidateResponseEncryption(contribution.CredentialResponseEncryption);
        if(responseEncryptionFault is not null)
        {
            return responseEncryptionFault;
        }

        return ValidateIssuerDisplay(contribution.Display);
    }


    /// <summary>
    /// §12.2.4: every <c>credential_configurations_supported</c> entry MUST carry a <c>format</c>,
    /// and when it carries a <c>proof_types_supported</c> each proof type MUST carry a
    /// <c>proof_signing_alg_values_supported</c>.
    /// </summary>
    private static string? ValidateCredentialConfigurations(IReadOnlyDictionary<string, object>? configurations)
    {
        if(configurations is null)
        {
            return null;
        }

        foreach(KeyValuePair<string, object> entry in configurations)
        {
            if(entry.Value is not IReadOnlyDictionary<string, object> configuration)
            {
                return $"credential_configurations_supported['{entry.Key}'] must be an object (§12.2.4).";
            }

            //§12.2.4: "format : REQUIRED. A JSON string identifying the format of this Credential".
            if(!HasNonEmptyString(configuration, CredentialIssuerMetadataParameterNames.Format))
            {
                return $"credential_configurations_supported['{entry.Key}'] is missing the REQUIRED "
                    + "format member (§12.2.4).";
            }

            string? proofFault = ValidateProofTypes(entry.Key, configuration);
            if(proofFault is not null)
            {
                return proofFault;
            }
        }

        return null;
    }


    /// <summary>
    /// §12.2.4: when a configuration declares <c>proof_types_supported</c>, each proof type's value
    /// MUST carry a non-empty <c>proof_signing_alg_values_supported</c> array.
    /// </summary>
    private static string? ValidateProofTypes(string configurationId, IReadOnlyDictionary<string, object> configuration)
    {
        if(!configuration.TryGetValue(AttestationProofParameterNames.ProofTypesSupported, out object? proofTypesValue))
        {
            return null;
        }

        if(proofTypesValue is not IReadOnlyDictionary<string, object> proofTypes)
        {
            return $"credential_configurations_supported['{configurationId}'].proof_types_supported "
                + "must be an object (§12.2.4).";
        }

        foreach(KeyValuePair<string, object> proofType in proofTypes)
        {
            if(proofType.Value is not IReadOnlyDictionary<string, object> proofTypeConfiguration)
            {
                return $"credential_configurations_supported['{configurationId}']."
                    + $"proof_types_supported['{proofType.Key}'] must be an object (§12.2.4).";
            }

            //§12.2.4: "proof_signing_alg_values_supported : REQUIRED. A non-empty array of
            //algorithm identifiers that the Issuer supports for this proof type."
            if(!HasNonEmptyArray(
                proofTypeConfiguration, CredentialIssuerMetadataParameterNames.ProofSigningAlgValuesSupported))
            {
                return $"credential_configurations_supported['{configurationId}']."
                    + $"proof_types_supported['{proofType.Key}'] is missing the REQUIRED non-empty "
                    + "proof_signing_alg_values_supported array (§12.2.4).";
            }
        }

        return null;
    }


    /// <summary>
    /// §12.2.4: <c>batch_credential_issuance</c>, when present, MUST carry a <c>batch_size</c> that
    /// "MUST be 2 or greater".
    /// </summary>
    private static string? ValidateBatchCredentialIssuance(IReadOnlyDictionary<string, object>? batch)
    {
        if(batch is null)
        {
            return null;
        }

        if(!batch.TryGetValue(CredentialIssuerMetadataParameterNames.BatchSize, out object? batchSizeValue)
            || !TryReadInteger(batchSizeValue, out long batchSize))
        {
            return "batch_credential_issuance is missing the REQUIRED integer batch_size member (§12.2.4).";
        }

        //§12.2.4: "batch_size : REQUIRED ... It MUST be 2 or greater."
        if(batchSize < 2)
        {
            return $"batch_credential_issuance.batch_size is {batchSize}; §12.2.4 requires it to be "
                + "2 or greater.";
        }

        return null;
    }


    /// <summary>
    /// §12.2.4: a present <c>credential_request_encryption</c> object MUST carry <c>jwks</c>,
    /// <c>enc_values_supported</c>, and <c>encryption_required</c>.
    /// </summary>
    private static string? ValidateRequestEncryption(IReadOnlyDictionary<string, object>? requestEncryption)
    {
        if(requestEncryption is null)
        {
            return null;
        }

        //§12.2.4: "jwks : REQUIRED. A JSON Web Key Set ... to be used by the Wallet as an input to
        //a key agreement for encryption of the Credential Request."
        if(!requestEncryption.ContainsKey(CredentialIssuerMetadataParameterNames.Jwks))
        {
            return "credential_request_encryption is missing the REQUIRED jwks member (§12.2.4).";
        }

        //§12.2.4: "enc_values_supported : REQUIRED. A non-empty array ... to decode the Credential
        //Request from a JWT."
        if(!HasNonEmptyArray(requestEncryption, CredentialIssuerMetadataParameterNames.EncValuesSupported))
        {
            return "credential_request_encryption is missing the REQUIRED non-empty "
                + "enc_values_supported array (§12.2.4).";
        }

        //§12.2.4: "encryption_required : REQUIRED. Boolean value specifying whether the Credential
        //Issuer requires the additional encryption on top of TLS for the Credential Requests."
        if(!HasBoolean(requestEncryption, CredentialIssuerMetadataParameterNames.EncryptionRequired))
        {
            return "credential_request_encryption is missing the REQUIRED boolean "
                + "encryption_required member (§12.2.4).";
        }

        return null;
    }


    /// <summary>
    /// §12.2.4: a present <c>credential_response_encryption</c> object MUST carry
    /// <c>alg_values_supported</c>, <c>enc_values_supported</c>, and <c>encryption_required</c>.
    /// </summary>
    private static string? ValidateResponseEncryption(IReadOnlyDictionary<string, object>? responseEncryption)
    {
        if(responseEncryption is null)
        {
            return null;
        }

        //§12.2.4: "alg_values_supported : REQUIRED. A non-empty array ... to encode the Credential
        //Response in a JWT."
        if(!HasNonEmptyArray(responseEncryption, CredentialIssuerMetadataParameterNames.AlgValuesSupported))
        {
            return "credential_response_encryption is missing the REQUIRED non-empty "
                + "alg_values_supported array (§12.2.4).";
        }

        //§12.2.4: "enc_values_supported : REQUIRED. A non-empty array ... to encode the Credential
        //Response in a JWT."
        if(!HasNonEmptyArray(responseEncryption, CredentialIssuerMetadataParameterNames.EncValuesSupported))
        {
            return "credential_response_encryption is missing the REQUIRED non-empty "
                + "enc_values_supported array (§12.2.4).";
        }

        //§12.2.4: "encryption_required : REQUIRED. Boolean value specifying whether the Credential
        //Issuer requires the additional encryption on top of TLS for the Credential Response."
        if(!HasBoolean(responseEncryption, CredentialIssuerMetadataParameterNames.EncryptionRequired))
        {
            return "credential_response_encryption is missing the REQUIRED boolean "
                + "encryption_required member (§12.2.4).";
        }

        return null;
    }


    /// <summary>
    /// §12.2.4: each Credential Issuer <c>display</c> entry carries an OPTIONAL <c>name</c>, but the
    /// library still validates the entry SHAPE — a non-object entry could only emit a malformed
    /// <c>display</c> array — and that a present <c>name</c> is a non-empty string.
    /// </summary>
    private static string? ValidateIssuerDisplay(IReadOnlyList<object>? display)
    {
        if(display is null)
        {
            return null;
        }

        for(int i = 0; i < display.Count; i++)
        {
            if(display[i] is not IReadOnlyDictionary<string, object> displayEntry)
            {
                return $"display[{i}] must be an object (§12.2.4).";
            }

            if(displayEntry.ContainsKey(CredentialIssuerMetadataParameterNames.Name)
                && !HasNonEmptyString(displayEntry, CredentialIssuerMetadataParameterNames.Name))
            {
                return $"display[{i}].name must be a non-empty string (§12.2.4).";
            }
        }

        return null;
    }


    /// <summary>Whether <paramref name="member"/> is present as a non-empty string.</summary>
    private static bool HasNonEmptyString(IReadOnlyDictionary<string, object> obj, string member) =>
        obj.TryGetValue(member, out object? value)
            && value is string text
            && !string.IsNullOrWhiteSpace(text);


    /// <summary>Whether <paramref name="member"/> is present as a boolean.</summary>
    private static bool HasBoolean(IReadOnlyDictionary<string, object> obj, string member) =>
        obj.TryGetValue(member, out object? value) && value is bool;


    /// <summary>Whether <paramref name="member"/> is present as a non-empty, non-string enumerable.</summary>
    private static bool HasNonEmptyArray(IReadOnlyDictionary<string, object> obj, string member)
    {
        if(!obj.TryGetValue(member, out object? value)
            || value is string
            || value is not IEnumerable enumerable)
        {
            return false;
        }

        foreach(object? _ in enumerable)
        {
            return true;
        }

        return false;
    }


    /// <summary>Reads a non-fractional integer from an <see cref="int"/>, <see cref="long"/>, or numeric string.</summary>
    private static bool TryReadInteger(object? value, out long result)
    {
        switch(value)
        {
            case int intValue:
            {
                result = intValue;

                return true;
            }
            case long longValue:
            {
                result = longValue;

                return true;
            }
            case string stringValue when long.TryParse(
                stringValue, System.Globalization.NumberStyles.Integer,
                System.Globalization.CultureInfo.InvariantCulture, out long parsed):
            {
                result = parsed;

                return true;
            }
            default:
            {
                result = 0;

                return false;
            }
        }
    }
}
