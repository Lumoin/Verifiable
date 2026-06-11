namespace Verifiable.OAuth.Siop;

/// <summary>
/// Validates the Relying Party's inbound Authorization Request on the Self-Issued OP
/// (wallet) side per
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-7.4">SIOPv2 §7.4</see>
/// and
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-10.3">SIOPv2 §10.3</see>.
/// </summary>
/// <remarks>
/// <para>
/// This is the mirror of <see cref="SelfIssuedIdTokenValidation"/>: that primitive is the
/// RP validating the OP's <c>id_token</c> response, this one is the OP validating the RP's
/// request. It is a free-standing primitive with no <c>AuthorizationServer</c>, executor,
/// dispatch, or HTTP coupling — a wallet, an agent, or a test harness all validate the
/// same way.
/// </para>
/// <para>
/// The OP obtains RP metadata one of three ways (§7): pre-registered (§7.1), by value in
/// the <c>client_metadata</c> parameter (§7.3), or by reference via
/// <c>client_metadata_uri</c> (§7.3). This primitive does NOT dereference
/// <c>client_metadata_uri</c> over the network — keeping with the library's transport
/// boundary, the already-dereferenced metadata (or the fact that the dereference failed)
/// is passed in as <see cref="SiopDereferencedClientMetadata"/>.
/// </para>
/// <para>
/// The check order is the OP's processing order and doubles as the error precedence,
/// most-specific structural failure first:
/// </para>
/// <list type="number">
///   <item><description>
///     §7.4 / §9 source consistency. §7.4: "Self-Issued OPs compliant with this
///     specification MUST NOT proceed with the transaction when pre-registered client
///     metadata has been found based on the Client ID, but <c>client_metadata</c>
///     parameter has also been present." §9: "<c>client_metadata</c> and
///     <c>client_metadata_uri</c> are mutually exclusive." A contradictory source is an
///     invalid RP parameter Object, so this maps to
///     <see cref="SiopErrors.InvalidClientMetadataObject"/> and gates everything below —
///     when the source is inconsistent the OP must not proceed, so the value checks are
///     not reached.
///   </description></item>
///   <item><description>
///     §10.3 <c>invalid_client_metadata_uri</c>: "the <c>client_metadata_uri</c> in the
///     Authorization Request returns an error or contains invalid data." When the request
///     used <c>client_metadata_uri</c> and the dereference failed there are no metadata
///     values to evaluate, so this precedes the value checks.
///   </description></item>
///   <item><description>
///     §10.3 <c>subject_syntax_types_not_supported</c>: "the Self-Issued OP does not
///     support any of the Subject Syntax Types supported by the RP, which were
///     communicated in the request in the <c>subject_syntax_types_supported</c>
///     parameter." <c>subject_syntax_types_supported</c> is itself a <c>client_metadata</c>
///     value, but §10.3 gives it its own, more-specific code, so it is checked before the
///     general value bucket.
///   </description></item>
///   <item><description>
///     §10.3 <c>client_metadata_value_not_supported</c>: "the Self-Issued OP does not
///     support some Relying Party parameter values received in the request." The general
///     bucket for any remaining unsupported <c>client_metadata</c> value (e.g. an
///     <c>id_token_signed_response_alg</c> the OP will not honor).
///   </description></item>
/// </list>
/// </remarks>
public static class SiopRequestValidation
{
    /// <summary>
    /// Validates the RP's Authorization Request against the OP's capabilities and
    /// registration knowledge, returning the per-check outcome and the §10.3 error code
    /// to return on failure.
    /// </summary>
    /// <param name="request">The parsed RP Authorization Request to validate.</param>
    /// <param name="supportedSubjectSyntaxTypes">
    /// The Subject Syntax Type identifiers the OP supports — the value space of its own
    /// <c>subject_syntax_types_supported</c> (§6.1). A request whose
    /// <c>subject_syntax_types_supported</c> shares none of these fails §10.3
    /// <c>subject_syntax_types_not_supported</c>.
    /// </param>
    /// <param name="supportedIdTokenSignedResponseAlgValues">
    /// The <c>id_token_signed_response_alg</c> values the OP will sign with — its
    /// <c>id_token_signing_alg_values_supported</c> (§6.1). A request asking for an
    /// algorithm outside this set fails §10.3 <c>client_metadata_value_not_supported</c>.
    /// </param>
    /// <param name="isClientPreRegistered">
    /// The OP's own registration knowledge: <see langword="true"/> when the request's
    /// <c>client_id</c> is pre-registered with the OP per §7.1. §7.4 forbids a
    /// pre-registered Client ID from also carrying <c>client_metadata</c>/
    /// <c>client_metadata_uri</c>. This is the OP's app-held state, supplied as data, the
    /// same way replay/jti checks consult app-held state through a seam.
    /// </param>
    /// <param name="dereferencedClientMetadata">
    /// The metadata obtained by dereferencing <c>client_metadata_uri</c>, supplied as
    /// data because dereferencing is a network act the OP performs outside this primitive
    /// (§7.3). Required only when <see cref="SiopRequest.ClientMetadataUri"/> is set;
    /// <see langword="null"/> otherwise. When the dereference failed,
    /// <see cref="SiopDereferencedClientMetadata.IsResolved"/> is <see langword="false"/>
    /// (§10.3 <c>invalid_client_metadata_uri</c>).
    /// </param>
    /// <returns>The per-check validation outcome.</returns>
    public static SiopRequestValidationResult Validate(
        SiopRequest request,
        IReadOnlyCollection<string> supportedSubjectSyntaxTypes,
        IReadOnlyCollection<string> supportedIdTokenSignedResponseAlgValues,
        bool isClientPreRegistered,
        SiopDereferencedClientMetadata? dereferencedClientMetadata)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(supportedSubjectSyntaxTypes);
        ArgumentNullException.ThrowIfNull(supportedIdTokenSignedResponseAlgValues);

        bool hasClientMetadata = request.ClientMetadata is not null;
        bool hasClientMetadataUri = request.ClientMetadataUri is not null;

        //§7.4: "Self-Issued OPs compliant with this specification MUST NOT proceed with
        //the transaction when pre-registered client metadata has been found based on the
        //Client ID, but client_metadata parameter has also been present." §9:
        //"client_metadata and client_metadata_uri are mutually exclusive." A
        //pre-registered Client ID that also carries a just-in-time metadata source, or a
        //request carrying both just-in-time sources, is a contradictory RP parameter
        //Object.
        bool hasPreRegisteredConflict = isClientPreRegistered && (hasClientMetadata || hasClientMetadataUri);
        bool hasBothJustInTimeSources = hasClientMetadata && hasClientMetadataUri;
        bool isMetadataSourceConsistent = !hasPreRegisteredConflict && !hasBothJustInTimeSources;

        //§10.3 invalid_client_metadata_uri: "the client_metadata_uri in the Authorization
        //Request returns an error or contains invalid data." A request with no
        //client_metadata_uri has nothing to dereference and so trivially resolves; a
        //request that used it depends on the dereference outcome supplied as data.
        bool isClientMetadataUriResolved = !hasClientMetadataUri
            || (dereferencedClientMetadata is not null && dereferencedClientMetadata.IsResolved);

        //The effective RP metadata is the inline client_metadata when present, otherwise
        //the dereferenced client_metadata_uri payload. §7.5: subject_syntax_types_supported
        //is REQUIRED, so its value space is evaluated whenever metadata is available.
        SiopRelyingPartyMetadata? effectiveMetadata = request.ClientMetadata
            ?? (isClientMetadataUriResolved ? dereferencedClientMetadata?.Metadata : null);

        //§10.3 subject_syntax_types_not_supported: "the Self-Issued OP does not support
        //any of the Subject Syntax Types supported by the RP, which were communicated in
        //the request in the subject_syntax_types_supported parameter." Support means at
        //least one requested type is also OP-supported. With no metadata to evaluate the
        //request communicated no types to reject, so this check does not fail closed here.
        bool isSubjectSyntaxSupported = effectiveMetadata is null
            || HasAnySupportedSubjectSyntaxType(
                effectiveMetadata.SubjectSyntaxTypesSupported, supportedSubjectSyntaxTypes);

        //§10.3 client_metadata_value_not_supported: "the Self-Issued OP does not support
        //some Relying Party parameter values received in the request." The governed value
        //here is id_token_signed_response_alg; an absent value asks for nothing the OP
        //must honor and so cannot be unsupported.
        bool areClientMetadataValuesSupported = effectiveMetadata is null
            || effectiveMetadata.IdTokenSignedResponseAlg is null
            || ContainsOrdinal(supportedIdTokenSignedResponseAlgValues, effectiveMetadata.IdTokenSignedResponseAlg);

        string? errorCode = ResolveErrorCode(
            isMetadataSourceConsistent,
            isClientMetadataUriResolved,
            isSubjectSyntaxSupported,
            areClientMetadataValuesSupported);

        return new SiopRequestValidationResult
        {
            IsMetadataSourceConsistent = isMetadataSourceConsistent,
            IsClientMetadataUriResolved = isClientMetadataUriResolved,
            IsSubjectSyntaxSupported = isSubjectSyntaxSupported,
            AreClientMetadataValuesSupported = areClientMetadataValuesSupported,
            ErrorCode = errorCode
        };
    }


    //Maps the failing check to its §7.4 / §10.3 error code in precedence order: a
    //contradictory metadata source (§7.4/§9) is the structural failure that stops the
    //transaction, then a failed client_metadata_uri dereference (no values to evaluate),
    //then the dedicated subject-syntax code, then the general unsupported-value bucket.
    private static string? ResolveErrorCode(
        bool isMetadataSourceConsistent,
        bool isClientMetadataUriResolved,
        bool isSubjectSyntaxSupported,
        bool areClientMetadataValuesSupported) => true switch
        {
            _ when !isMetadataSourceConsistent => SiopErrors.InvalidClientMetadataObject,
            _ when !isClientMetadataUriResolved => SiopErrors.InvalidClientMetadataUri,
            _ when !isSubjectSyntaxSupported => SiopErrors.SubjectSyntaxTypesNotSupported,
            _ when !areClientMetadataValuesSupported => SiopErrors.ClientMetadataValueNotSupported,
            _ => null
        };


    private static bool HasAnySupportedSubjectSyntaxType(
        IReadOnlyList<string> requestedTypes,
        IReadOnlyCollection<string> supportedTypes)
    {
        foreach(string requested in requestedTypes)
        {
            if(ContainsOrdinal(supportedTypes, requested))
            {
                return true;
            }
        }

        return false;
    }


    private static bool ContainsOrdinal(IEnumerable<string> values, string candidate)
    {
        foreach(string value in values)
        {
            if(string.Equals(value, candidate, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
