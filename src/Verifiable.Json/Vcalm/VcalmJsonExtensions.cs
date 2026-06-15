using System.Text.Json;
using Verifiable.Vcalm;

namespace Verifiable.Json;

/// <summary>
/// Wires the default <c>System.Text.Json</c> VCALM 1.0 request parsers
/// (<see cref="VcalmJsonParsing"/>) onto a <see cref="VcalmIntegration"/>. This is the JSON-side
/// counterpart the <c>Verifiable.Vcalm</c> serialization firewall expects the application to supply
/// for the §3.2.1 issuer and §3.3.1 / §3.3.2 verifier endpoints.
/// </summary>
public static class VcalmJsonExtensions
{
    /// <summary>
    /// Sets <see cref="VcalmIntegration.ParseVcalmVerifyCredentialAsync"/>,
    /// <see cref="VcalmIntegration.ParseVcalmVerifyPresentationAsync"/>,
    /// <see cref="VcalmIntegration.ParseVcalmIssueCredentialAsync"/>,
    /// <see cref="VcalmIntegration.ParseVcalmDeriveCredentialAsync"/>,
    /// <see cref="VcalmIntegration.ParseVcalmCreatePresentationAsync"/>,
    /// <see cref="VcalmIntegration.ParseVcalmUpdateStatusAsync"/>, and
    /// <see cref="VcalmIntegration.ParseVcalmCreateStatusListAsync"/> to the default STJ parsers when
    /// they are not already set, so an application can override any before or after calling this. The
    /// cryptographic seams (which carry behavior, not wire) are NOT set here — the application always
    /// supplies <see cref="VcalmIntegration.VcalmCredentialVerification"/> (verifier),
    /// <see cref="VcalmIntegration.VcalmCredentialIssuance"/> (issuer),
    /// <see cref="VcalmIntegration.VcalmCredentialDerivation"/> / <see cref="VcalmIntegration.VcalmPresentationSigning"/>
    /// (§3.5 holder), and <see cref="VcalmIntegration.VcalmStatusListIssuance"/> (§C.1 status service).
    /// </summary>
    /// <param name="integration">The integration to wire.</param>
    /// <param name="options">The serializer options carrying the Verifiable credential converters.</param>
    /// <returns>The same <paramref name="integration"/> for chaining.</returns>
    public static VcalmIntegration UseDefaultVcalmJsonParsing(
        this VcalmIntegration integration,
        JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(integration);
        ArgumentNullException.ThrowIfNull(options);

        integration.ParseVcalmVerifyCredentialAsync ??=
            VcalmJsonParsing.CreateCredentialParser(options);
        integration.ParseVcalmVerifyPresentationAsync ??=
            VcalmJsonParsing.CreatePresentationParser(options);
        integration.ParseVcalmIssueCredentialAsync ??=
            VcalmJsonParsing.CreateIssueParser(options);
        integration.ParseVcalmDeriveCredentialAsync ??=
            VcalmJsonParsing.CreateDeriveParser(options);
        integration.ParseVcalmCreatePresentationAsync ??=
            VcalmJsonParsing.CreateCreatePresentationParser(options);

        //The §C.3 / §C.1 status bodies are small fixed-shape objects read with JsonDocument, so their
        //parsers carry no serializer-options dependency.
        integration.ParseVcalmUpdateStatusAsync ??=
            VcalmJsonParsing.CreateUpdateStatusParser();
        integration.ParseVcalmCreateStatusListAsync ??=
            VcalmJsonParsing.CreateStatusListParser();

        //The §3.6.3 create-exchange body is a small fixed-shape object; the §3.6.5 vcapi message
        //carries a verifiablePresentation / verifiablePresentationRequest that needs the converters.
        integration.ParseVcalmCreateExchangeAsync ??=
            VcalmJsonParsing.CreateExchangeParser();
        integration.ParseVcalmExchangeMessageAsync ??=
            VcalmJsonParsing.CreateExchangeMessageParser(options);

        //§3.6.1 create-workflow and §3.6.7 callback bodies are fixed-shape objects read with
        //JsonDocument; their parsers carry no serializer-options dependency.
        integration.ParseVcalmCreateWorkflowAsync ??=
            VcalmJsonParsing.CreateWorkflowParser();
        integration.ParseVcalmCallbackAsync ??=
            VcalmJsonParsing.CreateCallbackParser();

        //§3.6 issuance-in-exchange: the JSON → JsonataValue adapter the workflow step engine feeds to
        //the credential-template evaluation. STJ stays behind this seam (serialization firewall).
        integration.ParseVcalmTemplateInputAsync ??=
            VcalmJsonParsing.CreateTemplateInputParser();

        //§3.7.5 inviteRequest body is a fixed-shape object read with JsonDocument; its parser carries no
        //serializer-options dependency.
        integration.ParseVcalmInviteRequestAsync ??=
            VcalmJsonParsing.CreateInviteRequestParser();

        return integration;
    }
}
