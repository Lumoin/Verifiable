using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.SecurityEvents;
using Verifiable.OAuth.Logout;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> parser for the Global Token Revocation request
/// body (<see href="https://datatracker.ietf.org/doc/draft-parecki-oauth-global-token-revocation/">draft-parecki-oauth-global-token-revocation §3</see>)
/// — the JSON side the <c>Verifiable.OAuth</c> serialization firewall keeps out of
/// the core library. Wire it onto an
/// <see cref="Verifiable.OAuth.Server.AuthorizationServerIntegration"/> with
/// <see cref="GlobalTokenRevocationJsonExtensions.UseDefaultGlobalTokenRevocationJsonParsing"/>.
/// </summary>
public static class GlobalTokenRevocationJsonParsing
{
    /// <summary>
    /// The request body's single required member — an RFC 9493 Subject Identifier
    /// object (reused from the Shared Signals subsystem).
    /// </summary>
    private const string SubIdMember = "sub_id";

    /// <summary>
    /// Parses a Global Token Revocation request body: a JSON object with a single
    /// REQUIRED <c>sub_id</c> member carrying an RFC 9493 Subject Identifier.
    /// </summary>
    /// <remarks>
    /// STRICT, per the strict-conformance principle: a body that is not a JSON
    /// object, omits <c>sub_id</c>, or whose <c>sub_id</c> is not a well-formed
    /// Subject Identifier yields <see langword="null"/> — the endpoint then
    /// responds HTTP 400. Never throws to the caller. The endpoint additionally
    /// rejects a parsed-but-unrecognized-format <c>sub_id</c> via
    /// <see cref="SubjectIdentifier.IsValidForKnownFormat"/>.
    /// </remarks>
    public static ValueTask<GlobalTokenRevocationRequest?> ParseGlobalTokenRevocationRequest(
        string requestBody, ExchangeContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestBody);

        try
        {
            using JsonDocument doc = JsonDocument.Parse(requestBody);
            JsonElement root = doc.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return ValueTask.FromResult<GlobalTokenRevocationRequest?>(null);
            }

            //ReadSubject returns null when the member is absent and throws when it
            //is present but malformed; the catch maps the throw to null (HTTP 400).
            SubjectIdentifier? subId = SsfJsonReadHelpers.ReadSubject(root, SubIdMember);
            if(subId is null)
            {
                return ValueTask.FromResult<GlobalTokenRevocationRequest?>(null);
            }

            return ValueTask.FromResult<GlobalTokenRevocationRequest?>(new GlobalTokenRevocationRequest
            {
                SubId = subId
            });
        }
        catch(Exception ex) when(SsfJsonReadHelpers.IsParseFailure(ex))
        {
            return ValueTask.FromResult<GlobalTokenRevocationRequest?>(null);
        }
    }
}
