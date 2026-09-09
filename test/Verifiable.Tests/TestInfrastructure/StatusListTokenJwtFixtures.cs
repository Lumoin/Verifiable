using Verifiable.Core.Model.Credentials;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth.StatusList;
using Verifiable.Tests.DataIntegrity;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Issues the Token Status List JWT wire form
/// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status
/// List, Section 5.1</see>) for real-wire capstones, over the library's own composition
/// (<see cref="StatusListTokenIssuance"/>) rather than a fixture-local re-implementation — the read side is
/// the library's own <see cref="StatusListTokenResolvers.BuildResolving"/>, composed directly at each call
/// site rather than wrapped here.
/// </summary>
internal static class StatusListTokenJwtFixtures
{
    /// <summary>The shared memory pool backing every pooled carrier this fixture allocates.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    /// <summary>
    /// Issues a compact-serialized JWT Status List Token for <paramref name="token"/>, signed by
    /// <paramref name="issuerPrivate"/> — a thin call onto <see cref="StatusListTokenIssuance.ComposeAsync"/>
    /// with the test project's own base64url and JSON-leaf JWT part codecs.
    /// </summary>
    /// <param name="token">The Status List Token to serialize and sign.</param>
    /// <param name="issuerPrivate">The issuer's signing key; its <see cref="Tag"/> resolves the JWA algorithm and the signing function.</param>
    /// <param name="keyId">The <c>kid</c> header value identifying the signing key.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The compact JWT (<c>header.payload.signature</c>).</returns>
    public static async Task<string> IssueJwtAsync(
        StatusListToken token, PrivateKeyMemory issuerPrivate, string keyId, CancellationToken cancellationToken) =>
        await StatusListTokenIssuance.ComposeAsync(
            token,
            issuerPrivate,
            keyId,
            TestSetup.Base64UrlEncoder,
            JwtClaimsJson.HeaderSerializer,
            JwtClaimsJson.PayloadSerializer,
            Pool,
            cancellationToken).ConfigureAwait(false);


    /// <summary>
    /// Deserializes <paramref name="template"/> as a <see cref="VerifiableCredential"/> and patches its
    /// first credential subject's <see cref="BitstringStatusListConstants.EncodedListProperty"/> to
    /// <paramref name="encodedList"/> — the VC-DM 2.0 Bitstring Status List credential wire shape, distinct
    /// from this class's JWT/CWT Status List Token shape above.
    /// </summary>
    /// <param name="template">The status list credential's fixed JSON-LD template text.</param>
    /// <param name="encodedList">The base64url, zlib-compressed bitstring to install as <c>encodedList</c>.</param>
    /// <returns>The patched credential.</returns>
    public static VerifiableCredential BuildStatusListCredential(string template, string encodedList)
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(template, CredentialSecuringMaterial.JsonOptions)!;
        credential.CredentialSubject![0].AdditionalData![BitstringStatusListConstants.EncodedListProperty] = encodedList;

        return credential;
    }
}
