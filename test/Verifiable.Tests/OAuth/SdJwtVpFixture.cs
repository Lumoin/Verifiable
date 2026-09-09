using System.Buffers;
using System.Buffers.Text;
using System.Text;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Json.StatusList;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The SD-JWT VC (<c>dc+sd-jwt</c>) credential format expressed as a
/// <see cref="FormatFixture"/> for the scheme × format matrix: it builds a plain
/// host, issues a PID SD-JWT VC (holder JWK in <c>cnf</c>), registers the issuer's
/// trust, and wires the presentation drop-out
/// (<see cref="TestHostShell.BuildSdJwtProduceDelegate(string, PrivateKeyMemory)"/>).
/// The single source of the SD-JWT PID issuance every SD-JWT VC seat shares: the
/// matrix, the <see cref="Oid4VpWalletClientTests"/> presentation/disclosure tests,
/// the OID4VP flow tests and the SIOPv2 combined-response tests, including the
/// status-bearing variant they mint through
/// <see cref="IssuePidCredentialWithClaimsAsync"/>.
/// </summary>
internal static class SdJwtVpFixture
{
    /// <summary>The issuer identifier the PID is issued under and registered as trusted.</summary>
    public const string IssuerId = "https://issuer.example.com";

    private const string IssuerKeyId = "did:web:issuer.example.com#key-1";

    /// <summary>
    /// The tilde RFC 9901 Section 4 separates an SD-JWT's issuer-signed JWT, its Disclosures and its
    /// Key Binding JWT with.
    /// </summary>
    private const string SdJwtSeparator = "~";

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    /// <summary>The SD-JWT matrix-format row: name plus the per-run <see cref="FormatRun"/> factory.</summary>
    public static FormatFixture Format => new("dc+sd-jwt", StartAsync);


    private static async ValueTask<FormatRun> StartAsync(FakeTimeProvider tp, CancellationToken cancellationToken)
    {
        TestHostShell app = new(tp);

        (string serializedSdJwt, PrivateKeyMemory holderKey, PublicKeyMemory issuerKey) =
            await IssuePidCredentialAsync(tp, cancellationToken).ConfigureAwait(false);
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        return new FormatRun
        {
            App = app,
            Query = DcqlFixtures.PidFamilyNamePrepared(),
            Produce = TestHostShell.BuildSdJwtProduceDelegate(serializedSdJwt, holderKey),
            AssertClaims = static verified => Assert.IsTrue(verified.Credentials.ContainsKey(new CredentialQueryId("pid")),
                "Verifier must surface the wallet's presentation under the 'pid' credential query id."),
            Owned = [holderKey, issuerKey]
        };
    }


    /// <summary>
    /// Issues an EUDI PID SD-JWT VC (P-256 issuer signature, Ed25519 holder key in
    /// <c>cnf</c>, <c>given_name</c> + <c>family_name</c> disclosable) for
    /// <c>Erika Mustermann</c> under this fixture's own issuer identity, key id and
    /// pool. The caller owns the returned holder private key and issuer public key.
    /// </summary>
    /// <param name="tp">The clock whose current instant becomes the credential's <c>iat</c>.</param>
    /// <param name="cancellationToken">Cancels the issuance.</param>
    public static ValueTask<(string SerializedSdJwt, PrivateKeyMemory HolderPrivateKey, PublicKeyMemory IssuerPublicKey)> IssuePidCredentialAsync(
        FakeTimeProvider tp, CancellationToken cancellationToken) =>
        IssuePidCredentialWithClaimsAsync(
            tp, "Erika", "Mustermann", IssuerId, IssuerKeyId, Pool, status: null, cancellationToken);


    /// <summary>
    /// Issues an EUDI PID SD-JWT VC (P-256 issuer signature, Ed25519 holder key in <c>cnf</c>,
    /// <c>given_name</c> + <c>family_name</c> disclosable) with the caller's claim values, issuer
    /// identity, key id and pool, optionally referencing an entry in a Status List. The caller owns
    /// the returned holder private key and issuer public key.
    /// </summary>
    /// <param name="tp">The clock whose current instant becomes the credential's <c>iat</c>.</param>
    /// <param name="givenName">The value of the disclosable <c>given_name</c> claim.</param>
    /// <param name="familyName">The value of the disclosable <c>family_name</c> claim.</param>
    /// <param name="issuerId">The issuer identifier the credential is issued under.</param>
    /// <param name="issuerKeyId">The key id the issuer's signature carries.</param>
    /// <param name="pool">The pool every issuance buffer is rented from.</param>
    /// <param name="status">
    /// The Status List entry the credential references, or <see langword="null"/> for a credential
    /// that references none.
    /// </param>
    /// <param name="cancellationToken">Cancels the issuance.</param>
    /// <param name="rawStatusObject">
    /// A hand-built <c>status</c> object to write verbatim instead of <paramref name="status"/> —
    /// <see cref="StatusListReference"/>'s own constructor validates its <c>uri</c>/<c>idx</c>, so a
    /// test proving the seat refuses a malformed <c>status_list</c> reference (a relative uri, a
    /// negative index) or tolerates an unmodelled status mechanism needs a shape that type cannot
    /// hold. Ignored when <paramref name="status"/> is supplied.
    /// </param>
    /// <remarks>
    /// A supplied <paramref name="status"/> is written as the issuer payload's <c>status</c> object
    /// carrying a <c>status_list</c> object with its <c>idx</c> and <c>uri</c> members — the shape
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2">Token Status List, Section 6.2</see>
    /// defines for a Referenced Token in JOSE. The claim stays outside the disclosable paths, so it
    /// rides every presentation of the credential rather than depending on a disclosure.
    /// </remarks>
    public static async ValueTask<(string SerializedSdJwt, PrivateKeyMemory HolderPrivateKey, PublicKeyMemory IssuerPublicKey)> IssuePidCredentialWithClaimsAsync(
        FakeTimeProvider tp,
        string givenName,
        string familyName,
        string issuerId,
        string issuerKeyId,
        BaseMemoryPool pool,
        StatusListReference? status,
        CancellationToken cancellationToken,
        IReadOnlyDictionary<string, object>? rawStatusObject = null)
    {
        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey, PrivateKeyMemory issuerPrivateKey) =
            await IssuePidCredentialWithClaimsAndIssuerKeyAsync(
                tp, givenName, familyName, issuerId, issuerKeyId, pool, status, cancellationToken, rawStatusObject)
                .ConfigureAwait(false);
        issuerPrivateKey.Dispose();

        return (serializedSdJwt, holderPrivateKey, issuerPublicKey);
    }


    /// <summary>
    /// <see cref="IssuePidCredentialWithClaimsAsync"/>, additionally handing the caller the issuer's own
    /// private key — the Token Status List Section 11.3 same-key tests sign or compare against the
    /// credential issuer's key directly, rather than recovering it through
    /// <see cref="TestKeyMaterialProvider.CreateP256KeyMaterial"/>'s documented same-pair caching. The
    /// caller owns the returned issuer private key, alongside the holder private key, and must dispose
    /// both.
    /// </summary>
    /// <param name="tp">The clock whose current instant becomes the credential's <c>iat</c>.</param>
    /// <param name="givenName">The value of the disclosable <c>given_name</c> claim.</param>
    /// <param name="familyName">The value of the disclosable <c>family_name</c> claim.</param>
    /// <param name="issuerId">The issuer identifier the credential is issued under.</param>
    /// <param name="issuerKeyId">The key id the issuer's signature carries.</param>
    /// <param name="pool">The pool every issuance buffer is rented from.</param>
    /// <param name="status">
    /// The Status List entry the credential references, or <see langword="null"/> for a credential
    /// that references none.
    /// </param>
    /// <param name="cancellationToken">Cancels the issuance.</param>
    /// <param name="rawStatusObject">
    /// A hand-built <c>status</c> object to write verbatim instead of <paramref name="status"/>; see
    /// <see cref="IssuePidCredentialWithClaimsAsync"/> for the shapes it serves.
    /// </param>
    /// <returns>The serialized credential, the holder key its <c>cnf</c> binds to, and the issuer's public and private keys.</returns>
    public static async ValueTask<(string SerializedSdJwt, PrivateKeyMemory HolderPrivateKey, PublicKeyMemory IssuerPublicKey, PrivateKeyMemory IssuerPrivateKey)> IssuePidCredentialWithClaimsAndIssuerKeyAsync(
        FakeTimeProvider tp,
        string givenName,
        string familyName,
        string issuerId,
        string issuerKeyId,
        BaseMemoryPool pool,
        StatusListReference? status,
        CancellationToken cancellationToken,
        IReadOnlyDictionary<string, object>? rawStatusObject = null)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        PrivateKeyMemory issuerPrivateKey = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublicKey = holderKeys.PublicKey;

        Dictionary<string, object> holderJwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            holderPublicKey.Tag.Get<CryptoAlgorithm>(),
            holderPublicKey.Tag.Get<Purpose>(),
            holderPublicKey.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);

        List<KeyValuePair<string, object>> claims =
        [
            new(EudiPid.SdJwt.GivenName, givenName),
            new(EudiPid.SdJwt.FamilyName, familyName)
        ];

        if(status is not null)
        {
            claims.Add(new(StatusListJsonConstants.Status, new Dictionary<string, object>
            {
                [StatusListJsonConstants.StatusList] = new Dictionary<string, object>
                {
                    [StatusListJsonConstants.Index] = status.Value.Index,
                    [StatusListJsonConstants.Uri] = status.Value.Uri
                }
            }));
        }
        else if(rawStatusObject is not null)
        {
            claims.Add(new(StatusListJsonConstants.Status, rawStatusObject));
        }

        JwtPayload payload = JwtPayload.ForSdJwtVcIssuance(
            issuer: issuerId,
            verifiableCredentialType: EudiPid.SdJwtVct,
            issuedAt: tp.GetUtcNow(),
            holderConfirmation: holderJwk,
            claims: claims);

        HashSet<CredentialPath> disclosablePaths =
        [
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.GivenName}"),
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.FamilyName}")
        ];

        SdTokenResult result = await payload.IssueSdJwtAsync(
            c => JsonSerializerExtensions.SerializeToUtf8Bytes(c, TestSetup.DefaultSerializationOptions),
            SdJwtIssuance.IssueVerboseAsync,
            disclosablePaths, TestSalts.DefaultGenerator(),
            issuerPrivateKey, issuerKeyId, pool,
            mediaType: WellKnownMediaTypes.Jwt.VcSdJwt,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        string compactJws = Encoding.UTF8.GetString(result.SignedToken.Span);
        using SdToken<string> issuedToken = new(compactJws, result.Disclosures.ToList());
        string serializedSdJwt = SdJwtSerializer.SerializeToken(issuedToken, TestSetup.Base64UrlEncoder);

        return (serializedSdJwt, holderKeys.PrivateKey, issuerKeys.PublicKey, issuerPrivateKey);
    }


    /// <summary>
    /// The <c>status</c> object of a credential whose issuer wrote the member and put no mechanism in
    /// it — the literal <c>{}</c>. Per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">Token
    /// Status List, Section 6.1</see>: "The status (status) claim MUST specify a JSON Object that contains
    /// at least one reference to a status mechanism." Stated once here so every seat that presents this
    /// shape presents the same bytes.
    /// </summary>
    /// <returns>The hand-built <c>status</c> object to pass as this fixture's raw status object.</returns>
    public static IReadOnlyDictionary<string, object> EmptyStatusObject() =>
        new Dictionary<string, object>(StringComparer.Ordinal);


    /// <summary>
    /// The <c>status</c> object of a credential whose issuer named <c>identifier_list</c> and nothing
    /// else — a claim that meets
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">Token
    /// Status List, Section 6.1</see>'s "The status (status) claim MUST specify a JSON Object that contains
    /// at least one reference to a status mechanism." while carrying no <c>status_list</c> member the
    /// verifier can resolve. The mechanism is the Attestation Revocation List one the draft EU implementing
    /// act names: "When implementing the identifier list mechanism, the status element shall contain the
    /// identifier_list element as set out in EAA-6.2.10.1-11."
    /// </summary>
    /// <param name="identifier">The credential's entry identifier inside the issuer's identifier list.</param>
    /// <param name="listUri">The identifier list the entry lives in.</param>
    /// <returns>The hand-built <c>status</c> object to pass as this fixture's raw status object.</returns>
    /// <remarks>
    /// The value shape of an unmodelled mechanism is opaque to this library — a reader records the
    /// mechanism's name and skips its value — so the members here stand for a plausible entry rather than
    /// a modelled one. Stated once here so every seat that presents this shape presents the same bytes.
    /// </remarks>
    public static IReadOnlyDictionary<string, object> IdentifierListOnlyStatusObject(
        string identifier, string listUri) =>
        new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [StatusMechanismNames.IdentifierList] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["id"] = identifier,
                [StatusListJsonConstants.Uri] = listUri
            }
        };


    /// <summary>
    /// Writes one more top-level member into an already-issued credential's issuer-signed payload,
    /// carrying <paramref name="claimValueJson"/> verbatim. The shapes a JWT payload model cannot hold
    /// — a member whose value is not an object, and a member name that repeats — are reachable only by
    /// rewriting the wire bytes, and both are shapes a verifier has to answer for. The issuer signature
    /// no longer covers the rewritten payload, which is exactly what makes such a test meaningful: a
    /// refusal that names the payload's shape happened before any signature was checked.
    /// </summary>
    /// <param name="serializedSdJwt">The serialized SD-JWT VC whose issuer-signed payload is rewritten.</param>
    /// <param name="claimName">The top-level claim name to append.</param>
    /// <param name="claimValueJson">The claim's value, written verbatim as JSON.</param>
    /// <returns>The serialized SD-JWT VC carrying the rewritten issuer-signed payload.</returns>
    public static string AppendTopLevelClaimToIssuerPayload(
        string serializedSdJwt, string claimName, string claimValueJson)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serializedSdJwt);
        ArgumentException.ThrowIfNullOrWhiteSpace(claimName);
        ArgumentException.ThrowIfNullOrWhiteSpace(claimValueJson);

        int firstSeparator = serializedSdJwt.IndexOf(SdJwtSeparator, StringComparison.Ordinal);
        string issuerJws = firstSeparator < 0 ? serializedSdJwt : serializedSdJwt[..firstSeparator];
        string remainder = firstSeparator < 0 ? string.Empty : serializedSdJwt[firstSeparator..];

        string[] parts = issuerJws.Split('.');
        string payloadJson = Encoding.UTF8.GetString(Base64Url.DecodeFromChars(parts[1]));

        int closingBrace = payloadJson.LastIndexOf('}');
        string appended = string.Concat(
            payloadJson.AsSpan(0, closingBrace),
            $",\"{claimName}\":{claimValueJson}}}");

        parts[1] = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(appended));

        return string.Concat(string.Join('.', parts), remainder);
    }


    /// <summary>
    /// The <c>status</c> object of a credential whose <c>status_list</c> member names a negative index —
    /// a shape <see cref="StatusListReference"/> refuses to hold, so it can only be issued by writing the
    /// object verbatim. Per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2">Token
    /// Status List, Section 6.2</see>: "idx: REQUIRED. The idx (index) claim MUST specify a non-negative
    /// Integer that represents the index to check for status information in the Status List for the current
    /// Referenced Token."
    /// </summary>
    /// <param name="listUri">The Status List Token URI the malformed reference names.</param>
    /// <returns>The hand-built <c>status</c> object to pass as this fixture's raw status object.</returns>
    public static IReadOnlyDictionary<string, object> NegativeIndexStatusObject(string listUri) =>
        new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [StatusListJsonConstants.StatusList] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [StatusListJsonConstants.Index] = -1L,
                [StatusListJsonConstants.Uri] = listUri
            }
        };


    /// <summary>
    /// Binds a serialized SD-JWT VC (issued without a Key Binding JWT) to one presentation: parses it,
    /// signs a KB-JWT over its <c>sd_hash</c> input bound to <paramref name="nonce"/> and
    /// <paramref name="audience"/>, and re-serializes the token with the KB-JWT appended — the SIOPv2
    /// §12 combined-response and full-lifecycle presentation step every seat that presents an SD-JWT VC
    /// as its own <c>vp_token</c> artifact (rather than through <see cref="TestHostShell.BuildSdJwtProduceDelegate(string, PrivateKeyMemory)"/>'s
    /// DCQL-driven drop-out) shares.
    /// </summary>
    /// <param name="sdJwtWithoutKb">The issued SD-JWT VC, serialized without a Key Binding JWT.</param>
    /// <param name="holderPrivateKey">The holder's private key; must match the credential's <c>cnf</c>.</param>
    /// <param name="nonce">The verifier nonce the KB-JWT's <c>nonce</c> claim binds to.</param>
    /// <param name="audience">The verifier <c>client_id</c> the KB-JWT's <c>aud</c> claim binds to.</param>
    /// <param name="timeProvider">The clock the KB-JWT's <c>iat</c> claim is read from.</param>
    /// <param name="headerSerializer">Serializes the KB-JWT header.</param>
    /// <param name="payloadSerializer">Serializes the KB-JWT payload.</param>
    /// <param name="pool">The pool the parse and re-serialization rent transient buffers from.</param>
    /// <param name="cancellationToken">Cancels the KB-JWT signing.</param>
    /// <returns>The serialized SD-JWT VC with the KB-JWT appended.</returns>
    public static async ValueTask<string> PresentWithKeyBindingAsync(
        string sdJwtWithoutKb,
        PrivateKeyMemory holderPrivateKey,
        string nonce,
        string audience,
        TimeProvider timeProvider,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        using SdToken<string> token = SdJwtSerializer.ParseToken(
            sdJwtWithoutKb, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, pool, TestSalts.TestSaltTag);

        string hashInput = SdJwtSerializer.GetSdJwtForHashing(token, TestSetup.Base64UrlEncoder);

        string compactKbJwt = await KbJwtIssuance.IssueAsync(
            Encoding.UTF8.GetBytes(hashInput),
            holderPrivateKey,
            nonce,
            audience,
            timeProvider.GetUtcNow(),
            TestSetup.Base64UrlEncoder,
            headerSerializer,
            payloadSerializer,
            pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        using SdToken<string> tokenWithKb = token.WithKeyBinding(compactKbJwt, pool);

        return SdJwtSerializer.SerializeToken(tokenWithKb, TestSetup.Base64UrlEncoder);
    }
}
