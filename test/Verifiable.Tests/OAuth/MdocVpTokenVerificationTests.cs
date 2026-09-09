using System.Buffers;
using System.Buffers.Text;
using Verifiable.Cbor;
using Verifiable.Cbor.Mdoc;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.MdocTestFixtures;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Firewalled tests for <see cref="MdocVpTokenVerification"/> — the OID4VP
/// server-side mdoc VP-token verifier. A toy wallet produces the
/// <c>vp_token</c> and the transmitted <c>mdoc_generated_nonce</c>; the verifier
/// reconstructs everything strictly from those wire values (no shared in-memory
/// wallet objects, salts, or device key) and runs the full issuer-auth +
/// digest-binding + device-signature verification through the OAuth-layer
/// composition, producing a <see cref="VpTokenParsed"/>.
/// </summary>
[TestClass]
internal sealed class MdocVpTokenVerificationTests
{
    private static string PidNamespace { get; } = EudiPid.Mdoc.Namespace;
    private const string PidCredentialQueryId = "pid";
    private const string VerifierClientId = "https://verifier.example/oid4vp/client";
    private const string VerifierResponseUri = "https://verifier.example/oid4vp/response";
    private const string AuthorizationRequestNonce = "auth-req-nonce-vptoken-01";

    /// <summary>
    /// The trust evidence a relying party's own IssuerAuth x5chain resolution stands for here: the chain
    /// carries the AuthorityKeyIdentifier <see cref="DcqlFixtures.AkiExampleValue"/> spells, the
    /// <c>aki</c> evidence
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.1">
    /// Section 6.1.1.1</see> compares a query value against.
    /// </summary>
    private static TrustedAuthorityEvidence ExampleAuthorityKeyIdentifierEvidence { get; } = new()
    {
        AuthorityKeyIdentifiers = new HashSet<AuthorityKeyIdentifier>
        {
            new(Base64Url.DecodeFromChars(DcqlFixtures.AkiExampleValue))
        }
    };

    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task VerifiesEveryLayerAndExtractsClaimsFromWire()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            (string vpTokenValue, string transmittedNonce) =
                await ProduceVpTokenAsync(issuerKeys, deviceKeys).ConfigureAwait(false);

            using IMemoryOwner<byte> nonceOwner = Oid4VpMdocPresentation.DecodeMdocGeneratedNonceForTransmissionRoundTrip(
                transmittedNonce, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

            using MdocVpVerificationResult verification = await VerifyAsync(
                vpTokenValue, MdocVpFixture.TrustAnchorFor(issuerKeys.PublicKey), nonceOwner.Memory).ConfigureAwait(false);
            VpTokenParsed parsed = verification.Parsed;

            Assert.IsTrue(parsed.CredentialSignatureValid,
                "Issuer-auth signature and MSO digest binding must both hold over the wire-reconstructed document.");
            Assert.IsTrue(parsed.SessionTranscriptValid,
                "Device signature must verify against the verifier-reconstructed SessionTranscript.");

            //mdoc carries no KB-JWT / sd_hash; those N/A axes are reported as not-a-failure.
            Assert.IsTrue(parsed.KbJwtSignatureValid, "KB-JWT axis is N/A for mdoc and must not register as a failure.");
            Assert.IsTrue(parsed.SdHashValid, "sd_hash axis is N/A for mdoc and must not register as a failure.");

            IReadOnlyDictionary<CredentialPath, string> claims = parsed.Credential.Extracted;
            CredentialPath familyNamePath = CredentialPath.Root.Append(PidNamespace).Append(EudiPid.Mdoc.FamilyName);
            CredentialPath givenNamePath = CredentialPath.Root.Append(PidNamespace).Append(EudiPid.Mdoc.GivenName);
            Assert.AreEqual("Mustermann", claims[familyNamePath],
                "The disclosed family_name claim must decode from its CBOR element value.");
            Assert.AreEqual("Erika", claims[givenNamePath],
                "The disclosed given_name claim must decode from its CBOR element value.");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public async Task UntrustedIssuerKeyFailsCredentialSignature()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> wrongIssuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            (string vpTokenValue, string transmittedNonce) =
                await ProduceVpTokenAsync(issuerKeys, deviceKeys).ConfigureAwait(false);

            using IMemoryOwner<byte> nonceOwner = Oid4VpMdocPresentation.DecodeMdocGeneratedNonceForTransmissionRoundTrip(
                transmittedNonce, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

            //The trust framework resolves a key that did not sign the MSO — the issuer-auth
            //COSE_Sign1 verification fails, so CredentialSignatureValid is false.
            using MdocVpVerificationResult verification = await VerifyAsync(
                vpTokenValue, MdocVpFixture.TrustAnchorFor(wrongIssuerKeys.PublicKey), nonceOwner.Memory).ConfigureAwait(false);
            VpTokenParsed parsed = verification.Parsed;

            Assert.IsFalse(parsed.CredentialSignatureValid,
                "An issuer key that did not sign the MSO must fail the credential signature.");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
            DisposeKeyMaterial(wrongIssuerKeys);
        }
    }


    [TestMethod]
    public async Task WrongMdocGeneratedNonceFailsSessionTranscriptOnly()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            (string vpTokenValue, _) = await ProduceVpTokenAsync(issuerKeys, deviceKeys).ConfigureAwait(false);

            //A nonce that differs from the one the wallet signed under yields a different
            //reconstructed SessionTranscript, so the device signature fails — but the issuer-auth
            //signature and digest binding are independent and still hold.
            using IMemoryOwner<byte> wrongNonce =
                Oid4VpMdocSessionTranscriptEncoder.GenerateMdocGeneratedNonce(System.Security.Cryptography.RandomNumberGenerator.Fill, BaseMemoryPool.Shared);
            ReadOnlyMemory<byte> wrongNonceMemory =
                wrongNonce.Memory[..Oid4VpMdocSessionTranscriptEncoder.MinimumMdocGeneratedNonceLength];

            using MdocVpVerificationResult verification = await VerifyAsync(
                vpTokenValue, MdocVpFixture.TrustAnchorFor(issuerKeys.PublicKey), wrongNonceMemory).ConfigureAwait(false);
            VpTokenParsed parsed = verification.Parsed;

            Assert.IsTrue(parsed.CredentialSignatureValid,
                "Issuer-auth and digest binding are independent of the SessionTranscript and must still hold.");
            Assert.IsFalse(parsed.SessionTranscriptValid,
                "A mismatched mdoc_generated_nonce must fail the device signature over the transcript.");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    /// <summary>
    /// Wallet side: issue, device-sign over a fresh SessionTranscript, and assemble
    /// the base64url vp_token value plus the transmitted mdoc_generated_nonce.
    /// </summary>
    private async ValueTask<(string VpTokenValue, string TransmittedNonce)> ProduceVpTokenAsync(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys)
    {
        using MdocDocument issued = await MdocVpFixture.IssueAsync(
            issuerKeys, deviceKeys, status: null, TestContext.CancellationToken).ConfigureAwait(false);

        using IMemoryOwner<byte> mdocGeneratedNonce =
            Oid4VpMdocSessionTranscriptEncoder.GenerateMdocGeneratedNonce(System.Security.Cryptography.RandomNumberGenerator.Fill, BaseMemoryPool.Shared);
        ReadOnlyMemory<byte> nonceMemory =
            mdocGeneratedNonce.Memory[..Oid4VpMdocSessionTranscriptEncoder.MinimumMdocGeneratedNonceLength];
        ReadOnlyMemory<byte> sessionTranscript = Oid4VpMdocSessionTranscriptEncoder.Encode(
            VerifierClientId, VerifierResponseUri, AuthorizationRequestNonce, nonceMemory.Span, BaseMemoryPool.Shared);

        using MdocPresentationDocument intermediate = new(
            docType: issued.DocType,
            issuerSigned: MdocIssuerSignedView.FromOwned(issued.IssuerSigned));
        using MdocPresentationDocument presented = await intermediate.DeviceSignAsync(
            MdocDeviceNameSpaces.Empty,
            sessionTranscript,
            deviceKeys.PrivateKey,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        using MdocDeviceResponse deviceResponse = new(
            version: MdocWellKnownKeys.Version10,
            documents: [presented],
            status: MdocWellKnownKeys.StatusOk);

        string vpTokenValue = Oid4VpMdocPresentation.AssembleVpTokenValue(deviceResponse, TestSetup.Base64UrlEncoder);
        string transmittedNonce = Oid4VpMdocPresentation.EncodeMdocGeneratedNonceForTransmission(
            nonceMemory.Span, TestSetup.Base64UrlEncoder);

        return (vpTokenValue, transmittedNonce);
    }


    /// <summary>
    /// Verifier side: run <see cref="MdocVpTokenVerification.VerifyAsync"/> with the
    /// CBOR/COSE seams wired to the concrete serialization implementations. The IACA trust resolution
    /// travels back with the parsed result, since it owns the key
    /// <see cref="VpTokenParsed.CredentialIssuerKey"/> borrows; the caller releases it.
    /// </summary>
    private ValueTask<MdocVpVerificationResult> VerifyAsync(
        string vpTokenValue,
        ResolveMdocIssuerKeyDelegate resolveIssuerKey,
        ReadOnlyMemory<byte> mdocGeneratedNonce)
    {
        return VerifyAsync(
            vpTokenValue,
            resolveIssuerKey,
            //No trust-evidence extractor: this overload's callers do not exercise trusted_authorities.
            extractTrustedAuthorityEvidence: null,
            mdocGeneratedNonce);
    }


    /// <summary>
    /// <see cref="VerifyAsync(string, ResolveMdocIssuerKeyDelegate, ReadOnlyMemory{byte})"/> with the
    /// OID4VP 1.0 Section 6.1.1 trust-evidence extractor wired — the seam a relying party composes its
    /// own IssuerAuth x5chain resolution behind.
    /// </summary>
    /// <param name="vpTokenValue">The base64url DeviceResponse the wallet produced.</param>
    /// <param name="resolveIssuerKey">The issuer-key resolution the verifier's trust framework performs.</param>
    /// <param name="extractTrustedAuthorityEvidence">
    /// The trust-evidence extractor, or <see langword="null"/> when the verifier wires none.
    /// </param>
    /// <param name="mdocGeneratedNonce">The transmitted <c>mdoc_generated_nonce</c>.</param>
    /// <returns>The parsed presentation and the IACA trust resolution the caller disposes.</returns>
    private ValueTask<MdocVpVerificationResult> VerifyAsync(
        string vpTokenValue,
        ResolveMdocIssuerKeyDelegate resolveIssuerKey,
        ExtractMdocTrustedAuthorityEvidenceDelegate? extractTrustedAuthorityEvidence,
        ReadOnlyMemory<byte> mdocGeneratedNonce)
    {
        return MdocVpTokenVerification.VerifyAsync(
            vpTokenValue,
            new CredentialQueryId(PidCredentialQueryId),
            resolveIssuerKey,
            extractTrustedAuthorityEvidence,
            VerifierClientId,
            VerifierResponseUri,
            AuthorizationRequestNonce,
            mdocGeneratedNonce,
            MdocCborDeviceResponseReader.Read,
            Oid4VpMdocSessionTranscriptEncoder.Encode,
            MdocVpFixture.DecodeElementValue,
            CoseSerialization.ParseCoseSign1,
            CoseSerialization.ParseCoseSign1AllowingNilPayload,
            MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes,
            CoseSerialization.BuildSigStructure,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1">OpenID
    /// for Verifiable Presentations 1.0, Section 8.1</see>: "vp_token: REQUIRED. This is a JSON-encoded
    /// object containing entries where the key is the id value used for a Credential Query in the DCQL
    /// query and the value is an array of one or more Presentations that match the respective Credential
    /// Query." The verified presentation names the very identifier the wire keyed it by.
    /// </summary>
    [TestMethod]
    public async Task ParsedPresentationIsKeyedByTheCredentialQueryItAnswered()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            (string vpTokenValue, string transmittedNonce) =
                await ProduceVpTokenAsync(issuerKeys, deviceKeys).ConfigureAwait(false);

            using IMemoryOwner<byte> nonceOwner = Oid4VpMdocPresentation.DecodeMdocGeneratedNonceForTransmissionRoundTrip(
                transmittedNonce, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

            using MdocVpVerificationResult verification = await VerifyAsync(
                vpTokenValue, MdocVpFixture.TrustAnchorFor(issuerKeys.PublicKey), nonceOwner.Memory).ConfigureAwait(false);

            Assert.AreEqual(new CredentialQueryId(PidCredentialQueryId), verification.Parsed.CredentialQueryId,
                "Section 8.1: the presentation is keyed by the Credential Query id it answered.");
            Assert.AreEqual(PidCredentialQueryId, verification.Parsed.CredentialQueryId.Value,
                "The identifier's value is the same string the DCQL credential query carries.");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-7.2">OpenID
    /// for Verifiable Presentations 1.0, Section 7.2</see>: "A claims path pointer into an mdoc contains
    /// two elements of type string. The first element refers to a namespace and the second element refers
    /// to a data element identifier." Both the string projection and the engine-facing map are therefore
    /// keyed by the namespace and the element identifier together, since the same identifier may occur in
    /// two namespaces. An mdoc has no claim it cannot withhold — every presented item is a data element
    /// the wallet chose to send — so nothing is reported as unconditionally disclosed.
    /// </summary>
    [TestMethod]
    public async Task ParsedPresentationKeysEveryElementByItsNamespaceAndElementIdentifier()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            (string vpTokenValue, string transmittedNonce) =
                await ProduceVpTokenAsync(issuerKeys, deviceKeys).ConfigureAwait(false);

            using IMemoryOwner<byte> nonceOwner = Oid4VpMdocPresentation.DecodeMdocGeneratedNonceForTransmissionRoundTrip(
                transmittedNonce, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

            using MdocVpVerificationResult verification = await VerifyAsync(
                vpTokenValue, MdocVpFixture.TrustAnchorFor(issuerKeys.PublicKey), nonceOwner.Memory).ConfigureAwait(false);
            VpTokenParsed parsed = verification.Parsed;

            CredentialPath familyNamePath = CredentialPath.Root.Append(PidNamespace).Append(EudiPid.Mdoc.FamilyName);
            CredentialPath givenNamePath = CredentialPath.Root.Append(PidNamespace).Append(EudiPid.Mdoc.GivenName);

            Assert.AreEqual("Mustermann", parsed.Credential.Disclosed[familyNamePath],
                "Section 7.2: the family_name element is addressed by its namespace and element identifier.");
            Assert.AreEqual("Erika", parsed.Credential.Disclosed[givenNamePath],
                "Section 7.2: the given_name element is addressed by its namespace and element identifier.");
            foreach(CredentialPath disclosedPath in parsed.Credential.Disclosed.Keys)
            {
                Assert.IsTrue(parsed.Credential.Extracted.ContainsKey(disclosedPath),
                    "Section 7.2: both views of the presentation are keyed by the same two-component positions.");
            }

            Assert.IsEmpty(parsed.Credential.UnconditionallyDisclosed,
                "An mdoc presentation carries only the data elements the wallet chose to send, so none is unconditional.");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.3">
    /// OpenID for Verifiable Presentations 1.0, Appendix B.2.3</see>: "doctype_value: REQUIRED. String
    /// that specifies an allowed value for the doctype of the requested Verifiable Credential. It MUST be
    /// a valid doctype identifier as defined in [ISO.18013-5]." The document's own <c>DocType</c> is the
    /// evidence that constraint is answered against, so it is what the verifier surfaces as the
    /// credential's declared type. An mdoc carries no <c>iss</c> claim — the issuer identity travels in
    /// the IssuerAuth certificate chain — so no issuer identifier is surfaced.
    /// </summary>
    [TestMethod]
    public async Task ParsedPresentationCarriesTheDocumentTypeAndNoIssuerIdentifier()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            (string vpTokenValue, string transmittedNonce) =
                await ProduceVpTokenAsync(issuerKeys, deviceKeys).ConfigureAwait(false);

            using IMemoryOwner<byte> nonceOwner = Oid4VpMdocPresentation.DecodeMdocGeneratedNonceForTransmissionRoundTrip(
                transmittedNonce, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

            using MdocVpVerificationResult verification = await VerifyAsync(
                vpTokenValue, MdocVpFixture.TrustAnchorFor(issuerKeys.PublicKey), nonceOwner.Memory).ConfigureAwait(false);
            VpTokenParsed parsed = verification.Parsed;

            Assert.AreEqual(EudiPid.AttestationType, parsed.Credential.CredentialType,
                "Appendix B.2.3: the document's own doctype is the type evidence a doctype_value constraint is answered against.");
            Assert.IsNull(parsed.Credential.Issuer,
                "An mdoc carries no iss claim, so the verifier surfaces no issuer identifier for it.");
            Assert.IsEmpty(parsed.Credential.AdditionalTypes,
                "An mdoc declares one doctype and no additional types.");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">
    /// Token Status List, Section 8.3</see> step 1: "Check for the existence of a status claim, check for
    /// the existence of a status_list claim within the status claim and validate that the content of
    /// status_list adheres to the rules defined in Section 6.2 for JOSE-based Referenced Tokens and
    /// Section 6.3 for COSE-based Referenced Tokens." Existence is what is checked first, so an mdoc
    /// whose Mobile Security Object carries no <c>status</c> member is reported as carrying none rather
    /// than as carrying one that cannot be read.
    /// </summary>
    [TestMethod]
    public async Task ParsedPresentationCarriesNoStatusClaimWhenTheMobileSecurityObjectStatesNone()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            (string vpTokenValue, string transmittedNonce) =
                await ProduceVpTokenAsync(issuerKeys, deviceKeys).ConfigureAwait(false);

            using IMemoryOwner<byte> nonceOwner = Oid4VpMdocPresentation.DecodeMdocGeneratedNonceForTransmissionRoundTrip(
                transmittedNonce, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

            using MdocVpVerificationResult verification = await VerifyAsync(
                vpTokenValue, MdocVpFixture.TrustAnchorFor(issuerKeys.PublicKey), nonceOwner.Memory).ConfigureAwait(false);

            Assert.IsNull(verification.Parsed.Credential.Status,
                "Section 8.3 step 1: a credential carrying no status claim is reported as having none.");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">
    /// Token Status List, Section 11.3</see>: "If the Issuer of the Referenced Token is the same entity
    /// as the Status Issuer, then the same key that is embedded into the Referenced Token may be used for
    /// the Status List Token." Reaching that recommendation needs the key the Referenced Token's own
    /// issuer signature verified under, so the verified presentation carries it — the very key the trust
    /// framework's <see cref="ResolveMdocIssuerKeyDelegate"/> answered with, byte for byte.
    /// </summary>
    [TestMethod]
    public async Task ParsedPresentationCarriesTheIssuerKeyTheCredentialSignatureVerifiedUnder()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            (string vpTokenValue, string transmittedNonce) =
                await ProduceVpTokenAsync(issuerKeys, deviceKeys).ConfigureAwait(false);

            using IMemoryOwner<byte> nonceOwner = Oid4VpMdocPresentation.DecodeMdocGeneratedNonceForTransmissionRoundTrip(
                transmittedNonce, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

            using MdocVpVerificationResult verification = await VerifyAsync(
                vpTokenValue, MdocVpFixture.TrustAnchorFor(issuerKeys.PublicKey), nonceOwner.Memory).ConfigureAwait(false);
            VpTokenParsed parsed = verification.Parsed;

            Assert.IsTrue(parsed.CredentialSignatureValid,
                "The issuer-auth signature must verify before its key is published.");
            Assert.IsNotNull(parsed.CredentialIssuerKey,
                "Section 11.3: the key the Referenced Token verified under must be reachable from the presentation.");
            Assert.IsTrue(
                parsed.CredentialIssuerKey.AsReadOnlySpan().SequenceEqual(issuerKeys.PublicKey.AsReadOnlySpan()),
                "Section 11.3: the published key must be the key the trust framework resolved, byte for byte.");
            Assert.IsNotNull(verification.IssuerTrust,
                "The resolution that owns the borrowed key travels with the result so the caller can release it.");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">
    /// Token Status List, Section 11.3</see> makes the same-key recommendation conditional on the
    /// Referenced Token's own issuer key being known. A trust framework whose chain validation fails
    /// resolves no key at all, so the issuer-auth signature stays unverified and nothing is published as
    /// that credential's issuer key — a composition over it fails closed rather than borrowing a key that
    /// verified nothing.
    /// </summary>
    [TestMethod]
    public async Task ParsedPresentationCarriesNoIssuerKeyWhenTheTrustFrameworkResolvesNone()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            (string vpTokenValue, string transmittedNonce) =
                await ProduceVpTokenAsync(issuerKeys, deviceKeys).ConfigureAwait(false);

            using IMemoryOwner<byte> nonceOwner = Oid4VpMdocPresentation.DecodeMdocGeneratedNonceForTransmissionRoundTrip(
                transmittedNonce, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

            using MdocVpVerificationResult verification = await VerifyAsync(
                vpTokenValue, UntrustedChainResolver, nonceOwner.Memory).ConfigureAwait(false);
            VpTokenParsed parsed = verification.Parsed;

            Assert.IsFalse(parsed.CredentialSignatureValid,
                "A trust framework that resolves no key leaves the issuer-auth signature unverified.");
            Assert.IsNull(parsed.CredentialIssuerKey,
                "Section 11.3: no key verified the credential, so none is published as the Referenced Token's issuer key.");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>: "A Trusted Authorities Query is an
    /// object representing information that helps to identify an authority or the trust framework that
    /// certifies Issuers. A Credential is identified as a match to a Trusted Authorities Query if it
    /// matches with one of the provided values in one of the provided types." The evidence the relying
    /// party's own resolution produces from the IssuerAuth is what that matching is answered against, so
    /// the verified presentation carries it.
    /// </summary>
    [TestMethod]
    public async Task ParsedPresentationCarriesTheResolvedTrustEvidenceWhenTheSeamIsWired()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            (string vpTokenValue, string transmittedNonce) =
                await ProduceVpTokenAsync(issuerKeys, deviceKeys).ConfigureAwait(false);

            using IMemoryOwner<byte> nonceOwner = Oid4VpMdocPresentation.DecodeMdocGeneratedNonceForTransmissionRoundTrip(
                transmittedNonce, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

            string? doctypeSeenByTheExtractor = null;
            using MdocVpVerificationResult verification = await VerifyAsync(
                vpTokenValue,
                MdocVpFixture.TrustAnchorFor(issuerKeys.PublicKey),
                (issuerAuth, cancellationToken) =>
                {
                    doctypeSeenByTheExtractor = issuerAuth.Mso.DocType;

                    return ValueTask.FromResult<TrustedAuthorityEvidence?>(ExampleAuthorityKeyIdentifierEvidence);
                },
                nonceOwner.Memory).ConfigureAwait(false);

            Assert.AreEqual(EudiPid.AttestationType, doctypeSeenByTheExtractor,
                "Section 6.1.1: the evidence is resolved from the IssuerAuth of the very document presented.");
            Assert.AreSame(ExampleAuthorityKeyIdentifierEvidence, verification.Parsed.Credential.TrustedAuthorityEvidence,
                "Section 6.1.1: the resolved evidence is what a trusted_authorities constraint is matched against.");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.4.2">
    /// OpenID for Verifiable Presentations 1.0, Section 6.4.2</see>: "Credentials not matching the
    /// respective constraints expressed within credentials MUST NOT be returned, i.e., they are treated
    /// as if they would not exist in the Wallet." A verifier that wires no trust-evidence extractor
    /// surfaces no evidence at all, which is what makes a <c>trusted_authorities</c> constraint fail
    /// closed rather than be skipped.
    /// </summary>
    [TestMethod]
    public async Task ParsedPresentationCarriesNoTrustEvidenceWhenNoExtractorIsWired()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            (string vpTokenValue, string transmittedNonce) =
                await ProduceVpTokenAsync(issuerKeys, deviceKeys).ConfigureAwait(false);

            using IMemoryOwner<byte> nonceOwner = Oid4VpMdocPresentation.DecodeMdocGeneratedNonceForTransmissionRoundTrip(
                transmittedNonce, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

            using MdocVpVerificationResult verification = await VerifyAsync(
                vpTokenValue, MdocVpFixture.TrustAnchorFor(issuerKeys.PublicKey), nonceOwner.Memory).ConfigureAwait(false);

            Assert.IsNull(verification.Parsed.Credential.TrustedAuthorityEvidence,
                "Section 6.4.2: no evidence is surfaced when none is resolved, so the constraint has nothing to match.");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    /// <summary>
    /// A trust framework whose chain validation refuses the IssuerAuth: it hands back a failed resolution
    /// carrying no verification key at all, the mdoc counterpart of an issuer identifier the verifier
    /// knows no key for.
    /// </summary>
    /// <param name="issuerAuth">The IssuerAuth whose chain the framework refuses.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The failed resolution.</returns>
    private static ValueTask<MdocIacaTrustResolution> UntrustedChainResolver(
        MdocIssuerAuth issuerAuth,
        CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(MdocIacaTrustResolution.Failed(
            MdocIacaTrustFailureReason.ChainValidationFailed,
            "The verifier's trust framework accepts no chain for this IssuerAuth."));
    }
}
