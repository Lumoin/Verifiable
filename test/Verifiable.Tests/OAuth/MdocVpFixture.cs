using Lumoin.Veritas.Cbor;
using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cbor;
using Verifiable.Cbor.Mdoc;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.Model.SelectiveDisclosure.Strategy;
using Verifiable.Core.StatusLists;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.Microsoft;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;
using static Verifiable.Tests.TestInfrastructure.MdocTestFixtures;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The ISO mdoc (<c>mso_mdoc</c>) credential format expressed as a
/// <see cref="FormatFixture"/> for the scheme × format matrix: it builds a host
/// wired with the <see cref="MdocVpVerificationSeams"/> the executor dispatches
/// <c>mso_mdoc</c> through, issues a PID mdoc (issuer key resolved out of band via
/// the seams' trust anchor, device key committed into the MSO), and wires the
/// presentation drop-out that runs the Core DCQL engine + device-signs over the
/// OID4VP SessionTranscript. The single source of the mdoc flow setup shared by
/// the matrix and <see cref="Oid4VpMdocFlowIntegrationTests"/>.
/// </summary>
internal static class MdocVpFixture
{
    private const string PidCredentialQueryId = "pid";
    private static string PidDocType { get; } = EudiPid.AttestationType;
    private static string PidNamespace { get; } = EudiPid.Mdoc.Namespace;

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    /// <summary>The mdoc matrix-format row: name plus the per-run <see cref="FormatRun"/> factory.</summary>
    public static FormatFixture Format => new("mso_mdoc", StartAsync);


    /// <summary>
    /// Starts an mdoc <see cref="FormatRun"/> whose issued PID references no Token Status List
    /// entry — the matrix's plain row. Callers that need a status-bearing mdoc call
    /// <see cref="IssueAsync"/> directly with a <see cref="StatusListReference"/> and compose their
    /// own <see cref="FormatRun"/> the way this method does (see
    /// <c>MdocCredentialStatusGateTests.StartMdocRunAsync</c> and
    /// <c>MdocVpTokenVerificationStatusTests</c> for the two call sites that need per-test
    /// resolver/policy hosts <see cref="Format"/>'s fixed wiring cannot provide).
    /// </summary>
    /// <param name="tp">The clock the host and the MSO's <c>validityInfo</c> are built against.</param>
    /// <param name="cancellationToken">Cancels issuance.</param>
    private static async ValueTask<FormatRun> StartAsync(FakeTimeProvider tp, CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        TestHostShell app = new(tp, mdocSeams: BuildSeams(issuerKeys.PublicKey));

        //The wallet holds the issued mdoc; the device key matches the MSO's
        //committed device key. The credential and key never leave the wallet —
        //only the wire JWE crosses to the verifier.
        MdocDocument issued = await IssueAsync(issuerKeys, deviceKeys, status: null, cancellationToken).ConfigureAwait(false);

        return new FormatRun
        {
            App = app,
            Query = BuildMdocPreparedQuery(),
            Produce = BuildMdocProduceDelegate(issued, deviceKeys.PrivateKey),
            AssertClaims = AssertClaims,
            //ResolveIssuerKey clones issuerKeys.PublicKey per call, so it must outlive
            //verification; the device key drives the presentation drop-out. The host
            //owns neither — both halves of both pairs are disposed here.
            Owned =
            [
                issued,
                issuerKeys.PublicKey, issuerKeys.PrivateKey,
                deviceKeys.PublicKey, deviceKeys.PrivateKey
            ]
        };
    }


    /// <summary>
    /// The mdoc verification seams the executor dispatches an <c>mso_mdoc</c> presentation
    /// through: the project's own CBOR/COSE implementations, plus <paramref name="resolveIssuerKey"/>
    /// standing in for the verifier's trust framework and <paramref name="extractTrustedAuthorityEvidence"/>
    /// for DCQL <c>trusted_authorities</c> enforcement when a caller wires one. The single seam
    /// composition every host in this fixture and its callers builds a host from.
    /// </summary>
    /// <param name="resolveIssuerKey">The issuer-key resolution the verifier's trust framework performs.</param>
    /// <param name="extractTrustedAuthorityEvidence">
    /// The trust-evidence extractor for DCQL <c>trusted_authorities</c>, or <see langword="null"/> when
    /// the caller does not exercise it.
    /// </param>
    /// <returns>The seams a host is built with.</returns>
    public static MdocVpVerificationSeams BuildSeams(
        ResolveMdocIssuerKeyDelegate resolveIssuerKey,
        ExtractMdocTrustedAuthorityEvidenceDelegate? extractTrustedAuthorityEvidence = null) =>
        new()
        {
            ResolveIssuerKey = resolveIssuerKey,
            ParseDeviceResponse = MdocCborDeviceResponseReader.Read,
            EncodeSessionTranscript = Oid4VpMdocSessionTranscriptEncoder.Encode,
            DecodeElementValue = DecodeElementValue,
            ParseCoseSign1 = CoseSerialization.ParseCoseSign1,
            ParseCoseSign1AllowingNilPayload = CoseSerialization.ParseCoseSign1AllowingNilPayload,
            EncodeDeviceAuthenticationBytes = MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes,
            BuildSigStructure = CoseSerialization.BuildSigStructure,
            ExtractTrustedAuthorityEvidence = extractTrustedAuthorityEvidence
        };


    /// <summary>
    /// <see cref="BuildSeams(ResolveMdocIssuerKeyDelegate, ExtractMdocTrustedAuthorityEvidenceDelegate?)"/>
    /// over the common case: the verifier's trust framework knows the issuer key directly, resolved
    /// through <see cref="TrustAnchorFor"/>.
    /// </summary>
    /// <param name="trustedIssuerKey">The issuer public key the verifier resolves out of band.</param>
    /// <returns>The seams a host is built with.</returns>
    public static MdocVpVerificationSeams BuildSeams(PublicKeyMemory trustedIssuerKey) =>
        BuildSeams(TrustAnchorFor(trustedIssuerKey));


    private static void AssertClaims(PresentationVerifiedState verified)
    {
        Assert.IsTrue(verified.Credentials.TryGetValue(new CredentialQueryId(PidCredentialQueryId),
            out VpCredentialClaims? credential),
            "Verified credentials must be keyed by the DCQL credential query id.");
        IReadOnlyDictionary<CredentialPath, string> claims = credential.Extracted;
        CredentialPath familyNamePath = CredentialPath.Root.Append(EudiPid.Mdoc.Namespace).Append(EudiPid.Mdoc.FamilyName);
        CredentialPath givenNamePath = CredentialPath.Root.Append(EudiPid.Mdoc.Namespace).Append(EudiPid.Mdoc.GivenName);
        CredentialPath birthDatePath = CredentialPath.Root.Append(EudiPid.Mdoc.Namespace).Append(EudiPid.Mdoc.BirthDate);
        Assert.AreEqual("Mustermann", claims[familyNamePath],
            "The disclosed family_name must round-trip through the full flow.");
        Assert.AreEqual("Erika", claims[givenNamePath],
            "The disclosed given_name must round-trip through the full flow.");
        Assert.IsFalse(claims.ContainsKey(birthDatePath),
            "The issued mdoc carries birth_date, but the query asks only for family_name + " +
            "given_name; element-level trimming (MdocDocument.Derive) must withhold birth_date " +
            "from the DeviceResponse so it never surfaces in the verified set.");
    }


    public static PreparedDcqlQuery BuildMdocPreparedQuery()
    {
        var dcqlQuery = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = PidCredentialQueryId,
                    Format = MdocDcqlAdapter.FormatIdentifier,
                    Meta = new CredentialQueryMeta { DoctypeValue = PidDocType },
                    Claims =
                    [
                        new ClaimsQuery { Path = DcqlClaimPattern.ForMdoc(PidNamespace, EudiPid.Mdoc.FamilyName) },
                        new ClaimsQuery { Path = DcqlClaimPattern.ForMdoc(PidNamespace, EudiPid.Mdoc.GivenName) }
                    ]
                }
            ]
        };

        return DcqlPreparer.Prepare(dcqlQuery);
    }


    /// <summary>
    /// <see cref="BuildMdocPreparedQuery"/> with a DCQL <c>trusted_authorities</c> constraint
    /// of type <c>aki</c> (OID4VP 1.0 §6.1.1.1): the credential matches only when its
    /// IssuerAuth leaf certificate's AuthorityKeyIdentifier is one of
    /// <paramref name="trustedAuthorityKeyIdentifiers"/> (base64url). Drives the verifier's
    /// fail-closed trusted_authorities enforcement for the mdoc format.
    /// </summary>
    public static PreparedDcqlQuery BuildMdocTrustedAuthoritiesPreparedQuery(
        params string[] trustedAuthorityKeyIdentifiers)
    {
        var dcqlQuery = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = PidCredentialQueryId,
                    Format = MdocDcqlAdapter.FormatIdentifier,
                    Meta = new CredentialQueryMeta { DoctypeValue = PidDocType },
                    TrustedAuthorities =
                    [
                        new TrustedAuthoritiesQuery
                        {
                            Type = DcqlTrustedAuthorityTypes.Aki,
                            Values = trustedAuthorityKeyIdentifiers
                        }
                    ],
                    Claims =
                    [
                        new ClaimsQuery { Path = DcqlClaimPattern.ForMdoc(PidNamespace, EudiPid.Mdoc.FamilyName) },
                        new ClaimsQuery { Path = DcqlClaimPattern.ForMdoc(PidNamespace, EudiPid.Mdoc.GivenName) }
                    ]
                }
            ]
        };

        return DcqlPreparer.Prepare(dcqlQuery);
    }


    /// <summary>
    /// The mdoc trust-evidence extractor wired behind
    /// <see cref="MdocVpVerificationSeams.ExtractTrustedAuthorityEvidence"/> — the library
    /// composition of <see cref="MdocCborTrustedAuthorityEvidence"/> (x5chain) and a resolver
    /// reading every chain certificate's AuthorityKeyIdentifier via
    /// <see cref="MicrosoftX509Functions.GetAuthorityKeyIdentifier"/>, the exact analogue of how the
    /// IACA resolver is composed from <c>MdocCborIacaTrustResolver.Create</c> +
    /// <c>MicrosoftX509Functions.ValidateChainAsync</c>.
    /// </summary>
    public static ExtractMdocTrustedAuthorityEvidenceDelegate ExtractTrustedAuthorityEvidence { get; } =
        MdocCborTrustedAuthorityEvidence.Create(ResolveAuthorityKeyIdentifierEvidence, Pool);


    /// <summary>
    /// A minimal <see cref="ResolveTrustedAuthorityEvidenceDelegate"/>: reads every chain
    /// certificate's AuthorityKeyIdentifier via the shipped
    /// <see cref="X509TrustedAuthorityEvidence.CollectAuthorityKeyIdentifiers"/> composition — the
    /// <c>aki</c> arm only, since the fixture's chains carry no ETSI Trusted List or OpenID
    /// Federation evidence.
    /// </summary>
    private static ValueTask<TrustedAuthorityEvidence?> ResolveAuthorityKeyIdentifierEvidence(
        IReadOnlyList<PkiCertificateMemory> chain, string? issuerIdentifier, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        IReadOnlySet<AuthorityKeyIdentifier> authorityKeyIdentifiers =
            X509TrustedAuthorityEvidence.CollectAuthorityKeyIdentifiers(chain, MicrosoftX509Functions.GetAuthorityKeyIdentifier);

        return ValueTask.FromResult<TrustedAuthorityEvidence?>(
            new TrustedAuthorityEvidence { AuthorityKeyIdentifiers = authorityKeyIdentifiers });
    }


    /// <summary>
    /// The presentation drop-out: runs the Core DCQL engine
    /// (<see cref="DcqlEvaluator"/> + <see cref="MdocDcqlAdapter"/> +
    /// <see cref="DcqlPathResolver"/>) to trim the mdoc to the requested elements,
    /// device-signs over the OID4VP SessionTranscript, and returns the base64url
    /// DeviceResponse with the <c>mdoc_generated_nonce</c> as the apu. The CBOR/COSE
    /// composition lives here in the application layer; the OAuth library only
    /// invokes the delegate.
    /// </summary>
    public static ProduceVpTokenPresentationsDelegate BuildMdocProduceDelegate(
        MdocDocument storedMdoc, PrivateKeyMemory deviceKey)
    {
        return async (context, cancellationToken) =>
        {
            Dictionary<string, string> presentations = new(StringComparer.Ordinal);
            string? responseEncryptionApu = null;

            foreach(CredentialQuery query in context.Request.DcqlQuery!.Credentials!)
            {
                string queryId = query.Id
                    ?? throw new InvalidOperationException("DCQL credential query is missing the 'id' field.");

                //Engine: the one canonical path every flow runs — DcqlEvaluator.Evaluate
                //-> DcqlPathResolver.ToDisclosureMatch -> DisclosureComputation.ComputeAsync
                //-> DisclosureStrategyGraph. mdoc has no always-visible mandatory paths, so
                //the lattice bottom is empty; the engine's SelectedPaths is the minimal set.
                DisclosureStrategyGraph<MdocDocument> graph = (await DcqlDisclosure.ComputeStrategyAsync(query, storedMdoc, MdocDcqlAdapter.CreateMetadataExtractor(), MdocDcqlAdapter.ClaimExtractor, new FakeTimeProvider(TestClock.CanonicalEpoch), cancellationToken: cancellationToken).ConfigureAwait(false)).Graph;

                MdocPresentationDocument trimmed = storedMdoc.Derive(graph.Decisions[0].SelectedPaths);

                //Fresh mdoc_generated_nonce → SessionTranscript + apu (ISO/IEC 18013-7 §B.4.4).
                using IMemoryOwner<byte> nonceOwner =
                    Oid4VpMdocSessionTranscriptEncoder.GenerateMdocGeneratedNonce(
                        System.Security.Cryptography.RandomNumberGenerator.Fill, Pool);
                ReadOnlyMemory<byte> nonce =
                    nonceOwner.Memory[..Oid4VpMdocSessionTranscriptEncoder.MinimumMdocGeneratedNonceLength];

                ReadOnlyMemory<byte> sessionTranscript = Oid4VpMdocSessionTranscriptEncoder.Encode(
                    context.Request.ClientId,
                    context.Request.ResponseUri.OriginalString,
                    context.Request.Nonce,
                    nonce.Span,
                    BaseMemoryPool.Shared);

                using MdocPresentationDocument presented = await trimmed.DeviceSignAsync(
                    MdocDeviceNameSpaces.Empty, sessionTranscript, deviceKey, Pool, cancellationToken)
                    .ConfigureAwait(false);

                using MdocDeviceResponse deviceResponse = new(
                    MdocWellKnownKeys.Version10, [presented], MdocWellKnownKeys.StatusOk);

                presentations[queryId] = Oid4VpMdocPresentation.AssembleVpTokenValue(
                    deviceResponse, context.Base64UrlEncoder);
                responseEncryptionApu = context.Base64UrlEncoder(nonce.Span);
            }

            return new Oid4VpPresentationSet
            {
                PresentationsByQueryId = presentations,
                ResponseEncryptionApu = responseEncryptionApu
            };
        };
    }


    /// <summary>
    /// Issues the shared PID logical document, optionally referencing a Token Status List entry
    /// on the MSO's <c>status</c> member.
    /// </summary>
    /// <param name="issuerKeys">The issuer's P-256 signing key material.</param>
    /// <param name="deviceKeys">The wallet's device key material the MSO commits to.</param>
    /// <param name="status">
    /// The Status List entry to commit into the MSO's optional <c>status</c> member as a
    /// <c>status_list</c>-only status claim, or <see langword="null"/> to issue a credential with no
    /// status entry.
    /// </param>
    /// <param name="cancellationToken">Cancels issuance.</param>
    public static async ValueTask<MdocDocument> IssueAsync(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys,
        StatusListReference? status,
        CancellationToken cancellationToken)
    {
        return await BuildPidLogicalDocument().SignAsync(
            new MdocIssuerSigningConfig
            {
                DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                Validity = SampleValidity(),
                DeviceKey = CoseKeyFromP256Public(deviceKeys.PublicKey),
                Status = status is { } reference
                    ? StatusClaim.FromStatusList(reference.Index, reference.Uri)
                    : null
            },
            issuerKeys.PrivateKey,
            Pool,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>The shared PID logical document — family_name + given_name + (withheld) birth_date.</summary>
    private static MdocLogicalDocument BuildPidLogicalDocument() =>
        MdocIssuance.BuildDocument(
            docType: PidDocType,
            claims:
            [
                new() { NameSpace = PidNamespace, ElementIdentifier = EudiPid.Mdoc.FamilyName, EncodedElementValue = CborText("Mustermann") },
                new() { NameSpace = PidNamespace, ElementIdentifier = EudiPid.Mdoc.GivenName, EncodedElementValue = CborText("Erika") },
                //An element the DCQL query does NOT ask for, so element-level trimming
                //(MdocDocument.Derive) must withhold it — the mdoc mirror of the SD-CWT
                //fixture's withheld email. Without it the trim has nothing to drop.
                new() { NameSpace = PidNamespace, ElementIdentifier = EudiPid.Mdoc.BirthDate, EncodedElementValue = CborText("1984-09-19") }
            ],
            generateRandom: () => ItemRandomSalt(Pool));


    /// <summary>
    /// Builds an mdoc VP run whose IssuerAuth carries a real IACA x5chain (self-issued root +
    /// leaf, the leaf bearing an AuthorityKeyIdentifier), wired so the verifier (a) resolves the
    /// issuer key via <see cref="MdocCborIacaTrustResolver"/> against the root and (b) surfaces
    /// the leaf AuthorityKeyIdentifier for DCQL <c>trusted_authorities</c> (type <c>aki</c>)
    /// enforcement. Returns the run plus the leaf's AuthorityKeyIdentifier (base64url) so the
    /// caller can pin it (accept) or pin a stranger (reject). Pass a <paramref name="tp"/> whose
    /// clock is inside the certificate validity window (2025–2031) so chain validation succeeds.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The root trust anchor's ownership transfers to FormatRun.Owned, which " +
            "disposes it in FormatRun.DisposeAsync; it must outlive the run to back the IACA resolver.")]
    public static async ValueTask<(FormatRun Run, string AuthorityKeyIdentifier)> StartWithIacaChainAsync(
        FakeTimeProvider tp, CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        //The IACA root + leaf are setup-only: their DER is copied into the IssuerAuth x5chain
        //(during signing) and into the trust anchor, after which the X509 / ECDsa handles are
        //released. The leaf's private key signs the MSO; the verifier resolves it from the chain.
        //Framework ECDsa + CertificateRequest mint the chain (the test-side CA/attestation-chain
        //certificate-factory carve-out; CertificateRequest has no project-side equivalent).
        MdocDocument issued;
        PkiCertificateMemory rootTrustAnchor;
        using(ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        using(ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        using(X509Certificate2 rootCert = CreateIacaRoot("CN=Test IACA Root", rootKey))
        using(X509Certificate2 leafCert = CreateIacaLeaf("CN=Test mDL Issuer", leafKey, rootCert))
        using(PrivateKeyMemory leafPrivateKey = LoadP256PrivateKey(leafKey))
        {
            issued = await BuildPidLogicalDocument().SignAsync(
                new MdocIssuerSigningConfig
                {
                    DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                    Validity = SampleValidity(),
                    DeviceKey = CoseKeyFromP256Public(deviceKeys.PublicKey),
                    X5Chain = [leafCert.RawData, rootCert.RawData]
                },
                leafPrivateKey,
                Pool,
                cancellationToken).ConfigureAwait(false);

            rootTrustAnchor = CopyToPkiCertificate(rootCert.RawData);
        }

        MdocVpVerificationSeams seams = BuildSeams(
            MdocCborIacaTrustResolver.Create(
                MicrosoftX509Functions.ValidateChainAsync,
                trustAnchors: [rootTrustAnchor],
                timeProvider: tp,
                pool: Pool),
            ExtractTrustedAuthorityEvidence);

        TestHostShell app = new(tp, mdocSeams: seams);

        TrustedAuthorityEvidence? issuedEvidence = await ExtractTrustedAuthorityEvidence(
            issued.IssuerSigned.IssuerAuth, cancellationToken).ConfigureAwait(false);
        string authorityKeyIdentifier =
            issuedEvidence?.AuthorityKeyIdentifiers.Count > 0
                ? issuedEvidence.AuthorityKeyIdentifiers.First().ToBase64Url()
                : throw new InvalidOperationException(
                    "The issued mdoc's leaf certificate has no AuthorityKeyIdentifier to pin.");

        FormatRun run = new()
        {
            App = app,
            Query = BuildMdocPreparedQuery(),
            Produce = BuildMdocProduceDelegate(issued, deviceKeys.PrivateKey),
            AssertClaims = AssertClaims,
            Owned = [issued, deviceKeys.PublicKey, deviceKeys.PrivateKey, rootTrustAnchor]
        };

        return (run, authorityKeyIdentifier);
    }


    /// <summary>Creates a self-issued IACA root CA certificate (with a SubjectKeyIdentifier).</summary>
    private static X509Certificate2 CreateIacaRoot(string subjectName, ECDsa key)
    {
        //Test-side CA certificate factory carve-out: CertificateRequest mints the actual
        //self-signed X.509 structure the verifier's chain validator parses.
        var request = new CertificateRequest(subjectName, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 1, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        return request.CreateSelfSigned(
            notBefore: new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero),
            notAfter: new DateTimeOffset(2031, 1, 1, 0, 0, 0, TimeSpan.Zero));
    }


    /// <summary>
    /// Creates a leaf (document-signer) certificate signed by <paramref name="issuerCert"/>,
    /// carrying an AuthorityKeyIdentifier derived from the issuer's SubjectKeyIdentifier — the
    /// value a DCQL <c>trusted_authorities</c> entry of type <c>aki</c> matches (§6.1.1.1).
    /// </summary>
    private static X509Certificate2 CreateIacaLeaf(string subjectName, ECDsa leafKey, X509Certificate2 issuerCert)
    {
        //Test-side CA certificate factory carve-out: CertificateRequest signs the leaf against
        //the root, producing the AuthorityKeyIdentifier the DCQL trusted_authorities check reads.
        var request = new CertificateRequest(subjectName, leafKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
        request.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromCertificate(
                issuerCert, includeKeyIdentifier: true, includeIssuerAndSerial: false));

        using Salt serialNumber = X509ChainTestRing.CreateSerialNumber(16);
        return request.Create(
            issuerCert,
            notBefore: new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero),
            notAfter: new DateTimeOffset(2031, 1, 1, 0, 0, 0, TimeSpan.Zero),
            serialNumber.AsReadOnlySpan()).CopyWithPrivateKey(leafKey);
    }


    /// <summary>Wraps an <see cref="ECDsa"/> private scalar into the project's <see cref="PrivateKeyMemory"/> carrier.</summary>
    private static PrivateKeyMemory LoadP256PrivateKey(ECDsa key)
    {
        //Bridges the leaf key out of the test-side certificate factory carve-out into the
        //project's key-material carrier so the library's signing API can consume it.
        ECParameters parameters = key.ExportParameters(includePrivateParameters: true);
        byte[] dBytes = parameters.D!;

        IMemoryOwner<byte> owner = Pool.Rent(dBytes.Length);
        dBytes.CopyTo(owner.Memory.Span);

        return new PrivateKeyMemory(owner, CryptoTags.P256PrivateKey);
    }


    /// <summary>Copies DER certificate bytes into a pooled <see cref="PkiCertificateMemory"/> trust anchor.</summary>
    private static PkiCertificateMemory CopyToPkiCertificate(byte[] derBytes)
    {
        IMemoryOwner<byte> owner = Pool.Rent(derBytes.Length);
        derBytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    /// <summary>
    /// Trust-anchor resolver: the verifier knows the issuer key out of band (the
    /// legitimate trust input). Returns a fresh clone per call so the resolution owns
    /// its own carrier. Shared by every caller that needs a direct-trust
    /// <see cref="ResolveMdocIssuerKeyDelegate"/> rather than chain validation.
    /// </summary>
    /// <param name="trustedIssuerKey">The issuer public key the verifier resolves out of band.</param>
    /// <returns>The resolver delegate.</returns>
    public static ResolveMdocIssuerKeyDelegate TrustAnchorFor(PublicKeyMemory trustedIssuerKey) =>
        (issuerAuth, cancellationToken) => ValueTask.FromResult(
            MdocIacaTrustResolution.Success(ClonePublicKey(trustedIssuerKey, Pool)));


    /// <summary>Decodes a CBOR element value to its string form for the claim surface.</summary>
    /// <param name="encodedElementValue">The element's encoded CBOR bytes.</param>
    /// <returns>The decoded value as text.</returns>
    public static string DecodeElementValue(ReadOnlyMemory<byte> encodedElementValue)
    {
        var reader = new CborReader(encodedElementValue, CborOptions.Lax);

        return CborValueConverter.ReadValue(reader)?.ToString() ?? string.Empty;
    }


    /// <summary>Copies a public key into a freshly rented buffer, so the resolution owns an independently disposable carrier.</summary>
    /// <param name="source">The key to clone.</param>
    /// <param name="pool">The pool the clone's buffer is rented from.</param>
    /// <returns>The cloned key, carrying <paramref name="source"/>'s own <see cref="Lumoin.Base.SensitiveData.Tag"/>.</returns>
    public static PublicKeyMemory ClonePublicKey(PublicKeyMemory source, BaseMemoryPool pool)
    {
        ReadOnlySpan<byte> bytes = source.AsReadOnlySpan();
        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new PublicKeyMemory(owner, source.Tag);
    }


    /// <summary>
    /// Rewrites the CBOR data item found at <paramref name="path"/> inside <paramref name="encoded"/> and copies
    /// every other byte of the surrounding structure as encoded, so a test can put one exact malformed shape
    /// into an otherwise genuine wire form. A path step is a text map key, an integer map key, or an array
    /// index; a tag on the way is kept and passed through.
    /// </summary>
    /// <param name="encoded">The encoded data item to rewrite inside.</param>
    /// <param name="path">The steps from <paramref name="encoded"/> to the item to rewrite.</param>
    /// <param name="rewrite">Answers the replacement encoding of the item found at the path.</param>
    /// <returns>The rewritten encoding.</returns>
    public static byte[] RewriteAt(ReadOnlyMemory<byte> encoded, IReadOnlyList<object> path, Func<ReadOnlyMemory<byte>, byte[]> rewrite)
    {
        return RewriteAt(encoded, path, 0, rewrite);
    }


    /// <summary>
    /// Answers a copy of the CBOR data item found at <paramref name="path"/> inside <paramref name="encoded"/>.
    /// </summary>
    /// <param name="encoded">The encoded data item to read inside.</param>
    /// <param name="path">The steps from <paramref name="encoded"/> to the item, as <see cref="RewriteAt(ReadOnlyMemory{byte}, IReadOnlyList{object}, Func{ReadOnlyMemory{byte}, byte[]})"/> takes them.</param>
    /// <returns>The item's encoding.</returns>
    public static byte[] ReadAt(ReadOnlyMemory<byte> encoded, IReadOnlyList<object> path)
    {
        byte[] found = [];
        _ = RewriteAt(encoded, path, 0, item =>
        {
            found = item.ToArray();

            return found;
        });

        return found;
    }


    /// <summary>
    /// Copies an integer-labelled CBOR map and makes it carry <paramref name="label"/> twice: a label the map
    /// already holds gains a second entry with the same value, and an absent label is added twice with
    /// <paramref name="valueWhenAbsent"/>.
    /// </summary>
    /// <param name="map">The encoded definite-length map whose labels are integers.</param>
    /// <param name="label">The label the copy carries twice.</param>
    /// <param name="valueWhenAbsent">The encoded value the label is added with when the map does not hold it.</param>
    /// <returns>The encoded map carrying <paramref name="label"/> twice.</returns>
    public static byte[] WithLabelTwice(ReadOnlyMemory<byte> map, int label, ReadOnlyMemory<byte> valueWhenAbsent)
    {
        var reader = new CborReader(map, CborOptions.Lax);
        var entries = new List<(int Label, ReadOnlyMemory<byte> Value)>();
        int count = reader.ReadStartMap() ?? throw new InvalidOperationException("The map is a definite-length map.");
        for(int i = 0; i < count; i++)
        {
            entries.Add((reader.ReadInt32(), reader.ReadEncodedValue()));
        }

        bool isLabelHeld = entries.Exists(entry => entry.Label == label);
        ReadOnlyMemory<byte> repeatedValue = isLabelHeld ? entries.Find(entry => entry.Label == label).Value : valueWhenAbsent;
        int addedEntries = isLabelHeld ? 1 : 2;

        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.Lax);
        writer.WriteStartMap(count + addedEntries);
        foreach((int entryLabel, ReadOnlyMemory<byte> value) in entries)
        {
            writer.WriteInt32(entryLabel);
            writer.WriteEncodedValue(value.Span);
        }

        for(int i = 0; i < addedEntries; i++)
        {
            writer.WriteInt32(label);
            writer.WriteEncodedValue(repeatedValue.Span);
        }

        writer.WriteEndMap();

        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Rewrites an IssuerAuth COSE_Sign1 so the Mobile Security Object's <c>deviceKey</c> COSE_Key carries its
    /// <c>x</c> coordinate (label -2) twice, and signs the rewritten payload again under the issuer key, so the
    /// issuer signature over the malformed Mobile Security Object is genuine.
    /// </summary>
    /// <param name="issuerAuth">The encoded IssuerAuth COSE_Sign1.</param>
    /// <param name="issuerKey">The issuer's signing key.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The encoded IssuerAuth whose Mobile Security Object repeats the device key's <c>x</c>.</returns>
    public static async ValueTask<byte[]> ResignIssuerAuthWithDeviceKeyXTwiceAsync(
        ReadOnlyMemory<byte> issuerAuth, PrivateKeyMemory issuerKey, CancellationToken cancellationToken)
    {
        const int CoseKeyX = -2;

        var reader = new CborReader(issuerAuth, CborOptions.Lax);
        CborTag? issuerAuthTag = reader.PeekState() == CborReaderState.Tag ? reader.ReadTag() : null;
        _ = reader.ReadStartArray();
        byte[] protectedHeader = reader.ReadByteString();
        ReadOnlyMemory<byte> unprotectedHeader = reader.ReadEncodedValue();
        byte[] payload = reader.ReadByteString();

        var payloadReader = new CborReader(payload, CborOptions.Lax);
        CborTag payloadTag = payloadReader.ReadTag();
        byte[] mso = payloadReader.ReadByteString();
        byte[] rewrittenMso = RewriteAt(
            mso, ["deviceKeyInfo", "deviceKey"], deviceKey => WithLabelTwice(deviceKey, CoseKeyX, ReadOnlyMemory<byte>.Empty));

        var payloadBuffer = new ArrayBufferWriter<byte>();
        var payloadWriter = new CborWriter(payloadBuffer, CborOptions.Lax);
        payloadWriter.WriteTag(payloadTag);
        payloadWriter.WriteByteString(rewrittenMso);
        byte[] rewrittenPayload = payloadBuffer.WrittenSpan.ToArray();

        using CoseSign1Message signed = await Verifiable.JCose.Cose.SignAsync(
            EncodedCoseProtectedHeader.FromBytes(protectedHeader, Pool),
            unprotectedHeader: null,
            rewrittenPayload,
            CoseSerialization.BuildSigStructure,
            issuerKey,
            Pool,
            cancellationToken).ConfigureAwait(false);

        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.Lax);
        if(issuerAuthTag is CborTag tag)
        {
            writer.WriteTag(tag);
        }

        writer.WriteStartArray(4);
        writer.WriteByteString(protectedHeader);
        writer.WriteEncodedValue(unprotectedHeader.Span);
        writer.WriteByteString(rewrittenPayload);
        writer.WriteByteString(signed.Signature.AsReadOnlySpan());
        writer.WriteEndArray();

        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Walks one step of <paramref name="path"/> per nesting level for
    /// <see cref="RewriteAt(ReadOnlyMemory{byte}, IReadOnlyList{object}, Func{ReadOnlyMemory{byte}, byte[]})"/>.
    /// </summary>
    /// <param name="encoded">The encoded data item at this level.</param>
    /// <param name="path">The whole path.</param>
    /// <param name="depth">How many steps of the path lie above this level.</param>
    /// <param name="rewrite">Answers the replacement encoding of the item found at the path.</param>
    /// <returns>The rewritten encoding of this level.</returns>
    private static byte[] RewriteAt(ReadOnlyMemory<byte> encoded, IReadOnlyList<object> path, int depth, Func<ReadOnlyMemory<byte>, byte[]> rewrite)
    {
        if(depth == path.Count)
        {
            return rewrite(encoded);
        }

        var reader = new CborReader(encoded, CborOptions.Lax);
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.Lax);
        CborReaderState state = reader.PeekState();

        if(state == CborReaderState.Tag)
        {
            writer.WriteTag(reader.ReadTag());
            writer.WriteEncodedValue(RewriteAt(reader.ReadEncodedValue(), path, depth, rewrite));
        }
        else if(state == CborReaderState.StartMap)
        {
            int count = reader.ReadStartMap() ?? throw new InvalidOperationException("The map on the path is a definite-length map.");
            writer.WriteStartMap(count);
            for(int i = 0; i < count; i++)
            {
                ReadOnlyMemory<byte> key = reader.ReadEncodedValue();
                ReadOnlyMemory<byte> value = reader.ReadEncodedValue();
                writer.WriteEncodedValue(key.Span);
                writer.WriteEncodedValue(IsPathStep(key, path[depth]) ? RewriteAt(value, path, depth + 1, rewrite) : value.Span);
            }

            reader.ReadEndMap();
            writer.WriteEndMap();
        }
        else if(state == CborReaderState.StartArray)
        {
            int count = reader.ReadStartArray() ?? throw new InvalidOperationException("The array on the path is a definite-length array.");
            writer.WriteStartArray(count);
            for(int i = 0; i < count; i++)
            {
                ReadOnlyMemory<byte> element = reader.ReadEncodedValue();
                writer.WriteEncodedValue(path[depth] is int index && index == i ? RewriteAt(element, path, depth + 1, rewrite) : element.Span);
            }

            reader.ReadEndArray();
            writer.WriteEndArray();
        }
        else
        {
            throw new InvalidOperationException($"The path step {path[depth]} lands on a {state}, not a map or an array.");
        }

        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>Tells whether an encoded map key is the map-key step of a path.</summary>
    /// <param name="encodedKey">The encoded map key.</param>
    /// <param name="step">The path step: a text map key or an integer map key.</param>
    /// <returns><see langword="true"/> when the map key is the step.</returns>
    private static bool IsPathStep(ReadOnlyMemory<byte> encodedKey, object step)
    {
        var reader = new CborReader(encodedKey, CborOptions.Lax);
        CborReaderState state = reader.PeekState();

        return step switch
        {
            string text => state == CborReaderState.TextString && string.Equals(reader.ReadTextString(), text, StringComparison.Ordinal),
            int label => state is CborReaderState.UnsignedInteger or CborReaderState.NegativeInteger && reader.ReadInt32() == label,
            _ => false
        };
    }


    /// <summary>The fixed validity window every mdoc this fixture issues carries — a one-year window signed 2026-05-25.</summary>
    /// <returns>The validity window.</returns>
    public static MdocValidityInfo SampleValidity() =>
        new(
            signed: new DateTimeOffset(2026, 5, 25, 8, 0, 0, TimeSpan.Zero),
            validFrom: new DateTimeOffset(2026, 5, 25, 8, 0, 0, TimeSpan.Zero),
            validUntil: new DateTimeOffset(2027, 5, 25, 8, 0, 0, TimeSpan.Zero));
}
