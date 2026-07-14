using System.Buffers;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cbor;
using Verifiable.Cbor.Mdoc;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.Model.SelectiveDisclosure.Strategy;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.Microsoft;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
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
    private const string CredentialQueryId = "pid";
    private static readonly string PidDocType = EudiPid.AttestationType;
    private static readonly string PidNamespace = EudiPid.Mdoc.Namespace;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;


    /// <summary>The mdoc matrix-format row: name plus the per-run <see cref="FormatRun"/> factory.</summary>
    public static FormatFixture Format => new("mso_mdoc", StartAsync);


    private static async ValueTask<FormatRun> StartAsync(FakeTimeProvider tp, CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        //The verifier's trust framework resolves the issuer key out of band; the
        //seams carry that resolver plus the CBOR/COSE implementations the executor
        //dispatches mso_mdoc through.
        MdocVpVerificationSeams seams = new()
        {
            ResolveIssuerKey = TrustAnchorFor(issuerKeys.PublicKey),
            ParseDeviceResponse = MdocCborDeviceResponseReader.Read,
            EncodeSessionTranscript = Oid4VpMdocSessionTranscriptEncoder.Encode,
            DecodeElementValue = DecodeElementValue,
            ParseCoseSign1 = CoseSerialization.ParseCoseSign1,
            ParseCoseSign1AllowingNilPayload = CoseSerialization.ParseCoseSign1AllowingNilPayload,
            EncodeDeviceAuthenticationBytes = MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes,
            BuildSigStructure = CoseSerialization.BuildSigStructure
        };

        TestHostShell app = new(tp, mdocSeams: seams);

        //The wallet holds the issued mdoc; the device key matches the MSO's
        //committed device key. The credential and key never leave the wallet —
        //only the wire JWE crosses to the verifier.
        MdocDocument issued = await IssueAsync(issuerKeys, deviceKeys, cancellationToken).ConfigureAwait(false);

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


    private static void AssertClaims(PresentationVerifiedState verified)
    {
        Assert.IsTrue(verified.Claims.TryGetValue(CredentialQueryId,
            out IReadOnlyDictionary<string, string>? claims),
            "Verified claims must be keyed by the DCQL credential query id.");
        Assert.AreEqual("Mustermann", claims![EudiPid.Mdoc.FamilyName],
            "The disclosed family_name must round-trip through the full flow.");
        Assert.AreEqual("Erika", claims[EudiPid.Mdoc.GivenName],
            "The disclosed given_name must round-trip through the full flow.");
        Assert.IsFalse(claims.ContainsKey(EudiPid.Mdoc.BirthDate),
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
                    Id = CredentialQueryId,
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
                    Id = CredentialQueryId,
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
    /// The mdoc authority-identifier extractor wired behind
    /// <see cref="MdocVpVerificationSeams.ExtractAuthorityIdentifier"/> — the library
    /// composition of <see cref="MdocCborAuthorityIdentifierExtractor"/> (x5chain) and
    /// <see cref="MicrosoftX509Functions.GetAuthorityKeyIdentifier"/> (the leaf cert's AKI),
    /// the exact analogue of how the IACA resolver is composed from
    /// <c>MdocCborIacaTrustResolver.Create</c> + <c>MicrosoftX509Functions.ValidateChainAsync</c>.
    /// </summary>
    public static readonly ExtractMdocAuthorityIdentifierDelegate ExtractLeafAuthorityKeyIdentifier =
        MdocCborAuthorityIdentifierExtractor.Create(
            MicrosoftX509Functions.GetAuthorityKeyIdentifier,
            TestSetup.Base64UrlEncoder,
            Pool);


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
                DisclosureStrategyGraph<MdocDocument> graph = (await DcqlDisclosure.ComputeStrategyAsync(
                    query,
                    storedMdoc,
                    MdocDcqlAdapter.MetadataExtractor,
                    MdocDcqlAdapter.ClaimExtractor,
                    cancellationToken: cancellationToken).ConfigureAwait(false)).Graph;

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
                    nonce.Span);

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


    public static async ValueTask<MdocDocument> IssueAsync(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys,
        CancellationToken cancellationToken)
    {
        return await BuildPidLogicalDocument().SignAsync(
            new MdocIssuerSigningConfig
            {
                DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                Validity = SampleValidity(),
                DeviceKey = CoseKeyFromP256Public(deviceKeys.PublicKey)
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

        MdocVpVerificationSeams seams = new()
        {
            ResolveIssuerKey = MdocCborIacaTrustResolver.Create(
                MicrosoftX509Functions.ValidateChainAsync,
                trustAnchors: [rootTrustAnchor],
                validationTime: tp.GetUtcNow(),
                pool: Pool),
            ParseDeviceResponse = MdocCborDeviceResponseReader.Read,
            EncodeSessionTranscript = Oid4VpMdocSessionTranscriptEncoder.Encode,
            DecodeElementValue = DecodeElementValue,
            ParseCoseSign1 = CoseSerialization.ParseCoseSign1,
            ParseCoseSign1AllowingNilPayload = CoseSerialization.ParseCoseSign1AllowingNilPayload,
            EncodeDeviceAuthenticationBytes = MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes,
            BuildSigStructure = CoseSerialization.BuildSigStructure,
            ExtractAuthorityIdentifier = ExtractLeafAuthorityKeyIdentifier
        };

        TestHostShell app = new(tp, mdocSeams: seams);

        string authorityKeyIdentifier =
            ExtractLeafAuthorityKeyIdentifier(issued.IssuerSigned.IssuerAuth)
            ?? throw new InvalidOperationException(
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

        //Test-side CA certificate factory carve-out: the serial number is an X.509 structural
        //field of the leaf CertificateRequest.Create call, not fixture key material.
        byte[] serialNumber = RandomNumberGenerator.GetBytes(16);
        return request.Create(
            issuerCert,
            notBefore: new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero),
            notAfter: new DateTimeOffset(2031, 1, 1, 0, 0, 0, TimeSpan.Zero),
            serialNumber).CopyWithPrivateKey(leafKey);
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
    /// its own carrier.
    /// </summary>
    private static ResolveMdocIssuerKeyDelegate TrustAnchorFor(PublicKeyMemory trustedIssuerKey) =>
        (issuerAuth, cancellationToken) => ValueTask.FromResult(
            MdocIacaTrustResolution.Success(ClonePublicKey(trustedIssuerKey, Pool)));


    private static string DecodeElementValue(ReadOnlyMemory<byte> encodedElementValue)
    {
        var reader = new CborReader(encodedElementValue, CborConformanceMode.Lax);

        return CborValueConverter.ReadValue(reader)?.ToString() ?? string.Empty;
    }


    private static PublicKeyMemory ClonePublicKey(PublicKeyMemory source, MemoryPool<byte> pool)
    {
        ReadOnlySpan<byte> bytes = source.AsReadOnlySpan();
        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new PublicKeyMemory(owner, source.Tag);
    }


    private static MdocValidityInfo SampleValidity() =>
        new(
            signed: new DateTimeOffset(2026, 5, 25, 8, 0, 0, TimeSpan.Zero),
            validFrom: new DateTimeOffset(2026, 5, 25, 8, 0, 0, TimeSpan.Zero),
            validUntil: new DateTimeOffset(2027, 5, 25, 8, 0, 0, TimeSpan.Zero));
}
