using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Linq;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Model.Dcql;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Federation;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;


/// <summary>
/// Tests for JAR client identifier prefix handling per OID4VP 1.0 §5.9.
/// Covers the <c>verifier_attestation:</c> and <c>x509_san_dns:</c> prefixes
/// mandated by HAIP 1.0.
/// </summary>
/// <remarks>
/// <para>
/// Each test models the delegate boundary the Wallet crosses to resolve the Verifier's
/// JAR signing key. The key resolution mechanism (attestation JWT parsing, certificate
/// chain walking) is behind a delegate — the test supplies a concrete implementation
/// that represents "already resolved by the appropriate mechanism."
/// </para>
/// <para>
/// <c>x509_san_dns:</c> tests are pending the general-purpose X.509 chain validation
/// infrastructure. See the status document for the planned design.
/// </para>
/// </remarks>
[TestClass]
internal sealed class JarClientIdentifierTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();
    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;
    private static EncodeDelegate Encoder => TestSetup.Base64UrlEncoder;
    private static DecodeDelegate Decoder => TestSetup.Base64UrlDecoder;

    private static readonly JwtHeaderSerializer JwtHeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer JwtPayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);

    private const string VerifierClientId = "https://verifier.example.com";


    //verifier_attestation: prefix (OID4VP 1.0 §5.9.3, HAIP 1.0 mandatory).
    //
    //The JAR header carries a Verifier Attestation JWT in the "jwt" JOSE parameter.
    //The attestation is signed by a trust anchor. Its cnf claim holds the Verifier's
    //JAR signing public key. The Wallet resolves the signing key via the attestation
    //before verifying the JAR signature.
    //
    //Trust model:
    //
    //  Trust Anchor          Verifier                    Wallet
    //      |                    |                           |
    //      | Signs attestation  |                           |
    //      |-(sub=verifier, --->|                           |
    //      |  cnf=signingKey)   |                           |
    //      |                    |                           |
    //      |                    | JAR (jwt header =         |
    //      |                    | attestation JWT)          |
    //      |                    |-------------------------->|
    //      |                    |                           |
    //      |<--- Wallet knows trust anchor key ------------>|
    //      |                    | Wallet validates:         |
    //      |                    |  1. attestation.sig OK    |
    //      |                    |  2. attestation.sub ==    |
    //      |                    |     client_id (stripped)  |
    //      |                    |  3. JAR.sig OK with cnf   |

    [TestMethod]
    public async Task VerifierAttestationPrefixJarSignatureVerifiesWithValidAttestation()
    {
        //Trust anchor: signs the Verifier Attestation JWT.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> trustAnchorKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory trustAnchorPublicKey = trustAnchorKeys.PublicKey;
        using PrivateKeyMemory trustAnchorPrivateKey = trustAnchorKeys.PrivateKey;

        //Verifier signing keys: the JAR is signed with this key pair.
        //The public key is embedded in the attestation's cnf claim.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> verifierSigningKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory verifierSigningPublicKey = verifierSigningKeys.PublicKey;
        using PrivateKeyMemory verifierSigningPrivateKey = verifierSigningKeys.PrivateKey;

        //The full client_id using the verifier_attestation: prefix.
        string clientIdWithPrefix =
            $"{WellKnownClientIdPrefixes.VerifierAttestation}:{VerifierClientId}";
        string clientIdWithoutPrefix =
            WellKnownClientIdPrefixes.StripPrefix(clientIdWithPrefix);

        //Build and sign the Verifier Attestation JWT.
        //In production this JWT is issued by the trust anchor out-of-band and
        //stored by the Verifier for embedding in JAR headers.
        DateTimeOffset now = TimeProvider.GetUtcNow();
        string attestationCompactJwt = await VerifierAttestationIssuer.BuildAsync(
            issuer: "https://trust-anchor.example.com",
            subject: clientIdWithoutPrefix,
            verifierSigningPublicKey: verifierSigningPublicKey,
            trustAnchorPrivateKey: trustAnchorPrivateKey,
            issuedAt: now,
            expiresAt: now.AddHours(1),
            headerSerializer: JwtHeaderSerializer,
            payloadSerializer: JwtPayloadSerializer,
            base64UrlEncoder: Encoder,
            jwkConverter: static key => CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
                key.Tag.Get<CryptoAlgorithm>(),
                key.Tag.Get<Purpose>(),
                key.AsReadOnlySpan(),
                TestSetup.Base64UrlEncoder),
            pool: Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Build the JAR with the attestation in the jwt JOSE header.
        VerifierClientMetadata clientMetadata =
            HaipProfile.CreateVerifierClientMetadata(VerifierClientId,
                /*lang=json,strict*/ "{\"keys\":[]}");
        AuthorizationRequestObject requestObject =
            HaipProfile.CreateAuthorizationRequestObject(
                clientId: clientIdWithPrefix,
                responseUri: new Uri("https://verifier.example.com/cb"),
                nonce: "nonce-att-01",
                dcqlQuery: DcqlFixtures.PidGivenAndFamilyName(),
                clientMetadata: clientMetadata,
                state: "state-att-01",
                iat: now,
                nbf: now,
                exp: now + TimingPolicy.Default.Oid4VpRequestObjectLifetime);

        using SignedJar signedJar = await requestObject.SignJarAsync(
            signingKey: verifierSigningPrivateKey,
            headerSerializer: JwtHeaderSerializer,
            payloadSerializer: JwtPayloadSerializer,
            dcqlQuerySerializer: q => JsonSerializer.Serialize(q, TestSetup.DefaultSerializationOptions),
            clientMetadataSerializer: m => JsonSerializer.Serialize(m, TestSetup.DefaultSerializationOptions),
            base64UrlEncoder: Encoder,
            memoryPool: Pool,
            additionalHeaderClaims: new Dictionary<string, object>
            {
                [WellKnownJoseHeaderNames.Jwt] = attestationCompactJwt
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = JwsSerialization.SerializeCompact(signedJar.Message, Encoder);


        //=== Wallet side ===

        //Step 1: Extract the attestation JWT from the JAR header.
        bool hasAttestation = JarAttestationExtensions.TryGetVerifierAttestationJwt(
            compactJar,
            Decoder,
            bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            Pool,
            out VerifierAttestationJwt? attestation);

        Assert.IsTrue(hasAttestation,
            "Wallet must find a Verifier Attestation JWT in the jwt JOSE header.");
        Assert.IsNotNull(attestation);

        //Step 2: Validate the attestation and resolve the JAR signing key.
        //The delegate stands in for the Wallet's trust anchor verification logic.
        using PublicKeyMemory resolvedSigningKey = await ResolveKeyFromAttestationAsync(
            attestation!,
            clientIdWithoutPrefix,
            trustAnchorPublicKey,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Step 3: Verify the JAR signature with the resolved key and parse the claims.
        //VerifyAndParseJarAsync enforces that an invalid signature never produces a
        //usable AuthorizationRequestObject.
        AuthorizationRequestObject parsedRequest = await JarExtensions.VerifyAndParseJarAsync(
            compactJar,
            resolvedSigningKey,
            Decoder,
            bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            json => JsonSerializer.Deserialize<DcqlQuery>(
                json, TestSetup.DefaultSerializationOptions)!,
            json => JsonSerializer.Deserialize<VerifierClientMetadata>(
                json, TestSetup.DefaultSerializationOptions)!,
            StateParameterPolicy.Required,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(clientIdWithPrefix, parsedRequest.ClientId,
            "Parsed client_id must include the verifier_attestation: prefix.");
        Assert.AreEqual(WellKnownResponseModes.DirectPostJwt, parsedRequest.ResponseMode);
        Assert.IsNotNull(parsedRequest.DcqlQuery);
    }


    [TestMethod]
    public async Task VerifierAttestationPrefixJarSignatureFailsWithWrongAttestationKey()
    {
        //Trust anchor signs the attestation with its real key.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> realTrustAnchorKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory realTrustAnchorPublicKey = realTrustAnchorKeys.PublicKey;
        using PrivateKeyMemory realTrustAnchorPrivateKey = realTrustAnchorKeys.PrivateKey;

        //Wallet has a different key it believes is the trust anchor — an attacker
        //cannot forge an attestation that the Wallet accepts.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> wrongTrustAnchorKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory wrongTrustAnchorPublicKey = wrongTrustAnchorKeys.PublicKey;
        wrongTrustAnchorKeys.PrivateKey.Dispose();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> verifierSigningKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory verifierSigningPublicKey = verifierSigningKeys.PublicKey;
        using PrivateKeyMemory verifierSigningPrivateKey = verifierSigningKeys.PrivateKey;

        string clientIdWithPrefix =
            $"{WellKnownClientIdPrefixes.VerifierAttestation}:{VerifierClientId}";
        string clientIdWithoutPrefix =
            WellKnownClientIdPrefixes.StripPrefix(clientIdWithPrefix);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string attestationCompactJwt = await VerifierAttestationIssuer.BuildAsync(
            issuer: "https://trust-anchor.example.com",
            subject: clientIdWithoutPrefix,
            verifierSigningPublicKey: verifierSigningPublicKey,
            trustAnchorPrivateKey: realTrustAnchorPrivateKey,
            issuedAt: now,
            expiresAt: now.AddHours(1),
            headerSerializer: JwtHeaderSerializer,
            payloadSerializer: JwtPayloadSerializer,
            base64UrlEncoder: Encoder,
            jwkConverter: static key => CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
                key.Tag.Get<CryptoAlgorithm>(),
                key.Tag.Get<Purpose>(),
                key.AsReadOnlySpan(),
                TestSetup.Base64UrlEncoder),
            pool: Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        VerifierClientMetadata clientMetadata =
            HaipProfile.CreateVerifierClientMetadata(VerifierClientId,
                /*lang=json,strict*/ "{\"keys\":[]}");
        AuthorizationRequestObject requestObject =
            HaipProfile.CreateAuthorizationRequestObject(
                clientId: clientIdWithPrefix,
                responseUri: new Uri("https://verifier.example.com/cb"),
                nonce: "nonce-att-02",
                dcqlQuery: DcqlFixtures.PidGivenAndFamilyName(),
                clientMetadata: clientMetadata,
                state: "state-att-02",
                iat: now,
                nbf: now,
                exp: now + TimingPolicy.Default.Oid4VpRequestObjectLifetime);

        using SignedJar signedJar = await requestObject.SignJarAsync(
            signingKey: verifierSigningPrivateKey,
            headerSerializer: JwtHeaderSerializer,
            payloadSerializer: JwtPayloadSerializer,
            dcqlQuerySerializer: q => JsonSerializer.Serialize(q, TestSetup.DefaultSerializationOptions),
            clientMetadataSerializer: m => JsonSerializer.Serialize(m, TestSetup.DefaultSerializationOptions),
            base64UrlEncoder: Encoder,
            memoryPool: Pool,
            additionalHeaderClaims: new Dictionary<string, object>
            {
                [WellKnownJoseHeaderNames.Jwt] = attestationCompactJwt
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = JwsSerialization.SerializeCompact(signedJar.Message, Encoder);

        JarAttestationExtensions.TryGetVerifierAttestationJwt(
            compactJar,
            Decoder,
            bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            Pool,
            out VerifierAttestationJwt? attestation);

        //Wallet uses the wrong trust anchor key — attestation signature verification
        //must throw rather than return a key that was never validated.
        bool validWithCorrectKey;
        try
        {
            using PublicKeyMemory _ = await ResolveKeyFromAttestationAsync(
                attestation!, clientIdWithoutPrefix, realTrustAnchorPublicKey,
                Pool, TestContext.CancellationToken).ConfigureAwait(false);
            validWithCorrectKey = true;
        }
        catch(InvalidOperationException)
        {
            validWithCorrectKey = false;
        }

        bool validWithWrongKey;
        try
        {
            using PublicKeyMemory _ = await ResolveKeyFromAttestationAsync(
                attestation!, clientIdWithoutPrefix, wrongTrustAnchorPublicKey,
                Pool, TestContext.CancellationToken).ConfigureAwait(false);
            validWithWrongKey = true;
        }
        catch(InvalidOperationException)
        {
            validWithWrongKey = false;
        }

        Assert.IsTrue(validWithCorrectKey,
            "Attestation must verify with the real trust anchor key.");
        Assert.IsFalse(validWithWrongKey,
            "Attestation must not verify with a wrong trust anchor key.");
    }


    //x509_san_dns: prefix (OID4VP 1.0 §5.9.3, HAIP 1.0 mandatory).
    //Pending: requires general-purpose X.509 chain validation infrastructure.
    //The infrastructure will be shared with TPM EK/AK chain validation and
    //SD-JWT VC issuer certificate validation.

    //x509_san_dns: prefix (OID4VP 1.0 §5.9.3, HAIP 1.0 mandatory).
    //
    //The JAR x5c JOSE header carries the certificate chain. The leaf cert's DNS SAN
    //must match the client_id (minus the prefix). The Wallet validates the chain,
    //checks the SAN, and uses the leaf public key to verify the JAR signature.
    //
    //Trust model:
    //
    //  Trust Anchor CA          Verifier                    Wallet
    //      |                       |                           |
    //      | Issues cert           |                           |
    //      | (DNS SAN =            |                           |
    //      |  client.example.org)  |                           |
    //      |---------------------->|                           |
    //      |                       | JAR (x5c = [leaf, CA])   |
    //      |                       |-------------------------->|
    //      |                       |                           |
    //      |<--- Wallet has CA cert (trust anchor) ----------->|
    //      |                       | Wallet validates:         |
    //      |                       |  1. chain to trust anchor |
    //      |                       |  2. leaf DNS SAN matches  |
    //      |                       |     client_id (no prefix) |
    //      |                       |  3. JAR.sig OK with leaf  |
    //
    //Both BouncyCastle and Microsoft implementations are exercised and their results
    //cross-checked to verify consistent behaviour across driver libraries.

    [TestMethod]
    public async Task X509SanDnsPrefixJarSignatureVerifiesWithValidCertificateChain()
    {
        using CertificateChainMaterial chain =
            TestCertificateChainProvider.CreateP256ChainMaterial(TimeProvider);

        string clientIdWithPrefix =
            $"{WellKnownClientIdPrefixes.X509SanDns}:{chain.DnsName}";
        string clientIdWithoutPrefix =
            WellKnownClientIdPrefixes.StripPrefix(clientIdWithPrefix);

        string leafBase64 = Convert.ToBase64String(
            chain.LeafDerBytes.AsReadOnlyMemory().ToArray());
        string caBase64 = Convert.ToBase64String(
            chain.CaDerBytes.AsReadOnlyMemory().ToArray());
        string[] x5cValues = [leafBase64, caBase64];

        //Trust anchors loaded through each driver's own parsing facility.
        IReadOnlyList<PkiCertificateMemory> trustAnchorsMicrosoft =
            MicrosoftX509Functions.ParseX5c([caBase64], Pool);
        IReadOnlyList<PkiCertificateMemory> trustAnchorsBouncyCastle =
            BouncyCastleX509Functions.ParseX5c([caBase64], Pool);

        try
        {
            //Build the JAR with x5c in the header.
            VerifierClientMetadata clientMetadata =
                HaipProfile.CreateVerifierClientMetadata(clientIdWithPrefix,
                    /*lang=json,strict*/ "{\"keys\":[]}");
            DateTimeOffset now = TimeProvider.GetUtcNow();
            AuthorizationRequestObject requestObject =
                HaipProfile.CreateAuthorizationRequestObject(
                    clientId: clientIdWithPrefix,
                    responseUri: new Uri("https://verifier.example.com/cb"),
                    nonce: "nonce-x509-01",
                    dcqlQuery: DcqlFixtures.PidGivenAndFamilyName(),
                    clientMetadata: clientMetadata,
                    state: "state-x509-01",
                    iat: now,
                    nbf: now,
                    exp: now + TimingPolicy.Default.Oid4VpRequestObjectLifetime);

            using SignedJar signedJar = await requestObject.SignJarAsync(
                signingKey: chain.LeafSigningKey,
                headerSerializer: JwtHeaderSerializer,
                payloadSerializer: JwtPayloadSerializer,
                dcqlQuerySerializer: q => JsonSerializer.Serialize(
                    q, TestSetup.DefaultSerializationOptions),
                clientMetadataSerializer: m => JsonSerializer.Serialize(
                    m, TestSetup.DefaultSerializationOptions),
                base64UrlEncoder: Encoder,
                memoryPool: Pool,
                additionalHeaderClaims: new Dictionary<string, object>
                {
                    [WellKnownJwkMemberNames.X5c] = x5cValues
                },
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            string compactJar = JwsSerialization.SerializeCompact(signedJar.Message, Encoder);

            //=== Wallet side — both driver implementations exercise the same flow ===

            IReadOnlyList<string> extractedX5c = ExtractX5cFromJarHeader(compactJar);

            //Resolve key via Microsoft driver.
            using PublicKeyMemory microsoftKey = await X509SanDnsKeyResolver.ResolveAsync(
                extractedX5c,
                clientIdWithoutPrefix,
                trustAnchorsMicrosoft,
                TimeProvider.GetUtcNow(),
                MicrosoftX509Functions.ParseX5c,
                MicrosoftX509Functions.ValidateChainAsync,
                MicrosoftX509Functions.VerifyDnsSan,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

            //Resolve key via BouncyCastle driver.
            using PublicKeyMemory bouncyCastleKey = await X509SanDnsKeyResolver.ResolveAsync(
                extractedX5c,
                clientIdWithoutPrefix,
                trustAnchorsBouncyCastle,
                TimeProvider.GetUtcNow(),
                BouncyCastleX509Functions.ParseX5c,
                BouncyCastleX509Functions.ValidateChainAsync,
                BouncyCastleX509Functions.VerifyDnsSan,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

            //Both drivers must extract the same public key bytes.
            Assert.IsTrue(
                microsoftKey.AsReadOnlySpan().SequenceEqual(bouncyCastleKey.AsReadOnlySpan()),
                "Microsoft and BouncyCastle drivers must extract identical public key bytes.");

            Assert.AreEqual(microsoftKey.Tag, bouncyCastleKey.Tag,
                "Microsoft and BouncyCastle drivers must assign identical tags.");

            //Both keys must verify the JAR signature successfully.
            bool validWithMicrosoftKey = await Jws.VerifyAsync(
                compactJar, Decoder,
                static (ReadOnlySpan<byte> _) => (object?)null,
                Pool, microsoftKey, TestContext.CancellationToken).ConfigureAwait(false);

            bool validWithBouncyCastleKey = await Jws.VerifyAsync(
                compactJar, Decoder,
                static (ReadOnlySpan<byte> _) => (object?)null,
                Pool, bouncyCastleKey, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(validWithMicrosoftKey,
                "JAR signature must verify with the key resolved via the Microsoft driver.");
            Assert.IsTrue(validWithBouncyCastleKey,
                "JAR signature must verify with the key resolved via the BouncyCastle driver.");

            //Full end-to-end parse with the Microsoft key.
            AuthorizationRequestObject parsedRequest =
                await JarExtensions.VerifyAndParseJarAsync(
                    compactJar,
                    microsoftKey,
                    Decoder,
                    bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                        bytes, TestSetup.DefaultSerializationOptions)!,
                    bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                        bytes, TestSetup.DefaultSerializationOptions)!,
                    json => JsonSerializer.Deserialize<DcqlQuery>(
                        json, TestSetup.DefaultSerializationOptions)!,
                    json => JsonSerializer.Deserialize<VerifierClientMetadata>(
                        json, TestSetup.DefaultSerializationOptions)!,
                    StateParameterPolicy.Required,
                    Pool,
                    TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(clientIdWithPrefix, parsedRequest.ClientId,
                "Parsed client_id must include the x509_san_dns: prefix.");
            Assert.AreEqual(WellKnownResponseModes.DirectPostJwt, parsedRequest.ResponseMode);
            Assert.IsNotNull(parsedRequest.DcqlQuery);
        }
        finally
        {
            foreach(PkiCertificateMemory anchor in trustAnchorsMicrosoft)
            {
                anchor.Dispose();
            }

            foreach(PkiCertificateMemory anchor in trustAnchorsBouncyCastle)
            {
                anchor.Dispose();
            }
        }
    }


    //Cross-check: both drivers must produce equivalent results on the same chain.
    //MicrosoftX509Functions uses the BCL OS-backed X509Chain.
    //BouncyCastleX509Functions uses BouncyCastle's pure-managed PKIX implementation.
    //If both accept the chain and produce a key that verifies the same JAR signature,
    //the implementations are consistent.

    [TestMethod]
    public async Task X509SanDnsBothDriversProduceEquivalentResults()
    {
        using CertificateChainMaterial chain =
            TestCertificateChainProvider.CreateP256ChainMaterial(TimeProvider);

        string clientIdWithPrefix =
            $"{WellKnownClientIdPrefixes.X509SanDns}:{chain.DnsName}";
        string clientIdWithoutPrefix =
            WellKnownClientIdPrefixes.StripPrefix(clientIdWithPrefix);

        string leafBase64 = Convert.ToBase64String(
            chain.LeafDerBytes.AsReadOnlyMemory().ToArray());
        string caBase64 = Convert.ToBase64String(
            chain.CaDerBytes.AsReadOnlyMemory().ToArray());
        string[] x5cValues = [leafBase64, caBase64];

        IReadOnlyList<PkiCertificateMemory> trustAnchors =
            MicrosoftX509Functions.ParseX5c([caBase64], Pool);

        try
        {
            VerifierClientMetadata clientMetadata =
                HaipProfile.CreateVerifierClientMetadata(clientIdWithPrefix,
                    /*lang=json,strict*/ "{\"keys\":[]}");
            DateTimeOffset now = TimeProvider.GetUtcNow();
            AuthorizationRequestObject requestObject =
                HaipProfile.CreateAuthorizationRequestObject(
                    clientId: clientIdWithPrefix,
                    responseUri: new Uri("https://verifier.example.com/cb"),
                    nonce: "nonce-x509-crosscheck",
                    dcqlQuery: DcqlFixtures.PidGivenAndFamilyName(),
                    clientMetadata: clientMetadata,
                    state: "state-x509-crosscheck",
                    iat: now,
                    nbf: now,
                    exp: now + TimingPolicy.Default.Oid4VpRequestObjectLifetime);

            using SignedJar signedJar = await requestObject.SignJarAsync(
                signingKey: chain.LeafSigningKey,
                headerSerializer: JwtHeaderSerializer,
                payloadSerializer: JwtPayloadSerializer,
                dcqlQuerySerializer: q => JsonSerializer.Serialize(
                    q, TestSetup.DefaultSerializationOptions),
                clientMetadataSerializer: m => JsonSerializer.Serialize(
                    m, TestSetup.DefaultSerializationOptions),
                base64UrlEncoder: Encoder,
                memoryPool: Pool,
                additionalHeaderClaims: new Dictionary<string, object>
                {
                    [WellKnownJwkMemberNames.X5c] = x5cValues
                },
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            string compactJar = JwsSerialization.SerializeCompact(signedJar.Message, Encoder);
            IReadOnlyList<string> extractedX5c = ExtractX5cFromJarHeader(compactJar);
            DateTimeOffset validationTime = TimeProvider.GetUtcNow();

            //Resolve with Microsoft driver.
            using PublicKeyMemory microsoftKey = await X509SanDnsKeyResolver.ResolveAsync(
                extractedX5c,
                clientIdWithoutPrefix,
                trustAnchors,
                validationTime,
                MicrosoftX509Functions.ParseX5c,
                MicrosoftX509Functions.ValidateChainAsync,
                MicrosoftX509Functions.VerifyDnsSan,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

            //Resolve with BouncyCastle driver.
            using PublicKeyMemory bouncyCastleKey = await X509SanDnsKeyResolver.ResolveAsync(
                extractedX5c,
                clientIdWithoutPrefix,
                trustAnchors,
                validationTime,
                BouncyCastleX509Functions.ParseX5c,
                BouncyCastleX509Functions.ValidateChainAsync,
                BouncyCastleX509Functions.VerifyDnsSan,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

            //Both keys must verify the same JAR signature.
            bool microsoftVerifies = await Jws.VerifyAsync(
                compactJar, Decoder,
                static (ReadOnlySpan<byte> _) => (object?)null,
                Pool, microsoftKey, TestContext.CancellationToken).ConfigureAwait(false);

            bool bouncyCastleVerifies = await Jws.VerifyAsync(
                compactJar, Decoder,
                static (ReadOnlySpan<byte> _) => (object?)null,
                Pool, bouncyCastleKey, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(microsoftVerifies,
                "Microsoft driver must produce a key that verifies the JAR signature.");
            Assert.IsTrue(bouncyCastleVerifies,
                "BouncyCastle driver must produce a key that verifies the JAR signature.");

            //Both keys must be identical byte-for-byte.
            Assert.IsTrue(
                microsoftKey.AsReadOnlySpan()
                    .SequenceEqual(bouncyCastleKey.AsReadOnlySpan()),
                "Microsoft and BouncyCastle drivers must extract identical public key bytes.");
        }
        finally
        {
            foreach(PkiCertificateMemory anchor in trustAnchors)
            {
                anchor.Dispose();
            }
        }
    }


    private static IReadOnlyList<string> ExtractX5cFromJarHeader(string compactJar)
    {
        using UnverifiedJwsMessage unverified = JwsParsing.ParseCompact(
            compactJar,
            Decoder,
            bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            Pool);

        UnverifiedJwtHeader header = unverified.Signatures[0].ProtectedHeader;

        if(!header.TryGetValue(WellKnownJwkMemberNames.X5c, out object? x5cObj))
        {
            Assert.Fail("JAR header does not contain an x5c parameter.");
            throw new InvalidOperationException("Unreachable.");
        }

        return x5cObj switch
        {
            IReadOnlyList<string> list => list,
            IEnumerable<object> enumerable => enumerable.OfType<string>().ToList(),
            _ => throw new FormatException(
                $"Unexpected x5c value type: {x5cObj.GetType().Name}")
        };
    }


    private static ValueTask<PublicKeyMemory> ResolveKeyFromAttestationAsync(
        VerifierAttestationJwt attestation,
        string expectedSubject,
        PublicKeyMemory trustAnchorPublicKey,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken) =>
        VerifierAttestationKeyResolver.ResolveAsync(
            attestation,
            expectedSubject,
            trustAnchorPublicKey,
            Decoder,
            bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            pool,
            cancellationToken);


    //decentralized_identifier: prefix (OID4VP 1.0 §5.9.3).
    //
    //The client_id is a DID; the JAR's kid JOSE header carries the absolute DID
    //URL of the verification method that signed it. The Wallet's composite key
    //resolver routes to BuildDecentralizedIdentifierHandler, which uses the
    //configured DidResolver (here registered with KeyDidResolver for did:key)
    //to dereference the kid into a VerificationMethod, then decodes it into a
    //PublicKeyMemory via VerificationMethodCryptoConversions.

    [TestMethod]
    public async Task DecentralizedIdentifierPrefixJarVerifiesWithResolvedDidKey()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();

        //Verifier's signing key — a fresh P-256 keypair that becomes the did:key
        //identifier. The public side encodes into the DID multibase suffix.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> verifierKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory verifierPublicKey = verifierKeys.PublicKey;
        using PrivateKeyMemory verifierPrivateKey = verifierKeys.PrivateKey;

        //Synthesize the Verifier's did:key DID document to read out the canonical
        //did:key identifier and the verification-method DID URL. The same
        //KeyDidBuilder runs inside KeyDidResolver at resolution time.
        Verifiable.Core.Model.Did.DidDocument verifierDocument =
            await new Verifiable.Core.Model.Did.KeyDidBuilder().BuildAsync(
                verifierPublicKey,
                Verifiable.Core.Model.Did.CryptographicSuites.MultikeyVerificationMethodTypeInfo.Instance,
                includeDefaultContext: false,
                TestContext.CancellationToken).ConfigureAwait(false);

        string didKeyId = verifierDocument.Id!.ToString()!;
        string verificationMethodId = verifierDocument.VerificationMethod![0].Id!;
        string clientIdWithPrefix =
            $"{WellKnownClientIdPrefixes.DecentralizedIdentifier}:{didKeyId}";


        //Build the JAR. client_id carries the prefixed DID; the kid JOSE header
        //carries the absolute verification-method DID URL.
        VerifierClientMetadata clientMetadata =
            HaipProfile.CreateVerifierClientMetadata(clientIdWithPrefix,
                /*lang=json,strict*/ "{\"keys\":[]}");

        AuthorizationRequestObject requestObject =
            HaipProfile.CreateAuthorizationRequestObject(
                clientId: clientIdWithPrefix,
                responseUri: new Uri("https://verifier.example.com/cb"),
                nonce: "nonce-did-01",
                dcqlQuery: DcqlFixtures.PidGivenAndFamilyName(),
                clientMetadata: clientMetadata,
                state: "state-did-01",
                iat: now,
                nbf: now,
                exp: now + TimingPolicy.Default.Oid4VpRequestObjectLifetime);

        using SignedJar signedJar = await requestObject.SignJarAsync(
            signingKey: verifierPrivateKey,
            headerSerializer: JwtHeaderSerializer,
            payloadSerializer: JwtPayloadSerializer,
            dcqlQuerySerializer: q => JsonSerializer.Serialize(q, TestSetup.DefaultSerializationOptions),
            clientMetadataSerializer: m => JsonSerializer.Serialize(m, TestSetup.DefaultSerializationOptions),
            base64UrlEncoder: Encoder,
            memoryPool: Pool,
            additionalHeaderClaims: new Dictionary<string, object>
            {
                [WellKnownJwkMemberNames.Kid] = verificationMethodId,
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = JwsSerialization.SerializeCompact(signedJar.Message, Encoder);


        //=== Wallet side ===

        //Step 1: Build a DidResolver with KeyDidResolver registered for did:key.
        //In a production deployment this would also include WebDidResolver,
        //CheqdDidResolver, etc. for the methods the wallet supports.
        Verifiable.Core.Resolvers.DidResolver didResolver = new(
            Verifiable.Core.Resolvers.DidMethodSelectors.FromResolvers(
                (Verifiable.Core.Model.Did.Methods.WellKnownDidMethodPrefixes.KeyDidMethodPrefix,
                 Verifiable.Core.Resolvers.KeyDidResolver.Build(Pool))));

        //Step 2: Compose the wallet's signing-key resolver slot with handlers
        //for every prefix the deployment supports. Here only the
        //decentralized_identifier: handler is needed.
        ResolveClientIdSigningKeyAsyncDelegate composite =
            CompositeClientIdSigningKeyResolver.Build(
                new Dictionary<ClientIdPrefix, ResolveClientIdSigningKeyAsyncDelegate>
                {
                    [WellKnownClientIdPrefixes.DecentralizedIdentifier] =
                        CompositeClientIdSigningKeyResolver.BuildDecentralizedIdentifierHandler(
                            didResolver, Pool)
                });

        //Step 3: parse the JAR header so the resolver receives the same shape
        //the production wallet would see.
        using UnverifiedJwsMessage unverifiedJar = JwsParsing.ParseCompact(
            compactJar,
            Decoder,
            bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            Pool);
        UnverifiedJwtHeader jarHeader = unverifiedJar.Signatures[0].ProtectedHeader;

        //Step 4: resolve via the composite. Internally:
        //   composite dispatches by prefix → decentralized_identifier handler
        //     → didResolver.DereferenceAsync(kid) → KeyDidResolver synthesises
        //       a DidDocument → fragment-match selects the verification method
        //     → VerificationMethodCryptoConversions decodes to PublicKeyMemory.
        ExchangeContext didContext = new();
        didContext.SetValidationTime(now);
        using PublicKeyMemory resolvedKey = await composite(
            didContext,
            clientIdWithPrefix,
            jarHeader,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Step 5: verify the JAR signature with the resolved key — the round
        //trip that demonstrates the full decentralized_identifier: path works.
        AuthorizationRequestObject parsedRequest = await JarExtensions.VerifyAndParseJarAsync(
            compactJar,
            resolvedKey,
            Decoder,
            bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            json => JsonSerializer.Deserialize<DcqlQuery>(json, TestSetup.DefaultSerializationOptions)!,
            json => JsonSerializer.Deserialize<VerifierClientMetadata>(json, TestSetup.DefaultSerializationOptions)!,
            StateParameterPolicy.Required,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(clientIdWithPrefix, parsedRequest.ClientId,
            "Parsed client_id must include the decentralized_identifier: prefix.");
        Assert.AreEqual(WellKnownResponseModes.DirectPostJwt, parsedRequest.ResponseMode);
        Assert.IsNotNull(parsedRequest.DcqlQuery);
    }


    //openid_federation: prefix (OID4VP 1.0 §5.9.3).
    //
    //The Verifier publishes its identity through a Federation 1.0 trust chain whose
    //subject Entity Configuration carries the Verifier's JAR signing key in jwks. The
    //chain is presented inline via the trust_chain JOSE header parameter
    //(Federation 1.0 §4.3). The Wallet validates the chain to a configured anchor,
    //extracts the Verifier's signing key from the leaf EC, and verifies the JAR
    //signature. Per OID4VP §5.9.3, client_metadata MUST be ignored when this prefix
    //is used; final Verifier metadata comes from the resolved chain's effective
    //metadata.
    //
    //Trust model:
    //
    //  Trust Anchor               Verifier                    Wallet
    //      |                         |                           |
    //      | Signs SS about verifier |                           |
    //      |------------------------>|                           |
    //      |                         | EC (jwks = signing key)   |
    //      |                         |                           |
    //      |                         | JAR (trust_chain header = |
    //      |                         |  [verifier EC, SS, anchor EC]) |
    //      |                         |-------------------------->|
    //      |                         |                           |
    //      |<--- Wallet has anchor in allow-list ----------------|
    //      |                         | Wallet:                   |
    //      |                         |  1. trust chain parses    |
    //      |                         |  2. per-link sigs verify  |
    //      |                         |  3. TrustChainValidator   |
    //      |                         |     accepts under anchor  |
    //      |                         |  4. extract verifier key  |
    //      |                         |     from chain[0] jwks    |
    //      |                         |  5. JAR.sig OK with key   |

    [TestMethod]
    public async Task OpenIdFederationPrefixJarVerifiesWithTrustChain()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();

        //Build a 3-node trust chain: Verifier EC → anchor's SS about Verifier → anchor EC.
        //The Verifier's signing key is the one whose private side will sign the JAR;
        //its public side is published in the Verifier EC's jwks.
        using Tests.Federation.FederationTestRingNode verifierNode =
            Tests.Federation.FederationTestRing.CreateNode(new EntityIdentifier(VerifierClientId));
        using Tests.Federation.FederationTestRingNode anchorNode =
            Tests.Federation.FederationTestRing.CreateNode(
                new EntityIdentifier("https://anchor.example.com"));

        Tests.Federation.MintedChain mintedChain =
            await Tests.Federation.FederationTestRing.BuildDirectChainAsync(
                verifierNode, anchorNode, now, now.AddHours(1),
                TestContext.CancellationToken).ConfigureAwait(false);

        //Build the JAR with the openid_federation: prefix and the chain inline in the
        //trust_chain header parameter. The verifier's signing key is reconstructed
        //into a PrivateKeyMemory so SignJarAsync can use it. Per OID4VP §5.9.3 the
        //client_metadata MUST be ignored — we still send it for shape but assert it
        //is bypassed downstream.
        string clientIdWithPrefix =
            $"{WellKnownClientIdPrefixes.OpenIdFederation}:{VerifierClientId}";

        System.Security.Cryptography.ECParameters ecParameters =
            verifierNode.SigningKey.ExportParameters(includePrivateParameters: true);
        IMemoryOwner<byte> verifierPrivateOwner = Pool.Rent(ecParameters.D!.Length);
        ecParameters.D.CopyTo(verifierPrivateOwner.Memory.Span);
        using PrivateKeyMemory verifierPrivateKey = new(verifierPrivateOwner, CryptoTags.P256PrivateKey);

        VerifierClientMetadata clientMetadata =
            HaipProfile.CreateVerifierClientMetadata(clientIdWithPrefix,
                /*lang=json,strict*/ "{\"keys\":[]}");

        AuthorizationRequestObject requestObject =
            HaipProfile.CreateAuthorizationRequestObject(
                clientId: clientIdWithPrefix,
                responseUri: new Uri("https://verifier.example.com/cb"),
                nonce: "nonce-fed-01",
                dcqlQuery: DcqlFixtures.PidGivenAndFamilyName(),
                clientMetadata: clientMetadata,
                state: "state-fed-01",
                iat: now,
                nbf: now,
                exp: now + TimingPolicy.Default.Oid4VpRequestObjectLifetime);

        //trust_chain header is a JSON array of compact JWS strings, positionally
        //aligned with chain.Statements (subject → anchor).
        List<object> trustChainHeader = [.. mintedChain.CompactJwsByPosition];

        using SignedJar signedJar = await requestObject.SignJarAsync(
            signingKey: verifierPrivateKey,
            headerSerializer: JwtHeaderSerializer,
            payloadSerializer: JwtPayloadSerializer,
            dcqlQuerySerializer: q => JsonSerializer.Serialize(q, TestSetup.DefaultSerializationOptions),
            clientMetadataSerializer: m => JsonSerializer.Serialize(m, TestSetup.DefaultSerializationOptions),
            base64UrlEncoder: Encoder,
            memoryPool: Pool,
            additionalHeaderClaims: new Dictionary<string, object>
            {
                [WellKnownFederationClaimNames.TrustChain] = trustChainHeader,
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = JwsSerialization.SerializeCompact(signedJar.Message, Encoder);


        //=== Wallet side ===

        //Step 1: parse the JAR header only and pull out the trust_chain JOSE parameter.
        using UnverifiedJwsMessage unverifiedJar = JwsParsing.ParseCompact(
            compactJar,
            Decoder,
            bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            Pool);
        UnverifiedJwtHeader jarHeader = unverifiedJar.Signatures[0].ProtectedHeader;

        Assert.IsTrue(jarHeader.TryGetValue(WellKnownFederationClaimNames.TrustChain, out object? chainObj),
            "JAR header must carry trust_chain when the openid_federation: prefix is used.");
        List<string> chainValues = [];
        foreach(object entry in (IEnumerable<object>)chainObj!)
        {
            chainValues.Add((string)entry);
        }

        //Step 2: resolve the JAR signing key via the new one-call API. The driver
        //walks the chain (parse, per-link sig verify, TrustChainValidator), confirms
        //chain[0].sub matches the expected subject, and extracts the signing key
        //from chain[0]'s jwks.
        ValidateTrustChainAsyncDelegate validateChain =
            Tests.Federation.InlineTrustChainValidationDriver.Build(
                async (position, compactJws, ct) => position switch
                {
                    0 => await Tests.Federation.FederationTestRing.VerifyAsync(verifierNode, compactJws, ct).ConfigureAwait(false),
                    _ => await Tests.Federation.FederationTestRing.VerifyAsync(anchorNode, compactJws, ct).ConfigureAwait(false),
                });

        using PublicKeyMemory resolvedKey = await FederationBoundJarKeyResolver.ResolveAsync(
            chainValues,
            verifierNode.Identifier,
            new[] { anchorNode.Identifier },
            now,
            TimeSpan.FromMinutes(5),
            jarHeader,
            validateChain,
            Decoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Step 3: verify the JAR signature with the resolved key.
        AuthorizationRequestObject parsedRequest = await JarExtensions.VerifyAndParseJarAsync(
            compactJar,
            resolvedKey,
            Decoder,
            bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            json => JsonSerializer.Deserialize<DcqlQuery>(json, TestSetup.DefaultSerializationOptions)!,
            json => JsonSerializer.Deserialize<VerifierClientMetadata>(json, TestSetup.DefaultSerializationOptions)!,
            StateParameterPolicy.Required,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(clientIdWithPrefix, parsedRequest.ClientId,
            "Parsed client_id must include the openid_federation: prefix.");
        Assert.AreEqual(WellKnownResponseModes.DirectPostJwt, parsedRequest.ResponseMode);
        Assert.IsNotNull(parsedRequest.DcqlQuery);
    }
}
