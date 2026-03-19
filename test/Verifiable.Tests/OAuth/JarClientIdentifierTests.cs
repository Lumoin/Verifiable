using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Linq;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Core.Model.Dcql;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp;
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
    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;
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


    //=========================================================================
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
    //=========================================================================

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
                dcqlQuery: BuildPidDcqlQuery(),
                clientMetadata: clientMetadata);

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
                [WellKnownJwkValues.Jwt] = attestationCompactJwt
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
                dcqlQuery: BuildPidDcqlQuery(),
                clientMetadata: clientMetadata);

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
                [WellKnownJwkValues.Jwt] = attestationCompactJwt
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


    //=========================================================================
    //x509_san_dns: prefix (OID4VP 1.0 §5.9.3, HAIP 1.0 mandatory).
    //Pending: requires general-purpose X.509 chain validation infrastructure.
    //The infrastructure will be shared with TPM EK/AK chain validation and
    //SD-JWT VC issuer certificate validation.
    //=========================================================================

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
    //=========================================================================

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
            AuthorizationRequestObject requestObject =
                HaipProfile.CreateAuthorizationRequestObject(
                    clientId: clientIdWithPrefix,
                    responseUri: new Uri("https://verifier.example.com/cb"),
                    nonce: "nonce-x509-01",
                    dcqlQuery: BuildPidDcqlQuery(),
                    clientMetadata: clientMetadata);

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
                    [WellKnownJwkValues.X5c] = x5cValues
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
                MicrosoftX509Functions.ValidateChain,
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
                BouncyCastleX509Functions.ValidateChain,
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
                Pool, microsoftKey).ConfigureAwait(false);

            bool validWithBouncyCastleKey = await Jws.VerifyAsync(
                compactJar, Decoder,
                static (ReadOnlySpan<byte> _) => (object?)null,
                Pool, bouncyCastleKey).ConfigureAwait(false);

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
            AuthorizationRequestObject requestObject =
                HaipProfile.CreateAuthorizationRequestObject(
                    clientId: clientIdWithPrefix,
                    responseUri: new Uri("https://verifier.example.com/cb"),
                    nonce: "nonce-x509-crosscheck",
                    dcqlQuery: BuildPidDcqlQuery(),
                    clientMetadata: clientMetadata);

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
                    [WellKnownJwkValues.X5c] = x5cValues
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
                MicrosoftX509Functions.ValidateChain,
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
                BouncyCastleX509Functions.ValidateChain,
                BouncyCastleX509Functions.VerifyDnsSan,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

            //Both keys must verify the same JAR signature.
            bool microsoftVerifies = await Jws.VerifyAsync(
                compactJar, Decoder,
                static (ReadOnlySpan<byte> _) => (object?)null,
                Pool, microsoftKey).ConfigureAwait(false);

            bool bouncyCastleVerifies = await Jws.VerifyAsync(
                compactJar, Decoder,
                static (ReadOnlySpan<byte> _) => (object?)null,
                Pool, bouncyCastleKey).ConfigureAwait(false);

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

        if(!header.TryGetValue(WellKnownJwkValues.X5c, out object? x5cObj))
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
    //Requires DID resolution as a prerequisite — the client_id (minus the prefix) is a DID,
    //the kid JOSE header identifies the verificationMethod, and the public key is fetched
    //from the resolved DID Document. DID resolution is a separate library workstream.

    [TestMethod]
    public void DecentralizedIdentifierPrefixJarVerifiesWithResolvedDidKey()
    {
        Assert.Inconclusive(
            "decentralized_identifier: prefix requires DID resolution infrastructure. " +
            "Implement did:key and did:web resolution first, then wire the resolved " +
            "verification method public key into VerifyAndParseJarAsync.");
    }


    //openid_federation: prefix (OID4VP 1.0 §5.9.3).
    //OpenID Federation is a full protocol in its own right — not just a client identifier
    //prefix. It requires fetching and validating Entity Configurations and Subordinate
    //Statements, walking the trust chain, and applying metadata policy at each hop.
    //It applies across OID4VP, OID4VCI, and other protocols and belongs in its own
    //workstream. The client_metadata parameter MUST be ignored when this prefix is used;
    //final Verifier metadata is obtained from the resolved Trust Chain instead.

    [TestMethod]
    public void OpenIdFederationPrefixJarVerifiesWithTrustChain()
    {
        Assert.Inconclusive(
            "openid_federation: prefix requires OpenID Federation as a standalone " +
            "protocol implementation. Entity Configuration fetching, Subordinate Statement " +
            "validation, trust chain walking, and metadata policy application must all be " +
            "implemented first. This is a separate workstream shared across OID4VP, OID4VCI, " +
            "and other protocols.");
    }


    private static DcqlQuery BuildPidDcqlQuery() =>
        new()
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = "pid",
                    Format = WellKnownMediaTypes.Jwt.DcSdJwt,
                    Claims =
                    [
                        ClaimsQuery.ForPath(["given_name"]),
                        ClaimsQuery.ForPath(["family_name"])
                    ]
                }
            ]
        };
}
