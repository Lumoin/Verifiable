using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth.Federation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Minimal in-memory fixture for OpenID Federation 1.0 inline-path tests.
/// Generates fresh P-256 keys per node, mints signed Entity Statements
/// (both Configurations and Subordinate), and assembles
/// <see cref="TrustChain"/> instances along with the raw compact JWS list
/// expected by the chunk-4 chain validator orchestration.
/// </summary>
/// <remarks>
/// <para>
/// Scope: enough to exercise <see cref="EntityStatementValidator"/> and
/// <see cref="TrustChainValidator"/> against the chunk-3 profiles in the
/// happy-path and clearly-malformed cases. The fixture does NOT support
/// trust marks, federation HTTP fetch, metadata-policy operator
/// combinations, or pre-baked failure topologies — chunk 9's property
/// tests build failure cases by tweaking parameters (negative iat,
/// wrong sub, missing jwks) or by constructing
/// <see cref="TrustChain"/> instances directly.
/// </para>
/// <para>
/// Algorithm: ES256 only. Key material is in-process only and lives
/// for the fixture's lifetime; <see cref="FederationTestRingNode"/>
/// implements <see cref="IDisposable"/> for the underlying <see cref="ECDsa"/>.
/// </para>
/// </remarks>
internal static class FederationTestRing
{
    private const string AlgorithmName = "ES256";


    /// <summary>
    /// Creates a fresh node with a newly-generated P-256 keypair.
    /// </summary>
    public static FederationTestRingNode CreateNode(EntityIdentifier identifier)
    {
        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string kid = $"kid-{Guid.NewGuid():N}";
        return new FederationTestRingNode(identifier, key, kid);
    }


    /// <summary>
    /// Creates a node whose internal ECDsa is constructed from the supplied
    /// P-256 private key bytes. The resulting node's <c>JwksObject</c>
    /// publishes the public side derived from that scalar — so a chain
    /// minted from this node leaks the same JAR-signing public key the
    /// caller will register with an <see cref="OAuth.Server.AuthorizationServer"/>.
    /// </summary>
    /// <remarks>
    /// Use this when a federation chain must publish the verifier's JAR
    /// signing key in <c>chain[0].jwks</c> so the wallet's chain-validation
    /// resolver yields the same public key the server's AS used to sign the
    /// JAR. <see cref="PrivateKeyMemory"/> stays the API surface;
    /// <see cref="ECDsa"/> remains an implementation detail internal to the
    /// federation ring fixture.
    /// </remarks>
    public static FederationTestRingNode CreateNodeFromKey(
        EntityIdentifier identifier,
        PrivateKeyMemory privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);

        ECParameters parameters = new()
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = privateKey.AsReadOnlySpan().ToArray()
        };
        ECDsa key = ECDsa.Create(parameters);
        string kid = $"kid-{Guid.NewGuid():N}";

        return new FederationTestRingNode(identifier, key, kid);
    }


    /// <summary>
    /// Mints an Entity Configuration (self-issued) signed by
    /// <paramref name="node"/>. Returns the parsed
    /// <see cref="EntityStatement"/>, the unverified header (for feeding
    /// into the chunk-3 context), and the compact JWS string (for
    /// signature verification by the orchestrator).
    /// </summary>
    public static async ValueTask<MintedStatement> MintEntityConfigurationAsync(
        FederationTestRingNode node,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        IReadOnlyDictionary<string, object>? extraClaims = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(node);

        Dictionary<string, object> payload = BuildPayloadCore(
            issuer: node.Identifier.Value,
            subject: node.Identifier.Value,
            issuedAt: issuedAt,
            expiresAt: expiresAt);
        payload[WellKnownFederationClaimNames.Jwks] = node.JwksObject;
        MergeExtras(payload, extraClaims);

        return await MintInternalAsync(node, payload, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Mints a Subordinate Statement (issuer-signed about subject).
    /// </summary>
    public static async ValueTask<MintedStatement> MintSubordinateStatementAsync(
        FederationTestRingNode issuer,
        FederationTestRingNode subject,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        IReadOnlyDictionary<string, object>? extraClaims = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(subject);

        Dictionary<string, object> payload = BuildPayloadCore(
            issuer: issuer.Identifier.Value,
            subject: subject.Identifier.Value,
            issuedAt: issuedAt,
            expiresAt: expiresAt);
        //Subordinate Statements carry the subject's jwks per §3.1.
        payload[WellKnownFederationClaimNames.Jwks] = subject.JwksObject;
        MergeExtras(payload, extraClaims);

        return await MintInternalAsync(issuer, payload, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds a three-node trust chain: subject → trust anchor (no
    /// intermediates). The chain consists of:
    /// </summary>
    /// <list type="number">
    ///   <item><description>The subject's Entity Configuration at position 0.</description></item>
    ///   <item><description>The anchor's Subordinate Statement about the subject at position 1.</description></item>
    ///   <item><description>The anchor's Entity Configuration at position 2.</description></item>
    /// </list>
    public static async ValueTask<MintedChain> BuildDirectChainAsync(
        FederationTestRingNode subject,
        FederationTestRingNode anchor,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        MintedStatement subjectEc = await MintEntityConfigurationAsync(
            subject, issuedAt, expiresAt, cancellationToken: cancellationToken).ConfigureAwait(false);
        MintedStatement anchorAboutSubject = await MintSubordinateStatementAsync(
            anchor, subject, issuedAt, expiresAt, cancellationToken: cancellationToken).ConfigureAwait(false);
        MintedStatement anchorEc = await MintEntityConfigurationAsync(
            anchor, issuedAt, expiresAt, cancellationToken: cancellationToken).ConfigureAwait(false);

        TrustChain chain = new()
        {
            Statements = [subjectEc.Statement, anchorAboutSubject.Statement, anchorEc.Statement]
        };

        return new MintedChain(
            chain,
            [subjectEc.CompactJws, anchorAboutSubject.CompactJws, anchorEc.CompactJws],
            [subjectEc.Header, anchorAboutSubject.Header, anchorEc.Header]);
    }


    /// <summary>
    /// Builds a four-hop trust chain with one intermediate:
    /// subject → intermediate → trust anchor. The chain consists of five
    /// elements in leaf → anchor order:
    /// </summary>
    /// <list type="number">
    ///   <item><description>The subject's Entity Configuration (position 0, subject-signed).</description></item>
    ///   <item><description>The intermediate's Subordinate Statement about the subject (position 1, intermediate-signed).</description></item>
    ///   <item><description>The intermediate's Entity Configuration (position 2, intermediate-signed).</description></item>
    ///   <item><description>The anchor's Subordinate Statement about the intermediate (position 3, anchor-signed).</description></item>
    ///   <item><description>The anchor's Entity Configuration (position 4, anchor-signed).</description></item>
    /// </list>
    /// <remarks>
    /// Mirrors the wire shape the multi-host
    /// <c>FederationChainPropertyTests</c> rig fetches, but assembled
    /// in-process for tests that need a chain WITH stacked
    /// <c>metadata_policy</c> (the intermediate and the anchor each carry
    /// policy) without standing up three Kestrel listeners. The optional
    /// extra-claim bags inject the subject's declared metadata and the two
    /// Subordinate Statements' <c>metadata_policy</c> blocks. Per-link
    /// signature verification dispatches by position 0 → subject,
    /// 1|2 → intermediate, 3|4 → anchor.
    /// </remarks>
    public static async ValueTask<MintedChain> BuildChainWithIntermediateAsync(
        FederationTestRingNode subject,
        FederationTestRingNode intermediate,
        FederationTestRingNode anchor,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        IReadOnlyDictionary<string, object>? subjectExtraClaims = null,
        IReadOnlyDictionary<string, object>? intermediateAboutSubjectExtraClaims = null,
        IReadOnlyDictionary<string, object>? anchorAboutIntermediateExtraClaims = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(intermediate);
        ArgumentNullException.ThrowIfNull(anchor);

        MintedStatement subjectEc = await MintEntityConfigurationAsync(
            subject, issuedAt, expiresAt, subjectExtraClaims, cancellationToken).ConfigureAwait(false);
        MintedStatement intermediateAboutSubject = await MintSubordinateStatementAsync(
            intermediate, subject, issuedAt, expiresAt, intermediateAboutSubjectExtraClaims, cancellationToken).ConfigureAwait(false);
        MintedStatement intermediateEc = await MintEntityConfigurationAsync(
            intermediate, issuedAt, expiresAt, cancellationToken: cancellationToken).ConfigureAwait(false);
        MintedStatement anchorAboutIntermediate = await MintSubordinateStatementAsync(
            anchor, intermediate, issuedAt, expiresAt, anchorAboutIntermediateExtraClaims, cancellationToken).ConfigureAwait(false);
        MintedStatement anchorEc = await MintEntityConfigurationAsync(
            anchor, issuedAt, expiresAt, cancellationToken: cancellationToken).ConfigureAwait(false);

        TrustChain chain = new()
        {
            Statements =
            [
                subjectEc.Statement,
                intermediateAboutSubject.Statement,
                intermediateEc.Statement,
                anchorAboutIntermediate.Statement,
                anchorEc.Statement
            ]
        };

        return new MintedChain(
            chain,
            [
                subjectEc.CompactJws,
                intermediateAboutSubject.CompactJws,
                intermediateEc.CompactJws,
                anchorAboutIntermediate.CompactJws,
                anchorEc.CompactJws
            ],
            [
                subjectEc.Header,
                intermediateAboutSubject.Header,
                intermediateEc.Header,
                anchorAboutIntermediate.Header,
                anchorEc.Header
            ]);
    }


    /// <summary>
    /// Verifies a single compact JWS produced by the ring against the
    /// signer's public key. Returns <see langword="true"/> when the
    /// signature verifies. Test code uses this to populate
    /// <see cref="TrustChainValidationContext.LinkSignaturesVerified"/>
    /// without going through a full key-resolution delegate.
    /// </summary>
    public static async ValueTask<bool> VerifyAsync(
        FederationTestRingNode signer,
        string compactJws,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentException.ThrowIfNullOrEmpty(compactJws);

        byte[] publicKeyBytes = signer.SigningKey.ExportSubjectPublicKeyInfo();
        using PublicKeyMemory publicKey = CreatePublicKeyMemory(publicKeyBytes, CryptoTags.P256PublicKey);

        VerificationDelegate verificationDelegate = (dataToVerify, signature, publicKeyBytesArg, _, _) =>
        {
            using ECDsa ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(publicKeyBytesArg.Span, out _);
            return ValueTask.FromResult(ecdsa.VerifyData(dataToVerify.Span, signature.Span, HashAlgorithmName.SHA256));
        };

        return await Jws.VerifyAsync(
            compactJws,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            BaseMemoryPool.Shared,
            publicKey,
            verificationDelegate,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Mints a signed Trust Mark JWT per Federation §7.1. Returns the
    /// parsed mark, the unverified header, and the raw compact JWS.
    /// </summary>
    public static async ValueTask<MintedTrustMark> MintTrustMarkAsync(
        FederationTestRingNode issuer,
        FederationTestRingNode subject,
        string markId,
        DateTimeOffset issuedAt,
        DateTimeOffset? expiresAt = null,
        IReadOnlyDictionary<string, object>? extraClaims = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentException.ThrowIfNullOrEmpty(markId);

        Dictionary<string, object> headerDict = new(StringComparer.Ordinal)
        {
            [WellKnownJoseHeaderNames.Typ] = WellKnownFederationMediaTypes.TrustMarkJwt,
            [WellKnownJwkMemberNames.Alg] = AlgorithmName,
            [WellKnownJwkMemberNames.Kid] = issuer.Kid,
        };

        Dictionary<string, object> payloadDict = new(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Iss] = issuer.Identifier.Value,
            [WellKnownJwtClaimNames.Sub] = subject.Identifier.Value,
            [WellKnownJwtClaimNames.Iat] = issuedAt.ToUnixTimeSeconds(),
            [WellKnownFederationClaimNames.TrustMarkType] = markId,
        };
        if(expiresAt is { } exp)
        {
            payloadDict[WellKnownJwtClaimNames.Exp] = exp.ToUnixTimeSeconds();
        }
        MergeExtras(payloadDict, extraClaims);

        (UnverifiedJwtHeader header, UnverifiedJwtPayload payload, string compactJws) =
            await SignAsync(issuer, headerDict, payloadDict, cancellationToken).ConfigureAwait(false);

        TrustMarkParseResult parseResult = TrustMarkParser.Parse(header, payload);
        if(parseResult.Mark is null)
        {
            throw new InvalidOperationException(
                $"FederationTestRing produced a trust mark the parser rejected: {parseResult.FailureReason}");
        }

        return new MintedTrustMark(parseResult.Mark, header, compactJws);
    }


    /// <summary>
    /// Mints a signed Trust Mark Delegation JWT per Federation §7.2.2.
    /// </summary>
    public static async ValueTask<MintedTrustMarkDelegation> MintTrustMarkDelegationAsync(
        FederationTestRingNode owner,
        FederationTestRingNode issuer,
        string markId,
        DateTimeOffset issuedAt,
        DateTimeOffset? expiresAt = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentException.ThrowIfNullOrEmpty(markId);

        Dictionary<string, object> headerDict = new(StringComparer.Ordinal)
        {
            [WellKnownJoseHeaderNames.Typ] = WellKnownFederationMediaTypes.TrustMarkDelegationJwt,
            [WellKnownJwkMemberNames.Alg] = AlgorithmName,
            [WellKnownJwkMemberNames.Kid] = owner.Kid,
        };

        Dictionary<string, object> payloadDict = new(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Iss] = owner.Identifier.Value,
            [WellKnownJwtClaimNames.Sub] = issuer.Identifier.Value,
            [WellKnownJwtClaimNames.Iat] = issuedAt.ToUnixTimeSeconds(),
            [WellKnownFederationClaimNames.TrustMarkType] = markId,
        };
        if(expiresAt is { } exp)
        {
            payloadDict[WellKnownJwtClaimNames.Exp] = exp.ToUnixTimeSeconds();
        }

        (UnverifiedJwtHeader header, UnverifiedJwtPayload payload, string compactJws) =
            await SignAsync(owner, headerDict, payloadDict, cancellationToken).ConfigureAwait(false);

        TrustMarkDelegationParseResult parseResult = TrustMarkDelegationParser.Parse(header, payload);
        if(parseResult.Delegation is null)
        {
            throw new InvalidOperationException(
                $"FederationTestRing produced a delegation the parser rejected: {parseResult.FailureReason}");
        }

        return new MintedTrustMarkDelegation(parseResult.Delegation, header, compactJws);
    }


    private static async ValueTask<(UnverifiedJwtHeader Header, UnverifiedJwtPayload Payload, string CompactJws)> SignAsync(
        FederationTestRingNode signer,
        Dictionary<string, object> headerDict,
        Dictionary<string, object> payloadDict,
        CancellationToken cancellationToken)
    {
        ECParameters parameters = signer.SigningKey.ExportParameters(includePrivateParameters: true);
        using PrivateKeyMemory privateKey = CreatePrivateKeyMemory(parameters.D!, CryptoTags.P256PrivateKey);

        SigningDelegate signingDelegate = (privateKeyBytes, dataToSign, signaturePool, _, _) =>
        {
            using ECDsa ecdsa = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, D = privateKeyBytes.ToArray() });
            byte[] signatureBytes = ecdsa.SignData(dataToSign.Span, HashAlgorithmName.SHA256);
            IMemoryOwner<byte> memoryOwner = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryOwner.Memory.Span);
            return ValueTask.FromResult(new Signature(memoryOwner, CryptoTags.P256Signature));
        };

        JwsMessage jwsMessage = await Jws.SignAsync(
            headerDict,
            payloadDict,
            EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            signingDelegate,
            BaseMemoryPool.Shared,
            cancellationToken).ConfigureAwait(false);

        string compactJws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);
        UnverifiedJwtHeader header = new(headerDict);
        UnverifiedJwtPayload payload = new(payloadDict);
        return (header, payload, compactJws);
    }


    private static async ValueTask<MintedStatement> MintInternalAsync(
        FederationTestRingNode signer,
        Dictionary<string, object> payloadDict,
        CancellationToken cancellationToken)
    {
        Dictionary<string, object> headerDict = new(StringComparer.Ordinal)
        {
            [WellKnownJoseHeaderNames.Typ] = WellKnownFederationMediaTypes.EntityStatementJwt,
            [WellKnownJwkMemberNames.Alg] = AlgorithmName,
            [WellKnownJwkMemberNames.Kid] = signer.Kid,
        };

        ECParameters parameters = signer.SigningKey.ExportParameters(includePrivateParameters: true);
        using PrivateKeyMemory privateKey = CreatePrivateKeyMemory(parameters.D!, CryptoTags.P256PrivateKey);

        SigningDelegate signingDelegate = (privateKeyBytes, dataToSign, signaturePool, _, _) =>
        {
            using ECDsa ecdsa = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, D = privateKeyBytes.ToArray() });
            byte[] signatureBytes = ecdsa.SignData(dataToSign.Span, HashAlgorithmName.SHA256);
            IMemoryOwner<byte> memoryOwner = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryOwner.Memory.Span);
            return ValueTask.FromResult(new Signature(memoryOwner, CryptoTags.P256Signature));
        };

        JwsMessage jwsMessage = await Jws.SignAsync(
            headerDict,
            payloadDict,
            EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            signingDelegate,
            BaseMemoryPool.Shared,
            cancellationToken).ConfigureAwait(false);

        string compactJws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        UnverifiedJwtHeader header = new(headerDict);
        UnverifiedJwtPayload payload = new(payloadDict);
        EntityStatementParseResult parseResult = EntityStatementParser.Parse(header, payload);
        if(parseResult.Statement is null)
        {
            throw new InvalidOperationException(
                $"FederationTestRing produced a statement the parser rejected: {parseResult.FailureReason}");
        }

        return new MintedStatement(parseResult.Statement, header, compactJws);
    }


    private static Dictionary<string, object> BuildPayloadCore(
        string issuer,
        string subject,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt)
    {
        return new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Iss] = issuer,
            [WellKnownJwtClaimNames.Sub] = subject,
            [WellKnownJwtClaimNames.Iat] = issuedAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = expiresAt.ToUnixTimeSeconds(),
        };
    }


    private static void MergeExtras(
        Dictionary<string, object> target,
        IReadOnlyDictionary<string, object>? extras)
    {
        if(extras is null)
        {
            return;
        }

        foreach(KeyValuePair<string, object> kvp in extras)
        {
            target[kvp.Key] = kvp.Value;
        }
    }


    private static TaggedMemory<byte> EncodeJwtPart(Dictionary<string, object> part)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(
            JsonSerializerExtensions.Serialize(part, TestSetup.DefaultSerializationOptions));
        return new TaggedMemory<byte>(bytes, BufferTags.Json);
    }


    private static Dictionary<string, object> DecodeJwtPart(ReadOnlySpan<byte> bytes)
    {
        string json = Encoding.UTF8.GetString(bytes);
        return JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            json, TestSetup.DefaultSerializationOptions)!;
    }


    private static PrivateKeyMemory CreatePrivateKeyMemory(byte[] bytes, Tag tag)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);
        return new PrivateKeyMemory(owner, tag);
    }


    private static PublicKeyMemory CreatePublicKeyMemory(byte[] bytes, Tag tag)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);
        return new PublicKeyMemory(owner, tag);
    }
}
