using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared fixtures for the CTAP wave-2 <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c>
/// test suites: simulator composition, request-model construction, and the "register a credential first"
/// setup step every <c>authenticatorGetAssertion</c> test needs — factored once here rather than
/// reimplemented per test category.
/// </summary>
internal static class CtapWave2AuthenticatorFixtures
{
    /// <summary>The relying party identifier every fixture defaults to.</summary>
    public const string DefaultRpId = "example.com";

    /// <summary>The credential's default COSE algorithm — the one algorithm <see cref="CtapCredentialSigningBackend.CreateEs256Default"/> supports.</summary>
    public const int DefaultAlgorithm = WellKnownCoseAlgorithms.Es256;


    /// <summary>Builds a byte array of <paramref name="length"/> with a fixed, distinguishable pattern seeded by <paramref name="seed"/>.</summary>
    public static byte[] BuildFixedBytes(int length, byte seed)
    {
        byte[] bytes = new byte[length];
        for(int i = 0; i < length; i++)
        {
            bytes[i] = (byte)(seed + i);
        }

        return bytes;
    }


    /// <summary>Builds a 32-byte fixed-pattern <c>clientDataHash</c> carrier: rents from <paramref name="pool"/>, copies the fixed pattern, and returns the carrier immediately so ownership transfer is unambiguous to static analysis.</summary>
    private static DigestValue BuildFixedClientDataHash(byte seed, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(32);
        BuildFixedBytes(32, seed).AsSpan().CopyTo(owner.Memory.Span);

        return new DigestValue(owner, CryptoTags.Sha256Digest);
    }


    /// <summary>
    /// Builds a simulator wired with the shipped CBOR codecs, defaulting to the ES256-only credential
    /// backend and <paramref name="residentCredentialCapacity"/> resident credential slots.
    /// </summary>
    /// <param name="aaguid">
    /// The authenticator-wide AAGUID, or <see langword="null"/> (the default) to draw one from the
    /// simulator's own entropy source. A PKG-D real-wire capstone supplies an explicit value so a
    /// provisioning fixture's leaf certificate (waveep R14's <c>id-fido-gen-ce-aaguid</c> extension) can
    /// be minted with the SAME value BEFORE the simulator itself is constructed — the certificate and
    /// the simulator's own credential-minting AAGUID must agree for the RP-side cross-check to pass.
    /// </param>
    public static CtapAuthenticatorSimulator CreateSimulator(
        string runId, FillEntropyDelegate? rng = null, int residentCredentialCapacity = 8, TimeProvider? timeProvider = null,
        SimulateFingerprintCaptureDelegate? simulateFingerprintCapture = null, SimulateBuiltInUvDelegate? simulateBuiltInUv = null,
        CtapEnterpriseAttestationProvisioning? enterpriseAttestationProvisioning = null, Guid? aaguid = null) =>
        CreateSimulatorWithBackend(
            runId, CtapCredentialSigningBackend.CreateEs256Default(), rng, residentCredentialCapacity, timeProvider, simulateFingerprintCapture, simulateBuiltInUv,
            enterpriseAttestationProvisioning, aaguid);


    /// <summary>
    /// Builds a simulator wired with the shipped CBOR codecs and exactly <paramref name="backend"/> — unlike
    /// <see cref="CreateSimulator"/>, a <see langword="null"/> <paramref name="backend"/> here genuinely models
    /// no credential-signing backend injected at all, rather than falling back to the ES256 default. The
    /// certified-attestation encode seam (<see cref="PackedAttestationStatementCborWriter.WriteCertified"/>,
    /// waveep R7) is ALWAYS wired, regardless of whether <paramref name="enterpriseAttestationProvisioning"/>
    /// is supplied — mc Step 9 can never resolve the certified format choice without provisioning
    /// material, so wiring the seam unconditionally is harmless for every non-capable-authenticator test.
    /// </summary>
    /// <param name="aaguid">The authenticator-wide AAGUID — see <see cref="CreateSimulator"/>.</param>
    public static CtapAuthenticatorSimulator CreateSimulatorWithBackend(
        string runId,
        CtapCredentialSigningBackend? backend,
        FillEntropyDelegate? rng = null,
        int residentCredentialCapacity = 8,
        TimeProvider? timeProvider = null,
        SimulateFingerprintCaptureDelegate? simulateFingerprintCapture = null,
        SimulateBuiltInUvDelegate? simulateBuiltInUv = null,
        CtapEnterpriseAttestationProvisioning? enterpriseAttestationProvisioning = null,
        Guid? aaguid = null) =>
        new(
            runId,
            CtapGetInfoResponseCborWriter.Write,
            CtapMakeCredentialRequestCborReader.Read,
            CtapMakeCredentialResponseCborWriter.Write,
            CtapGetAssertionRequestCborReader.Read,
            CtapGetAssertionResponseCborWriter.Write,
            CredentialPublicKeyCborWriter.Write,
            PackedAttestationStatementCborWriter.Write,
            decodeClientPinRequest: CtapClientPinRequestCborReader.Read,
            encodeClientPinResponse: CtapClientPinResponseCborWriter.Write,
            decodeAuthenticatorConfigRequest: CtapAuthenticatorConfigRequestCborReader.Read,
            decodeCredentialManagementRequest: CtapCredentialManagementRequestCborReader.Read,
            encodeCredentialManagementResponse: CtapCredentialManagementResponseCborWriter.Write,
            decodeBioEnrollmentRequest: CtapBioEnrollmentRequestCborReader.Read,
            encodeBioEnrollmentResponse: CtapBioEnrollmentResponseCborWriter.Write,
            decodeLargeBlobsRequest: CtapLargeBlobsRequestCborReader.Read,
            encodeLargeBlobsResponse: CtapLargeBlobsResponseCborWriter.Write,
            encodeMakeCredentialExtensionOutputs: CtapMakeCredentialExtensionOutputsCborWriter.Write,
            encodeGetAssertionExtensionOutputs: CtapGetAssertionExtensionOutputsCborWriter.Write,
            aaguid: aaguid,
            residentCredentialCapacity: residentCredentialCapacity,
            rng: rng,
            credentialSigningBackend: backend,
            timeProvider: timeProvider,
            simulateFingerprintCapture: simulateFingerprintCapture,
            simulateBuiltInUv: simulateBuiltInUv,
            enterpriseAttestationProvisioning: enterpriseAttestationProvisioning,
            encodePackedCertifiedAttestationStatement: PackedAttestationStatementCborWriter.WriteCertified);


    /// <summary>Builds an <c>authenticatorMakeCredential</c> request model with sensible wave-2 defaults.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the clientDataHash and user handle carriers transfers to the returned CtapMakeCredentialRequest, which DisposeMakeCredentialRequest (or the simulator's own request-carrier disposal) disposes.")]
    public static CtapMakeCredentialRequest BuildMakeCredentialRequest(
        MemoryPool<byte> pool,
        string rpId = DefaultRpId,
        byte[]? userId = null,
        int alg = DefaultAlgorithm,
        IReadOnlyList<PublicKeyCredentialDescriptor>? excludeList = null,
        CtapCommandOptions? options = null,
        ReadOnlyMemory<byte>? pinUvAuthParam = null,
        int? pinUvAuthProtocol = null,
        int? enterpriseAttestation = null,
        IReadOnlyList<string>? attestationFormatsPreference = null,
        ReadOnlyMemory<byte>? extensions = null)
    {
        DigestValue clientDataHash = BuildFixedClientDataHash(0x10, pool);
        UserHandle userHandle = UserHandle.Create(userId ?? BuildFixedBytes(16, 0x40), pool);

        return new CtapMakeCredentialRequest(
            clientDataHash,
            new CtapPublicKeyCredentialRpEntity(rpId, "Example RP"),
            new CtapPublicKeyCredentialUserEntity(userHandle, "alice", "Alice Example"),
            [new PublicKeyCredentialParameters { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Alg = alg }],
            excludeList,
            extensions,
            options,
            pinUvAuthParam,
            pinUvAuthProtocol,
            enterpriseAttestation,
            attestationFormatsPreference);
    }


    /// <summary>
    /// Builds an <c>authenticatorMakeCredential</c> request's <c>extensions</c> (<c>0x06</c>) map CBOR
    /// bytes for the <c>credProtect</c>/<c>hmac-secret</c>/<c>largeBlobKey</c>/<c>minPinLength</c>/
    /// <c>hmac-secret-mc</c> extensions (CTAP 2.3 §12.1/§12.7/§12.3/§12.5/§12.8), omitting any key whose
    /// own parameter is <see langword="null"/> — the platform-side encode
    /// <see cref="BuildMakeCredentialRequest"/>'s own <c>extensions</c> parameter carries onto the wire,
    /// mirroring <see cref="CtapMakeCredentialExtensionOutputsCborWriter"/>'s canonical shorter-key-first
    /// ordering: <c>credProtect</c> (11 chars) before <c>hmac-secret</c> (11 chars, tie broken by
    /// <c>'c'</c> 0x63 &lt; <c>'h'</c> 0x68) before <c>largeBlobKey</c> (12 chars) before
    /// <c>minPinLength</c> (12 chars, and 'l' &lt; 'm' breaks that length tie) before <c>hmac-secret-mc</c>
    /// (14 chars, strictly longest, sorts LAST regardless of its shared <c>hmac-secret</c> prefix).
    /// </summary>
    /// <param name="credProtect">The <c>credProtect</c> map value, or <see langword="null"/> to omit the key.</param>
    /// <param name="minPinLength">The <c>minPinLength</c> map value, or <see langword="null"/> to omit the key.</param>
    /// <param name="largeBlobKey">The <c>largeBlobKey</c> map value, or <see langword="null"/> to omit the key.</param>
    /// <param name="hmacSecret">The <c>hmac-secret</c> map value, or <see langword="null"/> to omit the key.</param>
    /// <param name="hmacSecretMc">
    /// The <c>hmac-secret-mc</c> compound map value (the SAME keyAgreement/saltEnc/saltAuth/pinUvAuthProtocol
    /// shape <see cref="BuildGetAssertionHmacSecretExtensionsInput"/> encodes for ga's own <c>hmac-secret</c>
    /// input, contract R6), or <see langword="null"/> to omit the key.
    /// </param>
    /// <returns>The encoded <c>extensions</c> map bytes.</returns>
    public static ReadOnlyMemory<byte> BuildMakeCredentialExtensionsInput(
        int? credProtect = null, bool? minPinLength = null, bool? largeBlobKey = null, bool? hmacSecret = null,
        CtapGetAssertionHmacSecretInput? hmacSecretMc = null)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        int memberCount = (credProtect is not null ? 1 : 0) + (hmacSecret is not null ? 1 : 0)
            + (largeBlobKey is not null ? 1 : 0) + (minPinLength is not null ? 1 : 0) + (hmacSecretMc is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        if(credProtect is int credProtectValue)
        {
            writer.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.CredProtect);
            writer.WriteInt32(credProtectValue);
        }

        if(hmacSecret is bool hmacSecretValue)
        {
            writer.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.HmacSecret);
            writer.WriteBoolean(hmacSecretValue);
        }

        if(largeBlobKey is bool largeBlobKeyValue)
        {
            writer.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.LargeBlobKey);
            writer.WriteBoolean(largeBlobKeyValue);
        }

        if(minPinLength is bool minPinLengthValue)
        {
            writer.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.MinPinLength);
            writer.WriteBoolean(minPinLengthValue);
        }

        if(hmacSecretMc is CtapGetAssertionHmacSecretInput hmacSecretMcValue)
        {
            writer.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.HmacSecretMc);

            int innerMemberCount = 3 + (hmacSecretMcValue.PinUvAuthProtocol is not null ? 1 : 0);
            writer.WriteStartMap(innerMemberCount);
            writer.WriteInt32(WellKnownCtapHmacSecretExtensionKeys.KeyAgreement);
            writer.WriteEncodedValue(CredentialPublicKeyCborWriter.Write(hmacSecretMcValue.KeyAgreement).Span);
            writer.WriteInt32(WellKnownCtapHmacSecretExtensionKeys.SaltEnc);
            writer.WriteByteString(hmacSecretMcValue.SaltEnc.Span);
            writer.WriteInt32(WellKnownCtapHmacSecretExtensionKeys.SaltAuth);
            writer.WriteByteString(hmacSecretMcValue.SaltAuth.Span);
            if(hmacSecretMcValue.PinUvAuthProtocol is int hmacSecretMcProtocolValue)
            {
                writer.WriteInt32(WellKnownCtapHmacSecretExtensionKeys.PinUvAuthProtocol);
                writer.WriteInt32(hmacSecretMcProtocolValue);
            }
            writer.WriteEndMap();
        }

        writer.WriteEndMap();

        return writer.Encode();
    }


    /// <summary>
    /// Builds an <c>authenticatorGetAssertion</c> request's <c>extensions</c> (<c>0x04</c>) map CBOR
    /// bytes carrying only the <c>largeBlobKey</c> key (CTAP 2.3 §12.3) — this request type's sole
    /// modeled extension input (wavelb R8).
    /// </summary>
    /// <param name="largeBlobKey">The <c>largeBlobKey</c> map value.</param>
    /// <returns>The encoded <c>extensions</c> map bytes.</returns>
    public static ReadOnlyMemory<byte> BuildGetAssertionExtensionsInput(bool largeBlobKey)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        writer.WriteStartMap(1);
        writer.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.LargeBlobKey);
        writer.WriteBoolean(largeBlobKey);
        writer.WriteEndMap();

        return writer.Encode();
    }


    /// <summary>
    /// Builds an <c>authenticatorGetAssertion</c> request's <c>extensions</c> (<c>0x04</c>) map CBOR
    /// bytes carrying the <c>hmac-secret</c> compound extension (CTAP 2.3 §12.7, snapshot lines
    /// 13228-13248) — this request type's first COMPOUND extension input, and optionally
    /// <c>largeBlobKey</c> alongside it. Canonical key order matches
    /// <see cref="BuildMakeCredentialExtensionsInput"/>'s own derivation: <c>"hmac-secret"</c> (11
    /// characters) sorts before <c>"largeBlobKey"</c> (12 characters).
    /// </summary>
    /// <param name="keyAgreement">The platform's key-agreement COSE_Key (<c>0x01</c>).</param>
    /// <param name="saltEnc">The encrypted one- or two-salt plaintext (<c>0x02</c>).</param>
    /// <param name="saltAuth">The signature over <paramref name="saltEnc"/> (<c>0x03</c>).</param>
    /// <param name="pinUvAuthProtocol">
    /// The <c>pinUvAuthProtocol</c> member (<c>0x04</c>), or <see langword="null"/> to omit it — snapshot
    /// line 13279's defaulting-to-protocol-one is exercised by omitting this for a protocol-one session;
    /// line 13246 requires the platform include it whenever the session protocol is not protocol one.
    /// </param>
    /// <param name="largeBlobKey">The <c>largeBlobKey</c> map value, or <see langword="null"/> to omit that key.</param>
    /// <returns>The encoded <c>extensions</c> map bytes.</returns>
    public static ReadOnlyMemory<byte> BuildGetAssertionHmacSecretExtensionsInput(
        CoseKey keyAgreement, ReadOnlyMemory<byte> saltEnc, ReadOnlyMemory<byte> saltAuth, int? pinUvAuthProtocol = null, bool? largeBlobKey = null)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        int outerMemberCount = 1 + (largeBlobKey is not null ? 1 : 0);
        writer.WriteStartMap(outerMemberCount);

        writer.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.HmacSecret);

        int innerMemberCount = 3 + (pinUvAuthProtocol is not null ? 1 : 0);
        writer.WriteStartMap(innerMemberCount);
        writer.WriteInt32(WellKnownCtapHmacSecretExtensionKeys.KeyAgreement);
        writer.WriteEncodedValue(CredentialPublicKeyCborWriter.Write(keyAgreement).Span);
        writer.WriteInt32(WellKnownCtapHmacSecretExtensionKeys.SaltEnc);
        writer.WriteByteString(saltEnc.Span);
        writer.WriteInt32(WellKnownCtapHmacSecretExtensionKeys.SaltAuth);
        writer.WriteByteString(saltAuth.Span);
        if(pinUvAuthProtocol is int protocolValue)
        {
            writer.WriteInt32(WellKnownCtapHmacSecretExtensionKeys.PinUvAuthProtocol);
            writer.WriteInt32(protocolValue);
        }
        writer.WriteEndMap();

        if(largeBlobKey is bool largeBlobKeyValue)
        {
            writer.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.LargeBlobKey);
            writer.WriteBoolean(largeBlobKeyValue);
        }

        writer.WriteEndMap();

        return writer.Encode();
    }


    /// <summary>Disposes an <c>authenticatorMakeCredential</c> request model's own SensitiveMemory carriers.</summary>
    public static void DisposeMakeCredentialRequest(CtapMakeCredentialRequest request)
    {
        request.ClientDataHash.Dispose();
        request.User.Id.Dispose();

        if(request.ExcludeList is not null)
        {
            foreach(PublicKeyCredentialDescriptor descriptor in request.ExcludeList)
            {
                descriptor.Id.Dispose();
            }
        }
    }


    /// <summary>Builds an <c>authenticatorGetAssertion</c> request model with sensible wave-2 defaults.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the clientDataHash carrier transfers to the returned CtapGetAssertionRequest, which DisposeGetAssertionRequest (or the simulator's own request-carrier disposal) disposes.")]
    public static CtapGetAssertionRequest BuildGetAssertionRequest(
        MemoryPool<byte> pool,
        string rpId = DefaultRpId,
        IReadOnlyList<PublicKeyCredentialDescriptor>? allowList = null,
        CtapCommandOptions? options = null,
        ReadOnlyMemory<byte>? pinUvAuthParam = null,
        int? pinUvAuthProtocol = null,
        ReadOnlyMemory<byte>? extensions = null)
    {
        DigestValue clientDataHash = BuildFixedClientDataHash(0x20, pool);

        return new CtapGetAssertionRequest(rpId, clientDataHash, allowList, extensions, options, pinUvAuthParam, pinUvAuthProtocol);
    }


    /// <summary>Disposes an <c>authenticatorGetAssertion</c> request model's own SensitiveMemory carriers.</summary>
    public static void DisposeGetAssertionRequest(CtapGetAssertionRequest request)
    {
        request.ClientDataHash.Dispose();

        if(request.AllowList is not null)
        {
            foreach(PublicKeyCredentialDescriptor descriptor in request.AllowList)
            {
                descriptor.Id.Dispose();
            }
        }
    }


    /// <summary>Encodes, sends, and disposes an <c>authenticatorMakeCredential</c> request, returning the raw response envelope.</summary>
    public static async Task<PooledMemory> SendMakeCredentialAsync(
        CtapAuthenticatorSimulator simulator, CtapMakeCredentialRequest request, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] envelope = CtapWave2RequestEnvelopes.BuildMakeCredentialEnvelope(request);
        DisposeMakeCredentialRequest(request);

        return await simulator.TransceiveAsync(envelope, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Encodes, sends, and disposes an <c>authenticatorGetAssertion</c> request, returning the raw response envelope.</summary>
    public static async Task<PooledMemory> SendGetAssertionAsync(
        CtapAuthenticatorSimulator simulator, CtapGetAssertionRequest request, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] envelope = CtapWave2RequestEnvelopes.BuildGetAssertionEnvelope(request);
        DisposeGetAssertionRequest(request);

        return await simulator.TransceiveAsync(envelope, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Sends a bare <c>authenticatorGetNextAssertion</c> request, returning the raw response envelope.</summary>
    public static async Task<PooledMemory> SendGetNextAssertionAsync(
        CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] envelope = CtapWave2RequestEnvelopes.BuildGetNextAssertionEnvelope();

        return await simulator.TransceiveAsync(envelope, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Registers a credential (resident by default) for <paramref name="userId"/> and returns its minted
    /// credential ID carrier and public key — the shared setup step every <c>authenticatorGetAssertion</c>
    /// test needs. <paramref name="credProtect"/> mints the credential with that <c>credProtect</c> level
    /// requested (R4/R6); <paramref name="excludeList"/>/<paramref name="pinUvAuthParam"/>/
    /// <paramref name="pinUvAuthProtocol"/> thread through to the underlying mc request for R9's
    /// excludeList/UV-collection scenarios.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the credential ID carrier transfers to the returned CtapWave2RegisteredCredential, which the caller disposes.")]
    public static async Task<CtapWave2RegisteredCredential> RegisterCredentialAsync(
        CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, byte[] userId, CancellationToken cancellationToken, string rpId = DefaultRpId, bool resident = true,
        int? credProtect = null, IReadOnlyList<PublicKeyCredentialDescriptor>? excludeList = null,
        ReadOnlyMemory<byte>? pinUvAuthParam = null, int? pinUvAuthProtocol = null)
    {
        //Assigned via an explicit if/else rather than a ternary: a ternary whose "present" branch is a
        //ReadOnlyMemory<byte> and whose "absent" branch is the null literal infers a non-nullable
        //ReadOnlyMemory<byte>-typed conditional expression (null's own implicit convertibility to
        //ReadOnlyMemory<byte> via its byte[]-accepting operator out-competes promotion to
        //Nullable<ReadOnlyMemory<byte>>), so the outer Nullable<ReadOnlyMemory<byte>> ends up
        //HasValue=true (an empty, zero-length span) for an absent credProtect — mirroring
        //CtapMakeCredentialRequestCborReader's own documented reason for the identical if/else shape.
        ReadOnlyMemory<byte>? extensions;
        if(credProtect is int requestedCredProtect)
        {
            extensions = BuildMakeCredentialExtensionsInput(credProtect: requestedCredProtect);
        }
        else
        {
            extensions = null;
        }

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(
            pool, rpId: rpId, userId: userId, options: new CtapCommandOptions(ResidentKey: resident), excludeList: excludeList, extensions: extensions,
            pinUvAuthParam: pinUvAuthParam, pinUvAuthProtocol: pinUvAuthProtocol);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, cancellationToken).ConfigureAwait(false);
        if(!WellKnownCtapStatusCodes.IsOk(response.AsReadOnlySpan()[0]))
        {
            throw new Fido2FormatException($"Fixture registration failed with CTAP2 status 0x{response.AsReadOnlySpan()[0]:X2}.");
        }

        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);

        CredentialId credentialId = CredentialId.Create(authenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan(), pool);

        return new CtapWave2RegisteredCredential(credentialId, authenticatorData.AttestedCredentialData.CredentialPublicKey);
    }


    /// <summary>Convenience overload of <see cref="RegisterCredentialAsync"/> for tests that need only the minted credential ID bytes, disposing the intermediate carrier once its bytes are copied out. <paramref name="credProtect"/> mints the credential with that <c>credProtect</c> level requested (R4/R6).</summary>
    public static async Task<byte[]> RegisterAndCaptureCredentialIdBytesAsync(
        CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, byte[] userId, CancellationToken cancellationToken, string rpId = DefaultRpId, bool resident = true,
        int? credProtect = null)
    {
        CtapWave2RegisteredCredential registered = await RegisterCredentialAsync(
            simulator, pool, userId, cancellationToken, rpId, resident, credProtect).ConfigureAwait(false);
        byte[] credentialIdBytes = registered.CredentialId.AsReadOnlySpan().ToArray();
        registered.CredentialId.Dispose();

        return credentialIdBytes;
    }
}


/// <summary>
/// A credential minted by <see cref="CtapWave2AuthenticatorFixtures.RegisterCredentialAsync"/>: the
/// identifier carrier and public key a test needs to build an <c>allowList</c> entry and independently
/// verify a later assertion signature.
/// </summary>
/// <param name="CredentialId">
/// The minted credential's identifier, copied into its own pooled carrier. Owned by the caller, who must
/// dispose it once done.
/// </param>
/// <param name="PublicKey">The minted credential's public key, parsed from the registration response's <c>attestedCredentialData</c>.</param>
internal sealed record CtapWave2RegisteredCredential(CredentialId CredentialId, CoseKey PublicKey);
