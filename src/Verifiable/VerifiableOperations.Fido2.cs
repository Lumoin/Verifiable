using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Lumoin.Base;
using Verifiable.Cbor.Fido2;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;

namespace Verifiable;

/// <summary>
/// The FIDO2/WebAuthn verbs: registration and assertion ceremony verification, and challenge
/// generation. A sibling partial of <see cref="VerifiableOperations"/> — see that file's own doc
/// comment for the shared "used by both CLI commands and MCP tools" contract every method here
/// follows identically.
/// </summary>
internal static partial class VerifiableOperations
{
    /// <summary>
    /// The <see cref="TenantId"/> threaded through a Metadata BLOB verification request from this
    /// single-invocation, storage-free CLI verb. Opaque to the library; this CLI never resolves or
    /// persists serial-number state, so no deployment-specific tenant identity exists to carry — the
    /// constant exists only because <see cref="MetadataBlobVerificationRequest"/> requires one.
    /// </summary>
    private const string MdsVerificationTenantId = "verifiable-cli:fido2-mds-verification";

    /// <summary>
    /// The key identifier passed to <see cref="Verifiable.Cryptography.CryptographicKeyFactory"/> for
    /// the ephemeral credential key the observed-CBOM FIDO2 workload mints. Not a DID or credential
    /// id — this seam has no such identity to carry, only the key material and its algorithm tag.
    /// </summary>
    private const string ObservedFido2WorkloadKeyIdentifier = "cbom-observed-workload:fido2-credential";

    /// <summary>The synthetic challenge the observed-CBOM FIDO2 workload's <c>clientDataJSON</c> embeds.</summary>
    private const string ObservedFido2WorkloadChallenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX";

    /// <summary>The synthetic origin the observed-CBOM FIDO2 workload's <c>clientDataJSON</c> embeds.</summary>
    private const string ObservedFido2WorkloadOrigin = "https://cbom-observed-workload.example";

    /// <summary>
    /// The synthetic relying party ID the observed-CBOM FIDO2 workload's <c>rpIdHash</c> is the
    /// SHA-256 of — the host of <see cref="ObservedFido2WorkloadOrigin"/>, exactly as a real
    /// ceremony would relate the two.
    /// </summary>
    private const string ObservedFido2WorkloadRpId = "cbom-observed-workload.example";

    /// <summary>
    /// The <c>authData</c> flags byte the observed-CBOM FIDO2 workload's synthetic assertion carries:
    /// <c>UP</c> (user present) and <c>UV</c> (user verified) set, no attested credential data or
    /// extensions — the WebAuthn L3 section 6.1 assertion-response shape.
    /// </summary>
    private const byte ObservedFido2WorkloadAuthenticatorDataFlags = 0x01 | 0x04;


    /// <summary>
    /// Verifies a WebAuthn L3 §7.1 registration ceremony against a <c>none</c>, <c>packed</c>,
    /// <c>android-key</c>, or <c>fido-u2f</c> attestation object, using the shipped CBOR/JSON codec
    /// defaults and the Microsoft X.509 chain/profile/extension delegates.
    /// </summary>
    /// <param name="attestationObjectPath">The file path to the raw <c>attestationObject</c> CBOR bytes.</param>
    /// <param name="clientDataJsonPath">The file path to the raw <c>clientDataJSON</c> bytes.</param>
    /// <param name="rpId">The relying party ID whose SHA-256 hash <c>authData.rpIdHash</c> is checked against.</param>
    /// <param name="origin">The single origin the relying party accepts for this ceremony.</param>
    /// <param name="challenge">The base64url-encoded challenge exactly as issued to the client.</param>
    /// <param name="trustAnchorPaths">
    /// Repeatable PEM or DER attestation root certificate file paths, for a caller that already knows
    /// the attestation root. Mutually exclusive with <paramref name="mdsBlobPath"/>/<paramref name="mdsRootPath"/>.
    /// </param>
    /// <param name="mdsBlobPath">The file path to a compact-JWS FIDO Metadata Service BLOB.</param>
    /// <param name="mdsRootPath">The file path to the MDS root certificate <paramref name="mdsBlobPath"/> chains to.</param>
    /// <param name="requireTeeEnforcedAuthorizations">
    /// The <c>android-key</c> format's TEE-only policy knob (see
    /// <see cref="AndroidKeyAttestation.Build"/>'s parameter of the same name). Defaults to
    /// <see langword="false"/> — the specification's baseline posture.
    /// </param>
    /// <param name="userVerification">
    /// The relying party's user-verification policy wire value (<c>required</c>, <c>preferred</c>,
    /// or <c>discouraged</c>). Defaults to <c>preferred</c> — the CR's own IDL default.
    /// </param>
    /// <param name="authenticatorAttachment">
    /// The client-reported <c>authenticatorAttachment</c> value (<c>platform</c> or
    /// <c>cross-platform</c>) to store on the built credential record. Defaults to
    /// <see langword="null"/> — the CLI collects no such input by default.
    /// </param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>
    /// On success, the credential record JSON document (<see cref="Fido2CredentialRecordJsonWriter"/>'s
    /// shape) to store for future authentication ceremonies. On failure, the exact failing claim or
    /// attestation error identifier.
    /// </returns>
    public static async Task<Result<string, string>> VerifyFido2RegistrationAsync(
        string attestationObjectPath,
        string clientDataJsonPath,
        string rpId,
        string origin,
        string challenge,
        IReadOnlyList<string>? trustAnchorPaths,
        string? mdsBlobPath,
        string? mdsRootPath,
        bool requireTeeEnforcedAuthorizations = false,
        string? userVerification = null,
        string? authenticatorAttachment = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            CryptoProviderStartup.EnsureRegistered();

            DateTimeOffset now = TimeProvider.System.GetUtcNow();

            if(!TryParseUserVerification(userVerification, out UserVerificationRequirement userVerificationRequirement, out string? userVerificationError))
            {
                return Result.Failure<string, string>(userVerificationError!);
            }

            if(trustAnchorPaths is { Count: > 0 } && (mdsBlobPath is not null || mdsRootPath is not null))
            {
                return Result.Failure<string, string>(
                    "Specify either --trust-anchor file(s) or the --mds-blob/--mds-root pair, not both.");
            }

            byte[] attestationObjectBytes;
            byte[] clientDataJsonBytes;
            try
            {
                attestationObjectBytes = await File.ReadAllBytesAsync(attestationObjectPath, cancellationToken).ConfigureAwait(false);
                clientDataJsonBytes = await File.ReadAllBytesAsync(clientDataJsonPath, cancellationToken).ConfigureAwait(false);
            }
            catch(IOException ex)
            {
                return Result.Failure<string, string>($"Error reading registration input files: {ex.Message}");
            }

            AttestationObjectParts parts;
            try
            {
                parts = AttestationObjectCborReader.Parse(attestationObjectBytes);
            }
            catch(Fido2FormatException ex)
            {
                return Result.Failure<string, string>($"Malformed attestationObject: {ex.Message}");
            }

            AuthenticatorData authenticatorData;
            try
            {
                authenticatorData = AuthenticatorDataReader.Read(parts.AuthenticatorData, CredentialPublicKeyCborReader.Read, BaseMemoryPool.Shared);
            }
            catch(Fido2FormatException ex)
            {
                return Result.Failure<string, string>($"Malformed authenticatorData: {ex.Message}");
            }

            int? credentialAlgorithm = authenticatorData.AttestedCredentialData?.CredentialPublicKey.Alg;
            if(DescribeUnsupportedAlgorithm(credentialAlgorithm) is string unsupportedAlgorithmMessage)
            {
                authenticatorData.Dispose();

                return Result.Failure<string, string>(unsupportedAlgorithmMessage);
            }

            ClientData clientData;
            try
            {
                clientData = ClientDataJsonReader.Read(clientDataJsonBytes);
            }
            catch(Fido2FormatException ex)
            {
                authenticatorData.Dispose();

                return Result.Failure<string, string>($"Malformed clientDataJSON: {ex.Message}");
            }

            Result<IReadOnlyList<PkiCertificateMemory>, string> trustAnchorsResult = await ResolveRegistrationTrustAnchorsAsync(
                trustAnchorPaths, mdsBlobPath, mdsRootPath, authenticatorData, now, cancellationToken).ConfigureAwait(false);

            if(!trustAnchorsResult.IsSuccess)
            {
                authenticatorData.Dispose();

                return Result.Failure<string, string>(trustAnchorsResult.Error!);
            }

            IReadOnlyList<PkiCertificateMemory> trustAnchors = trustAnchorsResult.Value!;
            try
            {
                DigestValue expectedRpIdHash = ComputeRpIdHash(rpId, BaseMemoryPool.Shared);

                using RegistrationCeremonyInput ceremonyInput = new()
                {
                    ClientData = clientData,
                    AuthenticatorData = authenticatorData,
                    ExpectedChallenge = challenge,
                    ExpectedOrigins = new HashSet<string>(StringComparer.Ordinal) { origin },
                    ExpectedRpIdHash = expectedRpIdHash,
                    UserVerification = userVerificationRequirement,
                    AllowedAlgorithms = SupportedCoseAlgorithms
                };

                SelectAttestationVerifierDelegate selectVerifier = BuildAttestationVerifierSelector(requireTeeEnforcedAuthorizations);

                Fido2RegistrationOutcome outcome = await Fido2RegistrationVerifier.VerifyAsync(
                    parts.Format,
                    parts.AttestationStatement,
                    parts.AuthenticatorData,
                    clientDataJsonBytes,
                    ceremonyInput,
                    selectVerifier,
                    AlwaysUniqueCredentialId,
                    trustAnchors,
                    now,
                    Guid.NewGuid().ToString(),
                    BaseMemoryPool.Shared,
                    transports: null,
                    authenticatorAttachment: authenticatorAttachment,
                    cancellationToken: cancellationToken).ConfigureAwait(false);

                if(!outcome.IsAcceptable)
                {
                    return Result.Failure<string, string>(DescribeRegistrationFailure(outcome));
                }

                using Fido2CredentialRecord record = outcome.CredentialRecord!;
                var buffer = new ArrayBufferWriter<byte>();
                Fido2CredentialRecordJsonWriter.Write(record, buffer);

                return Result.Success<string, string>(Encoding.UTF8.GetString(buffer.WrittenSpan));
            }
            finally
            {
                foreach(PkiCertificateMemory anchor in trustAnchors)
                {
                    anchor.Dispose();
                }
            }
        }
        catch(Exception ex) when(ex is not OperationCanceledException)
        {
            return Result.Failure<string, string>($"Error verifying FIDO2 registration: {ex.Message}");
        }
    }


    /// <summary>
    /// Verifies a WebAuthn L3 §7.2 authentication assertion against a previously stored credential
    /// record, using the shipped JSON codec default for the record and the credential's own COSE_Key
    /// as the verification key.
    /// </summary>
    /// <param name="credentialRecordPath">
    /// The file path to a credential record JSON document (<see cref="Fido2CredentialRecordJsonWriter"/>'s
    /// shape), as produced by <see cref="VerifyFido2RegistrationAsync"/>.
    /// </param>
    /// <param name="authenticatorDataPath">The file path to the raw <c>authData</c> bytes (<c>response.authenticatorData</c>).</param>
    /// <param name="signaturePath">The file path to the raw assertion signature bytes (<c>response.signature</c>).</param>
    /// <param name="clientDataJsonPath">The file path to the raw <c>clientDataJSON</c> bytes.</param>
    /// <param name="rpId">The relying party ID whose SHA-256 hash <c>authData.rpIdHash</c> is checked against.</param>
    /// <param name="origin">The single origin the relying party accepts for this ceremony.</param>
    /// <param name="challenge">The base64url-encoded challenge exactly as issued to the client.</param>
    /// <param name="storedSignCount">The signature counter value stored for this credential from the previous ceremony. Defaults to <c>0</c>.</param>
    /// <param name="userVerification">
    /// The relying party's user-verification policy wire value (<c>required</c>, <c>preferred</c>,
    /// or <c>discouraged</c>). Defaults to <c>preferred</c> — the CR's own IDL default.
    /// </param>
    /// <param name="userHandlePath">The optional file path to the raw <c>response.userHandle</c> bytes.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>
    /// On success, a compact JSON verdict (<c>isAcceptable</c>, <c>signatureValid</c>, <c>signCount</c>).
    /// On failure, the exact failing claim or a signature-invalid message.
    /// </returns>
    public static async Task<Result<string, string>> VerifyFido2AssertionAsync(
        string credentialRecordPath,
        string authenticatorDataPath,
        string signaturePath,
        string clientDataJsonPath,
        string rpId,
        string origin,
        string challenge,
        uint storedSignCount = 0,
        string? userVerification = null,
        string? userHandlePath = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            CryptoProviderStartup.EnsureRegistered();

            if(!TryParseUserVerification(userVerification, out UserVerificationRequirement userVerificationRequirement, out string? userVerificationError))
            {
                return Result.Failure<string, string>(userVerificationError!);
            }

            byte[] recordBytes;
            byte[] authenticatorDataBytes;
            byte[] signatureBytes;
            byte[] clientDataJsonBytes;
            try
            {
                recordBytes = await File.ReadAllBytesAsync(credentialRecordPath, cancellationToken).ConfigureAwait(false);
                authenticatorDataBytes = await File.ReadAllBytesAsync(authenticatorDataPath, cancellationToken).ConfigureAwait(false);
                signatureBytes = await File.ReadAllBytesAsync(signaturePath, cancellationToken).ConfigureAwait(false);
                clientDataJsonBytes = await File.ReadAllBytesAsync(clientDataJsonPath, cancellationToken).ConfigureAwait(false);
            }
            catch(IOException ex)
            {
                return Result.Failure<string, string>($"Error reading assertion input files: {ex.Message}");
            }

            Fido2CredentialRecord record;
            try
            {
                record = Fido2CredentialRecordJsonReader.Read(recordBytes, BaseMemoryPool.Shared);
            }
            catch(Fido2FormatException ex)
            {
                return Result.Failure<string, string>($"Malformed credential record: {ex.Message}");
            }

            using(record)
            {
                if(DescribeUnsupportedAlgorithm(record.PublicKey.Alg) is string unsupportedAlgorithmMessage)
                {
                    return Result.Failure<string, string>(unsupportedAlgorithmMessage);
                }

                ClientData clientData;
                AuthenticatorData authenticatorData;
                try
                {
                    clientData = ClientDataJsonReader.Read(clientDataJsonBytes);
                    authenticatorData = AuthenticatorDataReader.Read(authenticatorDataBytes, CredentialPublicKeyCborReader.Read, BaseMemoryPool.Shared);
                }
                catch(Fido2FormatException ex)
                {
                    return Result.Failure<string, string>($"Malformed assertion input: {ex.Message}");
                }

                byte[]? userHandleBytes = null;
                if(userHandlePath is not null)
                {
                    try
                    {
                        userHandleBytes = await File.ReadAllBytesAsync(userHandlePath, cancellationToken).ConfigureAwait(false);
                    }
                    catch(IOException ex)
                    {
                        authenticatorData.Dispose();

                        return Result.Failure<string, string>($"Error reading user-handle file: {ex.Message}");
                    }
                }

                DigestValue expectedRpIdHash = ComputeRpIdHash(rpId, BaseMemoryPool.Shared);
                CredentialId credentialId = CredentialId.Create(record.Id.AsReadOnlySpan(), BaseMemoryPool.Shared);
                UserHandle? responseUserHandle = userHandleBytes is not null
                    ? UserHandle.Create(userHandleBytes, BaseMemoryPool.Shared)
                    : null;

                using AssertionCeremonyInput ceremonyInput = new()
                {
                    ClientData = clientData,
                    AuthenticatorData = authenticatorData,
                    ExpectedChallenge = challenge,
                    ExpectedOrigins = new HashSet<string>(StringComparer.Ordinal) { origin },
                    ExpectedRpIdHash = expectedRpIdHash,
                    UserVerification = userVerificationRequirement,
                    CredentialId = credentialId,
                    // This verb is verification-only against ONE named credential record (no
                    // discoverable-credential storage lookup exists in this CLI — scout-cli's
                    // "no storage lifecycle" finding), so the caller has already identified the
                    // credential exactly as WebAuthn L3 step 6's first case describes: an allowlist
                    // naming the one credential this record represents. That is what makes a
                    // userHandle optional here even when --user-handle is not supplied.
                    AllowedCredentialIds = [credentialId],
                    StoredSignCount = storedSignCount,
                    StoredUvInitialized = record.UvInitialized,
                    StoredBackupEligible = record.BackupEligible,
                    StoredBackupState = record.BackupState,
                    ResponseUserHandle = responseUserHandle
                };

                Fido2AssertionOutcome outcome = await Fido2AssertionVerifier.VerifyAsync(
                    record.PublicKey,
                    signatureBytes,
                    authenticatorDataBytes,
                    clientDataJsonBytes,
                    ceremonyInput,
                    Guid.NewGuid().ToString(),
                    BaseMemoryPool.Shared,
                    cancellationToken: cancellationToken).ConfigureAwait(false);

                if(!outcome.IsAcceptable)
                {
                    return Result.Failure<string, string>(DescribeAssertionFailure(outcome));
                }

                return Result.Success<string, string>(WriteAssertionVerdict(outcome, authenticatorData.SignCount));
            }
        }
        catch(Exception ex) when(ex is not OperationCanceledException)
        {
            return Result.Failure<string, string>($"Error verifying FIDO2 assertion: {ex.Message}");
        }
    }


    /// <summary>
    /// Generates a WebAuthn cryptographic challenge through the registered entropy provider.
    /// </summary>
    /// <param name="byteLength">
    /// The challenge length in bytes, or <see langword="null"/> for
    /// <see cref="Fido2ChallengeGeneration"/>'s default length.
    /// </param>
    /// <returns>On success, the base64url-encoded challenge string. On failure, the floor violation message.</returns>
    public static Result<string, string> CreateFido2Challenge(int? byteLength = null)
    {
        try
        {
            CryptoProviderStartup.EnsureRegistered();

            string challenge = byteLength is int length
                ? Fido2ChallengeGeneration.Generate(length, BaseMemoryPool.Shared)
                : Fido2ChallengeGeneration.Generate(BaseMemoryPool.Shared);

            return Result.Success<string, string>(challenge);
        }
        catch(ArgumentOutOfRangeException ex)
        {
            return Result.Failure<string, string>(ex.Message);
        }
    }


    /// <summary>
    /// The COSE algorithm identifiers <see cref="CryptoProviderStartup"/> registers verification
    /// functions for: ES256/384/512, RS256/384/512, and PS256/384/512. Ruling 2's "verb algorithm
    /// matrix" — EdDSA and ES256K are deliberately absent (see <see cref="CryptoProviderStartup"/>'s
    /// own doc comment) until an Ed25519/secp256k1 backend is referenced from this project.
    /// </summary>
    private static IReadOnlyList<int> SupportedCoseAlgorithms { get; } = BuildSupportedCoseAlgorithms();


    /// <summary>Builds <see cref="SupportedCoseAlgorithms"/>.</summary>
    private static IReadOnlyList<int> BuildSupportedCoseAlgorithms() =>
    [
        WellKnownCoseAlgorithms.Es256,
        WellKnownCoseAlgorithms.Es384,
        WellKnownCoseAlgorithms.Es512,
        WellKnownCoseAlgorithms.Rs256,
        WellKnownCoseAlgorithms.Rs384,
        WellKnownCoseAlgorithms.Rs512,
        WellKnownCoseAlgorithms.Ps256,
        WellKnownCoseAlgorithms.Ps384,
        WellKnownCoseAlgorithms.Ps512
    ];


    /// <summary>
    /// A human-readable listing of <see cref="SupportedCoseAlgorithms"/>, for the clean
    /// unsupported-algorithm verb error ruling 2 requires.
    /// </summary>
    private static string SupportedAlgorithmsDescription => "ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512";


    /// <summary>
    /// The step 26 credential-id-uniqueness check every registration verification calls. The CLI has
    /// no credential storage of its own (verification-only tooling — see scout-cli's "no storage
    /// lifecycle" finding), so every credential ID is reported unique; a relying party embedding this
    /// verb into a real service supplies its own storage-backed check instead.
    /// </summary>
    private static IsCredentialIdUniqueDelegate AlwaysUniqueCredentialId { get; } = static (_, _) => ValueTask.FromResult(true);


    /// <summary>
    /// Determines whether <paramref name="algorithm"/> is one of <see cref="SupportedCoseAlgorithms"/>,
    /// returning a clean, verb-level error message naming the supported matrix when it is not (ruling
    /// 2) — checked BEFORE any attestation/assertion verification runs, since the shipped verifiers
    /// themselves fail closed to a generic rejection for an unregistered algorithm rather than
    /// surfacing this specific, actionable message.
    /// </summary>
    /// <param name="algorithm">The credential's declared COSE <c>alg</c>, or <see langword="null"/> when absent.</param>
    /// <returns>The clean error message, or <see langword="null"/> when <paramref name="algorithm"/> is supported.</returns>
    private static string? DescribeUnsupportedAlgorithm(int? algorithm)
    {
        if(algorithm is not int value)
        {
            return $"The credential declares no algorithm. Supported algorithms: {SupportedAlgorithmsDescription}.";
        }

        if(SupportedCoseAlgorithms.Contains(value))
        {
            return null;
        }

        string algorithmName = WellKnownCoseAlgorithms.GetAlgorithmName(value) ?? value.ToString(CultureInfo.InvariantCulture);

        return $"Unsupported credential algorithm '{algorithmName}'. Supported algorithms: {SupportedAlgorithmsDescription}.";
    }


    /// <summary>
    /// Parses a <c>--user-verification</c>/MCP <c>userVerification</c> wire value into a
    /// <see cref="UserVerificationRequirement"/>, defaulting to
    /// <see cref="WellKnownUserVerificationRequirements.Preferred"/> — the CR's own IDL default —
    /// when <paramref name="value"/> is <see langword="null"/>.
    /// </summary>
    /// <param name="value">The raw wire value, or <see langword="null"/> to use the default.</param>
    /// <param name="userVerification">The parsed policy value on success.</param>
    /// <param name="error">
    /// A clean, verb-level error message naming the three registered values, when
    /// <paramref name="value"/> is neither <see langword="null"/> nor a registered value.
    /// </param>
    /// <returns><see langword="true"/> on success; otherwise <see langword="false"/>.</returns>
    private static bool TryParseUserVerification(string? value, out UserVerificationRequirement userVerification, out string? error)
    {
        string effectiveValue = value ?? WellKnownUserVerificationRequirements.Preferred;
        if(!WellKnownUserVerificationRequirements.IsRegisteredValue(effectiveValue))
        {
            userVerification = default;
            error = $"Unrecognized --user-verification value '{effectiveValue}'. Expected one of: "
                + $"{WellKnownUserVerificationRequirements.Required}, {WellKnownUserVerificationRequirements.Preferred}, {WellKnownUserVerificationRequirements.Discouraged}.";

            return false;
        }

        userVerification = WellKnownUserVerificationRequirements.FromWireValue(effectiveValue);
        error = null;

        return true;
    }


    /// <summary>
    /// Builds the <see cref="SelectAttestationVerifierDelegate"/> registering all four shipped
    /// attestation statement formats (<c>none</c>/<c>packed</c>/<c>android-key</c>/<c>fido-u2f</c>)
    /// with the Microsoft chain/profile/extension delegates. Per ruling 2, the CLI does not reference
    /// <c>Verifiable.BouncyCastle</c> this wave, so revocation checking and chain completion are both
    /// <see langword="null"/> — no revocation source is configured and <c>x5c</c> is validated exactly
    /// as presented.
    /// </summary>
    private static SelectAttestationVerifierDelegate BuildAttestationVerifierSelector(bool requireTeeEnforcedAuthorizations) =>
        Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.None, NoneAttestation.Build()),
            (WellKnownWebAuthnAttestationFormats.Packed, PackedAttestation.Build(
                PackedAttestationStatementCborReader.Parse,
                MicrosoftX509Functions.ValidateChainAsync,
                MicrosoftX509Functions.ReadCertificateProfile,
                MicrosoftX509Functions.ReadCertificateExtensionValue)),
            (WellKnownWebAuthnAttestationFormats.AndroidKey, AndroidKeyAttestation.Build(
                AndroidKeyAttestationStatementCborReader.Parse,
                MicrosoftX509Functions.ValidateChainAsync,
                MicrosoftX509Functions.ReadCertificateExtensionValue,
                requireTeeEnforcedAuthorizations: requireTeeEnforcedAuthorizations)),
            (WellKnownWebAuthnAttestationFormats.FidoU2f, FidoU2fAttestation.Build(
                FidoU2fAttestationStatementCborReader.Parse,
                MicrosoftX509Functions.ValidateChainAsync)),
            (WellKnownWebAuthnAttestationFormats.Tpm, TpmAttestation.Build(
                TpmAttestationStatementCborReader.Parse,
                MicrosoftX509Functions.ValidateChainAsync,
                MicrosoftX509Functions.ReadCertificateProfile,
                MicrosoftX509Functions.ReadCertificateExtensionValue)));


    /// <summary>
    /// Resolves the registration's trust anchors, either from directly supplied certificate files, or
    /// from a Metadata BLOB per the shipped wave-3 capstone chain: parse → verify → find the entry by
    /// AAGUID → evaluate its status → extract its trust anchors. When the MDS blob does not itself
    /// verify, this is reported as a verb failure; when no matching entry exists or its status is not
    /// accepted, this returns EMPTY anchors so the certified verifier fails closed with
    /// <see cref="Fido2AttestationErrors.NoTrustAnchors"/> rather than the CLI making that trust
    /// decision itself (ruling 11's documented §7.1 step 23 semantics).
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The matched entry's disposal is subsumed by the enclosing MetadataBlob's Dispose() (a MetadataBlobPayload disposes every entry it owns), which the using declaration on 'blob' below calls — disposing the entry a second time would be redundant, not a leak.")]
    private static async ValueTask<Result<IReadOnlyList<PkiCertificateMemory>, string>> ResolveRegistrationTrustAnchorsAsync(
        IReadOnlyList<string>? trustAnchorPaths,
        string? mdsBlobPath,
        string? mdsRootPath,
        AuthenticatorData authenticatorData,
        DateTimeOffset validationTime,
        CancellationToken cancellationToken)
    {
        if(trustAnchorPaths is { Count: > 0 })
        {
            var anchors = new List<PkiCertificateMemory>(trustAnchorPaths.Count);
            try
            {
                foreach(string path in trustAnchorPaths)
                {
                    anchors.Add(await ReadCertificateFileAsync(path, cancellationToken).ConfigureAwait(false));
                }
            }
            catch(Exception ex) when(ex is IOException or CryptographicException or FormatException)
            {
                foreach(PkiCertificateMemory anchor in anchors)
                {
                    anchor.Dispose();
                }

                return Result.Failure<IReadOnlyList<PkiCertificateMemory>, string>($"Error reading trust anchor certificate: {ex.Message}");
            }

            return Result.Success<IReadOnlyList<PkiCertificateMemory>, string>(anchors);
        }

        if(mdsBlobPath is null || mdsRootPath is null)
        {
            return Result.Success<IReadOnlyList<PkiCertificateMemory>, string>(Array.Empty<PkiCertificateMemory>());
        }

        byte[] blobBytes;
        PkiCertificateMemory mdsRoot;
        try
        {
            blobBytes = await File.ReadAllBytesAsync(mdsBlobPath, cancellationToken).ConfigureAwait(false);
            mdsRoot = await ReadCertificateFileAsync(mdsRootPath, cancellationToken).ConfigureAwait(false);
        }
        catch(Exception ex) when(ex is IOException or CryptographicException or FormatException)
        {
            return Result.Failure<IReadOnlyList<PkiCertificateMemory>, string>($"Error reading MDS input files: {ex.Message}");
        }

        using(mdsRoot)
        {
            VerifyMetadataBlobAsyncDelegate verifyBlob = MetadataBlobVerification.Build(MetadataBlobReader.Read, MicrosoftX509Functions.ValidateChainAsync);

            //The CLI verb has no serial-number/revocation storage of its own (a single, stateless
            //invocation) — NotTracked/NotChecked are the explicit, greppable postures for that, not a
            //silently-defaulted absence; ruling 2's own ValidateChainAsync call above wires no
            //revocation delegate either, so Required would fail closed unconditionally here.
            var request = new MetadataBlobVerificationRequest(
                blobBytes, [mdsRoot], validationTime, MdsVerificationTenantId,
                MetadataBlobSerialNumberPolicy.NotTracked, MetadataBlobRevocationPolicy.NotChecked, BaseMemoryPool.Shared);

            MetadataBlobResult blobResult = await verifyBlob(request, cancellationToken).ConfigureAwait(false);

            string? failureReason = blobResult switch
            {
                VerifiedMetadataBlobResult => null,
                RejectedMetadataBlobResult rejected => rejected.Error.Code,
                MetadataBlobStoreUnavailableResult unavailable => unavailable.Error.Code,
                _ => throw new System.Diagnostics.UnreachableException($"Unhandled {nameof(MetadataBlobResult)} subtype '{blobResult.GetType().Name}'; the closed sum admits only the three sibling records.")
            };

            if(failureReason is not null)
            {
                return Result.Failure<IReadOnlyList<PkiCertificateMemory>, string>($"Metadata BLOB did not verify: {failureReason}.");
            }

            var verified = (VerifiedMetadataBlobResult)blobResult;

            using MetadataBlob blob = verified.Blob;

            if(authenticatorData.AttestedCredentialData is not { } attestedCredentialData
                || !MetadataBlobPayloadQueries.TryFindEntryByAaguid(blob.Payload, attestedCredentialData.Aaguid, out MetadataBlobPayloadEntry? entry)
                || !MetadataBlobPayloadQueries.EvaluateStatus(entry!).Accepted)
            {
                return Result.Success<IReadOnlyList<PkiCertificateMemory>, string>(Array.Empty<PkiCertificateMemory>());
            }

            return Result.Success<IReadOnlyList<PkiCertificateMemory>, string>(
                MetadataBlobPayloadQueries.GetAttestationTrustAnchors(entry!, BaseMemoryPool.Shared));
        }
    }


    /// <summary>
    /// Reads a certificate file as either PEM or raw DER, returning a pooled
    /// <see cref="PkiCertificateMemory"/> carrier over its DER bytes.
    /// </summary>
    private static async ValueTask<PkiCertificateMemory> ReadCertificateFileAsync(string path, CancellationToken cancellationToken)
    {
        byte[] fileBytes = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        byte[] derBytes = ExtractDerBytes(fileBytes);

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(derBytes.Length);
        try
        {
            derBytes.CopyTo(owner.Memory);

            return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Extracts a certificate's DER bytes from <paramref name="fileBytes"/>, decoding a PEM envelope
    /// when present; otherwise returns <paramref name="fileBytes"/> unchanged as already-DER content.
    /// </summary>
    private static byte[] ExtractDerBytes(byte[] fileBytes)
    {
        ReadOnlySpan<byte> pemPrefix = "-----BEGIN"u8;
        if(fileBytes.Length < pemPrefix.Length || !fileBytes.AsSpan(0, pemPrefix.Length).SequenceEqual(pemPrefix))
        {
            return fileBytes;
        }

        string text = Encoding.ASCII.GetString(fileBytes);
        System.Security.Cryptography.PemFields fields = System.Security.Cryptography.PemEncoding.Find(text);

        return Convert.FromBase64String(text[fields.Base64Data]);
    }


    /// <summary>
    /// Computes the SHA-256 hash of <paramref name="rpId"/>'s UTF-8 bytes through the sync hash seam
    /// (<see cref="CryptographicKeyEvents.ComputeDigest"/>) — the same seam every other public-data
    /// hash in this codebase uses, mirroring <c>Fido2ClientDataHash.Compute</c>'s own call shape.
    /// </summary>
    private static DigestValue ComputeRpIdHash(string rpId, MemoryPool<byte> pool) =>
        CryptographicKeyEvents.ComputeDigest(Encoding.UTF8.GetBytes(rpId), 32, CryptoTags.Sha256Digest, pool);


    /// <summary>
    /// Names the single most specific reason a registration outcome was not acceptable: the
    /// attestation rejection's error code when the attestation itself was rejected, otherwise the
    /// first failing ceremony-rule claim.
    /// </summary>
    private static string DescribeRegistrationFailure(Fido2RegistrationOutcome outcome)
    {
        if(outcome.AttestationResult is RejectedAttestationResult rejected)
        {
            return $"Attestation rejected: {rejected.Error.Code}.";
        }

        foreach(Claim claim in outcome.Claims.Claims)
        {
            if(claim.Outcome == ClaimOutcome.Failure)
            {
                return $"Registration ceremony rule failed: {claim.Id}.";
            }
        }

        return "Registration was not acceptable for an unspecified reason.";
    }


    /// <summary>
    /// Names the single most specific reason an assertion outcome was not acceptable: the invalid
    /// signature itself, or otherwise the first failing ceremony-rule claim.
    /// </summary>
    private static string DescribeAssertionFailure(Fido2AssertionOutcome outcome)
    {
        if(!outcome.SignatureValid)
        {
            return "The assertion signature did not verify.";
        }

        foreach(Claim claim in outcome.Claims.Claims)
        {
            if(claim.Outcome == ClaimOutcome.Failure)
            {
                return $"Assertion ceremony rule failed: {claim.Id}.";
            }
        }

        return "Assertion was not acceptable for an unspecified reason.";
    }


    /// <summary>
    /// Writes the assertion verdict — <c>isAcceptable</c>, <c>signatureValid</c>, and the new
    /// <c>signCount</c> — as compact UTF-8 JSON via a manual <see cref="Utf8JsonWriter"/> (ruling 13:
    /// no reflection-based serialization in the AOT-published CLI).
    /// </summary>
    private static string WriteAssertionVerdict(Fido2AssertionOutcome outcome, uint newSignCount)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using(Utf8JsonWriter writer = new(buffer))
        {
            writer.WriteStartObject();
            writer.WriteBoolean("isAcceptable", outcome.IsAcceptable);
            writer.WriteBoolean("signatureValid", outcome.SignatureValid);
            writer.WriteNumber("signCount", newSignCount);
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }


    /// <summary>
    /// Runs an in-process WebAuthn L3 §7.2 authentication ceremony inside the observed-CBOM workload:
    /// mints an ephemeral P-256 credential, builds wire-shaped <c>authData</c>/<c>clientDataJSON</c>,
    /// signs their transcript through a <see cref="CryptographicKeyFactory"/>-created
    /// <see cref="PrivateKey"/> (so the sign event flows), and verifies through
    /// <see cref="Fido2AssertionVerifier"/> with the shipped codec defaults (so the verify path's
    /// event and Activity spans both flow) — the "observed FIDO2 provenance" ruling 3 asks
    /// <c>EmitCbom --observe</c> to show.
    /// </summary>
    /// <remarks>
    /// Internal rather than <see langword="private"/> so the integration test tying this workload to
    /// the <see cref="CryptographicKeyEvents"/> wiring (rulings 3+4) can invoke it directly, in-process,
    /// without spawning the CLI just to observe the event stream.
    /// </remarks>
    internal static async Task RunFido2ObservedWorkloadAsync(CancellationToken cancellationToken)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        //Routes through the CreateKeyPair choke point so the observed CBOM's provenance also carries the
        //KeyMaterialGeneratedEvent for this ceremony's mint step, completing mint+sign+verify coverage
        //(the sign step below already flows through PrivateKey.SignAsync's own choke point).
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm.P256, Purpose.Signing, pool);
        using PublicKeyMemory publicKeyMemory = keys.PublicKey;
        using PrivateKey privateKey = CryptographicKeyFactory.CreatePrivateKey(keys.PrivateKey, ObservedFido2WorkloadKeyIdentifier, keys.PrivateKey.Tag);

        DigestValue rpIdHash = ComputeRpIdHash(ObservedFido2WorkloadRpId, pool);
        byte[] authenticatorDataBytes = BuildObservedAuthenticatorData(rpIdHash.AsReadOnlySpan());
        byte[] clientDataJson = Encoding.UTF8.GetBytes(
            $$"""{"type":"webauthn.get","challenge":"{{ObservedFido2WorkloadChallenge}}","origin":"{{ObservedFido2WorkloadOrigin}}"}""");

        using DigestValue clientDataHash = Fido2ClientDataHash.Compute(clientDataJson, pool);
        byte[] toBeSigned = new byte[authenticatorDataBytes.Length + clientDataHash.Length];
        authenticatorDataBytes.CopyTo(toBeSigned, 0);
        clientDataHash.AsReadOnlySpan().CopyTo(toBeSigned.AsSpan(authenticatorDataBytes.Length));

        byte[] derSignature;
        Signature p1363Signature = await privateKey.SignAsync(toBeSigned, pool).ConfigureAwait(false);
        using(p1363Signature)
        {
            using IMemoryOwner<byte> derOwner = EcdsaSignatureEncoding.ConvertP1363ToDer(p1363Signature.AsReadOnlySpan(), pool, out int derLength);
            derSignature = derOwner.Memory.Span[..derLength].ToArray();
        }

        CoseKey credentialPublicKey = BuildObservedCredentialPublicKey(publicKeyMemory);

        using AssertionCeremonyInput ceremonyInput = new()
        {
            ClientData = ClientDataJsonReader.Read(clientDataJson),
            AuthenticatorData = AuthenticatorDataReader.Read(authenticatorDataBytes, CredentialPublicKeyCborReader.Read, pool),
            ExpectedChallenge = ObservedFido2WorkloadChallenge,
            ExpectedOrigins = new HashSet<string>(StringComparer.Ordinal) { ObservedFido2WorkloadOrigin },
            ExpectedRpIdHash = rpIdHash,
            //No other signal to base the policy on for this synthetic, non-CLI-exposed workload —
            //Discouraged, mirroring the registration verb's own "no other signal" reasoning.
            UserVerification = UserVerificationRequirement.Discouraged,
            StoredSignCount = 0,
            StoredUvInitialized = true
        };

        _ = await Fido2AssertionVerifier.VerifyAsync(
            credentialPublicKey,
            derSignature,
            authenticatorDataBytes,
            clientDataJson,
            ceremonyInput,
            "cbom-observed-fido2-workload",
            pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Assembles a WebAuthn L3 section 6.1 <c>authData</c> assertion-response layout: <c>rpIdHash</c>
    /// (32) | <c>flags</c> (<see cref="ObservedFido2WorkloadAuthenticatorDataFlags"/>) | <c>signCount</c>
    /// (4, big-endian, fixed at 1) — no attested credential data or extensions.
    /// </summary>
    private static byte[] BuildObservedAuthenticatorData(ReadOnlySpan<byte> rpIdHash)
    {
        byte[] buffer = new byte[37];
        rpIdHash.CopyTo(buffer);
        buffer[32] = ObservedFido2WorkloadAuthenticatorDataFlags;
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(33, 4), 1);

        return buffer;
    }


    /// <summary>
    /// Builds the EC2 P-256 <see cref="CoseKey"/> view of <paramref name="publicKey"/>, decompressing
    /// to recover the Y coordinate — the stored credential public key a relying party would have
    /// recorded at registration time.
    /// </summary>
    private static CoseKey BuildObservedCredentialPublicKey(PublicKeyMemory publicKey)
    {
        ReadOnlySpan<byte> compressed = publicKey.AsReadOnlySpan();
        EllipticCurveTypes curveType = EllipticCurveUtilities.CurveTypeFor(publicKey.Tag.Get<CryptoAlgorithm>());
        byte[] y = EllipticCurveUtilities.Decompress(compressed, curveType);

        return new CoseKey(kty: CoseKeyTypes.Ec2, alg: WellKnownCoseAlgorithms.Es256, curve: CoseKeyCurves.P256, x: compressed[1..].ToArray(), y: y);
    }


}
