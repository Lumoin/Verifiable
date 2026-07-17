using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Fido2;

/// <summary>
/// Orchestrates the WebAuthn L3 §7.1 registration ceremony verification: the <c>clientDataHash</c>
/// computation and attestation statement verification this library performs directly, composed
/// with the RP-supplied credential-id-uniqueness check (step 26) and the surface-field ceremony
/// rules in <see cref="Fido2ValidationProfiles.RegistrationRules"/>, ending with the step 27
/// credential record a relying party stores on success.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
/// Authentication Level 3, section 7.1: Registering a New Credential</see>. This type performs the
/// steps the rule list deliberately excludes — computing <c>hash</c> (step 12), dispatching and
/// running the attestation statement format's verification procedure (steps 21-23), checking
/// credential-id uniqueness (step 26), and building the credential record (step 27) — then runs
/// the remaining surface-field steps (7-11, 14-17, 20, 24-25) via the supplied
/// <see cref="ClaimIssuer{TInput}"/>.
/// </para>
/// <para>
/// The attestation statement is opaque at this layer: the caller supplies the already-parsed
/// <c>fmt</c> string, the raw <c>attStmt</c> bytes, and the parsed <see cref="AuthenticatorData"/>
/// plus its raw wire bytes. The outer <c>attestationObject</c> CBOR (<c>fmt</c>/<c>attStmt</c>/
/// <c>authData</c>) decoding is a codec-seam concern upstream of this orchestrator, mirroring how
/// <see cref="Fido2AssertionVerifier"/> stays independent of the CBOR/JSON codecs.
/// </para>
/// <para>
/// This is also the sole place that applies the ceremony's final-step (step 29) downgrade policy
/// (see <see cref="AttestationVerificationRequest.AcceptsUntrustedAttestationAsNone"/>'s remarks):
/// a certified attestation rejected purely for a trust-path shortfall is replaced with a
/// none-equivalent result before step 24's trust-gate rule runs, and
/// <see cref="Fido2ClaimIds.Fido2RegistrationAttestationDowngraded"/> is appended when that happens.
/// </para>
/// </remarks>
public static class Fido2RegistrationVerifier
{
    /// <summary>
    /// The issuer identifier stamped on <see cref="ClaimIssueResult.ClaimIssuerId"/> when the
    /// convenience overload builds its own <see cref="ClaimIssuer{TInput}"/> from
    /// <see cref="Fido2ValidationProfiles.RegistrationRules"/>.
    /// </summary>
    private const string DefaultIssuerId = "fido2-registration-verifier";


    /// <summary>
    /// Verifies a registration ceremony using a caller-supplied, already-configured
    /// <see cref="ClaimIssuer{TInput}"/> for the WebAuthn L3 §7.1 surface-field rules.
    /// </summary>
    /// <param name="attestationStatementFormat">The attestation statement format identifier (<c>fmt</c>).</param>
    /// <param name="attestationStatement">The raw, opaque <c>attStmt</c> CBOR bytes.</param>
    /// <param name="authenticatorDataBytes">The raw <c>authData</c> wire bytes the attestation signature covers.</param>
    /// <param name="clientDataJson">The raw <c>clientDataJSON</c> wire bytes.</param>
    /// <param name="ceremonyInput">
    /// The surface-field ceremony input the WebAuthn L3 §7.1 rules evaluate. Its
    /// <see cref="RegistrationCeremonyInput.AuthenticatorData"/> must be the parsed view aliasing
    /// <paramref name="authenticatorDataBytes"/>; its own
    /// <see cref="RegistrationCeremonyInput.AttestationResult"/> is overwritten with the result
    /// this method computes.
    /// </param>
    /// <param name="claimIssuer">The configured claim issuer to run the effective ceremony input through.</param>
    /// <param name="selectAttestationVerifier">Selects the verification procedure for <paramref name="attestationStatementFormat"/>.</param>
    /// <param name="isCredentialIdUnique">The RP-supplied step 26 credential-id-uniqueness check.</param>
    /// <param name="trustAnchors">The trust anchor certificates for a certified attestation's certificate path.</param>
    /// <param name="validationTime">The time at which to evaluate certificate validity during chain validation.</param>
    /// <param name="correlationId">Identifier correlating this verification with other operations.</param>
    /// <param name="pool">The memory pool the verification's working buffers rent from.</param>
    /// <param name="transports">
    /// The transports reported by <c>AuthenticatorAttestationResponse.getTransports()</c>, carried
    /// into the built <see cref="Fido2CredentialRecord.Transports"/> verbatim since they come from
    /// the client response, not <paramref name="authenticatorDataBytes"/>. Defaults to an empty
    /// list when omitted.
    /// </param>
    /// <param name="authenticatorAttachment">
    /// The client-reported <c>authenticatorAttachment</c> value, carried into the built
    /// <see cref="Fido2CredentialRecord.AuthenticatorAttachment"/> after normalization — like
    /// <paramref name="transports"/>, this comes from the client response, not
    /// <paramref name="authenticatorDataBytes"/>, so a verifier operating on wire bytes alone cannot
    /// derive it. Defaults to <see langword="null"/> when omitted.
    /// </param>
    /// <param name="acceptsUntrustedAttestationAsNone">
    /// Whether a certified attestation whose trust path did not reach a supplied anchor is
    /// downgraded to a none-equivalent result, per
    /// <see cref="AttestationVerificationRequest.AcceptsUntrustedAttestationAsNone"/>'s remarks.
    /// Defaults to <see langword="false"/> — today's fail-closed rejection, unchanged.
    /// </param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>The combined attestation, ceremony-rule, and credential-record outcome.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="ceremonyInput"/>, <paramref name="claimIssuer"/>,
    /// <paramref name="selectAttestationVerifier"/>, <paramref name="isCredentialIdUnique"/>,
    /// <paramref name="trustAnchors"/> or <paramref name="pool"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="attestationStatementFormat"/> or <paramref name="correlationId"/> is
    /// <see langword="null"/> or empty.
    /// </exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the built Fido2CredentialRecord (and its owned CredentialId copy) transfers to the caller via the returned Fido2RegistrationOutcome; a relying party persists the record beyond this call's scope and disposes it on its own schedule.")]
    public static async ValueTask<Fido2RegistrationOutcome> VerifyAsync(
        string attestationStatementFormat,
        ReadOnlyMemory<byte> attestationStatement,
        ReadOnlyMemory<byte> authenticatorDataBytes,
        ReadOnlyMemory<byte> clientDataJson,
        RegistrationCeremonyInput ceremonyInput,
        ClaimIssuer<RegistrationCeremonyInput> claimIssuer,
        SelectAttestationVerifierDelegate selectAttestationVerifier,
        IsCredentialIdUniqueDelegate isCredentialIdUnique,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        DateTimeOffset validationTime,
        string correlationId,
        MemoryPool<byte> pool,
        IReadOnlyList<string>? transports = null,
        string? authenticatorAttachment = null,
        bool acceptsUntrustedAttestationAsNone = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(attestationStatementFormat);
        ArgumentNullException.ThrowIfNull(ceremonyInput);
        ArgumentNullException.ThrowIfNull(claimIssuer);
        ArgumentNullException.ThrowIfNull(selectAttestationVerifier);
        ArgumentNullException.ThrowIfNull(isCredentialIdUnique);
        ArgumentNullException.ThrowIfNull(trustAnchors);
        ArgumentException.ThrowIfNullOrEmpty(correlationId);
        ArgumentNullException.ThrowIfNull(pool);

        AttestedCredentialData? attestedCredentialData = ceremonyInput.AuthenticatorData.AttestedCredentialData;

        bool credentialIdUnique = await TryCheckCredentialIdUniqueAsync(
            isCredentialIdUnique, attestedCredentialData, cancellationToken).ConfigureAwait(false);

        AttestationResult attestationResult = await ResolveAttestationResultAsync(
            attestationStatementFormat, attestationStatement, ceremonyInput.AuthenticatorData, authenticatorDataBytes,
            clientDataJson, selectAttestationVerifier, trustAnchors, validationTime, pool, acceptsUntrustedAttestationAsNone,
            cancellationToken).ConfigureAwait(false);

        RegistrationCeremonyInput effectiveInput = ceremonyInput with { AttestationResult = attestationResult };

        ClaimIssueResult ruleClaims = await claimIssuer.GenerateClaimsAsync(effectiveInput, correlationId, cancellationToken).ConfigureAwait(false);
        ClaimIssueResult claims = AppendCredentialIdUniqueClaim(ruleClaims, attestedCredentialData, credentialIdUnique);
        claims = AppendAttestationDowngradedClaim(claims, attestationResult);

        bool isAcceptable = !HasFailure(claims) && attestationResult is not RejectedAttestationResult;

        Fido2CredentialRecord? credentialRecord = isAcceptable
            ? BuildCredentialRecord(ceremonyInput.AuthenticatorData, transports ?? [], authenticatorAttachment, pool)
            : null;

        return new Fido2RegistrationOutcome(attestationResult, claims, isAcceptable, credentialRecord);
    }


    /// <summary>
    /// Convenience overload that builds its own <see cref="ClaimIssuer{TInput}"/> from
    /// <see cref="Fido2ValidationProfiles.RegistrationRules"/> and the supplied
    /// <paramref name="timeProvider"/>, for callers with no need for a custom rule list.
    /// </summary>
    /// <param name="attestationStatementFormat">The attestation statement format identifier (<c>fmt</c>).</param>
    /// <param name="attestationStatement">The raw, opaque <c>attStmt</c> CBOR bytes.</param>
    /// <param name="authenticatorDataBytes">The raw <c>authData</c> wire bytes the attestation signature covers.</param>
    /// <param name="clientDataJson">The raw <c>clientDataJSON</c> wire bytes.</param>
    /// <param name="ceremonyInput">
    /// The surface-field ceremony input the WebAuthn L3 §7.1 rules evaluate. Its
    /// <see cref="RegistrationCeremonyInput.AuthenticatorData"/> must be the parsed view aliasing
    /// <paramref name="authenticatorDataBytes"/>; its own
    /// <see cref="RegistrationCeremonyInput.AttestationResult"/> is overwritten with the result
    /// this method computes.
    /// </param>
    /// <param name="selectAttestationVerifier">Selects the verification procedure for <paramref name="attestationStatementFormat"/>.</param>
    /// <param name="isCredentialIdUnique">The RP-supplied step 26 credential-id-uniqueness check.</param>
    /// <param name="trustAnchors">The trust anchor certificates for a certified attestation's certificate path.</param>
    /// <param name="validationTime">The time at which to evaluate certificate validity during chain validation.</param>
    /// <param name="correlationId">Identifier correlating this verification with other operations.</param>
    /// <param name="pool">The memory pool the verification's working buffers rent from.</param>
    /// <param name="transports">
    /// The transports reported by <c>AuthenticatorAttestationResponse.getTransports()</c>. Defaults
    /// to an empty list when omitted.
    /// </param>
    /// <param name="authenticatorAttachment">
    /// The client-reported <c>authenticatorAttachment</c> value; see the other overload's parameter
    /// of the same name. Defaults to <see langword="null"/> when omitted.
    /// </param>
    /// <param name="acceptsUntrustedAttestationAsNone">
    /// Whether a certified attestation whose trust path did not reach a supplied anchor is
    /// downgraded to a none-equivalent result; see the other overload's parameter of the same name.
    /// Defaults to <see langword="false"/>.
    /// </param>
    /// <param name="timeProvider">
    /// Time provider for <see cref="ClaimIssueResult.CreationTimestampInUtc"/> stamping. When
    /// <see langword="null"/>, <see cref="TimeProvider.System"/> is used.
    /// </param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>The combined attestation, ceremony-rule, and credential-record outcome.</returns>
    public static ValueTask<Fido2RegistrationOutcome> VerifyAsync(
        string attestationStatementFormat,
        ReadOnlyMemory<byte> attestationStatement,
        ReadOnlyMemory<byte> authenticatorDataBytes,
        ReadOnlyMemory<byte> clientDataJson,
        RegistrationCeremonyInput ceremonyInput,
        SelectAttestationVerifierDelegate selectAttestationVerifier,
        IsCredentialIdUniqueDelegate isCredentialIdUnique,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        DateTimeOffset validationTime,
        string correlationId,
        MemoryPool<byte> pool,
        IReadOnlyList<string>? transports = null,
        string? authenticatorAttachment = null,
        bool acceptsUntrustedAttestationAsNone = false,
        TimeProvider? timeProvider = null,
        CancellationToken cancellationToken = default)
    {
        var claimIssuer = new ClaimIssuer<RegistrationCeremonyInput>(
            DefaultIssuerId, Fido2ValidationProfiles.RegistrationRules(), timeProvider);

        return VerifyAsync(
            attestationStatementFormat, attestationStatement, authenticatorDataBytes, clientDataJson, ceremonyInput,
            claimIssuer, selectAttestationVerifier, isCredentialIdUnique, trustAnchors, validationTime, correlationId,
            pool, transports, authenticatorAttachment, acceptsUntrustedAttestationAsNone, cancellationToken);
    }


    /// <summary>
    /// Convenience overload that reads <paramref name="timeProvider"/>'s clock once so every window
    /// check in one verification — certificate chain validity and <see cref="ClaimIssueResult.CreationTimestampInUtc"/>
    /// stamping alike — shares one instant, then delegates to the instant-taking overload.
    /// </summary>
    /// <param name="attestationStatementFormat">The attestation statement format identifier (<c>fmt</c>).</param>
    /// <param name="attestationStatement">The raw, opaque <c>attStmt</c> CBOR bytes.</param>
    /// <param name="authenticatorDataBytes">The raw <c>authData</c> wire bytes the attestation signature covers.</param>
    /// <param name="clientDataJson">The raw <c>clientDataJSON</c> wire bytes.</param>
    /// <param name="ceremonyInput">
    /// The surface-field ceremony input the WebAuthn L3 §7.1 rules evaluate. Its
    /// <see cref="RegistrationCeremonyInput.AuthenticatorData"/> must be the parsed view aliasing
    /// <paramref name="authenticatorDataBytes"/>; its own
    /// <see cref="RegistrationCeremonyInput.AttestationResult"/> is overwritten with the result
    /// this method computes.
    /// </param>
    /// <param name="selectAttestationVerifier">Selects the verification procedure for <paramref name="attestationStatementFormat"/>.</param>
    /// <param name="isCredentialIdUnique">The RP-supplied step 26 credential-id-uniqueness check.</param>
    /// <param name="trustAnchors">The trust anchor certificates for a certified attestation's certificate path.</param>
    /// <param name="timeProvider">
    /// The time provider read once, via <see cref="TimeProvider.GetUtcNow"/>, to obtain the instant
    /// used both for certificate chain validity evaluation and for
    /// <see cref="ClaimIssueResult.CreationTimestampInUtc"/> stamping.
    /// </param>
    /// <param name="correlationId">Identifier correlating this verification with other operations.</param>
    /// <param name="pool">The memory pool the verification's working buffers rent from.</param>
    /// <param name="transports">
    /// The transports reported by <c>AuthenticatorAttestationResponse.getTransports()</c>. Defaults
    /// to an empty list when omitted.
    /// </param>
    /// <param name="authenticatorAttachment">
    /// The client-reported <c>authenticatorAttachment</c> value; see the other overload's parameter
    /// of the same name. Defaults to <see langword="null"/> when omitted.
    /// </param>
    /// <param name="acceptsUntrustedAttestationAsNone">
    /// Whether a certified attestation whose trust path did not reach a supplied anchor is
    /// downgraded to a none-equivalent result; see the other overload's parameter of the same name.
    /// Defaults to <see langword="false"/>.
    /// </param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>The combined attestation, ceremony-rule, and credential-record outcome.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="timeProvider"/> is <see langword="null"/>.</exception>
    public static ValueTask<Fido2RegistrationOutcome> VerifyAsync(
        string attestationStatementFormat,
        ReadOnlyMemory<byte> attestationStatement,
        ReadOnlyMemory<byte> authenticatorDataBytes,
        ReadOnlyMemory<byte> clientDataJson,
        RegistrationCeremonyInput ceremonyInput,
        SelectAttestationVerifierDelegate selectAttestationVerifier,
        IsCredentialIdUniqueDelegate isCredentialIdUnique,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        TimeProvider timeProvider,
        string correlationId,
        MemoryPool<byte> pool,
        IReadOnlyList<string>? transports = null,
        string? authenticatorAttachment = null,
        bool acceptsUntrustedAttestationAsNone = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);

        DateTimeOffset validationTime = timeProvider.GetUtcNow();

        return VerifyAsync(
            attestationStatementFormat, attestationStatement, authenticatorDataBytes, clientDataJson, ceremonyInput,
            selectAttestationVerifier, isCredentialIdUnique, trustAnchors, validationTime, correlationId,
            pool, transports, authenticatorAttachment, acceptsUntrustedAttestationAsNone, timeProvider, cancellationToken);
    }


    /// <summary>
    /// Dispatches and runs the attestation statement format's verification procedure (steps
    /// 21-23), fail-closed: an unregistered <c>fmt</c> or any thrown crypto/format error yields a
    /// <see cref="RejectedAttestationResult"/> rather than escaping as an exception. Applies the
    /// row-6107 downgrade policy (see <see cref="TryDowngrade"/>) to the raw result before
    /// returning, so this is the one place in <see cref="Fido2RegistrationVerifier"/> that resolves
    /// the final <see cref="AttestationResult"/> — the caller's ceremony-input overwrite and its
    /// acceptability gate both consume this method's return value directly, so neither ever sees
    /// the pre-downgrade rejection.
    /// </summary>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Attestation dispatch is fail-closed: any crypto/format error, expected or not, must resolve to a rejected result rather than crash the caller.")]
    private static async ValueTask<AttestationResult> ResolveAttestationResultAsync(
        string attestationStatementFormat,
        ReadOnlyMemory<byte> attestationStatement,
        AuthenticatorData authenticatorData,
        ReadOnlyMemory<byte> authenticatorDataBytes,
        ReadOnlyMemory<byte> clientDataJson,
        SelectAttestationVerifierDelegate selectAttestationVerifier,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        DateTimeOffset validationTime,
        MemoryPool<byte> pool,
        bool acceptsUntrustedAttestationAsNone,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            AttestationVerifyDelegate? verify = selectAttestationVerifier(attestationStatementFormat);
            if(verify is null)
            {
                return new RejectedAttestationResult(Fido2AttestationErrors.UnregisteredFormat);
            }

            using DigestValue clientDataHash = Fido2ClientDataHash.Compute(clientDataJson.Span, pool);
            var request = new AttestationVerificationRequest(
                authenticatorDataBytes, authenticatorData, clientDataHash, attestationStatement, trustAnchors, validationTime, pool)
            {
                AcceptsUntrustedAttestationAsNone = acceptsUntrustedAttestationAsNone
            };

            AttestationResult result = await verify(request, cancellationToken).ConfigureAwait(false);

            return TryDowngrade(attestationStatementFormat, result, acceptsUntrustedAttestationAsNone);
        }
        catch(OperationCanceledException) when(cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch(Exception)
        {
            return new RejectedAttestationResult(Fido2AttestationErrors.VerificationFailed);
        }
    }


    /// <summary>
    /// Applies the row-6107 downgrade policy: when the relying party opted in
    /// (<paramref name="acceptsUntrustedAttestationAsNone"/>) and <paramref name="result"/> was
    /// rejected purely for a trust-path shortfall (<see cref="IsDowngradeEligible"/>) — never for a
    /// malformed statement or an invalid signature, both of which occur before or independent of
    /// the trust-path check — replaces it with a <see cref="NoneAttestationResult"/> carrying a
    /// <see cref="Fido2AttestationDowngrade"/> audit marker; otherwise returns
    /// <paramref name="result"/> unchanged.
    /// </summary>
    private static AttestationResult TryDowngrade(string attestationStatementFormat, AttestationResult result, bool acceptsUntrustedAttestationAsNone)
    {
        if(!acceptsUntrustedAttestationAsNone
            || result is not RejectedAttestationResult { Error: Fido2AttestationError error }
            || !IsDowngradeEligible(error))
        {
            return result;
        }

        return new NoneAttestationResult(new Fido2AttestationDowngrade(attestationStatementFormat, error));
    }


    /// <summary>
    /// Determines whether <paramref name="error"/> is one of the two trust-path-shortfall
    /// conditions the row-6107 downgrade policy may act on. Every other
    /// <see cref="RejectedAttestationResult"/> reason — an invalid signature, a malformed
    /// statement, or any other structural/cryptographic failure — is never eligible.
    /// </summary>
    private static bool IsDowngradeEligible(Fido2AttestationError error) =>
        error == Fido2AttestationErrors.NoTrustAnchors || error == Fido2AttestationErrors.ChainValidationFailed;


    /// <summary>
    /// Appends <see cref="Fido2ClaimIds.Fido2RegistrationAttestationDowngraded"/> when
    /// <paramref name="attestationResult"/> is a downgraded <see cref="NoneAttestationResult"/>;
    /// otherwise returns <paramref name="claims"/> unchanged — this claim is emitted only on the
    /// downgrade path, per its own doc comment, not as a claim carrying some other outcome for the
    /// ordinary case.
    /// </summary>
    private static ClaimIssueResult AppendAttestationDowngradedClaim(ClaimIssueResult claims, AttestationResult attestationResult)
    {
        if(attestationResult is not NoneAttestationResult { Downgrade: Fido2AttestationDowngrade downgrade })
        {
            return claims;
        }

        List<Claim> merged = [.. claims.Claims, new Claim(
            Fido2ClaimIds.Fido2RegistrationAttestationDowngraded,
            ClaimOutcome.Success,
            new Fido2AttestationDowngradeClaimContext(downgrade),
            Claim.NoSubClaims)];

        return claims with { Claims = merged };
    }


    /// <summary>
    /// Runs the RP-supplied step 26 credential-id-uniqueness check, fail-closed: a missing
    /// attested credential data has nothing to check (the caller reports
    /// <see cref="ClaimOutcome.NotApplicable"/> for that case, so the returned value here is
    /// discarded), and any thrown exception from the RP's own storage lookup — other than a
    /// genuine cancellation — is treated as "not verified unique" rather than escaping.
    /// </summary>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "The RP-supplied storage lookup is fail-closed: any error must resolve to \"not verified unique\" rather than crash the caller.")]
    private static async ValueTask<bool> TryCheckCredentialIdUniqueAsync(
        IsCredentialIdUniqueDelegate isCredentialIdUnique,
        AttestedCredentialData? attestedCredentialData,
        CancellationToken cancellationToken)
    {
        if(attestedCredentialData is null)
        {
            return false;
        }

        try
        {
            return await isCredentialIdUnique(attestedCredentialData.CredentialId, cancellationToken).ConfigureAwait(false);
        }
        catch(OperationCanceledException) when(cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch(Exception)
        {
            return false;
        }
    }


    /// <summary>
    /// Appends the step 26 credential-id-uniqueness claim to <paramref name="claims"/>:
    /// <see cref="ClaimOutcome.NotApplicable"/> when there is no attested credential data to check,
    /// otherwise <see cref="ClaimOutcome.Success"/> or <see cref="ClaimOutcome.Failure"/> from
    /// <paramref name="credentialIdUnique"/>.
    /// </summary>
    private static ClaimIssueResult AppendCredentialIdUniqueClaim(
        ClaimIssueResult claims, AttestedCredentialData? attestedCredentialData, bool credentialIdUnique)
    {
        ClaimOutcome outcome = attestedCredentialData is null
            ? ClaimOutcome.NotApplicable
            : credentialIdUnique ? ClaimOutcome.Success : ClaimOutcome.Failure;

        List<Claim> merged = [.. claims.Claims, new Claim(Fido2ClaimIds.Fido2RegistrationCredentialIdUnique, outcome)];

        return claims with { Claims = merged };
    }


    /// <summary>
    /// Builds the step 27 credential record from the verified <paramref name="authenticatorData"/>'s
    /// attested credential data and flags, and the caller-supplied <paramref name="transports"/> and
    /// <paramref name="authenticatorAttachment"/>.
    /// </summary>
    /// <param name="authenticatorData">The verified <c>authData</c> view to build the record from.</param>
    /// <param name="transports">The transports to carry into the built record.</param>
    /// <param name="authenticatorAttachment">
    /// The client-reported <c>authenticatorAttachment</c> value to normalize (via
    /// <see cref="WellKnownAuthenticatorAttachments.NormalizeOrDefault"/> — unknown values become
    /// <see langword="null"/>, per <see href="https://www.w3.org/TR/webauthn-3/#iface-pkcredential">W3C
    /// Web Authentication Level 3, section 5.1</see>'s "treat unknown values as if the value were
    /// null") and carry into the built record.
    /// </param>
    /// <param name="pool">
    /// The memory pool the record's own <see cref="Fido2CredentialRecord.Id"/> copy rents from. A
    /// fresh copy is required — not the same <see cref="CredentialId"/> instance
    /// <paramref name="authenticatorData"/> owns — because the record is expected to outlive the
    /// ceremony-scoped <paramref name="authenticatorData"/> a caller disposes once verification
    /// completes.
    /// </param>
    /// <returns>
    /// The built record, or <see langword="null"/> when <paramref name="authenticatorData"/>
    /// carries no attested credential data — unreachable on an acceptable outcome, since
    /// <see cref="Fido2RegistrationChecks.CheckRegistrationCredentialAlgorithm"/> and
    /// <see cref="Fido2RegistrationChecks.CheckRegistrationCredentialIdLength"/> both fail without
    /// it, but handled without throwing regardless.
    /// </returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the fresh CredentialId copy transfers to the returned Fido2CredentialRecord, which in turn transfers to the caller via VerifyAsync's returned outcome.")]
    private static Fido2CredentialRecord? BuildCredentialRecord(
        AuthenticatorData authenticatorData, IReadOnlyList<string> transports, string? authenticatorAttachment, MemoryPool<byte> pool)
    {
        if(authenticatorData.AttestedCredentialData is not { } attestedCredentialData)
        {
            return null;
        }

        AuthenticatorDataFlags flags = authenticatorData.Flags;
        CredentialId credentialId = CredentialId.Create(attestedCredentialData.CredentialId.AsReadOnlySpan(), pool);

        return new Fido2CredentialRecord(
            WellKnownPublicKeyCredentialTypes.PublicKey,
            credentialId,
            attestedCredentialData.CredentialPublicKey,
            authenticatorData.SignCount,
            flags.UserVerified,
            transports,
            flags.BackupEligible,
            flags.BackupState,
            WellKnownAuthenticatorAttachments.NormalizeOrDefault(authenticatorAttachment));
    }


    /// <summary>
    /// Determines whether <paramref name="claims"/> contains at least one
    /// <see cref="ClaimOutcome.Failure"/> claim.
    /// </summary>
    private static bool HasFailure(ClaimIssueResult claims)
    {
        foreach(Claim claim in claims.Claims)
        {
            if(claim.Outcome == ClaimOutcome.Failure)
            {
                return true;
            }
        }

        return false;
    }
}
