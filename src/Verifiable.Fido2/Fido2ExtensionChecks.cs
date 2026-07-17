using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Assessment;

namespace Verifiable.Fido2;

/// <summary>
/// Validation check functions for WebAuthn extension output processing, shared by both ceremonies.
/// Each function matches the <see cref="ClaimDelegateAsync{TInput}"/> signature for composition
/// via <see cref="ClaimIssuer{TInput}"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">W3C Web Authentication Level 3,
/// section 9: WebAuthn Extensions</see>.
/// </para>
/// <para>
/// Both checks share one semantics: group the ceremony's client and authenticator extension
/// outputs by identifier (ordinal — the
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-extension-id">section 9.1</see> case-sensitive
/// match MUST), dispatch each identifier to its registered
/// <see cref="ExtensionOutputProcessDelegate"/> when one exists, and fold every processor's claims
/// into the result alongside one ceremony-level claim summarizing whether processing itself
/// succeeded. No processor ever runs for an identifier the relying party did not register — an
/// unregistered identifier is silently skipped by default, satisfying section 9's "Relying Parties
/// MUST be prepared to handle cases where some or all of those extensions are ignored" — and a
/// thrown processor exception (other than genuine cancellation) fails only the ceremony-level
/// claim, never escapes as an exception.
/// </para>
/// </remarks>
public static class Fido2ExtensionChecks
{
    /// <summary>
    /// Checks the registration ceremony's client and authenticator extension outputs.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#reg-ceremony-verify-extension-outputs">W3C Web
    /// Authentication Level 3, section 7.1: Registering a New Credential</see>, step 28.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckRegistrationExtensionOutputs(
        RegistrationCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        return ProcessExtensionOutputsAsync(
            Fido2ClaimIds.Fido2RegistrationExtensionOutputs,
            input.ClientExtensionOutputs,
            input.AuthenticatorExtensionOutputs,
            input.ExtensionOutputProcessor,
            input.RejectUnregisteredExtensionOutputs,
            input.ExtensionProcessingPool,
            cancellationToken);
    }


    /// <summary>
    /// Checks the assertion ceremony's client and authenticator extension outputs.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#authn-ceremony-verify-extension-outputs">W3C
    /// Web Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, step 23.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckAssertionExtensionOutputs(
        AssertionCeremonyInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();

        return ProcessExtensionOutputsAsync(
            Fido2ClaimIds.Fido2AssertionExtensionOutputs,
            input.ClientExtensionOutputs,
            input.AuthenticatorExtensionOutputs,
            input.ExtensionOutputProcessor,
            input.RejectUnregisteredExtensionOutputs,
            input.ExtensionProcessingPool,
            cancellationToken);
    }


    /// <summary>
    /// Runs every present extension identifier's registered processor and folds the result into one
    /// claim list carrying a single ceremony-level claim, <paramref name="ceremonyClaimId"/>.
    /// </summary>
    /// <param name="ceremonyClaimId">The ceremony-level claim identifier to report.</param>
    /// <param name="clientExtensionOutputs">The ceremony's decoded client extension outputs.</param>
    /// <param name="authenticatorExtensionOutputs">The ceremony's decoded authenticator extension outputs.</param>
    /// <param name="extensionOutputProcessor">The relying party's processor selector, or <see langword="null"/>.</param>
    /// <param name="rejectUnregisteredExtensionOutputs">
    /// Whether a present identifier with no registered processor fails <paramref name="ceremonyClaimId"/>.
    /// </param>
    /// <param name="extensionProcessingPool">The memory pool each processor's request carries.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The processed claims, always ending with the ceremony-level claim.</returns>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types",
        Justification = "A processor's failure is reported as this ceremony's extension-output claim failing, fail-closed, rather than escaping and aborting the surrounding rule pipeline.")]
    private static async ValueTask<List<Claim>> ProcessExtensionOutputsAsync(
        ClaimId ceremonyClaimId,
        IReadOnlyList<Fido2ExtensionOutput>? clientExtensionOutputs,
        IReadOnlyList<Fido2ExtensionOutput>? authenticatorExtensionOutputs,
        SelectExtensionOutputProcessorDelegate? extensionOutputProcessor,
        bool rejectUnregisteredExtensionOutputs,
        MemoryPool<byte> extensionProcessingPool,
        CancellationToken cancellationToken)
    {
        bool hasClientOutputs = clientExtensionOutputs is { Count: > 0 };
        bool hasAuthenticatorOutputs = authenticatorExtensionOutputs is { Count: > 0 };
        if(!hasClientOutputs && !hasAuthenticatorOutputs)
        {
            //Section 9: extensions are OPTIONAL, so a ceremony carrying none is not a failure —
            //the "works with nothing" posture this claim exists to prove.
            return [new Claim(ceremonyClaimId, ClaimOutcome.NotApplicable)];
        }

        List<Claim> claims = [];
        ClaimOutcome ceremonyOutcome = ClaimOutcome.Success;
        foreach(string identifier in DistinctIdentifiers(clientExtensionOutputs, authenticatorExtensionOutputs))
        {
            ExtensionOutputProcessDelegate? processor = extensionOutputProcessor?.Invoke(identifier);
            if(processor is null)
            {
                if(rejectUnregisteredExtensionOutputs)
                {
                    ceremonyOutcome = ClaimOutcome.Failure;
                }

                continue;
            }

            var request = new ExtensionOutputProcessingRequest(
                identifier,
                FindValue(clientExtensionOutputs, identifier),
                FindValue(authenticatorExtensionOutputs, identifier),
                extensionProcessingPool);

            try
            {
                List<Claim> processorClaims = await processor(request, cancellationToken).ConfigureAwait(false);
                claims.AddRange(processorClaims);
            }
            catch(OperationCanceledException) when(cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch(Exception)
            {
                ceremonyOutcome = ClaimOutcome.Failure;
            }
        }

        claims.Add(new Claim(ceremonyClaimId, ceremonyOutcome));

        return claims;

        //Collects every identifier present on either side, ordinal-deduplicated, in first-seen
        //order (client outputs first, then any authenticator-only identifiers) — the grouping
        //step section 9's per-extension processing implies.
        static List<string> DistinctIdentifiers(
            IReadOnlyList<Fido2ExtensionOutput>? clientOutputs,
            IReadOnlyList<Fido2ExtensionOutput>? authenticatorOutputs)
        {
            HashSet<string> seen = new(StringComparer.Ordinal);
            List<string> identifiers = [];
            foreach(Fido2ExtensionOutput output in clientOutputs ?? [])
            {
                if(seen.Add(output.Identifier))
                {
                    identifiers.Add(output.Identifier);
                }
            }

            foreach(Fido2ExtensionOutput output in authenticatorOutputs ?? [])
            {
                if(seen.Add(output.Identifier))
                {
                    identifiers.Add(output.Identifier);
                }
            }

            return identifiers;
        }

        //Finds the ordinal-matching entry's value slice for one identifier on one side, or null
        //when that side carries no output for it.
        static ReadOnlyMemory<byte>? FindValue(IReadOnlyList<Fido2ExtensionOutput>? outputs, string identifier)
        {
            if(outputs is null)
            {
                return null;
            }

            foreach(Fido2ExtensionOutput output in outputs)
            {
                if(string.Equals(output.Identifier, identifier, StringComparison.Ordinal))
                {
                    return output.Value;
                }
            }

            return null;
        }
    }
}
