using Verifiable.Core.Assessment;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Validation;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// VC Data Integrity 1.0 §4.6 Context Validation for a document whose proof already verified:
/// <see cref="ValidateAfterProofVerifiedAsync"/> runs the combined check, and the subtree half of
/// §4.6 step 3 ("any subtree in <c>result.validatedDocument</c> contains an <c>@context</c>
/// property") is shared by the credential and presentation verify paths so a document's
/// open-world <c>AdditionalData</c> bags (the materialized-JSON shape <c>Verifiable.Json</c>'s
/// manual readers produce) are walked identically in both.
/// </summary>
/// <remarks>
/// See <see href="https://www.w3.org/TR/vc-data-integrity/#context-validation">VC Data Integrity
/// 1.0 §4.6 Context Validation</see>.
/// </remarks>
internal static class ContextDeepValidation
{
    /// <summary>
    /// Runs context validation for a credential whose proof has already verified: context
    /// validation runs after the proof verifies, per
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">VC Data Integrity
    /// 1.0 §2.4.1 Validating Contexts</see>. The normative
    /// <see cref="ContextValidationRules.ValidateCredentialContextAsync"/> pipeline runs first,
    /// then the <see href="https://www.w3.org/TR/vc-data-integrity/#context-validation">§4.6
    /// Context Validation</see> deep-equality comparison against <paramref name="knownContext"/>
    /// and the no-nested-<c>@context</c> check.
    /// </summary>
    /// <param name="credential">The credential whose <c>@context</c> is validated.</param>
    /// <param name="knownContext">The application's known <c>@context</c>.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>
    /// <see langword="true"/> when the normative pipeline reports no failure, the credential's
    /// own <c>@context</c> deeply equals <paramref name="knownContext"/>, and no subtree carries
    /// a nested <c>@context</c> member; otherwise <see langword="false"/>.
    /// </returns>
    public static async ValueTask<bool> ValidateAfterProofVerifiedAsync(
        VerifiableCredential credential,
        Context knownContext,
        CancellationToken cancellationToken)
    {
        List<Claim> normativeContextClaims = await ContextValidationRules.ValidateCredentialContextAsync(credential, cancellationToken)
            .ConfigureAwait(false);

        return !(normativeContextClaims.Exists(static claim => claim.Outcome == ClaimOutcome.Failure)
            || credential.Context is not { } documentContext
            || !documentContext.Equals(knownContext)
            || HasNestedContextProperty(credential));
    }


    /// <summary>
    /// The subtree condition of VC Data Integrity 1.0 §4.6 step 3: no member of the credential or of
    /// any of its own open-world <c>AdditionalData</c> bags is literally named <c>@context</c>. The
    /// type carries no embedded or enveloped credential, so only the credential's own subtrees are
    /// walked.
    /// </summary>
    /// <param name="credential">The credential whose subtrees are walked.</param>
    /// <returns><see langword="true"/> when a nested <c>@context</c> member exists; otherwise <see langword="false"/>.</returns>
    private static bool HasNestedContextProperty(VerifiableCredential credential)
    {
        return ContainsContextKey(credential.AdditionalData)
            || ContainsContextKey(credential.Issuer?.AdditionalData)
            || AnyContainsContextKey(credential.CredentialSubject, static subject => subject.AdditionalData)
            || AnyContainsContextKey(credential.CredentialStatus, static status => status.AdditionalData)
            || AnyContainsContextKey(credential.CredentialSchema, static schema => schema.AdditionalData)
            || AnyContainsContextKey(credential.RelatedResource, static resource => resource.AdditionalData)
            || AnyContainsContextKey(credential.RefreshService, static service => service.AdditionalData)
            || AnyContainsContextKey(credential.TermsOfUse, static terms => terms.AdditionalData)
            || AnyContainsContextKey(credential.Evidence, static evidence => evidence.AdditionalData);
    }


    /// <summary>
    /// Applies <see cref="ContainsContextKey(IDictionary{string, object}?)"/> to every item's own
    /// bag in a possibly-<see langword="null"/> list.
    /// </summary>
    /// <typeparam name="TItem">The list element type.</typeparam>
    /// <param name="items">The list to walk, or <see langword="null"/>.</param>
    /// <param name="selectBag">Selects the element's own <c>AdditionalData</c> bag.</param>
    /// <returns><see langword="true"/> when any element's bag carries a nested <c>@context</c> member.</returns>
    public static bool AnyContainsContextKey<TItem>(List<TItem>? items, Func<TItem, IDictionary<string, object>?> selectBag)
    {
        if(items is null)
        {
            return false;
        }

        foreach(TItem item in items)
        {
            if(ContainsContextKey(selectBag(item)))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// <see langword="true"/> when <paramref name="bag"/>, or any materialized-JSON object nested
    /// inside it, carries a member literally named <c>@context</c>.
    /// </summary>
    /// <param name="bag">The bag to inspect, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when a nested <c>@context</c> member was found.</returns>
    public static bool ContainsContextKey(IDictionary<string, object>? bag)
    {
        if(bag is null)
        {
            return false;
        }

        foreach(KeyValuePair<string, object> entry in bag)
        {
            if(string.Equals(entry.Key, "@context", StringComparison.Ordinal) || ContainsContextKeyInValue(entry.Value))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Recurses into one materialized-JSON value: a nested object or array is walked further; a
    /// scalar carries no member and is never a match.
    /// </summary>
    /// <param name="value">The value to inspect.</param>
    /// <returns><see langword="true"/> when a nested <c>@context</c> member was found.</returns>
    private static bool ContainsContextKeyInValue(object? value)
    {
        return value switch
        {
            IReadOnlyDictionary<string, object> map => ContainsContextKeyInMap(map),
            IReadOnlyList<object> list => ContainsContextKeyInList(list),
            _ => false
        };
    }


    /// <summary>
    /// <see langword="true"/> when <paramref name="map"/>, or any value nested inside it, carries a
    /// member literally named <c>@context</c>.
    /// </summary>
    /// <param name="map">The materialized-JSON object to inspect.</param>
    /// <returns><see langword="true"/> when a nested <c>@context</c> member was found.</returns>
    private static bool ContainsContextKeyInMap(IReadOnlyDictionary<string, object> map)
    {
        foreach(KeyValuePair<string, object> entry in map)
        {
            if(string.Equals(entry.Key, "@context", StringComparison.Ordinal) || ContainsContextKeyInValue(entry.Value))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// <see langword="true"/> when any element of <paramref name="list"/> carries a nested
    /// <c>@context</c> member.
    /// </summary>
    /// <param name="list">The materialized-JSON array to inspect.</param>
    /// <returns><see langword="true"/> when a nested <c>@context</c> member was found.</returns>
    private static bool ContainsContextKeyInList(IReadOnlyList<object> list)
    {
        foreach(object item in list)
        {
            if(ContainsContextKeyInValue(item))
            {
                return true;
            }
        }

        return false;
    }
}
