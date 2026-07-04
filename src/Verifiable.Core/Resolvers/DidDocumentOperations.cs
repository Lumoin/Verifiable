using System;
using System.Collections.Generic;
using Verifiable.Core.Model.Did;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// One step of a DIF DID Registration multi-operation <c>update</c>: a single <c>didDocumentOperation</c> paired with
/// the DID document operand it applies. The DIF
/// <see href="https://identity.foundation/did-registration/#update">update</see> function carries
/// <c>didDocumentOperation</c> and <c>didDocument</c> as two index-paired JSON arrays; this record is the paired form,
/// so an operation can never become separated from its operand (the wire's parallel arrays are zipped into steps at
/// the serialization boundary).
/// </summary>
/// <param name="Operation">
/// The DIF <c>didDocumentOperation</c> for this step — one of
/// <see cref="WellKnownDidRegistrationValues.SetDidDocument"/>,
/// <see cref="WellKnownDidRegistrationValues.AddToDidDocument"/>, or
/// <see cref="WellKnownDidRegistrationValues.RemoveFromDidDocument"/>.
/// </param>
/// <param name="Document">The DID document operand this operation applies (the replacement, additions, or removals).</param>
public sealed record DidDocumentOperationStep(string Operation, DidDocument Document);

/// <summary>
/// Applies a DIF <c>didDocumentOperation</c> to a DID document, producing a new document. This is the pure
/// document algebra behind a DID Registration <c>update</c>: the three standard operations
/// (<see cref="WellKnownDidRegistrationValues.SetDidDocument"/>,
/// <see cref="WellKnownDidRegistrationValues.AddToDidDocument"/>,
/// <see cref="WellKnownDidRegistrationValues.RemoveFromDidDocument"/>) transform a document independently of any
/// DID method, transport, or proof mechanism, so the same algebra is reusable wherever a DID document is merged
/// or pruned (not only in the registration flow).
/// </summary>
/// <remarks>
/// <para>
/// See the DIF
/// <see href="https://identity.foundation/did-registration/#update">update(did, options, secret, didDocumentOperation, didDocument)</see>
/// function and its
/// <see href="https://identity.foundation/did-registration/#diddocumentoperation">didDocumentOperation</see> values.
/// </para>
/// <para>
/// The operations are defined per top-level member, by identity:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <c>setDidDocument</c> replaces the document wholesale (the supplied document becomes the result; the
///     current document is ignored).
///   </description></item>
///   <item><description>
///     <c>addToDidDocument</c> unions each array member of the current document with the supplied document's,
///     keyed by identity (the <c>id</c> of a verification method, verification-relationship reference or service;
///     value equality for <c>controller</c> and <c>alsoKnownAs</c>). The current document's identity
///     (<c>@context</c>, <c>id</c>) and any extension members are preserved.
///   </description></item>
///   <item><description>
///     <c>removeFromDidDocument</c> drops from each array member of the current document the entries whose
///     identity appears in the supplied document, again preserving the current document's identity and
///     extension members. An array emptied by the removal becomes absent.
///   </description></item>
/// </list>
/// <para>
/// The <c>deactivate</c> extension value is a flow-level concern (it produces a deactivated DID, not a document
/// transform) and is rejected here. Extension members captured in <see cref="DidDocument.AdditionalData"/> are
/// carried over verbatim from the current document on add/remove but not themselves merged or pruned — only the
/// modelled core members participate in the algebra.
/// </para>
/// <para>
/// The inputs are never mutated; add and remove build a new <see cref="DidDocument"/>.
/// </para>
/// </remarks>
public static class DidDocumentOperations
{
    /// <summary>
    /// Applies <paramref name="operation"/> to <paramref name="current"/> using <paramref name="payload"/> as the
    /// operand, returning the resulting DID document.
    /// </summary>
    /// <param name="current">
    /// The current DID document the operation transforms. Ignored (and may be <see langword="null"/>) for
    /// <see cref="WellKnownDidRegistrationValues.SetDidDocument"/>; required for
    /// <see cref="WellKnownDidRegistrationValues.AddToDidDocument"/> and
    /// <see cref="WellKnownDidRegistrationValues.RemoveFromDidDocument"/>.
    /// </param>
    /// <param name="operation">
    /// The DIF <c>didDocumentOperation</c> selecting the transform — one of
    /// <see cref="WellKnownDidRegistrationValues.SetDidDocument"/>,
    /// <see cref="WellKnownDidRegistrationValues.AddToDidDocument"/>, or
    /// <see cref="WellKnownDidRegistrationValues.RemoveFromDidDocument"/>.
    /// </param>
    /// <param name="payload">The document supplied as the operand (the replacement, additions, or removals).</param>
    /// <returns>The resulting DID document (a new instance for add/remove; <paramref name="payload"/> for set).</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="payload"/> is <see langword="null"/>, or when <paramref name="current"/> is
    /// <see langword="null"/> for an add/remove operation.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="operation"/> is <c>deactivate</c>, a method-specific value, or any value that is
    /// not one of the three document-transform operations.
    /// </exception>
    public static DidDocument Apply(DidDocument? current, string operation, DidDocument payload)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operation);
        ArgumentNullException.ThrowIfNull(payload);

        if(operation == WellKnownDidRegistrationValues.SetDidDocument)
        {
            //setDidDocument replaces the document wholesale; the current document is not consulted.
            return payload;
        }

        if(operation == WellKnownDidRegistrationValues.AddToDidDocument)
        {
            ArgumentNullException.ThrowIfNull(current);

            return Add(current, payload);
        }

        if(operation == WellKnownDidRegistrationValues.RemoveFromDidDocument)
        {
            ArgumentNullException.ThrowIfNull(current);

            return Remove(current, payload);
        }

        throw new ArgumentException(
            $"'{operation}' is not a document-transform operation. Expected one of "
            + $"'{WellKnownDidRegistrationValues.SetDidDocument}', '{WellKnownDidRegistrationValues.AddToDidDocument}', "
            + $"or '{WellKnownDidRegistrationValues.RemoveFromDidDocument}' (the '{WellKnownDidRegistrationValues.DeactivateOperation}' "
            + "extension is a flow-level operation, not a document transform).",
            nameof(operation));
    }

    /// <summary>
    /// Applies a sequence of <c>didDocumentOperation</c> steps to <paramref name="current"/> in order, threading the
    /// result of each step into the next, and returns the final DID document. This is the DIF multi-operation
    /// <c>update</c>: the <c>didDocumentOperation</c>/<c>didDocument</c> array pairs are applied by position — for
    /// example <c>removeFromDidDocument</c> then <c>addToDidDocument</c> to rotate a verification method.
    /// </summary>
    /// <param name="current">
    /// The current DID document the first step transforms. Required when the first step is
    /// <see cref="WellKnownDidRegistrationValues.AddToDidDocument"/> or
    /// <see cref="WellKnownDidRegistrationValues.RemoveFromDidDocument"/>; ignored when the first step is
    /// <see cref="WellKnownDidRegistrationValues.SetDidDocument"/>. Each later step transforms the running result of
    /// the previous step, never <paramref name="current"/> directly.
    /// </param>
    /// <param name="operations">The ordered operation steps to apply, at least one.</param>
    /// <returns>The DID document produced after the final step.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="operations"/> is <see langword="null"/>, or when a step transforms a
    /// <see langword="null"/> document (a leading <c>addToDidDocument</c>/<c>removeFromDidDocument</c> with no
    /// <paramref name="current"/>).
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="operations"/> is empty, or when a step names an operation that is not a document
    /// transform.
    /// </exception>
    public static DidDocument Apply(DidDocument? current, IReadOnlyList<DidDocumentOperationStep> operations)
    {
        ArgumentNullException.ThrowIfNull(operations);
        if(operations.Count == 0)
        {
            throw new ArgumentException(
                "A DID document update requires at least one didDocumentOperation step.", nameof(operations));
        }

        DidDocument? running = current;
        foreach(DidDocumentOperationStep step in operations)
        {
            running = Apply(running, step.Operation, step.Document);
        }

        //Every step returns a non-null document and there is at least one step, so the running result is non-null.
        return running!;
    }

    /// <summary>
    /// Builds the <c>addToDidDocument</c> result: each array member is the union (by identity) of
    /// <paramref name="current"/> and <paramref name="additions"/>, with <paramref name="current"/>'s identity and
    /// extension members preserved.
    /// </summary>
    /// <param name="current">The current DID document.</param>
    /// <param name="additions">The document whose members are merged in.</param>
    /// <returns>A new merged DID document.</returns>
    private static DidDocument Add(DidDocument current, DidDocument additions)
    {
        return new DidDocument
        {
            Context = current.Context,
            Id = current.Id,
            AdditionalData = current.AdditionalData,
            AlsoKnownAs = Union(current.AlsoKnownAs, additions.AlsoKnownAs, static value => value),
            Controller = Union(current.Controller, additions.Controller, static controller => controller.Did),
            VerificationMethod = Union(current.VerificationMethod, additions.VerificationMethod, static method => method.Id),
            Authentication = Union(current.Authentication, additions.Authentication, static reference => reference.Id),
            AssertionMethod = Union(current.AssertionMethod, additions.AssertionMethod, static reference => reference.Id),
            KeyAgreement = Union(current.KeyAgreement, additions.KeyAgreement, static reference => reference.Id),
            CapabilityInvocation = Union(current.CapabilityInvocation, additions.CapabilityInvocation, static reference => reference.Id),
            CapabilityDelegation = Union(current.CapabilityDelegation, additions.CapabilityDelegation, static reference => reference.Id),
            Service = Union(current.Service, additions.Service, static service => service.Id?.ToString())
        };
    }

    /// <summary>
    /// Builds the <c>removeFromDidDocument</c> result: each array member is <paramref name="current"/>'s entries
    /// minus those whose identity appears in <paramref name="removals"/>, with <paramref name="current"/>'s
    /// identity and extension members preserved.
    /// </summary>
    /// <param name="current">The current DID document.</param>
    /// <param name="removals">The document whose entries are removed.</param>
    /// <returns>A new pruned DID document.</returns>
    private static DidDocument Remove(DidDocument current, DidDocument removals)
    {
        return new DidDocument
        {
            Context = current.Context,
            Id = current.Id,
            AdditionalData = current.AdditionalData,
            AlsoKnownAs = Difference(current.AlsoKnownAs, removals.AlsoKnownAs, static value => value),
            Controller = Difference(current.Controller, removals.Controller, static controller => controller.Did),
            VerificationMethod = Difference(current.VerificationMethod, removals.VerificationMethod, static method => method.Id),
            Authentication = Difference(current.Authentication, removals.Authentication, static reference => reference.Id),
            AssertionMethod = Difference(current.AssertionMethod, removals.AssertionMethod, static reference => reference.Id),
            KeyAgreement = Difference(current.KeyAgreement, removals.KeyAgreement, static reference => reference.Id),
            CapabilityInvocation = Difference(current.CapabilityInvocation, removals.CapabilityInvocation, static reference => reference.Id),
            CapabilityDelegation = Difference(current.CapabilityDelegation, removals.CapabilityDelegation, static reference => reference.Id),
            Service = Difference(current.Service, removals.Service, static service => service.Id?.ToString())
        };
    }

    /// <summary>
    /// Returns the union of <paramref name="current"/> and <paramref name="additions"/> keyed by
    /// <paramref name="keyOf"/>: every entry of <paramref name="current"/> (order preserved) followed by each
    /// addition whose key is not already present. Entries with a <see langword="null"/> key cannot be deduplicated
    /// and are always appended.
    /// </summary>
    /// <typeparam name="T">The array element type.</typeparam>
    /// <param name="current">The current entries (may be <see langword="null"/> or empty).</param>
    /// <param name="additions">The entries to merge in (may be <see langword="null"/> or empty).</param>
    /// <param name="keyOf">The identity selector for an entry.</param>
    /// <returns>The merged array, or <see langword="null"/> when both inputs are empty.</returns>
    private static T[]? Union<T>(T[]? current, T[]? additions, Func<T, string?> keyOf)
    {
        if(additions is not { Length: > 0 })
        {
            return current;
        }

        if(current is not { Length: > 0 })
        {
            return additions;
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach(T item in current)
        {
            string? key = keyOf(item);
            if(key is not null)
            {
                _ = seen.Add(key);
            }
        }

        var result = new List<T>(current);
        foreach(T addition in additions)
        {
            string? key = keyOf(addition);
            if(key is null || seen.Add(key))
            {
                result.Add(addition);
            }
        }

        return result.ToArray();
    }

    /// <summary>
    /// Returns <paramref name="current"/> minus every entry whose key (per <paramref name="keyOf"/>) appears in
    /// <paramref name="removals"/>. Entries with a <see langword="null"/> key are retained (they cannot be matched
    /// for removal).
    /// </summary>
    /// <typeparam name="T">The array element type.</typeparam>
    /// <param name="current">The current entries (may be <see langword="null"/> or empty).</param>
    /// <param name="removals">The entries to remove (may be <see langword="null"/> or empty).</param>
    /// <param name="keyOf">The identity selector for an entry.</param>
    /// <returns>The pruned array, or <see langword="null"/> when nothing remains.</returns>
    private static T[]? Difference<T>(T[]? current, T[]? removals, Func<T, string?> keyOf)
    {
        if(current is not { Length: > 0 } || removals is not { Length: > 0 })
        {
            return current;
        }

        var removeKeys = new HashSet<string>(StringComparer.Ordinal);
        foreach(T removal in removals)
        {
            string? key = keyOf(removal);
            if(key is not null)
            {
                _ = removeKeys.Add(key);
            }
        }

        var result = new List<T>(current.Length);
        foreach(T item in current)
        {
            string? key = keyOf(item);
            if(key is null || !removeKeys.Contains(key))
            {
                result.Add(item);
            }
        }

        return result.Count == 0 ? null : result.ToArray();
    }
}
