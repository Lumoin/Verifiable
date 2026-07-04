using System;
using System.Collections.Immutable;

namespace Verifiable.Core.Did.Methods.WebPlus;

/// <summary>
/// A did:webplus <c>updateRules</c> expression: the policy governing which signatures authorize the next DID
/// document in the microledger (did:webplus Draft v0.4, Update Rules). An update rule is exactly one of the
/// defined forms; the model admits no others, so a parsed rule is well-formed by construction (WP-UR-1).
/// </summary>
/// <remarks>
/// This is a data-only discriminated union (sealed records over an abstract base, the same shape as
/// <see cref="Verifiable.Core.Resolvers.RegistrationFlowState"/>); satisfaction is decided by the static
/// <see cref="WebPlusUpdateRuleEvaluation"/>, not by methods on the types. Parsing an <c>updateRules</c> JSON
/// value into this model is a <c>Verifiable.Json</c> seam added later.
/// </remarks>
public abstract record WebPlusUpdateRule;


/// <summary>
/// <c>{}</c> — updates are disallowed; no signature can satisfy it. Used as the deactivation tombstone
/// (did:webplus Draft v0.4, Update Rules; Deactivate). WP-UR-2.
/// </summary>
public sealed record DisallowUpdateRule: WebPlusUpdateRule;


/// <summary>
/// <c>{"key":"&lt;MBPubKey&gt;"}</c> — satisfied by a valid signature from the named key. WP-UR-3.
/// </summary>
/// <param name="MbPubKey">The MBPubKey that must have produced a valid proof.</param>
public sealed record KeyUpdateRule(string MbPubKey): WebPlusUpdateRule;


/// <summary>
/// <c>{"hashedKey":"&lt;MBHash&gt;"}</c> — satisfied by a valid signature from a key whose MBHash equals the
/// given value (a pre-rotation commitment). WP-UR-4.
/// </summary>
/// <param name="MbHash">The MBHash a satisfying key must hash to.</param>
public sealed record HashedKeyUpdateRule(string MbHash): WebPlusUpdateRule;


/// <summary>
/// <c>{"any":[…]}</c> — satisfied if at least one sub-rule is satisfied. WP-UR-5.
/// </summary>
/// <param name="Rules">The sub-rules.</param>
public sealed record AnyUpdateRule(ImmutableArray<WebPlusUpdateRule> Rules): WebPlusUpdateRule;


/// <summary>
/// <c>{"all":[…]}</c> — satisfied if every sub-rule is satisfied. WP-UR-6.
/// </summary>
/// <param name="Rules">The sub-rules.</param>
public sealed record AllUpdateRule(ImmutableArray<WebPlusUpdateRule> Rules): WebPlusUpdateRule;


/// <summary>
/// <c>{"atLeast":N,"of":[Weighted…]}</c> — satisfied if the summed weights of the satisfied sub-rules are at
/// least <paramref name="Threshold"/>. WP-UR-7.
/// </summary>
/// <param name="Threshold">The minimum summed weight required.</param>
/// <param name="Of">The weighted sub-rules.</param>
public sealed record AtLeastUpdateRule(int Threshold, ImmutableArray<WeightedUpdateRule> Of): WebPlusUpdateRule;


/// <summary>
/// A weighted sub-rule within an <see cref="AtLeastUpdateRule"/>. The weight defaults to <c>1</c> when absent in
/// the JSON; the model carries it explicitly (did:webplus Draft v0.4, Update Rules — <c>{"weight":N,…}</c>).
/// </summary>
/// <param name="Weight">The weight contributed when <see cref="Rule"/> is satisfied.</param>
/// <param name="Rule">The sub-rule.</param>
public sealed record WeightedUpdateRule(int Weight, WebPlusUpdateRule Rule);


/// <summary>
/// Decides whether a key satisfies a <see cref="HashedKeyUpdateRule"/>: whether <paramref name="mbPubKey"/>
/// hashes to <paramref name="mbHash"/> under the (self-describing) MBHash algorithm.
/// </summary>
/// <remarks>
/// The matcher is supplied as an explicit seam because the MBHash computation (decode the algorithm from the
/// MBHash, hash the key, compare) depends on the registered hash functions; the evaluation stays free of that
/// dependency. Per the library convention the per-call data reaches the matcher as explicit parameters, never
/// captured in a closure.
/// </remarks>
/// <param name="mbPubKey">A candidate MBPubKey that produced a valid proof.</param>
/// <param name="mbHash">The pre-rotation MBHash commitment to match against.</param>
/// <param name="cancellationToken">Cancels an in-flight digest on a hardware-async backend (TPM2_Hash, KMS).</param>
/// <returns><see langword="true"/> when <paramref name="mbPubKey"/> hashes to <paramref name="mbHash"/>.</returns>
public delegate ValueTask<bool> HashedKeyMatcher(string mbPubKey, string mbHash, CancellationToken cancellationToken);


/// <summary>
/// Parses the <c>updateRules</c> field of a did:webplus DID document into a <see cref="WebPlusUpdateRule"/> tree
/// (did:webplus Draft v0.4, Update Rules; WP-UR-1: a valid expression is one of the defined forms).
/// </summary>
/// <remarks>
/// Implemented by the <c>Verifiable.Json</c> leaf, which owns JSON parsing so <see cref="Verifiable.Core"/> takes
/// no serializer dependency. The parse is iterative (an explicit stack, no recursion) and bounds the JSON depth;
/// a malformed expression — an unknown form, a wrong-typed member, a non-array <c>any</c>/<c>all</c>/<c>of</c> —
/// is rejected by throwing. The resulting tree is evaluated by <see cref="WebPlusUpdateRuleEvaluation"/>.
/// </remarks>
/// <param name="didDocumentJson">The UTF-8 JSON bytes of the DID document whose <c>updateRules</c> is parsed.</param>
/// <returns>The parsed update-rule tree.</returns>
public delegate WebPlusUpdateRule WebPlusUpdateRuleParser(ReadOnlySpan<byte> didDocumentJson);
