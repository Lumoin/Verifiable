using System;
using System.Collections.Generic;
using System.Collections.Immutable;

namespace Verifiable.Core.Did.Methods.WebVh;

/// <summary>
/// An active did:webvh witness rule: the <c>threshold</c> number of approvals required and the set of
/// witness <c>did:key</c> identifiers that may provide them (did:webvh v1.0, The witness Parameter).
/// </summary>
/// <param name="Threshold">The number of distinct witness approvals an entry needs to be considered witnessed.</param>
/// <param name="Witnesses">The witness <c>did:key</c> identifiers, non-empty and unique.</param>
public sealed record WebVhWitnessRule(int Threshold, ImmutableArray<string> Witnesses);


/// <summary>
/// What a single log entry declares for the <c>witness</c> parameter. The <c>witness</c> property is
/// tri-state: absent (no declaration → retain the accumulated rule), present as the empty object
/// <c>{}</c> (disable witnessing → <see cref="Rule"/> is <see langword="null"/>), or present as a rule
/// (<see cref="Rule"/> is non-null). The empty-object and absent cases are distinct and MUST NOT be
/// collapsed, because <c>{}</c> actively disables witnessing while absence retains the prior rule.
/// </summary>
/// <param name="Rule">The declared rule, or <see langword="null"/> when the entry declared the empty object <c>{}</c>.</param>
public sealed record WebVhWitnessDeclaration(WebVhWitnessRule? Rule);


/// <summary>
/// The parameters a single did:webvh log entry declares. Every property is optional: a value present in
/// the entry overrides the accumulated value, while a <see langword="null"/> value means the property was
/// absent and the accumulated value is retained (per the parameter rules in the did:webvh specification).
/// </summary>
/// <remarks>
/// This is the per-entry view produced when a <c>did.jsonl</c> line is parsed. It is folded onto the
/// accumulated <see cref="WebVhParameters"/> by <see cref="WebVhParameters.FoldGenesis"/> (first entry) and
/// <see cref="WebVhParameters.Fold"/> (subsequent entries). Watchers are not modelled here yet
/// — they are processed in a later did:webvh increment.
/// </remarks>
public sealed record WebVhDeclaredParameters
{
    /// <summary>The declared <c>method</c> (did:webvh specification version), or <see langword="null"/> when absent.</summary>
    public string? Method { get; init; }

    /// <summary>The declared <c>scid</c>, or <see langword="null"/> when absent. Valid only in the first entry.</summary>
    public string? Scid { get; init; }

    /// <summary>The declared <c>updateKeys</c> (multikey strings), or <see langword="null"/> when absent.</summary>
    public ImmutableArray<string>? UpdateKeys { get; init; }

    /// <summary>The declared <c>nextKeyHashes</c> (pre-rotation commitments), or <see langword="null"/> when absent.</summary>
    public ImmutableArray<string>? NextKeyHashes { get; init; }

    /// <summary>The declared <c>portable</c> flag, or <see langword="null"/> when absent.</summary>
    public bool? Portable { get; init; }

    /// <summary>The declared <c>deactivated</c> flag, or <see langword="null"/> when absent.</summary>
    public bool? Deactivated { get; init; }

    /// <summary>The declared <c>ttl</c> in seconds, or <see langword="null"/> when absent.</summary>
    public int? Ttl { get; init; }

    /// <summary>The declared <c>witness</c> parameter, or <see langword="null"/> when absent (retain the accumulated rule). A non-null value whose <see cref="WebVhWitnessDeclaration.Rule"/> is <see langword="null"/> is the empty object <c>{}</c> that disables witnessing.</summary>
    public WebVhWitnessDeclaration? Witness { get; init; }

    /// <summary>The declared <c>watchers</c> (opaque URL strings), or <see langword="null"/> when absent (retain the accumulated list).</summary>
    public ImmutableArray<string>? Watchers { get; init; }
}


/// <summary>
/// The accumulated, active did:webvh processing parameters after folding a sequence of log entries. These
/// drive verification of subsequent entries (the authorized <c>updateKeys</c>, the pre-rotation commitments)
/// and the resolution outcome (<c>deactivated</c>, <c>ttl</c>).
/// </summary>
/// <remarks>
/// Built and advanced exclusively through <see cref="FoldGenesis"/> and <see cref="Fold"/>, which apply the
/// did:webvh specification's per-parameter default, retention and constraint rules. did:webvh v1.0 fixes the
/// <c>method</c> to <see cref="SupportedMethod"/> (SHA-256 + eddsa-jcs-2022).
/// </remarks>
public sealed record WebVhParameters
{
    /// <summary>The only did:webvh method version this implementation processes (SHA-256, eddsa-jcs-2022).</summary>
    public const string SupportedMethod = "did:webvh:1.0";

    /// <summary>The default <c>ttl</c> in seconds when the first entry omits it.</summary>
    public const int DefaultTtlSeconds = 3600;

    /// <summary>The active method (did:webvh specification version).</summary>
    public required string Method { get; init; }

    /// <summary>The self-certifying identifier, fixed by the first entry.</summary>
    public required string Scid { get; init; }

    /// <summary>The active authorized update keys (multikey strings).</summary>
    public required ImmutableArray<string> UpdateKeys { get; init; }

    /// <summary>The active pre-rotation commitments; a non-empty array means pre-rotation is active.</summary>
    public required ImmutableArray<string> NextKeyHashes { get; init; }

    /// <summary>Whether the DID is portable (settable to <see langword="true"/> only in the first entry).</summary>
    public required bool Portable { get; init; }

    /// <summary>Whether the DID is deactivated.</summary>
    public required bool Deactivated { get; init; }

    /// <summary>The resolver cache hint in seconds.</summary>
    public required int Ttl { get; init; }

    /// <summary>
    /// The active witness rule after folding this entry, or <see langword="null"/> when witnessing is not
    /// active. This is the rule that governs witnessing of <em>subsequent</em> entries; the rule that must
    /// witness a <em>given</em> entry is resolved at resolution time from the prior accumulated rule (see
    /// the fold-timing remarks on <see cref="WebVhWitnessVerification"/>).
    /// </summary>
    public required WebVhWitnessRule? Witness { get; init; }

    /// <summary>The active <c>watchers</c>: opaque URL strings monitoring the DID, surfaced in resolution metadata.</summary>
    public required ImmutableArray<string> Watchers { get; init; }

    /// <summary>Whether key pre-rotation is active (a non-empty <see cref="NextKeyHashes"/>).</summary>
    public bool IsPreRotationActive => NextKeyHashes.Length > 0;

    /// <summary>Whether a witness rule is active (a rule with a positive threshold).</summary>
    public bool IsWitnessActive => Witness is { Threshold: > 0 };


    /// <summary>
    /// Folds the parameters declared by the first (genesis) log entry into the initial accumulated
    /// parameters, applying the first-entry MUSTs and defaults.
    /// </summary>
    /// <param name="declared">The parameters declared by the genesis entry.</param>
    /// <returns>The accumulated parameters, or a non-null error string when a first-entry MUST is violated.</returns>
    public static (WebVhParameters? Parameters, string? Error) FoldGenesis(WebVhDeclaredParameters declared)
    {
        ArgumentNullException.ThrowIfNull(declared);

        if(declared.Method is null)
        {
            return (null, "The first did:webvh log entry MUST declare the method parameter.");
        }

        if(declared.Method != SupportedMethod)
        {
            return (null, $"Unsupported did:webvh method '{declared.Method}'; this resolver processes '{SupportedMethod}'.");
        }

        if(declared.Scid is null)
        {
            return (null, "The first did:webvh log entry MUST declare the scid parameter.");
        }

        if(declared.UpdateKeys is not { Length: > 0 } updateKeys)
        {
            return (null, "The first did:webvh log entry MUST declare a non-empty updateKeys array.");
        }

        if(declared.Ttl is int genesisTtl && genesisTtl <= 0)
        {
            return (null, $"A did:webvh ttl parameter MUST be a positive integer; got {genesisTtl}.");
        }

        //The witness parameter defaults to {} (no witnesses) in the first entry, so an absent declaration
        //yields no active rule (did:webvh v1.0, Parameters: "Defaults to {} if not set in the first log entry").
        (WebVhWitnessRule? witness, string? witnessError) = FoldWitness(null, declared.Witness);
        if(witnessError is not null)
        {
            return (null, witnessError);
        }

        var parameters = new WebVhParameters
        {
            Method = declared.Method,
            Scid = declared.Scid,
            UpdateKeys = updateKeys,
            NextKeyHashes = declared.NextKeyHashes ?? ImmutableArray<string>.Empty,
            Portable = declared.Portable ?? false,
            Deactivated = declared.Deactivated ?? false,
            Ttl = declared.Ttl ?? DefaultTtlSeconds,
            Witness = witness,
            Watchers = declared.Watchers ?? ImmutableArray<string>.Empty
        };

        return (parameters, null);
    }


    /// <summary>
    /// Folds the parameters declared by a subsequent log entry onto the accumulated parameters, applying the
    /// retention rules and the constraints that hold after the first entry.
    /// </summary>
    /// <param name="prior">The accumulated parameters from the most recent prior entry.</param>
    /// <param name="declared">The parameters declared by the current entry.</param>
    /// <returns>The advanced accumulated parameters, or a non-null error string when a constraint is violated.</returns>
    public static (WebVhParameters? Parameters, string? Error) Fold(WebVhParameters prior, WebVhDeclaredParameters declared)
    {
        ArgumentNullException.ThrowIfNull(prior);
        ArgumentNullException.ThrowIfNull(declared);

        if(declared.Scid is not null)
        {
            return (null, "The scid parameter MUST NOT appear after the first did:webvh log entry.");
        }

        if(declared.Method is not null && declared.Method != SupportedMethod)
        {
            return (null, $"Unsupported did:webvh method '{declared.Method}'; this resolver processes '{SupportedMethod}'.");
        }

        if(declared.Ttl is int declaredTtl && declaredTtl <= 0)
        {
            return (null, $"A did:webvh ttl parameter MUST be a positive integer; got {declaredTtl}.");
        }

        bool portable = prior.Portable;
        if(declared.Portable is bool declaredPortable)
        {
            if(declaredPortable && !prior.Portable)
            {
                return (null, "The portable parameter MUST NOT be changed to true after the first did:webvh log entry.");
            }

            portable = declaredPortable;
        }

        (WebVhWitnessRule? witness, string? witnessError) = FoldWitness(prior.Witness, declared.Witness);
        if(witnessError is not null)
        {
            return (null, witnessError);
        }

        var parameters = new WebVhParameters
        {
            Method = declared.Method ?? prior.Method,
            Scid = prior.Scid,
            UpdateKeys = declared.UpdateKeys ?? prior.UpdateKeys,
            NextKeyHashes = declared.NextKeyHashes ?? prior.NextKeyHashes,
            Portable = portable,
            Deactivated = declared.Deactivated ?? prior.Deactivated,
            Ttl = declared.Ttl ?? prior.Ttl,
            Witness = witness,
            Watchers = declared.Watchers ?? prior.Watchers
        };

        return (parameters, null);
    }


    //Folds the declared witness parameter onto the accumulated rule (did:webvh v1.0, Parameters / The witness
    //Parameter): an absent declaration retains the prior rule, the empty object {} disables witnessing, and a
    //declared rule replaces it after validation. The fold yields the rule active AFTER this entry; which rule
    //must witness THIS entry is a separate resolution-time decision (see WebVhWitnessVerification).
    private static (WebVhWitnessRule? Rule, string? Error) FoldWitness(WebVhWitnessRule? prior, WebVhWitnessDeclaration? declared)
    {
        if(declared is null)
        {
            return (prior, null);
        }

        if(declared.Rule is not WebVhWitnessRule rule)
        {
            return (null, null);
        }

        string? error = ValidateWitnessRule(rule);

        return error is null ? (rule, null) : (null, error);
    }


    //A declared witness rule MUST have a threshold between 1 and the number of witnesses inclusive, a
    //non-empty witnesses list, each witness a unique did:key DID (did:webvh v1.0, The witness Parameter). A
    //malformed witness rule terminates resolution with an error rather than being coerced to "no witnesses".
    private static string? ValidateWitnessRule(WebVhWitnessRule rule)
    {
        if(rule.Witnesses.IsDefaultOrEmpty)
        {
            return "A did:webvh witness rule MUST declare a non-empty witnesses array.";
        }

        if(rule.Threshold < 1 || rule.Threshold > rule.Witnesses.Length)
        {
            return $"A did:webvh witness threshold MUST be between 1 and the witness count ({rule.Witnesses.Length}); got {rule.Threshold}.";
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach(string witness in rule.Witnesses)
        {
            if(witness is not { Length: > 0 } || !witness.StartsWith(DidKeyPrefix, StringComparison.Ordinal) || witness.Length == DidKeyPrefix.Length)
            {
                return $"A did:webvh witness id MUST be a did:key DID; got '{witness}'.";
            }

            if(!seen.Add(witness))
            {
                return $"A did:webvh witness id MUST be unique within the witnesses array; '{witness}' is duplicated.";
            }
        }

        return null;
    }


    private const string DidKeyPrefix = "did:key:";
}
