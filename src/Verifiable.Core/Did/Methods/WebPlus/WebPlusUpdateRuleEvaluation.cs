using System;
using System.Collections.Generic;

namespace Verifiable.Core.Did.Methods.WebPlus;

/// <summary>
/// Decides whether a did:webplus <c>updateRules</c> expression is satisfied by a set of keys that produced
/// valid proofs (did:webplus Draft v0.4, Update Rules; the WP-VAL-7e check that a non-root document's proofs
/// satisfy the predecessor's <c>updateRules</c>).
/// </summary>
/// <remarks>
/// The expression is a tree (<see cref="AnyUpdateRule"/>/<see cref="AllUpdateRule"/>/<see cref="AtLeastUpdateRule"/>
/// nest sub-rules), but it is evaluated <strong>iteratively with an explicit <see cref="Stack{T}"/></strong> of
/// frames rather than by recursion: each frame holds a composite rule and a cursor over its children and folds
/// child results into an accumulator, so an adversarially deep rule cannot overflow the call stack.
/// </remarks>
public static class WebPlusUpdateRuleEvaluation
{
    /// <summary>
    /// Returns whether <paramref name="rule"/> is satisfied by <paramref name="satisfiedKeys"/>.
    /// </summary>
    /// <param name="rule">The update rule to evaluate.</param>
    /// <param name="satisfiedKeys">The MBPubKeys that produced valid proofs.</param>
    /// <param name="hashedKeyMatcher">Decides whether a key hashes to a <see cref="HashedKeyUpdateRule"/>'s MBHash.</param>
    /// <param name="cancellationToken">Cancels an in-flight hashed-key digest on a hardware-async backend (TPM2_Hash, KMS).</param>
    /// <returns><see langword="true"/> when the rule is satisfied.</returns>
    public static async ValueTask<bool> IsSatisfiedAsync(WebPlusUpdateRule rule, IReadOnlySet<string> satisfiedKeys, HashedKeyMatcher hashedKeyMatcher, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(satisfiedKeys);
        ArgumentNullException.ThrowIfNull(hashedKeyMatcher);

        if(!IsComposite(rule))
        {
            return await EvaluateLeafAsync(rule, satisfiedKeys, hashedKeyMatcher, cancellationToken).ConfigureAwait(false);
        }

        var stack = new Stack<Frame>();
        stack.Push(new Frame(rule));

        bool finalResult = false;
        while(stack.Count > 0)
        {
            Frame frame = stack.Peek();
            if(frame.Index < frame.ChildCount)
            {
                WebPlusUpdateRule child = frame.ChildAt(frame.Index);
                if(IsComposite(child))
                {
                    //Descend into the composite child; its result folds into this frame when it finalizes.
                    stack.Push(new Frame(child));
                }
                else
                {
                    frame.Apply(await EvaluateLeafAsync(child, satisfiedKeys, hashedKeyMatcher, cancellationToken).ConfigureAwait(false));
                    frame.Index++;
                }
            }
            else
            {
                bool result = frame.Finalize();
                stack.Pop();
                if(stack.Count > 0)
                {
                    Frame parent = stack.Peek();
                    parent.Apply(result);
                    parent.Index++;
                }
                else
                {
                    finalResult = result;
                }
            }
        }

        return finalResult;
    }


    private static bool IsComposite(WebPlusUpdateRule rule)
    {
        return rule is AnyUpdateRule or AllUpdateRule or AtLeastUpdateRule;
    }


    private static async ValueTask<bool> EvaluateLeafAsync(WebPlusUpdateRule rule, IReadOnlySet<string> satisfiedKeys, HashedKeyMatcher hashedKeyMatcher, CancellationToken cancellationToken)
    {
        return rule switch
        {
            DisallowUpdateRule => false,
            KeyUpdateRule key => satisfiedKeys.Contains(key.MbPubKey),
            HashedKeyUpdateRule hashed => await MatchesAnyHashedKeyAsync(hashed.MbHash, satisfiedKeys, hashedKeyMatcher, cancellationToken).ConfigureAwait(false),
            _ => false
        };
    }


    private static async ValueTask<bool> MatchesAnyHashedKeyAsync(string mbHash, IReadOnlySet<string> satisfiedKeys, HashedKeyMatcher hashedKeyMatcher, CancellationToken cancellationToken)
    {
        foreach(string key in satisfiedKeys)
        {
            if(await hashedKeyMatcher(key, mbHash, cancellationToken).ConfigureAwait(false))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// A composite rule mid-evaluation: the rule, a cursor over its children, and the accumulator that folds
    /// child results. Held as a class frame on the explicit evaluation stack.
    /// </summary>
    private sealed class Frame
    {
        /// <summary>The composite rule this frame folds the child results of.</summary>
        private WebPlusUpdateRule Rule { get; }

        /// <summary>Whether any child of an <c>any</c> rule has been satisfied so far.</summary>
        private bool AnySatisfied { get; set; }

        /// <summary>Whether every child of an <c>all</c> rule folded so far is satisfied.</summary>
        private bool AllSatisfied { get; set; } = true;

        /// <summary>
        /// The summed weight of the satisfied children of an <c>atLeast</c> rule. A <see langword="long"/>
        /// accumulator so summing many positive <see langword="int"/> weights cannot overflow to a negative value
        /// and make an otherwise-satisfied threshold spuriously fail; every weight is a positive int, validated at
        /// parse.
        /// </summary>
        private long SatisfiedWeight { get; set; }

        /// <summary>Creates a frame for a composite <paramref name="rule"/>.</summary>
        /// <param name="rule">The composite rule.</param>
        public Frame(WebPlusUpdateRule rule)
        {
            Rule = rule;
        }

        /// <summary>The index of the next child to evaluate.</summary>
        public int Index { get; set; }

        /// <summary>The number of child rules.</summary>
        public int ChildCount => Rule switch
        {
            AnyUpdateRule any => any.Rules.Length,
            AllUpdateRule all => all.Rules.Length,
            AtLeastUpdateRule atLeast => atLeast.Of.Length,
            _ => 0
        };

        /// <summary>The child rule at <paramref name="index"/>.</summary>
        /// <param name="index">The child index.</param>
        /// <returns>The child rule.</returns>
        public WebPlusUpdateRule ChildAt(int index) => Rule switch
        {
            AnyUpdateRule any => any.Rules[index],
            AllUpdateRule all => all.Rules[index],
            AtLeastUpdateRule atLeast => atLeast.Of[index].Rule,
            _ => throw new InvalidOperationException("A non-composite rule has no children.")
        };

        /// <summary>Folds the current child's <paramref name="result"/> into the accumulator.</summary>
        /// <param name="result">Whether the child at <see cref="Index"/> is satisfied.</param>
        public void Apply(bool result)
        {
            switch(Rule)
            {
                case AnyUpdateRule:
                {
                    AnySatisfied |= result;
                    break;
                }
                case AllUpdateRule:
                {
                    AllSatisfied &= result;
                    break;
                }
                case AtLeastUpdateRule atLeast:
                {
                    if(result)
                    {
                        SatisfiedWeight += atLeast.Of[Index].Weight;
                    }

                    break;
                }
                default:
                {
                    break;
                }
            }
        }

        /// <summary>The satisfaction of the composite once all children have been folded in.</summary>
        /// <returns>Whether the composite rule is satisfied.</returns>
        public bool Finalize() => Rule switch
        {
            AnyUpdateRule => AnySatisfied,
            AllUpdateRule => AllSatisfied,
            AtLeastUpdateRule atLeast => SatisfiedWeight >= atLeast.Threshold,
            _ => false
        };
    }
}
