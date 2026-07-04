using System.Collections.Generic;

namespace Verifiable.Acdc;

/// <summary>
/// A far node ACDC as the edge evaluation needs it: the SAID that identifies it, the Issuee AID that makes it a
/// targeted ACDC (or <see langword="null"/> when it is untargeted), and whether the far node is itself valid. A
/// caller resolves an edge's node SAID to this descriptor, having verified the far node's own SAID, schema, chain,
/// and issuance binding to the degree its policy requires; the edge evaluation then applies the edge operators over
/// these descriptors.
/// </summary>
/// <param name="Said">The far node ACDC's top-level SAID, which MUST match the edge's node, <c>n</c>, value.</param>
/// <param name="IssueeAid">The far node's Issuee AID (its attribute section's <c>i</c>), or <see langword="null"/> when the far node is an untargeted ACDC with no Issuee.</param>
/// <param name="IsValid">Whether the far node ACDC is itself valid, as the caller's resolution determined.</param>
public sealed record AcdcFarNode(string Said, string? IssueeAid, bool IsValid);


/// <summary>
/// Resolves an edge's node SAID to the far node ACDC's evaluation descriptor, or <see langword="null"/> when the far
/// node cannot be resolved. The caller supplies this seam, having located and verified the far node ACDCs to the
/// degree its policy requires — the edge evaluation does not reach across ACDCs itself, exactly as the KERI replay
/// drops out to a resolver for a delegated event's delegating seal.
/// </summary>
/// <param name="nodeSaid">The edge's node, <c>n</c>, value: the SAID of the far node ACDC the edge points to.</param>
/// <returns>The far node's evaluation descriptor, or <see langword="null"/> when it cannot be resolved.</returns>
public delegate AcdcFarNode? AcdcFarNodeResolver(string nodeSaid);


/// <summary>
/// Resolves an AID to the AID that delegated it — its delegator — or <see langword="null"/> when the AID is not a
/// delegated AID. The caller supplies this seam from the AIDs' key state (a delegated AID's inception names its
/// delegator), so the <c>DI2I</c> operator can accept a near node Issuer that the far node's Issuee delegated,
/// without the edge evaluation reaching into KELs itself.
/// </summary>
/// <param name="delegatedAid">The AID whose delegator is sought.</param>
/// <returns>The delegator's AID, or <see langword="null"/> when the AID has no delegator.</returns>
public delegate string? AcdcDelegationResolver(string delegatedAid);


/// <summary>
/// Evaluates the validity of an ACDC's edge section as a fragment of a distributed property graph: it walks the
/// edge sub-graph, applies each edge's unary operator against the far node it points to, and aggregates an
/// edge-group's members under its m-ary operator. This is what turns a chain of ACDCs into a verifiable
/// chain-of-authority — for an <c>I2I</c> edge, the near node's Issuer must be the Issuee of the far node, so each
/// step of the chain authorizes the next.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#edge">
/// edge</see> and <see href="https://trustoverip.github.io/kswg-acdc-specification/#node-n-field">node validation</see>
/// rules: a validator confirms the far node's SAID matches the edge's node value, then applies the operators. The
/// unary operator default is resolved per the far node's targeting — <c>I2I</c> for a targeted far node, <c>NI2I</c>
/// for an untargeted one — and when more than one issuer-constraint operator is present the last takes precedence.
/// The m-ary operator default is <c>AND</c>.
/// </para>
/// <para>
/// The sub-graph is walked iteratively with an explicit work stack rather than by recursion, so the evaluation uses
/// bounded call-stack space however deeply the edge-groups nest. This applies the operators at one level: each
/// edge's far node validity is supplied by the resolver, so a caller that resolves far nodes recursively obtains a
/// recursive provenance-tree evaluation. The delegated issuer-to-issuee operator (<c>DI2I</c>) is evaluated when a
/// delegation resolver (<see cref="AcdcDelegationResolver"/>) is supplied, which lets an edge accept a near node
/// Issuer the far node's Issuee delegated; without one, a <c>DI2I</c> edge is rejected rather than silently narrowed
/// to <c>I2I</c>. The far-node schema constraint (<c>s</c>) and the averaging operators (<c>AVG</c>, <c>WAVG</c>) need
/// schema validation and weighted numeric properties respectively and are not evaluated here. An edge disclosed only
/// as its compact SAID cannot be evaluated and is rejected.
/// </para>
/// </remarks>
public static class AcdcEdgeEvaluation
{
    /// <summary>
    /// Evaluates whether an ACDC's edge section is valid given the near node's Issuer and a resolver for the far
    /// node ACDCs the edges point to. A <c>DI2I</c> edge is rejected by this overload; use the overload taking an
    /// <see cref="AcdcDelegationResolver"/> to evaluate delegated issuer-to-issuee edges.
    /// </summary>
    /// <param name="edgeSection">The near node's edge section (its top-level edge-group), expanded.</param>
    /// <param name="nearIssuerAid">The near node ACDC's Issuer AID, against which an <c>I2I</c> edge checks the far node's Issuee.</param>
    /// <param name="resolve">The seam that resolves an edge's node SAID to the far node's evaluation descriptor.</param>
    /// <returns><see langword="true"/> when the edge section is valid under its operators.</returns>
    /// <exception cref="AcdcException">An edge is disclosed only as its compact SAID, or an operator is one not evaluated here (<c>DI2I</c> without a delegation resolver, <c>AVG</c>, <c>WAVG</c>, or an unrecognized one).</exception>
    public static bool Evaluate(AcdcEdgeGroup edgeSection, string nearIssuerAid, AcdcFarNodeResolver resolve)
    {
        return Evaluate(edgeSection, nearIssuerAid, resolve, resolveDelegation: null);
    }


    /// <summary>
    /// Evaluates whether an ACDC's edge section is valid given the near node's Issuer, a resolver for the far node
    /// ACDCs the edges point to, and a resolver for AID delegation that lets a <c>DI2I</c> edge accept a near node
    /// Issuer the far node's Issuee delegated.
    /// </summary>
    /// <param name="edgeSection">The near node's edge section (its top-level edge-group), expanded.</param>
    /// <param name="nearIssuerAid">The near node ACDC's Issuer AID, against which an <c>I2I</c> or <c>DI2I</c> edge checks the far node's Issuee.</param>
    /// <param name="resolve">The seam that resolves an edge's node SAID to the far node's evaluation descriptor.</param>
    /// <param name="resolveDelegation">The seam that resolves an AID to its delegator, used by <c>DI2I</c>; <see langword="null"/> when the caller supports no delegated issuer-to-issuee edges, in which case a <c>DI2I</c> edge is rejected.</param>
    /// <returns><see langword="true"/> when the edge section is valid under its operators.</returns>
    /// <exception cref="AcdcException">An edge is disclosed only as its compact SAID, or an operator is one not evaluated here (<c>DI2I</c> without a delegation resolver, <c>AVG</c>, <c>WAVG</c>, or an unrecognized one).</exception>
    public static bool Evaluate(AcdcEdgeGroup edgeSection, string nearIssuerAid, AcdcFarNodeResolver resolve, AcdcDelegationResolver? resolveDelegation)
    {
        ArgumentNullException.ThrowIfNull(edgeSection);
        ArgumentNullException.ThrowIfNull(nearIssuerAid);
        ArgumentNullException.ThrowIfNull(resolve);

        var stack = new Stack<EvalFrame>();
        stack.Push(new EvalFrame(edgeSection));
        bool result = false;

        while(stack.Count > 0)
        {
            EvalFrame frame = stack.Peek();
            if(frame.Cursor < frame.Members.Count)
            {
                AcdcEdgeMember member = frame.Members[frame.Cursor];
                frame.Cursor++;

                //An edge is a leaf — evaluate it inline against its far node; a nested edge-group is descended into
                //and its aggregate result added on pop; a compact (undisclosed) edge cannot be evaluated.
                EvalFrame? child = member.Node switch
                {
                    AcdcEdge edge => AddResult(frame, EvaluateEdge(edge, nearIssuerAid, resolve, resolveDelegation)),
                    AcdcEdgeGroup group => new EvalFrame(group),
                    AcdcCompactEdgeNode compact => throw new AcdcException($"ACDC edge '{member.Label}' is disclosed only as its compact SAID '{compact.Value}'; an edge MUST be expanded to be evaluated."),
                    _ => throw new AcdcException("An ACDC edge node is of an unexpected kind.")
                };

                if(child is not null)
                {
                    stack.Push(child);
                }

                continue;
            }

            stack.Pop();
            bool groupResult = Aggregate(frame.Operator, frame.Results);
            if(stack.Count == 0)
            {
                result = groupResult;
            }
            else
            {
                stack.Peek().Results.Add(groupResult);
            }
        }

        return result;

        static EvalFrame? AddResult(EvalFrame frame, bool edgeResult)
        {
            frame.Results.Add(edgeResult);

            return null;
        }

        static bool EvaluateEdge(AcdcEdge edge, string nearIssuerAid, AcdcFarNodeResolver resolve, AcdcDelegationResolver? resolveDelegation)
        {
            AcdcFarNode? far = resolve(edge.Node);

            //The far node must resolve and its SAID must match the edge's node value before any operator applies.
            if(far is null || !string.Equals(far.Said, edge.Node, StringComparison.Ordinal))
            {
                return false;
            }

            //The issuer constraint: I2I requires the near node's Issuer be the targeted far node's Issuee; DI2I also
            //accepts an Issuer the far node's Issuee delegated; NI2I imposes no such requirement. The far node's
            //validity then contributes directly, or inverted under NOT.
            string constraint = ResolveIssuerConstraint(edge.Operators, far.IssueeAid is not null);
            bool issuerSatisfied = constraint switch
            {
                _ when constraint == AcdcEdgeOperators.NotIssuerToIssuee => true,
                _ when constraint == AcdcEdgeOperators.IssuerToIssuee => string.Equals(nearIssuerAid, far.IssueeAid, StringComparison.Ordinal),
                _ when constraint == AcdcEdgeOperators.DelegatedIssuerToIssuee => SatisfiesDelegatedIssuerToIssuee(nearIssuerAid, far, resolveDelegation),
                _ => throw new AcdcException($"The ACDC edge issuer-constraint operator '{constraint}' is not recognized.")
            };

            return issuerSatisfied && (HasNot(edge.Operators) ? !far.IsValid : far.IsValid);
        }

        static bool SatisfiesDelegatedIssuerToIssuee(string nearIssuerAid, AcdcFarNode far, AcdcDelegationResolver? resolveDelegation)
        {
            //DI2I requires a targeted far node: an untargeted far node has no Issuee to delegate from.
            if(far.IssueeAid is null)
            {
                return false;
            }

            //The Issuee itself always satisfies the constraint.
            if(string.Equals(nearIssuerAid, far.IssueeAid, StringComparison.Ordinal))
            {
                return true;
            }

            //Beyond the Issuee, DI2I accepts an AID the Issuee delegated; without a delegation resolver that cannot
            //be determined, so the edge is rejected as not evaluable rather than silently narrowed to I2I.
            if(resolveDelegation is null)
            {
                throw new AcdcException("The ACDC edge operator 'DI2I' needs a delegation resolver to accept an AID delegated by the far node's Issuee; supply one to the evaluation.");
            }

            //Walk up the near Issuer's delegation chain: it satisfies DI2I when the far node's Issuee is one of its
            //(transitive) delegators. The visited set bounds a malformed resolver that returns a cycle.
            var visited = new HashSet<string>(StringComparer.Ordinal) { nearIssuerAid };
            string current = nearIssuerAid;
            while(resolveDelegation(current) is string delegator && visited.Add(delegator))
            {
                if(string.Equals(delegator, far.IssueeAid, StringComparison.Ordinal))
                {
                    return true;
                }

                current = delegator;
            }

            return false;
        }

        static string ResolveIssuerConstraint(IReadOnlyList<string>? operators, bool farTargeted)
        {
            string? explicitConstraint = null;
            if(operators is not null)
            {
                //When more than one issuer-constraint operator appears, the last takes precedence.
                foreach(string operatorToken in operators)
                {
                    if(AcdcEdgeOperators.IsIssuerConstraint(operatorToken))
                    {
                        explicitConstraint = operatorToken;
                    }
                }
            }

            return explicitConstraint ?? (farTargeted ? AcdcEdgeOperators.IssuerToIssuee : AcdcEdgeOperators.NotIssuerToIssuee);
        }

        static bool HasNot(IReadOnlyList<string>? operators)
        {
            if(operators is null)
            {
                return false;
            }

            foreach(string operatorToken in operators)
            {
                if(string.Equals(operatorToken, AcdcEdgeOperators.Not, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }

        static bool Aggregate(string? groupOperator, List<bool> results)
        {
            int validCount = 0;
            foreach(bool valid in results)
            {
                if(valid)
                {
                    validCount++;
                }
            }

            bool all = validCount == results.Count;
            bool any = validCount > 0;
            string m = groupOperator ?? AcdcEdgeOperators.And;

            return m switch
            {
                _ when m == AcdcEdgeOperators.And => all,
                _ when m == AcdcEdgeOperators.Or => any,
                _ when m == AcdcEdgeOperators.Nand => !all,
                _ when m == AcdcEdgeOperators.Nor => !any,
                _ when m == AcdcEdgeOperators.Average || m == AcdcEdgeOperators.WeightedAverage => throw new AcdcException($"The ACDC edge-group operator '{m}' aggregates a numeric property and is not evaluated here."),
                _ => throw new AcdcException($"The ACDC edge-group operator '{m}' is not a recognized m-ary operator.")
            };
        }
    }


    /// <summary>
    /// A mutable work item for the edge-evaluation walk: an edge-group being evaluated — its operator, its members,
    /// and the validity results accumulated from its evaluated members. Held as a class so the cursor and results
    /// mutate in place across <see cref="Stack{T}.Peek"/> calls.
    /// </summary>
    private sealed class EvalFrame
    {
        /// <summary>
        /// Creates a frame for evaluating an edge-group.
        /// </summary>
        /// <param name="group">The edge-group to evaluate.</param>
        public EvalFrame(AcdcEdgeGroup group)
        {
            Operator = group.Operator;
            Members = group.Members;
            Results = new List<bool>(group.Members.Count);
        }

        /// <summary>The edge-group's m-ary operator, or <see langword="null"/> for the <c>AND</c> default.</summary>
        public string? Operator { get; }

        /// <summary>The edge-group's members in order.</summary>
        public IReadOnlyList<AcdcEdgeMember> Members { get; }

        /// <summary>The validity results of the members evaluated so far, aggregated when the group is closed.</summary>
        public List<bool> Results { get; }

        /// <summary>The index of the next member to evaluate.</summary>
        public int Cursor { get; set; }
    }
}
