using System.Collections.Generic;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The three-valued outcome of evaluating a <see cref="QualifierCondition"/> tree against a certificate's
/// facts. Three-valued because a criteria tree can carry criteria this model does not recognise
/// (<see cref="OtherQualifierCondition"/>) or be non-conformantly empty, and under the <c>none</c>
/// combination of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.5.9.2.2</see> a silently-false unknown leaf would make the tree PASS —
/// so unknowns must propagate as <see cref="Indeterminate"/> rather than collapse to a boolean.
/// </summary>
public enum CriteriaMatchResult
{
    /// <summary>The condition does not hold for the certificate.</summary>
    NotMatched = 0,

    /// <summary>The condition holds for the certificate.</summary>
    Matched = 1,

    /// <summary>The condition cannot be soundly evaluated (an unrecognised criterion, or a non-conformant empty criteria list).</summary>
    Indeterminate = 2
}


/// <summary>
/// Evaluates a <see cref="QualificationElement"/>'s criteria tree against a certificate's
/// <see cref="QualifiedCertificateFacts"/>, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.5.9.2.2</see> — the "whose 'CriteriaList' element identifies <c>CERT</c>"
/// selection every determination table of ETSI TS 119 615 V1.4.1 clause 4.4 builds on.
/// </summary>
public static class TrustedListCriteriaEvaluation
{
    /// <summary>
    /// Evaluates <paramref name="condition"/> against <paramref name="certificate"/>. The tree is walked
    /// iteratively with an explicit stack — never recursively — because the document is attacker-reachable
    /// and the schema permits unbounded <c>CriteriaList</c> nesting (the parse seam bounds the depth, and
    /// this walk must not reintroduce a stack-depth dependency on it).
    /// </summary>
    /// <param name="condition">The root condition (typically <see cref="QualificationElement.Condition"/>).</param>
    /// <param name="certificate">The certificate facts to assert against.</param>
    /// <returns>The three-valued match outcome.</returns>
    public static CriteriaMatchResult Evaluate(QualifierCondition condition, QualifiedCertificateFacts certificate)
    {
        //Post-order evaluation: composite frames wait until every child has produced a value, leaves
        //evaluate immediately. The child-results stack carries completed subtree outcomes; a composite
        //frame pops exactly Children.Count of them when it completes.
        var frames = new Stack<(QualifierCondition Node, bool ChildrenScheduled)>();
        var results = new Stack<CriteriaMatchResult>();
        frames.Push((condition, false));

        while(frames.Count > 0)
        {
            (QualifierCondition node, bool childrenScheduled) = frames.Pop();
            if(node is CriteriaListCondition composite)
            {
                if(!childrenScheduled)
                {
                    frames.Push((composite, true));
                    foreach(QualifierCondition child in composite.Children)
                    {
                        frames.Push((child, false));
                    }
                }
                else
                {
                    results.Push(CombineChildren(composite, results));
                }
            }
            else
            {
                results.Push(EvaluateLeaf(node, certificate));
            }
        }

        return results.Pop();


        /// <summary>Combines the completed child outcomes of <paramref name="composite"/> per its <c>assert</c> value.</summary>
        static CriteriaMatchResult CombineChildren(CriteriaListCondition composite, Stack<CriteriaMatchResult> results)
        {
            //Clause 5.5.9.2.2.0 requires "a non-empty sequence of assertions": an empty CriteriaList is
            //non-conformant, and treating it as vacuously matched (assert="all" over nothing) would grant
            //qualifiers on no evidence — so it evaluates as indeterminate instead.
            if(composite.Children.Count == 0)
            {
                return CriteriaMatchResult.Indeterminate;
            }

            bool anyMatched = false;
            bool anyNotMatched = false;
            bool anyIndeterminate = false;
            for(int i = 0; i < composite.Children.Count; ++i)
            {
                switch(results.Pop())
                {
                    case CriteriaMatchResult.Matched:
                        anyMatched = true;
                        break;

                    case CriteriaMatchResult.NotMatched:
                        anyNotMatched = true;
                        break;

                    default:
                        anyIndeterminate = true;
                        break;
                }
            }

            return composite.Assert switch
            {
                //"all": one definite miss refutes it; otherwise any unknown leaves it unknown.
                QualifierAssertion.All when anyNotMatched => CriteriaMatchResult.NotMatched,
                QualifierAssertion.All when anyIndeterminate => CriteriaMatchResult.Indeterminate,
                QualifierAssertion.All => CriteriaMatchResult.Matched,

                //"atLeastOne": one definite hit satisfies it; otherwise any unknown leaves it unknown.
                QualifierAssertion.AtLeastOne when anyMatched => CriteriaMatchResult.Matched,
                QualifierAssertion.AtLeastOne when anyIndeterminate => CriteriaMatchResult.Indeterminate,
                QualifierAssertion.AtLeastOne => CriteriaMatchResult.NotMatched,

                //"none": one definite hit refutes it; otherwise any unknown leaves it unknown — this is the
                //combination that makes three-valued propagation load-bearing.
                QualifierAssertion.None when anyMatched => CriteriaMatchResult.NotMatched,
                QualifierAssertion.None when anyIndeterminate => CriteriaMatchResult.Indeterminate,
                QualifierAssertion.None => CriteriaMatchResult.Matched,

                _ => CriteriaMatchResult.Indeterminate
            };
        }


        /// <summary>Evaluates one leaf assertion against the certificate facts.</summary>
        static CriteriaMatchResult EvaluateLeaf(QualifierCondition leaf, QualifiedCertificateFacts certificate) => leaf switch
        {
            KeyUsageCondition keyUsage => EvaluateKeyUsage(keyUsage, certificate),
            PolicySetCondition policySet => EvaluatePolicySet(policySet, certificate),
            ExtendedKeyUsageCondition extendedKeyUsage => EvaluateExtendedKeyUsage(extendedKeyUsage, certificate),
            CertSubjectDistinguishedNameAttributeCondition subjectAttribute => EvaluateSubjectAttributes(subjectAttribute, certificate),

            //Clause 5.5.9.2.2.3 lets a scheme operator define new criteria; one this model does not
            //recognise cannot be soundly evaluated in either direction.
            _ => CriteriaMatchResult.Indeterminate
        };


        /// <summary>Clause 5.5.9.2.2.1: the KeyUsage extension is present and every asserted bit matches the certificate's bit.</summary>
        static CriteriaMatchResult EvaluateKeyUsage(KeyUsageCondition condition, QualifiedCertificateFacts certificate)
        {
            if(!certificate.HasKeyUsageExtension)
            {
                return CriteriaMatchResult.NotMatched;
            }

            foreach(KeyUsageBitAssertion assertion in condition.Bits)
            {
                bool bitIsSet = false;
                foreach(KeyUsageBitName setBit in certificate.SetKeyUsageBits)
                {
                    if(setBit == assertion.Bit)
                    {
                        bitIsSet = true;
                        break;
                    }
                }

                if(bitIsSet != assertion.Asserted)
                {
                    return CriteriaMatchResult.NotMatched;
                }
            }

            return CriteriaMatchResult.Matched;
        }


        /// <summary>Clause 5.5.9.2.2.2: the CertificatePolicies extension is present and every listed policy identifier is present in it.</summary>
        static CriteriaMatchResult EvaluatePolicySet(PolicySetCondition condition, QualifiedCertificateFacts certificate)
        {
            if(!certificate.HasCertificatePoliciesExtension)
            {
                return CriteriaMatchResult.NotMatched;
            }

            foreach(string requiredOid in condition.PolicyOids)
            {
                if(!ContainsOrdinal(certificate.CertificatePolicyOids, requiredOid))
                {
                    return CriteriaMatchResult.NotMatched;
                }
            }

            return CriteriaMatchResult.Matched;
        }


        /// <summary>Clause 5.5.9.2.2.3 (1): the ExtendedKeyUsage extension is present and every listed key purpose is present in it.</summary>
        static CriteriaMatchResult EvaluateExtendedKeyUsage(ExtendedKeyUsageCondition condition, QualifiedCertificateFacts certificate)
        {
            if(!certificate.HasExtendedKeyUsageExtension)
            {
                return CriteriaMatchResult.NotMatched;
            }

            foreach(string requiredOid in condition.KeyPurposeOids)
            {
                if(!ContainsOrdinal(certificate.ExtendedKeyUsageOids, requiredOid))
                {
                    return CriteriaMatchResult.NotMatched;
                }
            }

            return CriteriaMatchResult.Matched;
        }


        /// <summary>Clause 5.5.9.2.2.3 (2): every listed attribute type object identifier is present in the certificate's subject distinguished name.</summary>
        static CriteriaMatchResult EvaluateSubjectAttributes(CertSubjectDistinguishedNameAttributeCondition condition, QualifiedCertificateFacts certificate)
        {
            foreach(string requiredOid in condition.AttributeOids)
            {
                if(!ContainsOrdinal(certificate.SubjectAttributeTypeOids, requiredOid))
                {
                    return CriteriaMatchResult.NotMatched;
                }
            }

            return CriteriaMatchResult.Matched;
        }


        /// <summary>Determines whether <paramref name="values"/> contains <paramref name="candidate"/> by ordinal comparison.</summary>
        static bool ContainsOrdinal(IReadOnlyList<string> values, string candidate)
        {
            foreach(string value in values)
            {
                if(string.Equals(value, candidate, System.StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
