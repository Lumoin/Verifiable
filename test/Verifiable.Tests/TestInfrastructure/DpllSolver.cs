using System;
using System.Collections.Generic;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// A literal in a SAT clause: a variable index and its polarity.
/// </summary>
/// <param name="Variable">Zero-based variable index.</param>
/// <param name="Positive">Whether the literal is positive (true) or negated (false).</param>
internal readonly record struct Literal(int Variable, bool Positive)
{
    /// <summary>
    /// Returns the negation of this literal.
    /// </summary>
    public Literal Negate()
    {
        return new Literal(Variable, !Positive);
    }

    /// <inheritdoc/>
    public override string ToString()
    {
        return Positive ? $"x{Variable}" : $"~x{Variable}";
    }
}


/// <summary>
/// Result of a SAT solver run.
/// </summary>
/// <param name="Satisfiable">Whether a satisfying assignment exists.</param>
/// <param name="Assignment">
/// The satisfying assignment when <see cref="Satisfiable"/> is <see langword="true"/>.
/// Maps variable index to its assigned truth value. <see langword="null"/> when unsatisfiable.
/// </param>
internal readonly record struct SatResult(bool Satisfiable, IReadOnlyDictionary<int, bool>? Assignment);


/// <summary>
/// A minimal DPLL-based SAT solver for disclosure constraint optimization in tests.
/// </summary>
/// <remarks>
/// <para>
/// Implements the Davis-Putnam-Logemann-Loveland (DPLL) algorithm with unit propagation.
/// Operates on formulas in conjunctive normal form (CNF): a conjunction of clauses, where
/// each clause is a disjunction of literals.
/// </para>
/// <para>
/// <strong>Disclosure constraint encoding:</strong> Each boolean variable represents
/// whether a specific path is disclosed from a specific credential. Constraints are
/// encoded as clauses:
/// </para>
/// <list type="bullet">
/// <item><description>
/// Coverage: "At least one credential discloses name" becomes (name_A | name_B | name_C).
/// </description></item>
/// <item><description>
/// Mutual exclusion: "Never disclose SSN from both A and B" becomes (~ssn_A | ~ssn_B).
/// </description></item>
/// <item><description>
/// Mandatory: "Credential A's issuer is always disclosed" becomes (iss_A).
/// </description></item>
/// </list>
/// <para>
/// For the scale of selective disclosure problems (tens of variables, handful of
/// credentials), DPLL without watched literals or VSIDS is instantaneous.
/// </para>
/// </remarks>
internal static class DpllSolver
{
    /// <summary>
    /// Solves a SAT problem in conjunctive normal form.
    /// </summary>
    /// <param name="clauses">
    /// The formula as a list of clauses. Each clause is an array of literals
    /// representing a disjunction (OR). The formula is the conjunction (AND) of all clauses.
    /// </param>
    /// <param name="variableCount">The number of boolean variables (indexed 0 to variableCount - 1).</param>
    /// <returns>
    /// A <see cref="SatResult"/> indicating satisfiability and, if satisfiable,
    /// the satisfying assignment. Unmentioned variables default to <see langword="false"/>
    /// (minimum disclosure preference).
    /// </returns>
    public static SatResult Solve(IReadOnlyList<Literal[]> clauses, int variableCount)
    {
        ArgumentNullException.ThrowIfNull(clauses);
        if(variableCount < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(variableCount), "Variable count must be non-negative.");
        }

        var assignment = new Dictionary<int, bool>();
        bool result = Dpll(clauses, assignment, variableCount);

        if(result)
        {
            //Assign unset variables to false (minimum disclosure preference).
            for(int i = 0; i < variableCount; i++)
            {
                assignment.TryAdd(i, false);
            }

            return new SatResult(true, assignment);
        }

        return new SatResult(false, null);
    }


    /// <summary>
    /// The recursive DPLL procedure with unit propagation.
    /// </summary>
    private static bool Dpll(
        IReadOnlyList<Literal[]> clauses,
        Dictionary<int, bool> assignment,
        int variableCount)
    {
        //Evaluate every clause under the current partial assignment.
        //A clause is satisfied if any literal is true.
        //A clause is conflicting if all literals are false.
        //A clause is unit if exactly one literal is unassigned and the rest are false.
        int? unitVariable = null;
        bool unitPolarity = false;

        foreach(var clause in clauses)
        {
            bool satisfied = false;
            int unassignedCount = 0;
            int lastUnassignedVariable = -1;
            bool lastUnassignedPolarity = false;

            foreach(var literal in clause)
            {
                if(assignment.TryGetValue(literal.Variable, out bool value))
                {
                    if(literal.Positive == value)
                    {
                        satisfied = true;
                        break;
                    }
                }
                else
                {
                    unassignedCount++;
                    lastUnassignedVariable = literal.Variable;
                    lastUnassignedPolarity = literal.Positive;
                }
            }

            if(satisfied)
            {
                continue;
            }

            if(unassignedCount == 0)
            {
                //All literals false — conflict.
                return false;
            }

            if(unassignedCount == 1)
            {
                //Unit clause — must assign this literal to true.
                unitVariable = lastUnassignedVariable;
                unitPolarity = lastUnassignedPolarity;
            }
        }

        //If a unit clause was found, propagate it.
        if(unitVariable is not null)
        {
            assignment[unitVariable.Value] = unitPolarity;
            bool result = Dpll(clauses, assignment, variableCount);
            if(result)
            {
                return true;
            }

            assignment.Remove(unitVariable.Value);
            return false;
        }

        //All clauses satisfied — done.
        bool allSatisfied = true;
        int chosenVariable = -1;

        foreach(var clause in clauses)
        {
            bool satisfied = false;

            foreach(var literal in clause)
            {
                if(assignment.TryGetValue(literal.Variable, out bool value))
                {
                    if(literal.Positive == value)
                    {
                        satisfied = true;
                        break;
                    }
                }
                else if(chosenVariable < 0)
                {
                    //Pick the first unassigned variable we encounter for branching.
                    chosenVariable = literal.Variable;
                }
            }

            if(!satisfied)
            {
                allSatisfied = false;
            }
        }

        if(allSatisfied)
        {
            return true;
        }

        if(chosenVariable < 0)
        {
            return false;
        }

        //Branch: try false first (prefer not disclosing), then true.
        assignment[chosenVariable] = false;
        if(Dpll(clauses, assignment, variableCount))
        {
            return true;
        }

        assignment[chosenVariable] = true;
        if(Dpll(clauses, assignment, variableCount))
        {
            return true;
        }

        assignment.Remove(chosenVariable);
        return false;
    }
}
