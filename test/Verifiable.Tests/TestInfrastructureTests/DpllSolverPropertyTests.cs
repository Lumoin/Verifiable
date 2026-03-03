using CsCheck;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.TestInfrastructureTests;

/// <summary>
/// Property-based tests for <see cref="DpllSolver"/> verifying solver invariants
/// hold across randomly generated SAT instances.
/// </summary>
[TestClass]
internal sealed class DpllSolverPropertyTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void SatisfyingAssignmentMakesAllClausesTrue()
    {
        //For any satisfiable formula, the returned assignment must satisfy every clause.
        GenerateRandomCnf(variableRange: (2, 8), clauseRange: (1, 15), literalRange: (1, 4))
        .Sample(input =>
        {
            var (clauses, variableCount) = input;
            var result = DpllSolver.Solve(clauses, variableCount);

            if(result.Satisfiable)
            {
                foreach(var clause in clauses)
                {
                    bool clauseSatisfied = false;
                    foreach(var literal in clause)
                    {
                        bool value = result.Assignment![literal.Variable];
                        if(literal.Positive == value)
                        {
                            clauseSatisfied = true;
                            break;
                        }
                    }

                    Assert.IsTrue(clauseSatisfied, $"Clause must be satisfied by the assignment.");
                }
            }
        });
    }


    [TestMethod]
    public void AssignmentCoversAllVariables()
    {
        //When satisfiable, every variable from 0 to variableCount-1 must be assigned.
        GenerateRandomCnf(variableRange: (2, 6), clauseRange: (1, 10), literalRange: (1, 3))
        .Sample(input =>
        {
            var (clauses, variableCount) = input;
            var result = DpllSolver.Solve(clauses, variableCount);

            if(result.Satisfiable)
            {
                Assert.HasCount(variableCount, result.Assignment!);
                for(int i = 0; i < variableCount; i++)
                {
                    Assert.IsTrue(result.Assignment!.ContainsKey(i),
                        $"Variable {i} must be present in the assignment.");
                }
            }
        });
    }


    [TestMethod]
    public void SinglePositiveLiteralClauseIsSatisfiable()
    {
        //A formula with a single unit clause (x0) is always satisfiable.
        Gen.Int[1, 10].Sample(variableCount =>
        {
            var clauses = new Literal[][]
            {
                [new Literal(0, true)]
            };

            var result = DpllSolver.Solve(clauses, variableCount);

            Assert.IsTrue(result.Satisfiable, "Single positive unit clause must be satisfiable.");
            Assert.IsTrue(result.Assignment![0], "Variable 0 must be true.");
        });
    }


    [TestMethod]
    public void ContradictoryUnitClausesAreUnsatisfiable()
    {
        //A formula with (x0) AND (~x0) is always unsatisfiable.
        Gen.Int[1, 10].Sample(variableCount =>
        {
            var clauses = new Literal[][]
            {
                [new Literal(0, true)],
                [new Literal(0, false)]
            };

            var result = DpllSolver.Solve(clauses, variableCount);

            Assert.IsFalse(result.Satisfiable, "Contradictory unit clauses must be unsatisfiable.");
            Assert.IsNull(result.Assignment);
        });
    }


    [TestMethod]
    public void EmptyFormulaIsSatisfiable()
    {
        //A formula with no clauses is trivially satisfiable.
        Gen.Int[0, 10].Sample(variableCount =>
        {
            var clauses = Array.Empty<Literal[]>();

            var result = DpllSolver.Solve(clauses, variableCount);

            Assert.IsTrue(result.Satisfiable, "Empty formula must be satisfiable.");
        });
    }


    [TestMethod]
    public void MutualExclusionConstraintIsRespected()
    {
        //For any pair of variables, (~xi | ~xj) prevents both being true simultaneously.
        (from i in Gen.Int[0, 4]
         from j in Gen.Int[0, 4]
         where i != j
         select (i, j))
        .Sample(pair =>
        {
            var (i, j) = pair;
            int variableCount = Math.Max(i, j) + 1;

            var clauses = new Literal[][]
            {
                //At least one must be true.
                [new Literal(i, true), new Literal(j, true)],
                //But not both.
                [new Literal(i, false), new Literal(j, false)]
            };

            var result = DpllSolver.Solve(clauses, variableCount);

            Assert.IsTrue(result.Satisfiable, "Mutual exclusion with coverage must be satisfiable.");
            bool vi = result.Assignment![i];
            bool vj = result.Assignment![j];
            Assert.IsTrue(vi || vj, "At least one must be true (coverage).");
            Assert.IsFalse(vi && vj, "Both must not be true (mutual exclusion).");
        });
    }


    [TestMethod]
    public void PigeonholeFormulaIsUnsatisfiable()
    {
        //The pigeonhole principle: n+1 pigeons into n holes is unsatisfiable.
        //Encoding: variable (pigeon * holes + hole) means pigeon P is in hole H.
        Gen.Int[2, 4].Sample(holes =>
        {
            int pigeons = holes + 1;
            int variableCount = pigeons * holes;
            var clauses = new List<Literal[]>();

            //Each pigeon must be in at least one hole.
            for(int p = 0; p < pigeons; p++)
            {
                var clause = new Literal[holes];
                for(int h = 0; h < holes; h++)
                {
                    clause[h] = new Literal(p * holes + h, true);
                }

                clauses.Add(clause);
            }

            //No two pigeons in the same hole.
            for(int h = 0; h < holes; h++)
            {
                for(int p1 = 0; p1 < pigeons; p1++)
                {
                    for(int p2 = p1 + 1; p2 < pigeons; p2++)
                    {
                        clauses.Add(
                        [
                            new Literal(p1 * holes + h, false),
                            new Literal(p2 * holes + h, false)
                        ]);
                    }
                }
            }

            var result = DpllSolver.Solve(clauses, variableCount);

            Assert.IsFalse(result.Satisfiable, $"Pigeonhole({pigeons},{holes}) must be unsatisfiable.");
        });
    }


    [TestMethod]
    public void UnusedVariablesDefaultToFalse()
    {
        //Variables not mentioned in any clause should be assigned false (minimum disclosure).
        Gen.Int[3, 10].Sample(variableCount =>
        {
            //Only constrain variable 0.
            var clauses = new Literal[][]
            {
                [new Literal(0, true)]
            };

            var result = DpllSolver.Solve(clauses, variableCount);

            Assert.IsTrue(result.Satisfiable);
            Assert.IsTrue(result.Assignment![0], "Constrained variable must be true.");
            for(int i = 1; i < variableCount; i++)
            {
                Assert.IsFalse(result.Assignment![i],
                    $"Unconstrained variable {i} should default to false.");
            }
        });
    }


    [TestMethod]
    public void AllPositiveChainIsSatisfiable()
    {
        //A formula where every clause is a single positive literal is always satisfiable.
        Gen.Int[1, 8].Sample(variableCount =>
        {
            var clauses = new Literal[variableCount][];
            for(int i = 0; i < variableCount; i++)
            {
                clauses[i] = [new Literal(i, true)];
            }

            var result = DpllSolver.Solve(clauses, variableCount);

            Assert.IsTrue(result.Satisfiable, "All positive unit clauses must be satisfiable.");
            for(int i = 0; i < variableCount; i++)
            {
                Assert.IsTrue(result.Assignment![i],
                    $"Variable {i} must be true when forced by unit clause.");
            }
        });
    }


    /// <summary>
    /// Generates random CNF formulas with configurable variable count, clause count, and clause width.
    /// </summary>
    private static Gen<(Literal[][] Clauses, int VariableCount)> GenerateRandomCnf(
        (int Min, int Max) variableRange,
        (int Min, int Max) clauseRange,
        (int Min, int Max) literalRange)
    {
        return
            from variableCount in Gen.Int[variableRange.Min, variableRange.Max]
            from clauseCount in Gen.Int[clauseRange.Min, clauseRange.Max]
            from clauseWidths in Gen.Int[literalRange.Min, literalRange.Max].Array[clauseCount]
            from variables in Gen.Int[0, variableCount - 1].Array[clauseCount * literalRange.Max]
            from polarities in Gen.Bool.Array[clauseCount * literalRange.Max]
            select BuildCnf(variableCount, clauseCount, clauseWidths, variables, polarities);
    }


    /// <summary>
    /// Builds a CNF formula from generated parameters.
    /// </summary>
    private static (Literal[][] Clauses, int VariableCount) BuildCnf(
        int variableCount,
        int clauseCount,
        int[] clauseWidths,
        int[] variables,
        bool[] polarities)
    {
        var clauses = new Literal[clauseCount][];
        int idx = 0;

        for(int c = 0; c < clauseCount; c++)
        {
            int width = clauseWidths[c];
            var literals = new Literal[width];

            for(int l = 0; l < width; l++)
            {
                int varIdx = variables[idx % variables.Length] % variableCount;
                bool polarity = polarities[idx % polarities.Length];
                literals[l] = new Literal(varIdx, polarity);
                idx++;
            }

            clauses[c] = literals;
        }

        return (clauses, variableCount);
    }
}