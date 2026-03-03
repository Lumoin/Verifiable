using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.TestInfrastructureTests;

/// <summary>
/// Example-based tests for <see cref="DpllSolver"/> verifying correctness on
/// known-answer SAT instances and disclosure-specific constraint patterns.
/// </summary>
[TestClass]
internal sealed class DpllSolverTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void SingleUnitClauseSatisfiable()
    {
        var clauses = new Literal[][]
        {
            [new Literal(0, true)]
        };

        var result = DpllSolver.Solve(clauses, 1);

        Assert.IsTrue(result.Satisfiable);
        Assert.IsTrue(result.Assignment![0]);
    }


    [TestMethod]
    public void NegatedUnitClauseSatisfiable()
    {
        var clauses = new Literal[][]
        {
            [new Literal(0, false)]
        };

        var result = DpllSolver.Solve(clauses, 1);

        Assert.IsTrue(result.Satisfiable);
        Assert.IsFalse(result.Assignment![0]);
    }


    [TestMethod]
    public void ContradictionUnsatisfiable()
    {
        var clauses = new Literal[][]
        {
            [new Literal(0, true)],
            [new Literal(0, false)]
        };

        var result = DpllSolver.Solve(clauses, 1);

        Assert.IsFalse(result.Satisfiable);
        Assert.IsNull(result.Assignment);
    }


    [TestMethod]
    public void EmptyFormulaIsSatisfiable()
    {
        var result = DpllSolver.Solve(Array.Empty<Literal[]>(), 3);

        Assert.IsTrue(result.Satisfiable);
        Assert.HasCount(3, result.Assignment!);
    }


    [TestMethod]
    public void ImplicationChainSatisfiable()
    {
        //x0 AND (~x0 | x1) AND (~x1 | x2): forces x0=true, x1=true, x2=true.
        var clauses = new Literal[][]
        {
            [new Literal(0, true)],
            [new Literal(0, false), new Literal(1, true)],
            [new Literal(1, false), new Literal(2, true)]
        };

        var result = DpllSolver.Solve(clauses, 3);

        Assert.IsTrue(result.Satisfiable);
        Assert.IsTrue(result.Assignment![0]);
        Assert.IsTrue(result.Assignment![1]);
        Assert.IsTrue(result.Assignment![2]);
    }


    [TestMethod]
    public void MutualExclusionWithCoverage()
    {
        //At least one of x0, x1 must be true. But not both.
        //(x0 | x1) AND (~x0 | ~x1).
        var clauses = new Literal[][]
        {
            [new Literal(0, true), new Literal(1, true)],
            [new Literal(0, false), new Literal(1, false)]
        };

        var result = DpllSolver.Solve(clauses, 2);

        Assert.IsTrue(result.Satisfiable);
        bool x0 = result.Assignment![0];
        bool x1 = result.Assignment![1];
        Assert.IsTrue(x0 || x1, "Coverage: at least one must be true.");
        Assert.IsFalse(x0 && x1, "Exclusion: both must not be true.");
    }


    [TestMethod]
    public void DisclosureConstraintNameFromExactlyOneCredential()
    {
        //Three credentials can disclose "name": variables x0, x1, x2.
        //Requirement: at least one discloses name.
        //Preference: at most one discloses name (pairwise exclusion).
        var clauses = new Literal[][]
        {
            //Coverage.
            [new Literal(0, true), new Literal(1, true), new Literal(2, true)],
            //Pairwise exclusion.
            [new Literal(0, false), new Literal(1, false)],
            [new Literal(0, false), new Literal(2, false)],
            [new Literal(1, false), new Literal(2, false)]
        };

        var result = DpllSolver.Solve(clauses, 3);

        Assert.IsTrue(result.Satisfiable);
        int trueCount = 0;
        for(int i = 0; i < 3; i++)
        {
            if(result.Assignment![i])
            {
                trueCount++;
            }
        }

        Assert.AreEqual(1, trueCount, "Exactly one credential should disclose name.");
    }


    [TestMethod]
    public void DisclosureConstraintSsnNeverFromBothCredentials()
    {
        //Variables: ssn_A=0, ssn_B=1, name_A=2, name_B=3.
        //Requirement: at least one discloses name.
        //Constraint: never disclose SSN from both A and B.
        //Mandatory: if A discloses anything, A discloses name (implication: ~ssn_A | name_A).
        var clauses = new Literal[][]
        {
            //Name coverage.
            [new Literal(2, true), new Literal(3, true)],
            //SSN mutual exclusion.
            [new Literal(0, false), new Literal(1, false)],
            //If SSN from A, then name from A.
            [new Literal(0, false), new Literal(2, true)],
            //If SSN from B, then name from B.
            [new Literal(1, false), new Literal(3, true)]
        };

        var result = DpllSolver.Solve(clauses, 4);

        Assert.IsTrue(result.Satisfiable);
        bool ssnA = result.Assignment![0];
        bool ssnB = result.Assignment![1];
        Assert.IsFalse(ssnA && ssnB, "SSN must not be disclosed from both credentials.");
    }


    [TestMethod]
    public void ThreeCredentialRealisticScenario()
    {
        //National ID: name(0), birthdate(1), ssn(2), nationality(3).
        //Driver license: name(4), birthdate(5), category(6), address(7).
        //Utility bill: name(8), address(9), account(10).
        //Requirements: name, age proof (birthdate), address.
        //Constraints: never SSN and account to same verifier (~ssn | ~account).
        //Preference: fewer credentials (solver finds minimum assignment).

        var clauses = new Literal[][]
        {
            //Name coverage: at least one credential discloses name.
            [new Literal(0, true), new Literal(4, true), new Literal(8, true)],
            //Birthdate coverage: at least one credential discloses birthdate.
            [new Literal(1, true), new Literal(5, true)],
            //Address coverage: at least one credential discloses address.
            [new Literal(7, true), new Literal(9, true)],
            //Privacy: never disclose both SSN and account number.
            [new Literal(2, false), new Literal(10, false)]
        };

        var result = DpllSolver.Solve(clauses, 11);

        Assert.IsTrue(result.Satisfiable);

        //Verify all requirements are covered.
        bool nameCovered = result.Assignment![0] || result.Assignment![4] || result.Assignment![8];
        bool birthdateCovered = result.Assignment![1] || result.Assignment![5];
        bool addressCovered = result.Assignment![7] || result.Assignment![9];
        Assert.IsTrue(nameCovered, "Name must be covered.");
        Assert.IsTrue(birthdateCovered, "Birthdate must be covered.");
        Assert.IsTrue(addressCovered, "Address must be covered.");

        //Verify privacy constraint.
        Assert.IsFalse(result.Assignment![2] && result.Assignment![10],
            "SSN and account number must not both be disclosed.");
    }


    [TestMethod]
    public void PigeonholeTwoPigeonsOneHoleUnsatisfiable()
    {
        //Two pigeons, one hole. Variable p*1+h: pigeon P in hole H.
        //Pigeon 0 in hole 0: x0. Pigeon 1 in hole 0: x1.
        var clauses = new Literal[][]
        {
            //Pigeon 0 must be in a hole.
            [new Literal(0, true)],
            //Pigeon 1 must be in a hole.
            [new Literal(1, true)],
            //Hole 0 can hold at most one pigeon.
            [new Literal(0, false), new Literal(1, false)]
        };

        var result = DpllSolver.Solve(clauses, 2);

        Assert.IsFalse(result.Satisfiable, "Two pigeons in one hole is unsatisfiable.");
    }


    [TestMethod]
    public void NegativeVariableCountThrows()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            DpllSolver.Solve(Array.Empty<Literal[]>(), -1));
    }


    [TestMethod]
    public void NullClausesThrows()
    {
        Assert.Throws<ArgumentNullException>(() =>
            DpllSolver.Solve(null!, 1));
    }
}