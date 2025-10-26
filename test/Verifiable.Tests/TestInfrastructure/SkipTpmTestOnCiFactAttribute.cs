using System.Runtime.CompilerServices;

namespace Verifiable.Tests.TestInfrastructure
{
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public sealed class SkipOnCiTestMethodAttribute([CallerFilePath] string callerFilePath = "", [CallerLineNumber] int callerLineNumber = -1): TestMethodAttribute(callerFilePath, callerLineNumber)
    {
        public override Task<TestResult[]> ExecuteAsync(ITestMethod testMethod)
        {
            if(Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT") == "CI")
            {
                return Task.FromResult<TestResult[]>([
                    new TestResult
                    {
                        Outcome = UnitTestOutcome.Inconclusive,
                        TestFailureException = new AssertInconclusiveException("Skipping on CI since running this test is not supported on CI at the moment.")
                    }
                ]);
            }

            return base.ExecuteAsync(testMethod);
        }
    }
}
