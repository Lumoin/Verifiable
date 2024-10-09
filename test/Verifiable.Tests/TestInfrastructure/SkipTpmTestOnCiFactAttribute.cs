namespace Verifiable.Tests.TestInfrastructure
{
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public sealed class SkipOnCiTestMethodAttribute: TestMethodAttribute
    {
        public override TestResult[] Execute(ITestMethod testMethod)
        {
            if(Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT") == "CI")
            {
                return
                [
                    new TestResult
                    {
                        Outcome = UnitTestOutcome.Inconclusive,
                        TestFailureException = new AssertInconclusiveException("Skipping on CI since running this test is not supported on CI at the moment.")
                    }
                ];
            }

            return base.Execute(testMethod);
        }
    }
}
