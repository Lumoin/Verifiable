using System.Reflection;
using System.Runtime.InteropServices;

namespace Verifiable.Tests.TestInfrastructure
{
    public static class Platforms
    {
        public const string Windows = "windows";
        public const string Linux = "linux";
        public const string MacOS = "macos";
    }




    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public class RunOnlyOnPlatformTestMethodAttribute: TestMethodAttribute
    {
        private readonly string[] _platforms;
        private readonly string _reason;

        public RunOnlyOnPlatformTestMethodAttribute(params string[] platforms)
        {
            _platforms = platforms;
            _reason = $"Test only runs on {string.Join(", ", _platforms)}.";
        }

        public override TestResult[] Execute(ITestMethod testMethod)
        {
            if(!IsRunningOnAnyPlatform(_platforms))
            {
                return
                [
                    new TestResult
                    {
                        Outcome = UnitTestOutcome.Inconclusive,
                        TestFailureException = new AssertInconclusiveException(_reason)
                    }
                ];
            }

            return base.Execute(testMethod);
        }

        private static bool IsRunningOnAnyPlatform(string[] platforms)
        {
            foreach(var platform in platforms)
            {
                if((platform.Equals(Platforms.Windows, StringComparison.OrdinalIgnoreCase) && RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) ||
                    (platform.Equals(Platforms.Linux, StringComparison.OrdinalIgnoreCase) && RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) ||
                    (platform.Equals(Platforms.MacOS, StringComparison.OrdinalIgnoreCase) && RuntimeInformation.IsOSPlatform(OSPlatform.OSX)))
                {
                    return true;
                }
            }

            return false;
        }
    }


    public static class TestConditions
    {
        public static bool IsLinux() => RuntimeInformation.IsOSPlatform(OSPlatform.Linux);

        public static bool IsWindows() => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

        public static bool IsCIEnvironment() => Environment.GetEnvironmentVariable("CI") == "true";
    }


    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public class IgnoreIfAttribute: Attribute, ITestDataSource
    {
        private readonly Func<bool> _condition;
        private readonly string _reason;

        public IgnoreIfAttribute(Type conditionType, string conditionMethodName, string reason)
        {
            var method = conditionType.GetMethod(conditionMethodName, BindingFlags.Static | BindingFlags.Public);
            if(method == null)
            {
                throw new ArgumentException("Invalid condition method.");
            }
            _condition = (Func<bool>)Delegate.CreateDelegate(typeof(Func<bool>), method);
            _reason = reason;
        }

        public IEnumerable<object[]> GetData(MethodInfo methodInfo)
        {
            if(_condition())
            {
                Assert.Inconclusive($"Test ignored: {_reason}");
            }
            yield return Array.Empty<object>();
        }

        public string? GetDisplayName(MethodInfo methodInfo, object?[]? data)
        {
            return methodInfo.Name;
        }
    }

}
