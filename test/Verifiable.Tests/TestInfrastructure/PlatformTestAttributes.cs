using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Verifiable.Tests.TestInfrastructure
{
    /// <summary>
    /// Platform identifiers for use with platform-specific test attributes.
    /// </summary>
    public static class Platforms
    {
        /// <summary>
        /// Windows operating system identifier.
        /// </summary>
        public const string Windows = "windows";

        /// <summary>
        /// Linux operating system identifier.
        /// </summary>
        public const string Linux = "linux";

        /// <summary>
        /// macOS operating system identifier.
        /// </summary>
        public const string MacOS = "macos";
    }


    /// <summary>
    /// Provides methods to check the current test execution environment.
    /// </summary>
    public static class TestConditions
    {
        /// <summary>
        /// Returns true if the current platform is Linux.
        /// </summary>
        public static bool IsLinux() => RuntimeInformation.IsOSPlatform(OSPlatform.Linux);

        /// <summary>
        /// Returns true if the current platform is Windows.
        /// </summary>
        public static bool IsWindows() => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

        /// <summary>
        /// Returns true if the current platform is macOS.
        /// </summary>
        public static bool IsMacOS() => RuntimeInformation.IsOSPlatform(OSPlatform.OSX);

        /// <summary>
        /// Returns true if running in a CI environment. Checks the DOTNET_ENVIRONMENT variable
        /// set by the GitHub Actions workflow.
        /// </summary>
        public static bool IsCIEnvironment() => Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT") == "CI";

        /// <summary>
        /// Returns true if the current platform is not macOS.
        /// </summary>
        public static bool IsNotMacOS() => !IsMacOS();
    }


    /// <summary>
    /// Test method attribute that only runs the test on specified platforms.
    /// On other platforms, the test is marked as inconclusive.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public sealed class RunOnlyOnPlatformTestMethodAttribute: TestMethodAttribute
    {
        private readonly string[] _platforms;
        private readonly string _reason;

        /// <summary>
        /// Creates a new instance that will only run on the specified platforms.
        /// </summary>
        /// <param name="platforms">Array of platform identifiers from <see cref="Platforms"/>.</param>
        /// <param name="filePath">Automatically populated by the compiler.</param>
        /// <param name="lineNumber">Automatically populated by the compiler.</param>
        public RunOnlyOnPlatformTestMethodAttribute(
            string[] platforms,
            [CallerFilePath] string? filePath = null,
            [CallerLineNumber] int lineNumber = 0) : base(filePath ?? string.Empty, lineNumber)
        {
            _platforms = platforms;
            _reason = $"Test only runs on {string.Join(", ", _platforms)}.";
        }


        /// <inheritdoc/>
        public override Task<TestResult[]> ExecuteAsync(ITestMethod testMethod)
        {
            if(!IsRunningOnAnyPlatform(_platforms))
            {
                return Task.FromResult<TestResult[]>([
                    new TestResult
                    {
                        Outcome = UnitTestOutcome.Inconclusive,
                        TestFailureException = new AssertInconclusiveException(_reason)
                    }
                ]);
            }

            return base.ExecuteAsync(testMethod);
        }


        private static bool IsRunningOnAnyPlatform(string[] platforms)
        {
            foreach(var platform in platforms)
            {
                bool isMatch = platform.ToLowerInvariant() switch
                {
                    Platforms.Windows => RuntimeInformation.IsOSPlatform(OSPlatform.Windows),
                    Platforms.Linux => RuntimeInformation.IsOSPlatform(OSPlatform.Linux),
                    Platforms.MacOS => RuntimeInformation.IsOSPlatform(OSPlatform.OSX),
                    _ => false
                };

                if(isMatch)
                {
                    return true;
                }
            }

            return false;
        }
    }


    /// <summary>
    /// Test method attribute that skips the test when running in CI environment.
    /// Useful for tests that require hardware or resources not available in CI.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public sealed class SkipOnCiTestMethodAttribute: TestMethodAttribute
    {
        private readonly string _reason;

        /// <summary>
        /// Creates a new instance with a default skip reason.
        /// </summary>
        /// <param name="callerFilePath">Automatically populated by the compiler.</param>
        /// <param name="callerLineNumber">Automatically populated by the compiler.</param>
        public SkipOnCiTestMethodAttribute(
            [CallerFilePath] string callerFilePath = "",
            [CallerLineNumber] int callerLineNumber = -1) : base(callerFilePath, callerLineNumber)
        {
            _reason = "Skipping on CI since running this test is not supported on CI at the moment.";
        }


        /// <summary>
        /// Creates a new instance with a custom skip reason.
        /// </summary>
        /// <param name="reason">The reason why this test is skipped on CI.</param>
        /// <param name="callerFilePath">Automatically populated by the compiler.</param>
        /// <param name="callerLineNumber">Automatically populated by the compiler.</param>
        public SkipOnCiTestMethodAttribute(
            string reason,
            [CallerFilePath] string callerFilePath = "",
            [CallerLineNumber] int callerLineNumber = -1) : base(callerFilePath, callerLineNumber)
        {
            _reason = reason;
        }


        /// <inheritdoc/>
        public override Task<TestResult[]> ExecuteAsync(ITestMethod testMethod)
        {
            if(TestConditions.IsCIEnvironment())
            {
                return Task.FromResult<TestResult[]>([
                    new TestResult
                    {
                        Outcome = UnitTestOutcome.Inconclusive,
                        TestFailureException = new AssertInconclusiveException(_reason)
                    }
                ]);
            }

            return base.ExecuteAsync(testMethod);
        }
    }


    /// <summary>
    /// Test method attribute that skips the test on macOS.
    /// Useful for tests that use APIs not supported on macOS, such as certain cryptographic curves.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public sealed class SkipOnMacOSTestMethodAttribute: TestMethodAttribute
    {
        private const string DefaultReason = "This test is not supported on macOS.";

        /// <summary>
        /// Gets or sets the reason why this test is skipped on macOS.
        /// </summary>
        public string Reason { get; set; } = DefaultReason;

        /// <summary>
        /// Creates a new instance with a default skip reason.
        /// </summary>
        /// <param name="callerFilePath">Automatically populated by the compiler.</param>
        /// <param name="callerLineNumber">Automatically populated by the compiler.</param>
        public SkipOnMacOSTestMethodAttribute(
            [CallerFilePath] string callerFilePath = "",
            [CallerLineNumber] int callerLineNumber = -1) : base(callerFilePath, callerLineNumber)
        {
        }


        /// <inheritdoc/>
        public override Task<TestResult[]> ExecuteAsync(ITestMethod testMethod)
        {
            if(TestConditions.IsMacOS())
            {
                return Task.FromResult<TestResult[]>([
                    new TestResult
                    {
                        Outcome = UnitTestOutcome.Inconclusive,
                        TestFailureException = new AssertInconclusiveException(Reason)
                    }
                ]);
            }

            return base.ExecuteAsync(testMethod);
        }
    }


    /// <summary>
    /// Test method attribute that combines platform restriction with CI skip.
    /// The test is skipped if not on a supported platform OR if running in CI.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public sealed class RunOnlyOnPlatformSkipOnCiTestMethodAttribute: TestMethodAttribute
    {
        private readonly string[] _platforms;
        private readonly string _platformReason;
        private readonly string _ciReason;

        /// <summary>
        /// Creates a new instance that will only run on the specified platforms and not in CI.
        /// </summary>
        /// <param name="platforms">Array of platform identifiers from <see cref="Platforms"/>.</param>
        /// <param name="callerFilePath">Automatically populated by the compiler.</param>
        /// <param name="callerLineNumber">Automatically populated by the compiler.</param>
        public RunOnlyOnPlatformSkipOnCiTestMethodAttribute(
            string[] platforms,
            [CallerFilePath] string callerFilePath = "",
            [CallerLineNumber] int callerLineNumber = -1) : base(callerFilePath, callerLineNumber)
        {
            _platforms = platforms;
            _platformReason = $"Test only runs on {string.Join(", ", _platforms)}.";
            _ciReason = "Skipping on CI since running this test is not supported on CI at the moment.";
        }


        /// <inheritdoc/>
        public override Task<TestResult[]> ExecuteAsync(ITestMethod testMethod)
        {
            if(!IsRunningOnAnyPlatform(_platforms))
            {
                return Task.FromResult<TestResult[]>([
                    new TestResult
                    {
                        Outcome = UnitTestOutcome.Inconclusive,
                        TestFailureException = new AssertInconclusiveException(_platformReason)
                    }
                ]);
            }

            if(TestConditions.IsCIEnvironment())
            {
                return Task.FromResult<TestResult[]>([
                    new TestResult
                    {
                        Outcome = UnitTestOutcome.Inconclusive,
                        TestFailureException = new AssertInconclusiveException(_ciReason)
                    }
                ]);
            }

            return base.ExecuteAsync(testMethod);
        }


        private static bool IsRunningOnAnyPlatform(string[] platforms)
        {
            foreach(var platform in platforms)
            {
                bool isMatch = platform.ToLowerInvariant() switch
                {
                    Platforms.Windows => RuntimeInformation.IsOSPlatform(OSPlatform.Windows),
                    Platforms.Linux => RuntimeInformation.IsOSPlatform(OSPlatform.Linux),
                    Platforms.MacOS => RuntimeInformation.IsOSPlatform(OSPlatform.OSX),
                    _ => false
                };

                if(isMatch)
                {
                    return true;
                }
            }

            return false;
        }
    }


    /// <summary>
    /// Attribute for conditionally ignoring tests based on a runtime condition.
    /// Use with <see cref="TestConditions"/> methods.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public sealed class IgnoreIfAttribute: Attribute, ITestDataSource
    {
        private readonly Func<bool> _condition;
        private readonly string _reason;

        /// <summary>
        /// Creates a new instance that ignores the test when the condition returns true.
        /// </summary>
        /// <param name="conditionType">The type containing the condition method.</param>
        /// <param name="conditionMethodName">The name of a static, parameterless method returning bool.</param>
        /// <param name="reason">The reason displayed when the test is skipped.</param>
        public IgnoreIfAttribute(Type conditionType, string conditionMethodName, string reason)
        {
            var method = conditionType.GetMethod(conditionMethodName, BindingFlags.Static | BindingFlags.Public)
                ?? throw new ArgumentException($"Method '{conditionMethodName}' not found on type '{conditionType.Name}'.");
            _condition = (Func<bool>)Delegate.CreateDelegate(typeof(Func<bool>), method);
            _reason = reason;
        }


        /// <inheritdoc/>
        public IEnumerable<object[]> GetData(MethodInfo methodInfo)
        {
            if(_condition())
            {
                Assert.Inconclusive($"Test ignored: {_reason}");
            }

            yield return Array.Empty<object>();
        }


        /// <inheritdoc/>
        public string? GetDisplayName(MethodInfo methodInfo, object?[]? data)
        {
            return methodInfo.Name;
        }
    }
}