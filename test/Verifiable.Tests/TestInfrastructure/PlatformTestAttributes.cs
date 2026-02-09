using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Verifiable.Tests.TestInfrastructure
{
    /// <summary>
    /// Platform identifiers for use with platform-specific test attributes.
    /// </summary>
    internal static class Platforms
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

        /// <summary>
        /// Determines whether the current runtime environment matches any of the specified platforms.
        /// </summary>
        /// <remarks>This method checks the provided platform names against the operating system of the
        /// current runtime. It supports Windows, Linux, and macOS platforms.</remarks>
        /// <param name="platforms">An array of platform names to check against the current runtime environment. Each platform name should be
        /// specified in a case-insensitive manner.</param>
        /// <returns>True if the current runtime environment matches any of the specified platforms; otherwise, false.</returns>
        internal static bool IsRunningOnAnyPlatform(string[] platforms)
        {
            foreach(var platform in platforms)
            {
                bool isMatch = platform switch
                {
                    var p when p.Equals(Windows, StringComparison.OrdinalIgnoreCase)
                        => RuntimeInformation.IsOSPlatform(OSPlatform.Windows),

                    var p when p.Equals(Linux, StringComparison.OrdinalIgnoreCase)
                        => RuntimeInformation.IsOSPlatform(OSPlatform.Linux),

                    var p when p.Equals(MacOS, StringComparison.OrdinalIgnoreCase)
                        => RuntimeInformation.IsOSPlatform(OSPlatform.OSX),

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
    /// Provides methods to check the current test execution environment.
    /// </summary>
    internal static class TestConditions
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
    internal sealed class RunOnlyOnPlatformTestMethodAttribute: TestMethodAttribute
    {
        /// <summary>
        /// Gets the array of platforms supported by the application.
        /// </summary>
        /// <remarks>This property provides a list of platforms on which the application can run, allowing
        /// developers to determine compatibility with various environments.</remarks>
        public string[] Platforms { get; }
        
        /// <summary>
        /// Gets the reason associated with the current state or operation.
        /// </summary>
        public string Reason { get; }
        
        /// <summary>
        /// Gets the file path of the source code where the associated event, such as an error or exception, occurred.
        /// </summary>
        public string? FilePath { get; }

        /// <summary>
        /// Gets the line number in the source code where the associated event, such as an error or exception, occurred.
        /// </summary>
        /// <remarks>This property is typically used for debugging and diagnostic purposes to help
        /// identify the precise location in the source file related to the event.</remarks>
        public int LineNumber { get; }


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
            Platforms = platforms;
            Reason = $"Test only runs on {string.Join(", ", Platforms)}.";
        }


        /// <inheritdoc/>
        public override Task<TestResult[]> ExecuteAsync(ITestMethod testMethod)
        {
            if(!TestInfrastructure.Platforms.IsRunningOnAnyPlatform(Platforms))
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
    /// Test method attribute that skips the test when running in CI environment.
    /// Useful for tests that require hardware or resources not available in CI.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    internal sealed class SkipOnCiTestMethodAttribute: TestMethodAttribute
    {
        /// <summary>
        /// Gets the reason associated with the current state or action.
        /// </summary>
        public string Reason { get; }

        /// <summary>
        /// Gets the full path of the source code file that contains the caller of the method.
        /// </summary>
        /// <remarks>This property is useful for debugging and logging scenarios, as it allows developers
        /// to identify the exact location in the code where a method was invoked. It can help trace errors or
        /// understand the context of method calls during development and troubleshooting.</remarks>
        public string CallerFilePath { get; }
        
        /// <summary>
        /// Gets the line number in the source code at which the method is called.
        /// </summary>
        /// <remarks>This property is useful for debugging and logging purposes, allowing developers to
        /// trace the origin of method calls.</remarks>
        public int CallerLineNumber { get; }


        /// <summary>
        /// Creates a new instance with a default skip reason.
        /// </summary>
        /// <param name="callerFilePath">Automatically populated by the compiler.</param>
        /// <param name="callerLineNumber">Automatically populated by the compiler.</param>
        public SkipOnCiTestMethodAttribute(
            [CallerFilePath] string callerFilePath = "",
            [CallerLineNumber] int callerLineNumber = -1): base(callerFilePath, callerLineNumber)
        {
            Reason = "Skipping on CI since running this test is not supported on CI at the moment.";
            CallerFilePath = callerFilePath;
            CallerLineNumber = callerLineNumber;
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
            Reason = reason;
            CallerFilePath = callerFilePath;
            CallerLineNumber = callerLineNumber;
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
                        TestFailureException = new AssertInconclusiveException(Reason)
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
    /// <remarks>
    /// Creates a new instance with a default skip reason.
    /// </remarks>
    /// <param name="callerFilePath">Automatically populated by the compiler.</param>
    /// <param name="callerLineNumber">Automatically populated by the compiler.</param>
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    internal sealed class SkipOnMacOSTestMethodAttribute(
        [CallerFilePath] string callerFilePath = "",
        [CallerLineNumber] int callerLineNumber = -1): TestMethodAttribute(callerFilePath, callerLineNumber)
    {
        private const string DefaultReason = "This test is not supported on macOS.";

        /// <summary>
        /// Gets or sets the reason why this test is skipped on macOS.
        /// </summary>
        public string Reason { get; set; } = DefaultReason;

        /// <summary>
        /// Gets the full path of the source code file that contains the caller of the method or property.
        /// </summary>
        /// <remarks>This property is typically used for debugging, logging, or diagnostic purposes to
        /// identify the location in source code where a method or property was invoked. It can help trace the origin of
        /// calls in complex applications and is especially useful when troubleshooting issues or generating detailed
        /// logs.</remarks>
        public string CallerFilePath { get; } = callerFilePath;

        /// <summary>
        /// Gets the line number in the source code at which the method is called.
        /// </summary>
        /// <remarks>This property is useful for debugging and logging purposes, allowing developers to
        /// trace the origin of method calls.</remarks>
        public int CallerLineNumber { get; } = callerLineNumber;


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
    internal sealed class RunOnlyOnPlatformSkipOnCiTestMethodAttribute: TestMethodAttribute
    {
        /// <summary>
        /// Gets the array of platforms supported by the application.
        /// </summary>
        /// <remarks>This property provides a list of platforms on which the application can run, allowing
        /// developers to determine compatibility with various environments.</remarks>
        public string[] Platforms { get; }
        
        /// <summary>
        /// Gets the reason for the platform's current state or behavior.
        /// </summary>
        /// <remarks>This property provides insight into the underlying reasons that may affect platform
        /// functionality or performance. It is useful for debugging and understanding platform-specific
        /// issues.</remarks>
        public string PlatformReason { get; }
        
        /// <summary>
        /// Gets the reason associated with the current configuration item.
        /// </summary>
        /// <remarks>This property provides a description of the context or purpose for the configuration
        /// item, which can help developers understand why it was set or modified.</remarks>
        public string CIReason { get; }

        /// <summary>
        /// Gets the full path of the source code file that contains the caller of the method.
        /// </summary>
        /// <remarks>This property is useful for debugging and logging scenarios, as it allows developers
        /// to trace the location in the code where a method was invoked. It can help identify the origin of errors or
        /// track execution flow during development.</remarks>
        public string CallerFilePath { get; }

        /// <summary>
        /// Gets the line number in the source code at which the method is called.
        /// </summary>
        /// <remarks>This property is useful for debugging and logging purposes, allowing developers to
        /// trace the origin of method calls.</remarks>
        public int CallerLineNumber { get; }


        /// <summary>
        /// Creates a new instance that will only run on the specified platforms and not in CI.
        /// </summary>
        /// <param name="platforms">Array of platform identifiers from <see cref="Platforms"/>.</param>
        /// <param name="callerFilePath">Automatically populated by the compiler.</param>
        /// <param name="callerLineNumber">Automatically populated by the compiler.</param>
        public RunOnlyOnPlatformSkipOnCiTestMethodAttribute(
            string[] platforms,
            [CallerFilePath] string callerFilePath = "",
            [CallerLineNumber] int callerLineNumber = -1): base(callerFilePath, callerLineNumber)
        {
            Platforms = platforms;
            PlatformReason = $"Test only runs on {string.Join(", ", Platforms)}.";
            CIReason = "Skipping on CI since running this test is not supported on CI at the moment.";
            CallerFilePath = callerFilePath;
            CallerLineNumber = callerLineNumber;
        }


        /// <inheritdoc/>
        public override Task<TestResult[]> ExecuteAsync(ITestMethod testMethod)
        {
            if(!TestInfrastructure.Platforms.IsRunningOnAnyPlatform(Platforms))
            {
                return Task.FromResult<TestResult[]>([
                    new TestResult
                    {
                        Outcome = UnitTestOutcome.Inconclusive,
                        TestFailureException = new AssertInconclusiveException(PlatformReason)
                    }
                ]);
            }

            if(TestConditions.IsCIEnvironment())
            {
                return Task.FromResult<TestResult[]>([
                    new TestResult
                    {
                        Outcome = UnitTestOutcome.Inconclusive,
                        TestFailureException = new AssertInconclusiveException(CIReason)
                    }
                ]);
            }

            return base.ExecuteAsync(testMethod);
        }        
    }


    /// <summary>
    /// Attribute for conditionally ignoring tests based on a runtime condition.
    /// Use with <see cref="TestConditions"/> methods.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    internal sealed class IgnoreIfAttribute: Attribute, ITestDataSource
    {
        /// <summary>
        /// Gets the condition function that determines whether the test should be ignored.
        /// </summary>
        public Func<bool> Condition { get; }
        
        /// <summary>
        /// Gets the reason associated with the current state or operation.
        /// </summary>
        public string Reason { get; }

        /// <summary>
        /// Gets the type of the condition associated with this instance.
        /// </summary>
        /// <remarks>Use this property to determine the specific condition type represented by the
        /// instance. This can be useful for reflection, type checking, or when implementing custom logic based on the
        /// condition's type.</remarks>
        public Type ConditionType { get; }

        /// <summary>
        /// Gets the name of the method that is used to evaluate the condition for processing.
        /// </summary>
        /// <remarks>Use this property to determine which method is responsible for establishing the
        /// condition under which certain operations are performed. This can be useful for debugging or for
        /// understanding the application's logic flow.</remarks>
        public string ConditionMethodName { get; }


        /// <summary>
        /// Creates a new instance that ignores the test when the condition returns true.
        /// </summary>
        /// <param name="conditionType">The type containing the condition method.</param>
        /// <param name="conditionMethodName">The name of a static, parameterless method returning bool.</param>
        /// <param name="reason">The reason displayed when the test is skipped.</param>
        public IgnoreIfAttribute(Type conditionType, string conditionMethodName, string reason)
        {
            var method = 
                conditionType.GetMethod(conditionMethodName, BindingFlags.Static | BindingFlags.Public)
                ?? throw new ArgumentException($"Method '{conditionMethodName}' not found on type '{conditionType.Name}'.");
            Condition = (Func<bool>)Delegate.CreateDelegate(typeof(Func<bool>), method);
            Reason = reason;
            ConditionType = conditionType;
            ConditionMethodName = conditionMethodName;
        }


        /// <inheritdoc/>
        public IEnumerable<object[]> GetData(MethodInfo methodInfo)
        {
            if(Condition())
            {
                Assert.Inconclusive($"Test ignored: {Reason}");
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