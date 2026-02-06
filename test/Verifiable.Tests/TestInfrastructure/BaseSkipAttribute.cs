namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Abstract base class for conditional test skip attributes.
/// </summary>
/// <remarks>
/// <para>
/// Inherit from this class to create custom skip conditions. The derived class
/// must implement <see cref="ShouldSkip"/> to determine whether the test should
/// be skipped, and should set <see cref="SkipReason"/> to explain why.
/// </para>
/// <para>
/// This attribute is used with <see cref="ConditionalTestMethodAttribute"/> which
/// checks for skip attributes before executing the test.
/// </para>
/// </remarks>
/// <seealso cref="ConditionalTestMethodAttribute"/>
/// <seealso cref="ConditionalTestClassAttribute"/>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
internal abstract class BaseSkipAttribute: Attribute
{
    /// <summary>
    /// Gets the reason why the test is being skipped.
    /// </summary>
    public string SkipReason { get; protected set; } = "Test skipped due to unmet condition.";

    /// <summary>
    /// Determines whether the test should be skipped.
    /// </summary>
    /// <param name="testMethod">The test method being evaluated.</param>
    /// <returns><c>true</c> if the test should be skipped; otherwise, <c>false</c>.</returns>
    internal abstract bool ShouldSkip(ITestMethod testMethod);
}