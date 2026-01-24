using Verifiable.Tpm;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Skips the test if no TPM is available on the system.
/// </summary>
/// <remarks>
/// <para>
/// Use this attribute on test methods or test classes that require a real TPM device.
/// The test will be skipped (not failed) if <see cref="TpmDevice.IsAvailable"/>
/// returns <c>false</c>.
/// </para>
/// <para>
/// <b>Method-level usage:</b>
/// </para>
/// <code>
/// [ConditionalTestMethod]
/// [SkipIfNoTpm]
/// public void TestRequiringRealTpm()
/// {
///     using TpmDevice tpm = TpmDevice.Open();
///     //Test code here.
/// }
/// </code>
/// <para>
/// <b>Class-level usage:</b>
/// </para>
/// <code>
/// [ConditionalTestClass]
/// [SkipIfNoTpm]
/// public class HardwareTpmTests
/// {
///     [TestMethod]
///     public void AllTestsSkippedIfNoTpm()
///     {
///         //All tests in class skip if no TPM.
///     }
/// }
/// </code>
/// </remarks>
/// <seealso cref="ConditionalTestMethodAttribute"/>
/// <seealso cref="ConditionalTestClassAttribute"/>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public sealed class SkipIfNoTpmAttribute: BaseSkipAttribute
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SkipIfNoTpmAttribute"/> class.
    /// </summary>
    public SkipIfNoTpmAttribute()
    {
        SkipReason = "TPM is not available on this system.";
    }


    /// <inheritdoc/>
    internal override bool ShouldSkip(ITestMethod testMethod)
    {
        return !TpmDevice.IsAvailable;
    }
}