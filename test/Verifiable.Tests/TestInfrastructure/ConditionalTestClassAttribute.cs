namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// An extension of <see cref="TestClassAttribute"/> that automatically upgrades
/// all <c>[TestMethod]</c> attributes to <see cref="ConditionalTestMethodAttribute"/>.
/// </summary>
/// <remarks>
/// <para>
/// When applied to a test class, any <c>[TestMethod]</c> attributes within the class
/// are automatically upgraded to support conditional skipping via <see cref="BaseSkipAttribute"/>.
/// This allows class-level skip attributes to be honored without requiring each method
/// to use <c>[ConditionalTestMethod]</c>.
/// </para>
/// <para>
/// <b>Usage:</b>
/// </para>
/// <code>
/// [ConditionalTestClass]
/// [SkipIfNoTpm]
/// public class HardwareTpmTests
/// {
///     [TestMethod]  //Automatically upgraded to [ConditionalTestMethod].
///     public void TestRequiringTpm()
///     {
///         using TpmDevice tpm = TpmDevice.Open();
///         //All tests in this class skip if no TPM available.
///     }
/// }
/// </code>
/// </remarks>
/// <seealso cref="ConditionalTestMethodAttribute"/>
/// <seealso cref="BaseSkipAttribute"/>
internal sealed class ConditionalTestClassAttribute: TestClassAttribute
{
    /// <inheritdoc/>
    public override TestMethodAttribute? GetTestMethodAttribute(TestMethodAttribute? testMethodAttribute)
    {
        if(testMethodAttribute is ConditionalTestMethodAttribute)
        {
            return testMethodAttribute;
        }

        return new ConditionalTestMethodAttribute();
    }
}