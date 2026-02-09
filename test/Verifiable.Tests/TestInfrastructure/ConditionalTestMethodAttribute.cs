using System.Reflection;
using System.Runtime.CompilerServices;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// An extension to <see cref="TestMethodAttribute"/> that supports conditional skipping.
/// </summary>
/// <remarks>
/// <para>
/// This attribute walks the method and class hierarchy looking for <see cref="BaseSkipAttribute"/>
/// instances. If any returns <c>true</c> from <see cref="BaseSkipAttribute.ShouldSkip"/>,
/// the test is skipped with an <see cref="UnitTestOutcome.Inconclusive"/> result.
/// </para>
/// <para>
/// <b>Usage:</b>
/// </para>
/// <code>
/// [ConditionalTestMethod]
/// [SkipIfNoTpm]
/// public void TestRequiringTpm()
/// {
///     using TpmDevice tpm = TpmDevice.Open();
///     //Test code here.
/// }
/// </code>
/// <para>
/// When used with <see cref="ConditionalTestClassAttribute"/>, all <c>[TestMethod]</c> attributes
/// are automatically upgraded to <c>[ConditionalTestMethod]</c>.
/// </para>
/// </remarks>
/// <seealso cref="BaseSkipAttribute"/>
/// <seealso cref="ConditionalTestClassAttribute"/>
internal sealed class ConditionalTestMethodAttribute: TestMethodAttribute
{
    /// <summary>
    /// Gets the file path of the source file that contains the method that called this property.
    /// </summary>
    public string CallerFilePath { get; }
    
    /// <summary>
    /// Gets the line number in the source file at which the method that called this property is invoked.
    /// </summary>
    /// <remarks>This property is typically used for debugging, logging, or diagnostic purposes to help
    /// identify the exact location in the source code where a call originated. It is especially useful when combined
    /// with caller information attributes to provide detailed trace information.</remarks>
    public int CallerLineNumber { get; }


    /// <summary>
    /// Initializes a new instance of the <see cref="ConditionalTestMethodAttribute"/> class.
    /// </summary>
    /// <param name="callerFilePath">The file path of the caller. Automatically populated.</param>
    /// <param name="callerLineNumber">The line number of the caller. Automatically populated.</param>
    public ConditionalTestMethodAttribute(
        [CallerFilePath] string callerFilePath = "",
        [CallerLineNumber] int callerLineNumber = -1): base(callerFilePath, callerLineNumber)
    {
        CallerFilePath = callerFilePath;
        CallerLineNumber = callerLineNumber;
    }


    /// <inheritdoc/>
    public override async Task<TestResult[]> ExecuteAsync(ITestMethod testMethod)
    {
        List<BaseSkipAttribute> skipAttributes = FindSkipAttributes(testMethod);
        foreach(BaseSkipAttribute skipAttribute in skipAttributes)
        {
            if(skipAttribute.ShouldSkip(testMethod))
            {
                return
                [
                    new TestResult
                    {
                        Outcome = UnitTestOutcome.Inconclusive,
                        TestFailureException = new AssertInconclusiveException(skipAttribute.SkipReason)
                    }
                ];
            }
        }

        return await base.ExecuteAsync(testMethod).ConfigureAwait(false);
    }


    private static List<BaseSkipAttribute> FindSkipAttributes(ITestMethod testMethod)
    {
        var skipAttributes = new List<BaseSkipAttribute>();

        //Look for skip attributes on the method.
        Attribute[]? methodAttributes = testMethod.GetAllAttributes();
        if(methodAttributes is not null)
        {
            skipAttributes.AddRange(methodAttributes.OfType<BaseSkipAttribute>());
        }

        //Walk the class hierarchy looking for skip attributes.
        Type? type = testMethod.MethodInfo.DeclaringType;
        while(type is not null)
        {
            skipAttributes.AddRange(type.GetCustomAttributes<BaseSkipAttribute>(inherit: true));
            type = type.DeclaringType;
        }

        return skipAttributes;
    }    
}