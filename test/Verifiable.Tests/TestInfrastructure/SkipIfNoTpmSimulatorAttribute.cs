using System;
using Verifiable.Tests.TestInfrastructure.TpmSimulator;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Skips the test if no TPM simulator is reachable on the local command/platform ports.
/// </summary>
/// <remarks>
/// <para>
/// Use this attribute on test classes or methods that require the ms-tpm-20-ref software TPM simulator (start
/// the container from <c>TestInfrastructure/TpmSimulator/Dockerfile</c>, publishing ports 2321/2322). The test
/// is skipped (not failed) when the simulator is not reachable, independently of the
/// <c>MapInconclusiveToFailed</c> run setting, mirroring <see cref="SkipIfNoTpmAttribute"/>.
/// </para>
/// </remarks>
/// <seealso cref="SkipIfNoTpmAttribute"/>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
internal sealed class SkipIfNoTpmSimulatorAttribute: BaseSkipAttribute
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SkipIfNoTpmSimulatorAttribute"/> class.
    /// </summary>
    public SkipIfNoTpmSimulatorAttribute()
    {
        SkipReason = "No TPM simulator is reachable on localhost:2321/2322.";
    }

    /// <inheritdoc/>
    internal override bool ShouldSkip(ITestMethod testMethod)
    {
        return !MsTpmSimulatorConnection.IsAvailable("localhost", MsTpmSimulatorConnection.DefaultCommandPort, TimeSpan.FromSeconds(1));
    }
}
