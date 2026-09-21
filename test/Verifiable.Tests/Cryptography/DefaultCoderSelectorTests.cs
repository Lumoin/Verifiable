using Verifiable.Cryptography;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// <see cref="DefaultCoderSelector.IsInitialized"/> and the <see cref="CryptoLibrary.EnsureInitialized"/>
/// composition-time aggregate over the registries <see cref="CryptoLibrary.InitializeProviders"/> sets.
/// The process-wide <c>[ModuleInitializer]</c> in <c>TestSetup</c> initializes every registry before any
/// test runs, so only the true-after state is observable here without disturbing the other tests'
/// process-wide registration; there is no false-before assertion in this file for that reason.
/// </summary>
[TestClass]
internal sealed class DefaultCoderSelectorTests
{
    /// <summary>
    /// <see cref="DefaultCoderSelector.IsInitialized"/> is <see langword="true"/> once
    /// <c>TestSetup</c>'s module initializer has run <see cref="CryptoLibrary.InitializeProviders"/>.
    /// </summary>
    [TestMethod]
    public void IsInitializedIsTrueAfterProcessWideSetup()
    {
        Assert.IsTrue(DefaultCoderSelector.IsInitialized);
    }


    /// <summary>
    /// <see cref="CryptoLibrary.EnsureInitialized"/> returns normally once
    /// <see cref="DefaultCoderSelector"/> — the only registry <see cref="CryptoLibrary.InitializeProviders"/>
    /// itself sets — is initialized.
    /// </summary>
    [TestMethod]
    public void EnsureInitializedReturnsNormallyAfterProcessWideSetup()
    {
        CryptoLibrary.EnsureInitialized();
    }
}
