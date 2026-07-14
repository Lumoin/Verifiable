using Verifiable.Fido2;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Unit tests for <see cref="WellKnownClientDataTypes"/>: the registered <c>CollectedClientData.type</c>
/// identifiers and their recognition predicates.
/// </summary>
[TestClass]
internal sealed class WellKnownClientDataTypesTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>The registration-ceremony identifier is the literal <c>webauthn.create</c>.</summary>
    [TestMethod]
    public void CreateTypeHasRegisteredIdentifier()
    {
        Assert.AreEqual("webauthn.create", WellKnownClientDataTypes.Create);
    }


    /// <summary>The authentication-ceremony identifier is the literal <c>webauthn.get</c>.</summary>
    [TestMethod]
    public void GetTypeHasRegisteredIdentifier()
    {
        Assert.AreEqual("webauthn.get", WellKnownClientDataTypes.Get);
    }


    /// <summary><see cref="WellKnownClientDataTypes.IsCreate"/> recognizes the registration-ceremony identifier.</summary>
    [TestMethod]
    public void IsCreateRecognizesTheCreateIdentifier()
    {
        Assert.IsTrue(WellKnownClientDataTypes.IsCreate("webauthn.create"));
    }


    /// <summary><see cref="WellKnownClientDataTypes.IsCreate"/> rejects the authentication-ceremony identifier.</summary>
    [TestMethod]
    public void IsCreateRejectsTheGetIdentifier()
    {
        Assert.IsFalse(WellKnownClientDataTypes.IsCreate("webauthn.get"));
    }


    /// <summary><see cref="WellKnownClientDataTypes.IsCreate"/> rejects an unrecognized identifier.</summary>
    [TestMethod]
    public void IsCreateRejectsAnUnknownIdentifier()
    {
        Assert.IsFalse(WellKnownClientDataTypes.IsCreate("bogus"));
    }


    /// <summary><see cref="WellKnownClientDataTypes.IsGet"/> recognizes the authentication-ceremony identifier.</summary>
    [TestMethod]
    public void IsGetRecognizesTheGetIdentifier()
    {
        Assert.IsTrue(WellKnownClientDataTypes.IsGet("webauthn.get"));
    }


    /// <summary><see cref="WellKnownClientDataTypes.IsGet"/> rejects the registration-ceremony identifier.</summary>
    [TestMethod]
    public void IsGetRejectsTheCreateIdentifier()
    {
        Assert.IsFalse(WellKnownClientDataTypes.IsGet("webauthn.create"));
    }


    /// <summary><see cref="WellKnownClientDataTypes.IsGet"/> rejects an unrecognized identifier.</summary>
    [TestMethod]
    public void IsGetRejectsAnUnknownIdentifier()
    {
        Assert.IsFalse(WellKnownClientDataTypes.IsGet("bogus"));
    }
}
