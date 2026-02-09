using CsCheck;
using System.Globalization;

namespace Verifiable.Tests.ToolTests;

/// <summary>
/// Property-based tests for VerifiableOperations and MCP tools using CsCheck.
/// </summary>
[TestClass]
internal sealed class McpServerPropertyTests
{
    [TestMethod]
    public void CreateDidAnyIntegerIdSucceeds()
    {
        Gen.Int.Sample(id =>
        {
            var result = VerifiableOperations.CreateDid(id, "param", null);

            Assert.IsTrue(result.IsSuccess);
            Assert.IsNotNull(result.Value);
            Assert.Contains(id.ToString(CultureInfo.InvariantCulture), result.Value, StringComparison.Ordinal);
        });
    }


    [TestMethod]
    public void CreateDidAnyStringParamSucceeds()
    {
        Gen.String[0, 1000].Sample(param =>
        {
            var result = VerifiableOperations.CreateDid(1, param, null);

            Assert.IsTrue(result.IsSuccess);
            Assert.IsNotNull(result.Value);
        });
    }


    [TestMethod]
    public void CreateDidAnyExtraParamSucceeds()
    {
        Gen.String[0, 500].Sample(extra =>
        {
            var result = VerifiableOperations.CreateDid(1, "param", extra);

            Assert.IsTrue(result.IsSuccess);
            Assert.IsNotNull(result.Value);
        });
    }


    [TestMethod]
    public void CreateDidNullExtraParamSucceeds()
    {
        Gen.Int.Sample(id =>
        {
            var result = VerifiableOperations.CreateDid(id, "param", null);

            Assert.IsTrue(result.IsSuccess);
            Assert.DoesNotContain("Extra parameter:", result.Value!, StringComparison.Ordinal);
        });
    }


    [TestMethod]
    public void CreateDidWithExtraParamContainsExtraInOutput()
    {
        Gen.String[1, 100].Where(s => !string.IsNullOrWhiteSpace(s)).Sample(extra =>
        {
            var result = VerifiableOperations.CreateDid(1, "param", extra);

            Assert.IsTrue(result.IsSuccess);
            Assert.Contains(extra, result.Value!, StringComparison.Ordinal);
        });
    }


    [TestMethod]
    public void RevokeDidAnyIntegerIdSucceeds()
    {
        Gen.Int.Sample(id =>
        {
            var result = VerifiableOperations.RevokeDid(id);

            Assert.IsTrue(result.IsSuccess);
            Assert.IsNotNull(result.Value);
            Assert.Contains(id.ToString(CultureInfo.InvariantCulture), result.Value, StringComparison.Ordinal);
        });
    }


    [TestMethod]
    public void ViewDidAnyIntegerIdSucceeds()
    {
        Gen.Int.Sample(id =>
        {
            var result = VerifiableOperations.ViewDid(id);

            Assert.IsTrue(result.IsSuccess);
            Assert.IsNotNull(result.Value);
            Assert.Contains(id.ToString(CultureInfo.InvariantCulture), result.Value, StringComparison.Ordinal);
        });
    }


    [TestMethod]
    public void ListDidsAlwaysSucceeds()
    {
        for(int i = 0; i < 2; i++)
        {
            var result = VerifiableOperations.ListDids();

            Assert.IsTrue(result.IsSuccess);
            Assert.IsNotNull(result.Value);
        }
    }


    [TestMethod]
    public void CheckTpmSupportMessageNeverThrows()
    {
        for(int i = 0; i < 2; i++)
        {
            string result = VerifiableOperations.CheckTpmSupportMessage();

            Assert.IsNotNull(result);
            Assert.IsGreaterThan(0, result.Length);
        }
    }


    [TestMethod]
    public void GetTpmInfoAsJsonNeverThrows()
    {
        for(int i = 0; i < 2; i++)
        {
            var result = VerifiableOperations.GetTpmInfoAsJson();

            Assert.IsTrue(result.IsSuccess || !string.IsNullOrEmpty(result.Error));
        }
    }


    [TestMethod]
    public void CreateDidUnicodeStringsSucceed()
    {
        var unicodeStrings = new[]
        {
            "NewWorld_Protocol",
            "RedLine_Crossing",
            "Alabasta_Region",
            "Dressrosa_Network",
            "Sabaody_Cluster",
            "Wano_国_Gateway",
            "GrandLine_航路",
            "Skypiea_雲_Node",
        };

        foreach(var unicode in unicodeStrings)
        {
            var result = VerifiableOperations.CreateDid(1, unicode, null);

            Assert.IsTrue(result.IsSuccess, $"Failed for: {unicode}");
            Assert.IsNotNull(result.Value);
        }
    }


    [TestMethod]
    public void CreateDidVeryLongStringsSucceed()
    {
        var lengths = new[] { 1000, 5000, 10000, 50000 };

        foreach(var length in lengths)
        {
            string longParam = new('x', length);
            var result = VerifiableOperations.CreateDid(1, longParam, null);

            Assert.IsTrue(result.IsSuccess, $"Failed for length: {length}");
            Assert.IsNotNull(result.Value);
        }
    }


    [TestMethod]
    public void OperationResultEqualityIsConsistent()
    {
        Gen.Int.Sample(id =>
        {
            var result1 = VerifiableOperations.CreateDid(id, "param", null);
            var result2 = VerifiableOperations.CreateDid(id, "param", null);

            Assert.AreEqual(result1.IsSuccess, result2.IsSuccess);
        });
    }

    [TestMethod]
    public void OperationResultSuccessAndFailureAreMutuallyExclusive()
    {
        Gen.Int.Sample(id =>
        {
            var result = VerifiableOperations.CreateDid(id, "param", null);

            bool hasValue = result.Value is not null;
            bool hasError = result.Error is not null;

            Assert.AreEqual(result.IsSuccess, hasValue, "IsSuccess should match presence of Value.");
            Assert.AreNotEqual(result.IsSuccess, hasError, "IsSuccess and HasError should be mutually exclusive.");
        });
    }
}