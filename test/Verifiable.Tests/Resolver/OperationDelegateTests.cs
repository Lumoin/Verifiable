using System.Text;
using Verifiable.Core;
using Verifiable.Core.Resolvers;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for the operation delegates (<see cref="ApplyCreateDelegate{TState}"/>,
/// <see cref="ApplyUpdateDelegate{TState}"/>, <see cref="ApplyDeactivateDelegate{TState}"/>,
/// <see cref="ValidateProofDelegate{TState}"/>), demonstrating that each is independently
/// testable and composable.
/// </summary>
[TestClass]
internal sealed class OperationDelegateTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task ApplyCreateDelegateIsIndependentlyTestable()
    {
        ApplyCreateDelegate<string> applyCreate = (operationData, ct) =>
        {
            string content = Encoding.UTF8.GetString(operationData.Span);
            if(string.IsNullOrWhiteSpace(content))
            {
                return ValueTask.FromResult(Result<string, string>.Failure("Create operation data must not be empty."));
            }

            return ValueTask.FromResult(Result<string, string>.Success(content));
        };

        Result<string, string> success = await applyCreate(Encoding.UTF8.GetBytes("initial-state"), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(success.IsSuccess);
        Assert.AreEqual("initial-state", success.Value);

        Result<string, string> failure = await applyCreate(ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(failure.IsSuccess);
        Assert.IsNotNull(failure.Error);
    }


    [TestMethod]
    public async Task ApplyUpdateDelegateIsIndependentlyTestable()
    {
        ApplyUpdateDelegate<string> applyUpdate = (currentState, operationData, ct) =>
        {
            string patch = Encoding.UTF8.GetString(operationData.Span);
            return ValueTask.FromResult(Result<string, string>.Success($"{currentState}+{patch}"));
        };

        Result<string, string> result = await applyUpdate("v1", Encoding.UTF8.GetBytes("patch1"), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual("v1+patch1", result.Value);
    }


    [TestMethod]
    public async Task ApplyDeactivateDelegateProducesTerminalState()
    {
        ApplyDeactivateDelegate<string> applyDeactivate = (currentState, operationData, ct) =>
            ValueTask.FromResult(Result<string, string>.Success($"DEACTIVATED:{currentState}"));

        Result<string, string> result = await applyDeactivate("active-state", ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess);
        Assert.IsTrue(result.Value!.StartsWith("DEACTIVATED:", StringComparison.Ordinal));
    }


    [TestMethod]
    public async Task ValidateProofDelegateCanRejectInvalidSignatures()
    {
        ValidateProofDelegate<string> validateProof = (currentState, operationData, ct) =>
        {
            if(operationData.Length > 0 && operationData.Span[0] == 0x01)
            {
                return ValueTask.FromResult(Result<string, string>.Success(currentState ?? ""));
            }

            return ValueTask.FromResult(Result<string, string>.Failure("Invalid proof: missing validity marker."));
        };

        Result<string, string> valid = await validateProof("state", new byte[] { 0x01, 0x02, 0x03 }, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(valid.IsSuccess);

        Result<string, string> invalid = await validateProof("state", new byte[] { 0x00, 0x02, 0x03 }, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(invalid.IsSuccess);
    }


    [TestMethod]
    public async Task ValidateProofDelegateCanBeAsyncForRemoteHsm()
    {
        ValidateProofDelegate<string> remoteHsmValidation = async (currentState, operationData, ct) =>
        {
            await Task.Yield();

            if(operationData.Length >= 4)
            {
                return Result<string, string>.Success(currentState ?? "");
            }

            return Result<string, string>.Failure("Proof too short.");
        };

        Result<string, string> result = await remoteHsmValidation("state", new byte[] { 0x01, 0x02, 0x03, 0x04 }, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess);

        result = await remoteHsmValidation("state", new byte[] { 0x01 }, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(result.IsSuccess);
    }


    [TestMethod]
    public async Task OperationRulesGroupsDelegatesTogether()
    {
        ApplyCreateDelegate<string> create = (data, ct) =>
            ValueTask.FromResult(Result<string, string>.Success(Encoding.UTF8.GetString(data.Span)));

        ApplyUpdateDelegate<string> update = (state, data, ct) =>
            ValueTask.FromResult(Result<string, string>.Success($"{state}+{Encoding.UTF8.GetString(data.Span)}"));

        ApplyDeactivateDelegate<string> deactivate = (state, _, ct) =>
            ValueTask.FromResult(Result<string, string>.Success($"DEACTIVATED:{state}"));

        ValidateProofDelegate<string> validate = (state, data, ct) =>
            ValueTask.FromResult(Result<string, string>.Success(state ?? ""));

        var rules = new OperationRules<string>(create, update, deactivate, validate);

        Result<string, string> created = await rules.ApplyCreate(Encoding.UTF8.GetBytes("doc-v1"), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual("doc-v1", created.Value);

        Result<string, string> updated = await rules.ApplyUpdate("doc-v1", Encoding.UTF8.GetBytes("patch"), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual("doc-v1+patch", updated.Value);
    }


    [TestMethod]
    public async Task MethodsCanShareDelegatesSelectively()
    {
        ApplyCreateDelegate<string> sharedCreate = (data, ct) =>
            ValueTask.FromResult(Result<string, string>.Success(Encoding.UTF8.GetString(data.Span)));

        ApplyUpdateDelegate<string> sharedUpdate = (state, data, ct) =>
            ValueTask.FromResult(Result<string, string>.Success($"{state}+{Encoding.UTF8.GetString(data.Span)}"));

        ApplyDeactivateDelegate<string> sharedDeactivate = (state, _, ct) =>
            ValueTask.FromResult(Result<string, string>.Success($"DEACTIVATED:{state}"));

        //Different proof validation delegates for different methods.
        ValidateProofDelegate<string> celValidateProof = (state, data, ct) =>
        {
            if(data.Length >= 2 && data.Span[0] == 0xCE && data.Span[1] == 0x10)
            {
                return ValueTask.FromResult(Result<string, string>.Success(state ?? ""));
            }

            return ValueTask.FromResult(Result<string, string>.Failure("Missing oblivious witness signature."));
        };

        ValidateProofDelegate<string> webvhValidateProof = (state, data, ct) =>
        {
            if(data.Length >= 2 && data.Span[0] == 0xBC && data.Span[1] == 0x60)
            {
                return ValueTask.FromResult(Result<string, string>.Success(state ?? ""));
            }

            return ValueTask.FromResult(Result<string, string>.Failure("Missing organizational witness approval."));
        };

        var celRules = new OperationRules<string>(sharedCreate, sharedUpdate, sharedDeactivate, celValidateProof);
        var webvhRules = new OperationRules<string>(sharedCreate, sharedUpdate, sharedDeactivate, webvhValidateProof);

        //Same create delegate produces the same result.
        byte[] createData = Encoding.UTF8.GetBytes("did-document-v1");
        Result<string, string> celCreated = await celRules.ApplyCreate(createData, TestContext.CancellationToken).ConfigureAwait(false);
        Result<string, string> webvhCreated = await webvhRules.ApplyCreate(createData, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(celCreated.Value, webvhCreated.Value);

        //Different validate delegates produce different results for the same proof data.
        byte[] celProof = [0xCE, 0x10, 0x01, 0x02];
        Result<string, string> celValid = await celRules.ValidateProof("state", celProof, TestContext.CancellationToken).ConfigureAwait(false);
        Result<string, string> webvhInvalid = await webvhRules.ValidateProof("state", celProof, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(celValid.IsSuccess);
        Assert.IsFalse(webvhInvalid.IsSuccess);
    }
}
