using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for <see cref="OAuthClientInfrastructure.Create"/>'s constructor-time validation.
/// </summary>
[TestClass]
internal sealed class OAuthClientInfrastructureTests
{
    /// <summary>
    /// <see cref="OAuthClientInfrastructure.GenerateIdentifierAsync"/> is a required argument: no
    /// platform-provided default composes it, so a caller supplying <see langword="null"/> fails
    /// fast at construction rather than silently falling back to a library-chosen generator.
    /// </summary>
    [TestMethod]
    public void CreateWithNullGenerateIdentifierAsyncThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => OAuthClientInfrastructure.Create(
            sendFormPostAsync: (_, _, _, _, _) => throw new NotImplementedException(),
            saveStateAsync: (_, _, _) => ValueTask.CompletedTask,
            loadStateAsync: (_, _, _) => ValueTask.FromResult<FlowState?>(null),
            loadStateByRequestUriAsync: (_, _, _) => ValueTask.FromResult<FlowState?>(null),
            parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
            parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
            parseAuthorizationServerMetadataAsync: (body, ct) => throw new NotImplementedException(),
            parseRegistrationResponseAsync: (body, ct) => throw new NotImplementedException(),
            resolveAuthorizationServerMetadataAsync: (issuer, context, ct) => throw new NotImplementedException(),
            resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            memoryPool: BaseMemoryPool.Shared,
            timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch),
            fillEntropy: TestEntropy.NewCounterStream(),
            generateIdentifierAsync: null!));
    }
}
