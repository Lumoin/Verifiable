using System.Text;
using Verifiable.Core;
using Verifiable.Core.Outbound;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>Every metadata resolution preserves the guarded reader's size evidence on both transports.</summary>
[TestClass]
internal sealed class MetadataResponseSizeTests
{
    /// <summary>The runner's cancellation context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The issuer shared by the authorization-server and JWT VC documents.</summary>
    private static Uri Issuer { get; } = new("https://issuer.example");

    /// <summary>The location used for client metadata and the JWK Set.</summary>
    private static Uri MetadataUri { get; } = new("https://issuer.example/metadata");

    /// <summary>A valid document for each parser, with extension members the other parsers ignore.</summary>
    private static byte[] Document => Encoding.UTF8.GetBytes(
        """{"issuer":"https://issuer.example","client_id":"https://issuer.example/metadata","jwks":{"keys":[]},"keys":[]}""");


    /// <summary>A declared excess is its own typed refusal, without parsing or reading the body.</summary>
    [TestMethod]
    [DataRow("AuthorizationServer", false)]
    [DataRow("AuthorizationServer", true)]
    [DataRow("JwtVcIssuer", false)]
    [DataRow("JwtVcIssuer", true)]
    [DataRow("ClientId", false)]
    [DataRow("ClientId", true)]
    [DataRow("JwksUri", false)]
    [DataRow("JwksUri", true)]
    public async Task DeclaredLengthOverLimitRetainsEvidence(string resolver, bool useHttpClient)
    {
        using StreamingOutboundTransport transport = new([1], 4096, useHttpClient);
        object result = await ResolveAsync(resolver, transport.Delegate, 64).ConfigureAwait(false);

        Assert.AreEqual(new OutboundResponseTooLarge(64, 4096, OutboundResponseLengthKind.Declared), SizeEvidence(result));
        Assert.AreEqual(0, transport.BytesRead);
        Assert.IsTrue(transport.IsDisposed);
    }


    /// <summary>An undeclared excess retains the observed lower bound instead of becoming unreachable.</summary>
    [TestMethod]
    [DataRow("AuthorizationServer", false)]
    [DataRow("AuthorizationServer", true)]
    [DataRow("JwtVcIssuer", false)]
    [DataRow("JwtVcIssuer", true)]
    [DataRow("ClientId", false)]
    [DataRow("ClientId", true)]
    [DataRow("JwksUri", false)]
    [DataRow("JwksUri", true)]
    public async Task StreamedLengthOverLimitRetainsEvidence(string resolver, bool useHttpClient)
    {
        using StreamingOutboundTransport transport = new(new byte[4096], null, useHttpClient);
        object result = await ResolveAsync(resolver, transport.Delegate, 64).ConfigureAwait(false);

        Assert.AreEqual(new OutboundResponseTooLarge(64, 65, OutboundResponseLengthKind.Observed), SizeEvidence(result));
        Assert.AreEqual(65, transport.BytesRead);
        Assert.IsTrue(transport.IsDisposed);
    }


    /// <summary>A valid document exactly at the configured limit still resolves.</summary>
    [TestMethod]
    [DataRow("AuthorizationServer", false)]
    [DataRow("AuthorizationServer", true)]
    [DataRow("JwtVcIssuer", false)]
    [DataRow("JwtVcIssuer", true)]
    [DataRow("ClientId", false)]
    [DataRow("ClientId", true)]
    [DataRow("JwksUri", false)]
    [DataRow("JwksUri", true)]
    public async Task ExactLimitDocumentResolves(string resolver, bool useHttpClient)
    {
        byte[] document = Document;
        using StreamingOutboundTransport transport = new(document, document.Length, useHttpClient);
        object result = await ResolveAsync(resolver, transport.Delegate, document.Length).ConfigureAwait(false);

        bool resolved = result switch
        {
            AuthorizationServerMetadataResolved => true,
            JwtVcIssuerMetadataResolution value => value.IsResolved,
            ClientIdMetadataResolution value => value.IsResolved,
            JwksUriResolution value => value.IsResolved,
            _ => false
        };
        Assert.IsTrue(resolved, $"{resolver} must accept a valid document exactly at its limit.");
        Assert.AreEqual(document.Length, transport.BytesRead);
        Assert.IsTrue(transport.IsDisposed);
    }


    /// <summary>An exception type used by a host for unrelated failures is never guessed to mean size.</summary>
    [TestMethod]
    [DataRow("AuthorizationServer")]
    [DataRow("JwtVcIssuer")]
    [DataRow("ClientId")]
    [DataRow("JwksUri")]
    public async Task NonSizeTransportFailureRemainsUnreachableWithKind(string resolver)
    {
        object result = await ResolveAsync(resolver,
            static (_, _, _, _) => throw new InvalidOperationException("Unrelated transport failure."), 64)
            .ConfigureAwait(false);

        Type? kind = result switch
        {
            AuthorizationServerMetadataUnreachable value => value.FailureKind,
            JwtVcIssuerMetadataResolution { Outcome: JwtVcIssuerMetadataResolutionOutcome.Unreachable } value => value.FailureKind,
            ClientIdMetadataResolution { Outcome: ClientIdMetadataResolutionOutcome.Unreachable } value => value.FailureKind,
            JwksUriResolution { Outcome: JwksUriResolutionOutcome.Unreachable } value => value.FailureKind,
            _ => null
        };
        Assert.AreEqual(typeof(InvalidOperationException), kind);
    }


    /// <summary>Reads evidence only from each resolver's own typed too-large outcome.</summary>
    private static OutboundResponseTooLarge? SizeEvidence(object result) => result switch
    {
        AuthorizationServerMetadataTooLarge value => value.Evidence,
        JwtVcIssuerMetadataResolution { Outcome: JwtVcIssuerMetadataResolutionOutcome.TooLarge } value => value.TooLarge,
        ClientIdMetadataResolution { Outcome: ClientIdMetadataResolutionOutcome.TooLarge } value => value.TooLarge,
        JwksUriResolution { Outcome: JwksUriResolutionOutcome.TooLarge } value => value.TooLarge,
        _ => null
    };


    /// <summary>Invokes the real resolution pipeline selected by the test row.</summary>
    private async ValueTask<object> ResolveAsync(string resolver, OutboundTransportDelegate transport, long limit)
    {
        ExchangeContext context = [];
        return resolver switch
        {
            "AuthorizationServer" => await AuthorizationServerMetadataDocuments.ResolveAsync(
                Issuer, WellKnownPaths.OAuthAuthorizationServer, context, transport, AuthorizationServerMetadataJson.Parse,
                new AuthorizationServerMetadataResolverOptions { MaximumDocumentBytes = limit }, TestContext.CancellationToken).ConfigureAwait(false),
            "JwtVcIssuer" => await JwtVcIssuerMetadataDocuments.ResolveAsync(
                Issuer, context, transport, new JwtVcIssuerMetadataDocumentResolverOptions { MaximumDocumentBytes = limit },
                TestContext.CancellationToken).ConfigureAwait(false),
            "ClientId" => await ClientIdMetadataDocuments.ResolveAsync(
                MetadataUri, context, transport, new ClientIdMetadataDocumentResolverOptions { MaximumDocumentBytes = limit },
                TestContext.CancellationToken).ConfigureAwait(false),
            "JwksUri" => await JwksUriResolver.ResolveAsync(
                MetadataUri, context, transport, new JwksUriResolverOptions { MaximumDocumentBytes = limit },
                TestContext.CancellationToken).ConfigureAwait(false),
            _ => throw new ArgumentOutOfRangeException(nameof(resolver), resolver, "Unknown metadata resolver.")
        };
    }
}
