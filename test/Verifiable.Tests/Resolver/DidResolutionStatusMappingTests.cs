using System;
using Verifiable.Core.Resolvers;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Unit tests for <see cref="DidResolutionHttpApplication.MapErrorToStatus"/>: the W3C DID Resolution
/// HTTP(S) binding's error-type-to-HTTP-status table. Each <see cref="DidResolutionErrors"/> instance is
/// asserted against its mandated status, an unknown problem-type URI and a <see langword="null"/> error
/// both map to 500, and the table is exercised on the AbsoluteUri string so a regression to
/// fragment-collapsing <see cref="Uri"/> value-equality (which would map every error type to one identity)
/// would fail these assertions.
/// </summary>
[TestClass]
internal sealed class DidResolutionStatusMappingTests
{
    [TestMethod]
    public void InvalidDidMapsTo400()
    {
        Assert.AreEqual(400, DidResolutionHttpApplication.MapErrorToStatus(DidResolutionErrors.InvalidDid),
            "INVALID_DID MUST map to HTTP 400.");
    }


    [TestMethod]
    public void InvalidDidUrlMapsTo400()
    {
        Assert.AreEqual(400, DidResolutionHttpApplication.MapErrorToStatus(DidResolutionErrors.InvalidDidUrl),
            "INVALID_DID_URL MUST map to HTTP 400.");
    }


    [TestMethod]
    public void InvalidOptionsMapsTo400()
    {
        Assert.AreEqual(400, DidResolutionHttpApplication.MapErrorToStatus(DidResolutionErrors.InvalidOptions),
            "INVALID_OPTIONS MUST map to HTTP 400.");
    }


    [TestMethod]
    public void NotFoundMapsTo404()
    {
        Assert.AreEqual(404, DidResolutionHttpApplication.MapErrorToStatus(DidResolutionErrors.NotFound),
            "NOT_FOUND MUST map to HTTP 404.");
    }


    [TestMethod]
    public void RepresentationNotSupportedMapsTo406()
    {
        Assert.AreEqual(406, DidResolutionHttpApplication.MapErrorToStatus(DidResolutionErrors.RepresentationNotSupported),
            "REPRESENTATION_NOT_SUPPORTED MUST map to HTTP 406.");
    }


    [TestMethod]
    public void InvalidDidDocumentMapsTo500()
    {
        Assert.AreEqual(500, DidResolutionHttpApplication.MapErrorToStatus(DidResolutionErrors.InvalidDidDocument),
            "INVALID_DID_DOCUMENT MUST map to HTTP 500.");
    }


    [TestMethod]
    public void MethodNotSupportedMapsTo501()
    {
        Assert.AreEqual(501, DidResolutionHttpApplication.MapErrorToStatus(DidResolutionErrors.MethodNotSupported),
            "METHOD_NOT_SUPPORTED MUST map to HTTP 501.");
    }


    [TestMethod]
    public void FeatureNotSupportedMapsTo501()
    {
        Assert.AreEqual(501, DidResolutionHttpApplication.MapErrorToStatus(DidResolutionErrors.FeatureNotSupported),
            "FEATURE_NOT_SUPPORTED MUST map to HTTP 501.");
    }


    [TestMethod]
    public void InternalErrorMapsTo500()
    {
        Assert.AreEqual(500, DidResolutionHttpApplication.MapErrorToStatus(DidResolutionErrors.InternalError),
            "INTERNAL_ERROR MUST map to HTTP 500.");
    }


    [TestMethod]
    public void UnknownErrorTypeMapsTo500()
    {
        DidProblemDetails unknown = new(new Uri("https://example.com/x"));

        Assert.AreEqual(500, DidResolutionHttpApplication.MapErrorToStatus(unknown),
            "An unrecognized problem-type URI MUST map to HTTP 500.");
    }


    [TestMethod]
    public void NullErrorMapsTo500()
    {
        Assert.AreEqual(500, DidResolutionHttpApplication.MapErrorToStatus(null),
            "A null error MUST map to HTTP 500.");
    }
}
