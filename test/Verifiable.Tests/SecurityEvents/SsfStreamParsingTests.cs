using Verifiable.Core.SecurityEvents;
using Verifiable.Json;

namespace Verifiable.Tests.SecurityEvents;

/// <summary>
/// Tests for <see cref="SsfStreamJsonParsing"/> — the faithful, strict parsers for
/// the Stream Configuration (SSF 1.0 §8.1.1) and Stream Status (§8.1.2) bodies.
/// </summary>
[TestClass]
internal sealed class SsfStreamParsingTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void FullStreamConfigurationParses()
    {
        const string Json = """
        {
            "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
            "iss": "https://transmitter.example/",
            "aud": ["https://receiver.example/", "https://receiver.example/alt"],
            "events_supported": ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
            "events_requested": ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
            "events_delivered": ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
            "delivery": {
                "method": "urn:ietf:rfc:8935",
                "endpoint_url": "https://receiver.example/push"
            },
            "min_verification_interval": 60,
            "description": "primary stream",
            "inactivity_timeout": 86400
        }
        """;

        SsfStreamConfiguration? config = SsfStreamJsonParsing.ParseStreamConfiguration(Json);

        Assert.IsNotNull(config);
        Assert.AreEqual("f67e39a0a4d34d56b3aa1bc4cff0069f", config.StreamId);
        Assert.AreEqual("https://transmitter.example/", config.Issuer);
        Assert.HasCount(2, config.Audiences);
        Assert.IsTrue(SsfDeliveryMethods.IsPushHttp(config.Delivery.Method));
        Assert.AreEqual("https://receiver.example/push", config.Delivery.EndpointUrl);
        Assert.HasCount(1, config.EventsDelivered!);
        Assert.AreEqual(60, config.MinVerificationInterval);
        Assert.AreEqual("primary stream", config.Description);
        Assert.AreEqual(86400, config.InactivityTimeout);
    }


    [TestMethod]
    public void SingleStringAudienceParses()
    {
        SsfStreamConfiguration? config = SsfStreamJsonParsing.ParseStreamConfiguration("""
        {
            "stream_id": "s1",
            "iss": "https://t.example/",
            "aud": "https://r.example/",
            "delivery": { "method": "urn:ietf:rfc:8936" }
        }
        """);

        Assert.IsNotNull(config);
        Assert.HasCount(1, config.Audiences);
        Assert.AreEqual("https://r.example/", config.Audiences[0]);
        Assert.IsTrue(SsfDeliveryMethods.IsPollHttp(config.Delivery.Method));
    }


    [TestMethod]
    public void StreamConfigurationMissingRequiredFieldIsRejected()
    {
        //Missing delivery.
        Assert.IsNull(SsfStreamJsonParsing.ParseStreamConfiguration(
            """{ "stream_id": "s1", "iss": "https://t.example/", "aud": "https://r.example/" }"""));
        //Missing iss.
        Assert.IsNull(SsfStreamJsonParsing.ParseStreamConfiguration(
            """{ "stream_id": "s1", "aud": "https://r.example/", "delivery": { "method": "urn:ietf:rfc:8935" } }"""));
        //Delivery without method.
        Assert.IsNull(SsfStreamJsonParsing.ParseStreamConfiguration(
            """{ "stream_id": "s1", "iss": "https://t.example/", "aud": "https://r.example/", "delivery": { "endpoint_url": "https://r.example/push" } }"""));
    }


    [TestMethod]
    public void StreamConfigurationWithWronglyTypedIntervalIsRejected() =>
        Assert.IsNull(SsfStreamJsonParsing.ParseStreamConfiguration("""
        {
            "stream_id": "s1", "iss": "https://t.example/", "aud": "https://r.example/",
            "delivery": { "method": "urn:ietf:rfc:8935" },
            "min_verification_interval": "soon"
        }
        """));


    [TestMethod]
    public void StreamStatusParses()
    {
        SsfStreamStatus? status = SsfStreamJsonParsing.ParseStreamStatus("""
        { "stream_id": "s1", "status": "paused", "reason": "SYSTEM_DOWN_FOR_MAINTENANCE" }
        """);

        Assert.IsNotNull(status);
        Assert.AreEqual("s1", status.StreamId);
        Assert.IsTrue(SsfStreamStatusValues.IsPaused(status.Status));
        Assert.AreEqual("SYSTEM_DOWN_FOR_MAINTENANCE", status.Reason);
    }


    [TestMethod]
    public void StreamStatusWithoutReasonParses()
    {
        SsfStreamStatus? status = SsfStreamJsonParsing.ParseStreamStatus("""{ "stream_id": "s1", "status": "enabled" }""");

        Assert.IsNotNull(status);
        Assert.IsTrue(SsfStreamStatusValues.IsEnabled(status.Status));
        Assert.IsNull(status.Reason);
    }


    [TestMethod]
    public void InvalidStatusValueIsRejected() =>
        Assert.IsNull(SsfStreamJsonParsing.ParseStreamStatus("""{ "stream_id": "s1", "status": "halted" }"""));


    [TestMethod]
    public void StreamStatusMissingStreamIdIsRejected() =>
        Assert.IsNull(SsfStreamJsonParsing.ParseStreamStatus("""{ "status": "disabled" }"""));
}
