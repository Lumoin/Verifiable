using System.Collections.Generic;
using System.Collections.Immutable;
using Verifiable.Core.Did.Methods.WebVh;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="WebVhPortabilityVerification.Verify"/> — the did:webvh portability rules: every entry's
/// DIDDoc <c>id</c> retains the established SCID, and a change of <c>id</c> (a move) is permitted only when
/// portability was active in the prior entry and the new DIDDoc lists the prior DID in <c>alsoKnownAs</c>
/// (did:webvh v1.0, DID Portability).
/// </summary>
[TestClass]
internal sealed class WebVhPortabilityVerificationTests
{
    private const string Scid = "QmScidExampleValueXXXXXXXXXXXXXXXXXXXXXXXXXXX";
    private const string DidA = $"did:webvh:{Scid}:a.example";
    private const string DidB = $"did:webvh:{Scid}:b.example";


    private static WebVhState State(string versionId, bool portable)
    {
        WebVhParameters parameters = new()
        {
            Method = WebVhParameters.SupportedMethod,
            Scid = Scid,
            UpdateKeys = ["z6MkExampleUpdateKeyXXXXXXXXXXXXXXXXXXXXXXXXXXXX"],
            NextKeyHashes = ImmutableArray<string>.Empty,
            Portable = portable,
            Deactivated = false,
            Ttl = WebVhParameters.DefaultTtlSeconds,
            Witness = null,
            Watchers = ImmutableArray<string>.Empty
        };

        return new WebVhState(parameters, versionId, "2025-01-01T00:00:00Z");
    }


    private static WebVhDocumentIdentity Identity(string? id, params string[] alsoKnownAs) =>
        new(id, [.. alsoKnownAs]);


    [TestMethod]
    public void UnchangedIdPasses()
    {
        List<WebVhState> states = [State("1-a", portable: false), State("2-b", portable: false)];
        List<WebVhDocumentIdentity> identities = [Identity(DidA), Identity(DidA)];

        Assert.IsNull(WebVhPortabilityVerification.Verify(states, identities));
    }


    [TestMethod]
    public void MoveWithPortabilityAndAlsoKnownAsPasses()
    {
        List<WebVhState> states = [State("1-a", portable: true), State("2-b", portable: true)];
        List<WebVhDocumentIdentity> identities = [Identity(DidA), Identity(DidB, DidA)];

        Assert.IsNull(WebVhPortabilityVerification.Verify(states, identities));
    }


    [TestMethod]
    public void MoveWithoutPriorPortabilityFails()
    {
        //Portability is governed by the prior entry's flag; the genesis here is not portable.
        List<WebVhState> states = [State("1-a", portable: false), State("2-b", portable: false)];
        List<WebVhDocumentIdentity> identities = [Identity(DidA), Identity(DidB, DidA)];

        Assert.IsNotNull(WebVhPortabilityVerification.Verify(states, identities));
    }


    [TestMethod]
    public void MoveWithoutAlsoKnownAsFails()
    {
        List<WebVhState> states = [State("1-a", portable: true), State("2-b", portable: true)];
        List<WebVhDocumentIdentity> identities = [Identity(DidA), Identity(DidB)];

        Assert.IsNotNull(WebVhPortabilityVerification.Verify(states, identities));
    }


    [TestMethod]
    public void MovedIdWithDifferentScidFails()
    {
        List<WebVhState> states = [State("1-a", portable: true), State("2-b", portable: true)];
        List<WebVhDocumentIdentity> identities = [Identity(DidA), Identity("did:webvh:QmOtherScidYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY:b.example", DidA)];

        Assert.IsNotNull(WebVhPortabilityVerification.Verify(states, identities));
    }


    [TestMethod]
    public void IdNotBearingScidFails()
    {
        List<WebVhState> states = [State("1-a", portable: false)];
        List<WebVhDocumentIdentity> identities = [Identity("did:example:123")];

        Assert.IsNotNull(WebVhPortabilityVerification.Verify(states, identities));
    }


    [TestMethod]
    public void MissingIdFails()
    {
        List<WebVhState> states = [State("1-a", portable: false)];
        List<WebVhDocumentIdentity> identities = [Identity(null)];

        Assert.IsNotNull(WebVhPortabilityVerification.Verify(states, identities));
    }
}
