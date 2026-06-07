using System.Text.Json;
using Verifiable.Core.Model.Dcql;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// Guards the DCQL parameter-requiredness rules the in-house reader enforces as a
/// strict conformance oracle: <c>meta</c> is REQUIRED on a Credential Query
/// (OID4VP 1.0 §6.1) and a Claims Query <c>id</c> is REQUIRED when <c>claim_sets</c>
/// is present (§6.3). The <c>meta</c> rule is configurable because deployed Verifiers
/// widely omit it; the default is strict (spec-conformant).
/// </summary>
[TestClass]
internal sealed class DcqlRequirednessTests
{
    private static JsonSerializerOptions Strict => new JsonSerializerOptions().ApplyVerifiableDefaults();
    private static JsonSerializerOptions Lenient => new JsonSerializerOptions().ApplyVerifiableDefaults(requireDcqlMeta: false);

    private const string MetaAbsentWire =
        """{"credentials":[{"id":"pid","format":"dc+sd-jwt"}]}""";

    private const string EmptyMetaWire =
        """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{}}]}""";


    [TestMethod]
    public void MetaAbsentIsRejectedUnderStrictDefault()
    {
        //OID4VP 1.0 §6.1: a Credential Query without 'meta' is non-conformant; the
        //strict (default) reader rejects it.
        Assert.ThrowsExactly<JsonException>(
            () => JsonSerializerExtensions.Deserialize<DcqlQuery>(MetaAbsentWire, Strict));
    }


    [TestMethod]
    public void MetaAbsentIsToleratedUnderLenientKnob()
    {
        //The configurability knob lets a deployment interoperate with Verifiers that
        //omit 'meta' (widely seen in practice).
        DcqlQuery? query = JsonSerializerExtensions.Deserialize<DcqlQuery>(MetaAbsentWire, Lenient);

        Assert.IsNotNull(query);
        Assert.IsNull(query!.Credentials![0].Meta);
    }


    [TestMethod]
    public void EmptyMetaIsAccepted()
    {
        //§6.1 allows an empty 'meta' (present, but placing no metadata constraints).
        //The reader accepts it; the evaluator treats it as "no type constraint".
        DcqlQuery? query = JsonSerializerExtensions.Deserialize<DcqlQuery>(EmptyMetaWire, Strict);

        Assert.IsNotNull(query);
        Assert.IsNotNull(query!.Credentials![0].Meta);
        Assert.IsFalse(query.Credentials[0].Meta!.HasTypeConstraints,
            "An empty meta carries no type constraints.");
    }


    [TestMethod]
    public void ClaimsQueryIdRequiredWhenClaimSetsPresent()
    {
        //OID4VP 1.0 §6.3: claim_sets references claims by id, so each Claims Query
        //MUST carry an id when claim_sets is present. Here the claims entry omits id.
        const string wire =
            """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{},"claims":[{"path":["family_name"]}],"claim_sets":[["family_name"]]}]}""";

        Assert.ThrowsExactly<JsonException>(
            () => JsonSerializerExtensions.Deserialize<DcqlQuery>(wire, Strict));
    }


    [TestMethod]
    public void ClaimsQueryWithoutClaimSetsAllowsAbsentId()
    {
        //§6.3: when claim_sets is absent, the Claims Query id is OPTIONAL.
        const string wire =
            """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{},"claims":[{"path":["family_name"]}]}]}""";

        DcqlQuery? query = JsonSerializerExtensions.Deserialize<DcqlQuery>(wire, Strict);

        Assert.IsNotNull(query);
        Assert.IsNull(query!.Credentials![0].Claims![0].Id);
    }
}
