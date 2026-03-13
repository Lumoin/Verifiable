using System.Text.Json.Serialization;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.Did;
using Verifiable.Core.StatusList;

namespace Verifiable.Json;

/// <summary>
/// Source-generated serialization metadata for roundtrip tests. Lists root
/// document types and types that custom converters resolve via
/// <c>options.GetTypeInfo</c>. All converters read primitive arrays
/// (string, int, bool) manually, so no <c>List&lt;string&gt;</c> entry is needed.
/// </summary>
//DID and VC root document types.
[JsonSerializable(typeof(DidDocument))]
[JsonSerializable(typeof(VerifiableCredential))]
[JsonSerializable(typeof(VerifiablePresentation))]
//DCQL root type. Element types have custom converters and are resolved
//per-element via GetTypeInfo.
[JsonSerializable(typeof(DcqlQuery))]
[JsonSerializable(typeof(CredentialQuery))]
[JsonSerializable(typeof(CredentialSetQuery))]
[JsonSerializable(typeof(ClaimsQuery))]
[JsonSerializable(typeof(TrustedAuthoritiesQuery))]
[JsonSerializable(typeof(CredentialQueryMeta))]
//VerificationMethod resolved via GetTypeInfo in VerificationMethodConverter
//and for embedded verification in VerificationMethodReferenceConverter and
//DataIntegrityProofConverter. VerificationMethodReference subclasses are
//fully handled by manual converters and do not go through source-gen.
[JsonSerializable(typeof(VerificationMethod))]
//JOSE header serialization.
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(Dictionary<string, object?>))]
[JsonSerializable(typeof(Dictionary<string, object>))]
//Primitive arrays used in manual converters (e.g. StatusListAggregationJsonConverter).
[JsonSerializable(typeof(string[]))]
//JSON-LD context serialization for proof options documents.
[JsonSerializable(typeof(Context))]
//Status list types resolved via GetTypeInfo in status list converters.
[JsonSerializable(typeof(Core.StatusList.StatusList))]
[JsonSerializable(typeof(StatusListReference))]
[JsonSerializable(typeof(StatusClaim))]
[JsonSerializable(typeof(StatusListAggregation))]
internal partial class VerifiableJsonContext: JsonSerializerContext
{
}