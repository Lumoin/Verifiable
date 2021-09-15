using System;
using System.Diagnostics;

namespace Verifiable.Core.Did
{
    /// <summary>
    /// https://www.w3.org/TR/did-core/#services
    /// </summary>
    [DebuggerDisplay("Service(Id = {Id})")]
    public class Service
    {
        public Uri? Id { get; set; }

        //This should be an array, see new document. Do in converter like for Context. Maybe introduce type for this purpose?
        //https://docs.microsoft.com/en-us/dotnet/api/system.collections.generic.sortedlist-2 etc.?
        //Maybe with explicit conversions to/from a type? See https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/operators/user-defined-conversion-operators.
        public string? Type { get; set; }

        //This can a string, a map or a set. See at https://www.w3.org/TR/did-core/#service-properties. In ION there is "serviceEndpoint": { "origins": [ "https://www.vcsatoshi.com/" ] }.
        //Look at https://github.com/dotnet/runtime/issues/53195, https://github.com/steveharter/designs/blob/6437453395619af937bf84a60c13d1bc43d7ca05/accepted/2020/serializer/WriteableDomAndDynamic.md#api-walkthrough
        //and https://github.com/dotnet/designs/pull/163 for a writeable DOM and complex object logic with STJ (and Newtonsoft).
        public string? ServiceEndpoint { get; set; }

        //Here is an example of a more complicated service endpoint. -> Take in as a test.
        //https://www.w3.org/TR/did-spec-registries/#example-24-example-of-service-and-serviceendpoint-properties

        //The following comment should probably include, in addition to "standard notes" that
        //one preferably should extend the data instead of putting it into a bucket like that.
        //But that the bucket exists in case one wants to "eat up" all data.
        //Is ServiceDtos examples the best way to see this? I.e. the AdditionalData is not visible
        //UNLESS on inherits. It needs to clear it's so that one needs to inherit if additional data
        //is expected? Also, shouldn't in those examples the ServiceEndpoint be extended?

        /// <summary>
        /// Each service extension MAY include additional properties and MAY further restrict the properties associated with the extension.
        /// </summary>
        //public IDictionary<string, object>? AdditionalData { get; set; }
    }
}
