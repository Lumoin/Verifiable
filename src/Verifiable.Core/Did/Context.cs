using System.Collections.Generic;

namespace Verifiable.Core.Did
{
    //TODO: Should the additional data be typed or a generic? In .NET5 it could be
    //Dynamic, modelled as in https://docs.microsoft.com/en-us/dotnet/standard/serialization/system-text-json-converters-how-to?pivots=dotnet-5-0#deserialize-inferred-types-to-object-properties.
    //The issue here already now is about reading arbitrary amounts of data from a network
    //or another source beyond trust boundary.
    //Look at https://github.com/dotnet/runtime/issues/29690, https://github.com/steveharter/designs/blob/6437453395619af937bf84a60c13d1bc43d7ca05/accepted/2020/serializer/WriteableDomAndDynamic.md#api-walkthrough
    //and https://github.com/dotnet/designs/pull/163 for a writeable DOM and complex object logic with STJ (and Newtonsoft).
    /// <summary>
    /// https://www.w3.org/TR/did-spec-registries/#context
    /// </summary>
    public class Context
    {
        public List<object>? Contexes { get; set; }

        public IDictionary<string, object>? AdditionalData { get; set; }
    }
}
