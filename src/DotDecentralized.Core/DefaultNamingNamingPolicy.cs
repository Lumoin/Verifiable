using System;
using System.Collections.ObjectModel;
using System.Text.Json;

namespace DotDecentralized.Core
{
    /// <summary>
    /// This naming policy combines the naming policies needed for DID Core specification
    /// conformant naming serialization and deserialization. The policies are applied
    /// in given order.
    /// </summary>
    /// <remarks>This handles @context element in JSON to a known type Context
    /// by naming it so the <see cref="JsonSerializer"/> can use it during serialization
    /// and deserialization and applies also any other policies to elements</remarks>
    public class DefaultNamingNamingPolicy: JsonNamingPolicy
    {
        /// <summary>
        /// Applied policies in application order.
        /// </summary>
        private ReadOnlyCollection<JsonNamingPolicy> Policies { get; }

        /// <summary>
        /// <see cref="DefaultNamingNamingPolicy"/> constructor.
        /// </summary>
        /// <param name="policies">Policies that are applied in given order.</param>
        public DefaultNamingNamingPolicy(ReadOnlyCollection<JsonNamingPolicy> policies)
        {
            Policies = policies ?? throw new ArgumentException(nameof(policies));
        }


        /// <inheritdoc />
        public override string ConvertName(string name)
        {
            string convertedName = name;
            if(string.IsNullOrWhiteSpace(name))
            {
                throw new ArgumentException(nameof(name));
            }

            if(name.Equals("@context", StringComparison.InvariantCultureIgnoreCase))
            {
                convertedName = "Context";
            }

            if(name.Equals("Context", StringComparison.InvariantCultureIgnoreCase))
            {
                return "@context";
            }

            int policyCount = Policies.Count;
            for(int i = 0; i < policyCount; ++i)
            {
                convertedName = Policies[i].ConvertName(convertedName);
            }

            return convertedName;
        }
    }
}
