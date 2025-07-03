using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;

namespace Verifiable.Core.Did.CryptographicSuites
{
    public abstract class CryptographicSuite2
    {
        /// <summary>
        /// All proof types supported by this suite.
        /// </summary>
        public abstract ReadOnlyCollection<ProofTypeInfo> ProofTypes { get; }

        /// <summary>
        /// All verification methods compatible with any proof type in this suite.
        /// </summary>
        public IEnumerable<VerificationMethodTypeInfo> GetCompatibleVerificationMethods(IEnumerable<VerificationMethodTypeInfo> availableVerificationMethods)
        {
            return availableVerificationMethods.Where(vm =>
                ProofTypes.Any(pt => pt.IsCompatibleWith(vm)));
        }
    }
}
