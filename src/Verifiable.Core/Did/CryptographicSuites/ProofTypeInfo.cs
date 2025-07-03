using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace Verifiable.Core.Did.CryptographicSuites
{
    public sealed class ProofTypeInfo
    {
        public string TypeName { get; }
        public ReadOnlyCollection<string> Contexts { get; }
        public Func<VerificationMethodTypeInfo, bool> IsCompatibleWith { get; }

        public ProofTypeInfo(string typeName, IEnumerable<string> contexts, Func<VerificationMethodTypeInfo, bool> compatibilityCheck)
        {
            TypeName = typeName ?? throw new ArgumentNullException(nameof(typeName));
            Contexts = contexts?.ToList().AsReadOnly() ?? throw new ArgumentNullException(nameof(contexts));
            IsCompatibleWith = compatibilityCheck ?? throw new ArgumentNullException(nameof(compatibilityCheck));
        }
    }
}
