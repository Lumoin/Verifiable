using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotDecentralized.Core
{
    //https://www.w3.org/TR/vc-data-model/#types
    //All of these types MUST have type information.

    public class Credential { }

    public class VerifiableCredential: Credential { }

    public class Presentation { }

    public class VerifiablePresentation: Presentation { }

    public class Proof { }

    public class CredentialStatus { }

    public class TermsOfUse { }

    public class Evidence { }
}
