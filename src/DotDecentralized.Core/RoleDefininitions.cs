using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotDecentralized.Core
{
    //Look at https://github.com/dotnet/runtime/issues/29690, https://github.com/steveharter/designs/blob/6437453395619af937bf84a60c13d1bc43d7ca05/accepted/2020/serializer/WriteableDomAndDynamic.md#api-walkthrough
    //and https://github.com/dotnet/designs/pull/163 for a writeable DOM and complex object logic with STJ (and Newtonsoft).

    //These implement the roles at https://www.w3.org/TR/vc-data-model/#ecosystem-overview.
    public class Holder
    {
        //These are used by Verified to call VerifiableDataRegistry.
        public void VerifyIdentifierKeys() { }
        public void VerifyIdentifierSchemas() { }
        public void VerifyIdetifiers(VerifiableDataRegistry verifificationRegister, Credential credential, string schema) { }
    }


    /// <summary>
    /// This issues <see cref="VerifiableCredential"/> to users. Often the user is the <see cref="Subject"/> but
    /// sometimes credentials are issued on behalf of somene. Like the <see cref="Subject"/> can be a vaccination
    /// certificate and the <see cref="Issuer"/> issues it to the that person. Another similar example is issuing
    /// a vaccination certification to a pet owner.
    /// </summary>
    public class Issuer
    {
        //This is called by someone to issue a credential to some Holder.
        public Credential Issue(string someParams) { return new Credential();  }
    }

    public class Subject { }

    public class Verifier
    {
        //This is called by holder.
        public void PresentCrential(Presentation presentation) { }

        //These are used by Verified to call VerifiableDataRegistry.
        public void VerifyIdentifierKeys() { }
        public void VerifyIdentifierSchemas() { }
        public void VerifyIdetifiers(VerifiableDataRegistry verifificationRegister, Credential credential, string schema) { }
    }


    public class VerifiableDataRegistry { }

    //An extra piece...
    public class Wallet
    {
        //These are used by the holder.
        public void StoreCredential(Credential credential) { }
        public Credential RetrieveCredential(string id) { return new Credential(); }
    }
}
