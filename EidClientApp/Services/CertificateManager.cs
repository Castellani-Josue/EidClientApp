using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI41;


namespace EidClientApp.Services
{
    public class CertificateManager
    {
        public IObjectHandle FindCertificate(ISession session, string label)
        {
            var searchTemplate = new List<IObjectAttribute>
        {
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
            new ObjectAttribute(CKA.CKA_LABEL, label)
        };

            session.FindObjectsInit(searchTemplate);
            var foundObjects = session.FindObjects(1);
            session.FindObjectsFinal();

            return foundObjects.FirstOrDefault();
        }

        public byte[] GetRawCertificateValue(ISession session, IObjectHandle certHandle)
        {
            var attrs = session.GetAttributeValue(certHandle, new List<CKA> { CKA.CKA_VALUE });
            return attrs.FirstOrDefault()?.GetValueAsByteArray();
        }

        public string GetLabel(ISession session, IObjectHandle certHandle)
        {
            var attrs = session.GetAttributeValue(certHandle, new List<CKA> { CKA.CKA_LABEL });
            return attrs.FirstOrDefault()?.GetValueAsString();
        }
    }
}
