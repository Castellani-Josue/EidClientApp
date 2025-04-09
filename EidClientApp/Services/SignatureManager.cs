using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI41;


namespace EidClientApp.Services
{
    public class SignatureManager
    {
        public byte[] SignMessage(ISession session, string label, byte[] messageBytes)
        {
            try
            {
                // Recherche de la clé privée avec le même label
                List<IObjectAttribute> privateKeyAttributes = new List<IObjectAttribute>
                {
                    new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                    new ObjectAttribute(CKA.CKA_LABEL, label)
                };

                session.FindObjectsInit(privateKeyAttributes);
                var privateKeys = session.FindObjects(1);
                session.FindObjectsFinal();

                if (privateKeys.Count == 0)
                {
                    Console.WriteLine("Aucune clé privée trouvée associée au certificat " + label);
                    return null;
                }

                var privateKey = privateKeys[0];

                // Modification : utiliser le mécanisme CKM_ECDSA_SHA256
                IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_ECDSA_SHA256);
                Console.WriteLine("Mécanisme de signature CKM_ECDSA_SHA256 créé.");
                byte[] 

                // Signature du message brut (le mécanisme se charge du hachage)
                Console.WriteLine("Signature du message...");
                //byte[] signature = session.Sign(mechanism, privateKey, messageBytes);
                Console.WriteLine("Message signé.");
                return signature;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erreur lors de la signature du message : {ex.Message}");
                throw;
            }
        }

        public byte[] SignMessageWithoutSignature(ISession session, byte[] bytes)
        {
            try
            {
                IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_ECDSA_SHA256);
                Console.WriteLine("Mécanisme de signature CKM_ECDSA_SHA256 créé.");

                // Signature du message brut (le mécanisme se charge du hachage)
                Console.WriteLine("Signature du message...");
                byte[] signature = session.Sign(mechanism, null, bytes);
                Console.WriteLine("Message signé.");
                return signature;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erreur lors de la signature du message : {ex.Message}");
                throw;
            }
        }

    }
}

