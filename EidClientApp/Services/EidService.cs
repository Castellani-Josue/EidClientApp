using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI41;
using Net.Pkcs11Interop.HighLevelAPI80.Factories;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace EidClientApp.Services
{
    public class EidService
    {
        private readonly string _pkcs11LibraryPath = @"C:\Windows\System32\beidpkcs11.dll";

        public void ListAvailableSlots()
        {
            var factories = new Pkcs11InteropFactories();

            try
            {
                Console.WriteLine("Chargement de la bibliothèque PKCS#11...");
                using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory
                    .LoadPkcs11Library(factories, _pkcs11LibraryPath, AppType.MultiThreaded))
                {
                    Console.WriteLine("Bibliothèque PKCS#11 chargée avec succès.");

                    List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);

                    if (slots.Count == 0)
                    {
                        Console.WriteLine(" Aucun lecteur avec carte eID insérée.");
                        return;
                    }

                    Console.WriteLine(" Lecteurs eID détectés :");
                    foreach (var slot in slots)
                    {
                        var info = slot.GetSlotInfo();
                        Console.WriteLine($"  - {info.SlotDescription.Trim()}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($" Erreur lors du chargement de la bibliothèque ou de la récupération des slots : {ex.Message}");
            }
        }

        public void ProcessEidCard()
        {
            var factories = new Pkcs11InteropFactories();

            try
            {
                Console.WriteLine("Chargement de la bibliothèque PKCS#11...");
                using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory
                    .LoadPkcs11Library(factories, _pkcs11LibraryPath, AppType.MultiThreaded))
                {
                    Console.WriteLine("Bibliothèque PKCS#11 chargée avec succès.");

                    var slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);
                    if (slots.Count == 0)
                    {
                        Console.WriteLine("Aucun token trouvé.");
                        return;
                    }

                    var slot = slots[0];
                    Console.WriteLine($"Token trouvé dans le slot : {slot.GetSlotInfo().SlotDescription.Trim()}");

                    using (ISession session = slot.OpenSession(SessionType.ReadWrite))
                    {
                        Console.WriteLine("Session ouverte avec succès.");

                        // Recherche des objets (certificats)
                        Console.WriteLine("Recherche des certificats...");
                        session.FindObjectsInit(new List<IObjectAttribute>
                        {
                         
                            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE) // Utilisation des noms corrects
                        });
                        Console.WriteLine("Recherche des certificats presque terminée.");
                        var certificates = session.FindObjects(1); // Correction : FindObjects retourne une liste d'objets
                        Console.WriteLine("Recherche des certificats terminée.");
                        session.FindObjectsFinal();

                        if (certificates.Count > 0)
                        {
                            var certificate = certificates[0];
                            var certInfo = session.GetAttributeValue(certificate, new List<CKA> { CKA.CKA_LABEL, CKA.CKA_VALUE });

                            Console.WriteLine("Certificat X.509 trouvé !");
                            Console.WriteLine($"Label : {certInfo[0].GetValueAsString()}");
                            Console.WriteLine($"Certificat (hex) : {BitConverter.ToString(certInfo[1].GetValueAsByteArray())}");

                            // Message à signer
                            string message = "Ceci est un message à signer";
                            byte[] messageBytes = Encoding.UTF8.GetBytes(message);

                            // Signature du message
                            byte[] signature = SignMessage(session, certificate, messageBytes);
                            Console.WriteLine("Signature effectuée avec succès !");
                            Console.WriteLine($"Signature : {BitConverter.ToString(signature)}");
                        }
                        else
                        {
                            Console.WriteLine("Aucun certificat trouvé.");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erreur lors du traitement de la carte eID : {ex.Message}");
            }
        }

        private byte[] SignMessage(ISession session, IObjectHandle certificate, byte[] messageBytes)
        {
            try
            {
                Console.WriteLine("Création du mécanisme de signature RSA...");

                // Retrieve the label of the certificate
                var certAttributes = session.GetAttributeValue(certificate, new List<CKA> { CKA.CKA_LABEL });
                string certLabel = certAttributes.FirstOrDefault(attr => attr.Type == (ulong)CKA.CKA_LABEL)?.GetValueAsString();

                if (string.IsNullOrEmpty(certLabel))
                {
                    Console.WriteLine("Impossible de récupérer le label du certificat.");
                    return null;
                }

                // Search for the private key associated with the certificate label
                List<IObjectAttribute> privateKeyAttributes = new List<IObjectAttribute>
        {
            new ObjectAttribute((ulong)CKA.CKA_LABEL, certLabel) // Cast CKA to ulong to fix CS1503
        };

                session.FindObjectsInit(privateKeyAttributes);
                var privateKeys = session.FindObjects(1); // Limité à 1 clé privée
                session.FindObjectsFinal();

                if (privateKeys.Count == 0)
                {
                    Console.WriteLine("Aucune clé privée trouvée associée au certificat de signature.");
                    return null;
                }

                var privateKey = privateKeys[0];

                using (SHA256 sha256 = SHA256.Create())
                {

                    IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_SHA256_RSA_PKCS);
                    Console.WriteLine("Mécanisme de signature ECDSA créé.");

                    Console.WriteLine("Signature du message...");
                    byte[] signature = session.Sign(mechanism, privateKey, messageBytes);
                    Console.WriteLine("Message signé.");
                    return signature;
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erreur lors de la signature du message : {ex.Message}");
                throw;
            }
        }



        public void ListSupportedMechanisms()
        {
            var factories = new Pkcs11InteropFactories();

            try
            {
                Console.WriteLine("Chargement de la bibliothèque PKCS#11...");
                using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory
                    .LoadPkcs11Library(factories, _pkcs11LibraryPath, AppType.MultiThreaded))
                {
                    Console.WriteLine("Bibliothèque PKCS#11 chargée avec succès.");

                    List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);

                    if (slots.Count == 0)
                    {
                        Console.WriteLine("Aucun lecteur avec carte eID insérée.");
                        return;
                    }

                    Console.WriteLine("Lecteurs eID détectés :");
                    foreach (var slot in slots)
                    {
                        var info = slot.GetSlotInfo();
                        Console.WriteLine($"  - {info.SlotDescription.Trim()}");

                        // Liste des mécanismes supportés pour ce slot
                        var mechanisms = slot.GetMechanismList();
                        Console.WriteLine("  Mécanismes supportés :");
                        foreach (var mechanism in mechanisms)
                        {
                            Console.WriteLine($"   - {mechanism}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erreur lors du chargement de la bibliothèque ou de la récupération des mécanismes : {ex.Message}");
            }
        }


    }
}
