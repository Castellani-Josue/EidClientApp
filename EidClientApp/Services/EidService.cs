using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI41;
using Net.Pkcs11Interop.HighLevelAPI80.Factories;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
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
                        Console.WriteLine("Aucun lecteur avec carte eID insérée.");
                        return;
                    }

                    Console.WriteLine("Lecteurs eID détectés :");
                    foreach (var slot in slots)
                    {
                        var info = slot.GetSlotInfo();
                        Console.WriteLine($"  - {info.SlotDescription.Trim()}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erreur lors du chargement de la bibliothèque ou de la récupération des slots : {ex.Message}");
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

                        // Récupérer les certificats "Authentication" et "Signature"
                        var authCertHandle = FindCertificate(session, "Authentication");
                        var signCertHandle = FindCertificate(session, "Signature");

                        if (authCertHandle == null)
                        {
                            Console.WriteLine("Certificat d'Authentication non trouvé.");
                            return;
                        }
                        if (signCertHandle == null)
                        {
                            Console.WriteLine("Certificat de Signature non trouvé.");
                            return;
                        }

                        // Afficher les certificats (en hexadécimal)
                        var authCertValue = GetAttributeValue(session, authCertHandle, CKA.CKA_VALUE);
                        var signCertValue = GetAttributeValue(session, signCertHandle, CKA.CKA_VALUE);

                        Console.WriteLine("Certificat d'Authentication trouvé !");
                        Console.WriteLine($"  Label: {GetAttributeValue(session, authCertHandle, CKA.CKA_LABEL)}");
                        Console.WriteLine($"  Certificat (hex): {BitConverter.ToString(authCertValue)}");

                        Console.WriteLine("Certificat de Signature trouvé !");
                        Console.WriteLine($"  Label: {GetAttributeValue(session, signCertHandle, CKA.CKA_LABEL)}");
                        Console.WriteLine($"  Certificat (hex): {BitConverter.ToString(signCertValue)}");

                        // Extraction du NISS depuis le certificat d'Authentication
                        string niss = ExtractNissFromCertificate(authCertValue);
                        Console.WriteLine($"NISS extrait : {niss}");

                        // Message à signer
                        string message = "Ceci est un message à signer";
                        byte[] messageBytes = Encoding.UTF8.GetBytes(message);

                        // Signature du message en utilisant la clé privée associée au certificat de Signature
                        byte[] signature = SignMessage(session, "Signature", messageBytes);
                        if (signature != null)
                        {
                            Console.WriteLine("Signature effectuée avec succès !");
                            Console.WriteLine($"Signature (hex) : {BitConverter.ToString(signature)}");
                        }
                        else
                        {
                            Console.WriteLine("Erreur lors de la signature.");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erreur lors du traitement de la carte eID : {ex.Message}");
            }
        }

        /// <summary>
        /// Recherche un certificat à partir de son label
        /// </summary>
        private IObjectHandle FindCertificate(ISession session, string label)
        {
            List<IObjectAttribute> searchTemplate = new List<IObjectAttribute>
            {
                new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                new ObjectAttribute(CKA.CKA_LABEL, label)
            };

            session.FindObjectsInit(searchTemplate);
            var foundObjects = session.FindObjects(1);
            session.FindObjectsFinal();

            return foundObjects.Count > 0 ? foundObjects[0] : null;
        }

        /// <summary>
        /// Récupère la valeur d'un attribut donné à partir d'un objet
        /// </summary>
        private byte[] GetAttributeValue(ISession session, IObjectHandle objectHandle, CKA attributeType)
        {
            var attributes = session.GetAttributeValue(objectHandle, new List<CKA> { attributeType });
            return attributes.FirstOrDefault()?.GetValueAsByteArray();
        }

        /// <summary>
        /// Récupère la valeur en chaîne d'un attribut (ex: CKA_LABEL)
        /// </summary>
        private string GetAttributeValue(ISession session, IObjectHandle objectHandle, CKA attributeType, bool asString = true)
        {
            var attributes = session.GetAttributeValue(objectHandle, new List<CKA> { attributeType });
            return attributes.FirstOrDefault()?.GetValueAsString();
        }

        /// <summary>
        /// Extrait le NISS à partir du certificat.
        /// Cette méthode suppose que le sujet du certificat contient un champ "SN=" suivi du NISS.
        /// Adapte la méthode selon le format réel.
        /// </summary>
        private string ExtractNissFromCertificate(byte[] certBytes)
        {
            string niss = "";
            try
            {
                // On crée un X509Certificate2 pour analyser le sujet
                var cert = new X509Certificate2(certBytes);
                Console.WriteLine(cert.ToString(true));
                string subject = cert.Subject;
                // Recherche du champ "SN=" dans le sujet
                string[] parts = subject.Split(',');
                foreach (var part in parts)
                {
                    var trimmedPart = part.Trim();
                    if (trimmedPart.StartsWith("SERIALNUMBER="))
                    {
                        niss = trimmedPart.Substring("SERIALNUMBER=".Length);
                        break;
                    }
                }
                Console.WriteLine($"NISS trouvé dans le certificat : {niss}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erreur lors de l'extraction du NISS : {ex.Message}");
            }
            return niss;
        }

        /// <summary>
        /// Cherche la clé privée associée à un label donné (ici "Signature") et signe le message.
        /// On utilise CKM_SHA256_RSA_PKCS qui se charge du hachage.
        /// </summary>
        private byte[] SignMessage(ISession session, string label, byte[] messageBytes)
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

                // Signature du message brut (le mécanisme se charge du hachage)
                Console.WriteLine("Signature du message...");
                byte[] signature = session.Sign(mechanism, privateKey, messageBytes);
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
