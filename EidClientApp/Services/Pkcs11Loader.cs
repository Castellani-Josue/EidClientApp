using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EidClientApp.Services
{
    public class Pkcs11Loader
    {
        private readonly string _libraryPath;
        private readonly Pkcs11InteropFactories _factories;

        public Pkcs11Loader(string libraryPath)
        {
            _libraryPath = libraryPath;
            _factories = new Pkcs11InteropFactories();
        }

        public IPkcs11Library LoadLibrary()
        {
            return _factories.Pkcs11LibraryFactory.LoadPkcs11Library(_factories, _libraryPath, AppType.MultiThreaded);
        }

        public List<ISlot> GetAvailableSlots(IPkcs11Library library)
        {
            return library.GetSlotList(SlotsType.WithTokenPresent);
        }
    }
}
