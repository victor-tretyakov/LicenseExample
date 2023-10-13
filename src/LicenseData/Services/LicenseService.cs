using grdlic;
using System.Collections;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Xml.Linq;
using System.Xml;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace LicenseData.Services
{
    public class LicenseService : ILicenseService
    {
        private readonly ILogger _logger;

        public LicenseService(ILogger<LicenseService> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public bool CheckLicense()
        {
            _logger.LogInformation("Example of using Grdlic API");
            try
            {
                // call GrdGetApiVersion
                _logger.LogInformation("Call GrdGetApiVersion");

                uint v, major, minor;

                Status r = GrdlicApi.GrdGetApiVersion(out v, out major, out minor);
                HandleError(r);
                _logger.LogInformation("API version: " + major.ToString() + "." + minor.ToString());

                // get info about available licenses across this PC (because of m_remoteMode = RemoteMode.LOCAL)
                string visibility = "{\"dongleModel\": 0x480, \"remoteMode\": 3}";
                _logger.LogInformation("Call GrdGetLicenseInfo");

                r = GrdlicApi.GrdGetLicenseInfo(visibility, null, out string licenses);
                HandleError(r);

                _logger.LogInformation("ALL AVAILABLE LICENSES:");

                // get some feature to work with
                uint featureNumber;
                PrintLicensesInfo(licenses, out featureNumber);

                // do login to feature
                _logger.LogInformation("Try login feature {0}", featureNumber);

                GrdlicApi.Feature feature = new(featureNumber);

                VendorCodes vendorAccessCodes = new VendorCodes(0x519175b7, 0x51917645);

                r = feature.Login(vendorAccessCodes, visibility);

                HandleError(r);

                // get feature license info
                _logger.LogInformation("Get feature {0} info", featureNumber);

                string licenseInfo;

                r = feature.GetInfo(out licenseInfo);
                HandleError(r);

                // print feature info
                _logger.LogInformation("FEATURE INFO:");

                uint dummy;
                PrintLicenseInfo(licenseInfo, out dummy);

                // check feature
                _logger.LogInformation("Check feature");
                r = feature.Check(null);
                HandleError(r);

                // encrypt data
                _logger.LogInformation("Encrypt data");

                byte[] data = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

                byte[] hash = SHA1.HashData(data);
                r = feature.Encrypt(data, FeatureEncryptMode.GRD_EM_ECB, null);
                HandleError(r);

                // decrypt data
                _logger.LogInformation("Decrypt data");
                r = feature.Decrypt(data, FeatureEncryptMode.GRD_EM_ECB, null);
                HandleError(r);
                bool compareResult = StructuralComparisons.StructuralEqualityComparer.Equals(hash, SHA1.HashData(data));
                _logger.LogInformation("Decryption sanity check: {0}", compareResult);

                if (!compareResult)
                    throw new ApplicationException("Invalid hash data!");

                // unlimited encrypt data
                _logger.LogInformation("Encrypt data");
                hash = SHA1.HashData(data);
                r = feature.Encrypt(data, FeatureEncryptMode.GRD_NO_COUNTER_DECREMENT | FeatureEncryptMode.GRD_EM_ECB, null);
                HandleError(r);

                // unlimited decrypt data
                _logger.LogInformation("Decrypt data");
                r = feature.Decrypt(data, FeatureEncryptMode.GRD_NO_COUNTER_DECREMENT | FeatureEncryptMode.GRD_EM_ECB, null);
                HandleError(r);

                compareResult = StructuralComparisons.StructuralEqualityComparer.Equals(hash, SHA1.HashData(data));

                _logger.LogInformation("Unlimited decryption sanity check: {0}", compareResult);

                if (!compareResult)
                    throw new ApplicationException("Invalid hash data!");

                // sign data
                _logger.LogInformation("Sign data");
                byte[] message = new byte[(int)GrdECC160.MESSAGE_SIZE];
                byte[] digest;
                r = feature.Sign(message, out digest);
                HandleError(r);

                //                // verify sign [! required feature correct public key]
                //                Console.WriteLine("Verify sign");
                //                byte[] publicKey = {0x1D, 0xCE, 0x42, 0x91, 0xEF, 0xF6, 0x8C, 0x6A, 0xEC, 0xB6, 0xC6, 0x76, 0x7E, 0xF0, 0xCC, 0x0B, 0x61, 0xD5, 0xA1, 0x73, 0x69, 0x14, 0x53, 0x05, 0xC3, 0xFD, 0x98, 0x93, 0xD6, 0x0A, 0xF8, 0xFA, 0x03, 0xE1, 0x8C, 0x37, 0x99, 0x4B, 0x95, 0x6B};
                //                r = GrdlicApi.GrdVerifySign(publicKey, message, digest);
                //                HandleError(r);

                // get feature rest of the lifetime in seconds
                _logger.LogInformation("Get feature rest of the lifetime");

                long remainingTime;

                r = feature.GetTimeLimit(out remainingTime);
                if (r == Status.NO_SERVICE)
                    _logger.LogInformation("NO SERVICE (skip)");
                else
                    HandleError(r);

                _logger.LogInformation("Remaining time: {0}", remainingTime);

                // get rest of feature run counter value
                _logger.LogInformation("Get feature rest of the run counter value");

                uint runCounter;
                r = feature.GetRunCounter(out runCounter);

                if (r == Status.NO_SERVICE)
                    _logger.LogInformation("NO SERVICE (skip)");
                else
                    HandleError(r);

                _logger.LogInformation("Run counter value: {0}", runCounter);

                // get time from real clock in seconds
                _logger.LogInformation("Get time from real clock");

                long currentTime;

                r = feature.GetRealTime(out currentTime);

                HandleError(r);

                _logger.LogInformation("Current time: {0}", currentTime);

                // get feature max concurrent resource value
                _logger.LogInformation("Get feature max concurrent resource value");

                uint value;

                r = feature.GetMaxConcurrentResource(out value);

                HandleError(r);

                _logger.LogInformation("Feature max concurrent resource value: {0}", value);

                // logout from feature
                _logger.LogInformation("Logout from feature {0}", featureNumber);
                r = feature.Logout();
                HandleError(r);
            }
            catch (Exception e)
            {
                _logger.LogInformation(e.ToString());
                return false;
            }

            return true;
        }

        private void HandleError(Status s)
        {
            _logger.LogInformation("Status: " + s.ToString());
            if (s != Status.OK)
            {
                _logger.LogInformation("Error. Quit program");
                Environment.Exit(-1);
            }
        }

        private void PrintLicenseInfo(string licenseInfo, out UInt32 firstFeatureNumber)
        {
            firstFeatureNumber = 0;

            var x = new XmlDictionaryReaderQuotas();
            var jsonReader = JsonReaderWriterFactory.CreateJsonReader(Encoding.UTF8.GetBytes(licenseInfo), x);
            var license = XElement.Load(jsonReader);

            PrintLicenseInfo(license, out firstFeatureNumber);
        }

        private void PrintLicenseInfo(XElement license, out UInt32 firstFeatureNumber)
        {
            firstFeatureNumber = 0;

            int isBroken = Convert.ToInt32(license.Element("isBroken").Value);
            if (isBroken == 1)
            {
                _logger.LogInformation("License {0} in DL is broken", license.Attribute("licenseId").Value);
                return;
            }

            var licenseInfo = license.Element("licenseInfo");
            if (licenseInfo == null || licenseInfo.IsEmpty)
            {
                var dongleInfo = license.Element("dongleInfo");
                _logger.LogInformation("Hardware dongle without license. Dongle: ID {0}. Model: {1}. Vendor public code: {2}",
                                                                 dongleInfo.Element("dongleId").Value,
                                                                 dongleInfo.Element("dongleModel").Value,
                                                                 dongleInfo.Element("publicCode").Value);
                return;
            }

            _logger.LogInformation("License {0} vendor public {1} vendor company {2} products count {3} ",
                                                              licenseInfo.Element("licenseId").Value,
                                                              licenseInfo.Element("vendorPublicCode").Value,
                                                              licenseInfo.Element("vendorCompanyName").Value,
                                                              licenseInfo.Element("productsCount").Value);

            var products = licenseInfo.Elements("products");
            Console.WriteLine("\tProducts:");
            foreach (XElement product in products.Elements())
            {
                _logger.LogInformation("\tProduct {0} with number {1} [modification {2}] with {3} features",
                                  product.Element("name").Value,
                                  product.Element("number").Value,
                                  product.Element("modification").Value,
                                  product.Element("featuresCount").Value);

                var features = product.Elements("features");
                _logger.LogInformation("\t\tFeatures:");
                bool setFirstFeatureNumber = false;
                foreach (XElement feature in features.Elements())
                {
                    if (!setFirstFeatureNumber)
                    {
                        firstFeatureNumber = Convert.ToUInt32(feature.Element("number").Value);
                        setFirstFeatureNumber = true;
                    }

                    _logger.LogInformation("\t\tFeature {0} with number {1}",
                                      feature.Element("name").Value,
                                      feature.Element("number").Value,
                                      feature.Element("restOfLifeTime").Value
                                      );
                }
            }
        }

        private void PrintLicensesInfo(string licenses, out UInt32 firstFeatureNumber)
        {
            firstFeatureNumber = 0;

            if (licenses == null)
                return;

            var x = new XmlDictionaryReaderQuotas();
            var jsonReader = JsonReaderWriterFactory.CreateJsonReader(Encoding.UTF8.GetBytes(licenses), x);
            var root = XElement.Load(jsonReader);

            var lic = root.Elements("licenses");

            if (lic == null)
                return;

            foreach (XElement el in lic.Elements())
            {
                PrintLicenseInfo(el, out firstFeatureNumber);
            }
        }
    }
}
