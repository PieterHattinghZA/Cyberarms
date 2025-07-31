using System;
using System.Collections.Generic;
using System.Net;
using System.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Cyberarms.IntrusionDetection.Shared;

namespace IdsServiceForWindowsTest {
    [TestClass]
    public class LockTest {
        private TestContext testContextInstance;
        public TestContext TestContext {
            get { return testContextInstance; }
            set { testContextInstance = value; }
        }

        [TestMethod]
        public void TestIpAddressLocal() {
            AssertIpAddressLocalLogic();
        }

        [TestMethod]
        public void TestIsIpAddressLocalPerformanceTest() {
            var stopwatch = Stopwatch.StartNew();
            for (int i = 0; i < 2000; i++) {
                AssertIpAddressLocalLogic();
            }
            stopwatch.Stop();
            if (stopwatch.Elapsed.TotalSeconds > 1) {
                Assert.Fail($"Time taken for 28,000 IP address comparisons: {stopwatch.Elapsed.TotalSeconds} seconds!");
            }
        }

        private void AssertIpAddressLocalLogic() {
            IPAddress ip = IPAddress.Parse("127.0.0.1");
            Assert.IsTrue(IddsConfig.Instance.IsIpAddressLocal(ip), "127.0.0.1 should be local");

            foreach (IPAddress address in GetLocalIps()) {
                Assert.IsTrue(IddsConfig.Instance.IsIpAddressLocal(address), $"{address} should be local");
            }

            Assert.IsFalse(IddsConfig.Instance.IsIpAddressLocal(IPAddress.Parse("10.1.1.1")), "10.1.1.1 should not be local");
            Assert.IsFalse(IddsConfig.Instance.IsIpAddressLocal(IPAddress.Parse("192.168.13.1")), "192.168.13.1 should not be local");
            Assert.IsFalse(IddsConfig.Instance.IsIpAddressLocal(IPAddress.Parse("73.24.12.42")), "73.24.12.42 should not be local");
        }

        private static List<IPAddress> _localAddresses;
        private static readonly object _lock = new object();

        private static List<IPAddress> GetLocalIps() {
            if (_localAddresses == null) {
                lock (_lock) {
                    if (_localAddresses == null) {
                        _localAddresses = new List<IPAddress>();
                        foreach (var iface in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()) {
                            var iprop = iface.GetIPProperties();
                            foreach (var info in iprop.UnicastAddresses) {
                                _localAddresses.Add(info.Address);
                            }
                        }
                    }
                }
            }
            return _localAddresses;
        }
    }
}
