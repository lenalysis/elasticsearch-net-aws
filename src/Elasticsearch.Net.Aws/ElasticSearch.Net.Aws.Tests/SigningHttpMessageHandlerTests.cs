﻿using System;
using System.Diagnostics;
using System.Globalization;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Amazon.Runtime;
using Elasticsearch.Net.Aws;
using NUnit.Framework;
using Elasticsearch.Net;
using System.IO;
using Amazon;
#if NETFRAMEWORK
using System.Net;
#endif

namespace Tests
{
    [TestFixture]
    public class SigningHttpMessageHandlerTests
    {
#if NETCOREAPP
        private class TestHandler : HttpClientHandler
        {
            public bool Disposed;
            protected override void Dispose(bool disposing)
            {
                base.Dispose(disposing);
                Disposed = true;
            }
        }

        [Test]
        public void TestDispose()
        {
            var inner = new TestHandler();
            var outer = new SigningHttpMessageHandler(new BasicAWSCredentials("foo", "bar"), RegionEndpoint.USEast1, false);
            outer.Dispose();
            Assert.AreEqual(true, inner.Disposed);
        }
#endif
    }
}
