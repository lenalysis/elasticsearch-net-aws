#if NETSTANDARD
using System;
using System.Diagnostics;
using Amazon;
using Amazon.Runtime;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Aws.Crt.Auth;
using Aws.Crt.Http;
using Newtonsoft.Json.Linq;

namespace Elasticsearch.Net.Aws
{
    class SigningHttpMessageHandler : DelegatingHandler
    {
        readonly AWSCredentials _credentials;
        readonly RegionEndpoint _region;
        readonly bool _isServerlessService;

        public DateTimeOffset Timestamp;

        public SigningHttpMessageHandler(AWSCredentials credentials, RegionEndpoint region, bool isServerlessService)
        {
            _credentials = credentials;
            _region = region;
            _isServerlessService = isServerlessService;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var credentials = _credentials.GetCredentials();
            var serviceName = _isServerlessService ? "aoss" : "es";
            var creds = new Credentials(credentials.AccessKey, credentials.SecretKey, credentials.Token);
            var awsRequest = new HttpRequest
            {
                Method = request.Method.ToString(),
                Headers = new[] { new HttpHeader("host", request.RequestUri.Host) },
                Uri = request.RequestUri.PathAndQuery,
            };
            var awsSigningConfig = new AwsSigningConfig
            {
                Service = serviceName,
                Region = _region.SystemName,
                Algorithm = AwsSigningAlgorithm.SIGV4,
                SignatureType = AwsSignatureType.HTTP_REQUEST_VIA_HEADERS,
                SignedBodyHeader = AwsSignedBodyHeaderType.X_AMZ_CONTENT_SHA256,
                Credentials = creds,
                Timestamp = Timestamp,
            };

            var result = AwsSigner.SignHttpRequest(awsRequest, awsSigningConfig);
            var signingResult = result.Get();
            var signedRequest = signingResult.SignedRequest;
            foreach (var header in signedRequest.Headers)
            {
                if (request.Headers.Contains(header.Name))
                    request.Headers.Remove(header.Name);
                request.Headers.TryAddWithoutValidation(header.Name, header.Value);
            }

            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
    }
}
#endif
