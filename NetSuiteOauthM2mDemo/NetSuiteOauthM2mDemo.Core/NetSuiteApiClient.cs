using System.Text.Json;
using System.Linq;

using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;

using Microsoft.IdentityModel.Tokens;

namespace NetSuiteOauthM2mDemo.Core
{
    public class NetSuiteApiClient
    {
        private const string AccountId = "XXXXX-sb1";

        private const string ClientCredentialsCertificateId = "XXXXX";
        private string ApiConsumerKey = "XXXXX";

        private const string PrivateKeyPem = @"-----BEGIN PRIVATE KEY-----
XXXXX
-----END PRIVATE KEY-----";


        private static string RestApiRoot = $"https://{AccountId}.suitetalk.api.netsuite.com/services/rest";

        private static string Oauth2ApiRoot = $"{RestApiRoot}/auth/oauth2/v1";
        private static string RecordApiRoot = $"{RestApiRoot}/record/v1";

        private static string TokenEndPointUrl = $"{Oauth2ApiRoot}/token";

        private static readonly HttpClient _httpClient = new HttpClient();

        private static string _accessToken;

        public async Task<string> GetAccessToken()
        {
            var url = Oauth2ApiRoot + "/token/";

            string clientAssertion = GetJwtToken();

            var requestParams = new List<KeyValuePair<string, string>>();
            requestParams.Add(new KeyValuePair<string, string>("grant_type", "client_credentials"));
            requestParams.Add(new KeyValuePair<string, string>("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
            requestParams.Add(new KeyValuePair<string, string>("client_assertion", clientAssertion));

            using var httpRequest = new HttpRequestMessage(HttpMethod.Post, url);
            httpRequest.Content = new FormUrlEncodedContent(requestParams);

            var httpResponse = await _httpClient.SendAsync(httpRequest);
            var responseJson = await httpResponse.Content.ReadAsStringAsync();


            var response = JsonSerializer.Deserialize<NsToken>(responseJson);

            return response.access_token;

        }

        private string GetJwtToken()
        {
            string privateKeyPem = PrivateKeyPem;

            // keep only the payload of the key. 
            privateKeyPem = privateKeyPem.Replace("-----BEGIN PRIVATE KEY-----", "");
            privateKeyPem = privateKeyPem.Replace("-----END PRIVATE KEY-----", "");

            // Create the RSA key.
            byte[] privateKeyRaw = Convert.FromBase64String(privateKeyPem);
            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.ImportPkcs8PrivateKey(new ReadOnlySpan<byte>(privateKeyRaw), out _);
            
            RsaSecurityKey rsaSecurityKey = new RsaSecurityKey(provider);

            // Create signature and add to it the certificate ID provided by NetSuite.
            var signingCreds = new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha256);
            signingCreds.Key.KeyId = ClientCredentialsCertificateId;

            // Get issuing timestamp.
            var now = DateTime.UtcNow;

            // Create token.
            var tokenHandler = new JwtSecurityTokenHandler();

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = ApiConsumerKey,
                Audience = TokenEndPointUrl,
                Expires = now.AddMinutes(5),
                IssuedAt = now,
                Claims = new Dictionary<string, object> { 
                                                            { "scope", new[] { "rest_webservices" } } 
                                                        },
                SigningCredentials = signingCreds
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenText =  tokenHandler.WriteToken(token);

            return tokenText;
        }

        public async Task<List<string>> FindCustomerIds(int limit)
        {
            var url = RecordApiRoot + "/customer?limit=" + limit;

            if (_accessToken == null)
                _accessToken = await GetAccessToken();

            using var httpRequest = new HttpRequestMessage(HttpMethod.Get, url);
            httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);

            var httpResponse = await _httpClient.SendAsync(httpRequest);
            var responseJson = await httpResponse.Content.ReadAsStringAsync();

            var response =
                JsonSerializer.Deserialize<NsFindIdsResponse>(responseJson);

            return response.items.Select(i => i.id).ToList();
        }

        public async Task<NsCustomer> GetCustomer(int customerId)
        {
            var url = RecordApiRoot + "/customer/" + customerId;

            if (_accessToken == null)
                _accessToken = await GetAccessToken();

            using var httpRequest = new HttpRequestMessage(HttpMethod.Get, url);
            httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
            
             var httpResponse = await _httpClient.SendAsync(httpRequest);
            var responseJson = await httpResponse.Content.ReadAsStringAsync();

            var customer =
                 JsonSerializer.Deserialize<NsCustomer>(responseJson);

            return customer;
        }

    }
}