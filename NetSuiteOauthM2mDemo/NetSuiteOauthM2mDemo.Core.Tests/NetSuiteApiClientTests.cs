using NUnit.Framework;
using System.Threading.Tasks;

namespace NetSuiteOauthM2mDemo.Core.Tests
{
    public class NetSuiteApiClientTests
    {

        [Test]
        public async Task GetAccessToken_ReturnsValidToken()
        {
            var nsApiClient = new NetSuiteApiClient();
            var accessToken = await nsApiClient.GetAccessToken();
            Assert.IsNotEmpty(accessToken);
        }

        [Test]
        public async Task FindCustomerIds_LimitTwo_TwoIds()
        {
            var nsApiClient = new NetSuiteApiClient();
            var ids = await nsApiClient.FindCustomerIds(2);
            Assert.AreEqual(2, ids.Count);
        }

        [Test]
        public async Task GetCustomer_ValidId_ReturnsCustomer()
        {
            var nsApiClient = new NetSuiteApiClient();
            var customer = await nsApiClient.GetCustomer(125173);

            Assert.IsNotNull(customer);

        }
    }
}