using System.Configuration;

using Amazon;
using Amazon.KeyManagementService;

using FluentAssertions;

using NUnit.Framework;

namespace AwsContrib.EnvelopeCrypto.IntegrationTests
{
	public class CryptoProviderTests
	{
		[Test]
		public void RoundTrip_Ok()
		{
			// Depends on client being configured in app.config or ambient environment.
			IAmazonKeyManagementService client = AWSClientFactory.CreateAmazonKeyManagementServiceClient();

			string keyid = ConfigurationManager.AppSettings["kmsKeyId"];
			ICryptoProvider crypto = new EnvelopeCryptoProvider(client, keyid);

			const string plaintext = "Peek-a-boo!";
			string dataKey;
			string ciphertext = crypto.Encrypt(out dataKey, plaintext);

			dataKey.Should().NotBeEmpty();
			ciphertext.Should().NotBe(plaintext);

			string decrypted = crypto.Decrypt(dataKey, ciphertext);
			decrypted.Should().Be("Peek-a-boo!");
		}
	}
}