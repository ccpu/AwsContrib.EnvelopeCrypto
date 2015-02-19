using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
			var client = Amazon.AWSClientFactory.CreateAmazonKeyManagementServiceClient();
			ICryptoProvider crypto = new EnvelopeCryptoProvider(client, ConfigurationManager.AppSettings["kmsKeyId"]);

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
