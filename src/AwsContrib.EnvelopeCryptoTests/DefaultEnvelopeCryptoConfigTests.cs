using AwsContrib.EnvelopeCrypto;
using AwsContrib.EnvelopeCrypto.Internal;

using FluentAssertions;

using NUnit.Framework;

namespace AwsContrib.EnvelopeCryptoTests
{
	public class DefaultEnvelopeCryptoConfigTests
	{
		private DefaultEnvelopeCryptoConfig Config { get; set; }

		[SetUp]
		public void SetUp()
		{
			Config = new DefaultEnvelopeCryptoConfig();
		}

		[Test]
		public void AlgorithmName_Ok()
		{
			Config.AlgorithmName.Should().Be(EnvelopeCryptoProvider.AlgorithmName);
		}

		[Test]
		public void KeyBits_Ok()
		{
			Config.KeyBits.Should().Be(EnvelopeCryptoProvider.KeyBits);
		}

		[Test]
		public void BlockBytes_Ok()
		{
			Config.BlockBytes.Should().Be(EnvelopeCryptoProvider.BlockBytes);
		}

		[Test]
		public void IVBytes_Ok()
		{
			Config.IVBytes.Should().Be(EnvelopeCryptoProvider.IVBytes);
		}

		[Test]
		public void Mode_Ok()
		{
			Config.Mode.Should().Be(EnvelopeCryptoProvider.Mode);
		}

		[Test]
		public void Padding_Ok()
		{
			Config.Padding.Should().Be(EnvelopeCryptoProvider.Padding);
		}
	}
}