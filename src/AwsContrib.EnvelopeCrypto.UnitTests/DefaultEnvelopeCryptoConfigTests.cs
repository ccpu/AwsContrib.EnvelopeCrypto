#region license
//
// Copyright 2015 ICA.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#endregion
using AwsContrib.EnvelopeCrypto;
using AwsContrib.EnvelopeCrypto.Internal;

using FluentAssertions;

using NUnit.Framework;

namespace AwsContrib.EnvelopeCrypto.UnitTests
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