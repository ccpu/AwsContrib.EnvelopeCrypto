using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AwsContrib.EnvelopeCrypto.Internal
{
	/// <summary>
	///     Represents an encrypted payload and metadata needed to decrypt it (except for the key).
	/// </summary>
	internal class EncryptedItem : IEnvelopeCryptoConfig
	{
		private static readonly Regex _prefixPattern = new Regex(@"^\{(\w{1,10})-(\d{1,5})(?:-(\w{1,5})(?:-(\w{1,10}))?)?\}");
		private readonly IEnvelopeCryptoConfig _cryptoConfig;
		private readonly byte[] _payload;

		public EncryptedItem(IEnvelopeCryptoConfig cryptoConfig, byte[] payload)
		{
			_cryptoConfig = cryptoConfig;
			_payload = payload;
		}

		public byte[] Payload
		{
			get { return _payload; }
		}

		public string AlgorithmName
		{
			get { return _cryptoConfig.AlgorithmName; }
		}

		public int KeyBits
		{
			get { return _cryptoConfig.KeyBits; }
		}

		public int BlockBytes
		{
			get { return _cryptoConfig.BlockBytes; }
		}

		public int IVBytes
		{
			get { return _cryptoConfig.IVBytes; }
		}

		public CipherMode Mode
		{
			get { return _cryptoConfig.Mode; }
		}

		public PaddingMode Padding
		{
			get { return _cryptoConfig.Padding; }
		}

		/// <returns>
		///     The encrypted payload formatted as a base64-encoded string, with a prefix that defines the algorithm, key size,
		///     mode, and possibly padding.
		/// </returns>
		public string Encode()
		{
			const int overhead =
				10 + // algo
				5 + // bits
				5 + // mode
				10 + // padding
				3 + // hyphens
				2; // braces

			int base64Size = ((Payload.Length + 2) / 3) * 4;

#if MAINTAINER
			var sb = new StringBuilder(overhead + base64Size, overhead + base64Size);
#else
			var sb = new StringBuilder(overhead + base64Size);
#endif
			sb.Append("{");
			sb.Append(AlgorithmName);
			sb.Append("-");
			sb.Append(KeyBits.ToString(NumberFormatInfo.InvariantInfo));
			sb.Append("-");
			sb.Append(Mode);
			if (Padding != PaddingMode.PKCS7)
			{
				sb.Append("-");
				sb.Append(Padding);
			}
			sb.Append("}");
			sb.Append(Convert.ToBase64String(Payload));
			return sb.ToString();
		}

		/// <summary>
		///     Parses a string in the format of <see cref="Encode" /> and returns an <see cref="EncryptedItem" /> with the
		///     component parts.
		/// </summary>
		/// <param name="input">a string from a prior <see cref="Encode" /></param>
		/// <returns>a populated <see cref="EncryptedItem" /></returns>
		public static EncryptedItem Parse(string input)
		{
			Match m = _prefixPattern.Match(input);
			if (! m.Success)
			{
				throw new CryptographicException("the ciphertext string does not begin with a suitably formatted algorithm marker, e.g. {AES-256-CBC}");
			}
			var config = new CryptoConfig(m.Groups[1].Value, int.Parse(m.Groups[2].Value));
			if (m.Groups[3].Success)
			{
				config.Mode = (CipherMode) Enum.Parse(typeof (CipherMode), m.Groups[3].Value);
			}
			if (m.Groups[4].Success)
			{
				config.Padding = (PaddingMode) Enum.Parse(typeof (PaddingMode), m.Groups[4].Value);
			}
			string remainder = input.Substring(m.Length);
			return new EncryptedItem(config, Convert.FromBase64String(remainder));
		}
	}
}