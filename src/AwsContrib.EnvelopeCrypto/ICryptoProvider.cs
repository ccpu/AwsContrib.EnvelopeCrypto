using System.Collections.Generic;
using System.IO;

namespace AwsContrib.EnvelopeCrypto
{
	public interface ICryptoProvider
	{
		/// <summary>
		///     Encrypts a single byte array.
		/// </summary>
		/// <param name="dataKey">The encrypted key whose plaintext was used to encrypt <see cref="plaintextBlob" /></param>
		/// <param name="plaintextBlob">The bytes to be encrypted.</param>
		/// <returns>The encrypted bytes.</returns>
		byte[] Encrypt(out byte[] dataKey, byte[] plaintextBlob);

		/// <summary>
		///     Encrypts a stream in small chunks.
		///     Remember to dispose it when you're finished with it, so the private key will be released properly.
		/// </summary>
		/// <param name="dataKey">The encrypted key whose plaintext was used to encrypt <see cref="plaintextStream" /></param>
		/// <param name="plaintextStream">The stream to be encrypted</param>
		/// <returns>The encrypted bytes.</returns>
		Stream Encrypt(out byte[] dataKey, Stream plaintextStream);

		/// <summary>
		///     Encrypts a stream in small chunks.
		///     Remember to dispose it when you're finished with it, so the private key will be released properly.
		/// </summary>
		/// <param name="dataKey">The encrypted key whose plaintext was used to encrypt <see cref="plaintextStream" /></param>
		/// <param name="plaintextStream">The stream to be encrypted</param>
		/// <param name="context">
		///     A collection of name-value pairs that will be cryptographically bound to the produced encrypted
		///     text. The same context values must be provided at decryption time.
		/// </param>
		/// <returns>The encrypted bytes.</returns>
		Stream Encrypt(out byte[] dataKey, Stream plaintextStream, IDictionary<string, string> context);

		/// <summary>
		///     Encrypts a single byte array.
		/// </summary>
		/// <param name="dataKey">The encrypted key whose plaintext was used to encrypt <see cref="plaintextBlob" /></param>
		/// <param name="plaintextBlob">The bytes to be encrypted.</param>
		/// <returns>The encrypted bytes.</returns>
		byte[] Encrypt(out string dataKey, byte[] plaintextBlob);

		/// <summary>
		///     Encrypts a stream in small chunks.
		///     Remember to dispose it when you're finished with it, so the private key will be released properly.
		/// </summary>
		/// <param name="dataKey">The encrypted key whose plaintext was used to encrypt <see cref="plaintextStream" /></param>
		/// <param name="plaintextStream">The stream to be encrypted</param>
		/// <returns>The encrypted bytes.</returns>
		Stream Encrypt(out string dataKey, Stream plaintextStream);

		/// <summary>
		///     Encrypts a stream in small chunks.
		///     Remember to dispose it when you're finished with it, so the private key will be released properly.
		/// </summary>
		/// <param name="dataKey">The encrypted key whose plaintext was used to encrypt <see cref="plaintextStream" /></param>
		/// <param name="plaintextStream">The stream to be encrypted</param>
		/// <param name="context">
		///     A collection of name-value pairs that will be cryptographically bound to the produced encrypted
		///     text. The same context values must be provided at decryption time.
		/// </param>
		/// <returns>The encrypted bytes.</returns>
		Stream Encrypt(out string dataKey, Stream plaintextStream, IDictionary<string, string> context);

		/// <summary>
		///     Encrypts a single string and returns the encrypted string.
		/// </summary>
		/// <param name="dataKey">The encrypted key whose plaintext was used to encrypt <see cref="plaintext" /></param>
		/// <param name="plaintext">The string to be encrypted.</param>
		/// <returns>The encrypted string.</returns>
		string Encrypt(out string dataKey, string plaintext);

		/// <summary>
		///     Encrypts any number of byte arrays using the same key.
		/// </summary>
		/// <param name="dataKey">The encrypted key whose plaintext was used to encrypt <see cref="plaintextBlobs" /></param>
		/// <param name="plaintextBlobs">A list of byte arrays to be encrypted.</param>
		/// <returns>The encrypted blobs.</returns>
		IEnumerable<byte[]> Encrypt(out byte[] dataKey, IEnumerable<byte[]> plaintextBlobs);

		/// <summary>
		///     Encrypts any number of byte arrays using the same key.
		/// </summary>
		/// <param name="dataKey">The encrypted key whose plaintext was used to encrypt <see cref="plaintextBlobs" /></param>
		/// <param name="plaintextBlobs">A list of byte arrays to be encrypted.</param>
		/// <returns>The encrypted blobs.</returns>
		IEnumerable<byte[]> Encrypt(out string dataKey, IEnumerable<byte[]> plaintextBlobs);

		/// <summary>
		///     Encrypts any number of strings using the same key.
		/// </summary>
		/// <param name="dataKey">The encrypted string whose plaintext was used to encrypt <see cref="plaintexts" /></param>
		/// <param name="plaintexts">A list of byte arrays to be encrypted.</param>
		/// <returns>The encrypted strings.</returns>
		IEnumerable<string> Encrypt(out string dataKey, IEnumerable<string> plaintexts);

		/// <summary>
		///     Decrypts an encrypted byte array and returns the decrypted blob.
		/// </summary>
		/// <param name="dataKey">The key that was returned from a prior call to Encrypt.</param>
		/// <param name="ciphertextBlob">An encrypted blob that was returned from a prior call to Encrypt.</param>
		/// <returns>The decrypted blobs.</returns>
		byte[] Decrypt(byte[] dataKey, byte[] ciphertextBlob);

		/// <summary>
		///     Decrypts a stream in small chunks.
		///     Remember to dispose it when you're finished with it, so the private key will be released properly.
		/// </summary>
		/// <param name="dataKey">The encrypted key whose plaintext was used to encrypt <see cref="ciphertextStream" /></param>
		/// <param name="ciphertextStream">The stream to be decrypted</param>
		/// <returns>The encrypted bytes.</returns>
		Stream Decrypt(byte[] dataKey, Stream ciphertextStream);

		/// <summary>
		///     Decrypts an encrypted byte array and returns the decrypted blob.
		/// </summary>
		/// <param name="dataKey">The key that was returned from a prior call to Encrypt.</param>
		/// <param name="ciphertextBlob">An encrypted blob that was returned from a prior call to Encrypt.</param>
		/// <returns>The decrypted blobs.</returns>
		byte[] Decrypt(string dataKey, byte[] ciphertextBlob);

		/// <summary>
		///     Decrypts a stream in small chunks.
		///     Remember to dispose it when you're finished with it, so the private key will be released properly.
		/// </summary>
		/// <param name="dataKey">The encrypted key whose plaintext was used to encrypt <see cref="ciphertextStream" /></param>
		/// <param name="ciphertextStream">The stream to be decrypted</param>
		/// <returns>The encrypted bytes.</returns>
		Stream Decrypt(string dataKey, Stream ciphertextStream);

		/// <summary>
		///     Decrypts any number of encrypted byte arrays using the same key and returns the decrypted blobs.
		/// </summary>
		/// <param name="dataKey">The key that was returned from a prior call to Encrypt.</param>
		/// <param name="ciphertextBlobs">The encrypted blobs that was returned from a prior call to Encrypt.</param>
		/// <returns>The decrypted blobs.</returns>
		IEnumerable<byte[]> Decrypt(byte[] dataKey, IEnumerable<byte[]> ciphertextBlobs);

		/// <summary>
		///     Decrypts any number of encrypted byte arrays using the same key and returns the decrypted blobs.
		/// </summary>
		/// <param name="dataKey">The key that was returned from a prior call to Encrypt.</param>
		/// <param name="ciphertextBlobs">The encrypted blobs that was returned from a prior call to Encrypt.</param>
		/// <returns>The decrypted blobs.</returns>
		IEnumerable<byte[]> Decrypt(string dataKey, IEnumerable<byte[]> ciphertextBlobs);

		/// <summary>
		///     Decrypts an encrypted string and returns the original string.
		/// </summary>
		/// <param name="dataKey">The key that was returned from a prior call to Encrypt.</param>
		/// <param name="ciphertext">An encrypted string that was returned from a prior call to Encrypt.</param>
		/// <returns>The decrypted string.</returns>
		string Decrypt(string dataKey, string ciphertext);

		/// <summary>
		///     Decrypts any number of encrypted strings using the same key and returns the decrypted strings.
		/// </summary>
		/// <param name="dataKey">The key that was returned from a prior call to Encrypt.</param>
		/// <param name="ciphertexts">The encrypted strings that were returned from a prior call to Encrypt.</param>
		/// <returns>The decrypted strings.</returns>
		IEnumerable<string> Decrypt(string dataKey, IEnumerable<string> ciphertexts);

		/// <summary>
		///     Encrypts a single byte array.
		/// </summary>
		/// <param name="dataKey">The encrypted key whose plaintext was used to encrypt <see cref="plaintextBlob" /></param>
		/// <param name="plaintextBlob">The bytes to be encrypted.</param>
		/// <param name="context">
		///     A collection of name-value pairs that will be cryptographically bound to the produced encrypted
		///     text. The same context values must be provided at decryption time.
		/// </param>
		/// <returns>The encrypted bytes.</returns>
		byte[] Encrypt(out byte[] dataKey, byte[] plaintextBlob, IDictionary<string, string> context);

		/// <summary>
		///     Encrypts a single byte array.
		/// </summary>
		/// <param name="dataKey">The encrypted key whose plaintext was used to encrypt <see cref="plaintextBlob" /></param>
		/// <param name="plaintextBlob">The bytes to be encrypted.</param>
		/// <param name="context">
		///     A collection of name-value pairs that will be cryptographically bound to the produced encrypted
		///     text. The same context values must be provided at decryption time.
		/// </param>
		/// <returns>The encrypted bytes.</returns>
		byte[] Encrypt(out string dataKey, byte[] plaintextBlob, IDictionary<string, string> context);

		/// <summary>
		///     Encrypts a single string and returns the encrypted string.
		/// </summary>
		/// <param name="dataKey">The encrypted key whose plaintext was used to encrypt <see cref="plaintext" /></param>
		/// <param name="plaintext">The string to be encrypted.</param>
		/// <param name="context">
		///     A collection of name-value pairs that will be cryptographically bound to the produced encrypted
		///     text. The same context values must be provided at decryption time.
		/// </param>
		/// <returns>The encrypted string.</returns>
		string Encrypt(out string dataKey, string plaintext, IDictionary<string, string> context);

		/// <summary>
		///     Encrypts any number of byte arrays using the same key.
		/// </summary>
		/// <param name="dataKey">The encrypted key whose plaintext was used to encrypt <see cref="plaintextBlobs" /></param>
		/// <param name="plaintextBlobs">A list of byte arrays to be encrypted.</param>
		/// <param name="context">
		///     A collection of name-value pairs that will be cryptographically bound to the produced encrypted
		///     text. The same context values must be provided at decryption time.
		/// </param>
		/// <returns>The encrypted blobs.</returns>
		IEnumerable<byte[]> Encrypt(out byte[] dataKey, IEnumerable<byte[]> plaintextBlobs, IDictionary<string, string> context);

		/// <summary>
		///     Encrypts any number of byte arrays using the same key.
		/// </summary>
		/// <param name="dataKey">The encrypted key whose plaintext was used to encrypt <see cref="plaintextBlobs" /></param>
		/// <param name="plaintextBlobs">A list of byte arrays to be encrypted.</param>
		/// <param name="context">
		///     A collection of name-value pairs that will be cryptographically bound to the produced encrypted
		///     text. The same context values must be provided at decryption time.
		/// </param>
		/// <returns>The encrypted blobs.</returns>
		IEnumerable<byte[]> Encrypt(out string dataKey, IEnumerable<byte[]> plaintextBlobs, IDictionary<string, string> context);

		/// <summary>
		///     Encrypts any number of strings using the same key.
		/// </summary>
		/// <param name="dataKey">The encrypted string whose plaintext was used to encrypt <see cref="plaintexts" /></param>
		/// <param name="plaintexts">A list of byte arrays to be encrypted.</param>
		/// <param name="context">
		///     A collection of name-value pairs that will be cryptographically bound to the produced encrypted
		///     text. The same context values must be provided at decryption time.
		/// </param>
		/// <returns>The encrypted strings.</returns>
		IEnumerable<string> Encrypt(out string dataKey, IEnumerable<string> plaintexts, IDictionary<string, string> context);

		/// <summary>
		///     Decrypts an encrypted byte array and returns the decrypted blob.
		/// </summary>
		/// <param name="dataKey">The key that was returned from a prior call to Encrypt.</param>
		/// <param name="ciphertextBlob">An encrypted blob that was returned from a prior call to Encrypt.</param>
		/// <param name="context">
		///     A collection of name-value pairs that will be cryptographically bound to the produced encrypted
		///     text. The same context values must be provided at decryption time.
		/// </param>
		/// <returns>The decrypted blobs.</returns>
		byte[] Decrypt(byte[] dataKey, byte[] ciphertextBlob, IDictionary<string, string> context);

		/// <summary>
		///     Decrypts a stream in small chunks.
		///     Remember to dispose it when you're finished with it, so the private key will be released properly.
		/// </summary>
		/// <param name="dataKey">The encrypted key whose plaintext was used to encrypt <see cref="ciphertextStream" /></param>
		/// <param name="ciphertextStream">The stream to be decrypted</param>
		/// <param name="context">
		///     A collection of name-value pairs that will be cryptographically bound to the produced encrypted
		///     text. The same context values must be provided at decryption time.
		/// </param>
		/// <returns>The encrypted bytes.</returns>
		Stream Decrypt(byte[] dataKey, Stream ciphertextStream, IDictionary<string, string> context);

		/// <summary>
		///     Decrypts an encrypted byte array and returns the decrypted blob.
		/// </summary>
		/// <param name="dataKey">The key that was returned from a prior call to Encrypt.</param>
		/// <param name="ciphertextBlob">An encrypted blob that was returned from a prior call to Encrypt.</param>
		/// <param name="context">
		///     A collection of name-value pairs that will be cryptographically bound to the produced encrypted
		///     text. The same context values must be provided at decryption time.
		/// </param>
		/// <returns>The decrypted blobs.</returns>
		byte[] Decrypt(string dataKey, byte[] ciphertextBlob, IDictionary<string, string> context);

		/// <summary>
		///     Decrypts a stream in small chunks.
		///     Remember to dispose it when you're finished with it, so the private key will be released properly.
		/// </summary>
		/// <param name="dataKey">The encrypted key whose plaintext was used to encrypt <see cref="ciphertextStream" /></param>
		/// <param name="ciphertextStream">The stream to be decrypted</param>
		/// <param name="context">
		///     A collection of name-value pairs that will be cryptographically bound to the produced encrypted
		///     text. The same context values must be provided at decryption time.
		/// </param>
		/// <returns>The encrypted bytes.</returns>
		Stream Decrypt(string dataKey, Stream ciphertextStream, IDictionary<string, string> context);

		/// <summary>
		///     Decrypts any number of encrypted byte arrays using the same key and returns the decrypted blobs.
		/// </summary>
		/// <param name="dataKey">The key that was returned from a prior call to Encrypt.</param>
		/// <param name="ciphertextBlobs">The encrypted blobs that was returned from a prior call to Encrypt.</param>
		/// <param name="context">
		///     A collection of name-value pairs that will be cryptographically bound to the produced encrypted
		///     text. The same context values must be provided at decryption time.
		/// </param>
		/// <returns>The decrypted blobs.</returns>
		IEnumerable<byte[]> Decrypt(byte[] dataKey, IEnumerable<byte[]> ciphertextBlobs, IDictionary<string, string> context);

		/// <summary>
		///     Decrypts any number of encrypted byte arrays using the same key and returns the decrypted blobs.
		/// </summary>
		/// <param name="dataKey">The key that was returned from a prior call to Encrypt.</param>
		/// <param name="ciphertextBlobs">The encrypted blobs that was returned from a prior call to Encrypt.</param>
		/// <param name="context">
		///     A collection of name-value pairs that will be cryptographically bound to the produced encrypted
		///     text. The same context values must be provided at decryption time.
		/// </param>
		/// <returns>The decrypted blobs.</returns>
		IEnumerable<byte[]> Decrypt(string dataKey, IEnumerable<byte[]> ciphertextBlobs, IDictionary<string, string> context);

		/// <summary>
		///     Decrypts an encrypted string and returns the original string.
		/// </summary>
		/// <param name="dataKey">The key that was returned from a prior call to Encrypt.</param>
		/// <param name="ciphertext">An encrypted string that was returned from a prior call to Encrypt.</param>
		/// <param name="context">
		///     A collection of name-value pairs that will be cryptographically bound to the produced encrypted
		///     text. The same context values must be provided at decryption time.
		/// </param>
		/// <returns>The decrypted string.</returns>
		string Decrypt(string dataKey, string ciphertext, IDictionary<string, string> context);

		/// <summary>
		///     Decrypts any number of encrypted strings using the same key and returns the decrypted strings.
		/// </summary>
		/// <param name="dataKey">The key that was returned from a prior call to Encrypt.</param>
		/// <param name="ciphertexts">The encrypted strings that were returned from a prior call to Encrypt.</param>
		/// <param name="context">
		///     A collection of name-value pairs that will be cryptographically bound to the produced encrypted
		///     text. The same context values must be provided at decryption time.
		/// </param>
		/// <returns>The decrypted strings.</returns>
		IEnumerable<string> Decrypt(string dataKey, IEnumerable<string> ciphertexts, IDictionary<string, string> context);
	}
}