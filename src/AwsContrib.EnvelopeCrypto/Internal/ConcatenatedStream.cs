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
using System;
using System.Collections.Generic;
using System.IO;

namespace AwsContrib.EnvelopeCrypto.Internal
{
	internal class ConcatenatedStream : Stream
	{
		private readonly Queue<Stream> _streams;

		public ConcatenatedStream(IEnumerable<Stream> streams)
		{
			_streams = new Queue<Stream>(streams);
		}

		public ConcatenatedStream(params Stream[] streams)
			: this((IEnumerable<Stream>) streams) {}

		public override bool CanRead
		{
			get { return true; }
		}

		public override bool CanSeek
		{
			get { return false; }
		}

		public override bool CanWrite
		{
			get { return false; }
		}

		public override long Length
		{
			get { throw new NotImplementedException(); }
		}

		public override long Position
		{
			get { throw new NotImplementedException(); }
			set { throw new NotImplementedException(); }
		}

		protected override void Dispose(bool disposing)
		{
			foreach (Stream s in _streams)
			{
				s.Dispose();
			}
			base.Dispose(disposing);
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			if (_streams.Count == 0)
			{
				return 0;
			}

			int bytesRead = _streams.Peek().Read(buffer, offset, count);
			if (bytesRead != 0)
			{
				return bytesRead;
			}

			_streams.Dequeue().Dispose();
			bytesRead += Read(buffer, offset + bytesRead, count - bytesRead);
			return bytesRead;
		}

		public override void Flush()
		{
			throw new NotImplementedException();
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw new NotImplementedException();
		}

		public override void SetLength(long value)
		{
			throw new NotImplementedException();
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			throw new NotImplementedException();
		}
	}
}