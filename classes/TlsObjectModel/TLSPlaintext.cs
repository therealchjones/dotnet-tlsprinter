namespace TlsObjectModel
{
	public class TlsPlaintext : Record
	{
		bool initialized;
		public ContentType type { get; set; }
		ProtocolVersion legacy_record_version;
		RecordContent? fragment;
		TlsPlaintext()
		{

		}
		public TlsPlaintext(byte[] bytes) : this()
		{
			FromBytes(bytes);
		}
		public override byte[] ToBytes()
		{
			if (fragment is null) throw new InvalidOperationException("Object is not yet defined.");
			byte[] fragmentBytes;
			if (Enum.IsDefined(type)) fragmentBytes = fragment.ToBytes();
			else if (fragment.HasRawData())
				fragmentBytes = fragment.GetRawData();
			else throw new InvalidOperationException("Object is not yet defined.");
			if (Length is not null && (int)Length != fragmentBytes.Length)
				throw new InvalidOperationException("Data length mismatch");
			Length = (ulong)fragmentBytes.Length;
			return type.ToBytes()
				.Concat(legacy_record_version.ToBytes())
				.Concat(GetLengthBytes())
				.Concat(fragmentBytes)
				.ToArray();
		}
		public override void FromBytes(byte[] bytes)
		{
			if (initialized) throw new InvalidOperationException("This object has been initialized. Use 'AddBytes' instead.");
			initialized = true;
			AddBytes(bytes);
		}
		public override void AddBytes(byte[] bytes)
		{
			if (BackingBytes is not null && BackingBytes.Length > 0)
				throw new InvalidOperationException("This object is already loaded; no further bytes can be added.");
			if (PendingBytes is null) PendingBytes = new byte[0];
			if (PendingBytes.Length == 0)
			{
				if (bytes.Length > 0)
				{
					type = (ContentType)bytes[0];
					PendingBytes = PendingBytes.Append(bytes[0]).ToArray();
					bytes = bytes.Remove(1);
				}
			}
			if (PendingBytes.Length == 1)
			{
				if (bytes.Length > 0)
				{
					PendingBytes = PendingBytes.Append(bytes[0]).ToArray();
					bytes = bytes.Remove(1);
				}
			}
			if (PendingBytes.Length == 2)
			{
				if (bytes.Length > 0)
				{
					PendingBytes = PendingBytes.Append(bytes[0]).ToArray();
					bytes = bytes.Remove(1);
					legacy_record_version = new ProtocolVersion(PendingBytes[1..3]);
				}
			}
			if (PendingBytes.Length == 3)
			{
				if (bytes.Length > 0)
				{
					PendingBytes = PendingBytes.Append(bytes[0]).ToArray();
					bytes = bytes.Remove(1);
				}
			}
			if (PendingBytes.Length == 4)
			{
				if (bytes.Length > 0)
				{
					PendingBytes = PendingBytes.Append(bytes[0]).ToArray();
					bytes = bytes.Remove(1);
					Length = this.GetType().GetLength(PendingBytes[3..5]);
				}
			}
			if (PendingBytes.Length >= 5)
			{
				if (Length is null) throw new InvalidOperationException();
				if (PendingBytes.LongLength < (long)Length + 5)
				{
					long remainingBytes = (long)Length + 5 - PendingBytes.LongLength;
					if (bytes.LongLength >= remainingBytes)
					{
						PendingBytes = PendingBytes.Concat(new ArraySegment<byte>(bytes, 0, (int)remainingBytes)).ToArray();
						bytes = bytes.Remove((int)remainingBytes);
					}
					else
					{
						PendingBytes = PendingBytes.Concat(bytes).ToArray();
						bytes = new byte[0];
					}

					if (bytes.Length > 0) ExtraBytes = bytes;
					if (PendingBytes.Length == (int)Length + 5)
					{
						BackingBytes = PendingBytes;
						byte[] contentBytes = new ArraySegment<byte>(BackingBytes, 5, BackingBytes.Length - 5).ToArray();
						PendingBytes = new byte[0];
						switch (type)
						{
							default:
								fragment = new UnknownRecordContent(contentBytes);
								break;
						}
					}
				}
			}
		}
		public bool NeedsBytes()
		{
			if (BackingBytes is not null && BackingBytes.Length != 0) return false;
			else return true;
		}
		public byte[]? GetExtraBytes()
		{
			if (HasExtraBytes()) return ExtraBytes;
			else return null;
		}
		public bool HasExtraBytes()
		{
			if (ExtraBytes is not null && ExtraBytes.Length != 0) return true;
			else return false;
		}
	}

}