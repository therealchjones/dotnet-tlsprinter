using System.Collections.ObjectModel;
using System.Net.Security;
using System.Security.Authentication;
using TlsPrinter;

namespace TlsObjectModel
{
	public enum TlsExtension
	{

	}
	public enum TlsCurve
	{

	}
	public enum TlsPointFormat
	{

	}

	public class TlsClientHello
	{
		SslProtocols Versions;
		SslProtocols ClientVersion;
		byte[] Random;
		byte[] SessionId;
		List<TlsCipherSuite>? Ciphers;
		List<TlsExtension>? Extensions;
		List<TlsCurve>? Curves;
		List<TlsPointFormat>? PointFormats;

		internal TlsClientHello(TlsPrinterSettings settings)
		{
			if (settings.ClientVersion is not null) ClientVersion = (SslProtocols)settings.ClientVersion;
			else ClientVersion = SslProtocols.Tls12;
			Random = new byte[32];
			SessionId = new byte[32];
			if (settings.Ciphers is not null) Ciphers = settings.Ciphers;
			if (settings.Extensions is not null) Extensions = settings.Extensions;
			if (settings.Curves is not null) Curves = settings.Curves;
			if (settings.PointFormats is not null) PointFormats = settings.PointFormats;
		}
		public byte[] ToBytes()
		{
			List<byte[]> handshakeBuilder = new();
			List<byte[]> messageBuilder = new();
			messageBuilder.Add(new byte[] { 0x16, 3, 1 });
			byte[] recordHeader = new byte[] { 0x16, 0x03, 0x01, 0x00, 0x00 };
			byte[] handshakeHeader = new byte[] { 0x01, 0x00, 0x00, 0x00 };
			byte[] clientVersion = new byte[] { 0x03, 0x03 };
			byte[] clientRandom = new byte[32];
			//rng.NextBytes(clientRandom);
			byte[] sessionId = new byte[33];
			//rng.NextBytes(sessionId);
			sessionId[0] = 32;
			byte[] cipherSuites = new byte[] { 0, 8, 0x13, 0x02, 0x13, 0x01, 0x13, 0x03, 0, 0xff };
			byte[] compressionMethods = new byte[] { 1, 0 };
			byte[] extensionsLength = new byte[] { 0, 0 };

			return new byte[0];
		}
		public void SetBase(byte[] clientHello)
		{

		}
	}

	public abstract class TlsObject
	{
		protected byte[]? BackingBytes { get; set; }
		public abstract void AddBytes(byte[] bytes);
		public void AddBytes(IEnumerable<byte> bytes)
		{
			AddBytes(bytes.ToArray<byte>());
		}
		public abstract byte[] ToBytes();
		public abstract void FromBytes(byte[] bytes);
		public bool HasRawData()
		{
			return BackingBytes is not null;
		}
		public byte[] GetRawData()
		{
			if (BackingBytes is null) throw new InvalidOperationException();
			else return BackingBytes;
		}
	}
	public static class TlsExtensions
	{
		// Dictionary matching the known data types of fixed length with the number of bytes they use
		private static readonly ReadOnlyDictionary<Type, UInt32> TlsFixedObjectLengths = new(new Dictionary<Type, uint>()
		{
			{ typeof(CipherSuite), 2 },
			{ typeof(ContentType), 1 },
			{ typeof(ExtensionType), 4 },
			{ typeof(HandshakeType), 1 },
			{ typeof(ProtocolVersion), 2 },
			{ typeof(Random), 32 },
		});
		private static readonly ReadOnlyDictionary<Type, UInt32> TlsLengthFieldLengths = new(new Dictionary<Type, uint>() {
			{ typeof(Handshake), 3},
			{ typeof(TLSPlaintext), 2},
		});
		public static bool IsFixedLength(this Type type)
		{
			return TlsFixedObjectLengths.ContainsKey(type);
		}
		public static uint GetFixedLength(this Type type)
		{
			if (!type.IsFixedLength()) throw new ArgumentException();
			else return TlsFixedObjectLengths[type];
		}
		public static uint GetLengthFieldLength(this Type type)
		{
			if (type.IsFixedLength()) return 0;
			else if (TlsLengthFieldLengths.ContainsKey(type)) return TlsLengthFieldLengths[type];
			else throw new NotSupportedException();
		}
		public static ulong GetLength(this Type type, byte[] bytes)
		{
			if (type.IsFixedLength()) throw new ArgumentException();
			bytes = new ArraySegment<byte>(bytes, 0, (int)GetLengthFieldLength(type)).ToArray();
			return Utils.BytesToUInt64(bytes);
		}
		public static byte[] ToBytes(this Enum value)
		{
			uint length;
			if (value.GetType().IsFixedLength()) length = value.GetType().GetFixedLength();
			else throw new NotSupportedException();
			ulong valueNum = Convert.ToUInt64(value);
			return valueNum.ToBytes(length);
		}
		public static void FromBytes(this Enum value, byte[] bytes)
		{
			uint length;
			if (value.GetType().IsFixedLength()) length = value.GetType().GetFixedLength();
			else throw new NotSupportedException();
			if (bytes.Length != length || bytes.Length > 8) throw new NotSupportedException();
			ulong number = Utils.BytesToUInt64(bytes);
			value = (Enum)Enum.ToObject(value.GetType(), number);
		}
		public static byte[] ToBytes(this ulong value, ulong length)
		{
			byte[] rawBytes = BitConverter.GetBytes(value);
			if (BitConverter.IsLittleEndian) rawBytes = rawBytes.Reverse().ToArray();
			for (ulong i = 0; i < (ulong)rawBytes.Length - length; i++)
			{
				if (rawBytes[i] != 0) throw new OverflowException();
			}
			return new ArraySegment<byte>(rawBytes, (int)((ulong)rawBytes.Length - length), (int)length).ToArray();
		}
		public static byte[] Remove(this byte[] bytes, int i)
		{
			int length = bytes.Length;
			if (length < i) throw new ArgumentException();
			return new ArraySegment<byte>(bytes, i, length - i).ToArray();
		}
	}
	internal static class Utils
	{
		public static ulong BytesToUInt64(byte[] bytes)
		{
			if (bytes.Length > 8) throw new ArgumentException();
			bytes = new byte[8 - bytes.Length].Concat(bytes).ToArray();
			if (BitConverter.IsLittleEndian) bytes = bytes.Reverse().ToArray();
			return BitConverter.ToUInt64(bytes);
		}
	}
	public class CipherSuite
	{

	}
	/*
	public class ClientHello : TlsObject
	{
		ProtocolVersion legacy_version = new(new byte[] { 3, 3 });
		Random random;
		byte[] legacy_session_id;
		List<CipherSuite> cipher_suites;
		byte[] legacy_compression_methods;
		List<Extension> extensions;
	}
	*/
	public enum ContentType : byte
	{
		invalid = 0,
		change_cipher_spec = 20,
		alert = 21,
		handshake = 22,
		application_data = 23,
		heartbeat = 24
	}
	public class Extension
	{
		ExtensionType extension_type;
		byte[]? extension_data;
	}
	public enum ExtensionType
	{
		server_name = 1,
		max_fragment_length = 2,
		status_request = 5,
		supported_groups = 10,
		signature_algorithms = 13,
		use_srtp = 14,
		heartbeat = 15,
		application_layer_protocol_negotiation = 16,
		signed_certificate_timestamp = 18,
		client_certificate_type = 19,
		server_certificate_type = 20,
		padding = 21,
		pre_shared_key = 41,
		early_data = 42,
		supported_version = 43,
		cookie = 44,
		psk_key_exchange_modes = 45,
		certificate_authorities = 47,
		oid_filters = 48,
		post_handshake_auth = 49,
		signature_algorithms_cert = 50,
		key_share = 51
	}
	public class Handshake : RecordContent
	{
		public HandshakeType msg_type;
		HandshakeLength length;
		HandshakeMessage? msg;
		public Handshake(HandshakeMessage message)
		{
			msg = message;
		}
		public Handshake(byte[] bytes)
		{
			FromBytes(bytes);
		}
		public override void FromBytes(byte[] bytes)
		{
			throw new NotImplementedException();
		}
		public override void AddBytes(byte[] bytes)
		{
			throw new NotImplementedException();
		}
		public override byte[] ToBytes()
		{
			throw new NotImplementedException();
		}
	}
	internal struct HandshakeLength
	{
		byte[] bytes = new byte[3] { 0, 0, 0 }; // stored in bigendian order
		public UInt32 Length
		{
			get
			{
				if (bytes is null) return 0;
				return GetUInt24(bytes);
			}
			set
			{
				bytes = FromUInt24(value);
			}
		}
		public HandshakeLength(byte[] valueBytes)
		{
			if (valueBytes.Length != 3) throw new ArgumentException();
			bytes = valueBytes;
		}
		public HandshakeLength(UInt32 value)
		{
			Length = value;
		}
		UInt32 GetUInt24(byte[] intBytes)
		{
			if (bytes.Length != 3) throw new InvalidOperationException();
			intBytes = new byte[] { 0 }.Concat(intBytes).ToArray();
			if (BitConverter.IsLittleEndian) intBytes = intBytes.Reverse().ToArray();
			return BitConverter.ToUInt32(intBytes);
		}
		byte[] FromUInt24(UInt32 value)
		{
			byte[] intBytes = BitConverter.GetBytes(value);
			if (BitConverter.IsLittleEndian) intBytes = intBytes.Reverse().ToArray();
			if (intBytes[0] != 0) throw new OverflowException();
			return new ArraySegment<byte>(intBytes, 1, 3).ToArray();
		}
		byte[] ToBytes()
		{
			return bytes;
		}
	}
	public abstract class HandshakeMessage
	{

	}
	public enum HandshakeType
	{
		hello_request_RESERVED = 0,
		client_hello = 1,
		server_hello = 2,
		hello_verify_request_RESERVED = 3,
		new_session_ticket = 4,
		end_of_early_data = 5,
		encrypted_extensions = 8,
		certificate = 11,
		certificate_request = 13,
		certificate_verify = 15,
		finished = 20,
		key_update = 24,
		message_hash = 254
	}
	public struct ProtocolVersion
	{
		byte[] bytes = new byte[2] { 0, 0 };
		public ProtocolVersion(string versionString)
		{
			if (String.IsNullOrEmpty(versionString)) throw new ArgumentException();
			switch (versionString)
			{
				case "1.0":
					bytes[0] = 3;
					bytes[1] = 1;
					break;
				case "1.1":
					bytes[0] = 3;
					bytes[1] = 2;
					break;
				case "1.2":
					bytes[0] = 3;
					bytes[1] = 3;
					break;
				case "1.3":
					bytes[0] = 3;
					bytes[1] = 4;
					break;
				default:
					throw new ArgumentException();
			}
		}
		public ProtocolVersion(byte[] versionBytes)
		{
			if (versionBytes.Length != 2) throw new ArgumentException();
			bytes = versionBytes;
		}
		public ProtocolVersion(SslProtocols versionProtocol)
		{
			switch (versionProtocol)
			{
				case SslProtocols.Tls:
					bytes[0] = 3;
					bytes[1] = 1;
					break;
				case SslProtocols.Tls11:
					bytes[0] = 3;
					bytes[1] = 2;
					break;
				case SslProtocols.Tls12:
					bytes[0] = 3;
					bytes[1] = 3;
					break;
				case SslProtocols.Tls13:
					bytes[0] = 3;
					bytes[1] = 4;
					break;
				default:
					throw new ArgumentException();
			}
		}
		public byte[] ToBytes()
		{
			return bytes;
		}
	}
	public class Random
	{

	}
	public abstract class TlsEnvelope : TlsObject
	{
		protected ulong? Length;
		protected byte[]? ExtraBytes { get; set; }
		protected byte[]? PendingBytes { get; set; }
		protected byte[] GetLengthBytes()
		{
			if (Length is null) throw new InvalidOperationException("Length is not defined.");
			else return ((ulong)Length).ToBytes(this.GetType().GetLengthFieldLength());
		}
		protected void SetLength(byte[] bytes)
		{
			Length = this.GetType().GetLength(bytes);
		}
	}
	public abstract class TlsRecord : TlsEnvelope
	{

	}
	public abstract class RecordContent : TlsEnvelope
	{

	}
	public class UnknownRecordContent : RecordContent
	{
		public UnknownRecordContent(byte[] bytes)
		{
			FromBytes(bytes);
		}
		public override void FromBytes(byte[] bytes)
		{
			if (BackingBytes is not null && BackingBytes.Length != 0)
			{
				throw new InvalidOperationException();
			}
			BackingBytes = bytes;
		}
		public override void AddBytes(byte[] bytes)
		{
			FromBytes(bytes);
		}
		public override byte[] ToBytes()
		{
			return GetRawData();
		}
	}
	public class TLSPlaintext : TlsRecord
	{
		bool initialized;
		public ContentType type { get; set; }
		ProtocolVersion legacy_record_version;
		RecordContent? fragment;
		TLSPlaintext()
		{

		}
		public TLSPlaintext(byte[] bytes) : this()
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
			if (Length is null) throw new InvalidOperationException();
			if (PendingBytes.LongLength < (long)Length + 5)
			{
				ulong remainingBytes = (ulong)Length + 5 - (ulong)PendingBytes.Length;
				if (bytes.LongLength >= (long)remainingBytes)
				{
					PendingBytes = PendingBytes.Concat(new ArraySegment<byte>(bytes, 0, (int)remainingBytes)).ToArray();
					bytes = bytes.Remove((int)remainingBytes);
				}
				else
				{
					PendingBytes = PendingBytes.Concat(bytes).ToArray();
					bytes = new byte[0];
				}
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
