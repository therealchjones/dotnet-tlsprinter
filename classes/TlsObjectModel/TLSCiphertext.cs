namespace TlsObjectModel
{
	public class TLSCiphertext
	{
		ContentType opaque_type = ContentType.application_data;
		ProtocolVersion legacy_record_version = new ProtocolVersion(new byte[] { 3, 3 });
		ushort length;
		byte[]? encrypted_record;
	}
}