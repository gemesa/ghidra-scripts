//Extracts Hancitor config from the .data section
//@author gemesa

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class HancitorConfigExtractor2 extends GhidraScript {

	@Override
	protected void run() throws Exception {
		Memory memory = currentProgram.getMemory();

		MemoryBlock dataSection = currentProgram.getMemory().getBlock(".data");

		Address dataSectionAddress = dataSection.getStart();

		Address keyAddress = currentProgram.getAddressFactory()
				.getAddress(Long.toHexString(dataSectionAddress.getOffset() + 0x10));

		Address dataAddress = currentProgram.getAddressFactory()
				.getAddress(Long.toHexString(dataSectionAddress.getOffset() + 0x18));

		println("key address: 0x" + Long.toHexString(keyAddress.getOffset()));
		println("data address: 0x" + Long.toHexString(dataAddress.getOffset()));

		byte[] keyData = new byte[0x8];
		byte[] encryptedData = new byte[0x2000];

		memory.getBytes(dataAddress, encryptedData);
		memory.getBytes(keyAddress, keyData);

		println("key data: 0x" + new BigInteger(1, keyData).toString(16));

		MessageDigest sha1 = MessageDigest.getInstance("SHA1");
		byte[] keyHash = sha1.digest(keyData);

		byte[] derivedKey = Arrays.copyOf(keyHash, 5);

		println("derived key: 0x" + new BigInteger(1, derivedKey).toString(16));

		SecretKeySpec secretKey = new SecretKeySpec(derivedKey, "RC4");
		Cipher cipher = Cipher.getInstance("RC4");
		cipher.init(Cipher.DECRYPT_MODE, secretKey);

		byte[] decryptedData = cipher.doFinal(encryptedData);

		String decryptedString =
			new String(decryptedData, StandardCharsets.UTF_8).replace("\0", ".");
		println("decrypted config: " + decryptedString);
	}
}
