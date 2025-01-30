//Extracts Hancitor config by finding specific instruction patterns
//@author gemesa

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;

public class HancitorConfigExtractor extends GhidraScript {

	@Override
	protected void run() throws Exception {
		Listing listing = currentProgram.getListing();
		Memory memory = currentProgram.getMemory();
		InstructionIterator instructions =
			listing.getInstructions(currentProgram.getImageBase(), true);

		/*
		 * we are looking for the pattern below, where
		 * 0x8 is the key size
		 * DAT_10005010 is the key address
		 * 0x2000 is the data size
		 * key address + key size is the data address
		100025fe 6a 08           PUSH       0x8
		10002600 68 10 50        PUSH       DAT_10005010
		         00 10
		10002605 68 00 20        PUSH       0x2000
		         00 00
		1000260a a1 64 72        MOV        EAX,[DAT_10007264]
		         00 10
		1000260f 50              PUSH       EAX
		10002610 e8 bb 06        CALL       mw_decrypt_config
		         00 00
		 */

		Address keyAddress = null;
		Address dataAddress = null;

		while (instructions.hasNext()) {
			Instruction instr = instructions.next();

			if (!instr.getMnemonicString().equals("PUSH")) {
				continue;
			}

			Scalar scalar = instr.getScalar(0);
			if (scalar != null && scalar.getValue() != 0x8) {
				continue;
			}

			Instruction nextInstr = getInstructionAfter(instr);

			if (!nextInstr.getMnemonicString().equals("PUSH")) {
				continue;
			}

			scalar = nextInstr.getScalar(0);

			if (scalar == null) {
				continue;
			}

			keyAddress =
				currentProgram.getAddressFactory().getAddress(Long.toHexString(scalar.getValue()));
			dataAddress =
				currentProgram.getAddressFactory()
						.getAddress(Long.toHexString(scalar.getValue() + 0x8));

			nextInstr = getInstructionAfter(nextInstr);

			if (!nextInstr.getMnemonicString().equals("PUSH")) {
				continue;
			}

			scalar = nextInstr.getScalar(0);
			if (scalar != null && scalar.getValue() != 0x2000) {
				continue;
			}

			nextInstr = getInstructionAfter(nextInstr);

			if (!nextInstr.getMnemonicString().equals("MOV")) {
				continue;
			}

			nextInstr = getInstructionAfter(nextInstr);

			if (!nextInstr.getMnemonicString().equals("PUSH")) {
				continue;
			}

			nextInstr = getInstructionAfter(nextInstr);

			if (!nextInstr.getMnemonicString().equals("CALL")) {
				continue;
			}

			break;
		}

		println("key address: 0x" + Long.toHexString(keyAddress.getOffset()));
		println("data address: 0x" + Long.toHexString(dataAddress.getOffset()));

		byte[] keyData = new byte[0x8];
		byte[] encryptedData = new byte[0x2000];

		memory.getBytes(dataAddress, encryptedData);
		memory.getBytes(keyAddress, keyData);

		println("key data: " + new BigInteger(1, keyData).toString(16));

		MessageDigest sha1 = MessageDigest.getInstance("SHA1");
		byte[] keyHash = sha1.digest(keyData);

		byte[] derivedKey = Arrays.copyOf(keyHash, 5);

		println("derived key: " + new BigInteger(1, derivedKey).toString(16));

		SecretKeySpec secretKey = new SecretKeySpec(derivedKey, "RC4");
		Cipher cipher = Cipher.getInstance("RC4");
		cipher.init(Cipher.DECRYPT_MODE, secretKey);

		byte[] decryptedData = cipher.doFinal(encryptedData);

		String decryptedString =
			new String(decryptedData, StandardCharsets.UTF_8).replace("\0", "");
		println("decrypted config: " + decryptedString);
	}
}
