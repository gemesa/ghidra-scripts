//Extracts Mirai config (SORA)
//@author gemesa

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

public class MiraiConfigExtractorSORA extends GhidraScript {

    // Encryption key hardcoded into the binary used to decrypt the configuration.
    private static final int ENCRYPTION_KEY = 0xdedefbaf;
    // 0xdeadbeef is the encryption key hardcoded into the leaked source code used to decrypt the configuration.
    // Authors often leave some configuration data encrypted with 0xdeadbeef in their variant.
    // This data cannot be decrypted with other encryption keys,
    // but it is worth it to run the decryption with 0xdeadbeef as well,
    // if we see garbled data after decrypting with the hardcoded key (e.g. 0xdedefbaf)
    // to make sure our decryption algorithm works properly,
    // and some of the data may have been encrypted with just a different key (e.g. 0xdeadbeef).
    //private static final int ENCRYPTION_KEY = 0xdeadbeef;
    public Memory memory = null;

    @Override
    protected void run() throws Exception {

        FunctionManager functionManager = currentProgram.getFunctionManager();
        Iterator<Function> functions = functionManager.getFunctions(true);
        Listing listing = currentProgram.getListing();
        memory = currentProgram.getMemory();
        ReferenceManager refManager = currentProgram.getReferenceManager();

        Function targetFunctionDecrypt = null;
        Function targetFunctionCopy = null;
        Address configAddress = null;

        while (functions.hasNext()) {
            Function func = functions.next();
            AddressSetView functionBody = func.getBody();

            InstructionIterator instructions = listing.getInstructions(functionBody, true);

            /*
				00013218 80 01 a0 e1     mov        r0,r0, lsl #0x3
				0001321c f0 40 2d e9     stmdb      sp!,{r4,r5,r6,r7,lr}
				00013220 07 00 c0 e3     bic        r0,r0,#0x7
				00013224 9c 30 9f e5     ldr        r3,[DAT_000132c8]                                = 00020E64h
				00013228 80 0a a0 e1     mov        r0,r0, lsl #0x15
				0001322c a0 0a a0 e1     mov        r0,r0, lsr #0x15
				00013230 03 e0 80 e0     add        lr,r0,r3
				00013234 90 30 9f e5     ldr        r3,[DAT_000132cc]                                = 00020B80h
				00013238 04 70 8e e2     add        r7,lr,#0x4
				0001323c 00 20 93 e5     ldr        r2,[r3,#0x0]=>mw_key                             = DEDEFBAFh
				00013240 04 10 de e5     ldrb       r1,[lr,#0x4]=>DAT_00020e68                       = ??
				00013244 01 30 d7 e5     ldrb       r3,[r7,#0x1]=>DAT_00020e69                       = ??
             */
            String[] patternDecrypt = {"mov", "stmdb", "bic", "ldr", "mov", "mov", "add"};
            int matchIndexDecrypt = 0;

            /*
				000143cc 00 00 52 e3     cmp        r2,#0x0
				000143d0 0e f0 a0 01     moveq      pc,lr
				000143d4 00 c0 a0 e3     mov        r12,#0x0
									LAB_000143d8                                    XREF[1]:     000143e8(j)  
				000143d8 01 30 dc e7     ldrb       r3,[r12,r1]
				000143dc 00 30 cc e7     strb       r3,[r12,r0]
				000143e0 01 c0 8c e2     add        r12,r12,#0x1
				000143e4 02 00 5c e1     cmp        r12,r2
				000143e8 fa ff ff 1a     bne        LAB_000143d8
				000143ec 0e f0 a0 e1     mov        pc,lr
             */
            String[] patternCopy = {"cmp", "moveq", "mov", "ldrb", "strb", "add", "cmp"};
            int matchIndexCopy = 0;

            Instruction instructionLdr = null;
            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                String mnemonic = instruction.getMnemonicString();

                if (mnemonic.equals(patternDecrypt[matchIndexDecrypt])) {
                    if (mnemonic.equals("ldr")) {
                        instructionLdr = instruction;
                    }

                    matchIndexDecrypt++;

                    if (matchIndexDecrypt == patternDecrypt.length) {
                        targetFunctionDecrypt = func;

                        // get config address
                        Object[] opObjs1 = instructionLdr.getOpObjects(1);
                        Object opObj1 = opObjs1[0];
                        Address address = toAddr(opObj1.toString());
                        // deref
                        int value = memory.getInt(address);
                        configAddress = toAddr(value);

                        break;
                    }

                } else {
                    matchIndexDecrypt = 0;

                    if (mnemonic.equals(patternDecrypt[0])) {
                        matchIndexCopy = 1;
                    }
                }

                if (mnemonic.equals(patternCopy[matchIndexCopy])) {

                    matchIndexCopy++;

                    if (matchIndexCopy == patternCopy.length) {
                        targetFunctionCopy = func;

                        break;
                    }

                } else {
                    matchIndexCopy = 0;

                    if (mnemonic.equals(patternCopy[0])) {
                        matchIndexCopy = 1;
                    }
                }
            }
        }

        if (targetFunctionDecrypt != null) {
            println("located decryption function: " + targetFunctionDecrypt.getName());
        } else {
            println("could not locate decryption function");
            return;
        }
        if (configAddress != null) {
            println("config address: " + configAddress.toString());
        } else {
            println("could not locate config address");
            return;
        }

        if (targetFunctionCopy != null) {
            println("located copy function: " + targetFunctionCopy.getName());
        } else {
            println("could not locate copy function");
            return;
        }

        ReferenceIterator references = refManager.getReferencesTo(targetFunctionDecrypt.getEntryPoint());
        List<Address> addressList = new ArrayList<>();
        while (references.hasNext()) {
            Reference reference = references.next();
            //println(reference.toString());
            Address fromAddr = reference.getFromAddress();
            Address currentAddr = fromAddr;

            for (int i = 0; i < 4; i++) {
                currentAddr = currentAddr.subtract(4);
                Instruction instruction = listing.getInstructionAt(currentAddr);
                String mnemonic = instruction.getMnemonicString();
                Object[] opObjs0 = instruction.getOpObjects(0);
                Object opObj0 = opObjs0[0];
                if (mnemonic.equals("mov") && opObj0.toString().equals("r0")) {
                    Object[] opObjs1 = instruction.getOpObjects(1);
                    Object opObj1 = opObjs1[0];
                    int value = (int) ((Scalar) opObj1).getValue();
                    value *= 8;
                    value += configAddress.getOffset();
                    Address address = toAddr(value);
                    //println(address.toString());
                    addressList.add(address);
                    break;
                }
            }
        }

        references = refManager.getReferencesTo(targetFunctionCopy.getEntryPoint());
        HashMap<Address, AddressSize> addressMap = new HashMap<>();
        List<Long> sizeList = new ArrayList<>();
        Address addressOfCopiedData = null;
        Address addressOfOrigData = null;
        long additionTotal = 0;
        while (references.hasNext()) {
            Reference reference = references.next();
            //println(reference.toString());
            Address fromAddr = reference.getFromAddress();
            Address currentAddr = fromAddr;

            boolean configFound = false;
            for (int i = 0; i < 4; i++) {
                currentAddr = currentAddr.subtract(4);
                Instruction instruction = listing.getInstructionAt(currentAddr);
                String mnemonic = instruction.getMnemonicString();
                Object[] opObjs0 = instruction.getOpObjects(0);
                Object opObj0 = opObjs0[0];
                if (mnemonic.equals("ldr") && opObj0.toString().equals("r1")) {
                    Object[] opObjs1 = instruction.getOpObjects(1);
                    Object opObj1 = opObjs1[0];
                    if (opObj1.toString().contains("sp")) {
                        continue;
                    }

                    addressOfOrigData = toAddr(opObj1.toString());
                    // deref
                    int value = memory.getInt(addressOfOrigData);
                    addressOfOrigData = toAddr(value);
                    //println(addressOfOrigData.toString());
                    configFound = true;
                    break;
                }
            }

            // todo: review the variable names
            if (configFound) {
                currentAddr = fromAddr;
                for (int i = 0; i < 4; i++) {
                    currentAddr = currentAddr.add(4);
                    Instruction instruction = listing.getInstructionAt(currentAddr);
                    //println(instruction.toString());
                    String mnemonic = instruction.getMnemonicString();
                    if (mnemonic.equals("str")) {
                        Object[] opObjs1 = instruction.getOpObjects(1);
                        Object opObj1 = opObjs1[1];
                        long value = ((Scalar) opObj1).getValue();
                        value += configAddress.getOffset();
                        addressOfCopiedData = toAddr(value);
                        //println(address2.toString());
                        //addressMap.put(addressOfCopiedData, addressOfOrigData);
                    }
                }

                currentAddr = fromAddr;
                while (true) {
                    currentAddr = currentAddr.subtract(4);
                    //println(currentAddr.toString());
                    Instruction instruction = listing.getInstructionAt(currentAddr);
                    String mnemonic = instruction.getMnemonicString();

                    if (mnemonic.equals("mov")) {
                        Object[] opObjs0 = instruction.getOpObjects(0);
                        Object opObj0 = opObjs0[0];
                        if (opObj0.toString().equals("r2")) {
                            Scalar scalar = instruction.getScalar(1);
                            long size = scalar.getValue();
                            sizeList.add(size);
                            println(addressOfCopiedData.toString() + " - " + addressOfOrigData.toString() + " - " + size + " (mov)");
                            addressMap.put(addressOfCopiedData, new AddressSize(addressOfOrigData, size));
                            break;
                        }
                    }

                    if (mnemonic.equals("bl") || mnemonic.equals("stmdb")) {
                        //println("found bl or stmdb at " + currentAddr + ", following cpy");
                        // we did not find the size value by looking for `mov r2, <size>`
                        // we need to follow the `cpy r2, <reg>` instruction now
                        Address tmpAddr = fromAddr;
                        tmpAddr = tmpAddr.subtract(4);
                        instruction = listing.getInstructionAt(tmpAddr);
                        //println("tmpInstr - " + instruction.toString() + " @ " + tmpAddr.toString());
                        mnemonic = instruction.getMnemonicString();

                        Object tmpOpObj0 = null;
                        if (instruction.getNumOperands() > 0) {
                            Object[] opObjs0 = instruction.getOpObjects(0);
                            tmpOpObj0 = opObjs0[0];
                        }

                        while (!(mnemonic.equals("cpy") && tmpOpObj0.toString().equals("r2"))) {
                            tmpAddr = tmpAddr.subtract(4);
                            instruction = listing.getInstructionAt(tmpAddr);
                            //println("tmpInstr - " + instruction.toString() + " @ " + tmpAddr.toString());
                            mnemonic = instruction.getMnemonicString();
                            Object[] opObjs0 = instruction.getOpObjects(0);
                            tmpOpObj0 = opObjs0[0];
                        }

                        //println("cpy r2 found @ " + tmpAddr.toString());
                        Object[] opObjs1 = instruction.getOpObjects(1);
                        Object opObj1 = opObjs1[0];

                        String targetReg = opObj1.toString();
                        //println("tracking " + targetReg);
                        additionTotal = 0;
                        Address trackAddr = tmpAddr;

                        while (true) {
                            trackAddr = trackAddr.subtract(4);
                            Instruction trackInst = listing.getInstructionAt(trackAddr);

                            String trackMnemonic = trackInst.getMnemonicString();

                            if (trackInst.getNumOperands() > 0) {
                                Object[] trackOpObjs0 = trackInst.getOpObjects(0);
                                if (trackOpObjs0[0].toString().equals(targetReg)) {

                                    if (trackMnemonic.equals("mov")) {
                                        Scalar trackScalar = trackInst.getScalar(1);
                                        long trackSize = trackScalar.getValue();
                                        // Add any accumulated additions to the final size
                                        if (additionTotal > 0) {
                                            trackSize += additionTotal;
                                            println(addressOfCopiedData.toString() + " - " + addressOfOrigData.toString() + " - " + trackSize + " (cpy+adds " + additionTotal + ")");
                                        } else {
                                            println(addressOfCopiedData.toString() + " - " + addressOfOrigData.toString() + " - " + trackSize + " (cpy)");
                                        }

                                        addressMap.put(addressOfCopiedData, new AddressSize(addressOfOrigData, trackSize));
                                        sizeList.add(trackSize);
                                        break;
                                    } else if (trackMnemonic.equals("cpy")) {
                                        Object[] trackOpObjs1 = trackInst.getOpObjects(1);
                                        targetReg = trackOpObjs1[0].toString();
                                    } else if (trackMnemonic.equals("add")) {
                                        if (trackInst.getNumOperands() > 2 && trackInst.getOpObjects(2)[0] instanceof Scalar) {
                                            Scalar addValue = (Scalar) trackInst.getOpObjects(2)[0];
                                            long value = addValue.getValue();
                                            additionTotal += value;
                                            println("Found addition to " + targetReg + ": +" + value);
                                        } else {
                                            Object[] trackOpObjs1 = trackInst.getOpObjects(1);
                                            targetReg = trackOpObjs1[0].toString();
                                            println("Following register after add: " + targetReg);
                                        }
                                    }
                                }
                            }
                            if (trackMnemonic.equals("stmdb")) {
                                println("error: epilogue reached while tracking cpy registers");
                                return;
                            }
                        }
                        break;

                    }
                }
            }
        }
        /*
        for (Map.Entry<Address, Address> entry : addressMap.entrySet()) {
            Address address = entry.getValue();
            println(decode(address));
        }
         */
        //println("number of total configs: " + addressMap.size());
        //println("number of used configs: " + addressList.size());
        /*
        for (Address address : addressList) {
            Address addressMapped = addressMap.get(address);
            println(address.toString() + " - " + toAddr(address.getOffset() / 8 - configAddress.getOffset() / 8).toString() + " - " + addressMapped.toString() + " - " + decode(addressMapped));
        }

        println("sizeList:");
        for (long size : sizeList) {
            println("" + size);
        }

        println("size of sizeList: " + sizeList.size());
         */

        // todo: they are not mapped properly ..............
        /*
        for (int i = 0; i < addressList.size(); i++) {
            Address address = addressList.get(i);
            Long size = sizeList.get(i);

            Address addressMapped = addressMap.get(address);
            println(address.toString() + " - " + toAddr(address.getOffset() / 8 - configAddress.getOffset() / 8).toString() + " - " + addressMapped.toString() + " - " + decode(addressMapped, size));

        }
         */
        for (Map.Entry<Address, AddressSize> entry : addressMap.entrySet()) {
            Address mappedAddress = entry.getKey();
            AddressSize addressSize = entry.getValue();

            println(mappedAddress.toString() + " -> "
                    + addressSize.address.toString() + " (size: "
                    + addressSize.size + ")");
        }
        /*
        for (Map.Entry<Address, AddressSize> entry : addressMap.entrySet()) {
            Address mappedAddress = entry.getKey();
            AddressSize addressSize = entry.getValue();

            println(decode(addressSize.address, addressSize.size));
        }
         */
        for (Address address : addressList) {
            AddressSize addressMapped = addressMap.get(address);
            println(address.toString() + " - " + toAddr(address.getOffset() / 8 - configAddress.getOffset() / 8).toString() + " - " + addressMapped.address.toString() + " - " + decode(addressMapped.address, addressMapped.size));
        }
        println("size of addressMap: " + addressMap.size());
    }

    private class AddressSize {

        public Address address;
        public long size;

        public AddressSize(Address address, long size) {
            this.address = address;
            this.size = size;
        }
    }

    private String decode(Address address, long size) throws Exception {
        int bytesToRead = (int) size;
        byte[] inputBytes = new byte[bytesToRead];

        for (int i = 0; i < bytesToRead; i++) {
            inputBytes[i] = memory.getByte(address.add(i));
        }

        byte[] outputBytes = new byte[bytesToRead];

        int key = ENCRYPTION_KEY;
        byte keyByte0 = (byte) key;
        byte keyByte1 = (byte) (key >> 8);
        byte keyByte2 = (byte) (key >> 16);
        byte keyByte3 = (byte) (key >> 24);

        for (int i = 0; i < bytesToRead; i++) {
            byte current = inputBytes[i];
            current = (byte) (keyByte0 ^ current);
            current = (byte) (keyByte1 ^ current);
            current = (byte) (keyByte2 ^ current);
            current = (byte) (keyByte3 ^ current);
            outputBytes[i] = current;
        }

        StringBuilder asciiOutput = new StringBuilder();
        for (int i = 0; i < bytesToRead; i++) {
            byte b = outputBytes[i];
            if (b >= 32 && b <= 126) {
                asciiOutput.append((char) b);
            } else {
                asciiOutput.append('.');
            }
        }

        StringBuilder hexOutput = new StringBuilder();
        for (int i = 0; i < bytesToRead; i++) {
            hexOutput.append(String.format("%02X ", outputBytes[i] & 0xFF));
        }

        return asciiOutput.toString() + " (" + hexOutput.toString().trim() + ")";
        //return asciiOutput.toString();
    }
}
