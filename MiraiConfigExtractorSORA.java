//Extracts Mirai config (SORA)
//@author gemesa

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

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

    FunctionManager functionManager = null;
    Iterator<Function> functions = null;
    Listing listing = null;
    Memory memory = null;
    ReferenceManager refManager = null;

    @Override
    protected void run() throws Exception {

        functionManager = currentProgram.getFunctionManager();
        functions = functionManager.getFunctions(true);
        listing = currentProgram.getListing();
        memory = currentProgram.getMemory();
        refManager = currentProgram.getReferenceManager();

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

        Function targetFunctionDecrypt = locateFunctionByPattern(patternDecrypt);

        if (targetFunctionDecrypt == null) {
            println("could not locate decryption function");
            return;
        }

        println("located decryption function: " + targetFunctionDecrypt.getName());

        Address configAddress = locateConfigAddress(targetFunctionDecrypt);

        if (configAddress == null) {
            println("could not locate config address");
            return;
        }

        println("located config address: " + configAddress.toString());

        Function targetFunctionCopy = locateFunctionByPattern(patternCopy);

        if (targetFunctionCopy == null) {
            println("could not locate copy function");
            return;
        }

        println("located copy function: " + targetFunctionCopy.getName());

        List<Address> referencedConfigAddressList = locateReferencedConfigAddresses(targetFunctionDecrypt, configAddress);

        println("located " + referencedConfigAddressList.size() + " referenced config blocks");

        HashMap<Address, AddressSize> mappedConfigData = mapConfigData(targetFunctionCopy, configAddress);

        println("located " + mappedConfigData.size() + " total config blocks");

        println("referenced config blocks (.bss address - config ID - .rodata address - string (hex bytes)):");

        for (Address address : referencedConfigAddressList) {
            AddressSize addressMapped = mappedConfigData.get(address);
            println(address.toString() + " - " + toAddr(address.getOffset() / 8 - configAddress.getOffset() / 8).toString() + " - " + addressMapped.address.toString() + " - " + decrypt(addressMapped.address, addressMapped.size));
        }
    }

    private Function locateFunctionByPattern(String[] pattern) {
        int matchIndex = 0;
        Function targetFunction = null;
        functionLoop:
        while (functions.hasNext()) {
            Function func = functions.next();
            AddressSetView functionBody = func.getBody();
            InstructionIterator instructions = listing.getInstructions(functionBody, true);

            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                String mnemonic = instruction.getMnemonicString();

                if (mnemonic.equals(pattern[matchIndex])) {
                    matchIndex++;

                    if (matchIndex == pattern.length) {
                        targetFunction = func;

                        break functionLoop;
                    }

                } else {
                    matchIndex = 0;

                    if (mnemonic.equals(pattern[0])) {
                        matchIndex = 1;
                    }
                }
            }
        }
        return targetFunction;
    }

    private Address locateConfigAddress(Function targetFunction) throws Exception {
        // Start address of the configuration data block is loaded by the first `ldr`
        // in the config decryption function.

        /*
            00013218 80 01 a0 e1     mov        r0,r0, lsl #0x3
            0001321c f0 40 2d e9     stmdb      sp!,{r4,r5,r6,r7,lr}
            00013220 07 00 c0 e3     bic        r0,r0,#0x7
            00013224 9c 30 9f e5     ldr        r3,[DAT_000132c8]                                = 00020E64h
         */
        AddressSetView functionBody = targetFunction.getBody();
        InstructionIterator instructions = listing.getInstructions(functionBody, true);

        Address configAddress = null;
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            String mnemonic = instruction.getMnemonicString();

            if (mnemonic.equals("ldr")) {
                Object[] opObjs1 = instruction.getOpObjects(1);
                Object opObj1 = opObjs1[0];
                Address address = toAddr(opObj1.toString());
                // deref
                int value = memory.getInt(address);
                configAddress = toAddr(value);
                break;
            }

        }
        return configAddress;
    }

    private List<Address> locateReferencedConfigAddresses(Function targetFunctionDecrypt, Address configAddress) {
        // Locate the references to the config decryption function and check the parameter passed in r0.
        // r0 holds the config ID which is an offset multiplied by 8 and added to the start address of the config block.

        /*
            0000a7bc 14 00 a0 e3     mov        r0,#0x14
            0000a7c0 94 22 00 eb     bl         mw_decrypt_with_key                              undefined mw_decrypt_with_key()
         */
        ReferenceIterator references = refManager.getReferencesTo(targetFunctionDecrypt.getEntryPoint());
        List<Address> addressList = new ArrayList<>();
        while (references.hasNext()) {
            Reference reference = references.next();
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
                    addressList.add(address);
                    break;
                }
            }
        }
        return addressList;
    }

    private HashMap<Address, AddressSize> mapConfigData(Function targetFunctionCopy, Address configAddress) throws Exception {
        // Previously we collected the referenced configuration data blocks (by following the decryption function references).
        // Now we collect all configuration data blocks (by following the copy function references).
        // This function copies the hardcoded encrypted data from .rodata to dynamically allocated blocks
        // The address of these dynamically allocated blocks are stored in .bss.
        // After that we map the 2 results.
        ReferenceIterator references = refManager.getReferencesTo(targetFunctionCopy.getEntryPoint());
        HashMap<Address, AddressSize> mappedConfigData = new HashMap<>();
        Address addressOfBssData = null;
        Address addressOfRoData = null;
        long additionTotal = 0;
        while (references.hasNext()) {
            Reference reference = references.next();
            Address addressOfFunctionCall = reference.getFromAddress();
            Address currentAddr = addressOfFunctionCall;

            boolean configFound = false;
            // Check the 4 instructions before the function call and look for the value loaded into r1.
            // r1 holds the .rodata address of the encrypted data.
            // Example:
            /*
                000132d4 02 00 a0 e3     mov        r0,#0x2
                000132d8 ff 08 00 eb     bl         mw_alloc                                         undefined mw_alloc()
                000132dc 02 50 a0 e3     mov        r5,#0x2
                000132e0 d8 4e 9f e5     ldr        r4,[DAT_000141c0]                                = 00020E64h
                000132e4 05 20 a0 e1     cpy        r2,r5
                000132e8 d4 1e 9f e5     ldr        r1=>s_Qt_00017cf0,[DAT_000141c4]                 = "Qt"
                                                                                                    = 00017CF0h
                000132ec 00 60 a0 e3     mov        r6,#0x0
                000132f0 00 70 a0 e1     cpy        r7,r0
                000132f4 34 04 00 eb     bl         mw_copy                                          undefined mw_copy()
             */
 /*
                uVar1 = mw_alloc(2);
                mw_copy(uVar1,"Qt",2);
             */
            for (int i = 0; i < 4; i++) {
                currentAddr = currentAddr.subtract(4);
                Instruction instruction = listing.getInstructionAt(currentAddr);
                String mnemonic = instruction.getMnemonicString();
                Object[] opObjs0 = instruction.getOpObjects(0);
                Object opObj0 = opObjs0[0];
                if (mnemonic.equals("ldr") && opObj0.toString().equals("r1")) {
                    Object[] opObjs1 = instruction.getOpObjects(1);
                    Object opObj1 = opObjs1[0];
                    // This is a generic copy function and is being used frequently in the code,
                    // so we need to filter out false positives, e.g. ldr r1,[sp,#0x4].
                    if (opObj1.toString().contains("sp")) {
                        continue;
                    }

                    addressOfRoData = toAddr(opObj1.toString());
                    // deref
                    int value = memory.getInt(addressOfRoData);
                    addressOfRoData = toAddr(value);
                    configFound = true;
                    break;
                }
            }

            if (!configFound) {
                continue;
            }

            // Now we check the 4 instructions after the function call,
            // the goal is to find the address of the dynamically allocated block (stored in .bss).
            // This address can be found in the 1. operand of the str instruction.
            // r4 holds the start address of the configuration block.
            // Example:
            /*
                000132e0 d8 4e 9f e5     ldr        r4,[DAT_000141c0]                                = 00020E64h
                ...
                000132f4 34 04 00 eb     bl         mw_copy                                          undefined mw_copy()
                000132f8 05 00 a0 e1     cpy        r0,r5
                000132fc 08 70 84 e5     str        r7,[r4,#0x8]=>DAT_00020e6c                       = ??
                00013300 0c 50 c4 e5     strb       r5,[r4,#0xc]=>DAT_00020e70                       = ??
                00013304 0d 60 c4 e5     strb       r6,[r4,#0xd]=>DAT_00020e71                       = ??
             */
 /*
                uVar1 = mw_alloc(2);
                mw_copy(uVar1,"Qt",2);
                DAT_00020e70 = 2;
                DAT_00020e71 = 0;
                DAT_00020e6c = uVar1;
             */
            currentAddr = addressOfFunctionCall;
            for (int i = 0; i < 4; i++) {
                currentAddr = currentAddr.add(4);
                Instruction instruction = listing.getInstructionAt(currentAddr);
                String mnemonic = instruction.getMnemonicString();
                if (mnemonic.equals("str")) {
                    Object[] opObjs1 = instruction.getOpObjects(1);
                    Object opObj1 = opObjs1[1];
                    long value = ((Scalar) opObj1).getValue();
                    value += configAddress.getOffset();
                    addressOfBssData = toAddr(value);
                }
            }

            // At this point we located the .rodata and .bss address pairs.
            // The only missing information is the size of the configuration data block,
            // which is passed via r2 to the copy function.
            currentAddr = addressOfFunctionCall;
            while (true) {
                currentAddr = currentAddr.subtract(4);
                Instruction instruction = listing.getInstructionAt(currentAddr);
                String mnemonic = instruction.getMnemonicString();

                // It is trivial to retrieve the size in case an immediate value is loaded into r2:
                // Example:
                /*
                    00013334 11 20 a0 e3     mov        r2,#0x11
                    00013338 11 b0 a0 e3     mov        r11,#0x11
                    0001333c 00 50 a0 e1     cpy        r5,r0
                    00013340 21 04 00 eb     bl         mw_copy                                          undefined mw_copy()
                 */
                if (mnemonic.equals("mov")) {
                    Object[] opObjs0 = instruction.getOpObjects(0);
                    Object opObj0 = opObjs0[0];
                    if (opObj0.toString().equals("r2")) {
                        Scalar scalar = instruction.getScalar(1);
                        long size = scalar.getValue();
                        mappedConfigData.put(addressOfBssData, new AddressSize(addressOfRoData, size));
                        break;
                    }
                }

                // In other cases the value is copied from an other register to r2.
                // Example:
                /*
                    000132e4 05 20 a0 e1     cpy        r2,r5
                    000132e8 d4 1e 9f e5     ldr        r1=>s_Qt_00017cf0,[DAT_000141c4]                 = "Qt"
                                                                                                        = 00017CF0h
                    000132ec 00 60 a0 e3     mov        r6,#0x0
                    000132f0 00 70 a0 e1     cpy        r7,r0
                    000132f4 34 04 00 eb     bl         mw_copy                                          undefined mw_copy()
                 */
                // When this happens we need to follow the source register until we find the immediate value.
                // The idea is that we check the previous instructions until we find a bl.
                // If we did not find a mov r2, <size> then we look for cpy.
                if (mnemonic.equals("bl")) {
                    Address trackAddressOfCpy = addressOfFunctionCall;
                    trackAddressOfCpy = trackAddressOfCpy.subtract(4);
                    instruction = listing.getInstructionAt(trackAddressOfCpy);
                    mnemonic = instruction.getMnemonicString();

                    Object opObj0 = null;
                    if (instruction.getNumOperands() > 0) {
                        Object[] opObjs0 = instruction.getOpObjects(0);
                        opObj0 = opObjs0[0];
                    }

                    // Search until we find the cpy r2, <source register> instruction.
                    while (!(mnemonic.equals("cpy") && opObj0.toString().equals("r2"))) {
                        trackAddressOfCpy = trackAddressOfCpy.subtract(4);
                        instruction = listing.getInstructionAt(trackAddressOfCpy);
                        mnemonic = instruction.getMnemonicString();
                        Object[] opObjs0 = instruction.getOpObjects(0);
                        opObj0 = opObjs0[0];
                    }

                    Object[] opObjs1 = instruction.getOpObjects(1);
                    Object opObj1 = opObjs1[0];

                    // Identify the source register.
                    String targetReg = opObj1.toString();
                    additionTotal = 0;
                    Address trackAddr = trackAddressOfCpy;

                    // At this point we identified the source register.
                    // Now we need to retreive its value.
                    while (true) {
                        trackAddr = trackAddr.subtract(4);
                        Instruction trackInst = listing.getInstructionAt(trackAddr);

                        String trackMnemonic = trackInst.getMnemonicString();

                        if (trackInst.getNumOperands() > 0) {
                            Object[] trackOpObjs0 = trackInst.getOpObjects(0);
                            if (trackOpObjs0[0].toString().equals(targetReg)) {

                                if (trackMnemonic.equals("mov")) {
                                    // We will end up here, even when tracking the value via cpy and add instructions.
                                    // Example:
                                    /*
                                        00013380 07 80 a0 e3     mov        r8,#0x7
                                        ...
                                        000137f0 08 80 88 e2     add        r8,r8,#0x8
                                        ...
                                        000139f8 08 20 a0 e1     cpy        r2,r8
                                        ...
                                        00013a04 70 02 00 eb     bl         mw_copy                                          undefined mw_copy()
                                     */
                                    Scalar trackScalar = trackInst.getScalar(1);
                                    long trackSize = trackScalar.getValue();
                                    // Add any accumulated additions to the final size.
                                    if (additionTotal > 0) {
                                        trackSize += additionTotal;

                                    }
                                    mappedConfigData.put(addressOfBssData, new AddressSize(addressOfRoData, trackSize));
                                    break;
                                } else if (trackMnemonic.equals("cpy")) {
                                    // We encountered an other cpy,
                                    // and now we need to track its source register.
                                    Object[] trackOpObjs1 = trackInst.getOpObjects(1);
                                    targetReg = trackOpObjs1[0].toString();
                                } else if (trackMnemonic.equals("add")) {
                                    // The value of the resigter we are tracking might be incremented.
                                    // Example:
                                    /*
                                        00013380 07 80 a0 e3     mov        r8,#0x7
                                        ...
                                        000137f0 08 80 88 e2     add        r8,r8,#0x8
                                        ...
                                        000139f8 08 20 a0 e1     cpy        r2,r8
                                        ...
                                        00013a04 70 02 00 eb     bl         mw_copy                                          undefined mw_copy()
                                     */
                                    if (trackInst.getNumOperands() > 2 && trackInst.getOpObjects(2)[0] instanceof Scalar) {
                                        Scalar addValue = (Scalar) trackInst.getOpObjects(2)[0];
                                        long value = addValue.getValue();
                                        additionTotal += value;
                                    }
                                }
                            }
                        }
                        if (trackMnemonic.equals("stmdb")) {
                            println("fatal error: prologue reached while tracking cpy registers");
                            return null;
                        }
                    }
                    // We found the size, lets break and continue with the next reference.
                    break;
                }
            }
        }

        return mappedConfigData;
    }

    private class AddressSize {

        public Address address;
        public long size;

        public AddressSize(Address address, long size) {
            this.address = address;
            this.size = size;
        }
    }

    private String decrypt(Address address, long size) throws Exception {
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
    }
}
