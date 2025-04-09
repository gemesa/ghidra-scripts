//Extracts Mirai credentials (SORA)
//@author gemesa

import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

public class MiraiCredentialExtractorSORA extends GhidraScript {

    public Memory memory = null;

    @Override
    protected void run() throws Exception {

        FunctionManager functionManager = currentProgram.getFunctionManager();
        Iterator<Function> functions = functionManager.getFunctions(true);
        Listing listing = currentProgram.getListing();

        Function targetFunction = null;

        while (functions.hasNext()) {
            Function func = functions.next();
            AddressSetView functionBody = func.getBody();

            InstructionIterator instructions = listing.getInstructions(functionBody, true);

            /*
				0000ff98 00 20 a0 e3     mov        r2,#0x0
									LAB_0000ff9c                                    XREF[1]:     0000ffb0(j)  
				0000ff9c 06 30 d2 e7     ldrb       r3,[r2,r6]
				0000ffa0 54 30 23 e2     eor        r3,r3,#0x54
				0000ffa4 06 30 c2 e7     strb       r3,[r2,r6]
				0000ffa8 01 20 82 e2     add        r2,r2,#0x1
				0000ffac 02 00 57 e1     cmp        r7,r2
				0000ffb0 f9 ff ff 1a     bne        LAB_0000ff9c
             */
            String[] pattern = {"mov", "ldrb", "eor", "strb", "add", "cmp", "bne"};
            int matchIndex = 0;

            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                String mnemonic = instruction.getMnemonicString();

                if (mnemonic.equals(pattern[matchIndex])) {
                    matchIndex++;

                    if (matchIndex == pattern.length) {
                        targetFunction = func;
                        break;
                    }

                } else {
                    matchIndex = 0;

                    if (mnemonic.equals(pattern[0])) {
                        matchIndex = 1;
                    }
                }
            }
        }

        if (targetFunction != null) {
            println("located decryption function: " + targetFunction.getName());
        } else {
            println("could not locate decryption function");
            return;
        }

        memory = currentProgram.getMemory();

        ReferenceManager refManager = currentProgram.getReferenceManager();
        ReferenceIterator references = refManager.getReferencesTo(targetFunction.getEntryPoint());
        int numOfCreds = 0;
        while (references.hasNext()) {
            Reference reference = references.next();
            //println(reference.toString());
            Address fromAddr = reference.getFromAddress();
            Address currentAddr = fromAddr;

            String user = null;
            String pass = null;
            boolean sameCreds = false;
            for (int i = 0; i < 4; i++) {
                currentAddr = currentAddr.subtract(4);
                Instruction instruction = listing.getInstructionAt(currentAddr);
                String mnemonic = instruction.getMnemonicString();
                Object[] opObjs0 = instruction.getOpObjects(0);
                Object opObj0 = opObjs0[0];
                if (mnemonic.equals("ldr") && opObj0.toString().equals("r0")) {
                    user = decode(instruction);
                } else if (mnemonic.equals("cpy") && opObj0.toString().equals("r1")) {
                    sameCreds = true;
                } else if (mnemonic.equals("ldr") && opObj0.toString().equals("r1")) {
                    pass = decode(instruction);
                }

                if ((user != null && pass != null) || (user != null && sameCreds)) {
                    println("\"" + user + "\" : \"" + pass + "\"");
                    user = null;
                    pass = null;
                    sameCreds = false;
                    numOfCreds++;
                    break;
                }
            }
        }
        println("number of credential pairs: " + numOfCreds);

    }

    private String decode(Instruction instruction) throws Exception {
        Object[] opObjs1 = instruction.getOpObjects(1);
        Object opObj1 = opObjs1[0];

        Address address = toAddr(opObj1.toString());
        // deref
        int value = memory.getInt(address);
        address = toAddr(value);
        StringBuilder hexOutput = new StringBuilder();
        StringBuilder hexOutput_decoded = new StringBuilder();
        StringBuilder asciiOutput = new StringBuilder();
        int maxBytes = 50;

        for (int j = 0; j < maxBytes; j++) {
            byte b = memory.getByte(address.add(j));

            hexOutput.append(String.format("%02X ", b & 0xFF));

            if (b == 0) {
                //println("found null terminator after " + (j + 1) + " bytes");
                break;
            }

            byte decoded = (byte) (b ^ 0x54);
            hexOutput_decoded.append(String.format("%02X ", decoded & 0xFF));

            if (decoded >= 32 && decoded <= 126) {
                asciiOutput.append((char) decoded);
            } else {
                asciiOutput.append(".");
            }
        }

        //println("Raw bytes:           " + hexOutput.toString());
        //println("Raw bytes (decoded): " + hexOutput_decoded.toString());
        return asciiOutput.toString();
    }
}
