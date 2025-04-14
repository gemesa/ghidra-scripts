//Extracts Mirai credentials (SORA)
//@author gemesa

import java.util.ArrayList;
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
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

public class MiraiCredentialExtractorSORAArm extends GhidraScript {

    Memory memory = null;
    FunctionManager functionManager = null;
    Iterator<Function> functions = null;
    Listing listing = null;

    @Override
    protected void run() throws Exception {

        functionManager = currentProgram.getFunctionManager();
        functions = functionManager.getFunctions(true);
        listing = currentProgram.getListing();
        memory = currentProgram.getMemory();

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
        String[] patternDecrypt = {"mov", "ldrb", "eor", "strb", "add", "cmp", "bne"};

        Function targetFunctionDecrypt = locateFunctionByPattern(patternDecrypt);

        if (targetFunctionDecrypt == null) {
            println("could not locate decryption function");
            return;
        }

        println("located decryption function: " + targetFunctionDecrypt.getName());

        List<Pair<String, String>> credentialPairs = collectCredentialPairs(targetFunctionDecrypt);

        println("found " + credentialPairs.size() + " credential pairs");

        println("credential pairs (username : password):");

        for (Pair<String, String> pair : credentialPairs) {
            println(pair.toString());
        }

    }

    private List<Pair<String, String>> collectCredentialPairs(Function targetFunction) throws Exception {
        ReferenceManager refManager = currentProgram.getReferenceManager();
        ReferenceIterator references = refManager.getReferencesTo(targetFunction.getEntryPoint());
        List<Pair<String, String>> credentialPairs = new ArrayList<>();
        // Iterate over the references to the decryption function,
        // and decrypt the user:password pairs.
        // r0 holds the address of the username.
        // r1 holds the address of the password.
        // Example:
        /*
            0001036c 54 02 1f e5     ldr        r0=>s_pkkv_00017cd4,[DAT_00010120]               = "pkkv",04h
                                                                                                = 00017CD4h
            00010370 5c 12 1f e5     ldr        r1=>s_vkkp_00017cdc,[DAT_0001011c]               = "vkkp",04h
                                                                                                = 00017CDCh
            00010374 0a 20 a0 e3     mov        r2,#0xa
            00010378 0e 40 cb e5     strb       r4,[r11,#0xe]=>DAT_00020de2                      = ??
            0001037c e8 fe ff eb     bl         mw_decrypt                                       undefined mw_decrypt()
         */
        while (references.hasNext()) {
            Reference reference = references.next();

            Address addressOfFunctionCall = reference.getFromAddress();
            Address currentAddr = addressOfFunctionCall;

            String user = null;
            String pass = null;
            boolean sameCreds = false;
            // Check the 4 instructions before the function call and look for the r0 and r1 values.
            for (int i = 0; i < 4; i++) {
                currentAddr = currentAddr.subtract(4);
                Instruction instruction = listing.getInstructionAt(currentAddr);
                String mnemonic = instruction.getMnemonicString();
                Object[] opObjs0 = instruction.getOpObjects(0);
                Object opObj0 = opObjs0[0];
                if (mnemonic.equals("ldr") && opObj0.toString().equals("r0")) {
                    Object[] opObjs1 = instruction.getOpObjects(1);
                    Object opObj1 = opObjs1[0];
                    Address address = toAddr(opObj1.toString());
                    // deref
                    int value = memory.getInt(address);
                    address = toAddr(value);

                    user = decrypt(address);
                } else if (mnemonic.equals("cpy") && opObj0.toString().equals("r1")) {
                    // Example:
                    /*
                        000103c0 80 02 1f e5     ldr        r0=>s_0125!8_00017bb0,[DAT_00010148]             = "0125!8 "
                                                                                                            = 00017BB0h
                        000103c4 0e 20 a0 e3     mov        r2,#0xe
                        000103c8 00 10 a0 e1     cpy        r1=>s_0125!8_00017bb0,r0                         = "0125!8 "
                        000103cc d4 fe ff eb     bl         mw_decrypt                                       undefined mw_decrypt()
                     */
                    sameCreds = true;
                } else if (mnemonic.equals("ldr") && opObj0.toString().equals("r1")) {
                    Object[] opObjs1 = instruction.getOpObjects(1);
                    Object opObj1 = opObjs1[0];
                    Address address = toAddr(opObj1.toString());
                    // deref
                    int value = memory.getInt(address);
                    address = toAddr(value);

                    pass = decrypt(address);
                }

                if (user != null && pass != null) {
                    credentialPairs.add(new Pair<>(user, pass));
                    break;
                } else if (user != null && sameCreds) {
                    credentialPairs.add(new Pair<>(user, user));
                    break;
                }
            }
        }
        return credentialPairs;
    }

    class Pair<U, P> {

        private final U username;
        private final P password;

        public Pair(U username, P password) {
            this.username = username;
            this.password = password;
        }

        @Override
        public String toString() {
            return "(\"" + username + "\" : \"" + password + "\")";
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

    private String decrypt(Address address) throws Exception {

        StringBuilder asciiOutput = new StringBuilder();
        int maxBytes = 50;

        for (int j = 0; j < maxBytes; j++) {
            byte b = memory.getByte(address.add(j));

            if (b == 0) {
                break;
            }

            byte decoded = (byte) (b ^ 0x54);

            if (decoded >= 32 && decoded <= 126) {
                asciiOutput.append((char) decoded);
            } else {
                asciiOutput.append(".");
            }
        }

        return asciiOutput.toString();
    }
}
