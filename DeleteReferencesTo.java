
//Deletes all references to the current address
//@category References
//@author gemesa
import java.util.Arrays;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.ReferenceManager;

public class DeleteReferencesTo extends GhidraScript {

    @Override
    public void run() throws Exception {
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        String choice = askChoice("Delete references to", "Select input mode",
                Arrays.asList("Current address", "Enter address manually"),
                "Current address");

        Address address;
        if (choice.equals("Current address")) {
            address = currentAddress;
        } else {
            address = toAddr(askInt("Delete references to", "Enter address"));
        }

        int refCnt = refMgr.getReferenceCountTo(address);
        println("Selected address: " + address.toString() + " - found " + refCnt + " references");
        if (refCnt > 0) {
            refMgr.removeAllReferencesTo(address);
            println("References deleted");
        }
    }
}
