
//Deletes all references to the current address
//@category References
//@author gemesa
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.ReferenceManager;

public class DeleteReferencesTo extends GhidraScript {

    @Override
    public void run() throws Exception {
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        int refCnt = refMgr.getReferenceCountTo(currentAddress);
        println("Current address: " + currentAddress.toString() + " - found " + refCnt + " references");
        if (refCnt > 0) {
            refMgr.removeAllReferencesTo(currentAddress);
            println("References deleted");
        }
    }
}
