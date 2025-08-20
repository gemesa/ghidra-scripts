
//Prints the Go string at the specified address
//@category Go
//@author gemesa
import ghidra.app.script.GhidraScript;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.program.model.address.Address;
import ghidra.util.MessageType;

public class ExtractGoStringAt extends GhidraScript {

    @Override
    public void run() throws Exception {

        GhidraValuesMap values = new GhidraValuesMap();

        values.defineString("Address");
        values.defineString("Length");

        values.setValidator((valueMap, status) -> {
            if (!valueMap.hasValue("Address")) {
                status.setStatusText("Address must be specified", MessageType.ERROR);
                return false;
            }
            if (!valueMap.hasValue("Length")) {
                status.setStatusText("Length must be specified", MessageType.ERROR);
                return false;
            }
            return true;
        });

        values = askValues("Enter the Go string parameters", null, values);

        String addrStr = values.getString("Address");
        long addrRaw;
        if (addrStr.startsWith("0x") || addrStr.startsWith("0X")) {
            addrRaw = Long.parseUnsignedLong(addrStr.substring(2), 16);
        } else {
            addrRaw = Long.parseUnsignedLong(addrStr, 16);
        }

        String lenStr = values.getString("Length");
        long lenRaw;
        if (lenStr.startsWith("0x") || lenStr.startsWith("0X")) {
            lenRaw = Long.parseUnsignedLong(lenStr.substring(2), 16);
        } else {
            lenRaw = Long.parseUnsignedLong(lenStr, 16);
        }

        Address address = toAddr(addrRaw);

        byte[] bytes = getBytes(address, (int) lenRaw);
        String result = new String(bytes).trim();

        println("String at " + addrStr + ": " + result);
    }
}
