
//Generates an unordered text-based call graph for the current program
//@category Functions
//@author gemesa
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.address.Address;
import java.util.*;

public class UnorderedCallGraphGenerator extends GhidraScript {
	private Set<String> visited = new HashSet<>();
	private StringBuilder graph = new StringBuilder();

	@Override
	public void run() throws Exception {
		FunctionManager functionManager = currentProgram.getFunctionManager();
		Iterator<Function> functions = functionManager.getFunctions(true);

		while (functions.hasNext()) {
			Function func = functions.next();
			if (!visited.contains(func.getName())) {
				printCallGraph(func, 0);
			}
		}

		println("\n" + graph.toString());
	}

	private void printCallGraph(Function function, int depth) {
		String funcName = function.getName();
		String address;

		if (function.isExternal()) {
			address = "EXTERNAL:" + String.format("%08x", function.getID());
		}
		else {
			address = function.getEntryPoint().toString();
		}

		if (visited.contains(funcName)) {
			graph.append("  ".repeat(depth))
					.append(funcName)
					.append(" @ ")
					.append(address)
					.append(" [already visited!]\n");
			return;
		}

		visited.add(funcName);
		graph.append("  ".repeat(depth))
				.append(funcName)
				.append(" @ ")
				.append(address)
				.append("\n");

		Set<Function> calledFunctions = function.getCalledFunctions(monitor);
		for (Function called : calledFunctions) {
			printCallGraph(called, depth + 1);
		}
	}
}