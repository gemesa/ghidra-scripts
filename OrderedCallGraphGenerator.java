
//Generates an ordered text-based call graph for the current program
//@category Functions
//@author gemesa
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;
import java.util.*;

public class OrderedCallGraphGenerator extends GhidraScript {
	private Set<String> visited = new HashSet<>();
	private StringBuilder graph = new StringBuilder();

	@Override
	public void run() throws Exception {
		FunctionManager functionManager = currentProgram.getFunctionManager();
		Iterator<Function> functions = functionManager.getFunctions(true);

		while (functions.hasNext()) {
			Function func = functions.next();
			if (!visited.contains(func.getName())) {
				printOrderedCallGraph(func, 0);
			}
		}

		println(graph.toString());
	}

	private void printOrderedCallGraph(Function function, int depth) throws Exception {
		String funcName = function.getName();
		String address =
			function.isExternal() ? "EXTERNAL:" + String.format("%08x", function.getID())
					: function.getEntryPoint().toString();

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

		if (!function.isExternal()) {
			List<Function> orderedFunctions = new ArrayList<>();
			Address start = function.getEntryPoint();
			Address end = function.getBody().getMaxAddress();

			Listing listing = currentProgram.getListing();
			InstructionIterator instructions = listing.getInstructions(start, true);

			while (instructions.hasNext()) {
				Instruction instr = instructions.next();
				if (instr.getAddress().compareTo(end) > 0)
					break;

				Reference[] refs = instr.getReferencesFrom();
				for (Reference ref : refs) {
					RefType refType = ref.getReferenceType();
					if (refType.isCall() || refType.isData() || refType.isFlow()) {
						Function calledFunc = getFunctionAt(ref.getToAddress());
						if (calledFunc != null && !orderedFunctions.contains(calledFunc)) {
							orderedFunctions.add(calledFunc);
							printOrderedCallGraph(calledFunc, depth + 1);
						}
					}
				}
			}
		}
	}
}