
//Generates an ordered call graph for either current function or whole program
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
	private boolean analyzeWholeProgram = false;

	@Override
	public void run() throws Exception {
		String choice = askChoice("Call graph analysis", "Select analysis scope",
			Arrays.asList("Current function", "Whole program"),
			"Current function");

		analyzeWholeProgram = choice.equals("Whole program");

		if (analyzeWholeProgram) {
			generateProgramCallGraph();
		}
		else {
			generateCurrentFunctionCallGraph();
		}

		println("\n" + graph.toString());
	}

	private void generateProgramCallGraph() throws Exception {

		FunctionManager functionManager = currentProgram.getFunctionManager();
		Iterator<Function> functions = functionManager.getFunctions(true);

		while (functions.hasNext()) {
			Function func = functions.next();
			if (!visited.contains(func.getName())) {
				printOrderedCallGraph(func, 0);
			}
		}
	}

	private void generateCurrentFunctionCallGraph() throws Exception {
		Function currentFunction = getFunctionContaining(currentAddress);
		if (currentFunction == null) {
			println("No function selected!");
			return;
		}

		printOrderedCallGraph(currentFunction, 0);
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
					.append(address);
			if (!function.isExternal()) {
				graph.append(" [already visited!]\n");
			}
			else {
				graph.append("\n");
			}

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