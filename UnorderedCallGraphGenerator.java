
//Generates an unordered text-based call graph for the current program or function
//@category Functions
//@author gemesa
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import java.util.*;

public class UnorderedCallGraphGenerator extends GhidraScript {
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
				printCallGraph(func, 0);
			}
		}
	}

	private void generateCurrentFunctionCallGraph() throws Exception {
		Function currentFunction = getFunctionContaining(currentAddress);
		if (currentFunction == null) {
			println("No function selected!");
			return;
		}

		printCallGraph(currentFunction, 0);
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

		Set<Function> calledFunctions = function.getCalledFunctions(monitor);
		for (Function called : calledFunctions) {
			printCallGraph(called, depth + 1);
		}
	}
}