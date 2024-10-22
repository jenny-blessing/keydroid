package analysis_tool;

import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.InvokeExpr;

import java.util.Set;
import java.util.HashSet;
import java.util.List;

import static analysis_tool.Utils.*;

public class SootCall {
	public SootClass sootClass;
	public SootMethod sootMethod;
	public Unit sootUnit;
	public InvokeExpr expr;

	private List<Value> args;
	private List<Value> paramValues;

	private String registerStr;

	public boolean reachability;

	public SootCall(SootMethod sm, Unit u, InvokeExpr ie) {
		this.sootMethod = sm;
		this.sootUnit = u;
		this.expr = ie;
		this.sootClass = sm.getDeclaringClass();
		this.registerStr = null;

		this.reachability = false;
	}

	public String toString() {
		/*
		String pkgName = "Package Name: " + sootClass.getPackageName();
		String jPkgName = "Java Package Name: " + sootClass.getJavaPackageName();
		String appClass = "Is Application Class: " + sootClass.isApplicationClass();
		String c = "Class: " + sootClass.toString();
		String m = "Method: " + sootMethod.getSignature();
		String u = "Unit: " + sootUnit;

		return join("\n", pkgName, jPkgName, c, appClass, m, u);
		*/
		return sootMethod.getSignature();
	}

	public void setArgs(List<Value> args) {
		this.args = args;
	}

	public List<Value> getArgs() {
		return this.args;
	}

	public void setParamValues(List<Value> paramValues) {
		this.paramValues = paramValues;
	}

	public List<Value> getParamValues() {
		return this.paramValues;
	}

	public void setCallObject(String registerStr) {
		this.registerStr = registerStr;
	}

	public String getCallObject() {
		if (this.registerStr != null) {
			return this.registerStr;
		} else {
			return "-";
		}
	}

}