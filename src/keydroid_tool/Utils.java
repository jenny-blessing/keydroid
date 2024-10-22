package analysis_tool;

import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import soot.Body;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.Type;
import soot.Local;

public class Utils {
	public static String[] getParameterList(String jimpleMethod) {

		Matcher matchPattern = params.matcher(jimpleMethod);
		if (matchPattern.find()) {
			String t = matchPattern.group(1);
			if (t.length() == 0) {
				return new String[] {};
			}
			return t.split(",");
		}
		return new String[] {};
	}

	public static String getMethodName(String jimpleMethod) {
		return jimpleMethod.replaceFirst("<", "").split(" ")[2].split("\\(")[0].replaceAll("'", "");
	}

	public static String getSubSignature(String jimpleMethod) {
		StringBuffer sb = new StringBuffer();
		return sb.append(jimpleMethod.split(" ")[1] + " " + jimpleMethod.split(" ")[2]).deleteCharAt(sb.length() - 1)
				.toString();
	}

	public static String getPackage(String methodSignature) {
		String packageName = getClassNameForMethod(methodSignature);
		packageName = packageName.substring(0, packageName.lastIndexOf('.'));
		return packageName;
	}

	public static String getReturnType(String methodSignature) {
		return methodSignature.split(" ")[1];
	}

	public static boolean isAndroidMethod(SootMethod sootMethod) {
		String className = sootMethod.getDeclaringClass().getName();

		List<String> androidPkgPrefixes = Arrays.asList("android.", "com.google.android", "androidx.");

		// if (name.startsWith("android.") || name.startsWith)

		return androidPkgPrefixes.stream().map(className::startsWith).reduce(false, (res, curr) -> res || curr);
	}

	public static boolean isOwnMethod(SootMethod method , String ownPackageName){
		SootClass sc = method.getDeclaringClass();
		if(sc.getName().startsWith(ownPackageName)){
			return true;
		}
		return false;
	}

	public static void prettyPrint(SootClass sClass) {
		// String fileName = SourceLocator.v().getFileNameFor(sClass,
		// Options.output_format_jimple);
		// try (PrintWriter writerOut = new PrintWriter(new
		// OutputStreamWriter(System.out))) {
		// // Options.v().set_xml_attributes(true);
		// Options.v().set_print_tags_in_output(true);
		// Printer.v().printTo(sClass, writerOut);
		// writerOut.flush();
		// }

		Iterator<SootMethod> i = sClass.methodIterator();
		System.out.println("Class " + sClass.getName());
		System.out.println(" Methods: ");
		while (i.hasNext()) {
			SootMethod m = i.next();
			System.out.println("\t" + m.getDeclaration());
			System.out.println(prettyPrint(m.getActiveBody()));
		}

	}

	public static String prettyPrint(Body body) {
		StringBuffer bodyBuffer = new StringBuffer();

		Iterator<Local> il = body.getLocals().iterator();
		while (il.hasNext()) {
			Local l = il.next();
			bodyBuffer.append(l).append(" ").append(l.getType()).append("\n");
		}
		Iterator<Unit> iu = body.getUnits().iterator();
		while (iu.hasNext()) {
			bodyBuffer.append(iu.next()).append("\n");
		}
		return bodyBuffer.toString();
	}

	public static String join(String sep, Object... oo){
		String tstr = "";
		if(oo==null){
			return null;
		}else{
			for(Object o : oo){
				if(o instanceof Iterable){
					tstr = ">>>" + sep;
					Iterable ii = (Iterable) o;
					Iterator<Object> it = ii.iterator();
					
					while (it.hasNext()){
						Object o2 = it.next();
						if(!(o instanceof String)){
							tstr += String.valueOf(o2);
						}else{
							tstr += (String) o2;
						}
						tstr += sep;
					}
					tstr += "<<<";
				}else if(!(o instanceof String)){
					tstr += String.valueOf(o);
				}else{
					tstr += (String) o;
				}
				tstr += sep;
			}
			
			if(tstr.endsWith(sep)){
				tstr = tstr.substring(0, tstr.length()-1);
			}
			return tstr;
		}
	}
	
	public static String join(Object... oo){
		String sep = "|";
		String tstr = "";
		if(oo==null){
			return null;
		}else{
			for(Object o : oo){
				if(!(o instanceof String)){
					tstr += String.valueOf(o);
				}else{
					tstr += (String) o;
				}
				tstr += sep;
			}
			return tstr;
		}
	}
	
	
	public static String sootClassTypeToString(int value){
		switch(value){
			case SootClass.BODIES:
				return "BODIES";
			case SootClass.DANGLING:
				return "DANGLING";
			case SootClass.HIERARCHY:
				return "HIERARCHY";
			case SootClass.SIGNATURES:
				return "SIGNATURES";
			default:
				return "UNKNOWN";
		}
	}
	
	public static <T> List<T> iterableToList(Iterable<T> c){
		LinkedList<T> res = new LinkedList<T>();
		for(T e : c){
			res.add(e);
		}
		return res;
	}
	
	public static boolean isSupportClass(SootClass targetClass) {
		String cname = targetClass.getName();
		String[] clist = {"android.support.v", "com.google.common.", "junit.", "org.junit."};
		for(String n : clist){
			if(cname.startsWith(n)){
				return true;
			}
		}
		return false;
	}
	
	public static Collection<String> expandToSupportClasses(String className){
		String[] compactVersions = {"v4", "v7", "v8", "v13", "v14", "v17"};
		String pre = "android.";
		
		List<String> classNames = new LinkedList<String>();
		if( className.startsWith(pre)){
			classNames.add(className);
			for(String cv : compactVersions){
				String compatString;
				if(className.contains("$")){
					int i = className.indexOf("$");
					compatString = className.substring(0, i) + "Compat" + className.substring(i);
				}else{
					compatString = className + "Compat";
				}
				classNames.add(pre + "support." + cv + "." + compatString.substring(pre.length()));
			}
		}else{
			classNames.add(className);
		}
		return classNames;
	}
	
	public static void printMethod(String tag, SootMethod mm){
		print(tag, mm.getSignature());
		if(mm.hasActiveBody()){
			for(Unit uu : mm.getActiveBody().getUnits()){
				print(tag, uu, uu.getClass().getSimpleName());
			}
		}else{
			print(tag, "no active body");
		}
	}
	
	public static String strExtract(String tstr, String start, String end){
		String tmp;
		tmp = tstr.substring(tstr.indexOf(start)+start.length());
		return tmp.substring(0, tmp.indexOf(end));
	}
	
	public static boolean stringInList(String s, Collection<String> sl){
		for(String ss : sl){
			if(s.equals(ss)){
				return true;
			}
		}
		return false;
	}
	
	public static boolean isReg(String reg){
		if(! reg.startsWith("$")){
			return false;
		}
		if(reg.contains(".<")){
			return false;
		}
		return true;
	}

	public static boolean isLibraryMethod(SootMethod method) {
		String cname = method.getDeclaringClass().getName();
		String[] clist = {"com.google.", "junit.", "org.junit."};
		for(String n : clist){
			if(cname.startsWith(n)){
				return true;
			}
		}
		return false;
	}

	/*
	public static boolean isAndroidMethod(SootMethod sootMethod){
        String clsSig = sootMethod.getDeclaringClass().getName();
        List<String> androidPrefixPkgNames = Arrays.asList("android.", "com.google.android", "androidx.");
        return androidPrefixPkgNames.stream().map(clsSig::startsWith).reduce(false, (res, curr) -> res || curr);
    }
    */

}