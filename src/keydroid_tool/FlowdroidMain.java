package analysis_tool;

import java.io.File;
import java.io.FileWriter;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.FileNotFoundException;
import com.opencsv.CSVWriter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.util.Scanner;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.List;
import java.util.ArrayList;

import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.lang.InterruptedException;
import java.util.concurrent.ExecutionException;


//import com.google.gson.Gson;
//import com.google.gson.GsonBuilder;

import soot.PackManager;
import soot.Scene;
import soot.*;
import soot.SootMethod;
import soot.Unit;
import soot.Context;
//import soot.jimple.infoflow.InfoflowConfiguration;
//import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
//import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.callgraph.ContextSensitiveEdge;
import soot.jimple.toolkits.callgraph.Targets;
import soot.options.Options;

import static analysis_tool.Utils.*;

// static String mainActivityClassName = "dev.navids.multicomp1.MainActivity";

public class FlowdroidMain {

	static List<String> apkNames = new ArrayList<String>();
	static String androidJarPath = "src/analysis_tool/flowdroid_jar_files";
	
	//static String[] apkList = {"roblox.apk"};
	//static String androidJarPath = "/Users/jennyblessing/Library/Android/sdk/platforms";


	public static class RunApk implements Callable<Boolean> {
		private final String apkNameStr;
		private final String sizeCategoryStr;

		public RunApk(String apkNameStr, String sizeCategoryStr) {
			this.apkNameStr = apkNameStr;
			this.sizeCategoryStr = sizeCategoryStr;
		}

		@Override
		public Boolean call() throws Exception {
			System.out.println("Running " + apkNameStr + "!");

			try {
				SootApk apk = setup(apkNameStr, sizeCategoryStr);
				System.out.println("Finished setup.");

				if (apk != null) {
					apk.runAnalysis();

					// reset callers_cache?
				} else {
					System.out.println("Error with: " + apkNameStr);
					writeErrorApkToList(apkNameStr, sizeCategoryStr);
					return false;
				}

			} catch(Exception errorApk) {
				System.out.println("Exception with: " + apkNameStr);
				errorApk.printStackTrace();
				writeErrorApkToList(apkNameStr, sizeCategoryStr);
				return false;
			}

			return true;
		}
	}

	public static ArrayList<String> getApkList(String sizeCategory) {
		String listPathStr = "metadata/az_" + sizeCategory + "/az_" + sizeCategory + "_candidates.csv";

		Path listFile = Paths.get(listPathStr);
		ArrayList<String> apkList = new ArrayList<String>();
		if (Files.exists(listFile)) {
			// Read in each line and write it to arraylist

			try {
				Scanner s = new Scanner(new File(listPathStr));
				while (s.hasNextLine()) {
					apkList.add(s.nextLine().strip());
				}
				s.close();
			} catch (FileNotFoundException fe) {
				fe.printStackTrace();
				return null;
			}
		}

		return apkList;
	}

	public static ArrayList<String> getApkListFiles(String sizeCategory) {
		// Path apkScanPath = Paths.get("results/az_" + sizeCategory + "/" + apkName + "_android_method_freqs.csv");
		ArrayList<String> apkList = new ArrayList<String>();

		File results_folder = new File("results/az_" + sizeCategory);
		File[] fileList = results_folder.listFiles();
		if (fileList != null) {
			for (int i = 0; i < fileList.length; i++) {
				if (fileList[i].isFile()) {
					String fName = fileList[i].getName();
					String fSuffix = fName.substring(fName.length() - 24);

					if (fSuffix.equals("android_method_freqs.csv")) {
						String apkName = fName.substring(0, fName.length() - 25);
						apkList.add(apkName);
					}


				}
			}
		}

		System.out.println(apkList);
		return apkList;
	}

	public static void main(String[] args) {
		if (args.length < 3) {
			System.out.println("Invalid arguments.");
		}
		String sizeCategory = args[0];
		int startIdx = Integer.valueOf(args[1]);
		int endIdx = Integer.valueOf(args[2]);

		System.out.println("Reading in Keystore search files...");
		// Generate list of Keystore APKs to process for this size category.


		// Get list from overall candidates, then filter by APKs that have _android_method_freqs file.
		ArrayList<String> apkNames = getApkListFiles(sizeCategory);
		if (apkNames == null || apkNames.isEmpty()) {
			System.out.println("Error retrieving APK list.");
			return;
		}

		if (endIdx == 0) {
			endIdx = apkNames.size();
		}
		List<String> apkList = apkNames.subList(startIdx, endIdx);

		List<String> keystoreApkList = new ArrayList<String>();
		for (String apkName : apkList) {
			Path apkScanPath = Paths.get("results/az_" + sizeCategory + "/" + apkName + "_android_method_freqs.csv");

			if (Files.exists(apkScanPath)) {
				keystoreApkList.add(apkName);
			} else {
				System.out.println("No android_method_freqs file for: " + apkName);
			}
		}

		/*
		File[] files = new File("results/az_" + sizeCategory).listFiles();

		for (File file : files) {
			if (file.isFile()) {
				String fName = file.getName();

				if(fName.endsWith("_android_method_freqs.csv")) {
					String apkName = fName.substring(0, fName.length() - 25);
					apkNames.add(apkName);
				}
			}
		}
		*/


		// Check if analysis directory already exists for this size category.
		File sizeCategoryDir = new File("results/az_" + sizeCategory + "/call_analysis");
		if (!sizeCategoryDir.exists()) {
			sizeCategoryDir.mkdirs();
		}

		int numAPKs = keystoreApkList.size();
		if (endIdx == 0) {
			endIdx = numAPKs;
		}
		int counter = startIdx;

		// get Error APKs
		List<String> errorApks = getErrorApks(sizeCategory);

		//int counter = 0; // comment out
		//int numAPKs = 1; // comment out
		for (String apkName : keystoreApkList) {
			Path callsFile = Paths.get("results/az_" + sizeCategory + "/call_analysis/" + apkName + "_keystore_calls.csv");
			if (Files.exists(callsFile)) {
				// Have already successfully analyzed this APK.
				System.out.println("Already analyzed APK: " + apkName);
				counter++;
			} else if (errorApks != null && errorApks.contains(apkName)) {
				// Have already analyzed this APK and it resulted in an error.
				System.out.println("Already analyzed APK with error: " + apkName);
				counter++;
			} else {
				// Have not analyzed this APK.

				// Check if path for keystore call paths exists --- if so, delete file
				File pathsFile = new File("results/az_" + sizeCategory + "/call_analysis/" + apkName + "_keystore_call_paths.csv");
				if (pathsFile.exists()) {
					// The scenario where the call paths file exists but the calls file doesn't occurs if there's an error
					// part-way through the analysis.
					pathsFile.delete();
				}
				System.out.println();
				System.out.println(String.format("%s / %s", counter, numAPKs));

				long start = System.currentTimeMillis();
				
				ExecutorService executor = Executors.newCachedThreadPool();
				Boolean returnVal = true;
				Future<Boolean> future = executor.submit(new FutureTask(new RunApk(apkName, sizeCategory)), returnVal);
				try {
					Boolean result = future.get(30, TimeUnit.MINUTES);
				} catch (TimeoutException ex) {
					System.out.println("Timeout exception with: " + apkName);
					writeErrorApkToList(apkName, sizeCategory);
				} catch (InterruptedException e) {
				   	System.out.println("Timeout exception with: " + apkName);
					writeErrorApkToList(apkName, sizeCategory);
				} catch (ExecutionException e) {
				   	System.out.println("Timeout exception with: " + apkName);
					writeErrorApkToList(apkName, sizeCategory);
				} finally {
				   future.cancel(true); // may or may not desire this
				}

				long finish = System.currentTimeMillis();
				long timeElapsed = finish - start;
				String timeStr = Long.toString(timeElapsed/1000);
				System.out.println("Time to analyze APK: " + timeStr + " seconds.");

				writeRuntimeMetadata(apkName, timeStr, sizeCategory);

				// Pause for 1 second between each APK.
				try {
					Thread.sleep(1000);
				} catch(InterruptedException e) {
					System.out.println(e);
				}

				counter++;
			}
		}

		System.exit(99);
	}

	public static String getApkPathStr(String apkName, String sizeStr) {
		// To remove ".apk" suffix.
		//String apkNameStr = apkName.substring(0, apkName.length() - 4);

		return "apks/az_" + sizeStr + "/" + apkName;
	}

	public static boolean checkApk(String apkName, String sizeStr) {
		File apkFile = new File(getApkPathStr(apkName, sizeStr));
		if (!apkFile.exists()) {
			System.out.println("Cannot find APK file for: " + apkFile.getName());
			return false;
		}

		return true;
	}

	public static List<String> getErrorApks(String sizeCategory) {
		List<String> errorApks = new ArrayList<String>();

		try {
			Scanner s = new Scanner(new File(getErrorFilePath(sizeCategory)));
			
			while (s.hasNextLine()) {
				errorApks.add(s.nextLine().strip());
			}
			s.close();
		} catch (FileNotFoundException fe) {
			fe.printStackTrace();
			return null;
		}

		return errorApks;
	}

	public static void writeErrorApkToList(String apkName, String sizeCategory) {
		try {
			BufferedWriter bw = new BufferedWriter(new FileWriter(getErrorFilePath(sizeCategory)));
			bw.write(apkName);
			bw.newLine();
			bw.close();
		} catch(Exception errorWrite) {
			System.out.println("Exception writing APK Name to error file:" + apkName);
		}
	}

	public static String getMetaFilePath(String sizeCategory) {
		return "metadata/az_" + sizeCategory + "/az_" + sizeCategory + "_analysis_runtimes.csv";
	}

	public static String getErrorFilePath(String sizeCategory) {
		return "metadata/az_" + sizeCategory + "/az_" + sizeCategory + "_analysis_error_apks.csv";
	}

	public static void writeRuntimeMetadata(String apkName, String timeStr, String sizeCategory) {
		// Write line to meta file.
		File runtimeFile = new File(getMetaFilePath(sizeCategory));
		String[] apkRuntime = {apkName, timeStr};

    	try {
    		FileWriter outputFile = new FileWriter(runtimeFile, true);
    		CSVWriter writer = new CSVWriter(outputFile);

    		writer.writeNext(apkRuntime);

    		writer.close();
    	} catch (IOException e) {
    		e.printStackTrace();
    	}
	}

	public static SootApk runSetup(String apkName, String apkPath, String sizeStr) {
		System.out.println("Used Memory / Max Memory: " + getUsedMemory() + "/" + getMaxMemory());

		// Reset Soot Singletons to initial state to run Soot again inside same process.
		soot.G.reset();

		Options.v().set_process_dir(Collections.singletonList(apkPath));

		Options.v().set_android_jars(androidJarPath);
		Options.v().set_allow_phantom_refs(true);
		Options.v().set_whole_program(true);
		Options.v().set_no_bodies_for_excluded(true);
		Options.v().set_process_multiple_dex(true);
		Options.v().set_src_prec(Options.src_prec_apk);		// Specify input is APK
		Options.v().set_output_format(Options.output_format_jimple);
		Options.v().set_app(false);

		// Do not include methods unreachable from entry points in call graph.
		Options.v().setPhaseOption("cg", "all-reachable:true");
		Options.v().setPhaseOption("cg", "implicit-entry:true");
		// Use Call Hierarchy Analysis algorithm.
		Options.v().setPhaseOption("cg.cha", "enabled:true");

		// Eliminate unreachable code in Soot transformations.
		Options.v().setPhaseOption("jb.uce", "enabled:false");
		Options.v().setPhaseOption("jj.uce", "enabled:false");

		System.out.println("Generating call graph...");

		try {
			Scene.v().loadNecessaryClasses();
			PackManager.v().runPacks();

			// System.gc();

			Scene apkScene = Scene.v();
			SootApk sootApk = new SootApk(apkScene, apkName, sizeStr);
			return sootApk;
		} catch (OutOfMemoryError oom) {
			System.out.println("Out of Memory Error.");
			return null;
		}
	}

	public static SootApk setup(String apkName, String sizeStr) {
		String apkPath;
		if (checkApk(apkName + ".apk", sizeStr)) {
			apkPath = getApkPathStr(apkName + ".apk", sizeStr);
		} else if (checkApk(apkName + "_mod.apk", sizeStr)) {
			apkPath = getApkPathStr(apkName + "_mod.apk", sizeStr);
		} else {
			return null;
		}

		return runSetup(apkName, apkPath, sizeStr);
	}

	public static long getMaxMemory() {
	    return Runtime.getRuntime().maxMemory();
	}

	public static long getUsedMemory() {
	    return getMaxMemory() - getFreeMemory();
	}

	public static long getTotalMemory() {
	    return Runtime.getRuntime().totalMemory();
	}

	public static long getFreeMemory() {
    	return Runtime.getRuntime().freeMemory();
	}

}