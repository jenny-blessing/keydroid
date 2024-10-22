package analysis_tool;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.Iterator;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import com.opencsv.CSVWriter;

import soot.Body;
import soot.Hierarchy;
import soot.Scene;
import soot.SootClass;
import soot.SootField;
import soot.SootMethod;
import soot.SootMethodRef;
import soot.SootResolver;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.UnitBox;
import soot.jimple.FieldRef;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.Stmt;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.internal.JInstanceFieldRef;
import soot.jimple.internal.JInterfaceInvokeExpr;
import soot.jimple.internal.JInvokeStmt;
import soot.jimple.internal.JNewExpr;
import soot.jimple.internal.JSpecialInvokeExpr;
import soot.jimple.internal.JStaticInvokeExpr;
import soot.jimple.internal.JVirtualInvokeExpr;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.ResolutionFailedException;

import static analysis_tool.Utils.*;
import static analysis_tool.AndroidCallGraphFilter.*;


public class SootApk {
	static String pkgName;
	static String sizeCategory;

	public Scene scene;

	public HashMap<String, SootClass> classes = new HashMap<String, SootClass>();

	public SootApk(Scene s, String pkgName, String sizeCategory) {
		this.scene = s;
		this.pkgName = pkgName;
		this.sizeCategory = sizeCategory;


		// Collect all classes in Scene into classes.
		for (SootClass sc : scene.getClasses()) {
			classes.put(sc.getName(), sc);

			// Specify the level Soot will resolve to for performance reasons.
			// Options: Dangling, Hierarchy, Signatures, and Bodies
			try {
				if (sc.resolvingLevel() <= SootClass.HIERARCHY) {
					SootResolver.v().reResolve(sc, SootClass.SIGNATURES);
				}
			} catch (ResolutionFailedException e) {
				System.out.println("Resolution failed.");
				continue;
			}
		}

	}

	public void runAnalysis() {
		CallGraph cg = scene.v().getCallGraph();
		AndroidCallGraphFilter filter = new AndroidCallGraphFilter(classes, cg);
		System.out.println("Size:");
		System.out.println(filter.getCallGraphSize());

		runKeystoreTests(filter);
		runAndroidSecurityTests(filter);
		runKeyProtectionTests(filter);
		runJavaCryptoTests(filter);
		runJavaKeystoreTests(filter);

	}

	public void runKeystoreTests(AndroidCallGraphFilter filter) {
		Collection<SootCall> keystoreUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "void <init>(java.lang.String,int)", true, true);
		if (keystoreUsages != null) {
			System.out.println("Number of KeyGenParameterSpec$Builder usages: " + keystoreUsages.size());
		}

		Collection<SootCall> algorithmParameterSpecUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setAlgorithmParameterSpec(java.security.spec.AlgorithmParameterSpec)", false, true);
		Collection<SootCall> blockModeUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setBlockModes(java.lang.String[])", false, true);
		Collection<SootCall> digestUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setDigests(java.lang.String[])", false, true);
		Collection<SootCall> keySizeUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setKeySize(int)", false, true);
		Collection<SootCall> encryptionPaddingUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setEncryptionPaddings(java.lang.String[])", false, true);
		Collection<SootCall> signaturePaddingUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setSignaturePaddings(java.lang.String[])", false, true);
		Collection<SootCall> randomizedEncryptionUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setRandomizedEncryptionRequired(boolean)", false, true);
		Collection<SootCall> unlockRequiredUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setUnlockedDeviceRequired(boolean)", false, true);
		Collection<SootCall> biometricInvalidatedUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setInvalidatedByBiometricEnrollment(boolean)", false, true);
		Collection<SootCall> authenticationRequiredUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setUserAuthenticationRequired(boolean)", false, true);
		Collection<SootCall> authenticationParamUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setUserAuthenticationParameters(int,int)", false, true);
		Collection<SootCall> authenticationValidBodyUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setUserAuthenticationValidWhileOnBody(boolean)", false, true);
		Collection<SootCall> authenticationValidDurationUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setUserAuthenticationValidityDurationSeconds(int)", false, true);
		Collection<SootCall> confirmationRequiredUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setUserConfirmationRequired(boolean)", false, true);
		Collection<SootCall> userPresenceUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setUserPresenceRequired(boolean)", false, true);
		Collection<SootCall> attestAliasUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setAttestKeyAlias(java.lang.String)", false, true);
		Collection<SootCall> attestationChallengeUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setAttestationChallenge(byte[])", false, true);
		Collection<SootCall> keyValidEndUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setKeyValidityEnd(java.util.Date)", false, true);
		Collection<SootCall> keyValidConsumptionEndUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setKeyValidityForConsumptionEnd(java.util.Date)", false, true);
		Collection<SootCall> keyValidOriginationEndUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setKeyValidityForOriginationEnd(java.util.Date)", false, true);
		Collection<SootCall> keyValidStartUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setKeyValidityStart(java.util.Date)", false, true);
		Collection<SootCall> certNotAfterUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setCertificateNotAfter(java.util.Date)", false, true);
		Collection<SootCall> certNotBeforeUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setCertificateNotBefore(java.util.Date)", false, true);
		Collection<SootCall> maxUsages = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setMaxUsageCount(int)", false, true);

		Collection<SootCall> strongboxUsages1 = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setIsStrongBoxBacked(boolean)", true, true);
		Collection<SootCall> strongboxCheck1 = runCallAnalysis(filter, "android.security.keystore.KeyGenParameterSpec", "boolean isStrongBoxBacked()", false, false);

		Collection<SootCall> levelCheck1 = runCallAnalysis(filter, "android.security.keystore.KeyInfo", "int getSecurityLevel()", false, false);
		Collection<SootCall> levelCheck2 = runCallAnalysis(filter, "android.security.keystore.KeyInfo", "boolean isInsideSecureHardware()", false, false);

		Collection<SootCall> wrappedKeyUsages = runCallAnalysis(filter, "android.security.keystore.WrappedKeyEntry", "void <init>(byte[],java.lang.String,java.lang.String,java.security.spec.AlgorithmParameterSpec", false, false);

	}

	public void runAndroidSecurityTests(AndroidCallGraphFilter filter) {
		Collection<SootCall> masterKeyUsages1 = runCallAnalysis(filter, "androidx.security.crypto.MasterKey$Builder", "void <init>(android.content.Context)", false, true);
		Collection<SootCall> masterKeyUsages2 = runCallAnalysis(filter, "androidx.security.crypto.MasterKey$Builder", "void <init>(android.content.Context,java.lang.String)", false, true);

		Collection<SootCall> keystoreCheck1 = runCallAnalysis(filter, "androidx.security.crypto.MasterKey", "boolean isKeyStoreBacked()", false, false);
		
		Collection<SootCall> strongboxUsages1 = runCallAnalysis(filter, "androidx.security.crypto.MasterKey$Builder", "androidx.security.crypto.MasterKey$Builder setRequestStrongBoxBacked(boolean)", true, true);
		Collection<SootCall> strongboxCheck1 = runCallAnalysis(filter, "androidx.security.crypto.MasterKey", "boolean isStrongBoxBacked()", false, false);
		
		Collection<SootCall> authenticationUsages1 = runCallAnalysis(filter, "androidx.security.crypto.MasterKey$Builder", "androidx.security.crypto.MasterKey$Builder setUserAuthenticationRequired(boolean)", false, true);
		Collection<SootCall> authenticationUsages2 = runCallAnalysis(filter, "androidx.security.crypto.MasterKey$Builder", "androidx.security.crypto.MasterKey$Builder setUserAuthenticationRequired(boolean, int)", false, true);
		Collection<SootCall> authenticationCheck1 = runCallAnalysis(filter, "androidx.security.crypto.MasterKey", "boolean isUserAuthenticationRequired()", false, false);

		// Check for deprecated MasterKeys (plural) API
		Collection<SootCall> masterKeysUsages = runCallAnalysis(filter, "androidx.security.crypto.MasterKeys", "java.lang.String getOrCreate(android.security.keystore.KeyGenParameterSpec)", false, false);

		Collection<SootCall> confirmationUsages1 = runCallAnalysis(filter, "android.security.ConfirmationPrompt$Builder", "android.security.ConfirmationPrompt build()", false, false);
		Collection<SootCall> confirmationUsages2 = runCallAnalysis(filter, "android.security.ConfirmationPrompt$Builder", "android.security.ConfirmationPrompt.Builder setPromptText(java.lang.CharSequence)", false, false);
		Collection<SootCall> confirmationCallback = runCallAnalysis(filter, "android.security.ConfirmationCallback", "void onConfirmed(byte[])", false, false);

	}

	public void runKeyProtectionTests(AndroidCallGraphFilter filter) {
		Collection<SootCall> keyProtectionUsages = runCallAnalysis(filter, "android.security.keystore.KeyProtection$Builder", "void <init>(int)", false, true);
		Collection<SootCall> blockModeUsages = runCallAnalysis(filter, "android.security.keystore.KeyProtection$Builder", "android.security.keystore.KeyProtection$Builder setBlockModes(java.lang.String[])", false, true);
		Collection<SootCall> digestUsages = runCallAnalysis(filter, "android.security.keystore.KeyProtection$Builder", "android.security.keystore.KeyProtection$Builder setDigests(java.lang.String[])", false, true);
		Collection<SootCall> encryptionPaddingUsages = runCallAnalysis(filter, "android.security.keystore.KeyProtection$Builder", "android.security.keystore.KeyProtection$Builder setEncryptionPaddings(java.lang.String[])", false, true);
		Collection<SootCall> biometricInvalidatedUsages = runCallAnalysis(filter, "android.security.keystore.KeyProtection$Builder", "android.security.keystore.KeyProtection$Builder setInvalidatedByBiometricEnrollment(boolean)", false, true);
		Collection<SootCall> strongboxUsages = runCallAnalysis(filter, "android.security.keystore.KeyProtection$Builder", "android.security.keystore.KeyProtection$Builder setIsStrongBoxBacked(boolean)", true, true);
		Collection<SootCall> maxUsages = runCallAnalysis(filter, "android.security.keystore.KeyProtection$Builder", "android.security.keystore.KeyProtection$Builder setMaxUsageCount(boolean)", false, true);
		Collection<SootCall> randomizedEncryptionUsages = runCallAnalysis(filter, "android.security.keystore.KeyProtection$Builder", "android.security.keystore.KeyProtection$Builder setRandomizedEncryptionRequired(boolean)", false, true);
		Collection<SootCall> signaturePaddingUsages = runCallAnalysis(filter, "android.security.keystore.KeyProtection$Builder", "android.security.keystore.KeyProtection$Builder setSignaturePaddings(java.lang.String[])", false, true);
		Collection<SootCall> unlockRequiredUsages = runCallAnalysis(filter, "android.security.keystore.KeyProtection$Builder", "android.security.keystore.KeyProtection$Builder setUnlockedDeviceRequired(boolean)", false, true);
		Collection<SootCall> authenticationParamUsages = runCallAnalysis(filter, "android.security.keystore.KeyProtection$Builder", "android.security.keystore.KeyProtection$Builder setUserAuthenticationParameters(int,int)", false, true);
		Collection<SootCall> authenticationRequiredUsages = runCallAnalysis(filter, "android.security.keystore.KeyProtection$Builder", "android.security.keystore.KeyProtection$Builder setUserAuthenticationRequired(boolean)", false, true);
		Collection<SootCall> authenticationValidBodyUsages = runCallAnalysis(filter, "android.security.keystore.KeyProtection$Builder", "android.security.keystore.KeyProtection$Builder setUserAuthenticationValidWhileOnBody(boolean)", false, true);
		Collection<SootCall> authenticationValidDurationUsages = runCallAnalysis(filter, "android.security.keystore.KeyProtection$Builder", "android.security.keystore.KeyProtection$Builder setUserAuthenticationValidityDurationSeconds(int)", false, true);
		Collection<SootCall> confirmationRequiredUsages = runCallAnalysis(filter, "android.security.keystore.KeyProtection$Builder", "android.security.keystore.KeyProtection$Builder setUserConfirmationRequired(boolean)", false, true);
		Collection<SootCall> presenceRequiredUsages = runCallAnalysis(filter, "android.security.keystore.KeyProtection$Builder", "android.security.keystore.KeyProtection$Builder setUserPresenceRequired(boolean)", false, true);

	}

	public void runJavaCryptoTests(AndroidCallGraphFilter filter) {
		Collection<SootCall> keyGenUsages1 = runCallAnalysis(filter, "javax.crypto.KeyGenerator", "javax.crypto.KeyGenerator getInstance(java.lang.String)", false, false);
		Collection<SootCall> keyGenUsages2 = runCallAnalysis(filter, "javax.crypto.KeyGenerator", "javax.crypto.KeyGenerator getInstance(java.lang.String,java.lang.String)", false, false);
		Collection<SootCall> keyGenUsages3 = runCallAnalysis(filter, "javax.crypto.KeyGenerator", "javax.crypto.KeyGenerator getInstance(java.lang.String,java.security.Provider)", false, false);

		Collection<SootCall> cipherUsages1 = runCallAnalysis(filter, "javax.crypto.Cipher", "javax.crypto.Cipher getInstance(java.lang.String)", false, false);
		Collection<SootCall> cipherUsages2 = runCallAnalysis(filter, "javax.crypto.Cipher", "javax.crypto.Cipher getInstance(java.lang.String,java.lang.String)", false, false);
		Collection<SootCall> cipherUsages3 = runCallAnalysis(filter, "javax.crypto.Cipher", "javax.crypto.Cipher getInstance(java.lang.String,java.security.Provider)", false, false);

		Collection<SootCall> keyFactoryUsages1 = runCallAnalysis(filter, "javax.crypto.SecretKeyFactory", "javax.crypto.SecretKeyFactory getInstance(java.lang.String)", false, false);
		Collection<SootCall> keyFactoryUsages2 = runCallAnalysis(filter, "javax.crypto.SecretKeyFactory", "javax.crypto.SecretKeyFactory getInstance(java.lang.String,java.lang.String)", false, false);
		Collection<SootCall> keyFactoryUsages3 = runCallAnalysis(filter, "javax.crypto.SecretKeyFactory", "javax.crypto.SecretKeyFactory getInstance(java.lang.String,java.security.Provider)", false, false);
	}

	public void runJavaKeystoreTests(AndroidCallGraphFilter filter) {
		Collection<SootCall> keyPairGenUsages1 = runCallAnalysis(filter, "java.security.KeyPairGenerator", "java.security.KeyPairGenerator getInstance(java.lang.String)", false, false);
		Collection<SootCall> keyPairGenUsages2 = runCallAnalysis(filter, "java.security.KeyPairGenerator", "java.security.KeyPairGenerator getInstance(java.lang.String,java.lang.String)", false, false);
		Collection<SootCall> keyPairGenUsages3 = runCallAnalysis(filter, "java.security.KeyPairGenerator", "java.security.KeyPairGenerator getInstance(java.lang.String,java.security.Provider)", false, false);

		Collection<SootCall> javaUsages1 = runCallAnalysis(filter, "java.security.KeyStore", "java.security.KeyStore getInstance(java.lang.String)", false, false);
		Collection<SootCall> javaUsages2 = runCallAnalysis(filter, "java.security.KeyStore", "java.security.KeyStore getInstance(java.lang.String,java.lang.String)", false, false);
		Collection<SootCall> javaUsages3 = runCallAnalysis(filter, "java.security.KeyStore", "java.security.KeyStore getInstance(java.lang.String,java.security.Provider)", false, false);
		Collection<SootCall> javaUsages4 = runCallAnalysis(filter, "java.security.KeyStore", "java.security.KeyStore getInstance(java.io.File,char[])", false, false);
		Collection<SootCall> javaUsages5 = runCallAnalysis(filter, "java.security.KeyStore", "java.security.KeyStore getInstance(java.io.File,java.security.KeyStore.LoadStoreParameter)", false, false);

		Collection<SootCall> javaUsages6 = runCallAnalysis(filter, "java.security.KeyStore$Builder", "java.security.KeyStore$Builder newInstance(java.lang.String,java.security.Provider,java.security.KeyStore.ProtectionParameter)", false, false);
		Collection<SootCall> javaUsages7 = runCallAnalysis(filter, "java.security.KeyStore$Builder", "java.security.KeyStore$Builder newInstance(java.io.File,java.security.KeyStore.ProtectionParameter)", false, false);
		Collection<SootCall> javaUsages8 = runCallAnalysis(filter, "java.security.KeyStore$Builder", "java.security.KeyStore$Builder newInstance(java.lang.String,java.security.Provider,java.io.File,java.security.KeyStore.ProtectionParameter)", false, false);
		Collection<SootCall> javaUsages9 = runCallAnalysis(filter, "java.security.KeyStore$Builder", "java.security.KeyStore$Builder newInstance(java.security.KeyStore,java.security.KeyStore.ProtectionParameter)", false, false);

		Collection<SootCall> passwordProtectionUsages1 = runCallAnalysis(filter, "java.security.KeyStore$PasswordProtection", "void <init>(char[])", false, false);
		Collection<SootCall> passwordProtectionUsages2 = runCallAnalysis(filter, "java.security.KeyStore$PasswordProtection", "void <init>(char[],java.lang.String,java.security.spec.AlgorithmParameterSpec)", false, false);

		Collection<SootCall> certFactoryUsages1 = runCallAnalysis(filter, "java.security.cert.CertificateFactory", "java.security.cert.CertificateFactory getInstance(java.lang.String)", false, false);
		Collection<SootCall> certFactoryUsages2 = runCallAnalysis(filter, "java.security.cert.CertificateFactory", "java.security.cert.CertificateFactory getInstance(java.lang.String,java.lang.String)", false, false);
		Collection<SootCall> certFactoryUsages3 = runCallAnalysis(filter, "java.security.cert.CertificateFactory", "java.security.cert.CertificateFactory getInstance(java.lang.String,java.security.Provider)", false, false);
	}

	public boolean checkCollection(Collection<SootCall> c) {
		if (c == null || c.isEmpty()) {
			return false;
		}
		return true;
	}

	public Collection<SootCall> runCallAnalysis(AndroidCallGraphFilter filter, String className, String methodName, boolean reachabilityAnalysis, boolean traceCalls) {
		System.out.println("Analyzing: " + className + ": " + methodName);

		Collection<SootCall> usages = analyzeMethodUsage(filter, className, methodName, reachabilityAnalysis, traceCalls);
		if (checkCollection(usages)) {
			writeCallsToFile(className, methodName, usages);
		}

		return usages;
	}

	public static Collection<SootCall> analyzeMethodUsage(AndroidCallGraphFilter filter, String className, String methodName, boolean reachable, boolean traceCalls) {
        // Construct a SootMethod instance for the class/method combination.
        
		SootMethod m = filter.getSootMethod(className, methodName);
		if (m == null) {
			return null;
		}

        SootCall targetMethod = filter.getSootCall(m);
        Collection<SootCall> usages = filter.getAPIUsage(m);

        if (usages == null || usages.isEmpty()) {
            return null;
        }

        for (SootCall c : usages) {
            // System.out.println("Found usage: " + c.toString());

            // Get array of parameters
        	List<Value> args = filter.getInvokeParameters(c.sootUnit);
        	c.setArgs(args);

        	// Check if any of these arguments are registers and not the actual value. If a register, do a slice back to get actual parameter value
        	//List<Value> paramValues = filter.getParameterValues(c, args);
        	//c.setParamValues(paramValues);
        	//System.out.println("Param values:");
        	//System.out.println(paramValues);

        	// Value alias = filter.getInvokeParameter(line.sootUnit, 0);
            // System.out.println("Value of alias: " + alias.toString());

            if (traceCalls) {
        		// Trace calls is where we want to see what methods are called on the same object.
        		// Retrieve the register string of KeyGenParameterSpec$Builder object on which the method is called.
        		Unit u = c.sootUnit;
        		List<ValueBox> useBoxes = u.getUseBoxes();
        		if (useBoxes != null && !useBoxes.isEmpty()) {
        			// Get the first box that's a JimpleLocalBox --- first value can be a LinkedRValueBox
        			for (ValueBox b : useBoxes) {
        				// Get first box that's a register value and a android.security.keystore.KeyGenParameterSpec$Builder type
        				String value = b.getValue().toString();
        				String type = b.getValue().getType().toString();

        				if (value.startsWith("$") && (type == "android.security.keystore.KeyGenParameterSpec$Builder")) {
        					c.setCallObject(value);

        					// Break so that we only get the first register value.
        					break;
        				}
        			}
        			
        		}

        	}

        	// If we want to check for reachability for this method:
        	if (reachable) {
        		System.out.println("Running reachability analysis on: " + c.sootMethod.toString());
        		try {
        			Collection<SootCall> directCallers = filter.getEdgesInto(c);

        			TreeNode<SootCall> root = filter.getPossiblePaths(c, directCallers);
        			writeCallPaths(root);
        			c.reachability = true;
        		} catch (OutOfMemoryError oom) {
        			System.out.println("Out of memory error analyzing reachability.");
        			System.out.println("Used Memory / Max Memory: " + getUsedMemory() + "/" + getMaxMemory());

        			// Break and don't analyze reachability for this API method.
        			reachable = false;
        			
        		}
        	}

        }

        return usages;

    }

	public String getAnalysisFilePath() {
		return "results/az_" + this.sizeCategory + "/call_analysis/" + this.pkgName + "_keystore_calls.csv";
	}

	public static String getReachabilityAnalysisFilePath() {
    	return "results/az_" + sizeCategory + "/call_analysis/" + pkgName + "_keystore_call_paths.csv";
    }

    public void writeCallsToFile(String targetClassStr, String targetMethodStr, Collection<SootCall> calls) {
    	List<String[]> lines = new ArrayList<>();

    	// First, construct the array of call elements we want to write.
    	for (SootCall c : calls) {
    		List<String> lineData = new ArrayList<String>(Arrays.asList(targetClassStr, targetMethodStr, c.sootClass.getPackageName(), c.sootClass.toString(), c.sootMethod.toString(), c.getCallObject(), String.valueOf(c.reachability)));
    		
    		if (c.getArgs() != null) {
    			for (Value v : c.getArgs()) {
    				String paramStr = v.toString().strip().replaceAll("\"", "");
    				lineData.add(paramStr);
    			}
    		}
    		String[] arrStr = lineData.toArray(new String[0]);
    		lines.add(arrStr);
    	}

    	File callFile = new File(getAnalysisFilePath());

    	try {
    		FileWriter outputFile = new FileWriter(callFile, true);
    		CSVWriter writer = new CSVWriter(outputFile);

    		// Second, write lines as new rows to the file.
    		for (String[] lineArr : lines) {
    			writer.writeNext(lineArr);
    		}

    		writer.close();
    	} catch (IOException e) {
    		e.printStackTrace();
    	}

    }

    public static void writePathToFile(SootCall[] path, int pathLength) {
    	File pathsFile = new File(getReachabilityAnalysisFilePath());
    	try {
    		FileWriter outputFile = new FileWriter(pathsFile, true);
    		CSVWriter writer = new CSVWriter(outputFile);

    		String[] pathStr = new String[pathLength];
    		for (int i = 0; i < pathLength; i++) {
    			
    			pathStr[i] = path[i].sootMethod.toString();
    		}

    		writer.writeNext(pathStr);

    		writer.close();
    	} catch (IOException e) {
    		e.printStackTrace();
    	}
    }

    public static void generatePath(TreeNode<SootCall> node, SootCall[] path, int pathLen) {
    	if (node == null) {
    		return;
    	}

    	path[pathLen] = node.getValue();
    	pathLen++;

    	if (node.isLeaf()) {
    		writePathToFile(path, pathLen);
    	} else {
    		for (TreeNode<SootCall> child : node.getChildren()) {
    			generatePath(child, path, pathLen);
    		}
    	}

    }

    public static void writeCallPaths(TreeNode<SootCall> root) {
    	// Can use a maximum size of 500
        SootCall[] path = new SootCall[1000];
        generatePath(root, path, 0);

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

    public void printApkInfo() {
		int numAppClasses = 0;
		int numLibClasses = 0;
		int numMethods = 0;

		for (SootClass c : classes.values()) {
			if (c.isApplicationClass()) {
				numAppClasses += 1;
				numMethods += c.getMethodCount();
			}
			if (c.isLibraryClass()) {
				numLibClasses += 1;
			}
		}

		System.out.println("Number of application classes: " + numAppClasses);
		System.out.println("Number of library classes: " + numLibClasses);
		System.out.println("Number of methods: " + numMethods);
	}

}


