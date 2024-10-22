package analysis_tool;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import soot.Context;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.SootField;
import soot.Body;
import soot.Hierarchy;
import soot.SootMethodRef;
import soot.SootResolver;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.ValueBox;

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
import soot.jimple.toolkits.callgraph.ContextSensitiveEdge;
import soot.jimple.toolkits.callgraph.Targets;
import soot.jimple.toolkits.callgraph.Sources;
import soot.jimple.toolkits.scalar.ConstantPropagatorAndFolder;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.LinkedList;
import java.util.LinkedHashSet;
import java.util.Collection;
import java.util.HashSet;
import java.util.Collection;
import java.util.Iterator;
import java.util.Set;

public class AndroidCallGraphFilter {

    private Map<String, String> extendedActivities = new HashMap<>();

    public HashMap<String, SootClass> classes = new HashMap<String, SootClass>();

    public CallGraph cg;

    public Set<String> filteredMethods = new HashSet<String>();

    // Key is the source node and value is the set of neighbors.
    static Map<String, Set<String>> neighborMap = new HashMap<String, Set<String>>();

    public List<SootClass> getValidClasses() {
        return validClasses;
    }

    public Hierarchy ch;

    private List<SootClass> validClasses = new ArrayList<>();
    private List<SootClass> extendedClasses = new ArrayList<>();

    public HashMap<SootMethod, HashSet<SootCall>> callers_cache = new HashMap<SootMethod, HashSet<SootCall>>();
    public HashMap<SootField, HashSet<Tuple<Unit, SootMethod>>> field_cache = new HashMap<>();
    public HashMap<SootMethod, HashMap<String, Unit>> def_cache = new HashMap<SootMethod, HashMap<String, Unit>>();


    public AndroidCallGraphFilter(HashMap<String, SootClass> apkClasses, CallGraph cg) {
        this.classes = apkClasses;
        this.cg = cg;


        ch = new Hierarchy();

        /*
        for(SootClass sc : apkClasses){
            // cm.put(sc.getName(), sc);
            if(sc.resolvingLevel() == SootClass.HIERARCHY){
                SootResolver.v().reResolve(sc, SootClass.SIGNATURES);
            }
        }
        */

        /*
        for (SootClass sootClass : Scene.v().getApplicationClasses()) {
            if (!sootClass.getName().contains(appPackageName))
                continue;
            if (sootClass.getName().contains(appPackageName + ".R") || sootClass.getName().contains(appPackageName + ".BuildConfig"))
                continue;

            validClasses.add(sootClass);
        }
        */

        // Collect all SootFields into field_cache.
        for (SootClass sc : apkClasses.values()) {
            if (sc.resolvingLevel() == SootClass.BODIES) {
                for (SootMethod sm : sc.getMethods()) {
                    if (sm.hasActiveBody()) {
                        for (Unit u : sm.getActiveBody().getUnits()) {
                            for (ValueBox db : u.getDefBoxes()) {
                                Value vv = db.getValue();
                                try {
                                    FieldRef iff = (FieldRef) vv;
                                    SootField ff = iff.getField();

                                    HashSet<Tuple<Unit, SootMethod>> current_set = field_cache.get(ff);
                                    if (current_set == null) {
                                        current_set = new HashSet<Tuple<Unit, SootMethod>>();
                                        field_cache.put(ff, current_set);
                                    }
                                    current_set.add(new Tuple(u, sm));
                                } catch(ClassCastException e) {
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    public int getCallGraphSize() {
        return cg.size();
    }

    public static boolean isAndroidMethod(SootMethod sootMethod) {
        String className = sootMethod.getDeclaringClass().getName();

        List<String> androidPkgPrefixes = Arrays.asList("android.", "com.google.android", "androidx.");

        // if (name.startsWith("android.") || name.startsWith)

        return androidPkgPrefixes.stream().map(className::startsWith).reduce(false, (res, curr) -> res || curr);
    }

    private boolean isValidMethod(SootMethod sootMethod) {
        if (isAndroidMethod(sootMethod))
            return false;
        if (sootMethod.getDeclaringClass().getPackageName().startsWith("java"))
            return false;
        if (sootMethod.toString().contains("<init>") || sootMethod.toString().contains("<clinit>"))
            return false;
        if (sootMethod.getName().equals("dummyMainMethod"))
            return false;
        return true;
    }

    public boolean isValidEdge(soot.jimple.toolkits.callgraph.Edge sEdge) {
        if (!sEdge.src().getDeclaringClass().isApplicationClass())// || sEdge.tgt().getDeclaringClass().isApplicationClass())
            return false;
        if (!isValidMethod(sEdge.src()) || !isValidMethod(sEdge.tgt()))
            return false;
        boolean flag = validClasses.contains(sEdge.src().getDeclaringClass());
        flag |= validClasses.contains(sEdge.tgt().getDeclaringClass());
        return flag;
    }

    public List<SootClass> getActivityClasses(String appPackageName) {
        for (SootClass sootClass : Scene.v().getApplicationClasses()) {
            if (!sootClass.getName().contains(appPackageName))
                continue;
            if (sootClass.getName().contains(appPackageName + ".R") || sootClass.getName().contains(appPackageName + ".BuildConfig"))
                continue;
            if (sootClass.hasSuperclass()) {

                if (sootClass.getSuperclassUnsafe().toString().contains("android.app.Activity") ||
                        sootClass.getSuperclassUnsafe().toString().contains("BaseActivity")) {
                    extendedClasses.add(sootClass);
                }
            }

        }
        return extendedClasses;
    }


    public Map<String, String> getExtendedActivities(String appPackageName) {
        List<String> temp = new ArrayList<>();
        for (SootClass sootClass : Scene.v().getApplicationClasses()) {
            if (!sootClass.getName().contains(appPackageName))
                continue;
            if (sootClass.getName().contains(appPackageName + ".R") || sootClass.getName().contains(appPackageName + ".BuildConfig"))
                continue;
            if (sootClass.hasSuperclass()) {

                if (sootClass.getSuperclassUnsafe().toString().contains("android.app.Activity") ||
                        sootClass.getSuperclassUnsafe().toString().contains("BaseActivity")) {
                    temp.add(sootClass.toString());

                }
            }

        }
        for (SootClass sootClass : Scene.v().getApplicationClasses()) {
            if (!sootClass.getName().contains(appPackageName))
                continue;
            if (sootClass.getName().contains(appPackageName + ".R") || sootClass.getName().contains(appPackageName + ".BuildConfig"))
                continue;
            if (sootClass.hasSuperclass()) {
                for (String string : temp) {
                    if (string.equals(sootClass.getSuperclassUnsafe().toString())) {

                        extendedActivities.put(sootClass.toString(), sootClass.getSuperclassUnsafe().toString());

                    }
                }
            }
        }
        return extendedActivities;
    }

    public SootMethod getSootMethod(String className, String methodName) {
        SootClass sootClass = this.classes.get(className);

        //System.out.println();
        //System.out.println(sootClass.getMethods());
        //System.out.println();

        if (sootClass != null) {
            if (sootClass.resolvingLevel() != SootClass.BODIES) {
                SootResolver.v().reResolve(sootClass, SootClass.BODIES);
            }
            for (SootMethod sm : sootClass.getMethods()) {
                if (sm.getSubSignature().startsWith(methodName)) {

                    //System.out.println("Method subsignature:");
                    //System.out.println(sm.getSubSignature());

                    // System.out.println("Found equal method.");
                    return sm;
                }
            }
        }
        return null;
    }

    public SootCall getSootCall(SootMethod method) {
        return new SootCall(method, null, null);
    }

    public List<Unit> getUnitsInMethod(String className, String methodName) {
        List<Unit> units = new LinkedList<Unit>();

        SootClass sootClass = this.classes.get(className);
        if (sootClass != null) {
            if (sootClass.resolvingLevel() != SootClass.BODIES) {
                SootResolver.v().reResolve(sootClass, SootClass.BODIES);
            }
            for (SootMethod sm : sootClass.getMethods()) {
                if (sm.getSubSignature().startsWith(methodName)) {
                    System.out.println(sm);
                    System.out.println();

                    if (sm.hasActiveBody()) {
                        Body b = sm.getActiveBody();

                        System.out.println(b);
                        System.out.println();
                        for (Unit u : b.getUnits()) {
                            System.out.println();
                            System.out.println(u);
                            units.add(u);
                        }
                    }
                }
            }
        }

        return units;
    }

    public HashSet<SootCall> getEdgesInto(SootCall call) {
        // Use Set to get rid of duplicates. We don't care if there are multiple edges between two methods.
        Set<SootMethod> callers = new HashSet<SootMethod>();

        SootMethod method = call.sootMethod;

        for (Iterator<Edge> it = cg.edgesInto(method); it.hasNext();) {
            Edge edge = it.next();

            SootMethod sourceMethod = edge.src();

            //System.out.println(sourceMethod.toString() + "->" + method.toString());
            callers.add(sourceMethod);
        }

        // Construct a set of SootCall and return
        HashSet<SootCall> sootCallers = new HashSet<SootCall>();
        for (SootMethod m : callers) {
            SootCall c = new SootCall(m, null, null);
            sootCallers.add(c);
        }

        return sootCallers;
    }

    public Collection<SootCall> getEdgesInto(SootMethod method) {
        // Use Set to get rid of duplicates. We don't care if there are multiple edges between two methods.
        Set<SootMethod> callers = new HashSet<SootMethod>();

        for (Iterator<Edge> it = cg.edgesInto(method); it.hasNext();) {
            Edge edge = it.next();

            SootMethod sourceMethod = edge.src();

            //System.out.println(sourceMethod.toString() + "->" + method.toString());
            callers.add(sourceMethod);
        }

        // Construct a set of SootCall and return
        HashSet<SootCall> sootCallers = new HashSet<SootCall>();
        for (SootMethod m : callers) {
            SootCall c = new SootCall(m, null, null);
            sootCallers.add(c);
        }

        return sootCallers;
    }

    public List<SootMethod> getCallees(InvokeExpr ie, SootMethod container){
        SootMethod called = (SootMethod) ie.getMethodRef().resolve();
        
        if((ie instanceof JVirtualInvokeExpr) || (ie instanceof JInterfaceInvokeExpr)){
            SootClass target = ie.getMethodRef().declaringClass();
            List<SootMethod> tt;
            try{
                tt = ch.resolveAbstractDispatch(target, called);
            }catch(RuntimeException e){
                tt = new LinkedList<SootMethod>();
            }
            
            if(tt.size() == 0 && !target.isInterface()){
                tt = new LinkedList<SootMethod>();
                try{
                    SootMethod resm = ch.resolveConcreteDispatch(target, called);
                    tt.add(resm);
                }catch(RuntimeException e){
                    ;
                }
            }
            
            return tt;
        }else if(ie instanceof JStaticInvokeExpr){
            SootClass target = ie.getMethodRef().declaringClass();
            SootMethod resm = ch.resolveConcreteDispatch(target, called);
            List<SootMethod> res = new LinkedList<SootMethod>();
            res.add(resm);
            return res;
        }else if(ie instanceof JSpecialInvokeExpr){
            SootMethod resm = ch.resolveSpecialDispatch((JSpecialInvokeExpr)ie, container);
            List<SootMethod> res = new ArrayList<SootMethod>();
            res.add(resm);
            return res;
        }
        
        return null;
    }
    
    public Collection<SootMethod> getCallees(SootMethod m){
        HashSet<SootMethod> res = new LinkedHashSet<SootMethod>();
        List<InvokeExpr> iel = getInvokes(m);
        for(InvokeExpr ie : iel){
            res.addAll(getCallees(ie, m));
        }
        return res;
    }

    public Collection<Tuple<Unit, SootMethod>> getCalleesWithUnit(SootMethod m){
        HashSet<Tuple<Unit, SootMethod>> res = new LinkedHashSet<>();
        List<Tuple<Unit, InvokeExpr>> u_ieList = getInvokesWithUnit(m);
        for(Tuple<Unit, InvokeExpr> u_ie : u_ieList){
            for(SootMethod calledMethod : getCallees(u_ie.y, m)){
                res.add(new Tuple<Unit, SootMethod>(u_ie.x, calledMethod));
            }
        }
        return res;
    }

    // Safer to iterate over all expressions instead of getting edges into in case the call graph
    // missed an edge (e.g., with callbacks);
    public Collection<SootCall> getCallers(SootMethod method) {
        HashSet<String> seenMethods = new HashSet<String>();

        // Check if we've already calculated callers for this method:
        HashSet<SootCall> callers = callers_cache.get(method);
        if (callers != null) {
            return callers;
        } else {
            callers = new HashSet<SootCall>();
            callers_cache.put(method, callers);
        }

        for (SootClass sc : classes.values()) {
            if (sc.isApplicationClass()) {

                // Is this needed?
                List<SootMethod> copiedMethods = new LinkedList<SootMethod>();
                for (SootMethod sm : sc.getMethods()) {
                    copiedMethods.add(sm);
                }

                for (SootMethod sm : copiedMethods) {
                    if (sm.hasActiveBody()) {
                        Body b = sm.getActiveBody();
                        for (Unit u : b.getUnits()) {
                            // Check if Unit contains an expression?
                            InvokeExpr ie = getInvokeExpr(u);
                            if (ie != null) {
                                // Checking if the library method we're searching for is contained in the expression
                                if (ie.getMethod().getSignature().equals(method.getSignature())) {
                                    // Run constant propagator for method we're currently in.
                                    ConstantPropagatorAndFolder.v().transform(b);

                                    
                                    String sig = sm.getSignature();
                                    if (!seenMethods.contains(sig)) {
                                        SootCall call = new SootCall(sm, u, ie);
                                        callers.add(call);
                                        seenMethods.add(sig);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        return callers;
    }

    // For performance reasons, use call graph when analyzing reachability.
    // Make different getCallers for using the call graph and taking in a SootCall

    // Runs a backwards BFS to trace call history and stores all methods located on a Keystore call path.
    /*
    public HashMap<String, Set<String>> getPossiblePathsOld(SootMethod targetMethod) {
        List<SootMethod> queue = new ArrayList<>(Arrays.asList(targetMethod));
        queue.add(targetMethod);

        HashMap<String, Set<String>> keystorePaths = new HashMap<String, Set<String>>();

        for (int i = 0; i < queue.size(); i++) {
            SootMethod method = queue.get(i);
            Set<SootMethod> sources = getEdgesInto(method);

            // If method has incoming edges:
            if ((sources != null) && (!sources.isEmpty())) {
                System.out.println('\n');

                System.out.println("Method:");
                System.out.println(method);

                // Add to queue to later calculate incoming edges at the next depth level.
                for (SootMethod m : sources) {
                    queue.add(m);
                }

                // Add source methods to overall path map.
                for (SootMethod sourceMethod : sources) {
                    String pkgName = sourceMethod.getDeclaringClass().getPackageName();
                    String signature = sourceMethod.getSignature();

                    if (keystorePaths.containsKey(pkgName)) {
                        Set<String> methodsCalled = keystorePaths.get(pkgName);
                        methodsCalled.add(signature);
                    } else {
                        Set<String> methodsCalled = new HashSet<String>();
                        methodsCalled.add(signature);
                        keystorePaths.put(pkgName, methodsCalled);
                    }
                }
            }

        }

        System.out.println(keystorePaths);

        System.out.println("Total number of packages:");
        System.out.println(keystorePaths.size());

        return keystorePaths;

    }
    */

    public Collection<SootCall> getAPIUsage(SootMethod targetMethod) {
        // HashMap<String, Set<String>> keystorePaths = getPossiblePaths(targetMethod);
        //Set<SootMethod> directCallers = getEdgesInto(targetMethod);

        if (targetMethod != null) {
            Collection<SootCall> callers = getCallers(targetMethod);
            return callers;
        } else {
            System.out.println("Method is null.");
        }

        return null;
    }

    public TreeNode<SootCall> initCallTree(SootCall root, Collection<SootCall> directCallers) {
        // Set startMethod as root.
        TreeNode<SootCall> rootNode = new TreeNode<SootCall>(root, null);

        // Add direct callers as children of root.
        for (SootCall call : directCallers) {
            //System.out.println("Adding child: ");
            //System.out.println(call.sootMethod.getSignature());
            rootNode.addChild(call);
        }

        return rootNode;
    }

    public TreeNode<SootCall> getPossiblePaths(SootCall targetMethod, Collection<SootCall> directCallers) {
        // Initialize tree with startMethod and direct callers.
        TreeNode<SootCall> root = initCallTree(targetMethod, directCallers);

        // Add children of root to queue to start with.
        LinkedList<TreeNode<SootCall>> queue = new LinkedList<TreeNode<SootCall>>(root.getChildren());

        // int numUniqueNodes = queue.size() + 1;
        int numTotalNodes = queue.size() + 1;

        // Scenario where the number of children are greater than the fixed number of unique nodes
        int nodeThreshold = 1000;
        if (numTotalNodes > nodeThreshold) {
            nodeThreshold = numTotalNodes;
        }
        while ((queue.size() > 0) && (numTotalNodes <= nodeThreshold)) {
            TreeNode<SootCall> callNode = queue.poll();
            SootCall call = callNode.getValue();

            // Check if we've already seen this method.
            SootMethod method = call.sootMethod;
            HashSet<SootCall> callers = callers_cache.get(method);
            if (callers == null) {
                callers = getEdgesInto(call);
                callers_cache.put(method, callers);

                // Only increment node number if it's a method we haven't seen before.
                //numUniqueNodes++;
            }

            for (SootCall c : callers) {
                TreeNode<SootCall> child = callNode.addChild(c);
                numTotalNodes++;

                if (child != null) {
                    queue.add(child);
                }
            }

        }

        // Handle scenario where children are greater than number of unique nodes

        return root;
    }



    /*
    // Internal testing method
    public void printCallTree(TreeNode<SootCall> root) {
        // Root of the tree is <v6.a: javax.crypto.SecretKey d()>.
        // First child at level 0 is <v6.a: v6.a$a b(java.lang.String)>.

        List<TreeNode<SootCall>> queue = root.getChildren();

        for (int level = 0; level < 7; level++) {
            System.out.println("--------------------------------------------------------------------------------");
            System.out.println("Level : " + String.valueOf(level));
            System.out.println("Number of nodes at level: " + String.valueOf(queue.size()));
            System.out.println();

            List<TreeNode<SootCall>> childQueue = new ArrayList<TreeNode<SootCall>>();
            
            // Print out all current children.
            for(TreeNode<SootCall> e : queue) {
                // Print out curent child.
                //System.out.println(e.getValue().sootMethod.getSignature());

                List<TreeNode<SootCall>> children = e.getChildren();
                //System.out.println("Number of children: " + children.size());
                //System.out.println("Children:");
                //System.out.println(children);

                if (children != null) {
                    childQueue.addAll(children);
                }
            }
            
            queue.clear();
            queue.addAll(childQueue);

        }
    }
    */

    public InvokeExpr getInvokeExpr(Unit u) {
        Stmt ss = null;
        InvokeExpr ex = null;
        try {
            ss = (Stmt)u;
        } catch (ClassCastException e) {
            return null;
        }
        try {
            ex = ss.getInvokeExpr();
        } catch (RuntimeException e) {
            return null;
        }
        return ex;
    }

    public int iterateGraph() {
        int numEdges = 0;
        for (Iterator<Edge> edgeIt = cg.iterator(); edgeIt.hasNext(); ) {
            numEdges++;
            Edge edge = edgeIt.next();

            // THe method in which the call occurs (can be null for calls not occurring in a specific
            // method (e.g., implicit calls by the VM).
            SootMethod smSrc = edge.src(); // .toString()
            Unit uSrc = edge.srcStmt();
            // The target method
            SootMethod smDest = edge.tgt();

            Context c = edge.srcCtxt();

            System.out.println("Edge from " + uSrc + " in " + smSrc + " to " + smDest);
            System.out.println("Context: " + c);
            System.out.println("--------------------------------");
        }
        return numEdges;
    }

    public static void getNeighbors(Edge e) {
        String srcNode = e.getSrc().toString();
        String destNode = e.getTgt().toString();

        Set<String> localNeighbors;
        if (neighborMap.containsKey(srcNode)) {
            localNeighbors = neighborMap.get(srcNode);
        } else {
            localNeighbors = new HashSet<String>();
        }
        localNeighbors.add(destNode);
        neighborMap.put(srcNode, localNeighbors);
    }


    public Value getInvokeParameter(Unit u, int argIndex) {
        // 0 is the first argument, not "this"
        return getInvokeExpr(u).getArgs().get(argIndex);
    }

    public List<Value> getInvokeParameters(Unit u) {
        if (u != null) {
            return getInvokeExpr(u).getArgs();
        }
        return null;
    }

    public List<Value> getParameterValues(SootCall c, List<Value> args) {
        //System.out.println("Values: ");
        //System.out.println(args);
        
        List<Value> paramValues = new ArrayList<Value>();
        
        for (Value p : args) {
            String pStr = p.toString();

            System.out.println(p.getType().toString());

            // Check if parameter is register value.
            if (pStr.startsWith("$")) {
                //System.out.println("Flagged as register value.");

                Slicer s = new Slicer(this, c, pStr);
                s.followMethodParams = true;
                s.followReturns = true;
                s.followFields = true;
                
                //System.out.println("Running slicer.");
                Tree<SlicerState> t = s.run(100);

                //System.out.println();
                //System.out.println(String.valueOf(t));
                //System.out.println();

                //System.out.println("Analyzing leaves.");
                SlicerState leaf = null;
                for (SlicerState ss : t.getLeaves()) {
                    //System.out.println("Leaf:");
                    //System.out.println(ss);

                    if (ss != null) {
                        //System.out.println("Leaf is not null.");
                        leaf = ss;

                        List<ValueBox> boxes = leaf.unit.getUseBoxes();

                        for (ValueBox b : boxes) {
                            Value v = b.getValue();
                            paramValues.add(v);
                            //System.out.println(v);
                        }

                    }
                    
                    /*
                    if(!String.valueOf(ss.reg).equals("return")) {
                        if (leaf != null) {
                            break;
                        } else {
                            leaf = ss;
                        }
                    }
                    */
                }

                //isEncryptingConstant = isSliceToConstant(stree);


                //for (SlicerState ss : t.getLeaves()) {
                //}
            } else {
                paramValues.add(p);
            }
        }

        return paramValues;
    }

    public List<InvokeExpr> getInvokes(SootMethod sm) {
        List<InvokeExpr> res = new ArrayList<InvokeExpr>();
        if (sm.hasActiveBody()) {
            Body b = sm.getActiveBody();
            for (Unit u : b.getUnits()) {
                InvokeExpr ie = getInvokeExpr(u);
                if (ie != null) {
                    res.add(ie);
                }
            }
        }
        return res;
    }

    public List<Tuple<Unit, InvokeExpr>> getInvokesWithUnit(SootMethod m){
        List<Tuple<Unit, InvokeExpr>> res = new ArrayList<Tuple<Unit, InvokeExpr>>();
        if(m.hasActiveBody()){
            Body bb = m.getActiveBody();
            for(Unit uu : bb.getUnits()){
                InvokeExpr ie = getInvokeExpr(uu);
                if(ie!=null){
                    res.add(new Tuple<Unit, InvokeExpr>(uu, ie));
                }
            }
        }
        return res;
    }

    public boolean isNewAssignment(Unit u) {
        System.out.println("Running isNewAssignment");
        String newType = null;
        try {
            newType = (((JNewExpr) ((JAssignStmt)u).getRightOp()).getBaseType().toString());
        } catch (ClassCastException | NullPointerException e) {
            System.out.println(e);
        }
        boolean res = newType != null;
        return res;
    }

    // skipNews is typically true
    // boolean skipNews
    public Unit getDefUnit(String reg, SootMethod containerMethod) {
        HashMap<String, Unit> defMap = def_cache.get(containerMethod);
        if (defMap == null) {
            defMap = new HashMap<String, Unit>();
            Body b = containerMethod.getActiveBody();
            for (Unit u : b.getUnits()) {
                for (ValueBox df : u.getDefBoxes()) {
                    String cname = df.getClass().getSimpleName();
                    if (cname.equals("LinkedVariableBox") || cname.equals("JimpleLocalBox")) {
                        // If it is reg = new, we don't want it.
                        //boolean isNewAssignment = isNewAssignment(u);
                        // Instead, we look for the constructor.
                        //if (isNewAssignment && skipNews) {
                        Unit uReal = null;
                        for (Unit u2 :  b.getUnits()) {
                            InvokeExpr ie = getInvokeExpr(u2);
                            if (ie != null) {
                                if (ie instanceof InstanceInvokeExpr) {
                                    String nreg = ((InstanceInvokeExpr) ie).getBase().toString();
                                    if (nreg.equals(df.getValue().toString()) && ie.getMethod().getSubSignature().startsWith("void <init>")) {
                                        uReal = u2;
                                    }
                                }
                            }
                        }
                        if (uReal != null) {
                            defMap.put(df.getValue().toString(), uReal);
                            break; // there should not be more than one of type LinkedVariableBox because of SSA
                        }
                        //}
                        defMap.put(df.getValue().toString(), u);
                        break; // there should not be more than one of type LinkedVariableBox because of SSA
                    }
                }
            }
            def_cache.put(containerMethod, defMap);

        }
        Unit res = defMap.get(reg);
        return res;
    }

    public SootField getFieldAccess(Unit u) {
        for (ValueBox vb : u.getUseBoxes()) {
            try {
                Value v = vb.getValue();
                FieldRef iff = (FieldRef) v;
                SootField ff = iff.getField();
                return ff;
            } catch (ClassCastException e) {
                System.out.println(e);
            }
        }
        return null;
    }

    public SootField getFieldAccess(ValueBox vb) {
        try {
            Value v = vb.getValue();
            FieldRef iff = (FieldRef) v;
            SootField ff = iff.getField();
            return ff;
        } catch (ClassCastException e) {
            System.out.println(e);
        }
        return null;
    }

}