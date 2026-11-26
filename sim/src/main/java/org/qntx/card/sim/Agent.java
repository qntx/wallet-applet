// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import java.lang.classfile.ClassBuilder;
import java.lang.classfile.ClassElement;
import java.lang.classfile.ClassFile;
import java.lang.classfile.ClassHierarchyResolver;
import java.lang.classfile.ClassModel;
import java.lang.classfile.CodeBuilder;
import java.lang.classfile.CodeElement;
import java.lang.classfile.CodeTransform;
import java.lang.classfile.Label;
import java.lang.classfile.MethodModel;
import java.lang.classfile.MethodTransform;
import java.lang.classfile.Opcode;
import java.lang.classfile.TypeKind;
import java.lang.classfile.instruction.ArrayLoadInstruction;
import java.lang.classfile.instruction.ArrayStoreInstruction;
import java.lang.classfile.instruction.BranchInstruction;
import java.lang.classfile.instruction.ConstantInstruction;
import java.lang.classfile.instruction.ExceptionCatch;
import java.lang.classfile.instruction.FieldInstruction;
import java.lang.classfile.instruction.IncrementInstruction;
import java.lang.classfile.instruction.InvokeInstruction;
import java.lang.classfile.instruction.LoadInstruction;
import java.lang.classfile.instruction.LocalVariable;
import java.lang.classfile.instruction.LocalVariableType;
import java.lang.classfile.instruction.NewMultiArrayInstruction;
import java.lang.classfile.instruction.NewPrimitiveArrayInstruction;
import java.lang.classfile.instruction.NewReferenceArrayInstruction;
import java.lang.classfile.instruction.OperatorInstruction;
import java.lang.classfile.instruction.StoreInstruction;
import java.lang.classfile.instruction.SwitchCase;
import java.lang.constant.ClassDesc;
import java.lang.constant.MethodTypeDesc;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Java agent that weaves persistent-memory hooks into applet bytecode (architecture spec section 8,
 * patch 5). It runs on {@code -javaagent} with a semicolon-separated list of instrumented package
 * names, e.g. {@code -javaagent:sim-agent.jar=org/qntx/card/sim/probe}. A comma would survive
 * everywhere except the PIT launcher, which serializes JVM args comma-separated and splits a
 * literal one back out as a bogus class name.
 *
 * <p>Per instrumented class it registers fresh arrays with {@link Nvm#trackArray} so only
 * applet-allocated arrays count as persistent targets, replaces {@code bastore}/{@code sastore},
 * rewrites {@code Util.arrayCopy*}/{@code setShort}, {@code JCSystem.makeTransient*}, factory
 * {@code getInstance} calls and {@code KeyBuilder.buildKey*} through {@link Nvm}/{@link Memory},
 * and prepends a {@link Nvm#rethrowPowerLoss} stub to every exception handler so a {@link
 * PowerLoss} skips handler bodies entirely. Every call an instrumented class makes to an
 * instrumented method returning {@code short} is routed through {@link Fault#ret} so a test can arm
 * a chosen call to return a fault value or throw (architecture spec section 9).
 *
 * <p>When the agent argument contains the token {@code sites} (alongside the package names), every
 * conditional branch and every invoke instruction of an instrumented method — {@code <init>} and
 * {@code <clinit>} excluded — is additionally guarded by {@link Fault#site}: the woven lookup
 * switch runs the instruction normally, skips it (operands and receiver popped, the zero value of
 * the return type pushed), forces the branch taken or falls through, runs the negated branch, or —
 * for an invoke returning {@code short}/{@code byte}/{@code boolean} — pushes an armed value. Site
 * keys are {@code "Class.method#b<k>"} for the k-th branch and {@code "Class.method#i<k>}" for the
 * k-th invoke of the original method body in bytecode order; an overloaded method name gets a
 * {@code #d<hash>} descriptor suffix so keys stay unique. The guard's fast path while nothing is
 * armed or counted is one volatile read.
 *
 * <p>An {@code dsa=<Class|Class.method>}-list token (entries joined by {@code |}) additionally
 * weaves the data/store/arithmetic sites of architecture §6 into just those methods: every
 * int-category load (local, array element, int constant, field) passes through {@link Fault#data} —
 * {@code "…#d<k>"} sites, faulted to ZERO/ONES/FLIP — and every local store, {@code iinc}, {@code
 * bastore}/{@code sastore}/{@code castore} and int arithmetic instruction is guarded — {@code
 * "…#s<k>"} and {@code "…#a<k>"} sites that skip the store or keep the left operand. {@link
 * #siteKinds()} reports each woven site's kind and, for invokes, its return type.
 */
public final class Agent {

    private static final ClassDesc NVM = ClassDesc.of("org.qntx.card.sim.Nvm");
    private static final ClassDesc MEMORY = ClassDesc.of("org.qntx.card.sim.Memory");
    private static final ClassDesc FAULT = ClassDesc.of("org.qntx.card.sim.Fault");

    private static volatile boolean installed;
    private static volatile boolean sites;

    /** The kind and invoke return type of every woven site: key → {@code b|d|s|a|i<ret>}. */
    private static final Map<String, String> siteKinds = new HashMap<>();

    private Agent() {}

    public static void premain(String args, Instrumentation inst) {
        // no -javaagent argument: instrument the applet package
        if (args == null || args.isEmpty()) {
            args = "org/qntx/card";
        }
        Set<String> dsa = new HashSet<>();
        Set<String> packages = new HashSet<>();
        for (String token : args.split(";")) {
            if (token.startsWith("dsa=")) {
                // the D/S/A gate set of architecture §6: `Class` or `Class.method`
                // entries joined by `|` (a comma would split under the PIT launcher)
                dsa.addAll(Arrays.asList(token.substring(4).split("\\|")));
            } else {
                packages.add(token);
            }
        }
        sites = packages.remove("sites");
        inst.addTransformer(new AppletTransformer(packages, sites, dsa));
        installed = true;
    }

    /**
     * {@code Launcher-Agent-Class} entry of {@code card-sim.jar}: identical to {@link #premain},
     * which defaults to the applet package when the JVM passes no arguments.
     */
    public static void agentmain(String args, Instrumentation inst) {
        premain(args, inst);
    }

    /** True once {@link #premain} ran; {@link Card} refuses to work without it. */
    public static boolean installed() {
        return installed;
    }

    /**
     * True when the agent runs with the {@code sites} argument: the {@link Fault#site} guards
     * exist. Tests that need them assume this and skip otherwise.
     */
    public static boolean siteWeaving() {
        return sites;
    }

    /**
     * The kinds of all woven instruction sites: {@code "b"} branch, {@code "i"} invoke (followed by
     * the return descriptor char, e.g. {@code "iS"}), {@code "d"} data load, {@code "s"} store,
     * {@code "a"} arithmetic — keyed like {@link Fault#armSite}.
     */
    public static Map<String, String> siteKinds() {
        return siteKinds;
    }

    static final class AppletTransformer implements ClassFileTransformer {

        private final Set<String> packages;
        private final boolean sites;
        private final Set<String> dsa;

        AppletTransformer(Set<String> packages, boolean sites, Set<String> dsa) {
            this.packages = packages;
            this.sites = sites;
            this.dsa = dsa;
        }

        @Override
        public byte[] transform(
                ClassLoader loader,
                String className,
                Class<?> classBeingRedefined,
                ProtectionDomain protectionDomain,
                byte[] classfileBuffer) {
            if (className == null) {
                return null;
            }
            int slash = className.lastIndexOf('/');
            if (slash < 0 || !packages.contains(className.substring(0, slash))) {
                return null;
            }
            try {
                // defaultResolver() reads the system class path, which does
                // not contain the javacard supertypes; resolve hierarchy
                // questions through the defining loader instead so stack
                // maps can be recomputed.
                ClassHierarchyResolver resolver =
                        ClassHierarchyResolver.ofResourceParsing(loader)
                                .orElse(ClassHierarchyResolver.defaultResolver());
                ClassFile cf =
                        ClassFile.of(
                                ClassFile.StackMapsOption.GENERATE_STACK_MAPS,
                                ClassFile.ClassHierarchyResolverOption.of(resolver));
                ClassModel model = cf.parse(classfileBuffer);
                // overloaded names get a descriptor-hash suffix so their site keys stay unique
                Map<String, Integer> nameCounts = new HashMap<>();
                for (MethodModel m : model.methods()) {
                    nameCounts.merge(m.methodName().stringValue(), 1, Integer::sum);
                }
                String simple = className.substring(className.lastIndexOf('/') + 1);
                return cf.transformClass(
                        model,
                        // <clinit> stays unwoven: the constants it fills are CAP-loaded
                        // bytes, not runtime persistent writes — charging them would fake
                        // the install journal (architecture §8 patch 2)
                        (ClassBuilder builder, ClassElement element) -> {
                            if (!(element instanceof MethodModel m)
                                    || "<clinit>".equals(m.methodName().stringValue())) {
                                builder.with(element);
                                return;
                            }
                            // retransformation (PIT's coverage weaver re-runs every
                            // transformer on the already woven bytes) would wrap each
                            // guarded call a second time and shift every site index;
                            // a method is already woven exactly when it calls the sim
                            // package, which applet code never does on its own
                            if (woven(m)) {
                                builder.with(element);
                                return;
                            }
                            String name = m.methodName().stringValue();
                            String prefix =
                                    simple
                                            + "."
                                            + name
                                            + (nameCounts.getOrDefault(name, 0) > 1
                                                    ? "#d"
                                                            + Integer.toHexString(
                                                                    m.methodType()
                                                                            .stringValue()
                                                                            .hashCode())
                                                    : "");
                            boolean gate =
                                    !dsa.isEmpty()
                                            && (dsa.contains(simple)
                                                    || dsa.contains(simple + "." + name));
                            builder.transformMethod(
                                    m,
                                    MethodTransform.transformingCode(
                                            new HookTransform(
                                                    packages,
                                                    sites && !"<init>".equals(name),
                                                    gate,
                                                    prefix)));
                        });
            } catch (RuntimeException e) {
                throw new IllegalStateException("sim agent failed to transform " + className, e);
            }
        }
    }

    /**
     * A method is already woven once it calls the guards the weaver emits; probes legitimately
     * call {@code Memory}/{@code Nvm} themselves, and the instruction-replacing rewrites
     * ({@code bastore} to {@code Nvm.sastore}) cannot fire twice anyway — only the guards
     * appended beside an invoke are re-wrappable on retransformation.
     */
    private static final Set<String> WOVEN = Set.of("site", "ret", "skip", "data", "forced");

    private static boolean woven(MethodModel m) {
        return m.code()
                .map(
                        code ->
                                code.elementList().stream()
                                        .anyMatch(
                                                el ->
                                                        el
                                                                        instanceof
                                                                        InvokeInstruction inv
                                                                && inv.method()
                                                                        .owner()
                                                                        .name()
                                                                        .stringValue()
                                                                        .equals(
                                                                                "org/qntx/card/sim/Fault")
                                                                && WOVEN.contains(
                                                                        inv.method()
                                                                                .name()
                                                                                .stringValue())))
                .orElse(false);
    }

    private static final class HookTransform implements CodeTransform {

        private final Set<String> packages;
        private final boolean weaveSites;
        private final boolean weaveDsa;
        private final String keyPrefix;
        private int branchIndex;
        private int invokeIndex;
        private int dataIndex;
        private int storeIndex;
        private int arithIndex;
        private List<AbstractMap.SimpleEntry<Label, Label>> stubs;

        HookTransform(Set<String> packages) {
            this(packages, false, false, "");
        }

        HookTransform(
                Set<String> packages, boolean weaveSites, boolean weaveDsa, String keyPrefix) {
            this.packages = packages;
            this.weaveSites = weaveSites;
            this.weaveDsa = weaveDsa;
            this.keyPrefix = keyPrefix;
        }

        @Override
        public void atStart(CodeBuilder builder) {
            stubs = new ArrayList<>();
        }

        @Override
        public void accept(CodeBuilder builder, CodeElement element) {
            switch (element) {
                case ArrayStoreInstruction store -> rewriteArrayStore(builder, store);
                case ArrayLoadInstruction load -> weaveData(builder, load);
                case ConstantInstruction c -> weaveData(builder, c);
                case StoreInstruction store -> weaveStore(builder, store);
                case IncrementInstruction inc -> weaveStore(builder, inc);
                case OperatorInstruction op -> weaveArith(builder, op);
                case LoadInstruction load -> weaveData(builder, load);
                case FieldInstruction field -> rewriteFieldStore(builder, field);
                case BranchInstruction branch -> weaveBranch(builder, branch);
                case InvokeInstruction invoke -> weaveInvoke(builder, invoke);
                case NewPrimitiveArrayInstruction create -> trackNewArray(builder, create);
                case NewReferenceArrayInstruction create -> trackNewArray(builder, create);
                case NewMultiArrayInstruction create -> trackNewArray(builder, create);
                case ExceptionCatch handler -> redirectHandler(builder, handler);
                // PIT redefines these woven classes during mutation testing; a mutant whose
                // conditional becomes unconditional leaves a dead tail, so the recomputed
                // max_locals shrinks below the slots the local variable table still names
                // and the JVM refuses the redefinition (ClassFormatError)
                case LocalVariable var -> {}
                case LocalVariableType var -> {}
                default -> builder.with(element);
            }
        }

        @Override
        public void atEnd(CodeBuilder builder) {
            for (AbstractMap.SimpleEntry<Label, Label> stub : stubs) {
                builder.labelBinding(stub.getKey());
                builder.dup();
                builder.invokestatic(
                        NVM,
                        "rethrowPowerLoss",
                        MethodTypeDesc.ofDescriptor("(Ljava/lang/Throwable;)V"));
                builder.goto_(stub.getValue());
            }
            stubs = null;
        }

        /**
         * A byte/short/char array element store — routed through {@link Nvm} for persistent arrays
         * — is wrapped in a {@code #s} store site (architecture §6) so the logical store can be
         * skipped: the guard pops arrayref, index and value and the {@link Nvm} call never runs.
         */
        private void rewriteArrayStore(CodeBuilder builder, ArrayStoreInstruction store) {
            boolean site = weaveDsa && STORES.contains(store.opcode());
            Label normal = site ? builder.newLabel() : null;
            Label skip = site ? builder.newLabel() : null;
            Label end = site ? builder.newLabel() : null;
            if (site) {
                String key = keyPrefix + "#s" + (++storeIndex);
                siteKinds.put(key, "s");
                builder.ldc(key);
                builder.invokestatic(
                        FAULT, "site", MethodTypeDesc.ofDescriptor("(Ljava/lang/String;)I"));
                builder.lookupswitch(normal, List.of(SwitchCase.of(1, skip)));
                builder.labelBinding(normal);
            }
            if (store.opcode() == Opcode.BASTORE) {
                builder.invokestatic(
                        NVM, "bastore", MethodTypeDesc.ofDescriptor("(Ljava/lang/Object;II)V"));
            } else if (store.opcode() == Opcode.SASTORE) {
                builder.invokestatic(NVM, "sastore", MethodTypeDesc.ofDescriptor("([SII)V"));
            } else {
                builder.with(store);
            }
            if (site) {
                builder.goto_(end);
                builder.labelBinding(skip);
                builder.pop();
                builder.pop();
                builder.pop();
                builder.labelBinding(end);
            }
        }

        private void trackNewArray(CodeBuilder builder, CodeElement create) {
            builder.with(create);
            builder.dup();
            builder.invokestatic(
                    NVM, "trackArray", MethodTypeDesc.ofDescriptor("(Ljava/lang/Object;)V"));
        }

        private void rewriteFieldStore(CodeBuilder builder, FieldInstruction field) {
            if (field.opcode() == Opcode.PUTFIELD || field.opcode() == Opcode.PUTSTATIC) {
                builder.invokestatic(NVM, "field", MethodTypeDesc.ofDescriptor("()V"));
            }
            builder.with(field);
            // a getfield/getstatic of an int-category field is a data site like any other load
            if (!weaveDsa
                    || (field.opcode() != Opcode.GETFIELD && field.opcode() != Opcode.GETSTATIC)) {
                return;
            }
            char t = field.field().type().stringValue().charAt(0);
            if (t != 'B' && t != 'S' && t != 'C' && t != 'Z' && t != 'I') {
                return;
            }
            String key = keyPrefix + "#d" + (++dataIndex);
            siteKinds.put(key, "d");
            builder.ldc(key);
            builder.invokestatic(
                    FAULT, "data", MethodTypeDesc.ofDescriptor("(ILjava/lang/String;)I"));
        }

        private void redirectHandler(CodeBuilder builder, ExceptionCatch handler) {
            Label stub = builder.newLabel();
            stubs.add(new AbstractMap.SimpleEntry<>(stub, handler.handler()));
            builder.exceptionCatch(handler.tryStart(), handler.tryEnd(), stub, handler.catchType());
        }

        /**
         * The {@link Fault#site} guard of a conditional branch (agent argument {@code sites}): mode
         * 0 runs the branch, 1 pops its operands and falls through, 2 takes the negated opcode to
         * the same target. Sites are counted over the original method body, so keys are stable
         * under weaving.
         */
        private void weaveBranch(CodeBuilder builder, BranchInstruction branch) {
            if (!weaveSites || !CONDITIONAL.contains(branch.opcode())) {
                builder.with(branch);
                return;
            }
            Label normal = builder.newLabel();
            Label skip = builder.newLabel();
            Label invert = builder.newLabel();
            Label end = builder.newLabel();
            String key = keyPrefix + "#b" + (++branchIndex);
            siteKinds.put(key, "b");
            Label take = builder.newLabel();
            builder.ldc(key);
            builder.invokestatic(
                    FAULT, "site", MethodTypeDesc.ofDescriptor("(Ljava/lang/String;)I"));
            // FALL (4) shares the skip path: the operands are popped and the body falls through
            builder.lookupswitch(
                    normal,
                    List.of(
                            SwitchCase.of(1, skip),
                            SwitchCase.of(2, invert),
                            SwitchCase.of(3, take),
                            SwitchCase.of(4, skip)));
            builder.labelBinding(normal);
            builder.branch(branch.opcode(), branch.target());
            builder.goto_(end);
            builder.labelBinding(take);
            for (int i = 0; i < operandsOf(branch.opcode()); i++) {
                builder.pop();
            }
            builder.branch(Opcode.GOTO, branch.target());
            builder.goto_(end);
            builder.labelBinding(skip);
            for (int i = 0; i < operandsOf(branch.opcode()); i++) {
                builder.pop();
            }
            builder.goto_(end);
            builder.labelBinding(invert);
            builder.branch(negate(branch.opcode()), branch.target());
            builder.labelBinding(end);
        }

        private static int operandsOf(Opcode opcode) {
            return switch (opcode) {
                case IFEQ, IFNE, IFLT, IFGE, IFGT, IFLE, IFNULL, IFNONNULL -> 1;
                default -> 2;
            };
        }

        /**
         * The {@link Fault#site} guard of an invoke: mode 1 pops args and receiver and pushes the
         * zero value of the return type; the normal path is the ordinary invoke weave. A {@code
         * <init>} invoke gets no site: popping the constructor leaves the duplicated receiver
         * uninitialized, which no stack-map merge accepts.
         */
        private void weaveInvoke(CodeBuilder builder, InvokeInstruction invoke) {
            if (!weaveSites || invoke.method().name().equalsString("<init>")) {
                rewriteInvoke(builder, invoke);
                return;
            }
            String key = keyPrefix + "#i" + (++invokeIndex);
            String desc = invoke.method().type().stringValue();
            char ret = desc.charAt(desc.indexOf(')') + 1);
            siteKinds.put(key, "i" + ret);
            boolean forcible = ret == 'S' || ret == 'B' || ret == 'Z';
            Label normal = builder.newLabel();
            Label skip = builder.newLabel();
            Label forced = builder.newLabel();
            Label end = builder.newLabel();
            builder.ldc(key);
            builder.invokestatic(
                    FAULT, "site", MethodTypeDesc.ofDescriptor("(Ljava/lang/String;)I"));
            builder.lookupswitch(
                    normal,
                    forcible
                            ? List.of(SwitchCase.of(1, skip), SwitchCase.of(5, forced))
                            : List.of(SwitchCase.of(1, skip)));
            builder.labelBinding(normal);
            rewriteInvoke(builder, invoke);
            builder.goto_(end);
            builder.labelBinding(skip);
            emitPops(builder, invoke);
            pushZero(builder, desc);
            builder.goto_(end);
            if (forcible) {
                builder.labelBinding(forced);
                emitPops(builder, invoke);
                builder.ldc(key);
                builder.invokestatic(
                        FAULT, "forced", MethodTypeDesc.ofDescriptor("(Ljava/lang/String;)S"));
            }
            builder.labelBinding(end);
        }

        private static final Set<Opcode> STORES =
                Set.of(Opcode.BASTORE, Opcode.SASTORE, Opcode.CASTORE);

        /** Binary int arithmetic: the faulted result is the left operand. */
        private static final Set<Opcode> BINARY_ARITH =
                Set.of(
                        Opcode.IADD,
                        Opcode.ISUB,
                        Opcode.IMUL,
                        Opcode.IAND,
                        Opcode.IOR,
                        Opcode.IXOR,
                        Opcode.ISHL,
                        Opcode.ISHR,
                        Opcode.IUSHR);

        /**
         * The {@link Fault#data} guard of a primitive load (agent argument {@code dsa=}): the
         * loaded int-category value passes through {@code Fault.data}, which replaces it on the
         * armed occurrence — {@code #d<k>} sites, counted like branch and invoke sites.
         */
        private void weaveData(CodeBuilder builder, CodeElement element) {
            builder.with(element);
            if (!weaveDsa) {
                return;
            }
            boolean intValue =
                    switch (element) {
                        case LoadInstruction l -> l.typeKind().asLoadable() == TypeKind.INT;
                        case ArrayLoadInstruction a ->
                                switch (a.opcode()) {
                                    case BALOAD, SALOAD, CALOAD, IALOAD -> true;
                                    default -> false;
                                };
                        case ConstantInstruction c -> c.constantValue() instanceof Integer;
                        default -> false;
                    };
            if (!intValue) {
                return;
            }
            String key = keyPrefix + "#d" + (++dataIndex);
            siteKinds.put(key, "d");
            builder.ldc(key);
            builder.invokestatic(
                    FAULT, "data", MethodTypeDesc.ofDescriptor("(ILjava/lang/String;)I"));
        }

        /**
         * A local store or {@code iinc} gets a {@code #s} store site: the guard pops the stored
         * value (or nothing for {@code iinc}) and the write never lands.
         */
        private void weaveStore(CodeBuilder builder, CodeElement element) {
            boolean store =
                    switch (element) {
                        case StoreInstruction s -> s.typeKind().asLoadable() == TypeKind.INT;
                        case IncrementInstruction i -> true;
                        default -> false;
                    };
            if (!weaveDsa || !store) {
                builder.with(element);
                return;
            }
            String key = keyPrefix + "#s" + (++storeIndex);
            siteKinds.put(key, "s");
            Label normal = builder.newLabel();
            Label skip = builder.newLabel();
            Label end = builder.newLabel();
            builder.ldc(key);
            builder.invokestatic(
                    FAULT, "site", MethodTypeDesc.ofDescriptor("(Ljava/lang/String;)I"));
            builder.lookupswitch(normal, List.of(SwitchCase.of(1, skip)));
            builder.labelBinding(normal);
            builder.with(element);
            builder.goto_(end);
            builder.labelBinding(skip);
            if (element instanceof StoreInstruction s) {
                // a slot skipped on its first write would merge as unusable (top): write
                // 0 instead — the verifier needs a type and a never-executed init leaves
                // the slot's old bytes, modelled as 0
                builder.pop();
                builder.iconst_0();
                builder.istore(s.slot());
            }
            builder.labelBinding(end);
        }

        /**
         * An int arithmetic instruction gets an {@code #a} site: on the armed occurrence the result
         * is the left operand (the instruction's own operand for {@code ineg}) — the right operand
         * is popped and the operator never runs.
         */
        private void weaveArith(CodeBuilder builder, OperatorInstruction op) {
            boolean binary = BINARY_ARITH.contains(op.opcode());
            boolean unary = op.opcode() == Opcode.INEG;
            if (!weaveDsa || (!binary && !unary)) {
                builder.with(op);
                return;
            }
            String key = keyPrefix + "#a" + (++arithIndex);
            siteKinds.put(key, "a");
            Label normal = builder.newLabel();
            Label left = builder.newLabel();
            Label end = builder.newLabel();
            builder.ldc(key);
            builder.invokestatic(
                    FAULT, "site", MethodTypeDesc.ofDescriptor("(Ljava/lang/String;)I"));
            builder.lookupswitch(normal, List.of(SwitchCase.of(1, left)));
            builder.labelBinding(normal);
            builder.with(op);
            builder.goto_(end);
            builder.labelBinding(left);
            if (binary) {
                builder.pop();
            }
            builder.labelBinding(end);
        }

        private static final Set<Opcode> CONDITIONAL =
                Set.of(
                        Opcode.IFEQ,
                        Opcode.IFNE,
                        Opcode.IFLT,
                        Opcode.IFGE,
                        Opcode.IFGT,
                        Opcode.IFLE,
                        Opcode.IF_ICMPEQ,
                        Opcode.IF_ICMPNE,
                        Opcode.IF_ICMPLT,
                        Opcode.IF_ICMPGE,
                        Opcode.IF_ICMPGT,
                        Opcode.IF_ICMPLE,
                        Opcode.IF_ACMPEQ,
                        Opcode.IF_ACMPNE,
                        Opcode.IFNULL,
                        Opcode.IFNONNULL);

        /** The negated form of a conditional branch opcode (agent argument {@code sites}). */
        private static Opcode negate(Opcode opcode) {
            return switch (opcode) {
                case IFEQ -> Opcode.IFNE;
                case IFNE -> Opcode.IFEQ;
                case IFLT -> Opcode.IFGE;
                case IFGE -> Opcode.IFLT;
                case IFGT -> Opcode.IFLE;
                case IFLE -> Opcode.IFGT;
                case IF_ICMPEQ -> Opcode.IF_ICMPNE;
                case IF_ICMPNE -> Opcode.IF_ICMPEQ;
                case IF_ICMPLT -> Opcode.IF_ICMPGE;
                case IF_ICMPGE -> Opcode.IF_ICMPLT;
                case IF_ICMPGT -> Opcode.IF_ICMPLE;
                case IF_ICMPLE -> Opcode.IF_ICMPGT;
                case IF_ACMPEQ -> Opcode.IF_ACMPNE;
                case IF_ACMPNE -> Opcode.IF_ACMPEQ;
                case IFNULL -> Opcode.IFNONNULL;
                case IFNONNULL -> Opcode.IFNULL;
                default -> throw new IllegalArgumentException("not a conditional: " + opcode);
            };
        }

        /** Pushes the zero value of an invoke's return type; nothing for {@code void}. */
        private static void pushZero(CodeBuilder builder, String desc) {
            char t = desc.charAt(desc.indexOf(')') + 1);
            switch (t) {
                case 'V' -> {}
                case 'J' -> builder.lconst_0();
                case 'F' -> builder.fconst_0();
                case 'D' -> builder.dconst_0();
                case 'L', '[' -> builder.aconst_null();
                default -> builder.iconst_0();
            }
        }

        private void rewriteInvoke(CodeBuilder builder, InvokeInstruction invoke) {
            if (skipGuard(builder, invoke)) {
                return;
            }
            if (invoke.opcode() == Opcode.INVOKESTATIC) {
                rewriteStatic(builder, invoke);
            } else {
                builder.with(invoke);
            }
            String owner = invoke.method().owner().name().stringValue();
            int slash = owner.lastIndexOf('/');
            if (!invoke.method().type().stringValue().endsWith(")S")
                    || slash < 0
                    || !packages.contains(owner.substring(0, slash))) {
                return;
            }
            // Fault.ret observes and replaces the call's short result
            builder.ldc(owner.substring(slash + 1) + "." + invoke.method().name().stringValue());
            builder.invokestatic(
                    FAULT, "ret", MethodTypeDesc.ofDescriptor("(SLjava/lang/String;)S"));
        }

        /**
         * Guards every void call whose owner is instrumented — and {@code JCSystem.begin}/ {@code
         * commit}/{@code abortTransaction} — with {@code Fault.skip} so {@code armSkip} can drop
         * the call. The arguments (one {@code pop} per slot, {@code pop2} for categories two) and
         * the receiver go down when the guard fires.
         */
        private boolean skipGuard(CodeBuilder builder, InvokeInstruction invoke) {
            if (!invoke.method().type().stringValue().endsWith(")V")) {
                return false;
            }
            String methodName = invoke.method().name().stringValue();
            // a skipped <init> leaves the object uninitialized and the guarded
            // branch unverifiable; constructors are not armable methods
            if (methodName.equals("<init>") || methodName.equals("<clinit>")) {
                return false;
            }
            String owner = invoke.method().owner().name().stringValue();
            int slash = owner.lastIndexOf('/');
            String pkg = slash < 0 ? "" : owner.substring(0, slash);
            boolean transaction =
                    owner.equals("javacard/framework/JCSystem")
                            && (invoke.method().name().stringValue().equals("beginTransaction")
                                    || invoke.method()
                                            .name()
                                            .stringValue()
                                            .equals("commitTransaction")
                                    || invoke.method()
                                            .name()
                                            .stringValue()
                                            .equals("abortTransaction"));
            if (!packages.contains(pkg) && !transaction) {
                return false;
            }
            builder.ldc(owner.substring(slash + 1) + "." + invoke.method().name().stringValue());
            builder.invokestatic(
                    FAULT, "skip", MethodTypeDesc.ofDescriptor("(Ljava/lang/String;)Z"));
            Label skip = builder.newLabel();
            Label end = builder.newLabel();
            builder.branch(Opcode.IFNE, skip);
            if (invoke.opcode() == Opcode.INVOKESTATIC) {
                rewriteStatic(builder, invoke);
            } else {
                builder.with(invoke);
            }
            builder.goto_(end);
            builder.labelBinding(skip);
            emitPops(builder, invoke);
            builder.labelBinding(end);
            return true;
        }

        /** Pops the arguments of {@code invoke} (last first) and, for non-static, the receiver. */
        private static void emitPops(CodeBuilder builder, InvokeInstruction invoke) {
            String desc = invoke.method().type().stringValue();
            List<Integer> slots = new ArrayList<>();
            int i = 1;
            while (desc.charAt(i) != ')') {
                int size = 1;
                char c = desc.charAt(i);
                if (c == 'L') {
                    i = desc.indexOf(';', i);
                } else if (c == '[') {
                    while (desc.charAt(i) == '[') {
                        i++;
                    }
                    if (desc.charAt(i) == 'L') {
                        i = desc.indexOf(';', i);
                    }
                } else if (c == 'J' || c == 'D') {
                    size = 2;
                }
                i++;
                slots.add(0, size);
            }
            if (invoke.opcode() != Opcode.INVOKESTATIC) {
                slots.add(1); // the receiver sits below the arguments: popped last
            }
            for (int size : slots) {
                if (size == 2) {
                    builder.pop2();
                } else {
                    builder.pop();
                }
            }
        }

        private void rewriteStatic(CodeBuilder builder, InvokeInstruction invoke) {
            String owner = invoke.method().owner().name().stringValue();
            String name = invoke.method().name().stringValue();
            String desc = invoke.method().type().stringValue();
            ClassDesc target =
                    switch (owner) {
                        case "javacard/framework/Util" ->
                                switch (name) {
                                    case "arrayCopy",
                                            "arrayCopyNonAtomic",
                                            "arrayFillNonAtomic",
                                            "setShort" ->
                                            NVM;
                                    default -> null;
                                };
                        case "javacard/framework/JCSystem" ->
                                switch (name) {
                                    case "makeTransientByteArray",
                                            "makeTransientShortArray",
                                            "makeTransientBooleanArray",
                                            "makeTransientObjectArray" ->
                                            MEMORY;
                                    default -> null;
                                };
                        case "javacard/security/KeyBuilder" ->
                                switch (name) {
                                    case "buildKey", "buildKeyWithSharedDomain" -> MEMORY;
                                    default -> null;
                                };
                        case "javacardx/crypto/Cipher" ->
                                "getInstance".equals(name) ? MEMORY : null;
                        case "javacard/security/Signature" ->
                                "getInstance".equals(name) ? MEMORY : null;
                        case "javacard/security/MessageDigest" ->
                                "getInstance".equals(name) ? MEMORY : null;
                        case "javacard/security/KeyAgreement" ->
                                "getInstance".equals(name) ? MEMORY : null;
                        case "javacard/security/RandomData" ->
                                "getInstance".equals(name) ? MEMORY : null;
                        default -> null;
                    };
            if (target != null) {
                String hook =
                        target == MEMORY && "getInstance".equals(name) ? engineHook(owner) : name;
                builder.invokestatic(target, hook, MethodTypeDesc.ofDescriptor(desc));
            } else {
                builder.with(invoke);
            }
        }

        private static String engineHook(String owner) {
            return switch (owner) {
                case "javacardx/crypto/Cipher" -> "cipher";
                case "javacard/security/Signature" -> "signature";
                case "javacard/security/MessageDigest" -> "messageDigest";
                case "javacard/security/KeyAgreement" -> "keyAgreement";
                case "javacard/security/RandomData" -> "randomData";
                default -> throw new IllegalArgumentException(owner);
            };
        }
    }
}
