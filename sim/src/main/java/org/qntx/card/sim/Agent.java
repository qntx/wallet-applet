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
import java.lang.classfile.instruction.ArrayStoreInstruction;
import java.lang.classfile.instruction.BranchInstruction;
import java.lang.classfile.instruction.ExceptionCatch;
import java.lang.classfile.instruction.FieldInstruction;
import java.lang.classfile.instruction.InvokeInstruction;
import java.lang.classfile.instruction.LocalVariable;
import java.lang.classfile.instruction.LocalVariableType;
import java.lang.classfile.instruction.NewMultiArrayInstruction;
import java.lang.classfile.instruction.NewPrimitiveArrayInstruction;
import java.lang.classfile.instruction.NewReferenceArrayInstruction;
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
 * patch 5). It runs on {@code -javaagent} with a comma-separated list of instrumented package
 * names, e.g. {@code -javaagent:sim-agent.jar=org/qntx/card/sim/probe}.
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
 * the return type pushed), or runs the negated branch. Site keys are {@code "Class.method#b<k>"}
 * for the k-th branch and {@code "Class.method#i<k>}" for the k-th invoke of the original method
 * body in bytecode order; an overloaded method name gets a {@code #d<hash>} descriptor suffix so
 * keys stay unique. The guard's fast path while nothing is armed or counted is one volatile read.
 */
public final class Agent {

    private static final ClassDesc NVM = ClassDesc.of("org.qntx.card.sim.Nvm");
    private static final ClassDesc MEMORY = ClassDesc.of("org.qntx.card.sim.Memory");
    private static final ClassDesc FAULT = ClassDesc.of("org.qntx.card.sim.Fault");

    private static volatile boolean installed;
    private static volatile boolean sites;

    private Agent() {}

    public static void premain(String args, Instrumentation inst) {
        // no -javaagent argument: instrument the applet package
        if (args == null || args.isEmpty()) {
            args = "org/qntx/card";
        }
        Set<String> packages = new HashSet<>(Arrays.asList(args.split(",")));
        sites = packages.remove("sites");
        inst.addTransformer(new AppletTransformer(packages, sites));
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

    static final class AppletTransformer implements ClassFileTransformer {

        private final Set<String> packages;
        private final boolean sites;

        AppletTransformer(Set<String> packages, boolean sites) {
            this.packages = packages;
            this.sites = sites;
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
                            builder.transformMethod(
                                    m,
                                    MethodTransform.transformingCode(
                                            new HookTransform(
                                                    packages,
                                                    sites && !"<init>".equals(name),
                                                    prefix)));
                        });
            } catch (RuntimeException e) {
                throw new IllegalStateException("sim agent failed to transform " + className, e);
            }
        }
    }

    private static final class HookTransform implements CodeTransform {

        private final Set<String> packages;
        private final boolean weaveSites;
        private final String keyPrefix;
        private int branchIndex;
        private int invokeIndex;
        private List<AbstractMap.SimpleEntry<Label, Label>> stubs;

        HookTransform(Set<String> packages) {
            this(packages, false, "");
        }

        HookTransform(Set<String> packages, boolean weaveSites, String keyPrefix) {
            this.packages = packages;
            this.weaveSites = weaveSites;
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

        private void rewriteArrayStore(CodeBuilder builder, ArrayStoreInstruction store) {
            if (store.opcode() == Opcode.BASTORE) {
                builder.invokestatic(
                        NVM, "bastore", MethodTypeDesc.ofDescriptor("(Ljava/lang/Object;II)V"));
            } else if (store.opcode() == Opcode.SASTORE) {
                builder.invokestatic(NVM, "sastore", MethodTypeDesc.ofDescriptor("([SII)V"));
            } else {
                builder.with(store);
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
            builder.ldc(keyPrefix + "#b" + (++branchIndex));
            builder.invokestatic(
                    FAULT, "site", MethodTypeDesc.ofDescriptor("(Ljava/lang/String;)I"));
            builder.lookupswitch(normal, List.of(SwitchCase.of(1, skip), SwitchCase.of(2, invert)));
            builder.labelBinding(normal);
            builder.branch(branch.opcode(), branch.target());
            builder.goto_(end);
            builder.labelBinding(skip);
            int operands =
                    switch (branch.opcode()) {
                        case IFEQ, IFNE, IFLT, IFGE, IFGT, IFLE, IFNULL, IFNONNULL -> 1;
                        default -> 2;
                    };
            for (int i = 0; i < operands; i++) {
                builder.pop();
            }
            builder.goto_(end);
            builder.labelBinding(invert);
            builder.branch(negate(branch.opcode()), branch.target());
            builder.labelBinding(end);
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
            Label normal = builder.newLabel();
            Label skip = builder.newLabel();
            Label end = builder.newLabel();
            builder.ldc(keyPrefix + "#i" + (++invokeIndex));
            builder.invokestatic(
                    FAULT, "site", MethodTypeDesc.ofDescriptor("(Ljava/lang/String;)I"));
            builder.lookupswitch(normal, List.of(SwitchCase.of(1, skip)));
            builder.labelBinding(normal);
            rewriteInvoke(builder, invoke);
            builder.goto_(end);
            builder.labelBinding(skip);
            emitPops(builder, invoke);
            pushZero(builder, invoke.method().type().stringValue());
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
