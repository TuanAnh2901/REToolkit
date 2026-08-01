// retoolkit IL2CPP resolver (ES5, Duktape-compatible).
//
// Behavioral reimplementation of the battle_cheat il2cpp_resolve.js API
// (attribution: battle_cheat il2cpp_resolve.js / cheater_bypass.js patterns;
// reimplemented, not copied). Fixes over the original: collision-safe class
// arrays, namespace + assembly-aware lookup, IL2CPP-readiness wait, cached
// lookups, inherited-method resolution, icall resolution, and static-field
// support. Resolve-only: no Interceptor hooks and no memory writes.
//
// Runs inside a Frida script (global `send`, `Process`, `Memory`,
// `NativeFunction`, `Thread`, `ptr`) or under the Node test shim.
(function (global) {
    var PARAMS = global.__RETOOLKIT_PARAMS || {};
    var GA_NAME = "GameAssembly.dll";
    var GA_TIMEOUT_MS = PARAMS.ga_timeout_ms || 30000;
    var READY_TIMEOUT_MS = PARAMS.il2cpp_timeout_ms || 30000;
    var METHOD_INFO_CODE_OFFSET = PARAMS.method_info_code_offset || 0x08;
    var FIELD_ATTRIBUTE_STATIC = 0x0010;
    var DEFAULT_ASSEMBLIES = ["Assembly-CSharp", "UnityEngine.CoreModule", "mscorlib", "System", "System.Core"];

    var gaModule = null;
    var il2cppExports = null;
    var ready = false;
    var nativeCache = {};
    var classMapCache = null;
    var pointerCache = {};
    var staticFieldCache = {};

    function sendResult(kind, payload) {
        if (typeof global.send === "function") {
            global.send({ type: "resolver", kind: kind, payload: payload });
        }
    }

    function waitForGameAssembly() {
        if (gaModule) { return gaModule; }
        var waited = 0;
        while (!gaModule && waited < GA_TIMEOUT_MS) {
            gaModule = Process.findModuleByName(GA_NAME);
            if (!gaModule) { Thread.sleep(1); waited += 1; }
        }
        if (!gaModule) {
            throw new Error("GameAssembly.dll not loaded after " + GA_TIMEOUT_MS + "ms");
        }
        il2cppExports = gaModule;
        return gaModule;
    }

    function native(name, ret, args) {
        if (!il2cppExports) { waitForGameAssembly(); }
        if (!nativeCache[name]) {
            var addr = il2cppExports.findExportByName(name);
            if (addr === null || addr === undefined) { return null; }
            nativeCache[name] = new NativeFunction(addr, ret, args);
        }
        return nativeCache[name];
    }

    function waitForIl2Cpp() {
        if (ready) { return; }
        waitForGameAssembly();
        var probe = null;
        var waited = 0;
        while (!probe && waited < READY_TIMEOUT_MS) {
            var domain = native("il2cpp_domain_get", "pointer", []);
            if (domain) {
                var d = domain();
                if (d && !d.isNull()) {
                    var open = native("il2cpp_domain_assembly_open", "pointer", ["pointer", "pointer"]);
                    if (open) {
                        var asm = open(d, Memory.allocUtf8String("Assembly-CSharp"));
                        if (asm && !asm.isNull()) {
                            var image = native("il2cpp_assembly_get_image", "pointer", ["pointer"]);
                            var count = native("il2cpp_image_get_class_count", "uint32", ["pointer"]);
                            if (image && count) {
                                var img = image(asm);
                                if (img && !img.isNull() && count(img) > 0) { probe = d; }
                            }
                        }
                    }
                }
            }
            if (!probe) { Thread.sleep(10); waited += 10; }
        }
        if (!probe) {
            throw new Error("IL2CPP runtime not ready after " + READY_TIMEOUT_MS + "ms");
        }
        ready = true;
    }

    function buildClassMap() {
        if (classMapCache) { return classMapCache; }
        var map = {};
        var domain = native("il2cpp_domain_get", "pointer", [])();
        var open = native("il2cpp_domain_assembly_open", "pointer", ["pointer", "pointer"]);
        var imageFn = native("il2cpp_assembly_get_image", "pointer", ["pointer"]);
        var classCountFn = native("il2cpp_image_get_class_count", "uint32", ["pointer"]);
        var classAtFn = native("il2cpp_image_get_class", "pointer", ["pointer", "uint32"]);
        var getNameFn = native("il2cpp_class_get_name", "pointer", ["pointer"]);
        var getNsFn = native("il2cpp_class_get_namespace", "pointer", ["pointer"]);
        var asmNames = PARAMS.assemblies || DEFAULT_ASSEMBLIES;
        var i, j;
        for (i = 0; i < asmNames.length; i++) {
            var asm = open(domain, Memory.allocUtf8String(asmNames[i]));
            if (!asm || asm.isNull()) { continue; }
            var image = imageFn(asm);
            if (!image || image.isNull()) { continue; }
            var count = classCountFn(image);
            for (j = 0; j < count; j++) {
                var klass = classAtFn(image, j);
                if (!klass || klass.isNull()) { continue; }
                var name = getNameFn(klass).readUtf8String();
                var ns = getNsFn(klass).readUtf8String();
                if (!map[name]) { map[name] = []; }
                map[name].push({ klass: klass, ns: ns || "", asm: asmNames[i] });
            }
        }
        classMapCache = map;
        return map;
    }

    function parseClassName(full) {
        var asm = null;
        var cls = full;
        var idx = full.indexOf("::");
        if (idx >= 0) { asm = full.substring(0, idx); cls = full.substring(idx + 2); }
        var ns = "";
        var dot = cls.lastIndexOf(".");
        if (dot >= 0) { ns = cls.substring(0, dot); cls = cls.substring(dot + 1); }
        return { asm: asm, ns: ns, cls: cls };
    }

    function getClass(full) {
        waitForIl2Cpp();
        var spec = parseClassName(full);
        var candidates = buildClassMap()[spec.cls] || [];
        var i;
        for (i = 0; i < candidates.length; i++) {
            var candidate = candidates[i];
            if (spec.ns && candidate.ns !== spec.ns) { continue; }
            if (spec.asm && candidate.asm !== spec.asm) { continue; }
            return candidate.klass;
        }
        return null;
    }

    function findMethodInfo(klass, methodName, paramCount) {
        var getMethods = native("il2cpp_class_get_methods", "pointer", ["pointer", "pointer"]);
        var getName = native("il2cpp_method_get_name", "pointer", ["pointer"]);
        var getParams = native("il2cpp_method_get_param_count", "uint32", ["pointer"]);
        var getParent = native("il2cpp_class_get_parent", "pointer", ["pointer"]);
        var iter = Memory.alloc(Process.pointerSize);
        var cur = klass;
        var seen = {};
        while (cur && !cur.isNull() && !seen[cur.toString()]) {
            seen[cur.toString()] = true;
            iter.writePointer(ptr(0));
            var method = getMethods(cur, iter);
            while (method && !method.isNull()) {
                var name = getName(method).readUtf8String();
                if (name === methodName && (paramCount < 0 || getParams(method) === paramCount)) {
                    return method;
                }
                method = getMethods(cur, iter);
            }
            cur = getParent(cur);
        }
        return null;
    }

    function getMethodInfo(className, methodName, paramCount) {
        waitForIl2Cpp();
        var klass = getClass(className);
        if (!klass) { return null; }
        return findMethodInfo(klass, methodName, paramCount);
    }

    function resolveMethodPointer(className, methodName, paramCount) {
        var key = className + "::" + methodName + "(" + (paramCount < 0 ? "*" : paramCount) + ")";
        if (Object.prototype.hasOwnProperty.call(pointerCache, key)) {
            return pointerCache[key];
        }
        var klass = getClass(className);
        if (!klass) {
            sendResult("not_found", { target: key, reason: "class" });
            pointerCache[key] = null;
            return null;
        }
        var info = findMethodInfo(klass, methodName, paramCount);
        if (!info) {
            sendResult("not_found", { target: key, reason: "method" });
            pointerCache[key] = null;
            return null;
        }
        var codePtr = info.add(METHOD_INFO_CODE_OFFSET).readPointer();
        pointerCache[key] = codePtr;
        sendResult("ok", { target: key, pointer: codePtr.toString() });
        return codePtr;
    }

    function getField(className, fieldName) {
        waitForIl2Cpp();
        var klass = getClass(className);
        if (!klass) { return null; }
        var getFields = native("il2cpp_class_get_fields", "pointer", ["pointer", "pointer"]);
        var getName = native("il2cpp_field_get_name", "pointer", ["pointer"]);
        var getOffset = native("il2cpp_field_get_offset", "int32", ["pointer"]);
        var getFlags = native("il2cpp_field_get_flags", "uint32", ["pointer"]);
        var getParent = native("il2cpp_class_get_parent", "pointer", ["pointer"]);
        var iter = Memory.alloc(Process.pointerSize);
        var cur = klass;
        var seen = {};
        while (cur && !cur.isNull() && !seen[cur.toString()]) {
            seen[cur.toString()] = true;
            iter.writePointer(ptr(0));
            var field = getFields(cur, iter);
            while (field && !field.isNull()) {
                if (getName(field).readUtf8String() === fieldName) {
                    var flags = getFlags(field);
                    return {
                        offset: getOffset(field),
                        isStatic: (flags & FIELD_ATTRIBUTE_STATIC) !== 0,
                        klass: cur
                    };
                }
                field = getFields(cur, iter);
            }
            cur = getParent(cur);
        }
        return null;
    }

    function resolveStaticFieldAddress(className, fieldName) {
        var key = className + "::" + fieldName + "#static";
        if (Object.prototype.hasOwnProperty.call(staticFieldCache, key)) {
            return staticFieldCache[key];
        }
        var field = getField(className, fieldName);
        if (!field || !field.isStatic) {
            sendResult("not_found", { target: key, reason: field ? "not_static" : "field" });
            staticFieldCache[key] = null;
            return null;
        }
        var staticFields = native("il2cpp_class_get_static_fields", "pointer", ["pointer"]);
        if (!staticFields) { return null; }
        var base = staticFields(field.klass);
        if (!base || base.isNull()) { return null; }
        var address = base.add(field.offset);
        staticFieldCache[key] = address;
        sendResult("ok", { target: key, address: address.toString() });
        return address;
    }

    function resolveIcall(name) {
        waitForIl2Cpp();
        var resolveIcallFn = native("il2cpp_resolve_icall", "pointer", ["pointer"]);
        if (!resolveIcallFn) { return null; }
        var address = resolveIcallFn(Memory.allocUtf8String(name));
        if (!address || address.isNull()) { return null; }
        return address;
    }

    function guarded(fn) {
        return function () {
            try {
                return fn.apply(null, arguments);
            } catch (err) {
                sendResult("error", { message: String(err && err.message ? err.message : err) });
                return null;
            }
        };
    }

    global.retoolkitResolver = {
        waitForIl2Cpp: guarded(waitForIl2Cpp),
        getClass: guarded(getClass),
        getMethodInfo: guarded(getMethodInfo),
        resolveMethodPointer: guarded(resolveMethodPointer),
        getField: guarded(getField),
        resolveStaticFieldAddress: guarded(resolveStaticFieldAddress),
        resolveIcall: guarded(resolveIcall)
    };
})(typeof globalThis !== "undefined" ? globalThis : this);
