// Node tests for resolver.js using the Frida API shim + a fake il2cpp model.
import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import { makeShim } from "./frida-shim.mjs";

const RESOLVER_SOURCE = readFileSync(
    new URL("../../src/retoolkit/runtime/resolver.js", import.meta.url),
    "utf-8"
);

const NULL = { isNull: () => true, toString: () => "0x0" };

function mkPtr(id) {
    return {
        id,
        isNull: () => false,
        toString: () => `0x${id}`,
        add(offset) {
            return mkPtr(`${id}+${offset}`);
        },
        readPointer() {
            return mkPtr(`${id}->code`);
        },
    };
}

function strHandle(text) {
    return { readUtf8String: () => text };
}

class FakeModel {
    constructor() {
        this.assemblies = new Map();
        this.icalls = new Map();
        this.domain = mkPtr("domain");
        this.staticBases = new Map();
    }

    addAssembly(name, classes) {
        this.assemblies.set(name, classes);
    }

    addIcall(name, id) {
        this.icalls.set(name, mkPtr(id));
    }

    makeExports(ready) {
        const model = this;
        const imageName = (img) => img.id.substring("image:".length);
        const iterProtocol = (collectionOf) => (obj, iter) => {
            const collection = collectionOf(obj);
            if (iter._reset) {
                iter._index = 0;
                iter._reset = false;
            }
            if (iter._index >= collection.length) return NULL;
            return collection[iter._index++];
        };
        return {
            il2cpp_domain_get: () => (ready ? model.domain : NULL),
            il2cpp_domain_assembly_open: (d, nameArg) => {
                if (!ready) return NULL;
                return model.assemblies.has(nameArg.text) ? mkPtr(`asm:${nameArg.text}`) : NULL;
            },
            il2cpp_assembly_get_image: (asm) => mkPtr(`image:${asm.id.substring("asm:".length)}`),
            il2cpp_image_get_class_count: (img) => model.assemblies.get(imageName(img)).length,
            il2cpp_image_get_class: (img, index) => model.assemblies.get(imageName(img))[index].klass,
            il2cpp_class_get_name: (klass) => strHandle(klass.name),
            il2cpp_class_get_namespace: (klass) => strHandle(klass.ns || ""),
            il2cpp_class_get_methods: iterProtocol((klass) => klass.methods || []),
            il2cpp_method_get_name: (method) => strHandle(method.name),
            il2cpp_method_get_param_count: (method) => method.paramCount,
            il2cpp_class_get_parent: (klass) => klass.parent || NULL,
            il2cpp_class_get_fields: iterProtocol((klass) => klass.fields || []),
            il2cpp_field_get_name: (field) => strHandle(field.name),
            il2cpp_field_get_offset: (field) => field.offset,
            il2cpp_field_get_flags: (field) => field.flags,
            il2cpp_class_get_static_fields: (klass) => model.staticBases.get(klass.id) || NULL,
            il2cpp_resolve_icall: (nameArg) => model.icalls.get(nameArg.text) || NULL,
        };
    }
}

function buildModel() {
    const model = new FakeModel();
    const foo1 = {
        klass: { ...mkPtr("class:Foo:A"), name: "Foo", ns: "Namespace.One", id: "class:Foo:A" },
        methods: [
            { name: "Bar", paramCount: 1, code: "AA1" },
            { name: "Bar", paramCount: 2, code: "AA2" },
            { name: "Baz", paramCount: 0, code: "AA3" },
        ],
    };
    const foo2 = {
        klass: { ...mkPtr("class:Foo:B"), name: "Foo", ns: "Namespace.Two", id: "class:Foo:B" },
        methods: [{ name: "Bar", paramCount: 1, code: "BB1" }],
    };
    const withCode = (list) =>
        list.map((m) => ({ ...m, isNull: () => false, add: (o) => ({ readPointer: () => mkPtr(m.code) }) }));
    const withFieldApi = (list) => list.map((f) => ({ ...f, isNull: () => false }));
    foo1.klass.methods = withCode(foo1.methods);
    foo2.klass.methods = withCode(foo2.methods);
    const base = {
        klass: { ...mkPtr("class:Base"), name: "Base", ns: "Namespace.One", id: "class:Base" },
        fields: [{ name: "inheritedField", offset: 16, flags: 0 }],
    };
    base.klass.fields = withFieldApi(base.fields);
    const child = {
        klass: {
            ...mkPtr("class:Child"),
            name: "Child",
            ns: "Namespace.One",
            id: "class:Child",
            parent: base.klass,
        },
        methods: [],
    };
    child.klass.methods = [];
    const holder = {
        klass: { ...mkPtr("class:Holder"), name: "Holder", ns: "Namespace.One", id: "class:Holder" },
        fields: [
            { name: "counter", offset: 24, flags: 0x0010 },
            { name: "plain", offset: 8, flags: 0 },
        ],
    };
    holder.klass.methods = [];
    holder.klass.fields = withFieldApi(holder.fields);
    model.addAssembly("Assembly-CSharp", [foo1, base, child, holder]);
    model.addAssembly("Other.Assembly", [foo2]);
    model.addIcall("UnityEngine.Time::set_timeScale", "icall:ts");
    model.staticBases.set("class:Holder", mkPtr("staticbase:Holder"));
    return model;
}

function loadResolver(model, { ready = true } = {}) {
    const shim = makeShim(model.makeExports(ready), {});
    const globalObj = {
        ...shim,
        __RETOOLKIT_PARAMS: {
            ga_timeout_ms: 20,
            il2cpp_timeout_ms: 20,
            assemblies: ["Assembly-CSharp", "Other.Assembly"],
        },
    };
    // with-block lets the resolver's bare Process/Memory/... identifiers
    // resolve through the shim; the globalThis parameter keeps the IIFE's
    // trailing selection off the real Node global.
    const fn = new Function("globalThis", "global", "with (global) { " + RESOLVER_SOURCE + " }");
    fn(globalObj, globalObj);
    return { api: globalObj.retoolkitResolver, shim };
}

test("duplicate short names resolve exactly by namespace and assembly", () => {
    const model = buildModel();
    const { api } = loadResolver(model);
    assert.equal(api.getClass("Namespace.One.Foo").id, "class:Foo:A");
    assert.equal(api.getClass("Namespace.Two.Foo").id, "class:Foo:B");
    assert.equal(api.getClass("Other.Assembly::Namespace.Two.Foo").id, "class:Foo:B");
});

test("overloads resolve to distinct pointers", () => {
    const model = buildModel();
    const { api } = loadResolver(model);
    assert.equal(api.resolveMethodPointer("Namespace.One.Foo", "Bar", 1).toString(), "0xAA1");
    assert.equal(api.resolveMethodPointer("Namespace.One.Foo", "Bar", 2).toString(), "0xAA2");
});

test("missing class and missing method yield not_found results", () => {
    const model = buildModel();
    const { api, shim } = loadResolver(model);
    assert.equal(api.resolveMethodPointer("Namespace.One.Nope", "Bar", 1), null);
    assert.equal(api.resolveMethodPointer("Namespace.One.Foo", "Nope", 1), null);
    const kinds = shim.messages.filter((m) => m.type === "resolver").map((m) => m.kind);
    assert.deepEqual(kinds, ["not_found", "not_found"]);
});

test("inherited instance field resolves through parent walk", () => {
    const model = buildModel();
    const { api } = loadResolver(model);
    const field = api.getField("Namespace.One.Child", "inheritedField");
    assert.equal(field.offset, 16);
    assert.equal(field.isStatic, false);
});

test("static field address is static-base plus offset", () => {
    const model = buildModel();
    const { api, shim } = loadResolver(model);
    const address = api.resolveStaticFieldAddress("Namespace.One.Holder", "counter");
    assert.equal(address.toString(), "0xstaticbase:Holder+24");
    assert.equal(shim.messages.find((m) => m.type === "resolver").kind, "ok");
});

test("non-static field rejects static resolution", () => {
    const model = buildModel();
    const { api } = loadResolver(model);
    assert.equal(api.resolveStaticFieldAddress("Namespace.One.Holder", "plain"), null);
});

test("icall resolution via il2cpp_resolve_icall export", () => {
    const model = buildModel();
    const { api } = loadResolver(model);
    assert.equal(api.resolveIcall("UnityEngine.Time::set_timeScale").toString(), "0xicall:ts");
    assert.equal(api.resolveIcall("No.Such::icall"), null);
});

test("readiness timeout produces structured error, not exception", () => {
    const model = buildModel();
    const { api, shim } = loadResolver(model, { ready: false });
    assert.equal(api.resolveMethodPointer("Namespace.One.Foo", "Bar", 1), null);
    const error = shim.messages.find((m) => m.type === "resolver" && m.kind === "error");
    assert.ok(error, "expected structured error result");
    assert.match(error.payload.message, /not ready/i);
});

test("repeat lookup is memoized (single ok message, same pointer)", () => {
    const model = buildModel();
    const { api, shim } = loadResolver(model);
    const first = api.resolveMethodPointer("Namespace.One.Foo", "Baz", 0);
    const second = api.resolveMethodPointer("Namespace.One.Foo", "Baz", 0);
    assert.equal(first.toString(), second.toString());
    const okMessages = shim.messages.filter((m) => m.type === "resolver" && m.kind === "ok");
    assert.equal(okMessages.length, 1);
});
