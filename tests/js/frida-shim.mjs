// Minimal Frida API shim for testing resolver.js under Node's test runner.
// Implements only the surface resolver.js touches: Process.findModuleByName,
// Memory allocs, NativeFunction, Thread.sleep, ptr, and send. The il2cpp
// export registry is supplied per-test over a fake object model.

function makeShim(exportsRegistry, options = {}) {
    const messages = [];
    const nullPtr = {
        isNull: () => true,
        toString: () => "0x0",
    };

    const shim = {
        messages,

        send(msg) {
            messages.push(JSON.parse(JSON.stringify(msg)));
        },

        Process: {
            pointerSize: 8,
            findModuleByName(name) {
                return options.modules?.[name] ?? null;
            },
        },

        Memory: {
            alloc() {
                return { _index: 0, _reset: false, writePointer() { this._reset = true; } };
            },
            allocUtf8String(text) {
                return { text };
            },
        },

        Thread: {
            sleep(ms) {
                const sab = new Int32Array(new SharedArrayBuffer(4));
                Atomics.wait(sab, 0, 0, ms);
            },
        },

        NativeFunction: function (fn, ret, args) {
            // constructor-style call sites in resolver.js: new NativeFunction(...);
            // concise methods cannot be constructed, hence function expression
            const wrapper = function () {
                return fn.apply(null, arguments);
            };
            return wrapper;
        },

        ptr(value) {
            if (value === 0 || value === "0") return nullPtr;
            return nullPtr; // tests never dereference non-null raw pointers
        },
    };

    // wire the GameAssembly.dll module whose exports back the NativeFunctions
    shim.Process.findModuleByName = (name) => {
        if (name === "GameAssembly.dll") {
            return {
                findExportByName(exportName) {
                    return Object.prototype.hasOwnProperty.call(exportsRegistry, exportName)
                        ? exportsRegistry[exportName]
                        : null;
                },
            };
        }
        return null;
    };

    return shim;
}

export { makeShim };
