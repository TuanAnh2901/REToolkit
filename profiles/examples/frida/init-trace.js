// Read-only example: wait for IL2CPP readiness, resolve the metadata loader
// and il2cpp_init entry points from the method map, report them, and finish.
// No hooks, no memory writes.
(function () {
    retoolkitResolver.waitForIl2Cpp();
    var targets = (globalThis.__RETOOLKIT_PARAMS || {}).targets || [];
    targets.forEach(function (spec) {
        var info = retoolkitResolver.getMethodInfo(spec[0], spec[1], spec[2]);
        send({
            type: "trace",
            event: "method_info",
            target: spec[0] + "::" + spec[1],
            address: info ? info.toString() : null
        });
    });
    send({ type: "trace", event: "__retoolkit_done__" });
})();
