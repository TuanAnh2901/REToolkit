// Read-only example: resolve a list of methods supplied via
// __RETOOLKIT_PARAMS.targets ([["Namespace.Class", "Method", paramCount], ...])
// and report each pointer. No hooks, no memory writes.
(function () {
    var targets = (globalThis.__RETOOLKIT_PARAMS || {}).targets || [];
    targets.forEach(function (spec) {
        var pointer = retoolkitResolver.resolveMethodPointer(spec[0], spec[1], spec[2]);
        send({
            type: "trace",
            event: "method_resolved",
            target: spec[0] + "::" + spec[1],
            pointer: pointer ? pointer.toString() : null
        });
    });
    send({ type: "trace", event: "__retoolkit_done__" });
})();
