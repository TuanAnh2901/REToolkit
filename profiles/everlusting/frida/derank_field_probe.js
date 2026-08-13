(function () {
    var R = globalThis.retoolkitResolver;
    var P = globalThis.__RETOOLKIT_PARAMS || {};
    var duration = P.duration_ms || 90000;
    var specs = [
        { c: "AutoChess.UIScripts.WindowScripts.BattlefieldWindow.BattlefieldWindow", f: "settingsButton", m: "Start" },
        { c: "AutoChess.UIScripts.WindowScripts.BattleSettingsWindow", f: "surrenderButton", m: "Update" },
        { c: "AutoChess.UIScripts.WindowScripts.TechnicalWindows.TwoButtonWindow", f: "leftButton", m: "OnShown" },
        { c: "UGUIVisual.UGUIButtonListener", f: "m_OnClick", m: "HandleClick" },
        { c: "UGUIVisual.UGUIButtonListener", f: "onClick", m: "HandleClick" },
        { c: "UGUIVisual.UGUIButtonListener", f: "_onClick", m: "HandleClick" }
    ];

    function emit(kind, payload) {
        send({ type: "derank_probe", kind: kind, payload: payload });
    }
    function readObject(p, off) {
        try { return p.add(off).readPointer(); } catch (e) { return ptr(0); }
    }
    function attachSpec(s) {
        var field = R.getField(s.c, s.f);
        var method = R.resolveMethodPointer(s.c, s.m, -1);
        var row = { className: s.c, fieldName: s.f, methodName: s.m,
            fieldOffset: field ? field.offset : null,
            fieldStatic: field ? field.isStatic : null,
            method: method ? method.toString() : null };
        emit("field", row);
        if (!method) return;
        try {
            Interceptor.attach(method, {
                onEnter: function () {
                    var value = field && !field.isStatic ? readObject(this.context.rcx, field.offset) : ptr(0);
                    emit("hit", { className: s.c, fieldName: s.f, methodName: s.m,
                        self: this.context.rcx.toString(), fieldOffset: field ? field.offset : null,
                        fieldValue: value.toString() });
                }
            });
        } catch (e) { emit("attach_error", { className: s.c, methodName: s.m, error: String(e) }); }
    }
    try {
        R.waitForIl2Cpp();
        emit("module", { gameAssembly: Process.findModuleByName("GameAssembly.dll").base.toString() });
        for (var i = 0; i < specs.length; i++) attachSpec(specs[i]);
        setTimeout(function () { send("__retoolkit_done__"); }, duration);
    } catch (e) {
        emit("error", { error: String(e) });
        send("__retoolkit_done__");
    }
})();
