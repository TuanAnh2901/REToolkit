(function () {
    var R = globalThis.retoolkitResolver;
    var P = globalThis.__RETOOLKIT_PARAMS || {};
    var duration = P.duration_ms || 120000;
    var mc = "UI_Scripts.WindowManager.MultichestWindow";
    var listener = "UGUIVisual.UGUIButtonListener";
    var specs = [
        { c: mc, m: "ShowMultichestWindow", a: 6 },
        { c: mc, m: "OnEnable", a: 0 },
        { c: mc, m: "Start", a: 0 },
        { c: mc, m: "OnOpenAll", a: 0 },
        { c: mc, m: "CloseWindow", a: 0 },
        { c: mc, m: "OnCloseAction", a: 0 },
        { c: mc, m: "WindowHidden", a: 0 },
        { c: listener, m: "HandleClick", a: 0 },
        { c: listener, m: "Update", a: 0 }
    ];
    var fields = [
        "openCardsButton", "closeButton", "_beforeHideAction", "_onClose",
        "_multichestController", "_allRewards", "_rewardCount", "_freeCount",
        "_actualCount", "_currentCount", "_openAllActive", "_pressedOpenAll",
        "_cardsAppearAnimDone", "_openAllLock", "_buttonsActive"
    ];
    var openButtons = {};
    function emit(kind, payload) { send({ type: "multichest_probe", kind: kind, payload: payload }); }
    function p(self, off) { try { return self.add(off).readPointer(); } catch (e) { return ptr(0); } }
    function fieldDump(self) {
        var row = { self: self.toString(), offsets: {} };
        var offsets = { openCardsButton: 0xA8, closeButton: 0xB0, beforeHide: 0x130, onClose: 0x128,
            multichestController: 0x120, allRewards: 0x138, rewardCount: 0x148,
            freeCount: 0x14C, actualCount: 0x150, currentCount: 0x154,
            openAllActive: 0x168, pressedOpenAll: 0x169, cardsAppearAnimDone: 0x16A,
            openAllLock: 0x16B, buttonsActive: 0x188 };
        Object.keys(offsets).forEach(function (name) {
            var off = offsets[name];
            if (name.indexOf("Count") >= 0) {
                try { row.offsets[name] = { offset: "0x" + off.toString(16), value: self.add(off).readS32() }; } catch (e) { row.offsets[name] = { offset: "0x" + off.toString(16), value: null }; }
            } else if (name.indexOf("Active") >= 0 || name.indexOf("pressed") >= 0 || name.indexOf("Done") >= 0 || name.indexOf("Lock") >= 0) {
                try { row.offsets[name] = { offset: "0x" + off.toString(16), value: self.add(off).readU8() }; } catch (e) { row.offsets[name] = { offset: "0x" + off.toString(16), value: null }; }
            } else {
                row.offsets[name] = { offset: "0x" + off.toString(16), value: p(self, off).toString() };
            }
        });
        return row;
    }
    function attach(s) {
        var method = R.resolveMethodPointer(s.c, s.m, s.a);
        emit("method", { className: s.c, methodName: s.m, argc: s.a, address: method ? method.toString() : null });
        if (!method) return;
        try {
            Interceptor.attach(method, {
                onEnter: function (args) {
                    var self = args[0];
                    emit("enter", { className: s.c, methodName: s.m, self: self ? self.toString() : null });
                    if (self && (s.m === "OnEnable" || s.m === "Start" || s.m === "OnOpenAll" || s.m === "CloseWindow" || s.m === "OnCloseAction" || s.m === "WindowHidden")) {
                        var row = fieldDump(self);
                        emit("window_fields", { methodName: s.m, data: row });
                        if (s.m === "OnEnable" || s.m === "Start") {
                            var b = p(self, 0xA8);
                            if (!b.isNull()) openButtons[b.toString()] = true;
                        }
                    }
                    if (s.c === listener && s.m === "HandleClick" && self)
                        emit("button_click", { self: self.toString(), isOpenAllButton: !!openButtons[self.toString()] });
                },
                onLeave: function (retval) { emit("leave", { className: s.c, methodName: s.m, retval: retval.toString() }); }
            });
        } catch (e) { emit("attach_error", { className: s.c, methodName: s.m, error: String(e) }); }
    }
    try {
        R.waitForIl2Cpp();
        emit("module", { gameAssembly: Process.findModuleByName("GameAssembly.dll").base.toString() });
        for (var i = 0; i < specs.length; i++) attach(specs[i]);
        for (var j = 0; j < fields.length; j++) {
            var f = R.getField(mc, fields[j]);
            emit("field", { className: mc, fieldName: fields[j], offset: f ? f.offset : null, isStatic: f ? f.isStatic : null });
        }
        setTimeout(function () { send("__retoolkit_done__"); }, duration);
    } catch (e) { emit("error", { error: String(e) }); send("__retoolkit_done__"); }
})();
