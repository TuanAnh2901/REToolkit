(function () {
    // Deep probe: MultichestWindow elements list + button bindings.
    var R = globalThis.retoolkitResolver;
    var P = globalThis.__RETOOLKIT_PARAMS || {};
    var duration = P.duration_ms || 120000;
    var mc = "UI_Scripts.WindowManager.MultichestWindow";
    var listener = "UGUIVisual.UGUIButtonListener";
    var be = "UGUIVisual.ButtonEventListener";
    function emit(kind, payload) { send({ type: "mc_deep", kind: kind, payload: payload }); }
    function p(self, off) { try { return self.add(off).readPointer(); } catch (e) { return ptr(0); } }
    function pv(self, off) { try { return self.add(off).readPointer().toString(); } catch (e) { return "ERR"; } }
    function s32(self, off) { try { return self.add(off).readS32(); } catch (e) { return -1; } }
    function u8(self, off) { try { return self.add(off).readU8(); } catch (e) { return -1; } }

    // List<T> IL2CPP: list+0x10 = items array, array+0x18 = size (SZARRAY),
    // array items start at +0x10 (+0x18+... header), each element 8 bytes.
    function dumpList(listPtr, label) {
        var row = { label: label, list: listPtr.toString(), size: -1, items: [] };
        if (listPtr.isNull()) return row;
        var items = p(listPtr, 0x10);
        row.size = s32(listPtr, 0x18);
        if (items.isNull()) return row;
        row.itemsArray = items.toString();
        var count = row.size;
        if (count < 0 || count > 64) count = 0;
        for (var i = 0; i < count; i++) {
            var el = p(items, 0x10 + i * 8);
            var elRow = { index: i, ptr: el.toString() };
            // Try to read a couple of common fields: onClick (0x40), gameObject (0x18?)
            elRow.onClick = pv(el, 0x40);
            elRow.onDown = pv(el, 0x48);
            row.items.push(elRow);
        }
        return row;
    }

    function buttonBind(btnPtr, label) {
        var row = { label: label, button: btnPtr.toString() };
        if (btnPtr.isNull()) return row;
        row.onClick = pv(btnPtr, 0x40);
        row.onDown = pv(btnPtr, 0x48);
        row.onUp = pv(btnPtr, 0x58);
        row.onEnter = pv(btnPtr, 0x68);
        // Resolve delegate method pointers
        [["onClick", 0x40], ["onDown", 0x48], ["onUp", 0x58], ["onEnter", 0x68]].forEach(function (pair) {
            var d = p(btnPtr, pair[1]);
            if (!d.isNull()) {
                row[pair[0] + "Method"] = pv(d, 0x10);
            }
        });
        return row;
    }

    function fieldDump(self) {
        var row = { self: self.toString() };
        row.elements = dumpList(p(self, 0x80), "elements");
        row.guaranteedElements = dumpList(p(self, 0x90), "guaranteedRewardsElements");
        row.allRewards = dumpList(p(self, 0x138), "_allRewards");
        row.openCardsButton = buttonBind(p(self, 0xA8), "openCardsButton");
        row.closeButton = buttonBind(p(self, 0xB0), "closeButton");
        row.counts = { reward: s32(self, 0x148), free: s32(self, 0x14C), actual: s32(self, 0x150), current: s32(self, 0x154) };
        row.flags = { openAllActive: u8(self, 0x168), pressedOpenAll: u8(self, 0x169), cardsAnimDone: u8(self, 0x16A), openAllLock: u8(self, 0x16B), buttonsActive: u8(self, 0x188) };
        return row;
    }

    var specs = [
        { c: mc, m: "OnEnable", a: 0 },
        { c: mc, m: "Start", a: 0 },
        { c: mc, m: "OnOpenAll", a: 0 },
        { c: mc, m: "CloseWindow", a: 0 },
        { c: mc, m: "WindowHidden", a: 0 }
    ];
    try {
        R.waitForIl2Cpp();
        emit("module", { gameAssembly: Process.findModuleByName("GameAssembly.dll").base.toString() });
        specs.forEach(function (s) {
            var method = R.resolveMethodPointer(s.c, s.m, s.a);
            emit("method", { className: s.c, methodName: s.m, address: method ? method.toString() : null });
            if (!method) return;
            try {
                Interceptor.attach(method, {
                    onEnter: function (args) {
                        var self = args[0];
                        emit("enter", { methodName: s.m, self: self ? self.toString() : null });
                        if (self) emit("fields", { methodName: s.m, data: fieldDump(self) });
                    }
                });
            } catch (e) { emit("attach_error", { methodName: s.m, error: String(e) }); }
        });
        setTimeout(function () { send("__retoolkit_done__"); }, duration);
    } catch (e) { emit("error", { error: String(e) }); send("__retoolkit_done__"); }
})();
