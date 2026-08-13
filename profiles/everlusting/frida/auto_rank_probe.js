(function () {
    var R = globalThis.retoolkitResolver;
    var P = globalThis.__RETOOLKIT_PARAMS || {};
    var duration = P.duration_ms || 120000;
    var specs = [
        { c: "AutoChess.UIScripts.WindowScripts.BattlefieldWindow.BattlefieldWindow", m: "Start", a: 0 },
        { c: "AutoChess.UIScripts.WindowScripts.BattlefieldWindow.BattlefieldWindow", m: "InitAutoBattle", a: 0 },
        { c: "AutoChess.UIScripts.WindowScripts.BattlefieldWindow.BattlefieldWindow", m: "get_AutoBattleController", a: 0 },
        { c: "AutoChess.UIScripts.WindowScripts.BattlefieldWindow.BattlefieldWindow", m: "IsAutoBattleActive", a: 0 },
        { c: "AutoChess.UIScripts.WindowScripts.BattlefieldWindow.BattlefieldWindow", m: "SetAutoBattleInactive", a: 0 },
        { c: "AutoChess.CoreGameplay.Fight.AutoBattle.AutoBattleController", m: "OnAutoBattleClicked", a: 0 },
        { c: "AutoChess.CoreGameplay.Fight.AutoBattle.AutoBattleController", m: "IsAutoBattleActive", a: 0 },
        { c: "AutoChess.CoreGameplay.Fight.AutoBattle.AutoBattleController", m: "ToggleAutoBattleAIState", a: 0 },
        { c: "UGUIVisual.UGUIButtonListener", m: "get_Hotkey", a: 0 },
        { c: "UGUIVisual.UGUIButtonListener", m: "HandleClick", a: 0 },
        { c: "AutoChess.UIScripts.WindowScripts.MatchCompleted.MatchCompletedWindow", m: "ShowWindow", a: 4 },
        { c: "AutoChess.UIScripts.WindowScripts.MatchCompleted.MatchCompletedWindow", m: "Update", a: 0 },
        { c: "UI_Scripts.WindowManager.MultichestWindow", m: "ShowMultichestWindow", a: 6 },
        { c: "UI_Scripts.WindowManager.MultichestWindow", m: "OnOpenAll", a: 0 },
        { c: "UI_Scripts.WindowManager.MultichestWindow", m: "OnCloseAction", a: 0 },
        { c: "UI_Scripts.WindowManager.MultichestWindow", m: "WindowHidden", a: 0 },
        { c: "AutoChess.Journey.JourneyModuleABC.Service.ExternalJourneyFighter", m: "ClaimRewardsOnWin", a: 0 },
        { c: "AutoChess.LeagueFlow.Views.LeagueBarWindowPresenter", m: "OnShown", a: 0 },
        { c: "AutoChess.LeagueFlow.Views.LeagueBarWindowPresenter", m: "OnClose", a: 0 },
        { c: "AutoChess.LeagueFlow.Views.LeagueBarWindow", m: "UnlockButtons", a: 0 },
        { c: "AutoChess.CoreGameplay.Fight.AutoBattle.AutoBattleController", m: "OnMatchEnded", a: 0 },
        { c: "AutoChess.DataClasses.UserData.ItemModule", m: "get_Instance", a: 0 },
        { c: "AutoChess.DataClasses.UserData.ItemModule", m: "IsEnoughResource", a: 2 },
        { c: "AutoChess.DataClasses.UserData.ItemModule", m: "GetResourceCount", a: 1 },
        { c: "AutoChess.DataClasses.UserData.ItemModule", m: "get_Item", a: 1 }
    ];
    var fieldSpecs = [
        ["UI_Scripts.WindowManager.MultichestWindow", "openCardsButton"],
        ["UI_Scripts.WindowManager.MultichestWindow", "closeButton"],
        ["UI_Scripts.WindowManager.MultichestWindow", "_beforeHideAction"],
        ["UI_Scripts.WindowManager.MultichestWindow", "_onClose"],
        ["UI_Scripts.WindowManager.MultichestWindow", "_multichestController"],
        ["UI_Scripts.WindowManager.MultichestWindow", "_pressedOpenAll"],
        ["UI_Scripts.WindowManager.MultichestWindow", "_openAllLock"],
        ["AutoChess.UIScripts.WindowScripts.BattlefieldWindow.BattlefieldWindow", "autoBattleButton"],
        ["AutoChess.UIScripts.WindowScripts.BattlefieldWindow.BattlefieldWindow", "autoBattleController"],
        ["AutoChess.UIScripts.WindowScripts.BattlefieldWindow.BattlefieldWindow", "autoplayButton"],
        ["AutoChess.UIScripts.WindowScripts.BattlefieldWindow.BattlefieldWindow", "autoBattle"],
        ["AutoChess.CoreGameplay.Fight.AutoBattle.AutoBattleController", "button"],
        ["AutoChess.CoreGameplay.Fight.AutoBattle.AutoBattleController", "autoBattleButton"]
    ];
    var multichestButtons = {};
    function emit(kind, payload) { send({ type: "auto_rank_probe", kind: kind, payload: payload }); }
    function ptrAt(self, off) { try { return self.add(off).readPointer(); } catch (e) { return ptr(0); } }
    function attach(s) {
        var method = R.resolveMethodPointer(s.c, s.m, s.a);
        emit("method", { className: s.c, methodName: s.m, argc: s.a, address: method ? method.toString() : null });
        if (!method) return;
        try {
            Interceptor.attach(method, {
                onEnter: function (args) {
                    var self = args[0];
                    var row = { className: s.c, methodName: s.m, self: self ? self.toString() : null };
                    if (s.c.indexOf("ItemModule") >= 0 && (s.m === "GetResourceCount" || s.m === "get_Item"))
                        row.resourceArg = args[1] ? args[1].toInt32() : null;
                    emit("hit", row);
                    if (s.m === "Start" && self) {
                        var fields = {};
                        for (var off = 0x20; off <= 0x180; off += 8) {
                            var p = ptrAt(self, off);
                            if (!p.isNull()) fields["0x" + off.toString(16)] = p.toString();
                        }
                        emit("object_scan", { className: s.c, self: self.toString(), fields: fields });
                    }
                    if ((s.m === "OnEnable" || s.m === "Start") && s.c === "UI_Scripts.WindowManager.MultichestWindow" && self) {
                        var openBtn = ptrAt(self, 0xA8);
                        var closeBtn = ptrAt(self, 0xB0);
                        if (!openBtn.isNull()) multichestButtons[openBtn.toString()] = true;
                        emit("multichest_fields", { self: self.toString(), openCardsButton: openBtn.toString(), closeButton: closeBtn.toString(), beforeHide: ptrAt(self, 0x130).toString(), onClose: ptrAt(self, 0x128).toString() });
                    }
                    if (s.c === "UGUIVisual.UGUIButtonListener" && s.m === "HandleClick" && self) {
                        emit("button_click", { self: self.toString(), isMultichestOpenAll: !!multichestButtons[self.toString()] });
                    }
                },
                onLeave: function (retval) {
                    if (s.m === "IsAutoBattleActive" || s.m === "get_Hotkey")
                        emit("return", { className: s.c, methodName: s.m, value: retval.toString() });
                }
            });
        } catch (e) { emit("attach_error", { className: s.c, methodName: s.m, error: String(e) }); }
    }
    try {
        R.waitForIl2Cpp();
        emit("module", { gameAssembly: Process.findModuleByName("GameAssembly.dll").base.toString() });
        for (var i = 0; i < specs.length; i++) attach(specs[i]);
        for (var j = 0; j < fieldSpecs.length; j++) {
            var f = R.getField(fieldSpecs[j][0], fieldSpecs[j][1]);
            emit("field", { className: fieldSpecs[j][0], fieldName: fieldSpecs[j][1], offset: f ? f.offset : null, isStatic: f ? f.isStatic : null });
        }
        setTimeout(function () { send("__retoolkit_done__"); }, duration);
    } catch (e) { emit("error", { error: String(e) }); send("__retoolkit_done__"); }
})();
