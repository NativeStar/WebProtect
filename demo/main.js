import WebProtect from "../detectorMain.js";
let easterEggActive = false;
addEventListener("error", event => {
    console.log(event.message)
});
document.addEventListener("contextmenu", event => {
    event.preventDefault();
})
async function init() {
    //0-2分别正常 可疑 异常
    let stateIconLevel = 0;
    const reasonMap = new Map([
        [-1,"异常"],
        [0, "toString检测"],
        [1, "toString方法被篡改"],
        [2, "崩溃行为异常"],
        [3, "崩溃行为异常"],
        [4, "加载未知资源"],
        [5, "检测过程被篡改"],
        [6, "发现Proxy"],
        [7, "疑似存在Proxy"],
        [8, "属性描述符异常"],
        [9, "发现代码注入"],
        [10, "加载未被允许的资源,存在异常元素"],
        [11, "存在浏览器扩展"],
        [12, "控制台被打开"]
    ]);
    let settings;
    const usedReasonString = new Set();
    const settingString = localStorage.getItem("setting");
    if (settingString !== null) {
        settings = JSON.parse(settingString);
    }else{
        settings={};
        document.getElementById("ignoreChromeExtension").checked=true
    }
    WebProtect.initAll((value) => {
        if (value===-1) {
            document.getElementById("stateIcon").src = "./res/error.svg";
            document.getElementById("stateTitle").innerText = "发生异常";
            document.getElementById("stateDescriptor").innerText = "请打开控制台查看";
            //阻止接下来操作
            easterEggActive=true;
            return
        }
        const reason = reasonMap.get(value);
        if (easterEggActive || usedReasonString.has(reason)) return
        usedReasonString.add(reason);
        //追加详情
        const liElement = document.createElement("li");
        const smallElement = document.createElement("small");
        smallElement.innerText = reason;
        smallElement.classList.add("detailText");
        liElement.appendChild(smallElement);
        if (value === 11 || value === 12) {
            //检查最高等级再更改img避免错乱
            if (stateIconLevel < 2) {
                document.getElementById("stateIcon").src = "./res/suspicious.svg";
                document.getElementById("stateTitle").innerText = "找到可疑痕迹";
                document.getElementById("stateDescriptor").innerText = "没有发现痕迹,但是存在可疑迹象";
                stateIconLevel = 1;
            }
            document.getElementById("suspiciousCard").classList.remove("hide");
            document.getElementById("detectSuspiciousItemsTable").appendChild(liElement);
            return
        } else {
            document.getElementById("stateIcon").src = "./res/found.svg";
            document.getElementById("stateTitle").innerText = "环境异常";
            document.getElementById("stateDescriptor").innerText = "检测到对环境的修改";
            document.getElementById("detectDetailCard").classList.remove("hide");
            document.getElementById("detectDetailItemsTable").appendChild(liElement);
            stateIconLevel = 2;
        }
    }, {
        selfScripts: [{ type: "domain", value: "https://content.github.com" }, { type: "name", value: "main.js" }, { type: "name", value: "mdui.esm.js" }],
        ...settings
    }
    );
    document.getElementById("sysInfoText").innerText = navigator.appVersion || navigator.userAgent;
    setTimeout(() => {
        document.getElementById("loadingProgressBar").classList.add("progressHide");
        document.getElementById("main").classList.remove("hide")
        document.getElementById("main").classList.add("show");
        easterEggTriggerInit();
    }, 2500);
    document.getElementById("stateIcon").addEventListener("click", () => {
        const settingString = localStorage.getItem("setting");
        if (settingString!==null) {
            const settings=JSON.parse(settingString);
            for (const element of document.getElementsByClassName("settingCheckbox")) {
                if (settings[element.id]) {
                    element.checked=settings[element.id];
                }
            }
        } 
        document.getElementById("settingDialog").showModal()
    });
    document.getElementById("settingSave").addEventListener("click", () => {
        const tempSettingData={};
        for (const element of document.getElementsByClassName("settingCheckbox")) {
            tempSettingData[element.id] = element.checked;
        }
        localStorage.setItem("setting", JSON.stringify(tempSettingData));
        document.getElementById("settingDialog").close();
        location.reload();
    })
}
init();
function easterEggTriggerInit() {
    //彩蛋是否已经激活
    const konamiCode = [
        "ArrowUp",
        "ArrowUp",
        "ArrowDown",
        "ArrowDown",
        "ArrowLeft",
        "ArrowRight",
        "ArrowLeft",
        "ArrowRight",
        "b",
        "a"
    ];
    let inputIndex = 0;
    document.addEventListener("keyup", event => {
        if (event.key === konamiCode[inputIndex]) {
            inputIndex++;
        } else {
            inputIndex = 0;
        }
        //触发
        if (inputIndex === konamiCode.length) {
            inputIndex = 0;
            if (easterEggActive) return;
            activeEasterEgg();
            easterEggActive = true;
        }
    })
}
function activeEasterEgg() {
    //@HookVip
    const easterEggDetectDetailItems = ["原神", "逆水寒", "光·遇", "暗区突围", "金铲铲之战", "和平精英", "王者荣耀", "火影忍者", "穿越火线",
        "使命召唤手游", "明日方舟", "碧蓝航线", "碧蓝档案", "蛋仔派对", "黎明觉醒", "我的世界", "QQ飞车", "崩坏2", "崩坏3", "崩坏:星穹铁道"
    ];
    const easterEggSuspiciousItems = ["HookVip", "KModule", "VipKill", "MT管理器", "NP管理器"]
    document.getElementById("stateIcon").src = "./res/easterEgg.svg";
    document.getElementById("stateTitle").innerText = "环境异常";
    document.getElementById("stateDescriptor").innerText = "检测到过于逆天的环境";
    document.getElementById("detectDetailCard").classList.remove("hide");
    document.getElementById("suspiciousCard").classList.remove("hide");
    //检测项
    document.getElementById("detectDetailItemsTable").innerHTML = '<ul id="detectDetailItemsTable"></ul>'
    document.getElementById("detectSuspiciousItemsTable").innerHTML = '<ul id="detectSuspiciousItemsTable"></ul>'
    const detailItemsTableTempFragment = document.createDocumentFragment();
    for (const item of easterEggDetectDetailItems) {
        const liElement = document.createElement("li");
        const smallElement = document.createElement("small");
        smallElement.innerText = `找到 ${item}`;
        smallElement.classList.add("detailText");
        liElement.appendChild(smallElement);
        detailItemsTableTempFragment.appendChild(liElement);
    }
    const suspiciousItemsTableTempFragment = document.createDocumentFragment();
    for (const item of easterEggSuspiciousItems) {
        const liElement = document.createElement("li");
        const smallElement = document.createElement("small");
        smallElement.innerText = `发现 ${item}`;
        smallElement.classList.add("detailText");
        liElement.appendChild(smallElement);
        suspiciousItemsTableTempFragment.appendChild(liElement);
    }
    document.getElementById("detectDetailItemsTable").appendChild(detailItemsTableTempFragment);
    document.getElementById("detectSuspiciousItemsTable").appendChild(suspiciousItemsTableTempFragment);
}