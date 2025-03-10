# Web Protect

demo:等待上传调整

检测浏览器环境是否存在异常 如部分浏览器扩展及油猴脚本

同时保护网页运行环境不受外部脚本篡改

兼顾简单的控制台检测等功能

## 使用

````html
<!-- 引入 -->
<script type="module" src="./detectorMain.js"></script>
````

````javascript
import WebProtect from "./detectorMain.js";
/*初始化
使用initAll方法可快速初始化功能*/
WebProtect.initAll((value)=>{
    //发现异常时回调
},{
    //配置项 如自身资源列表等 避免误判
    selfScripts: [{ type: "domain", value: "http://127.0.0.1" }, { type: "name", value: "main.js" }],
});

//或使用init方法详细配置
WebProtect.init((value)=>{
    //发现异常时回调
},{
    //详见下方解释
    checkGlobalFunctionHook: true,
    checkGlobalObjectHook: true,
    enableProtect: true,
    ignoreChromeExtension:true,
    disableConsoleExecute:false,
    clearLogsOnOpenConsole:false,
    selfScripts:[];
});
````
### 配置项介绍

selfScripts:

数组 需传入表示网站本身需要的文件或来源域名的对象

对象格式如下:
````javascript
//允许名为worker.js的文件加载
{type:"name",value:"worker.js"}
//允许加载来自https://github.com的文件
{type:"domain",value="https://github.com"}
````

checkGlobalFunctionHook:检测挂载在全局上的函数(如alert open等)是否被篡改

checkGlobalObjectHook:检测挂载在全局上的对象(如XMLHttpRequest等)及其内部方法是否被篡改

enableProtect:是否在检测完毕后启用保护

ignoreChromeExtension:是否忽略Chrome扩展带来的的修改(目前只支持检测Chrome)

disableConsoleExecute:是否阻止在控制台执行部分代码(实验性功能 可以拦截如Object.defineProperty等)

clearLogsOnOpenConsole:发现控制台被打开后执行一次console.clear()

在部分版本的Chrome浏览器上该功能会导致页面崩溃 原因未知

~~也许把页面直接崩了会比弹个框要求关闭控制台效果更好~~


### 保护

如开启保护 会在检测完毕后(如果启用了检测)对目标方法进行保护 主要为:

防篡改 破坏部分修改脚本执行 阻止加载未被允许的外部脚本 检测控制台
> 可以尝试在TamperMonkey中写入诸如"alert=(value)=>{}"的脚本并将demo网站加入作用域且执行时间改为"document-start"以测试效果

执行init或initAll方法后会返回Protector对象 可执行其中的protectFunction方法对指定的自定义函数进行保护

````javascript
window.targetFunc=()=>{};
//保护自定义函数
WebProtect.initAll(()=>{/*...*/},{/*...*/}).protectFunction("targetFunc",window);
````

### 注意

检测项中的"FOUND_PROXY_BY_EXEC_TIME"可能存在误判 谨慎对待

### 特别致谢

MDUI:https://github.com/zdhxiong/mdui

Rikka:https://github.com/RikkaW