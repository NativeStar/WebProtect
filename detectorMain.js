import AntiHook from "./src/antiHook.js";
import Protect from "./src/protect.js";
import { globalWindowFunction, getGlobalObjects } from "./src/detectList.js";
/**
 * @typedef {{type:"domain"|"name",value:string}} ScriptDescriptor
 */
/**
 * @typedef {{
* selfScripts:ScriptDescriptor[],
* checkGlobalFunctionHook:boolean,
* checkGlobalObjectHook:boolean,
* enableProtect:boolean
* ignoreChromeExtension:boolean,
* disableConsoleExecute:boolean,
* clearLogsOnOpenConsole:boolean
 * }} WebProtectOption
 */
class WebProtect {
    /**
     * @private
     * @static
     * @type {{
     *      antiHook:Function|null
     * }} 
     * @memberof WebProtect
     */
    static #instances = {
        antiHook: null,
    };
    static #status = {
        isProtected: false
    };
    static #functionNameWhitelist=new Set(["constructor","toString","apply","bind","call","Symbol(Symbol.hasInstance)","Symbol(Symbol.toStringTag)","arguments","caller"]);
    /**
     * 初始化全部功能
     * @param {Function} callback 发现异常时回调
     * @param {WebProtectOption} options 
     * @returns {Protect|null}
     */
    static initAll(callback, options) {
        return this.init(callback, {
            checkGlobalFunctionHook: true,
            checkGlobalObjectHook: true,
            enableProtect: true,
            ignoreChromeExtension:true,
            disableConsoleExecute:false,
            clearLogsOnOpenConsole:false,
            ...options,
        })
    }
    /**
     * 初始化部分功能
     * @param {Function} callback 发现异常时回调
     * @param {WebProtectOption} options 功能设置
     * @returns {Protect|null}
     */
    static init(callback, options) {
        //checkGlobalFunctionHook
        try {
            if (options.selfScripts instanceof Array) {
                //自带脚本列表
                options.selfScripts.push(...[{type:"name",value:"detectorMain.js"},{type:"name",value:"antiHook.js"},{type:"name",value:"protect.js"},{type:"name",value:"detectList.js"}])
                // options.selfScripts.push(...["detectorMain.js","antiHook.js","protect.js","detectList.js"]);
            }else{
                options.selfScripts=["detectorMain.js","antiHook.js","protect.js","detectList.js"];
            }
            //window上的函数
            /**
             * @type {AntiHook}
             */
            const antiHookInstance = this.#instances.antiHook !== null ? this.#instances.antiHook : new AntiHook(options.selfScripts, callback);
            this.#instances.antiHook = antiHookInstance;
            if (options.checkGlobalFunctionHook) {
                for (const functionName of globalWindowFunction) {
                    const originFunction = Reflect.get(window, functionName);
                    const checkResult = antiHookInstance.checkGlobalFunction(originFunction, functionName)
                    if (checkResult.result) {
                        callback(checkResult.type);
                        // return
                    }
                }
                //window上对象内的函数
                for (const targetObj of getGlobalObjects()) {
                    if (!targetObj.parent) continue;
                    //keys为空 先获取内容
                    if (!targetObj.keys) {
                        targetObj.keys = Reflect.ownKeys(targetObj.parent)
                    }
                    for (const functionName of targetObj.keys) {
                        //部分方法和Symbol会出问题
                        if (this.#functionNameWhitelist.has(functionName)||typeof functionName==="symbol") continue;
                        if (targetObj.detectExclude&&targetObj.detectExclude.includes(functionName)) continue;
                        //getter和setter另外处理
                        const descriptor = Reflect.getOwnPropertyDescriptor(targetObj.parent, functionName);
                        if (descriptor) {
                            if (descriptor.get) {
                                const checkResult=antiHookInstance.checkGetterOrSetter(descriptor.get, functionName, true);
                                if (checkResult.result) {
                                    callback(checkResult.type);
                                }
                            }
                            if (descriptor.set) {
                                const checkResult=antiHookInstance.checkGetterOrSetter(descriptor.set, functionName, false);
                                if (checkResult.result) {
                                    callback(checkResult.type);
                                }
                            }
                            //已经处理完成 不需要执行后面的
                            if (descriptor.get) continue
                        };
                        //检测项排除
                        const originFunction = Reflect.get(targetObj.parent, functionName);
                        if (!(originFunction instanceof Function)) continue
                        const checkResult = antiHookInstance.checkGlobalFunction(originFunction, functionName)
                        if (checkResult.result) {
                            callback(checkResult.type)
                            // return
                        }
                    }
                }
            }
            if (options.checkGlobalObjectHook) {
                for (const globalObjectItem of getGlobalObjects()) {
                    // console.log(globalObjectItem,globalObjectItem.top);
                    if(globalObjectItem.enableHookDetect===false) {
                        continue
                    }
                    const checkResult=antiHookInstance.checkObject(globalObjectItem.topName);
                    if (checkResult.result) {
                        callback(checkResult.type)
                    }
                }
            }
            //enableProtect
            //避免重复执行保护 会异常
            if(this.#status.isProtected) return
            if (options.enableProtect) {
                const protectorInstance = new Protect(callback,options);
                protectorInstance.startProtect(() => {
                    // console.clear();
                    console.log("Protected");
                    this.#status.isProtected = true;
                });
                return protectorInstance;
            }
        } catch (error) {
            //检测脚本异常
            callback(AntiHook.CheckType.SOMETHING_WRONG)
            console.warn(error);
            return null
        }
    }
}
export default WebProtect;
export {
    AntiHook
}