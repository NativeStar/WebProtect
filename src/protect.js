import { globalWindowFunction, getGlobalObjects } from "./detectList.js";
import AntiHook from "./antiHook.js";
class Protect {
    /**
     * @param {Function} callback 发现尝试修改时回调
     * @param {{
     * selfScripts:import("../detectorMain.js").ScriptDescriptor[],
     * ignoreChromeExtension:boolean,
     * disableConsoleExecute:boolean,
     * clearLogsOnOpenConsole:boolean
     * }} options 
     */
    constructor(callback, options) {
        /**
         * @type {Function}
         */
        this.callback = callback;
        /**
         * @type {import("../detectorMain.js").ScriptDescriptor[]}
         */
        this.selfScripts = options.selfScripts;
        this.ignoreChromeExtension = options.ignoreChromeExtension;
        this.disableConsoleExecute = options.disableConsoleExecute;
        this.clearLogsOnOpenConsole = options.clearLogsOnOpenConsole;
        Protect.selfInstance = this;
        /**
         * @type {Error}
         * 避免在部分检测时死循环
         */
        this.backupErrorObject = Error;
    }
    /**
     * @type {null|Protect}
     * @static
     * @memberof Protect
     */
    static selfInstance = null;
    static getInstance() {
        return this.selfInstance;
    }
    #initialized = false;
    #functionRedefineBlacklist = new Set(["call", "apply", "bind", "name"]);
    #scriptListDetectRegexp = new RegExp("([a-z]|[0-9])\:[0-9]*\:[0-9]*\\)", "igm");
    /**
     * hook部分方法及对象防止其被用于篡改或本身被篡改
     */
    #initEnvironment() {
        (() => {
            const originMethods = {
                objectDefineProperty: Object.defineProperty.bind(window),
                objectDefineProperties: Object.defineProperties.bind(window),
                reflectDefineProperty: Reflect.defineProperty.bind(window),
                reflectSet: Reflect.set.bind(window),
                ProxyObject: Proxy.bind(window),
                createElement: document.createElement.bind(document),
            };
            Object.freeze(originMethods);
            const objectProxy = new Proxy(Object, {
                get: (target, prop) => {
                    const checkResult = this.#errorStackAndMessageCheck(new this.backupErrorObject().stack);
                    if (checkResult !== null) {
                        this.callback(checkResult.type);
                        return (() => { }).bind(window)
                    }
                    if (prop === "defineProperty") {
                        //返回修改后的方法
                        return (targetDefineProp, prop, descriptor) => {
                            //根据情况选择是否执行
                            if (!(targetDefineProp instanceof Function) || ((targetDefineProp instanceof Function) && !this.#functionRedefineBlacklist.has(prop))) {
                                descriptor ? originMethods.objectDefineProperty(targetDefineProp, prop, descriptor) : originMethods.objectDefineProperty(targetDefineProp, prop);
                            }
                            //执行后返回
                            return targetDefineProp;
                        }
                    } else if (prop === "defineProperties") {
                        return (target, propsObject) => {
                            //要改的属性列表
                            const inputKeys = Reflect.ownKeys(propsObject);
                            const filteredList = {};
                            for (const key of inputKeys) {
                                //阻止篡改原有方法
                                if (!(target instanceof Function) && !this.#functionRedefineBlacklist.has(key)) {
                                    filteredList[key] = propsObject[key];
                                }
                            }
                            return originMethods.objectDefineProperties(target, filteredList)
                        }
                    } else {
                        return target[prop];
                    }
                },
                //阻止修改
                set: (target, prop, value) => {
                    if (!(prop in Object)) {
                        target[prop] = value;
                    } else {
                        console.warn("Can not redefine this property");
                    }
                    return true
                },
                deleteProperty: () => {
                    console.warn("Can not delete property in this protected object");
                    return false
                },
                defineProperty: (target, prop, descriptor) => {
                    if (!(prop in Object)) {
                        descriptor ? originMethods.objectDefineProperty(target, prop, descriptor) : originMethods.objectDefineProperty(target, prop);
                    }
                    return true
                }
            });
            const reflectProxy = new Proxy(window.Reflect, {
                get: (target, prop) => {
                    const checkResult = this.#errorStackAndMessageCheck(new this.backupErrorObject().stack);
                    if (checkResult !== null&&checkResult.type!==AntiHook.CheckType.FOUND_PROXY) {
                        this.callback(checkResult.type);
                        return (() => { }).bind(window)
                    }
                    if (prop === "defineProperty") {
                        //返回修改后的方法
                        return (targetDefineProp, propDefine, descriptor) => {
                            if (!(targetDefineProp instanceof Function) || ((targetDefineProp instanceof Function) && !this.#functionRedefineBlacklist.has(propDefine))) {
                                originMethods.reflectDefineProperty(targetDefineProp, propDefine, descriptor);
                            }
                            return true
                        }
                    } else if (prop === "set") {
                        return (targetDefineProp, propDefine, value, receiver) => {
                            if (!(targetDefineProp instanceof Function) || ((targetDefineProp instanceof Function) && !this.#functionRedefineBlacklist.has(propDefine))) {
                                //如果receiver传undefined 操作会失败
                                return receiver ? originMethods.reflectSet(targetDefineProp, propDefine, value, receiver) : originMethods.reflectSet(targetDefineProp, propDefine, value);
                            }
                            return true;
                        }
                    } else {
                        return target[prop]
                    }
                },
                set: (target, prop, value) => {
                    if (!(prop in Reflect)) {
                        target[prop] = value;
                    } else {
                        console.warn("Can not redefine this property");
                    }
                    return true;
                },
                deleteProperty: () => {
                    console.warn("Can not delete property in this protected object");
                    return false;
                },
                defineProperty: (target, prop, descriptor) => {
                    if (!(prop in Reflect)) {
                        descriptor ? Reflect.defineProperty(target, prop, descriptor) : Reflect.deleteProperty(target, prop);
                    }
                    return true
                }
            });
            //覆盖原本的对象
            Object.defineProperties(window, {
                Object: {
                    get: () => {
                        return objectProxy;
                    },
                    set: () => {
                        console.warn("Can not redefine this protected object");
                    },
                    configurable: false
                },
                Reflect: {
                    get: () => {
                        return reflectProxy;
                    },
                    set: () => {
                        console.warn("Can not redefine this protected object");
                    },
                    configurable: false
                },
                Proxy: {
                    get: () => {
                        return originMethods.ProxyObject;
                    },
                    set: () => {
                        console.warn("Can not redefine this protected object");
                    },
                    configurable: false
                }
            });
            //*createElement hook
            // Object.defineProperty(document, "createElement", {
            //     get: () => {
            //         return (tagName, options) => {
            //             const errorInstance = new this.backupErrorObject();
            //             const errorCheckResult = this.#errorStackAndMessageCheck(errorInstance.stack, errorInstance.message);
            //             if (errorCheckResult !== null) {
            //                 this.callback(errorCheckResult.type);
            //                 return null;
            //             }
            //             return options ? originMethods.createElement(tagName, options) : originMethods.createElement(tagName);
            //         }
            //     },
            //     set: () => {
            //         console.warn("Can not redefine this protected object");
            //     }
            // });
        })();
    }
    /**
     * 
     * @param {string|Symbol} methodName
     * @param {object} parent
     */
    #protect(methodName, parent = window) {
        (() => {
            /**
             * @type {Function}
             */
            const originMethod = Reflect.get(parent, methodName);
            if (!(originMethod instanceof Function)) return;
            const methodProxy = new Proxy(originMethod, {
                set: () => {
                    console.warn("Can not redefine this property");
                    const result = this.#errorStackAndMessageCheck(new Error().stack);
                    if (result !== null) {
                        this.callback(result.type);
                    }
                    return true;
                },
                defineProperty: () => {
                    console.warn("Can not redefine this property");
                    const result = this.#errorStackAndMessageCheck(new Error().stack);
                    if (result !== null) {
                        this.callback(result.type);
                    }
                    return true;
                },
                setPrototypeOf: () => {
                    console.warn("Can not set prototype on this property");
                    return true;
                }
            })
            if (!(originMethod instanceof Function) || !(originMethod instanceof Object)) return
            const descriptor = Reflect.getOwnPropertyDescriptor(parent, methodName);
            //有些会是空
            //并且检测方法是否本身已是不可修改的
            if (!descriptor || !descriptor.configurable) {
                return
            };
            Object.freeze(originMethod);
            /* if (descriptor.writable) {
                parent[methodName] = null;
            } */
            //阻止其他篡改
            Object.defineProperty(parent, methodName, {
                get: () => {
                    return methodProxy
                },
                set: () => {
                    console.warn("Can not redefine this protected method");
                    const result = this.#errorStackAndMessageCheck(new Error().stack);
                    if (result !== null) {
                        this.callback(result.type);
                    }
                },
                configurable: false
            });
        })();
    }
    #protectObject(name, parent) {
        (() => {
            const originParent = parent;
            if (!(originParent instanceof Object)) return;
            const parentProxy = new Proxy(originParent, {
                construct: (target, args) => {
                    if (this.disableConsoleExecute) {
                        const result = this.#errorStackAndMessageCheck(new this.backupErrorObject().stack);
                        if (result !== null) {
                            this.callback(result.type);
                            return {};
                        }
                    }
                    //改为返回Proxy
                    const originInstance = new target(...args);
                    return new Proxy(originInstance, {
                        get: (target, prop) => {
                            const result = target[prop];
                            if (result instanceof Function) return result.bind(target);
                            return result
                        },
                        //阻止通过篡改原型链实现覆盖方法
                        setPrototypeOf: () => {
                            console.warn("Can not set prototype of this object");
                            return true;
                        },
                    });
                },
                set: (target, prop, value) => {
                    //防止篡改构造函数
                    if (prop === "constructor") {
                        console.warn("Can not redefine this property");
                        const result = this.#errorStackAndMessageCheck(new Error().stack);
                        if (result !== null) {
                            this.callback(result.type);
                        }
                        return true;
                    }
                    target[prop] = value;
                    return true;
                },
                defineProperty: (target, prop, descriptor) => {
                    if (prop === "constructor") {
                        console.warn("Can not redefine this property");
                        return true;
                    }
                    Object.defineProperty(target, prop, descriptor);
                    return true;
                },
                //有些对象内函数对this指向有要求 如performance.getEntries
                get: (target, prop) => {
                    if (this.disableConsoleExecute) {
                        const errorInstance = new this.backupErrorObject();
                        const errorCheckResult = this.#errorStackAndMessageCheck(errorInstance.stack, errorInstance.message);
                        if (errorCheckResult !== null) {
                            this.callback(errorCheckResult.type);
                            return target[prop] instanceof Function ? (() => { }).bind(window) : null;
                        }
                    }
                    if (target[prop] instanceof Function) {
                        return target[prop].bind(originParent);
                    }
                    return target[prop];
                },
                setPrototypeOf: () => {
                    console.warn("Can not set prototype on this property");
                    return true;
                }
            })
            Object.defineProperty(window, name, {
                get: () => {
                    if (this.disableConsoleExecute) {
                        const errorInstance = new this.backupErrorObject();
                        const errorCheckResult = this.#errorStackAndMessageCheck(errorInstance.stack, errorInstance.message);
                        if (errorCheckResult !== null) {
                            this.callback(errorCheckResult.type);
                            return window[name] instanceof Function ? (() => { }).bind(window) : null;
                        }
                    }
                    return parentProxy
                },
                set: () => {
                    console.warn("Can not redefine this protected object");
                    const result = this.#errorStackAndMessageCheck(new Error().stack);
                    if (result !== null) {
                        this.callback(result.type);
                    }
                },
                configurable: false
            });
        })();
    }
    /**
     * @param {Object} parent 
     * @param {string} name 
     * @param {TypedPropertyDescriptor} target 
     */
    #protectGetterAndSetter(target, parent, name) {
        if (!target.configurable) return
        /**
         * @type {TypedPropertyDescriptor}
         */
        const descriptor = { configurable: false };
        let originSetter = null;
        if (target.set) {
            originSetter = target.set;
        }
        if (target.get) {
            descriptor.get = target.get;
        }
        descriptor.set = function (value) {
            const protectorInstance = Protect.getInstance();
            if (protectorInstance && protectorInstance.#errorStackAndMessageCheck(new protectorInstance.backupErrorObject().stack)) {
                protectorInstance.callback(AntiHook.CheckType.LOADED_SCRIPTS_LIST)
                // return
            }
            if (originSetter) originSetter.call(this, value);
        }
        Reflect.defineProperty(parent, name, descriptor);
    }
    /**
     * 保护全局方法
     * @description 建议先运行篡改检测 以免无效
     * @param {Function?} successCallback 
     */
    startProtect(successCallback) {
        if (!this.#initialized) {
            this.#initEnvironment();
        }
        //window上的函数
        for (const targetFunctionName of globalWindowFunction) {
            this.#protect(targetFunctionName)
        }
        //对象内函数及对象本身
        for (const targetObj of getGlobalObjects()) {
            if (!targetObj.parent || targetObj.nonProtect) continue;
            //当设定只需要保护时 keys会为空
            if (!targetObj.keys) {
                targetObj.keys = Reflect.ownKeys(targetObj.parent)
            }
            for (const functionName of targetObj.keys) {
                const descriptor = Reflect.getOwnPropertyDescriptor(targetObj.parent, functionName);
                if (descriptor) {
                    if (descriptor.get || descriptor.set) {
                        this.#protectGetterAndSetter(descriptor, targetObj.parent, functionName);
                        continue
                    }
                };
                const originFunction = Reflect.get(targetObj.parent, functionName);
                if (!(originFunction instanceof Function)) continue
                this.#protect(functionName, targetObj.parent)
            }
            if (targetObj.top && targetObj.topName) {
                //获取本身是否可被再次定义
                const descriptor = Reflect.getOwnPropertyDescriptor(window, targetObj.topName);
                if (descriptor && !descriptor.configurable) {
                    console.log(`${targetObj.topName} is not configurable`);
                    continue
                };
                this.#protectObject(targetObj.topName, targetObj.top)
            }
        }
        //将方法检测并保护完成后 开启其他检测
        if (!this.#initialized) {
            // console.clear();
            this.#checkEnvironment();
            this.#initialized = true;
        }
        if (successCallback) successCallback();
    }
    /**
     * 保护自定义函数
     * @example 
     * window.test = function(){}
     * protectFunction("test",window) 
     * @param {string} name 
     */
    protectFunction(name, parent = window) {
        this.#protect(name, parent)
    }
    /**
     * 
     * @param {string} name 
     */
    protectObject(name, parent = window) {
        this.#protectObject(name, parent)
    }
    #errorStackAndMessageCheck(stack = "", message = "") {
        //@FOUND_INJECTION
        if (this.#isTamperMonkeyInject(stack)) {
            return { result: true, type: AntiHook.CheckType.FOUND_INJECTION }
        }
        //检测对返回内容做出修改的代理
        //@FOUND_PROXY
        if (stack.includes("on proxy:") || stack.includes("Proxy.") || message.includes("proxy")) {
            return { result: true, type: AntiHook.CheckType.FOUND_PROXY }
        }
        //堆栈检测 正常只会有检测脚本和网站自身脚本
        const splitStack = stack.split("\n");
        //@LOADED_SCRIPTS_LIST
        //@FOUND_INJECTION
        const filteredStack = structuredClone(splitStack);
        for (const stackItem of splitStack) {
            for (const scriptDesc of this.selfScripts) {
                if (scriptDesc.type === "name") {
                    if (stackItem.includes(scriptDesc.value)) {
                        filteredStack.splice(filteredStack.indexOf(stackItem), 1);
                        break
                    }
                } else {
                    //domain模式
                    //设置的域名需包含http或https
                    if (stackItem.startsWith(scriptDesc.value)) {
                        filteredStack.splice(filteredStack.indexOf(stackItem), 1);
                        break
                    }
                }
            }
        }
        //检测控制台执行特征
        if (this.disableConsoleExecute && filteredStack.length > 0) {
            if (splitStack[splitStack.length - 1].includes("at <anonymous>:")) return { result: true, type: AntiHook.CheckType.FOUND_INJECTION }
        }
        //被过滤后的脚本名应当以'/'开头
        if (this.#scriptListDetectRegexp.test(filteredStack.join())) {
            //忽略chrome扩展
            if (this.ignoreChromeExtension && filteredStack.join().includes("chrome-extension://")) {
                return null
            }
            // console.log(stack);
            return { result: true, type: AntiHook.CheckType.LOADED_SCRIPTS_LIST }
        }
        return null
    }
    #checkEnvironment() {
        //*检测dom
        //@LOAD_NOT_ALLOWED_RESOURCES
        const ob = new MutationObserver((mutationsList) => {
            for (const mutation of mutationsList) {
                if (mutation.addedNodes.length !== 0) {
                    //添加元素
                    for (const addedNode of mutation.addedNodes) {
                        if (addedNode instanceof HTMLScriptElement || addedNode instanceof HTMLLinkElement) {
                            const checkResult = this.#checkScriptOrLinkElement(addedNode);
                            if (checkResult.result) {
                                addedNode?.remove();
                                this.callback(checkResult.type);
                            }
                        }
                    }
                } else if (mutation.type === "attributes") {
                    const checkResult = this.#checkScriptOrLinkElement(mutation.target);
                    if (checkResult.result) {
                        mutation.target?.remove();
                        this.callback(checkResult.result);
                    }
                }
            }
        });
        ob.observe(document, { subtree: true, childList: true, attributes: true, attributeFilter: ["src", "href"] });
        //扫描元素列表
        const scriptElements = document.getElementsByTagName("script");
        for (const scriptElement of scriptElements) {
            const checkResult = this.#checkScriptOrLinkElement(scriptElement);
            if (checkResult.result) {
                this.callback(checkResult.type);
            }
        }
        const linkElements = document.getElementsByTagName("link");
        for (const linkElement of linkElements) {
            const checkResult = this.#checkScriptOrLinkElement(linkElement);
            if (checkResult.result) {
                this.callback(checkResult.type);
            }
        }
        //监听异常并判断
        addEventListener("error", event => {
            //跨域的脚本异常没法检测
            if (!event.error) return;
            //文件名检测
            if (this.#loadFileCheck(event.filename)) {
                this.callback(AntiHook.CheckType.LOAD_NOT_ALLOWED_RESOURCES)
            };
            //堆栈和消息检测
            const checkResult = this.#errorStackAndMessageCheck(event.error.stack, event.error.message);
            if (checkResult !== null) {
                this.callback(checkResult.type);
            }
        });
        //循环扫描所有资源 10秒一次
        //@LOADED_SCRIPTS_LIST
        setInterval(() => {
            const loadedResources = performance.getEntriesByType("resource");
            for (const resItem of loadedResources) {
                if (resItem.initiatorType === "script") {
                    if (this.#loadFileCheck(resItem.name)) {
                        this.callback(AntiHook.CheckType.LOADED_SCRIPTS_LIST);
                    }
                }
            }
        }, 10 * 1000);
        //控制台检测1
        let triggerConsoleDetectCount = 0;
        console.log(Object.defineProperties(new this.backupErrorObject, {
            message: {
                get() {
                    if (triggerConsoleDetectCount > 0) {
                        //!部分浏览器在此时清空日志会让页面崩溃(试了两个Chromium内核的)
                        //!也许可以利用下?
                        const protectorInstance=Protect.getInstance();
                        if(protectorInstance.clearLogsOnOpenConsole) console.clear();
                        Protect.getInstance().callback(AntiHook.CheckType.CONSOLE_OPENED);
                    }
                    triggerConsoleDetectCount++;
                }
            },
        }));
        //控制台检测2
        const consoleDetectLoop=setInterval(() => {
            performance.mark("debuggerDetectStart");
            //避免部分检测到eval内有debugger就直接把整段删了的
            try {
                eval(`const num=0;d\ebug\ger;
                    if(!num||num!==0) throw new Error("debuggerDetect")`);
            } catch (error) {
                if (error.message.includes("num")) {
                    //尝试绕过控制台检测
                    this.callback(AntiHook.CheckType.CONSOLE_OPENED);
                    clearInterval(consoleDetectLoop);
                }
            }
            performance.mark("debuggerDetectEnd");
            if (performance.measure("debuggerDetect", "debuggerDetectStart", "debuggerDetectEnd").duration > 25) {
                Protect.getInstance().callback(AntiHook.CheckType.CONSOLE_OPENED);
                clearInterval(consoleDetectLoop);
            }
        }, 100);
    }
    //@FOUND_INJECTION
    #isTamperMonkeyInject(stack = "") {
        return stack.includes("userscript.html")
    }
    /**
     * 检测追加或篡改的元素
     * @returns {{
     * result:boolean,
     * type?:AntiHook.CheckType
     * }}
     * @param {HTMLScriptElement|HTMLLinkElement} element 
     */
    #checkScriptOrLinkElement(element) {
        if (element instanceof HTMLScriptElement) {
            if(element.src==="") return { result: false }
            if (element.src.startsWith("chrome-extension://")) {
                // if (this.ignoreChromeExtension) {
                //     return { result: false }
                // }
                return { result: true, type: AntiHook.CheckType.FOUND_BROWSER_EXTENSION };
            }
            for (const scriptDesc of this.selfScripts) {
                if (scriptDesc.type === "name" && element.src.endsWith(scriptDesc)) {
                    return { result: true, type: AntiHook.CheckType.LOAD_NOT_ALLOWED_RESOURCES };
                } else if (scriptDesc.type === "domain" && element.src.startsWith(scriptDesc)) {
                    return { result: true, type: AntiHook.CheckType.LOAD_NOT_ALLOWED_RESOURCES };
                }
            }
            return false
        } else if (element instanceof HTMLLinkElement) {
            if(element.href==="") return { result: false };
            if (element.href.startsWith("chrome-extension://")) {
                // if (this.ignoreChromeExtension) {
                //     return { result: false }
                // }
                return { result: true, type: AntiHook.CheckType.FOUND_BROWSER_EXTENSION };
            }
            for (const scriptDesc of this.selfScripts) {
                if (scriptDesc.type === "name" && element.href.endsWith(scriptDesc)) {
                    return { result: true, type: AntiHook.CheckType.LOAD_NOT_ALLOWED_RESOURCES };
                } else if (scriptDesc.type === "domain" && element.href.startsWith(scriptDesc)) {
                    return { result: true, type: AntiHook.CheckType.LOAD_NOT_ALLOWED_RESOURCES };
                }
            }
            return { result: false }
        }
        return { result: false }
    }

    #loadFileCheck(url = "") {
        if (url === "") return;
        for (const scriptDesc of this.selfScripts) {
            if (scriptDesc.type === "name" && url.endsWith(scriptDesc.value)) {
                return false;
            } else if (scriptDesc.type === "domain" && url.startsWith(scriptDesc.value)) {
                return false;
            }
        }
        return true
    }
}
export default Protect;