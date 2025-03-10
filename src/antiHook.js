class AntiHook {
    //自定义的异常
    #CustomError = class CustomError extends Error {
        constructor(message) {
            super(message);
            this.name = "AntiHook";
        }
    }
    //抛异常检测函数用Symbol
    #envDetectFunctionSymbol = Symbol("_envDetect");
    //检测脚本列表 正则
    #scriptListDetectRegexp = new RegExp("([a-z]|[0-9])\:[0-9]*\:[0-9]*\\)", "igm")
    #crashDetectNoneCrashFunctionsName = new Set(["eval", "fetch", "parseInt", "parseFloat", "isFinite", 
    "isNaN", "decodeURI", "decodeURIComponent", "encodeURI", "encodeURIComponent","log","info","warn","error"
    ,"debug","valueOf"]);
    //返回Promise的方法列表
    #returnPromiseFunctionsName=new Set(["fetch","createImageBitmap","whenDefined","requestWindow","databases"])
    /**
     * @param {string[]} selfScripts 
     * @param {Function} callback 
     */
    constructor(selfScripts = [], callback) {
        /**
         * @type {import("../detectorMain").ScriptDescriptor[]} 自身脚本列表
         */
        this.selfScripts = selfScripts;
        /**
         * @type {Function} 检测到异常时回调
         */
        this.callback = callback;
    }
    //检测类型
    //在下面代码中 对应的检测模块将以//@标注
    static CheckType = {
        SOMETHING_WRONG: -1,//检测器异常
        CONVENTIONAL_TEST: 0, 
        FUTILE_HIDE: 1,
        CRASH_BEHAVIOR_WRONG: 2,
        CRASH_INSTANCE_TYPE: 3,
        LOADED_SCRIPTS_LIST: 4,
        DETECTOR_FUNCTION_MODIFIED: 5,
        FOUND_PROXY: 6,
        FOUND_PROXY_BY_EXEC_TIME:7,
        PROPERTY_DESCRIPTOR_MODIFIED: 8,
        FOUND_INJECTION:9,//发现脚本注入
        LOAD_NOT_ALLOWED_RESOURCES:10,//加载未被允许的资源
        FOUND_BROWSER_EXTENSION:11,//发现浏览器扩展
        CONSOLE_OPENED:12,
    }
    /**
     * @param {string} stack 异常栈字符串
     * @param {string} message 异常消息
     */
    #errorStackAndMessageCheck(stack = "", message = "") {
        //检测对返回内容做出修改的代理
        //@FOUND_PROXY
        if (stack.includes("on proxy:") || stack.includes("Proxy.") || message.includes("proxy")) {
            return { result: true, type: AntiHook.CheckType.FOUND_PROXY }
        }
        //堆栈检测 正常只会有检测脚本和网站自身脚本
        //@LOADED_SCRIPTS_LIST
        const splitStack = stack.split("\n");
        const filteredStack=structuredClone(splitStack);
        for (const stackItem of splitStack) {
            for (const scriptDesc of this.selfScripts) {
                if (stackItem.includes(scriptDesc.value)) {
                    filteredStack.splice(filteredStack.indexOf(stackItem), 1);
                    break
                }
            }
        }
        //被过滤后的脚本名应当以'/'开头
        if (this.#scriptListDetectRegexp.test(filteredStack.join())) {
            // console.log(stack);
            return { result: true, type: AntiHook.CheckType.LOADED_SCRIPTS_LIST }
        }
        return null
    }
    /**
     * 执行时间检测
     * @description 通过执行时间差异检测那些任务过于繁重的Proxy(有点玄学)
     * @param {Function|Object} target 
     * @returns 
     */
    async #executeTimeDetector(target) {
        //@FOUND_PROXY_BY_EXEC_TIME
        try {
            //被freeze的对象无法进行该步骤
            if (!Object.isFrozen(target)) {
                //赋值测试 检测set trap
                performance.mark("execDetectSetStart")
                for (let index = 0; index < 1000; index++) {
                    target["_detectProp"] = "nullptr"
                }
                performance.mark("execDetectSetEnd")
                const execTimeSetPropReport = performance.measure("execDetect", "execDetectSetStart", "execDetectSetEnd");
                //个人测试 PC一般1ms以内 移动端3ms以内
                //10ms以应对部分老设备 具体根据情况来 或者忽略该测试结果
                if (execTimeSetPropReport.duration >= 10) {
                    this.callback(AntiHook.CheckType.FOUND_PROXY_BY_EXEC_TIME)
                }
                //删除属性
                delete target["_detectProp"]
            }
            //读取测试 应对get trap
            //toString方法几乎所有对象都有 而且想绕前面的检测
            //这方法的处理强度一般低不了
            performance.mark("execDetectGetStart")
            for (let index = 0; index < 1000; index++) {
                target["toString"]
            }
            performance.mark("execDetectGetEnd");
            const execTimeGetPropReport = performance.measure("execDetect", "execDetectGetStart", "execDetectGetEnd");
            if (execTimeGetPropReport.duration >= 15) {
                this.callback(AntiHook.CheckType.FOUND_PROXY_BY_EXEC_TIME)
                return
            }
        } catch (error) {
            //正常不会崩溃
            this.callback(AntiHook.CheckType.FOUND_PROXY_BY_EXEC_TIME)
            return
        }
    }
    /**
     * @returns {{result:boolean,type?:number}} 是否发现异常
     * @param {Function} method 方法实例
     * @param {string} name 方法名
     */
    checkGlobalFunction(method, name) {
        if (!(method instanceof Function)) {
            return { result: false }
        }
        //toString返回值及方法本身检测
        //@CONVENTIONAL_TEST
        const detectString = `function ${name}() { [native code] }`;
        try {
            //返回值检测
            if (method.toString.toString.toString() !== "function toString() { [native code] }" ||method.toString.toString() !== "function toString() { [native code] }"|| method.toString() !== detectString) {
                return { result: true, type: AntiHook.CheckType.CONVENTIONAL_TEST };
            }
            //默认的toString方法没有原型
            if (method.toString.prototype !== undefined||method.toString.toString.prototype !== undefined) {
                return { result: true, type: AntiHook.CheckType.CONVENTIONAL_TEST };
            }
        } catch (error) {
            //正常不会崩溃
            return { result: true, type: AntiHook.CheckType.CONVENTIONAL_TEST };
        }
        //@FUTILE_HIDE
        try {
            //检测对toString的修改
            //正常情况下这样调用必定异常
            method.toString.apply(NaN);
            return { result: true, type: AntiHook.CheckType.FUTILE_HIDE };
        } catch (error) {
            if (error instanceof RangeError) {
                return { result: true, type: AntiHook.CheckType.FUTILE_HIDE }
            } else if (!(error instanceof TypeError) || error.message !== "Function.prototype.toString requires that 'this' be a Function") {
                return { result: true, type: AntiHook.CheckType.FUTILE_HIDE }
            }
        }
        /*仅对部分这么做不会崩溃的方法执行该检测
        apply设置一个异常的context
        不崩溃就是有问题 崩溃则检测栈内容*/
        //@CRASH_BEHAVIOR_WRONG
        //@LOADED_SCRIPTS_LIST
        try {
            //返回Promise的函数 特殊处理
            if (this.#returnPromiseFunctionsName.has(name)) {
                let crashed = false;
                method.apply(NaN).catch((reason) => {
                    crashed = true;
                    const checkResult = this.#errorStackAndMessageCheck(reason.stack, reason.message);
                    if (checkResult !== null) {
                        this.callback(checkResult.type)
                        return 
                    }
                }).then(() => {
                    if (!crashed) this.callback(AntiHook.CheckType.CRASH_BEHAVIOR_WRONG)
                })
            } else if(this.#crashDetectNoneCrashFunctionsName.has(name)){
                method.apply(NaN);
                }
            } catch (error) {
                return { result: true, type: AntiHook.CheckType.CRASH_BEHAVIOR_WRONG }
        }
        /*被保护函数内定义一个抛出异常的函数并执行
        如果异常栈或消息中有代理相关内容即为被hook*/
        //防止重复定义
        try {
            if (!method[this.#envDetectFunctionSymbol]) {
                Object.defineProperty(method, this.#envDetectFunctionSymbol, {
                    value: () => {
                        throw new this.#CustomError("Environment detect")
                    }
                });
            }
        } catch (error) {
            const checkResult = this.#errorStackAndMessageCheck(error.stack, error.message);
            if (checkResult !== null) {
                return checkResult
            }
        }
        //篡改检测方法后writeable和configurable会变为true
        //@PROPERTY_DESCRIPTOR_MODIFIED
        const detectingMethodDescriptor = Object.getOwnPropertyDescriptor(method, this.#envDetectFunctionSymbol);
        if (!(detectingMethodDescriptor)||detectingMethodDescriptor.configurable || detectingMethodDescriptor.writable) {
            return { result: true, type: AntiHook.CheckType.PROPERTY_DESCRIPTOR_MODIFIED }
        }
        //获取Symbol并判断
        //需要防止篡改函数导致崩溃
        //@DETECTOR_FUNCTION_MODIFIED
        try {
            method[this.#envDetectFunctionSymbol]();
            //正常执行不到这
            return { result: true, type: AntiHook.CheckType.DETECTOR_FUNCTION_MODIFIED }
        } catch (error) {
            //不是预定的异常
            if (!(error instanceof this.#CustomError)) {
                return { result: true, type: AntiHook.CheckType.DETECTOR_FUNCTION_MODIFIED }
            }
            const checkResult = this.#errorStackAndMessageCheck(error.stack, error.message);
            if (checkResult !== null) {
                return checkResult
            }
        }
        this.#executeTimeDetector(method);
        return { result: false }
    }
    /**
     * 
     * @param {Function} method 方法实例
     * @param {string} name 名称
     * @param {boolean} [isGetter=true] 是否为getter true则是 反之为setter  
     * @returns {{
     * result:boolean,
     * type?:number
     * }}
     */
    checkGetterOrSetter(method,name,isGetter=true) {
        //@CONVENTIONAL_TEST
        const detectString=`function ${isGetter?"get":"set"} ${name}() { [native code] }`;
        try {
            //返回值检测
            if (method.toString.toString() !== "function toString() { [native code] }"|| method.toString() !== detectString) {
                return { result: true, type: AntiHook.CheckType.CONVENTIONAL_TEST };
            }
            //默认toString方法没有原型
            if (method.toString.__proto__.toString() !== "function () { [native code] }"||method.__proto__.toString() !== "function () { [native code] }") {
                return { result: true, type: AntiHook.CheckType.CONVENTIONAL_TEST };
            }
        } catch (error) {
            //正常不会崩溃
            return { result: true, type: AntiHook.CheckType.CONVENTIONAL_TEST };
        }
        try {
            //检测对toString的修改
            //正常情况下这样调用必定异常
            //@FUTILE_HIDE
            method.toString.apply(NaN);
            return { result: true, type: AntiHook.CheckType.FUTILE_HIDE };
        } catch (error) {
            if (error instanceof RangeError) {
                return { result: true, type: AntiHook.CheckType.FUTILE_HIDE }
            } else if (!(error instanceof TypeError) || error.message !== "Function.prototype.toString requires that 'this' be a Function") {
                return { result: true, type: AntiHook.CheckType.FUTILE_HIDE }
            }
        }
        try {
            if (!method[this.#envDetectFunctionSymbol]) {
                Object.defineProperty(method, this.#envDetectFunctionSymbol, {
                    value: () => {
                        throw new this.#CustomError("Environment detect")
                    }
                });
            }
        } catch (error) {
            const checkResult = this.#errorStackAndMessageCheck(error.stack, error.message);
            if (checkResult !== null) {
                return checkResult
            }
        }
        //@PROPERTY_DESCRIPTOR_MODIFIED
        const detectingMethodDescriptor = Object.getOwnPropertyDescriptor(method, this.#envDetectFunctionSymbol);
        if (!(detectingMethodDescriptor)||detectingMethodDescriptor.configurable || detectingMethodDescriptor.writable) {
            return { result: true, type: AntiHook.CheckType.PROPERTY_DESCRIPTOR_MODIFIED }
        }
        //@DETECTOR_FUNCTION_MODIFIED
        try {
            method[this.#envDetectFunctionSymbol]();
            //正常执行不到这
            return { result: true, type: AntiHook.CheckType.DETECTOR_FUNCTION_MODIFIED }
        } catch (error) {
            //不是预定的异常
            if (!(error instanceof this.#CustomError)) {
                return { result: true, type: AntiHook.CheckType.DETECTOR_FUNCTION_MODIFIED }
            }
            const checkResult = this.#errorStackAndMessageCheck(error.stack, error.message);
            if (checkResult !== null) {
                return checkResult
            }
        }
        return {result:false};
    }
    /**
     * 
     * @param {string} name 
     */
    checkObject(name,parent=window){
        /**
         * @type {Function}
         */
        const target = Reflect.get(parent, name);
        if(!(target instanceof Object)) return;
        //toString检测
        //@CONVENTIONAL_TEST
        try {
            const detectStringFunction = `function ${name}() { [native code] }`;
            if (target.toString.toString() !== "function toString() { [native code] }" ||target.toString.toString.toString()!=="function toString() { [native code] }"|| (target.toString() !== detectStringFunction&&target.toString()!==`[object ${name}]`)) {
                return { result: true, type: AntiHook.CheckType.CONVENTIONAL_TEST };
            }
            //默认toString方法没有原型
            if (target.toString.prototype !== undefined||target.toString.toString.prototype !== undefined) {
                return { result: true, type: AntiHook.CheckType.CONVENTIONAL_TEST };
            }
        } catch (error) {
            return { result: true, type: AntiHook.CheckType.CONVENTIONAL_TEST };
        }
        //@FUTILE_HIDE
        try {
            //检测对toString的修改
            //正常情况下这样调用必定异常
            target.toString.apply(NaN);
            return { result: true, type: AntiHook.CheckType.FUTILE_HIDE };
        } catch (error) {
            if (error instanceof RangeError) {
                return { result: true, type: AntiHook.CheckType.FUTILE_HIDE }
            } else if (!(error instanceof TypeError) || error.message !== "Function.prototype.toString requires that 'this' be a Function") {
                return { result: true, type: AntiHook.CheckType.FUTILE_HIDE }
            }
        }
        try {
            if (!target[this.#envDetectFunctionSymbol]) {
                Object.defineProperty(target, this.#envDetectFunctionSymbol, {
                    value: () => {
                        throw new this.#CustomError("Environment detect")
                    },
                    writable:false
                });
            }
        } catch (error) {
            const checkResult = this.#errorStackAndMessageCheck(error.stack, error.message);
            if (checkResult !== null) {
                return checkResult
            }
        }
        //@PROPERTY_DESCRIPTOR_MODIFIED
        const detectingMethodDescriptor = Object.getOwnPropertyDescriptor(target, this.#envDetectFunctionSymbol)??Object.getOwnPropertyDescriptor(target.prototype, this.#envDetectFunctionSymbol);
        if (!(detectingMethodDescriptor)||detectingMethodDescriptor.configurable || detectingMethodDescriptor.writable) {
            //该对象无descriptor
            if (name!=="ShadowRoot") {
                return { result: true, type: AntiHook.CheckType.PROPERTY_DESCRIPTOR_MODIFIED }
            }
        }
        //@DETECTOR_FUNCTION_MODIFIED
        try {
            target[this.#envDetectFunctionSymbol]();
            //正常执行不到这
            return { result: true, type: AntiHook.CheckType.DETECTOR_FUNCTION_MODIFIED }
        } catch (error) {
            //不是预定的异常
            if (!(error instanceof this.#CustomError)) {
                return { result: true, type: AntiHook.CheckType.DETECTOR_FUNCTION_MODIFIED }
            }
            const checkResult = this.#errorStackAndMessageCheck(error.stack, error.message);
            if (checkResult !== null) {
                return checkResult
            }
        }
        this.#executeTimeDetector(target);
        return {result:false}
    }
}

export default AntiHook;