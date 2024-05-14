class MyVue {
    constructor(option){
        this.$el = document.querySelector(option.el)
        this.$data = option.data

        //数据代理:this.msg === this.$data.msg
        this.proxyData()

        //数据劫持
        this.dataHack()

        //文档编译：对指令和{{}}进行替换
        this.compile = new Compile(this)
    }

    dataHack(){
        let pub = new Publisher()

        Object.keys(this.$data).forEach(key=>{
            let val = this.$data[key]
            Object.defineProperty(this.$data,key,
                {
                    get() { 
                        Publisher.target && pub.addSub(Publisher.target) 
                        return val;
                    },
                    set(newValue) { 
                        val = newValue; 
                        pub.notify()
                    },
                    enumerable : true,
                    configurable : false
                }
            )
        })

    }

    proxyData(){
        for(let key in this.$data){
            Object.defineProperty(this,key,{
                get() { return this.$data[key]; },
                set(newValue) { this.$data[key] = newValue; },
                enumerable : true,
                configurable : false
            })
        }
    }
}