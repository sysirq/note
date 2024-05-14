class Compile{
    constructor(mv){
        this.$mv = mv
        this.$el = mv.$el
        this.$data = mv.$data
        //创建文档片段

        //将模板容器中的元素移动到文档片段中，该操作会将模板容器中的元素删除
        //用以减少对dom的操作，提高性能
        let df = this.nodeToFragment()

        //核心：编译工作，对{{}}和指令进行替换
        this.compile(df)

        //移动文档片段中的元素到模板容器中
        this.nodeToDom(df)
    }

    //{{}}格式解析
    compileText(node){
        let pattern = /\{\{(.+?)\}\}/g

        if(node.textContent.match(pattern)){
            let textContent = node.textContent
            let newContent = textContent.replace(pattern,(... args)=>{
                let key = args[1].trim()

                //注册监听器
                new Subscriber(this.$mv,key,()=>{
                    let content = textContent.replace(pattern,(... args)=>{
                        let key = args[1].trim()
                        return this.$data[key]
                    })
                    node.textContent = content
                })

                return this.$data[key]
            })

            node.textContent = newContent
        }

        
    }

    //指令解析
    compileInst(node){
        
        let attrs = Array.from(node.attributes)

        attrs.forEach(element=>{
            
            if(element.name.startsWith("v-")){
                switch(element.nodeName.slice(2)){
                    case "model":
                        node.value = this.$data[element.nodeValue.trim()]
                        
                        let key = element.nodeValue.trim()
                        
                        new Subscriber(this.$mv,key,()=>{
                            node.value = this.$data[key]
                        })

                        element.ownerElement.addEventListener("input",e=>{
                            this.$data[key] = e.target.value
                        })
                        break;
                }
            }
        })
    }

    compile(df){
        
        df.childNodes.forEach(element => {
            if(element.nodeType === 3){//text => {{}}格式的解析
                this.compileText(element)
            }
            else if(element.nodeType === 1){//指令解析
                this.compileInst(element)
            }
            if(element.childNodes && element.childNodes.length>0){
                this.compile(element)
            }
        });
    }

    nodeToFragment(){
        let df = document.createDocumentFragment()
        
        while(this.$el.firstChild){
            df.appendChild(this.$el.firstChild)
        }

        return df
    }

    nodeToDom(df){
       while(df.firstChild){
        this.$el.appendChild(df.firstChild)
       }
    }

}