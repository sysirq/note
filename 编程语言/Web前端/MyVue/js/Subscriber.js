class Subscriber{
    constructor(mv,key,cb){
        this.mv = mv
        this.cb = cb
        this.key = key

        //绑定
        Publisher.target = this
        this.mv.$data[key]
        Publisher.target = null
        
    }

    update(){
        this.cb()
    }
}