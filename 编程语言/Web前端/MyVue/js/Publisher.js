class Publisher {
    constructor(){
        this.sublist = []
    }

    addSub(sub){
        this.sublist.push(sub)
    }

    notify(){
        this.sublist.forEach(sub=>sub.update())
    }
}