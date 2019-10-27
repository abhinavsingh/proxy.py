export class Home {
    private name:string = "proxyHome"
  
    constructor () {
      
    }
 
    public enable(){
      $("#"+ this.name + "Section").show();
    }
    
    public disable(){
      $("#"+ this.name + "Section").hide();
    }


}