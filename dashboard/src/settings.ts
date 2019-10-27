export class Settings {
    private name:string = "proxySettings"
  
    constructor () {
      
    }
 

    public enable(){
      $("#"+ this.name + "Section").show();
    }
    
    public disable(){
      $("#"+ this.name + "Section").hide();
    }

}