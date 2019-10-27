export class Controls {
    private name = "proxyControls"
  
    constructor () {
      
    }
 

    public enable(){
      $("#"+ this.name + "Section").show();
    }
    
    public disable(){
      $("#"+ this.name + "Section").hide();
    }
}