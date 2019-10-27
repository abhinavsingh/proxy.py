export class ShortLinks {
    private name:string = "proxyShortLinks"
    private links: Map<string, string>;
  
    constructor () {
      this.links = new Map()
      this.fetchExistingLinks()
    }

    private fetchExistingLinks () {

    }

    public enable(){
      $("#"+ this.name + "Section").show();
    }
    
    public disable(){
      $("#"+ this.name + "Section").hide();
    }


}