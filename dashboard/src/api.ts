export class ApiDevelopment {
    private specs: Map<string, Map<string, JSON>>;
  
    constructor () {
      this.specs = new Map()
      this.fetchExistingSpecs()
    }
  
    private fetchExistingSpecs () {
      // TODO: Fetch list of currently configured APIs from the backend
      const apiExampleOrgSpec = new Map()
      apiExampleOrgSpec.set('/v1/users/', {
        count: 2,
        next: null,
        previous: null,
        results: [
          {
            email: 'you@example.com',
            groups: [],
            url: 'api.example.org/v1/users/1/',
            username: 'admin'
          },
          {
            email: 'someone@example.com',
            groups: [],
            url: 'api.example.org/v1/users/2/',
            username: 'someone'
          }
        ]
      })
      this.specs.set('api.example.org', apiExampleOrgSpec)
    }
}