/*
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable, TLS interception capable
    proxy server for Application debugging, testing and development.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
*/
import { DashboardPlugin } from '../core/plugin'
import { WebsocketApi } from '../core/ws'

export class MockRestApiPlugin extends DashboardPlugin {
  public name: string = 'api_development'
  public title: string = 'API Development'

  private specs: Map<string, Map<string, JSON>>;

  constructor (websocketApi: WebsocketApi) {
    super(websocketApi)
    this.specs = new Map()
    this.fetchExistingSpecs()
  }

  public initializeTab () : JQuery<HTMLElement> {
    return this.makeTab(this.title, 'fa-connectdevelop')
  }

  public initializeHeader (): JQuery<HTMLElement> {
    return this.makeHeader(this.title)
      .children('div.row')
      .append(
        $('<div></div>')
          .addClass('col-6')
          .addClass('text-right')
          .append(
            $('<button></button>')
              .attr('type', 'button')
              .addClass('btn')
              .addClass('btn-primary')
              .text('Create New API')
              .prepend(
                $('<i></i>')
                  .addClass('fa')
                  .addClass('fa-fw')
                  .addClass('fa-plus-circle')
              )
          )
      )
      .end()
  }

  public initializeBody (): JQuery<HTMLElement> {
    return $('<div></div>')
      .addClass('list-group')
      .addClass('position-relative')
      .append(
        $('<a></a>')
          .attr('href', '#')
          .addClass('list-group-item default text-decoration-none bg-light')
          .attr('data-toggle', 'collapse')
          .attr('data-target', '#api-example-com-path-specs')
          .attr('data-parent', '#proxyDashboard')
          .text('api.example.com ')
          .append(
            $('<span></span>')
              .addClass('badge badge-info')
              .text('3 Resources')
          )
      )
      .append(
        $('<button></button>')
          .addClass('position-absolute fa fa-close ml-auto btn btn-danger remove-api-spec')
          .attr('title', 'Delete api.example.com')
      )
      .append(
        $('<div></div>')
          .addClass('collapse api-path-spec')
          .attr('id', 'api-example-com-path-specs')
          .append(
            $('<div></div>')
              .addClass('list-group-item bg-light')
              .text('/v1/users/')
          )
          .append(
            $('<div></div>')
              .addClass('list-group-item bg-light')
              .text('/v1/groups/')
          )
          .append(
            $('<div></div>')
              .addClass('list-group-item bg-light')
              .text('/v1/messages/')
          )
      )
      .add(
        $('<div></div>')
          .addClass('list-group')
          .addClass('position-relative')
          .append(
            $('<a></a>')
              .attr('href', '#')
              .addClass('list-group-item default text-decoration-none bg-light')
              .attr('data-toggle', 'collapse')
              .attr('data-target', '#my-api')
              .attr('data-parent', '#proxyDashboard')
              .text('my.api ')
              .append(
                $('<span></span>')
                  .addClass('badge badge-info')
                  .text('1 Resource')
              )
          )
          .append(
            $('<button></button>')
              .addClass('position-absolute fa fa-close ml-auto btn btn-danger remove-api-spec')
              .attr('title', 'Delete my.api')
          )
          .append(
            $('<div></div>')
              .addClass('collapse api-path-spec')
              .attr('id', 'my-api')
              .append(
                $('<div></div>')
                  .addClass('list-group-item bg-light')
                  .text('/api/')
              )
          )
      )
  }

  public activated (): void {}

  public deactivated (): void {}

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
