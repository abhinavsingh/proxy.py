/*
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable, TLS interception capable
    proxy server for Application debugging, testing and development.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
*/

import { DashboardPlugin} from "../core/plugin";

export class MockRestApiPlugin extends DashboardPlugin {
  private specs: Map<string, Map<string, JSON>>;

  constructor (name: string) {
    super(name)
    this.specs = new Map()
    this.fetchExistingSpecs()
  }

  public initializeTab() : JQuery<HTMLElement> {
    return this.makeTab('API Development', 'fa-connectdevelop')
  }

  public initializeAppSkeleton(): JQuery<HTMLElement> {
    return $('<div></div>')
      .attr('id', 'app-header')
      .append(
        $('<div></div>')
          .addClass('container-fluid')
          .append(
            $('<div></div>')
              .addClass('row')
              .append(
                $('<div></div>')
                  .addClass('col-6')
                  .append(
                    $('<p></p>')
                      .addClass('h3')
                      .text('API Development')
                  )
              )
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
          )
      )
      .add(
        $('<div></div>')
          .attr('id', 'app-body')
          .append(
            $('<div></div>')
              .addClass('list-group')
              .addClass('position-relative')
          )
          .append(
            $('<div></div>')
              .addClass('list-group')
              .addClass('position-relative')
          )
      )
  }

  public activated(): void {}

  public deactivated(): void {}

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
