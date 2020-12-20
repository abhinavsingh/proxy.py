//
//  AppDelegate.swift
//  proxy.py
//
//  Created by Abhinav Singh on 11/22/19.
//  Copyright © 2013-present by Abhinav Singh and contributors.
//  All rights reserved.
//

import Cocoa
import SwiftUI

@NSApplicationMain
class AppDelegate: NSObject, NSApplicationDelegate {

    var window: NSWindow!
    var statusItem: NSStatusItem!
    var preferences: NSPopover!

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        // Create the SwiftUI view that provides the window contents.
        let contentView = ContentView()

        self.statusItem = NSStatusBar.system.statusItem(withLength:NSStatusItem.variableLength)

        self.preferences = NSPopover()
        preferences.contentSize = NSSize(width: 400, height: 500)
        preferences.behavior = .transient
        preferences.contentViewController = NSHostingController(rootView: contentView)

        if let button = statusItem.button {
            button.image = NSImage(named:NSImage.Name("StatusBarButtonImage"))
            // button.action = #selector(closePreferences)
        }
        constructMenu()
    }

    func applicationWillTerminate(_ aNotification: Notification) {
        // Insert code here to tear down your application
        print("Tearing down")
    }

    func constructMenu() {
        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "proxy.py is running", action: #selector(AppDelegate.status(_:)), keyEquivalent: "S"))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "About proxy.py", action: #selector(AppDelegate.about(_:)), keyEquivalent: "A"))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Preferences", action: #selector(AppDelegate.preferences(_:)), keyEquivalent: ","))
        menu.addItem(NSMenuItem(title: "Dashboard", action: #selector(AppDelegate.dashboard(_:)), keyEquivalent: "D"))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Report a bug", action: #selector(AppDelegate.reportbug(_:)), keyEquivalent: "B"))
        menu.addItem(NSMenuItem(title: "Learn", action: #selector(AppDelegate.learn(_:)), keyEquivalent: "L"))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Restart", action: #selector(AppDelegate.restart(_:)), keyEquivalent: "R"))
        menu.addItem(NSMenuItem(title: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "Q"))
        statusItem.menu = menu
    }

    @objc func status(_ sender: Any?) {
        print("Status clicked")
    }

    @objc func about(_ sender: Any?) {
        print("About clicked")
    }

    @objc func closePreferences(_ sender: Any?) {
        if self.statusItem.button != nil {
            if self.preferences.isShown {
                self.preferences.performClose(sender)
            }
        }
    }

    @objc func preferences(_ sender: Any?) {
        print("Preferences clicked")
        if let button = self.statusItem.button {
            self.preferences.show(relativeTo: button.bounds, of: button, preferredEdge: NSRectEdge.minY)
            self.preferences.contentViewController?.view.window?.becomeKey()
        }
    }

    @objc func dashboard(_ sender: Any?) {
        print("Dashboard clicked")
    }

    @objc func reportbug(_ sender: Any?) {
        print("Report bug clicked")
    }

    @objc func learn(_ sender: Any?) {
        print("Learn clicked")
    }

    @objc func restart(_ sender: Any?) {
        print("Restart clicked")
    }
}

struct AppDelegate_Previews: PreviewProvider {
    static var previews: some View {
        /*@START_MENU_TOKEN@*/Text("Hello, World!")/*@END_MENU_TOKEN@*/
    }
}
