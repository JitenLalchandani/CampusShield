"use strict";

const path = require("node:path");
const { app, BrowserWindow, Menu, session, shell } = require("electron");
const { start } = require("../src/server");

const APP_NAME = "CampusShield";
const GITHUB_URL = "https://github.com/JitenLalchandani/CampusShield";

let backend = null;
let mainWindow = null;
let quitting = false;

app.setName(APP_NAME);

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on("second-instance", () => {
    if (!mainWindow) return;
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
  });
}

function openExternal(target) {
  try {
    const parsed = new URL(target);
    if (["http:", "https:", "mailto:"].includes(parsed.protocol)) {
      shell.openExternal(target);
    }
  } catch {
    /* ignore malformed links */
  }
}

function buildMenu() {
  const isMac = process.platform === "darwin";

  return Menu.buildFromTemplate([
    ...(isMac
      ? [{
          label: APP_NAME,
          submenu: [
            { role: "about" },
            { type: "separator" },
            {
              label: "Open data folder",
              click: () => shell.openPath(app.getPath("userData"))
            },
            { type: "separator" },
            { role: "hide" },
            { role: "hideOthers" },
            { role: "unhide" },
            { type: "separator" },
            { role: "quit" }
          ]
        }]
      : []),
    {
      label: "Edit",
      submenu: [
        { role: "undo" },
        { role: "redo" },
        { type: "separator" },
        { role: "cut" },
        { role: "copy" },
        { role: "paste" },
        { role: "selectAll" }
      ]
    },
    {
      label: "View",
      submenu: [
        { role: "reload" },
        { role: "forceReload" },
        { type: "separator" },
        { role: "resetZoom" },
        { role: "zoomIn" },
        { role: "zoomOut" },
        { type: "separator" },
        { role: "togglefullscreen" },
        { role: "toggleDevTools" }
      ]
    },
    {
      label: "Window",
      submenu: [
        { role: "minimize" },
        { role: "zoom" },
        ...(isMac
          ? [{ type: "separator" }, { role: "front" }]
          : [{ role: "close" }])
      ]
    },
    {
      role: "help",
      submenu: [
        { label: "Project on GitHub", click: () => openExternal(GITHUB_URL) },
        {
          label: "Open data folder",
          click: () => shell.openPath(app.getPath("userData"))
        }
      ]
    }
  ]);
}

async function createWindow() {
  const origin = `http://127.0.0.1:${backend.port}`;

  const win = new BrowserWindow({
    width: 1360,
    height: 880,
    minWidth: 960,
    minHeight: 620,
    show: false,
    title: APP_NAME,
    backgroundColor: "#070e1c",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false
    }
  });

  win.once("ready-to-show", () => win.show());

  win.webContents.setWindowOpenHandler(({ url }) => {
    openExternal(url);
    return { action: "deny" };
  });

  win.webContents.on("will-navigate", (event, url) => {
    if (!url.startsWith(origin)) {
      event.preventDefault();
      openExternal(url);
    }
  });

  await win.loadURL(origin);
  return win;
}

app.whenReady()
  .then(async () => {
    session.defaultSession.setPermissionRequestHandler(
      (_webContents, _permission, callback) => callback(false)
    );

    backend = await start({
      port: 0,
      host: "127.0.0.1",
      dataDir: path.join(app.getPath("userData"), "data"),
      quiet: true
    });

    Menu.setApplicationMenu(buildMenu());
    mainWindow = await createWindow();

    app.on("activate", async () => {
      if (BrowserWindow.getAllWindows().length === 0) {
        mainWindow = await createWindow();
      }
    });
  })
  .catch(error => {
    console.error("CampusShield desktop failed to start:", error.message);
    app.quit();
  });

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", async event => {
  if (quitting || !backend) return;
  event.preventDefault();
  quitting = true;

  try {
    backend.server.close();
    await backend.store.close();
  } catch {
    /* shutting down */
  }

  app.quit();
});
