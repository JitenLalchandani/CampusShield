"use strict";

const { contextBridge } = require("electron");

contextBridge.exposeInMainWorld("campusshieldDesktop", {
  isDesktop: true,
  platform: process.platform
});
