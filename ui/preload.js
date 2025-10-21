// Preload - intentionally minimal. Extend as needed for secure IPC.
const { contextBridge } = require('electron')

contextBridge.exposeInMainWorld('electron', {
  // placeholder
})
