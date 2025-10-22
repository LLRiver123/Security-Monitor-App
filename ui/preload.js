const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('agentAPI', {
	start: () => ipcRenderer.send('start-agent'),
	stop: () => ipcRenderer.send('stop-agent'),
	onLog: (cb) => ipcRenderer.on('agent-log', (e, data) => cb(data)),
	onExit: (cb) => ipcRenderer.on('agent-exit', (e, data) => cb(data)),
	getPending: () => ipcRenderer.invoke('agent-get-pending'),
	approve: (id) => ipcRenderer.invoke('agent-approve', id),
	onControlUrl: (cb) => ipcRenderer.on('control-url', (e, url) => cb(url)),
})

