const { contextBridge, ipcRenderer } = require('electron')

/**
 * Secure API bridge between renderer and main process
 * Uses contextBridge for proper context isolation
 */
contextBridge.exposeInMainWorld('agentAPI', {
	// Agent control
	start: () => ipcRenderer.invoke('agent-start'),
	stop: () => ipcRenderer.invoke('agent-stop'),
	getStatus: () => ipcRenderer.invoke('agent-status'),
	checkHealth: () => ipcRenderer.invoke('agent-health'),
	
	// Remediation actions
	getPending: () => ipcRenderer.invoke('agent-get-pending'),
	approve: (id) => ipcRenderer.invoke('agent-approve', id),
	reject: (id) => ipcRenderer.invoke('agent-reject', id),
	setConfig: (config) => ipcRenderer.invoke('agent-set-config', config),
	
	// Event listeners (one-way from main to renderer)
	onLog: (callback) => {
		const subscription = (event, data) => callback(data)
		ipcRenderer.on('agent-log', subscription)
		
		// Return unsubscribe function
		return () => ipcRenderer.removeListener('agent-log', subscription)
	},
	
	onControlUrl: (callback) => {
		const subscription = (event, data) => callback(data)
		ipcRenderer.on('control-url', subscription)
		return () => ipcRenderer.removeListener('control-url', subscription)
	},
	
	onAgentExit: (callback) => {
		const subscription = (event, data) => callback(data)
		ipcRenderer.on('agent-exit', subscription)
		return () => ipcRenderer.removeListener('agent-exit', subscription)
	}
	,

	onUserNotification: (callback) => {
		const subscription = (event, data) => callback(data)
		ipcRenderer.on('agent-user', subscription)
		return () => ipcRenderer.removeListener('agent-user', subscription)
	}
})

// Log that preload script loaded successfully
console.log('Preload script loaded successfully')