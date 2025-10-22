const { app, BrowserWindow, ipcMain } = require('electron')
const path = require('path')
const { spawn } = require('child_process')
const fs = require('fs')

let mainWindow = null
let pyProc = null
let controlUrl = null
let controlToken = null

function findPythonExecutable() {
	const repoRoot = path.join(__dirname, '..')
	const envPaths = [process.env.REPO_PYTHON, process.env.PYTHON_EXECUTABLE, process.env.VENV_PYTHON]
	for (const p of envPaths) {
		if (p && fs.existsSync(p)) return p
	}

	const candidates = [
		path.join(repoRoot, 'venv-a', 'Scripts', 'python.exe'),
		path.join(repoRoot, 'venv', 'Scripts', 'python.exe'),
		path.join(repoRoot, '.venv', 'Scripts', 'python.exe'),
	]
	for (const c of candidates) {
		if (fs.existsSync(c)) return c
	}
	return 'python'
}

function createWindow() {
	mainWindow = new BrowserWindow({
		width: 800,
		height: 600,
		webPreferences: {
			preload: path.join(__dirname, 'preload.js'),
		},
	})

	mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'))
}

function startAgent() {
	if (pyProc) return
	const script = path.join(__dirname, '..', 'main.py')
	// Prefer repo venv python when available
	const pythonExe = findPythonExecutable()
	if (mainWindow) mainWindow.webContents.send('agent-log', `Starting python: ${pythonExe}`)
	pyProc = spawn(pythonExe, [script], { cwd: path.join(__dirname, '..') })

	pyProc.stdout.on('data', (data) => {
		const text = data.toString()

		// detect control server URL printed by agent
		const m1 = text.match(/Control API listening on (https?:\/\/[^\s]+)/)
		const m2 = text.match(/Control server serving on (https?:\/\/[^\s]+)/)
		const url = (m1 && m1[1]) || (m2 && m2[1])
		if (url) {
			controlUrl = url.replace(/\/$/, '')
			if (mainWindow) mainWindow.webContents.send('control-url', controlUrl)
		}
		if (mainWindow) mainWindow.webContents.send('agent-log', text)
	})

	pyProc.stderr.on('data', (data) => {
		const text = data.toString()
		if (mainWindow) mainWindow.webContents.send('agent-log', text)
	})

	pyProc.on('exit', (code, signal) => {
		if (mainWindow) mainWindow.webContents.send('agent-exit', { code, signal })
		pyProc = null
	})
}

// Helper to perform HTTP requests to the control API
function httpRequest(method, url, body) {
	return new Promise((resolve, reject) => {
		try {
			const parsed = new URL(url)
			const httpMod = parsed.protocol === 'https:' ? require('https') : require('http')
					const opts = {
				method: method,
				hostname: parsed.hostname,
				port: parsed.port,
				path: parsed.pathname + (parsed.search || ''),
				headers: {
					'Content-Type': 'application/json',
				},
			}
					// attach token from control.json if available
					if (controlToken) opts.headers['X-Auth-Token'] = controlToken

			const req = httpMod.request(opts, (res) => {
				let chunks = ''
				res.on('data', (d) => (chunks += d.toString()))
				res.on('end', () => {
					try {
						const json = chunks ? JSON.parse(chunks) : null
						resolve({ statusCode: res.statusCode, body: json })
					} catch (e) {
						resolve({ statusCode: res.statusCode, body: chunks })
					}
				})
			})
			req.on('error', (err) => reject(err))
			if (body) req.write(JSON.stringify(body))
			req.end()
		} catch (e) {
			reject(e)
		}
	})
}

// IPC handlers for renderer to query/approve pending requests
ipcMain.handle('agent-get-pending', async () => {
	if (!controlUrl) return { error: 'no-control-url' }
	const url = controlUrl + '/pending'
	try {
		const res = await httpRequest('GET', url)
		return res.body
	} catch (e) {
		return { error: String(e) }
	}
})

ipcMain.handle('agent-approve', async (evt, id) => {
	if (!controlUrl) return { error: 'no-control-url' }
	const url = controlUrl + '/approve'
	try {
		const res = await httpRequest('POST', url, { id })
		return res.body
	} catch (e) {
		return { error: String(e) }
	}
})

function stopAgent() {
	if (!pyProc) return
	try {
		pyProc.kill()
	} catch (e) {
		// ignore
	}
	pyProc = null
}

app.whenReady().then(() => {
	createWindow()

	// read control.json for discovery (agent may be started separately)
	function tryReadControlFile() {
		try {
			const file = path.join(__dirname, '..', 'agent', 'control.json')
			if (fs.existsSync(file)) {
				const raw = fs.readFileSync(file, 'utf8')
				const info = JSON.parse(raw)
				if (info && info.url) {
					controlUrl = info.url.replace(/\/$/, '')
					controlToken = info.token || null
					if (mainWindow) mainWindow.webContents.send('control-url', controlUrl)
				}
			}
		} catch (e) {
			console.error('read control file error', e)
		}
	}

	tryReadControlFile()
	setInterval(tryReadControlFile, 3000)

	ipcMain.on('start-agent', () => startAgent())
	ipcMain.on('stop-agent', () => stopAgent())

	app.on('activate', function () {
		if (BrowserWindow.getAllWindows().length === 0) createWindow()
	})
})

app.on('before-quit', () => {
	stopAgent()
})

