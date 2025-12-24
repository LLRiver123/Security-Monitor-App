const { app, BrowserWindow, ipcMain } = require('electron')
const path = require('path')
const { spawn } = require('child_process')
const fs = require('fs')

let mainWindow = null
let pyProc = null
let controlUrl = null
let controlToken = null
let controlFileWatcher = null
let agentRestartAttempts = 0
const MAX_RESTART_ATTEMPTS = 3
const RESTART_DELAY = 5000

/**
 * Find Python executable in order of priority
 */
function findPythonExecutable() {
	const repoRoot = path.join(__dirname, '..')
	
	// Check environment variables first
	const envPaths = [
		process.env.REPO_PYTHON,
		process.env.PYTHON_EXECUTABLE,
		process.env.VENV_PYTHON
	]
	
	for (const p of envPaths) {
		if (p && fs.existsSync(p)) {
			console.log(`Found Python from env: ${p}`)
			return p
		}
	}

	// Check common venv locations
	const candidates = [
		path.join(repoRoot, 'venv-a', 'Scripts', 'python.exe'),
		path.join(repoRoot, 'venv', 'Scripts', 'python.exe'),
		path.join(repoRoot, '.venv', 'Scripts', 'python.exe'),
		path.join(repoRoot, 'venv-a', 'bin', 'python'),
		path.join(repoRoot, 'venv', 'bin', 'python'),
		path.join(repoRoot, '.venv', 'bin', 'python'),
	]
	
	for (const c of candidates) {
		if (fs.existsSync(c)) {
			console.log(`Found Python venv: ${c}`)
			return c
		}
	}
	
	console.log('Using system Python')
	return process.platform === 'win32' ? 'python' : 'python3'
}

/**
 * Create main application window
 */
function createWindow() {
	mainWindow = new BrowserWindow({
		width: 1000,
		height: 700,
		minWidth: 800,
		minHeight: 600,
		webPreferences: {
			preload: path.join(__dirname, 'preload.js'),
			contextIsolation: true,
			nodeIntegration: false,
			sandbox: true
		},
	})

	mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'))
	
	// Uncomment for debugging
	// mainWindow.webContents.openDevTools()

	mainWindow.on('closed', () => {
		mainWindow = null
	})
}

/**
 * Send log message to renderer if window exists
 */
function sendLog(message, level = 'info') {
	console.log(`[${level.toUpperCase()}] ${message}`)
	if (mainWindow && !mainWindow.isDestroyed()) {
		mainWindow.webContents.send('agent-log', {
			message,
			level,
			timestamp: new Date().toISOString()
		})
	}
}

/**
 * Read control.json file for agent discovery
 */
function readControlFile() {
	try {
		const controlFile = path.join(__dirname, '..', 'agent', 'control.json')
		
		if (!fs.existsSync(controlFile)) {
			return null
		}

		const raw = fs.readFileSync(controlFile, 'utf8')
		const info = JSON.parse(raw)
		
		if (info && info.url) {
			const newUrl = info.url.replace(/\/$/, '')
			const newToken = info.token || null
			
			// Only update if changed
			if (newUrl !== controlUrl || newToken !== controlToken) {
				controlUrl = newUrl
				controlToken = newToken
				sendLog(`Control API discovered: ${controlUrl}`)
				
				if (mainWindow && !mainWindow.isDestroyed()) {
					mainWindow.webContents.send('control-url', {
						url: controlUrl,
						hasToken: !!controlToken
					})
				}
			}
			
			return info
		}
	} catch (e) {
		if (e.code !== 'ENOENT') {
			sendLog(`Error reading control file: ${e.message}`, 'error')
		}
	}
	return null
}

/**
 * Watch control.json for changes
 */
function watchControlFile() {
	if (controlFileWatcher) {
		controlFileWatcher.close()
	}

	const controlFile = path.join(__dirname, '..', 'agent', 'control.json')
	const controlDir = path.dirname(controlFile)

	// Ensure directory exists
	if (!fs.existsSync(controlDir)) {
		fs.mkdirSync(controlDir, { recursive: true })
	}

	try {
		controlFileWatcher = fs.watch(controlDir, (eventType, filename) => {
			if (filename === 'control.json') {
				readControlFile()
			}
		})
	} catch (e) {
		sendLog(`Could not watch control file: ${e.message}`, 'warn')
		// Fallback to polling
		setInterval(readControlFile, 3000)
	}
}

/**
 * Start Python agent process
 */
function startAgent() {
	if (pyProc) {
		sendLog('Agent already running', 'warn')
		return
	}

	const script = path.join(__dirname, '..', 'main.py')
	
	if (!fs.existsSync(script)) {
		sendLog(`Python script not found: ${script}`, 'error')
		return
	}

	const pythonExe = findPythonExecutable()
	sendLog(`Starting agent: ${pythonExe} ${script}`)

	try {
		pyProc = spawn(pythonExe, [script], {
			cwd: path.join(__dirname, '..'),
			env: { ...process.env, PYTHONUNBUFFERED: '1' }
		})

		pyProc.stdout.on('data', (data) => {
			const text = data.toString()
			sendLog(text.trim(), 'info')

			// Detect control server URL from stdout
			const m1 = text.match(/Control API listening on (https?:\/\/[^\s]+)/)
			const m2 = text.match(/Control server serving on (https?:\/\/[^\s]+)/)
			const url = (m1 && m1[1]) || (m2 && m2[1])
			
			if (url) {
				controlUrl = url.replace(/\/$/, '')
				sendLog(`Control URL detected: ${controlUrl}`)
				if (mainWindow && !mainWindow.isDestroyed()) {
					mainWindow.webContents.send('control-url', {
						url: controlUrl,
						hasToken: !!controlToken
					})
				}
			}
		})

		pyProc.stderr.on('data', (data) => {
			const text = data.toString()
			sendLog(text.trim(), 'error')
		})

		pyProc.on('error', (error) => {
			sendLog(`Agent process error: ${error.message}`, 'error')
			pyProc = null
		})

		pyProc.on('exit', (code, signal) => {
			const exitMsg = signal 
				? `Agent exited with signal: ${signal}`
				: `Agent exited with code: ${code}`
			
			sendLog(exitMsg, code === 0 ? 'info' : 'warn')
			
			if (mainWindow && !mainWindow.isDestroyed()) {
				mainWindow.webContents.send('agent-exit', { code, signal })
			}
			
			pyProc = null
			controlUrl = null
			controlToken = null

			// Auto-restart on unexpected exit
			if (code !== 0 && code !== null && agentRestartAttempts < MAX_RESTART_ATTEMPTS) {
				agentRestartAttempts++
				sendLog(`Auto-restarting agent (attempt ${agentRestartAttempts}/${MAX_RESTART_ATTEMPTS})`, 'warn')
				setTimeout(() => startAgent(), RESTART_DELAY)
			} else if (agentRestartAttempts >= MAX_RESTART_ATTEMPTS) {
				sendLog('Max restart attempts reached. Please check logs and restart manually.', 'error')
			}
		})

		// Reset restart counter on successful start
		agentRestartAttempts = 0

	} catch (e) {
		sendLog(`Failed to start agent: ${e.message}`, 'error')
		pyProc = null
	}
}

/**
 * Stop Python agent process gracefully
 */
function stopAgent() {
    if (!pyProc) {
        sendLog('No agent process to stop', 'info')
        return
    }

    sendLog('Stopping agent...', 'info')

    if (process.platform === 'win32') {
        // 💡 Bước 1: Gửi tín hiệu dừng (CTRL_C_EVENT) cho tiến trình Python
        // Điều này cho phép Python chạy hàm signal_handler (SIGINT) và khối finally.
        
        try {
            // Gửi SIGINT (dưới dạng sự kiện Console)
            // Lưu ý: process.kill('SIGINT') không hoạt động trên Windows
            // Dùng process.send('stop') nếu Agent có IPC, hoặc taskkill không /f
            
            // Thay vì SIGINT, thử SIGTERM (mặc dù không được hỗ trợ tốt):
            pyProc.kill('SIGTERM'); 
        } catch (e) {
             sendLog(`Failed to send SIGTERM: ${e.message}`, 'warn');
        }

        // 💡 Bước 2: Chờ 5 giây và buộc dừng (taskkill /f) nếu Agent không tắt
        setTimeout(() => {
            if (pyProc) {
                sendLog('Agent did not exit gracefully, forcing termination via taskkill...', 'warn');
                // Chỉ sử dụng /f sau khi chờ
                spawn('taskkill', ['/pid', pyProc.pid, '/f', '/t']); 
            }
        }, 5000); 

    } else {
        // Unix/Linux (Giữ nguyên logic SIGTERM)
        pyProc.kill('SIGTERM')
        // ... (Timeout 5000ms cho SIGKILL) ...
    }

    pyProc = null
    controlUrl = null
    controlToken = null
}

/**
 * Make HTTP request to control API
 */
function httpRequest(method, url, body = null, timeout = 5000) {
	return new Promise((resolve, reject) => {
		try {
			const parsed = new URL(url)
			const httpMod = parsed.protocol === 'https:' ? require('https') : require('http')
			
			// 1. Chuẩn bị Body (chuyển thành chuỗi JSON và tính độ dài)
            let jsonBody = null
            let contentLength = 0
            if (body) {
                jsonBody = JSON.stringify(body)
                contentLength = Buffer.byteLength(jsonBody, 'utf8') // <-- Tính Content-Length
            }

			const opts = {
				method: method,
				hostname: parsed.hostname,
				port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
				path: parsed.pathname + (parsed.search || ''),
				headers: {
					'Content-Type': 'application/json',
				},
				timeout: timeout
			}

			// 2. Thêm Content-Length chỉ khi có Body
            if (jsonBody) {
                opts.headers['Content-Length'] = contentLength
            }

			// Attach auth token if available
			if (controlToken) {
				opts.headers['X-Auth-Token'] = controlToken
			}

			const req = httpMod.request(opts, (res) => {
				let chunks = ''
				res.on('data', (d) => (chunks += d.toString()))
				res.on('end', () => {
					try {
						const json = chunks ? JSON.parse(chunks) : null
						resolve({ statusCode: res.statusCode, body: json, headers: res.headers })
					} catch (e) {
						resolve({ statusCode: res.statusCode, body: chunks, headers: res.headers })
					}
				})
			})

			req.on('timeout', () => {
				req.destroy()
				reject(new Error('Request timeout'))
			})

			req.on('error', (err) => reject(err))
			
			if (body) {
				req.write(JSON.stringify(body))
			}
			// 3. Ghi Body
            if (jsonBody) { // <-- Ghi jsonBody đã tính Content-Length
                req.write(jsonBody)
            }
			req.end()
		} catch (e) {
			reject(e)
		}
	})
}

// ===== IPC Handlers =====

ipcMain.handle('agent-start', async () => {
	try {
		startAgent()
		return { success: true }
	} catch (e) {
		return { success: false, error: e.message }
	}
})

ipcMain.handle('agent-stop', async () => {
	try {
		stopAgent()
		return { success: true }
	} catch (e) {
		return { success: false, error: e.message }
	}
})

ipcMain.handle('agent-status', async () => {
	return {
		running: !!pyProc,
		controlUrl: controlUrl,
		hasToken: !!controlToken,
		pid: pyProc ? pyProc.pid : null
	}
})

ipcMain.handle('agent-health', async () => {
	if (!controlUrl) {
		return { healthy: false, reason: 'No control URL available' }
	}

	try {
		const res = await httpRequest('GET', `${controlUrl}/health`, null, 3000)
		return {
			healthy: res.statusCode === 200,
			statusCode: res.statusCode,
			body: res.body
		}
	} catch (e) {
		return {
			healthy: false,
			reason: e.message
		}
	}
})

ipcMain.handle('agent-get-pending', async () => {
	if (!controlUrl) {
		return { error: 'No control URL available' }
	}

	try {
		const res = await httpRequest('GET', `${controlUrl}/pending`)
		
		if (res.statusCode !== 200) {
			return { error: `HTTP ${res.statusCode}`, details: res.body }
		}
		
		return res.body || { requests: [] }
	} catch (e) {
		return { error: e.message }
	}
})

ipcMain.handle('agent-approve', async (evt, id) => {
	if (!controlUrl) {
		return { error: 'No control URL available' }
	}

	if (!id) {
		return { error: 'Request ID is required' }
	}

	try {
		const res = await httpRequest('POST', `${controlUrl}/approve`, { id })
		
		if (res.statusCode !== 200) {
			return { error: `HTTP ${res.statusCode}`, details: res.body }
		}
		
		return res.body || { success: true }
	} catch (e) {
		return { error: e.message }
	}
})

ipcMain.handle('agent-reject', async (evt, id) => {
	if (!controlUrl) {
		return { error: 'No control URL available' }
	}

	if (!id) {
		return { error: 'Request ID is required' }
	}

	try {
		const res = await httpRequest('POST', `${controlUrl}/reject`, { id })
		
		if (res.statusCode !== 200) {
			return { error: `HTTP ${res.statusCode}`, details: res.body }
		}
		
		return res.body || { success: true }
	} catch (e) {
		return { error: e.message }
	}
})

ipcMain.handle('agent-set-config', async (evt, config) => {
	if (!controlUrl) {
		return { error: 'No control URL available' }
	}

	try {
		const res = await httpRequest('POST', `${controlUrl}/config`, config)
		
		if (res.statusCode !== 200) {
			return { error: `HTTP ${res.statusCode}`, details: res.body }
		}
		
		return res.body || { success: true }
	} catch (e) {
		return { error: e.message }
	}
})

// ===== App Lifecycle =====

app.whenReady().then(() => {
	createWindow()
	
	// Watch for control file changes
	watchControlFile()
	
	// Try to read existing control file
	readControlFile()

	app.on('activate', () => {
		if (BrowserWindow.getAllWindows().length === 0) {
			createWindow()
		}
	})
})

app.on('window-all-closed', () => {
	if (process.platform !== 'darwin') {
		app.quit()
	}
})

app.on('before-quit', () => {
	sendLog('Application shutting down...', 'info')
	
	if (controlFileWatcher) {
		controlFileWatcher.close()
	}
	
	stopAgent()
})

// Handle uncaught errors
process.on('uncaughtException', (error) => {
	console.error('Uncaught exception:', error)
	sendLog(`Uncaught exception: ${error.message}`, 'error')
})

process.on('unhandledRejection', (reason, promise) => {
	console.error('Unhandled rejection at:', promise, 'reason:', reason)
	sendLog(`Unhandled rejection: ${reason}`, 'error')
})
