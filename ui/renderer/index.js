const startBtn = document.getElementById('start')
const stopBtn = document.getElementById('stop')
const logEl = document.getElementById('log')
const pendingEl = document.getElementById('pending')
const controlUrlInput = document.getElementById('controlUrlInput')
const connectControlBtn = document.getElementById('connectControl')

let controlUrl = null

function renderPending(list) {
  if (!list || list.length === 0) {
    pendingEl.innerHTML = '<i>No pending requests</i>'
    return
  }
  pendingEl.innerHTML = ''
  list.forEach((r) => {
    const div = document.createElement('div')
    div.style = 'border:1px solid #ccc;padding:8px;margin:6px;'
    div.innerHTML = `<b>id:</b> ${r.id} <b>path:</b> ${r.path} <b>status:</b> ${r.status}`
    const btn = document.createElement('button')
    btn.textContent = 'Approve'
    btn.addEventListener('click', async () => {
      btn.disabled = true
      const res = await window.agentAPI.approve(r.id)
      logEl.textContent += `Approve response: ${JSON.stringify(res)}\n`
      fetchPendingOnce()
    })
    div.appendChild(document.createTextNode(' '))
    div.appendChild(btn)
    pendingEl.appendChild(div)
  })
}

async function fetchPendingOnce() {
  try {
    if (controlUrl) {
      const r = await fetch(controlUrl + '/pending')
      const body = await r.json()
      if (body && body.pending) renderPending(body.pending)
      else pendingEl.innerHTML = `<i>Error: ${JSON.stringify(body)}</i>`
      return
    }
    if (window.agentAPI && window.agentAPI.getPending) {
      const res = await window.agentAPI.getPending()
      if (res && res.pending) renderPending(res.pending)
      else pendingEl.innerHTML = `<i>Error: ${JSON.stringify(res)}</i>`
      return
    }
    pendingEl.innerHTML = '<i>No control API available</i>'
  } catch (e) {
    pendingEl.innerHTML = `<i>Request error: ${e}</i>`
  }
}

// Poll every 3s
setInterval(() => {
  fetchPendingOnce()
}, 3000)

window.agentAPI.onControlUrl((url) => {
  controlUrl = url
  logEl.textContent += `[Control URL] ${url}\n`
})

startBtn.addEventListener('click', () => {
  window.agentAPI.start()
})

stopBtn.addEventListener('click', () => {
  window.agentAPI.stop()
})

window.agentAPI.onLog((data) => {
  logEl.textContent += data + '\n'
  logEl.scrollTop = logEl.scrollHeight
})

window.agentAPI.onExit((info) => {
  logEl.textContent += `[Agent exited] code=${info.code} signal=${info.signal}\n`
})

// initial fetch
fetchPendingOnce()

connectControlBtn.addEventListener('click', () => {
  const v = controlUrlInput.value.trim()
  if (!v) return
  controlUrl = v.replace(/\/$/, '')
  logEl.textContent += `[Connected control API] ${controlUrl}\n`
  fetchPendingOnce()
})
