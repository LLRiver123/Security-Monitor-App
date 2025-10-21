const e = React.createElement

function AlertItem({ alert }) {
  const sev = (alert.severity || 'low').toLowerCase()
  return e('div', { className: `alert ${sev}` },
    e('div', null, e('strong', null, alert.message)),
    e('div', null, `Severity: ${alert.severity} | Confidence: ${alert.confidence}`),
    e('pre', null, JSON.stringify(alert.fields || {}, null, 2))
  )
}

function App() {
  const [alerts, setAlerts] = React.useState([])

  React.useEffect(() => {
    let ws
    // First fetch recent alerts
    fetch('http://127.0.0.1:8000/alerts')
      .then(r => r.json())
      .then(j => {
        if (j && Array.isArray(j.alerts)) {
          setAlerts(j.alerts)
        }
        // then open websocket for live updates
        ws = new WebSocket('ws://127.0.0.1:8000/ws/alerts')
        ws.onopen = () => console.log('ws open')
        ws.onmessage = (evt) => {
          try {
            const data = JSON.parse(evt.data)
            const item = data.alert
            setAlerts(prev => [item].concat(prev).slice(0, 200))
          } catch (err) {
            console.error('ws parse', err)
          }
        }
        ws.onerror = (e) => console.error('ws error', e)
        ws.onclose = () => console.log('ws closed')
      })
      .catch(err => {
        console.error('failed to fetch alerts', err)
        // still open websocket
        ws = new WebSocket('ws://127.0.0.1:8000/ws/alerts')
      })
    return () => ws && ws.close()
  }, [])

  return e('div', null,
    e('h2', null, 'Security Monitor Alerts'),
    e('div', null, alerts.map(a => e(AlertItem, { key: a.id, alert: a })))
  )
}

ReactDOM.createRoot(document.getElementById('root')).render(e(App))
