import { useEffect, useState } from 'react'

type Status = 'online' | 'offline' | 'checking'
type Health = {
  backend: { status: Status }
  database: { status: Status }
  redis: { status: Status }
  worker: { status: Status }
}

const initialHealth: Health = {
  backend: { status: 'checking' },
  database: { status: 'checking' },
  redis: { status: 'checking' },
  worker: { status: 'checking' },
}

const labels: Record<keyof Health, string> = {
  backend: 'Backend',
  database: 'SQLite',
  redis: 'Redis',
  worker: 'Worker',
}

export function App() {
  const [health, setHealth] = useState<Health>(initialHealth)

  useEffect(() => {
    fetch('/api/v1/health')
      .then((response) => {
        if (!response.ok) throw new Error('Health check failed')
        return response.json()
      })
      .then(setHealth)
      .catch(() =>
        setHealth({
          backend: { status: 'offline' },
          database: { status: 'offline' },
          redis: { status: 'offline' },
          worker: { status: 'offline' },
        }),
      )
  }, [])

  return (
    <main>
      <header>
        <div className="brand-mark">CS</div>
        <div>
          <p className="eyebrow">Crops Security</p>
          <h1>CropsSecurity</h1>
          <p className="subtitle">Fundação operacional da plataforma</p>
        </div>
      </header>

      <section className="hero">
        <div>
          <span className="release">Sprint 1 · v0.1.0</span>
          <h2>O ambiente está pronto para receber os primeiros módulos.</h2>
          <p>API, fila, persistência e interface compartilham uma base reproduzível em Docker.</p>
        </div>
        <div className="metric"><strong>0</strong><span>scanners instalados</span></div>
      </section>

      <section aria-labelledby="services-title">
        <div className="section-title"><h2 id="services-title">Serviços</h2><span>atualização ao abrir</span></div>
        <div className="grid">
          {(Object.keys(labels) as Array<keyof Health>).map((key) => (
            <article className="card" key={key}>
              <span className={`dot ${health[key].status}`} aria-hidden="true" />
              <div><h3>{labels[key]}</h3><p>{health[key].status}</p></div>
            </article>
          ))}
        </div>
      </section>

      <footer>Execução local · acesso em <code>localhost:1984</code></footer>
    </main>
  )
}
