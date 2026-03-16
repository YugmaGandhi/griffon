import { buildApp } from './app'
import { env } from './config/env'

async function start() {
  const app = buildApp()

  try {
    await app.listen({
      port: env.PORT,
      host: env.HOST,
    })
  } catch (err) {
    app.log.error(err)
    process.exit(1)
  } 

  // ── Graceful Shutdown ───────────────────────────────────
  // When the server receives SIGINT (Ctrl+C) or SIGTERM (Docker stop),
  // it stops accepting new requests and waits for existing ones to finish
  // before closing. Without this, requests mid-flight would be cut off.
  const shutdown = async (signal: string) => {
    app.log.info(`Received ${signal} — shutting down gracefully`)
    await app.close()
    app.log.info('Server closed')
    process.exit(0)
  }

  process.on('SIGINT', () => shutdown('SIGINT'))
  process.on('SIGTERM', () => shutdown('SIGTERM'))
}

start()