import express from 'express'
import routes from './routes.ts'

const app = express()

// for CAS Single Logout
app.use(express.urlencoded({ extended: false }));

app.use(routes)

const listenOn = Number(process.env.PORT || 3000)
app.listen(listenOn, () => {
  console.log(`Listening on http://0.0.0.0:${listenOn}`)
})
