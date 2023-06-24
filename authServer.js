require('dotenv').config()

const express = require('express')
const bcrypt = require('bcrypt')
const app = express()
const port = 4000

const jwt = require('jsonwebtoken')

app.use(express.json())

let refreshTokens = []
let users = []

app.post('/token', (req, res) => {
  const refreshToken = req.body.token
  if (refreshToken == null) return res.sendStatus(401)
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403)
  console.log(refreshTokens)
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403)

    const accessToken = generateAccessToken({ name: user.name })
    res.json({ accessToken: accessToken })
  })
})

app.get('/', (req, res) => res.send('Hello World!'))

app.delete('/logout', (req, res) => {
  refreshTokens = refreshTokens.filter((token) => token !== req.body.token)
  res.sendStatus(204)
  console.log(refreshTokens)
  //console.log('Successfully Logout')
})

app.post('/register', async (req, res) => {
  // Register User
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10)
    const user = { name: req.body.username, password: hashedPassword }
    users.push(user)
    res.status(201).send()
  } catch (error) {
    res.status(500).send()
  }
})

app.post('/login', async (req, res) => {
  // Authenticate User
  const userFound = users.find((user) => user.name === req.body.username)
  if (userFound == null) {
    return res.status(400).send('Cannot find user')
  }
  try {
    if (await bcrypt.compare(req.body.password, userFound.password)) {
      const username = req.body.username
      const password = req.body.password

      const user = { name: username, password: password }

      const accessToken = generateAccessToken(user)
      const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
      refreshTokens.push(refreshToken)
      res.json({ accessToken: accessToken, refreshToken: refreshToken })
    } else {
      res.send('Not Allowed')
    }
  } catch (error) {
    res.status(500).send()
  }
})

// Generate Access Token
function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '30s' })
}

app.listen(port, () => console.log(`Example app listening on port ${port}!`))
