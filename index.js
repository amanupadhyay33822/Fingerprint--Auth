// const http = require('http');
// const server= http.createServer()
const port = 4000;
const crypto = require("crypto");
if (!globalThis.crypto) {
  globalThis.crypto = crypto;
}
// server.listen(port ,(req,res)=>{
//     console.log(`listening on port ${port}`);
// })

const express = require("express");
const server = express();
const { generateRegistrationOptions, verifyRegistrationResponse } = require("@simplewebauthn/server");

server.use(express.static("./public"));
server.use(express.json());

//store
const userStore = {};
const challengeStore = {};
server.post("/signup", (req, res) => {
  const { username, password } = req.body;
  const id = `${Date.now()}`;
  const user = {
    id,
    username,
    password,
  };
  userStore[id] = user;
  return res.status(200).json({
    id,
  });
});
server.post("/register-challenge", async (req, res) => {
  const { userId } = req.body;
  if (!userStore[userId])
    return res.status(404).json({ error: "user not found!" });
  const user = userStore[userId];
  console.log(user);
  const challengePayload = await generateRegistrationOptions({
    rpID: "localhost",
    rpName: "Web auth",
    userName: user.username,

  });

  challengeStore[userId] = challengePayload.challenge;
  return res.status(200).json({
    options:challengePayload,
  });
});


server.post("/register-verify", async (req, res) => {
  const {userId, cred} = req.body;
  if (!userStore[userId]) return res.status(404).json({ error: 'user not found!' })

    const user = userStore[userId]
    const challenge = challengeStore[userId]
    const verificationResult = await verifyRegistrationResponse({
        expectedChallenge: challenge,
        expectedOrigin: 'http://localhost:4000',
        expectedRPID: 'localhost',
        response: cred,
    })
    if (!verificationResult.verified) return res.json({ error: 'could not verify' });
    userStore[userId].passkey = verificationResult.registrationInfo
     
    return res.json({ verified: true })
})


server.post('/login-challenge', async (req, res) => {
  const { userId } = req.body
  if (!userStore[userId]) return res.status(404).json({ error: 'user not found!' })
  
  const opts = await generateAuthenticationOptions({
      rpID: 'localhost',
  })

  challengeStore[userId] = opts.challenge

  return res.json({ options: opts })
})


server.post('/login-verify', async (req, res) => {
  const { userId, cred }  = req.body

  if (!userStore[userId]) return res.status(404).json({ error: 'user not found!' })
  const user = userStore[userId]
  const challenge = challengeStore[userId]

  const result = await verifyAuthenticationResponse({
      expectedChallenge: challenge,
      expectedOrigin: 'http://localhost:4000',
      expectedRPID: 'localhost',
      response: cred,
      authenticator: user.passkey
  })

  if (!result.verified) return res.json({ error: 'something went wrong' })
  
  // Login the user: Session, Cookies, JWT
  return res.json({ success: true, userId })
})

server.listen(port, (req, res) => {
  console.log(`listening on port ${port}`);
});
