import express from "express";
import jwt from "jsonwebtoken";
import fetch from "node-fetch";

const app = express();
const port = process.env.PORT || 3001;

const {
  OAUTH_CLIENT_ID="gitbook",
  OAUTH_CLIENT_SECRET="changeit",
  OAUTH_AUTHORIZATION_ENDPOINT="https://changeit/auth/realms/gazelle/protocol/openid-connect/auth",
  OAUTH_TOKEN_ENDPOINT="https://changeit/auth/realms/gazelle/protocol/openid-connect/token",
  OAUTH_REDIRECT_URI="https://changeit/gitbook-auth/oauth-verification",
  GITBOOK_DOCUMENTATION_URL="https://changeit/internal-documentation/",
  GITBOOK_SIGNING_SECRET="changeit",
} = process.env;

/*
 * Here is where your Auth Implementation starts the OAuth procedure
 */
app.get("/gitbook-visitor-auth-endpoint", (req, res) => {
  // If you have a mechanism for storing state across multiple requests, we
  // strongly recommend providing a random state parameter with the authorization
  // request so that you can verify that inbound requests to the /oauth-verification
  // endpoint originate from here. For more info please consult the following doc:
  // https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
  // const state = random-state-to-correlate-requests

  console.log("Inbound visitor authentication request");
  const authParameters = {
    client_id: OAUTH_CLIENT_ID,
    response_type: "code",
    redirect_uri: `${OAUTH_REDIRECT_URI}?location=${req.query.location}`
    // state
  };
  const outboundRedirectURI = `${OAUTH_AUTHORIZATION_ENDPOINT}?${new URLSearchParams(
    authParameters
  ).toString()}`;

  res.redirect(outboundRedirectURI);
});

/*
 * Here is where your Auth Implementation receives a code. It checks with the
 * OAuth server that the code is valid. If it is, it will send the user back
 * to GitBook with a signed token, so that they can view your docs.
 */
app.get("/oauth-verification", async (req, res) => {
  if (req.query["access_denied"] || !req.query["code"]) {
    console.log(
      `The visitor likely rejected permission in our oauth provider's dialog`
    );
    // You could return your own error page here if you like.
    res.status(401);
    res.send("Forbidden");
  } else {
    const locationRequest = req.query.location;
    const isValidCode = await verifyCode(req.query["code"],locationRequest);
    if (!isValidCode) {
      console.log("Could not exchange oauth code for oauth access token");
      res.status("401");
      res.send("Forbidden");
      return;
    }
    const signedJWT = jwt.sign({}, GITBOOK_SIGNING_SECRET);
    const gitBookRedirectParams = {
      jwt_token: signedJWT,
    };
    res.redirect(
      `${GITBOOK_DOCUMENTATION_URL}${locationRequest}?${new URLSearchParams(
        gitBookRedirectParams
      ).toString()}`
    );
    console.log("Successful visitor authentication token sign");
  }
});

/*
 * This function checks with the OAuth server that the code we received is valid.
 * This step is known as "Access Token Request" in the OAuth 2.0 spec
 * (IETF RFC 6749)
 */
async function verifyCode(code,locationRequest) {
  const tokenVerificationResponse = await fetch(OAUTH_TOKEN_ENDPOINT, {
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      // Some OAuth servers require client information in the authorization header,
      // rather than in the request body as below.
      // authorization: `Bearer ${Buffer.from(
      //   `${OAUTH_CLIENT_ID}:${OAUTH_CLIENT_SECRET}`
      // ).toString("base64")}`,
    },
    method: "POST",
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: OAUTH_CLIENT_ID,
      client_secret: OAUTH_CLIENT_SECRET,
      code,
      redirect_uri: `${OAUTH_REDIRECT_URI}?location=${locationRequest}`,
      // redirect_uri: OAUTH_REDIRECT_URI,
    }).toString(),
  });

  const data = await tokenVerificationResponse.json();

  return data.hasOwnProperty("access_token");
}

app.listen(port, () => {
  console.log(
    `GitBook Visitor Auth Demo app listening at http://localhost:${port}/gitbook-visitor-auth-endpoint`
  );
});

