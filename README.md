# SurveyWalk publisher

A small program that keeps published site surveys on a web address, in your own Cloudflare
account. SurveyWalk (the survey app) sends each survey here with a password; anyone with the
link can open it on any phone or computer. It holds no secret of its own — the password is
set when you deploy it.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/SignWalkApp/surveywalk-publisher)

1. In Cloudflare, add the R2 subscription first (left menu → **R2** → **Add R2 subscription**). It asks
   for a card; the bill is $0 under 10 GB.
2. Press the button above. Sign in, allow GitHub, name the Worker `surveys`.
3. Where it asks for `PUBLISH_KEY`, paste the password from SurveyWalk's *Publishing setup* screen
   (press **Copy** there). Press **Deploy**.
4. Copy the address it shows — `https://surveys.….workers.dev` — into SurveyWalk's *Publisher
   address*, press **Check**, then **Save**.

Files: `worker.js` (the publisher), `wrangler.jsonc` (its name and its R2 bucket `surveys`, bound as
`SURVEYS`), `.dev.vars.example` (declares `PUBLISH_KEY` so the deploy page asks for it).
