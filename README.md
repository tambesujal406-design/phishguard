# 🛡️ PhishGuard: AI-Powered Phishing Threat Detector

![HTML5](https://img.shields.io/badge/HTML5-E34F26?logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?logo=javascript&logoColor=black)
![License](https://img.shields.io/badge/License-MIT-green)

PhishGuard analyses **URLs, emails and SMS messages**, gives each one a **risk score from 0 to 100**, and explains every red flag it found. Everything runs in the browser, so nothing you paste is uploaded anywhere.

🔗 **Live demo:** https://YOUR-USERNAME.github.io/phishguard/

![PhishGuard screenshot](docs/screenshot.png)

## ✨ Features

- 🔗 **URL scanner** with 16 checks (see the table below)
- 💬 **Email / SMS scanner** that detects urgency, threats, credential requests, fake rewards and risky embedded links
- 📟 Animated terminal scan, then an animated **risk gauge** and a verdict: Safe, Suspicious or Dangerous
- 🚩 **Explainable results**: every finding shows what it is, why it matters and the points it added
- 📊 **Threat dashboard** with scan history and charts, saved with `localStorage`
- 🎨 Dark and light themes, a matrix-style canvas background, glitch title, cursor glow, and a responsive layout

## 🧠 How the detection works

Each scan extracts **features**, gives each one a weight, and adds them up into a score (capped at 100).

| Score | Verdict |
|-------|---------|
| 0 – 24 | ✅ Looks Safe |
| 25 – 54 | ⚠️ Suspicious |
| 55 – 100 | 🚨 Dangerous |

**URL features:** HTTPS check, IP address as host, `@` symbol trick, punycode, URL length, subdomain count, hyphen count, risky TLDs (`.xyz`, `.top`…), URL shorteners, sensitive keywords (`login`, `verify`…), **brand look-alikes** (`paypa1` → paypal, found with leetspeak normalisation + **Levenshtein distance**), brand in the wrong domain, digit-heavy hosts, unusual ports, heavy URL encoding, open-redirect patterns.

**Text features:** regex rules for urgency, threats, sensitive-data requests, reward bait, generic greetings, ALL CAPS, excessive `!`, plus every link inside the message is scanned with the URL engine.

> ℹ️ The current engine is **weighted feature scoring**, the same kind of features a machine-learning model learns from. A trained ML model is on the roadmap below.

## 🧰 Tech stack

| Part | Used for |
|------|----------|
| HTML5 | Page structure |
| CSS3 | CSS variables, grid/flexbox, keyframe animations, glassmorphism, dark/light theme |
| JavaScript (ES6+) | Detection engine, DOM updates, async scan animation, `localStorage`, Canvas API |

## 📁 Project structure

```
phishguard/
├── index.html      # page layout
├── css/style.css   # all styling and animations
├── js/app.js       # detection engine + UI logic
├── docs/           # screenshots
├── LICENSE
└── README.md
```

## 🚀 Run it locally

```bash
git clone https://github.com/YOUR-USERNAME/phishguard.git
cd phishguard
# just open index.html in your browser, or:
python -m http.server 8000   # then visit http://localhost:8000
```

## 🛠️ How I built it

1. **Picked the idea.** I wanted a project that combines web development, AI/ML concepts and cybersecurity, so I chose a phishing detector.
2. **Planned the features** by listing the signs of a phishing URL and message.
3. **Built it with AI assistance** (Claude by Anthropic) as a pair-programming partner, then read through the code, tested it with phishing and safe samples, and learned how each part works.
4. **Tested** with fake phishing links such as `http://amaz0n-account-verify.top/login/update` and safe ones such as `https://www.google.com`.
5. **Deployed** for free with GitHub Pages.

### 📚 What I learned
- Regular expressions for pattern matching
- Levenshtein distance for spotting look-alike domains
- Feature engineering and risk scoring
- DOM manipulation, async/await and the Canvas API
- Responsive design and CSS theming with variables

## 🗺️ Roadmap

- [ ] Python **Flask/FastAPI backend** with a **scikit-learn** model (Random Forest) trained on a Kaggle phishing dataset
- [ ] Domain age lookup (WHOIS) and Google Safe Browsing API
- [ ] Chrome extension that warns on suspicious pages
- [ ] Export scan reports as PDF

## ⚠️ Disclaimer

PhishGuard is an **educational, defensive-security project**. Its results are guidance, not a guarantee. Always verify suspicious messages through official channels. In India, report cyber fraud at [cybercrime.gov.in](https://cybercrime.gov.in) or call **1930**.

## 📄 License

MIT. See [LICENSE](LICENSE).
