<p align="center"><code>npm i -g uxarion</code><br />or <code>curl -fsSL https://raw.githubusercontent.com/rachidlaad/uxarion-downloads/main/install.sh | sh</code></p>
<p align="center"><strong>Uxarion</strong> is a terminal security assessment agent that runs locally on your computer.
<p align="center">
  <img src="https://github.com/rachidlaad/uxarion-security/blob/main/.github/uxarion-splash.png" alt="Uxarion splash" width="80%" />
</p>
</br>
Run <code>uxarion</code> after installation to open the interactive terminal UI.</p>

---

## Quickstart

### Installing and running Uxarion

Install globally with your preferred package manager:

```shell
# Install using npm
npm install -g uxarion
```

```shell
# Install directly from GitHub
curl -fsSL https://raw.githubusercontent.com/rachidlaad/uxarion-downloads/main/install.sh | sh
```

Then simply run `uxarion` to get started.

<details>
<summary>You can also go to the <a href="https://github.com/rachidlaad/uxarion-downloads/releases/latest">latest GitHub Release</a> and download the runtime archive directly.</summary>

Current published runtime artifact:

- Linux
  - x86_64: `uxarion-0.1.1-linux-x64.tar.xz`

The npm package also downloads this runtime automatically on first run.

</details>

### Authentication

Run `uxarion` and use `/apikey` inside the terminal UI to save an API key for future runs, or export `OPENAI_API_KEY` before launch if you prefer environment-based configuration.

## Docs

- [**GitHub Releases**](https://github.com/rachidlaad/uxarion-downloads/releases)
- [**Contributing**](./docs/contributing.md)
- [**Installing & building**](./docs/install.md)
- [**Open source fund**](./docs/open-source-fund.md)

This repository is licensed under the [Apache-2.0 License](LICENSE).
