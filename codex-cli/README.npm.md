# Uxarion

Uxarion is a terminal security assessment agent.

## Install

```sh
npm install -g uxarion
```

## Run

```sh
uxarion
```

## API key

You can either set an API key in your shell before launch:

```sh
export OPENAI_API_KEY="your_key_here"
uxarion
```

Or start Uxarion and use `/apikey` inside the chat UI to save a key for future runs.

## Notes

- This npm package is a thin launcher. On first run it downloads the native Uxarion runtime for your platform.
- Use Uxarion only on systems and targets you are explicitly authorized to assess.
