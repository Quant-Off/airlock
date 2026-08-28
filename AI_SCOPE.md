# Scope of AI Agent Use

[![Language](https://img.shields.io/badge/AI_SCOPE-Korean_Ver-blue?style=for-the-badge)](AI_SCOPE_KR.md)

> The Korean original of this document was written without AI. This English version was translated by an AI agent (Claude Fable 5).

Up to commit [fe02a87](https://github.com/Quant-Off/airlock/commit/fe02a8739ab29a57a82e1da10fe08ac3a012aeaa), AI was used only to write commit messages, with an on-premises Qwen3.6/8 model and Claude Opus 5. That process was a simple loop: the model read the changes the maintainer had made across the codebase, inferred what each change was, and wrote a fresh, short commit message into a `.txt` file.

Starting with commit [8a81806](https://github.com/Quant-Off/airlock/commit/8a8180667c8a19a0b2824cf11e83b1e0bef4b29a), however, I began using an AI agent with full read and write access to the codebase. Gaps in my own technical understanding are certainly part of the reason, but the larger one is that I judged it efficient to work alongside an agent that understands the `airlock` codebase from multiple angles, both what the maintainer is aiming for and what has been written so far.

Adding a new command to the binary is simple work, but it comes with a strong feeling of "why do this by hand right now". And when it comes to translating documents written in Korean into English, I am frankly more at ease letting an AI do the translation than doing it myself. Work like adding a new Mermaid diagram to a document or fixing typos also seems well suited to an AI. This is the domain of efficiency, and it can be used to produce new ideas as well, like the idea of giving `airlock` an interactive [setup wizard](https://github.com/Quant-Off/airlock/commit/d3f680123b4e1f39f5ca27a37a7e8efc63a7f4bf) so that users who might find installation and configuration difficult can complete all of it conversationally. Going further, AI agents can be applied to adding new features and reinforcing existing implementations so that the goals the maintainer has defined are met precisely.

Across every area where an AI agent is applied, including the work above, there may be changes I have failed to review. One could call that natural; I do not think so. It is plainly a mistake, and the picture it paints does not stop at a villain of a maintainer who irresponsibly dumps work on an AI agent while soliciting people's contributions: mistakes roll up like a snowball and cause enormous damage later. If that picture itself was created by AI, that maintainer is neither a vibe coder nor a developer who works with AI, but simply an irresponsible developer.

**In the end, what I want to say is this: starting from commit `8a81806`, I use AI agents.** And so that your contributions can keep making this a safer AI gateway, I will state a trailer naming the AI model used in every part of this repository where an AI agent was involved.

If you would like to discuss anything further with me, please reach out at <qtfelix@qu4nt.space>. I read your feedback myself.
