
# 🏡 Haven: Getting Started

**Your own private chat app, running on your own server.** 🔒
No cloud. No Docker. No accounts with big companies. Just you and your people.

---

## 🚀 Install in 3 steps

You need an **Ubuntu server** and a few minutes. ⏱️

**1️⃣ Get the files**

```bash
git clone https://github.com/Gravitatest080/haven.git
cd haven
```

**2️⃣ Run the installer**

```bash
sudo bash haven5.sh
```

**3️⃣ Open it in your browser** 🌐

```
https://YOUR-SERVER-IP:6060
```

> 💡 Not sure of your IP? Run `hostname -I` on the server.

The **first account you create becomes the admin** 👑

---

## 🔐 Remove the browser warning (one time per device)

Your browser may say the connection isn't trusted. That's normal: Haven makes its own certificate. Fix it once:

1. Open `https://YOUR-SERVER-IP:6060/trust` 📱💻
2. Tap **Download certificate**
3. Follow the steps for your device (iPhone, Android, Windows, Mac, Linux)

Now you'll get a padlock 🔒 and can **add Haven to your home screen** like a real app.

---

## ✨ Everything Haven can do

### 💬 Chatting
- 📢 **Public rooms** for everyone
- 🕵️ **Private rooms**: invite-only group chats
- 🔐 **Direct messages**: one-to-one and end-to-end encrypted
- ✏️ Edit and 🗑️ delete your messages
- ↩️ **Replies** that quote the message
- 😍 **Emoji reactions**
- ⌨️ **Typing indicators** and ✅ **"Seen" receipts** in DMs
- 🔔 **@mentions** that light up for the person you tag
- 📝 **Drafts** saved for every chat

### 🎨 Formatting (tap **Aa** next to the emoji button)
- **Bold**, *italic*, <u>underline</u>, ~~strikethrough~~
- `Inline code` and code blocks
- 💬 Quotes, • bullet lists, 1. numbered lists
- 🔗 Links and 🙈 spoilers (tap to reveal)
- ⌨️ Shortcuts: `Ctrl+B`, `Ctrl+I`, `Ctrl+U`, `Ctrl+E`

### 📎 Share anything
- 🎤 **Voice messages**: tap the mic and talk
- 🖼️ **Photos**: button, paste, or drag and drop
- 📁 **Files** up to 25 MB
- 🗳️ **Polls** with live results
- 🔍 Photo gallery and file list for every chat

### 🧠 Stay organised
- 📌 **Pin** important messages
- ⭐ **Save** messages for later
- 🔎 **Search** across all your rooms
- 🏷️ **Room topics**
- 🔕 **Mute** noisy chats
- ⏳ **Disappearing messages** (1 hour to 30 days)
- 📣 **Announcement banner** from the admin

### ⚡ Power moves
- 🚀 **Ctrl+K**: jump to any room, person or setting
- `/poll`  `/roll 2d6`  `/flip`  `/me`  `/shrug`  `/spoiler`  `/help`
- `@name` suggests people, `:smile:` suggests emoji

### 🎭 Make it yours
- 🖼️ **Profile picture** and 💭 **status**
- 🌙 Dark, ☀️ light, and ⚫ OLED-black themes
- 🌈 Five accent colours
- 🔤 Three text sizes and compact spacing
- 🔊 Sounds and 🖥️ desktop notifications (optional)

### 🛡️ Security
- 🔒 **HTTPS everywhere**
- 🕶️ **End-to-end encrypted DMs** with a security code you can compare
- 🔑 Passwords stored hashed, never in plain text
- 🚫 Admins **can't** read your DMs or private rooms
- 🧼 Photo location data stripped automatically

### 👑 For admins
- 🎟️ **Invite links** with limited uses and expiry
- 🚪 Open or close sign-ups
- 🔧 Reset passwords, make admins, remove people
- 📊 See how much space Haven is using

---

## 🧰 Handy commands

Run these on the server:

| Command | What it does |
|---|---|
| 🩺 `sudo haven status` | Check Haven is running |
| 💾 `sudo haven backup` | Back up everything now (it also backs up every night) |
| ♻️ `sudo haven restore FILE` | Restore from a backup |
| 🔄 `sudo haven regen-cert` | Fix the certificate if your server's IP changes |
| 🗑️ `sudo haven uninstall` | Remove Haven but **keep** your data |
| 💥 `sudo haven uninstall --purge` | Remove Haven **and** all data |
| 🆘 `sudo haven-admin --reset-password NAME` | Help someone who's locked out |

---

## ⬆️ Updating

Download the newer script and run it again. Your accounts, messages and files are kept, and Haven makes a backup first. 🛟

```bash
sudo bash haven5.sh
```

---

## ⚠️ Good to know

- 🏠 Haven is for **your own network**. Don't put it on the open internet. For remote access, use a private VPN like Tailscale.
- 🔐 **Only DMs are end-to-end encrypted.** Rooms are protected by HTTPS, but the server can read them.
- 🔑 If an admin resets someone's password, their **old DMs can't be read anymore**. That's how real encryption works.
- 🎤 Voice messages need microphone permission in your browser.

---

## ❓ Quick help

| Problem | Fix |
|---|---|
| 🌐 Page won't load | Run `sudo haven status` |
| ⚠️ Browser warning | Open `/trust` and install the certificate |
| 📍 Server's IP changed | Run `sudo haven regen-cert` |
| 🙈 Forgot password | Ask an admin, or run `sudo haven-admin --reset-password NAME` |

---

Made with ❤️ for people who want a chat that's **theirs**.
