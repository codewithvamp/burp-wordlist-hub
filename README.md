# 🔤 WordlistHub

**Wordlists, directly inside Burp Suite.**

WordlistHub is a Burp Suite extension that allows penetration testers and bug bounty hunters to **browse, search, download, cache, and use wordlists directly inside Burp Suite**.

It removes the repetitive process of searching GitHub, opening RAW files, downloading wordlists, and manually importing them into Burp Intruder.

> **Find the wordlist → Select it → Use it in Intruder.**

---

## 🚀 Why WordlistHub?

While testing web applications, pentesters frequently need different wordlists for:

* Content discovery
* API endpoint discovery
* Parameter fuzzing
* Authentication testing
* Technology-specific paths
* Backup files
* Hidden directories
* Custom fuzzing

The normal workflow often looks like this:

```text
Burp Suite
   ↓
Need a wordlist
   ↓
Open browser
   ↓
Search GitHub / SecLists
   ↓
Find the correct file
   ↓
Open RAW / Download
   ↓
Return to Burp
   ↓
Intruder → Payloads
   ↓
Load the wordlist
```

WordlistHub simplifies this to:

```text
Burp Suite
   ↓
WordlistHub
   ↓
Search / Browse
   ↓
Select Wordlist
   ↓
Set as Intruder Wordlist
   ↓
Start Testing
```

---

## ✨ Features

### 📚 Browse SecLists

Browse supported wordlists from the SecLists repository directly inside Burp Suite.

Wordlists are displayed using a familiar directory-style tree.

```text
Wordlists
└── SecLists
    ├── Discovery
    │   ├── DNS
    │   ├── Web-Content
    │   └── Infrastructure
    ├── Fuzzing
    ├── Passwords
    ├── Usernames
    └── ...
```

---

### 🔎 Search Wordlists

Quickly search the available catalog without manually navigating through GitHub directories.

For example:

```text
api
graphql
swagger
backup
admin
wordpress
parameters
```

---

### 🗂 Category Filtering

Filter available wordlists by their category to quickly narrow down the catalog.

---

### ⭐ Favorites

Frequently used wordlists can be marked as favorites for faster access.

---

### 🕘 Recently Used

WordlistHub maintains a list of recently used wordlists so you can quickly return to your common payload lists.

---

### 📥 On-Demand Downloads

WordlistHub does **not download the entire SecLists repository**.

A wordlist is downloaded only when you actually need it.

```text
Select Wordlist
      ↓
Is it cached?
   ↙       ↘
 YES       NO
  ↓         ↓
Use       Download
Cache     Wordlist
   ↘       ↙
   Ready
```

---

## 💾 Local Caching

Downloaded wordlists are cached locally.

Default location:

```text
~/.wordlist-hub/
```

Example:

```text
.wordlist-hub/
├── cache/
│   ├── seclists/
│   │   ├── Discovery/
│   │   ├── Fuzzing/
│   │   └── Passwords/
│   │
│   └── custom/
│
├── seclists_catalog.json
└── settings.json
```

Once downloaded, the same wordlist can be reused without downloading it again.

This also makes cached wordlists available when working offline.

---

## ⚡ Burp Intruder Integration

WordlistHub integrates with **Burp Intruder's extension-generated payload mechanism**.

First select the desired wordlist inside WordlistHub and click:

```text
Set as Intruder Wordlist
```

Then navigate to:

```text
Intruder
   ↓
Payloads
   ↓
Payload type
   ↓
Extension-generated
   ↓
Wordlist Hub
```

The selected wordlist will now be supplied to Intruder.

---

## 🌊 Streaming Large Wordlists

Large wordlists are **streamed directly from disk** instead of being loaded completely into JVM memory.

```text
Cached Wordlist
      ↓
Read next line
      ↓
Intruder Payload
      ↓
Read next line
      ↓
Intruder Payload
      ↓
...
```

This makes WordlistHub more suitable for large wordlists.

For extremely large lists, WordlistHub also displays a warning before activating them.

---

## 🌐 Custom GitHub Sources

WordlistHub isn't limited to SecLists.

You can add your own GitHub wordlist repositories.

Go to:

```text
WordlistHub
   ↓
Sources
   ↓
+ Add Source
```

WordlistHub supports:

### GitHub Repository

```text
https://github.com/user/wordlists
```

### GitHub Directory

```text
https://github.com/user/wordlists/tree/main/api
```

### GitHub File

```text
https://github.com/user/wordlists/blob/main/api.txt
```

### RAW URL

```text
https://raw.githubusercontent.com/user/repository/main/wordlist.txt
```

GitHub repositories and directories are automatically expanded into browsable wordlist entries.

GitHub `blob` URLs are automatically converted to their RAW equivalent when required.

---

## 📄 Supported Wordlist Formats

WordlistHub currently recognizes:

| Extension   | Supported |
| ----------- | :-------: |
| `.txt`      |     ✅     |
| `.lst`      |     ✅     |
| `.dic`      |     ✅     |
| `.csv`      |     ✅     |
| `.json`     |     ✅     |
| `.xml`      |     ✅     |
| `.fuzz`     |     ✅     |
| `.payloads` |     ✅     |

---

# 🛠 Installation

WordlistHub currently targets the **Burp Suite Legacy Extender API** and **Jython 2.7.x**.

## 1. Download Jython

Download the Jython standalone JAR.

Example:

```text
jython-standalone-2.7.x.jar
```

---

## 2. Configure Jython in Burp Suite

Open:

```text
Burp Suite
→ Extensions
→ Extensions settings
→ Python environment
```

Select your:

```text
jython-standalone-2.7.x.jar
```

---

## 3. Download WordlistHub

Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/burp-wordlist-hub.git
```

Or download the repository as ZIP.

---

## 4. Load the Extension

In Burp Suite:

```text
Extensions
→ Installed
→ Add
```

Select:

```text
Extension type: Python
```

Then choose:

```text
WordlistHub.py
```

Click **Next**.

---

## 5. Open WordlistHub

After successful installation, a new tab should appear:

```text
Wordlist Hub
```

You're ready to use it.

---

# 🖥 Interface

WordlistHub currently provides three main areas:

### Browse

Used for:

* Browsing wordlists
* Searching
* Category filtering
* Previewing wordlists
* Downloading wordlists
* Selecting Intruder wordlists
* Favorites
* Updating cached lists
* Deleting cached copies

### Sources

Used for adding:

* GitHub repositories
* GitHub directories
* GitHub files
* Direct RAW URLs

### Manage

Used for:

* Viewing downloaded wordlists
* Checking storage usage
* Viewing local paths
* Deleting cached wordlists
* Clearing the complete cache
* Opening the cache directory

---

# 🔄 Updating Wordlists

Cached wordlists are not automatically downloaded every time Burp starts.

To retrieve the latest version of a wordlist, select it and click:

```text
Update
```

This avoids unnecessary network requests and allows cached lists to remain usable offline.

---

# 🧹 Cache Management

WordlistHub provides controls for managing downloaded files.

You can:

```text
Delete Cache
Delete Selected Cache
Clear All Cache
Open Cache Folder
```

The extension also displays:

```text
Total cache size
Number of cached wordlists
Cache directory
```

---

# 🔐 Security & Privacy

WordlistHub does **not send your Burp traffic, HTTP requests, targets, credentials, or testing data to GitHub**.

Network requests are made only when WordlistHub needs to retrieve:

* Repository metadata
* Wordlist catalogs
* Selected wordlist files

Downloaded wordlists are stored locally.

Always review third-party wordlists before using them against a target.

---

# ⚠️ GitHub API Limits

WordlistHub uses the GitHub API for repository catalog discovery.

Unauthenticated GitHub API requests are subject to GitHub's rate limits.

Very large repositories may also return a truncated Git tree. WordlistHub detects this condition instead of silently presenting an incomplete repository.

---

# 📸 Screenshots

Screenshots will be added here.

Recommended screenshots:

```text
1. WordlistHub Browse tab
2. Searching SecLists
3. Wordlist preview
4. Adding a GitHub repository
5. Cache management
6. Selecting Wordlist Hub inside Intruder
```

---

# 🗺 Roadmap

Potential future improvements include:

* [ ] Additional public wordlist sources
* [ ] Better repository management
* [ ] GitHub API authentication
* [ ] Wordlist metadata
* [ ] Wordlist tagging
* [ ] Duplicate removal
* [ ] Payload transformations
* [ ] Context-menu integration
* [ ] Technology-based wordlist suggestions
* [ ] Improved offline catalog support
* [ ] Migration to the modern Burp Montoya API

---


# ⚖️ Disclaimer

WordlistHub is intended for **authorized security testing, penetration testing, security research, and educational purposes**.

Only use this tool against systems that you own or have explicit permission to test.

The authors and contributors are not responsible for misuse of this software.

---

## ⭐ Support the Project

If WordlistHub saves you time during penetration testing or bug bounty hunting, consider giving the repository a **star ⭐**.

It helps other security researchers discover the project.

---

**Built for pentesters who would rather spend time testing than copying wordlists.**
