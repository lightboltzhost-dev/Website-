# 🧩 AIO Repository — Pterodactyl & Paymenter Addons, Themes & Extensions  

<div align="center">

🎨 **Modern Designs. Powerful Integrations. Seamless Hosting Experience.** ⚡  

[![Stars](https://img.shields.io/github/stars/notanotherzenpai/AIO?style=for-the-badge&color=blueviolet)](https://github.com/notanotherzenpai/AIO/stargazers)
[![Forks](https://img.shields.io/github/forks/notanotherzenpai/AIO?style=for-the-badge&color=brightgreen)](https://github.com/notanotherzenpai/AIO/forks)
[![License](https://img.shields.io/github/license/notanotherzenpai/AIO?style=for-the-badge&color=yellow)](./LICENSE)
[![Issues](https://img.shields.io/github/issues/notanotherzenpai/AIO?style=for-the-badge&color=red)](https://github.com/notanotherzenpai/AIO/issues)

</div>

---

## 🧠 Overview

Welcome to **AIO (All-In-One)** — your complete resource hub for:

- 🎨 **Pterodactyl Panel Themes**  
- 💳 **Paymenter Extensions & Themes**  
- ⚙️ **Custom Addons & Integrations**

Whether you're building a hosting platform or customizing your existing setup, this repository provides **ready-to-use** designs, **optimized** extensions, and **premium-quality** UI packs that elevate your entire experience.

---

## 🖼️ Contents

### 🦋 Pterodactyl Panel Themes
> Beautiful, modern, and fully responsive panel themes for Pterodactyl.

| Theme | Description | Preview |
|:------|:-------------|:--------|
| **Nebula UI** | A futuristic gradient-based theme with glowing accents. | 🌌 |
| **AuroraX** | A sleek dark mode theme with smooth animations. | 🌃 |
| **Frostbyte** | Minimalist white theme with clean visuals. | ❄️ |

---

### 💰 Paymenter Extensions & Themes
> Boost your hosting billing system with these add-ons and UI packs.

| Extension / Theme | Type | Description |
|:------------------|:------|:-------------|
| **Stripe Pro Gateway** | 🔌 Extension | Enhanced Stripe integration with auto-renew & webhook support. |
| **DarkNova** | 🎨 Theme | Elegant dark UI for Paymenter with glassmorphism design. |
| **Client Portal+** | 🧾 Extension | Adds dashboard analytics and invoice widgets. |

---

## ⚙️ Installation

> Each theme and extension includes its own installation instructions in its folder.

### 📦 Example (Pterodactyl Theme)
```bash
cd /var/www/pterodactyl
git clone https://github.com/yourusername/yourrepo.git
cp -r themes/nebula-ui/* public/
php artisan cache:clear
