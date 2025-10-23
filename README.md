# 🛡️ LLM-Powered Threat Intelligence Pipeline

An advanced cybersecurity threat analysis tool powered by Large Language Models (LLMs) that provides intelligent security log analysis, threat detection, and actionable recommendations.

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## 🌟 Features

- **AI-Powered Analysis**: Leverages OpenAI GPT-4 or Anthropic Claude for intelligent threat assessment
- **Mock Demo Mode**: Test the application without API keys using simulated LLM responses
- **IOC Extraction**: Automatically extracts IP addresses, domains, users, ports, files, and emails
- **MITRE ATT&CK Mapping**: Maps detected threats to MITRE ATT&CK framework
- **Pre-loaded Scenarios**: 5 sample security scenarios (SSH brute-force, phishing, malware, DDoS, data exfiltration)
- **Real-time Analysis**: Instant threat classification and risk assessment
- **Business Impact Assessment**: Understanding security events from a business perspective

## 🚀 Getting Started

### Prerequisites

- Node.js (v16 or higher)
- npm or yarn

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/llm-threat-intelligence.git
cd llm-threat-intelligence
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm run dev
```

4. Open your browser and navigate to `http://localhost:3000`

## 🔧 Configuration

### Using Mock LLM (Demo Mode)
- Toggle "Use Mock LLM (Demo Mode)" checkbox
- No API key required
- Perfect for testing and demonstrations

### Using Real LLM APIs

1. **OpenAI GPT-4**:
   - Get your API key from [platform.openai.com](https://platform.openai.com)
   - Select "OpenAI GPT-4" from provider dropdown
   - Enter your API key

2. **Anthropic Claude**:
   - Get your API key from [console.anthropic.com](https://console.anthropic.com)
   - Select "Anthropic Claude" from provider dropdown
   - Enter your API key

## 📊 Sample Scenarios

1. **SSH Brute-force Attack**: Multiple failed login attempts
2. **Phishing Email**: Spam detection and malicious sender
3. **Malware Download**: Blocked executable from suspicious domain
4. **DDoS/SYN Flood**: Network flooding attack
5. **Data Exfiltration**: Insider threat with USB data transfer

## 🛠️ Tech Stack

- **React 18** - UI framework
- **Vite** - Build tool
- **Tailwind CSS** - Styling
- **Lucide React** - Icons
- **OpenAI API** - GPT-4 integration
- **Anthropic API** - Claude integration

## 📦 Build for Production
```bash
npm run build
```

The production-ready files will be in the `dist/` directory.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Always ensure you have permission before analyzing security logs from any system.

## 📧 Contact

Your Name - [@yourtwitter](https://twitter.com/yourtwitter)

Project Link: [https://github.com/yourusername/llm-threat-intelligence](https://github.com/yourusername/llm-threat-intelligence)

## 🙏 Acknowledgments

- MITRE ATT&CK Framework
- OpenAI and Anthropic for LLM APIs
- Lucide for beautiful icons
```

---

### 13. **`LICENSE`** (Optional - MIT License)
```
MIT License

Copyright (c) 2024 Your Name

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
