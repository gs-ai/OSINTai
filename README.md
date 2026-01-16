<img src="bd800949-d4d1-44ce-849e-ba40837590bc.png" alt="OSINTai Logo" width="100%">

# OSINTai v3.3 - Advanced AI-Powered OSINT Web Crawler

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Async](https://img.shields.io/badge/async-httpx-green.svg)](https://www.python-httpx.org/)
[![AI](https://img.shields.io/badge/AI-Ollama-purple.svg)](https://ollama.ai/)

## 🌟 Overview

**OSINTai** is a cutting-edge, AI-enhanced web crawler engineered for **Open Source Intelligence (OSINT)** professionals, cybersecurity researchers, and digital investigators. Leveraging advanced asynchronous processing, intelligent proxy rotation, and state-of-the-art LLM analysis, OSINTai automates comprehensive intelligence gathering from web sources with unparalleled efficiency and accuracy.

**Key Capabilities:**
- 🚀 **High-Performance Async Crawling** with intelligent concurrency controls
- 🧠 **AI-Powered Content Analysis** using Ollama LLMs for structured intelligence extraction
- 🎯 **Advanced Indicator Mining** with automated entity recognition and risk assessment
- 📊 **Graph-Based Intelligence Mapping** with ACE-T compatible export formats
- 🛡️ **Operational Security** featuring proxy rotation, user-agent randomization, and stealth techniques
- 🔍 **Hunt Mode** for targeted intelligence discovery with configurable search terms
- ⚡ **Near-Duplicate Detection** using Simhash algorithms to eliminate redundant content
- 📈 **Intelligent Scoring** and prioritization based on indicator density and risk factors

---

## ✨ Key Features

### 🚀 Performance & Scalability
- **Asynchronous Architecture**: Concurrent processing with configurable global (18) and per-host (4) concurrency limits
- **Intelligent Proxy Management**: Health-scored proxy rotation with automatic failover and performance tracking
- **Adaptive Throttling**: Per-host rate limiting prevents site overwhelming while maximizing throughput
- **Resume Capability**: Automatic checkpointing and state persistence for interrupted operations
- **Memory Efficient**: Optimized for large-scale crawls with minimal resource overhead

### 🧠 AI-Powered Intelligence
- **LLM Content Analysis**: Structured intelligence extraction using Ollama models (`granite3.2:latest`)
- **Vector Embeddings**: Semantic content embeddings for clustering and similarity analysis (`nomic-embed-text:latest`)
- **Risk Intelligence**: Automated identification of suspicious patterns, high-risk indicators, and threat signals
- **Contextual Analysis**: Deep content understanding with entity relationships and temporal analysis

### 🎯 Advanced Intelligence Extraction
- **Comprehensive Indicator Mining**: Extracts emails, phone numbers, cryptocurrency addresses, social media handles, domains, IP addresses, and custom patterns
- **Hunt Mode**: Targeted crawling for specific intelligence terms with configurable lead discovery limits
- **Content Deduplication**: Simhash-based near-duplicate detection to eliminate redundant information
- **Intelligence Scoring**: Automated prioritization based on indicator density, risk flags, and content relevance

### 📊 Intelligence Scoring Algorithm

OSINTai employs a sophisticated multi-factor scoring system that combines traditional indicator mining with AI-powered risk assessment to prioritize pages by intelligence value:

#### Traditional Indicators (Base Scoring)
- **Emails**: 2.0 points each (max 10 emails = 20 points)
- **Phone Numbers**: 1.5 points each (max 5 phones = 7.5 points)
- **BTC Addresses**: 3.0 points each (max 3 addresses = 9 points)
- **ETH Addresses**: 3.0 points each (max 3 addresses = 9 points)
- **Social Media Handles**: 1.0 point each (max 5 handles = 5 points)

#### AI Analysis Enhancement (Intelligence Boost)
- **Risk Flags**: 5.0 points each (unlimited - highest priority intelligence)
  - Examples: "Hacking Campaigns", "Data Breaches", "Regulatory Changes"
- **Actionable Leads**: 3.0 points each (unlimited - valuable insights)
  - Examples: Investigation recommendations, strategic intelligence
- **Key Entities**: 1.0 point each (max 10 entities = 10 points)
  - Named entities like organizations, people, technologies
- **Key Locations**: 1.5 points each (max 5 locations = 7.5 points)
  - Geographic intelligence and operational locations
- **Keywords**: 0.5 points each (max 20 keywords = 10 points)
  - Topic relevance and content categorization

#### Scoring Examples
- **High-Value Page**: Risk flags (10 pts) + actionable leads (9 pts) + entities (8 pts) = 27+ points
- **Medium-Value Page**: Entities (6 pts) + locations (4.5 pts) + keywords (8 pts) = 18.5 points
- **Low-Value Page**: Basic indicators only (emails, phones) = 5-15 points

Pages are automatically ranked by total score, with AI-enhanced intelligence receiving the highest prioritization for OSINT analysis.

### 📊 Data Export & Visualization
- **Graph Export**: ACE-T compatible JSONL format with nodes, edges, and relationship mapping
- **Multi-Format Reports**: Structured JSON, JSONL, and human-readable intelligence summaries
- **Visualization Ready**: Compatible with GraphXR, Neo4j, NetworkX, and D3.js for advanced analysis
- **Comprehensive Metadata**: Full crawl state, analysis results, timestamps, and provenance tracking

### 🛡️ Operational Security & Ethics
- **User-Agent Rotation**: Extensive randomization pool to avoid detection and fingerprinting
- **Proxy Anonymization**: Built-in proxy health management with automatic rotation
- **Configurable Delays**: Adaptive timing controls to respect site policies and avoid rate limiting
- **Domain Filtering**: Optional same-domain restriction for focused, controlled analysis
- **Ethical Design**: Built for authorized OSINT research with responsible data handling

---

## 📦 Installation

### Prerequisites
- **Python 3.10+**
- **Conda** (recommended for environment management)
- **Ollama** (optional, for AI-powered features)

### Quick Setup

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/OSINTai.git
cd OSINTai

# 2. Create conda environment
conda create -n osintai python=3.10 beautifulsoup4 requests httpx anyio lxml -y
conda activate osintai

# 3. Install Ollama (for AI features)
brew install ollama
ollama pull granite3.2:latest
ollama pull nomic-embed-text:latest

# 4. Verify installation
python run_osintai.py --help
```

### Alternative Installation (pip)
```bash
pip install beautifulsoup4 requests httpx anyio lxml
```

---

## 🚀 Quick Start

### Basic Intelligence Gathering
```bash
python run_osintai.py \
  --seed "https://example.com" \
  --depth 2 \
  --max 150 \
  --same-domain
```

### AI-Enhanced Analysis
```bash
python run_osintai.py \
  --seed "https://target-site.com" \
  --model "granite3.2:latest" \
  --embed-model "nomic-embed-text:latest" \
  --concurrency 12
```

### Targeted Hunt Mode
```bash
python run_osintai.py \
  --seed "https://investigation-target.com" \
  --hunt "invoice,wire transfer,bank,crypto,telegram,darkweb" \
  --hunt-max 60 \
  --depth 3
```

### High-Speed Crawling (No AI)
```bash
python run_osintai.py \
  --seed "https://large-site.com" \
  --no-ollama \
  --max 1000 \
  --concurrency 32 \
  --per-host 6
```

### Proxy-Enhanced Operations
```bash
python run_osintai.py \
  --seed "https://target.com" \
  --proxies "proxies.txt" \
  --concurrency 8 \
  --per-host 2
```

### Multi-Seed URL Crawling
Create a `seed_urls.txt` file in the project root:
```
https://site1.com
https://site2.com
https://site3.com
```

Then run:
```bash
python run_osintai.py --seed "https://example.com"  # Will also check for seed_urls.txt
```

---

## 📋 Command Line Options

```
usage: run_osintai.py [-h] [--seed SEED] [--depth DEPTH] [--max MAX]
                      [--same-domain] [--concurrency CONCURRENCY]
                      [--per-host PER_HOST] [--ua UA] [--proxies PROXIES]
                      [--model MODEL] [--embed-model EMBED_MODEL]
                      [--no-ollama] [--hunt HUNT] [--hunt-max HUNT_MAX]
                      [--run-id RUN_ID]

OSINTai v3.3 FULL (async + proxy + dedupe + embeddings + hunt + graph export)

required arguments:
  --seed SEED           Seed URL (or use seed_urls.txt file)

optional arguments:
  --depth DEPTH         Max crawl depth (default: 2)
  --max MAX            Max URLs to crawl (default: 150)
  --same-domain        Only crawl same domain as seed
  --concurrency CONCURRENCY  Global concurrency limit (default: 18)
  --per-host PER_HOST   Per-host concurrency limit (default: 4)
  --ua UA              User agents file (default: user_agents.txt)
  --proxies PROXIES    Optional proxy list file
  --model MODEL        Ollama analysis model (default: granite3.2:latest)
  --embed-model EMBED_MODEL  Ollama embeddings model (default: nomic-embed-text:latest)
  --no-ollama          Disable LLM analysis and embeddings
  --hunt HUNT          Comma-separated hunt terms (optional)
  --hunt-max HUNT_MAX  Max lead URLs per page from hunt mode (default: 50)
  --run-id RUN_ID      Optional run ID override (default: auto-generated)
```

---

## 📁 Output Structure

Each crawl generates a timestamped directory under `data/runs/` with comprehensive intelligence data:

### Core Intelligence Data
- **`urls_crawled.jsonl`** - Complete crawl log with HTTP status, timestamps, and metadata
- **`indicators.jsonl`** - Extracted intelligence indicators with context and confidence scores
- **`page_scores.jsonl`** - Intelligence-scored pages with analysis results and risk assessments
- **`crawl_state.json`** - Resume state for interrupted operations

### AI Analysis Results (when enabled)
- **`analysis/`** - Individual page intelligence analysis in JSON format
- **`embeddings/`** - Vector embeddings for semantic clustering and similarity analysis
- **`hunt.jsonl`** - Targeted hunt mode discoveries (when hunt terms specified)

### Intelligence Reports
- **`report.txt`** - Human-readable executive summary with key findings
- **`ranked_pages.json`** - Structured intelligence prioritization and scoring
- **`graph_nodes.jsonl`** - Graph nodes for network visualization and analysis
- **`graph_edges.jsonl`** - Graph relationships and connections

### Raw Content Archives
- **`pages_raw/`** - Original HTML content for forensic analysis
- **`pages_text/`** - Extracted text content for processing and review

### Example Output Structure
```
data/runs/2026-01-16_143022_investigation_001/
├── urls_crawled.jsonl          # Complete crawl audit trail
├── indicators.jsonl             # Intelligence indicators
├── page_scores.jsonl            # Intelligence scoring
├── crawl_state.json             # Resume capability
├── analysis/                    # AI analysis results
│   ├── abc123.analysis.json
│   └── def456.analysis.json
├── embeddings/                  # Vector embeddings
│   ├── abc123.embed.json
│   └── def456.embed.json
├── pages_raw/                   # Raw HTML archive
├── pages_text/                  # Text extraction
├── hunt.jsonl                   # Hunt mode results
├── report.txt                   # Executive summary
├── ranked_pages.json            # Structured intelligence
├── graph_nodes.jsonl            # Graph visualization
└── graph_edges.jsonl            # Graph relationships
```

---

## ⚙️ Configuration Files

### User Agents (`user_agents.txt`)
**Purpose**: Request header randomization to avoid detection
**Format**: One user agent string per line
**Location**: Project root

### Proxy Lists (Optional)
**Purpose**: IP rotation and anonymity
**Format**: One proxy URL per line (`http://ip:port` or `ip:port`)
**Location**: Any accessible file path

### Seed URLs (`seed_urls.txt`) - Optional
**Purpose**: Batch processing of multiple starting points
**Format**: One URL per line
**Location**: Project root (auto-detected)
**Example**:
```
https://target1.com/investigation
https://target2.com/research
https://target3.com/analysis
```

---

## 🎯 Advanced Usage Patterns

### Intelligence Pipeline Workflow
```bash
# Phase 1: Broad Discovery (High Speed)
python run_osintai.py \
  --seed "https://target.com" \
  --max 500 \
  --no-ollama \
  --concurrency 32

# Phase 2: Deep AI Analysis (Quality over Speed)
python run_osintai.py \
  --seed "https://target.com" \
  --max 100 \
  --model "granite3.2:latest" \
  --concurrency 8

# Phase 3: Targeted Intelligence Hunt
python run_osintai.py \
  --seed "https://target.com" \
  --hunt "malware,ransomware,exploit,credential" \
  --hunt-max 100 \
  --depth 4
```

### Large-Scale Enterprise Crawling
```bash
python run_osintai.py \
  --seed "https://enterprise-site.com" \
  --max 2000 \
  --concurrency 24 \
  --per-host 4 \
  --depth 5 \
  --run-id "enterprise_audit_2026"
```

### Custom Model Integration
```bash
# Using different Ollama models
python run_osintai.py \
  --seed "https://target.com" \
  --model "llama2:13b" \
  --embed-model "all-minilm:33m"
```

### Forensic Data Preservation
```bash
# Maximum data retention for investigations
python run_osintai.py \
  --seed "https://evidence-site.com" \
  --max 50 \
  --depth 3 \
  --run-id "forensic_case_123"
```

---

## 📊 Graph Export & Visualization

OSINTai generates ACE-T compatible graph data for advanced network analysis and visualization:

### Node Types
- **Pages**: Web pages with intelligence scores and metadata
- **Indicators**: Extracted entities (emails, domains, IPs, etc.)
- **Relationships**: Connections between entities and content

### Sample Node Format
```json
{"id": "page:https://example.com/intel", "type": "page", "label": "Intelligence Page", "props": {"title": "Secret Intel", "score": 25.7, "risk_flags": ["suspicious"]}, "ts": 1705411200.0}
{"id": "email:investigator@agency.gov", "type": "email", "label": "investigator@agency.gov", "props": {"confidence": 0.95}, "ts": 1705411200.0}
```

### Sample Edge Format
```json
{"src": "page:https://example.com/intel", "dst": "email:investigator@agency.gov", "type": "mentions_email", "props": {"context": "contact information"}, "ts": 1705411200.0}
```

### Visualization Platforms
- **🖥️ GraphXR**: Direct JSONL import for real-time graph exploration
- **🗄️ Neo4j**: Enterprise graph database with Cypher queries
- **🐍 NetworkX**: Python graph analysis and algorithmic processing
- **🌐 D3.js**: Custom web-based visualizations and dashboards

---

## ⚡ Performance Optimization

### Concurrency Tuning
- **Global Concurrency**: Total simultaneous requests (recommended: 12-24)
- **Per-Host Concurrency**: Domain-specific limits (recommended: 3-6)
- **Memory Scaling**: Reduce concurrency for large crawls (>1000 URLs)

### Network Optimization
- **Proxy Distribution**: Spread load across multiple IP addresses
- **Delay Configuration**: Adjust timing based on target site sensitivity
- **Timeout Management**: Increase for slow networks or international targets

### AI Performance
- **Model Selection**: Balance accuracy vs speed (`granite3.2:latest` recommended)
- **Batch Processing**: AI analysis scales with available Ollama resources
- **Embedding Optimization**: Vector storage requires ~700KB per analyzed page

---

## 🔧 Troubleshooting

### Common Issues & Solutions

**Ollama Connection Failed**
```bash
# Verify Ollama service
ollama serve
ollama list

# Test model availability
ollama run granite3.2:latest "test"

# Fallback to non-AI mode
python run_osintai.py --seed "https://example.com" --no-ollama
```

**Proxy Configuration Issues**
```bash
# Validate proxy file format
head -5 proxies.txt

# Test proxy connectivity
curl -x http://proxy-ip:port https://httpbin.org/ip

# Run without proxies
python run_osintai.py --seed "https://example.com"
```

**Memory/Resource Constraints**
```bash
# Reduce concurrency for large crawls
python run_osintai.py \
  --seed "https://example.com" \
  --concurrency 8 \
  --per-host 2 \
  --max 500
```

**Rate Limiting Detection**
```bash
# Increase delays between requests
# Modify fetcher.py: min_delay_s, max_delay_s defaults
# Or use proxy rotation for distribution
```

### Debug Mode
```python
# Enable verbose logging (modify cli.py)
import logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
```

---

## 🏗️ Architecture

### Core Module Structure
```
src/osintai/
├── cli.py              # Command-line interface and orchestration
├── crawler.py          # Async crawling engine with deduplication
├── fetcher.py          # HTTP client with proxy rotation and retry logic
├── extractor.py        # Content parsing and indicator extraction
├── analyzer.py         # Intelligence scoring and risk assessment
├── ollama_api.py       # LLM integration for analysis and embeddings
├── proxy_pool.py       # Proxy health management and rotation
├── graph_export.py     # Graph data serialization and export
├── hunt.py             # Targeted term discovery and lead generation
├── normalize.py        # URL processing and normalization utilities
├── dedupe.py           # Simhash-based content deduplication
├── scoring.py          # Page ranking and intelligence prioritization
├── report.py           # Human-readable report generation
├── storage.py          # File I/O and data persistence utilities
└── __init__.py         # Package initialization
```

### Data Processing Pipeline
1. **🎯 Initialization**: Parse arguments, load configurations, initialize components
2. **🌐 Crawling**: Async HTTP fetching with concurrency controls and proxy rotation
3. **🔍 Processing**: Content extraction, indicator mining, deduplication
4. **🧠 Analysis**: LLM-powered intelligence extraction and embedding generation
5. **📊 Scoring**: Risk assessment, prioritization, and intelligence value calculation
6. **💾 Persistence**: Structured data export and graph generation
7. **📋 Reporting**: Human-readable summaries and visualization data

---

## 🔒 Security & Ethics

### Operational Security Features
- **Anonymization**: Proxy rotation and user-agent randomization
- **Stealth Techniques**: Adaptive delays and request patterns
- **Data Sanitization**: No sensitive information logging
- **Provenance Tracking**: Complete audit trail for intelligence chain of custody

### Ethical Usage Guidelines
- **Legal Compliance**: Authorized access to publicly available information only
- **Terms Respect**: Honor site policies, robots.txt, and service agreements
- **Data Handling**: Secure storage and responsible intelligence dissemination
- **Attribution**: Maintain source credibility and investigation integrity

### Responsible Research
- **Authorization**: Obtain proper permissions for sensitive investigations
- **Transparency**: Document methodologies and data sources
- **Impact Assessment**: Consider potential consequences of findings
- **Community Standards**: Adhere to OSINT professional ethics and best practices

---

## 🤝 Contributing

### Development Environment
```bash
# Fork and clone
git clone https://github.com/yourusername/OSINTai.git
cd OSINTai

# Create development environment
conda create -n osintai-dev python=3.10 -y
conda activate osintai-dev
pip install -r requirements.txt

# Install development tools
pip install black flake8 pytest mypy
```

### Code Quality Standards
- **Formatting**: Black code formatter with 120 character line length
- **Linting**: flake8 for code quality and style consistency
- **Type Hints**: Full type annotation coverage
- **Testing**: Comprehensive unit and integration tests
- **Documentation**: Detailed docstrings and inline comments

### Contribution Workflow
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-enhancement`)
3. Implement changes with tests
4. Ensure all tests pass (`pytest`)
5. Format code (`black .`)
6. Lint code (`flake8`)
7. Commit with clear messages
8. Push and create pull request

---

## 📄 License

**MIT License** - See [LICENSE](LICENSE) file for complete terms.

---

## ⚖️ Legal Disclaimer

**OSINTai** is developed exclusively for **ethical open source intelligence research** and **authorized security investigations**. This tool must not be used for unauthorized surveillance, data collection, or any illegal activities.

**Users bear full responsibility** for compliance with applicable laws, regulations, and terms of service. The authors assume no liability for misuse or unauthorized application of this software.

**Obtain proper authorization before conducting any intelligence operations.**

---

## 📈 Changelog

### v3.3 FULL (2026-01-16) - Current Release
- ✨ **Complete Async Rewrite**: httpx + asyncio for 10x+ performance gains
- 🛡️ **Advanced Proxy System**: Health-scored rotation with intelligent failover
- 🔍 **Simhash Deduplication**: Near-duplicate detection for content efficiency
- 🧠 **Ollama API Integration**: Native LLM analysis and vector embeddings
- 🎯 **Hunt Mode**: Targeted intelligence discovery with configurable parameters
- 📊 **ACE-T Graph Export**: Professional visualization and network analysis
- ⚡ **Performance Optimization**: Concurrent processing with memory efficiency
- 🔄 **Resume Capability**: Automatic state persistence and crash recovery
- 🏗️ **Modular Architecture**: Clean separation in `src/osintai/` package
- 🧹 **Code Cleanup**: Removed legacy components and unused files
- 📝 **Enhanced Documentation**: Comprehensive README with usage examples

### v3.1 (Legacy - Deprecated)
- Synchronous crawling architecture
- Basic indicator extraction
- Subprocess Ollama integration
- Limited scalability and performance

---

## 📞 Support & Community

- **🐛 Bug Reports**: [GitHub Issues](https://github.com/yourusername/OSINTai/issues)
- **💡 Feature Requests**: [GitHub Discussions](https://github.com/yourusername/OSINTai/discussions)
- **📖 Documentation**: Comprehensive in-code docstrings and this README
- **🤝 Community**: OSINT professional forums and security research communities

---

## 🙏 Acknowledgments

Built for the OSINT community with contributions from security researchers, digital investigators, and open source intelligence professionals worldwide.

**Use responsibly. Research ethically. Impact positively.**

---

*OSINTai v3.3 - Illuminating the shadows of open source intelligence.*
