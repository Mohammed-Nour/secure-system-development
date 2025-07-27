# Secure System Development - Course Labs & Project

This repository contains comprehensive lab exercises and solutions for the **Secure System Development** course (Spring 2025). The labs cover essential security concepts including CI/CD infrastructure, vulnerability scanning, memory safety, fuzzing, and web application firewalls.

## 📚 Course Overview

The course focuses on practical security implementation through hands-on labs covering:

- DevSecOps and CI/CD security integration
- Static Application Security Testing (SAST)
- Memory safety and vulnerability analysis
- Fuzzing techniques for security testing
- Web Application Firewall (WAF) deployment and configuration

## 🗂️ Repository Structure

```log
secure-system-development/
├── lab1/                   # GitLab CI/CD & SAST Integration
├── lab2/                   # Vulnerability Scanning with SAST Tools
├── lab3/                   # Memory Safety & Valgrind Analysis
├── lab4/                   # Fuzzing Techniques
├── lab5/                   # Web Application Firewall (WAF)
└── README.md               # Documentation
```

## 🔬 Lab Descriptions

### Lab 1: GitLab CI/CD Infrastructure & SAST Integration

**Focus**: Setting up self-managed GitLab server and integrating Static Application Security Testing

**Key Learning Outcomes**:

- Deploy GitLab server using Docker on AWS EC2
- Configure GitLab Runner for CI/CD pipeline execution
- Integrate Semgrep SAST tool for automated security scanning
- Analyze vulnerability reports and implement fixes

**Technologies Used**: Docker, GitLab CE, AWS EC2, Semgrep, HTTPS/SSL configuration

**Highlights**:

- Self-signed certificate generation with mkcert
- Docker Compose configuration for GitLab deployment
- CI/CD pipeline automation with `.gitlab-ci.yml`
- SQL injection vulnerability detection and mitigation

---

### Lab 2: Vulnerability Scanning with SAST Tools

**Focus**: Comprehensive vulnerability scanning using multiple SAST tools across different programming languages

**Key Learning Outcomes**:

- Master popular SAST tools: Bandit (Python), Flawfinder (C), njsscan (Node.js)
- Practical exploitation of common web vulnerabilities
- Vulnerability analysis and risk assessment
- Security tool integration and reporting

**Vulnerabilities Explored**:

- **Cross-Site Scripting (XSS)**: Script injection and session hijacking
- **Path Traversal**: Directory traversal attacks and file system access
- **SQL Injection**: Database manipulation and data extraction
- **File Upload Exploits**: Malicious file upload and execution
- **Command Injection**: OS command execution vulnerabilities

**Tools & Technologies**: Bandit, Flawfinder, njsscan, Burp Suite, Docker containers

---

### Lab 3: Memory Safety & Valgrind Analysis

**Focus**: Memory safety analysis and debugging using Valgrind

**Key Learning Outcomes**:

- Memory leak detection and prevention
- Buffer overflow identification and mitigation
- Use-after-free vulnerability analysis
- Secure coding practices for memory management

**CWE Classifications Addressed**:

- **CWE-787**: Out-of-Bounds Write
- **CWE-125**: Out-of-Bounds Read  
- **CWE-401**: Memory Leak
- **CWE-416**: Use After Free
- **CWE-457**: Use of Uninitialized Variable
- **CWE-835**: Infinite Loop Conditions

**Technologies Used**: GCC, Valgrind, C programming, Memory debugging tools

---

### Lab 4: Fuzzing Techniques

**Focus**: Security testing through fuzzing methodologies

**Key Learning Outcomes**:

- Web application fuzzing with ffuf
- Python application fuzzing with AFL++
- Endpoint discovery and vulnerability identification
- Crash analysis and security impact assessment

**Fuzzing Targets**:

- **Web Application**: DVWA (Damn Vulnerable Web Application)
- **Directory Discovery**: Hidden endpoints and configuration files
- **File Extension Testing**: Server-side vulnerability discovery
- **Python Applications**: Memory corruption and crash detection

**Tools Used**: ffuf, AFL++, SecLists wordlists, Docker

---

### Lab 5: Web Application Firewall (WAF)

**Focus**: ModSecurity WAF deployment and SQL injection protection

**Key Learning Outcomes**:

- WAF deployment and configuration
- OWASP Core Rule Set (CRS) implementation
- Custom rule development for SQL injection prevention
- Attack pattern analysis and blocking effectiveness

**Key Achievements**:

- Deployed ModSecurity with OWASP CRS
- Created custom SQL injection detection rules
- Blocked 41,000+ malicious requests (improvement from 29,000 with default rules)
- Analyzed attack patterns and WAF effectiveness

**Technologies Used**: ModSecurity, Apache, OWASP CRS, Docker Compose

## 🚀 Course Project: HashiCorp Vault Secret Management

The final project demonstrates practical implementation of enterprise-grade secret management using HashiCorp Vault, applying all security concepts learned throughout the course.

**Project Repository**: [Vault Secret Use Cases Project](https://github.com/Mohammed-Nour/vault-secret-use-cases-project)

**Project Overview**:
This project implements a comprehensive secret management solution using HashiCorp Vault, showcasing real-world security practices for credential management, encryption, and secure data access patterns.

## 🛠️ Technologies & Tools Used

### Security Testing Tools

- **SAST Tools**: Bandit, Flawfinder, njsscan, Semgrep
- **Memory Analysis**: Valgrind, GCC debugging flags
- **Fuzzing**: ffuf, AFL++, SecLists
- **Web Security**: Burp Suite, ModSecurity WAF
- **Vulnerability Platforms**: DVWA, Custom vulnerable applications

### Infrastructure & DevOps

- **Containerization**: Docker, Docker Compose
- **CI/CD**: GitLab CE, GitLab Runner
- **Cloud Platform**: AWS EC2
- **Web Servers**: Apache, Nginx
- **SSL/TLS**: mkcert, self-signed certificates

### Programming & Analysis

- **Languages**: C, Python, Java, JavaScript/Node.js
- **Compilation**: GCC with security flags
- **Debugging**: Valgrind, static analysis tools
- **Scripting**: Bash, automation scripts

## 📊 Key Metrics & Achievements

- **29,000+ → 41,000+** SQL injection attempts blocked (42% improvement with custom WAF rules)
- **Multiple CWE classifications** identified and mitigated across all labs
- **5 comprehensive lab reports** with detailed vulnerability analysis
- **End-to-end security pipeline** from development to deployment
- **Production-ready security configurations** for real-world applications

## 📖 Documentation

Each lab contains comprehensive documentation including:

- Step-by-step implementation guides
- Screenshot evidence of security testing
- Vulnerability analysis and CWE mappings
- Mitigation strategies and secure coding practices
- Tool configuration and best practices

## 🎯 Learning Outcomes

Upon completion of this course, students will have practical experience with:

1. **DevSecOps Integration**: Seamless security integration in CI/CD pipelines
2. **Vulnerability Assessment**: Comprehensive security testing across multiple domains
3. **Memory Safety**: Low-level security analysis and secure coding practices
4. **Fuzzing Methodologies**: Advanced security testing techniques
5. **WAF Configuration**: Real-world web application protection
6. **Security Tool Mastery**: Professional-grade security testing tools
7. **Incident Response**: Vulnerability analysis and remediation strategies

## 🔗 Additional Resources

- [Course Project Repository](https://github.com/Mohammed-Nour/vault-secret-use-cases-project)
- [OWASP Security Guidelines](https://owasp.org/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [Secure Coding Standards](https://securecoding.cert.org/)

---

**Course**: Secure System Development - Spring 2025  
**Student**: Mohamad Nour Shahin  
**Institution**: Third Year, Second Semester
