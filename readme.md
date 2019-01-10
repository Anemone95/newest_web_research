# 关于这个仓库

本仓库将收录近三年来Web方向的相关研究，希望自己能从中找到新的研究方向。

# USENIX2018

## NAVEX: Precise and Scalable Exploit Generation for Dynamic Web Applications. 

我们构造了一个可拓展的动静结合的web漏洞生成框架，第一步，我们用符号执行构建各个模块的行为模型，第二不，我们构建应用并且使用爬虫获取网站路径，同时使用动态符号执行最大化代码覆盖范围

### 相关文献
* https://github.com/aalhuz/navex

Freezing the Web: A Study of ReDoS Vulnerabilities in JavaScript-based Web Servers. 

Rampart: protecting web applications from CPU-exhaustion denial-of-service attacks.

Who left open the cookie jar? a comprehensive evaluation of third-party cookie policies.

We Still Don’t Have Secure Cross-Domain Requests: an Empirical Study of CORS.

FlowCog: Context-aware Semantics Extraction and Analysis of Information Flow Leaks in Android Apps.

Same-Origin Policy: Evaluation in Modern Browsers. 

## USENIX2017

CCSP: Controlled Relaxation of Content Security Policies by Runtime Policy Composition.

Same-Origin Policy: Evaluation in Modern Browsers.

Measuring the Insecurity of Mobile Deep Links of Android. 

How the Web Tangled Itself: Uncovering the History of Client-Side Web (In)Security. 

Loophole: Timing Attacks on Shared Event Loops in Chrome.


## USENIX2016

k-fingerprinting: A Robust Scalable Website Fingerprinting Technique

Hey, You Have a Problem: On the Feasibility of Large-Scale Web Vulnerability Notification.

On Omitting Commits and Committing Omissions: Preventing Git Metadata Tampering That (Re)introduces Software Vulnerabilities



## FSE2018

The impact of regular expression denial of service (ReDoS) in practice: an empirical study at the ecosystem scale. **ReDoS哦*



## ASE2018

ReScue: crafting regular expression DoS attacks. **ReDoS怎么那么多？难道是现在的研究热点吗？**

## ASE2017

Static detection of asymptotic resource side-channel vulnerabilities in web applications.

## CCS2018

Predicting Impending Exposure to Malicious Content from User Behavior.

## CCS2017

Tail Attacks on Web Applications

Deemon: Detecting CSRF with Dynamic Analysis and Property Graphs. **动态检测CSRF，可以先读一下**

## CCS2016

Chainsaw: Chained Automated Workflow-based Exploit Generation.

CSPAutoGen: Black-box Enforcement of Content Security Policy upon Real-world Websites

# CCS2015

## FlowWatcher: Defending against Data Disclosure Vulnerabilities in Web Applications
10.1145/2810103.2813639



# CSS2014

## MACE: Detecting Privilege Escalation Vulnerabilities in Web Applications



# NDSS2019
## Understanding Open Ports in Android Applications: Discovery, Diagnosis, and Security Assessment
https://daoyuan14.github.io/papers/NDSS19_OpenPort.pdf

## Time Does Not Heal All Wounds: A Longitudinal Analysis of Security-Mechanism Support in Mobile Browsers

我们发现web应用存在的问题仍然会在Android中出现，但是很多移动端浏览器并没有遵从安全准则

## Don’t Trust The Locals: Investigating the Prevalence of Persistent Client-Side Cross-Site Scripting in the Wild

我们通过污点跟踪技术寻找客户端的XSS问题

* JavaScript Template Attacks: Automatically Inferring Host Information for Targeted Exploits
* How to end password reuse on the web

# NDSS2018

## SYNODE: Understanding and Automatically Preventing Injection Attacks on NODE.JS
### 摘要
我们在研究中发现Nodejs的很多模块存在命令注入攻击的问题，为此我们题注了Synode，一个结合静态分析和动态的方法，来使用户安全的使用这些有问题的库。具体来说，Synode静态分析哪些值会传播到API中，并且在安装时修复；动态运行时，它截恶意请求防止他们传递到api中。
### 相关工作
* X. Jin, X. Hu, K. Ying, W. Du, H. Yin, and G. N. Peri. Code injection attacks on HTML5-based mobile apps: Characterization, detection and mitigation. In Conference on Computer and Communications Security, pages 66–77, 2014
* P. Saxena, D. Molnar, and B. Livshits. SCRIPTGARD: automatic context-sensitive sanitization for large-scale legacy web applications. In CCS, pages 601–614, 2011. 
* M. Ter Louw and V. N. Venkatakrishnan. Blueprint: Robust prevention of cross-site scripting attacks for existing browsers. In Sec. and Privacy, pages 331–346, 2009. 
* S. Guarnieri and B. Livshits. GATEKEEPER: mostly static enforcement of security and reliability policies for JavaScript code. In USENIX Security, pages 151–168, 2009. 

## Riding out DOMsday: Towards Detecting and Preventing DOM Cross-Site Scripting
### 什么是DOM型XSS：
![1546778397220](readme/1546778397220.png)
### 怎么防御：

![1546778565366](readme/1546778565366.png)

### 方法

我们使用了向V8引擎注入污点技术，具体来说，我们在每个输入的字符串上增加了一个标记，最后看这些标记是否会被document.write()等函数(sink function)带出。在中间过程中我们需要考虑encodeURI等函数，他们应使标记失效。

### 实验结果

我们与其他静态工具做对比，发现BurpSuite只发现了10%的问题，但是发现了一些其他我们没有发现的问题，而其他工具存在相当高的误报率——95%

### 相关链接

* https://github.com/wrmelicher/ChromiumTaintTracking
* S. Lekies, B. Stock, and M. Johns, “25 million flows later: large-scale detection of DOM-based XSS,” in Proc. CCS, 2013, pp. 1193–1204.

## NDSS2017

Thou Shalt Not Depend on Me: Analysing the Use of Outdated JavaScript Libraries on the Web.

# NDSS2016

## Attack Patterns for Black-Box Security Testing of Multi-Party Web Applications. 
我们针对单点登陆(SSO)存在的问题，设计了两种攻击模式CSRF和XSS，并且基于ZAP设计了扫描器，经过实验我们发先它能发现知名网站的安全性问题。

# NDSS2015

## FlowWatcher: Defending against Data Disclosure Vulnerabilities in Web Applications



# NDSS2014
## Toward Black-Box Detection of Logic Flaws in Web Applications

由于缺失文档，判断逻辑漏洞十分困难，现有的工具需要调查源代码或是只适用于小规模应用，而我们利用用户产生的流量产生一个行为序列，接着重用这个序列判断网站是否存在问题。

## MACE: Detecting Privilege Escalation Vulnerabilities in Web Applications

我们实现了工具MACE，通过访问资源时的上下文不一致性来识别水平特权升级漏洞

# S&P2018
## Study and Mitigation of Origin Stripping Vulnerabilities in Hybrid-postMessage Enabled Mobile Applications



## Mobile Application Web API Reconnaissance: Web-to-Mobile Inconsistencies & Vulnerabilities. 



# S&P2017
## Cloak of Visibility: Detecting When Machines Browse a Different Web



## The Cracked Cookie Jar: HTTP Cookie Hijacking and the Exposure of Private Information.


