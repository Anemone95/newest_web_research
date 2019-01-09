# 关于这个仓库

本仓库将收录近三年来Web方向的相关研究，希望自己能从中找到新的研究方向。

## USENIX2018

NAVEX: Precise and Scalable Exploit Generation for Dynamic Web Applications. 

通过动静态结合的方式生成攻击脚本

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

The impact of regular expression denial of service (ReDoS) in practice: an empirical study at the ecosystem scale. **ReDoS哦**



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

## NDSS2019
Understanding Open Ports in Android Applications: Discovery, Diagnosis, and Security Assessment
https://daoyuan14.github.io/papers/NDSS19_OpenPort.pdf

# NDSS2018

SYNODE: Understanding and Automatically Preventing Injection Attacks on NODE.JS.

## Riding out DOMsday: Towards Detecting and Preventing DOM Cross-Site Scripting[NDSS18]
### 什么是DOM型XSS：
![1546778397220](readme/1546778397220.png)
### 怎么防御：

![1546778565366](readme/1546778565366.png)

### 方法

我们使用了向V8引擎注入污点技术，具体来说，我们在每个输入的字符串上增加了一个标记，最后看这些标记是否会被document.write()等函数带出。在中间过程中我们需要考虑encodeURI等函数，他们应使标记失效。

### 实验结果

我们与其他静态工具做对比，发现BurpSuite只发现了10%的问题，但是发现了一些其他我们没有发现的问题，而其他工具存在相当高的误报率——95%

### 相关链接

https://github.com/wrmelicher/ChromiumTaintTracking

## NDSS2017

Thou Shalt Not Depend on Me: Analysing the Use of Outdated JavaScript Libraries on the Web.

## NDSS2016

Attack Patterns for Black-Box Security Testing of Multi-Party Web Applications. 

我们针对单点登陆(SSO)存在的问题，设计了两种攻击模式CSRF和XSS，并且基于ZAP设计了扫描器，经过实验我们发先它能发现知名网站的安全性问题。

## NDSS15
Exploiting and Protecting Dynamic Code Generation.

## NDSS14
Toward Black-Box Detection of Logic Flaws in Web Applications.

